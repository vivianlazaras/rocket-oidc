//! This module provides `AuthGuard` which doesn't request user info, but simply validates server public key
//! this is useful for implementing local only login systems that don't rely on full OIDC support from the authorization server

use crate::BaseClaims;
use crate::CoreClaims;
use crate::client::{AuthClient, IssuerData, OIDCClient, Validator};
use crate::config::OIDCConfig;
use crate::errors::OIDCError;
use crate::{check_expiration, generate_hmac_secret, get_i64, get_str_or_vec};

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use rocket::Request;
use rocket::http::{Cookie, CookieJar, Status};
use rocket::request::{FromRequest, Outcome};
use rocket::response::Redirect;

use serde::{Serialize, de::DeserializeOwned};
use serde_derive::Deserialize;
use serde_json::Value;

use tokio::sync::{RwLock, RwLockReadGuard};

use openidconnect::OAuth2TokenResponse;
use openidconnect::{AuthorizationCode, RefreshToken};

use time::OffsetDateTime;

/// [`AuthGuard`] is similar to [`crate::OIDCGuard`] except that its built only to parse an access token from a cookie, and doesn't require an OIDCClient
/// This is useful for testing but probably shouldn't be used in production environments, if you need pure token parsing, [`ApiKeyGuard`] that loads from Bearer field may be preferable, and more semantically correct given this doesn't handle refresh tokens.
#[derive(Debug, Clone)]
pub struct AuthGuard<T: Serialize + DeserializeOwned + Debug> {
    pub claims: T,
    access_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub(crate) struct IDClaims {
    pub iss: String,
    pub alg: String,
    pub exp: i64,
}

impl<T: Serialize + DeserializeOwned + Debug> AuthGuard<T> {
    pub fn access_token(&self) -> &str {
        &self.access_token
    }
}

/// API Key based guard
/// This guard extracts the API key from the `Authorization` header and validates it
/// It is useful for API endpoints that require authentication via API keys
#[derive(Debug, Serialize)]
pub struct ApiKeyGuard<T: Serialize + DeserializeOwned + Debug> {
    pub claims: T,
    pub access_token: String,
}

fn alg_to_string(alg: &jsonwebtoken::Algorithm) -> String {
    match alg {
        jsonwebtoken::Algorithm::HS256 => "HS256".to_string(),
        jsonwebtoken::Algorithm::HS384 => "HS384".to_string(),
        jsonwebtoken::Algorithm::HS512 => "HS512".to_string(),
        jsonwebtoken::Algorithm::RS256 => "RS256".to_string(),
        jsonwebtoken::Algorithm::RS384 => "RS384".to_string(),
        jsonwebtoken::Algorithm::RS512 => "RS512".to_string(),
        jsonwebtoken::Algorithm::ES256 => "ES256".to_string(),
        jsonwebtoken::Algorithm::ES384 => "ES384".to_string(),
        jsonwebtoken::Algorithm::PS256 => "PS256".to_string(),
        jsonwebtoken::Algorithm::PS384 => "PS384".to_string(),
        jsonwebtoken::Algorithm::PS512 => "PS512".to_string(),
        _ => "unknown".to_string(),
    }
}

pub(crate) fn get_iss_alg(token: &str) -> Option<IDClaims> {
    use crate::get_i64;
    let alg = match jsonwebtoken::decode_header(token) {
        Ok(header) => alg_to_string(&header.alg),
        Err(e) => {
            eprintln!("error decoding algorithim: {}", e);
            return None;
        }
    };
    let claims: serde_json::Value = match jsonwebtoken::dangerous::insecure_decode(token) {
        Ok(data) => data.claims,
        Err(e) => {
            eprintln!("error decoding idclaims for iss: {}", e);
            return None;
        }
    };
    println!("iss: {:?}", claims.get("iss"));
    let mut iss = get_str_or_vec(&claims, "iss").expect("failed to get str or vec for iss");
    let exp = get_i64(&claims, "exp")
        .ok()
        .expect("failed to get expiration");
    #[cfg(not(debug_assertions))]
    panic!("this needs to be refactored to have ISS in IDClaims be a Vec");

    Some(IDClaims {
        iss: iss
            .pop()
            .expect("this should be fixed to allow IDClaims to store Vec"),
        alg,
        exp,
    })
}

pub(crate) fn extract_key_from_authorization_header(header: &str) -> Option<String> {
    if header.starts_with("Bearer ") {
        Some(header[7..].to_string())
    } else {
        None
    }
}

async fn parse_authorization_header<
    T: Serialize + Debug + DeserializeOwned + std::marker::Send + CoreClaims,
>(
    header: &str,
    auth: &AuthState,
) -> Outcome<ApiKeyGuard<T>, ()> {
    let api_key = match extract_key_from_authorization_header(header) {
        Some(key) => key,
        None => {
            eprintln!("Authorization header missing or invalid");
            return Outcome::Forward(Status::Unauthorized);
        }
    };

    let idclaims = match get_iss_alg(api_key.as_str()) {
        Some(claims) => claims,
        None => {
            eprintln!("Failed to decode token to get iss/alg");
            return Outcome::Forward(Status::Unauthorized);
        }
    };

    let validator = match auth.validator(&idclaims.iss).await {
        Ok(validator) => validator,
        Err(e) => {
            eprintln!("failed to fetch validator");
            return Outcome::Forward(Status::Unauthorized);
        }
    };
    match validator.decode_with_iss_alg::<T>(&idclaims.iss, &idclaims.alg, &api_key) {
        Ok(data) => {
            return Outcome::Success(ApiKeyGuard {
                claims: data.claims,
                access_token: api_key.to_string(),
            });
        }
        Err(err) => {
            eprintln!("API key invalid with iss/alg: {}", err);
            return Outcome::Forward(Status::Unauthorized);
        }
    }
}

#[rocket::async_trait]
impl<'r, T: Serialize + Debug + DeserializeOwned + std::marker::Send + CoreClaims> FromRequest<'r>
    for ApiKeyGuard<T>
{
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let api_key = req.headers().get_one("Authorization").unwrap_or_default();

        let auth = req.rocket().state::<AuthState>().unwrap().clone();

        parse_authorization_header(api_key, &auth).await
    }
}

#[rocket::async_trait]
impl<'r, T: Serialize + Debug + DeserializeOwned + std::marker::Send + CoreClaims> FromRequest<'r>
    for AuthGuard<T>
{
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let cookies = req.cookies();
        let validator = req
            .rocket()
            .state::<crate::client::Validator>()
            .expect("validator managed state not found")
            .clone();

        if let Some(access_token) = cookies.get_private("access_token") {
            if let Some(issuer_cookie) = cookies.get_private("issuer_data") {
                // Parse JSON into IssuerData
                match serde_json::from_str::<IssuerData>(issuer_cookie.value()) {
                    Ok(issuer_data) => {
                        match validator.decode_with_iss_alg::<T>(
                            &issuer_data.issuer,
                            &issuer_data.algorithm,
                            access_token.value(),
                        ) {
                            Ok(data) => Outcome::Success(AuthGuard {
                                claims: data.claims,
                                access_token: access_token.value().to_string(),
                            }),
                            Err(err) => {
                                eprintln!(
                                    "token expired or invalid: {}, issuer: {}, algorithm: {}",
                                    err, issuer_data.issuer, issuer_data.algorithm
                                );
                                cookies.remove(Cookie::build("access_token"));
                                Outcome::Forward(Status::Unauthorized)
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("invalid issuer_data JSON: {}", err);
                        cookies.remove(Cookie::build("access_token"));
                        Outcome::Forward(Status::Unauthorized)
                    }
                }
            } else {
                let idclaims = match get_iss_alg(&access_token.value()) {
                    Some(claims) => claims,
                    None => {
                        eprintln!("Failed to decode token to get iss/alg");
                        return Outcome::Forward(Status::Unauthorized);
                    }
                };
                match validator.decode_with_iss_alg::<T>(
                    &idclaims.iss,
                    &idclaims.alg,
                    access_token.value(),
                ) {
                    Ok(data) => Outcome::Success(AuthGuard {
                        claims: data.claims,
                        access_token: access_token.value().to_string(),
                    }),
                    Err(err) => {
                        eprintln!("token expired or invalid: {}", err);
                        cookies.remove(Cookie::build("access_token"));
                        Outcome::Forward(Status::Unauthorized)
                    }
                }
            }
        } else {
            eprintln!("no access token found");
            Outcome::Forward(Status::Unauthorized)
        }
    }
}

/// Holds the authentication state used by the application.
///
/// Contains:
/// - The OIDC token validator.
/// - The OpenID Connect client for user info requests.
/// - The static OIDC configuration.
#[derive(Clone)]
pub struct AuthState {
    /// issuer_url, OIDCClient key value store.
    pub client: Arc<RwLock<HashMap<String, AuthClient>>>,
    // a collection of refresh tokens identified by iss
    pub tokens: Arc<RwLock<HashMap<String, String>>>,
    pub(crate) hmac_secret: Vec<u8>,
}

impl AuthState {
    pub async fn validator<'a>(
        &'a self,
        issuer_url: &str,
    ) -> Result<RwLockReadGuard<'a, Validator>, OIDCError> {
        RwLockReadGuard::try_map(self.client_for(issuer_url).await?, |v| Some(v.validator()))
            .map_err(|v| OIDCError::MissingClient(issuer_url.to_string()))
    }
    pub async fn client_for<'a>(
        &'a self,
        issuer_url: &str,
    ) -> Result<RwLockReadGuard<'a, AuthClient>, OIDCError> {
        RwLockReadGuard::try_map(self.client.read().await, |v| v.get(issuer_url))
            .map_err(|v| OIDCError::MissingClient(issuer_url.to_string()))
    }

    pub(crate) async fn handle_callback(
        &self,
        jar: &CookieJar<'_>,
        code: String,
        issuer: String,
        route: Option<String>,
    ) -> Result<Redirect, OIDCError> {
        let iss = &issuer;
        let default_post_login = self
            .client_for(&issuer)
            .await?
            .as_oidc_config()
            .post_login
            .map(|v| v.to_string())
            .unwrap_or_else(|| "/auth/profiles".to_string());
        // ── 1. Short-circuit if valid access_token exists
        if let Some(cookie) = jar.get_private("access_token") {
            // attempt to decode access token for invalid signature.
            let token = cookie.to_string();
            // this should catch invalid signature, and result in refresh.
            if let Some(idclaims) = get_iss_alg(&token) {
                if self
                    .validator(&issuer)
                    .await?
                    .decode_with_iss_alg::<BaseClaims>(iss, &idclaims.alg, &token)
                    .is_ok()
                {
                    let (_, expired) = check_expiration(&cookie);
                    if let Ok(exp) = OffsetDateTime::from_unix_timestamp(idclaims.exp)
                        && !expired
                    {
                        if exp > OffsetDateTime::now_utc() {
                            return Ok(Redirect::to(default_post_login));
                        }
                    }
                }
            }
        }

        // ── 2. Exchange authorization code for tokens
        let token_response = self
            .client_for(&issuer)
            .await?
            .exchange_code(AuthorizationCode::new(code))
            .await?;

        // ── 3. Store the refresh token in self.tokens
        if let Some(refresh_token) = token_response.refresh_token() {
            let mut tokens_guard = self.tokens.write().await;
            tokens_guard.insert(iss.clone(), refresh_token.secret().to_string());
        }

        // ── 5. Select algorithm for issuer
        let supported_algs = self
            .client_for(&issuer)
            .await?
            .validator()
            .get_supported_algorithms_for_issuer(&iss)
            .ok_or(OIDCError::MissingIssuerUrl)?;

        // really this should check which alg appears in the validators map, but this should work for now.
        let chosen_alg = if supported_algs.iter().any(|a| a == "RS256") {
            "RS256".to_string()
        } else {
            supported_algs
                .first()
                .cloned()
                .ok_or(OIDCError::MissingAlgoForIssuer(iss.clone()))?
        };

        // ── 4. Determine expiration of access token

        let expires_at = match token_response.expires_in() {
            Some(expires_in) => OffsetDateTime::now_utc() + expires_in,
            None => {
                let token_data = self
                    .validator(&issuer)
                    .await?
                    .decode_with_iss_alg::<Value>(
                        iss,
                        &chosen_alg,
                        token_response.access_token().secret(),
                    )?;

                OffsetDateTime::from_unix_timestamp(get_i64(&token_data.claims, "exp")?)
                    .unwrap_or_else(|_| OffsetDateTime::now_utc())
            }
        };

        // ── 7. Finalize login
        let redirect = match route {
            Some(route) => route,
            None => default_post_login,
        };
        crate::login(
            redirect,
            jar,
            token_response.access_token().secret().to_string(),
            &issuer,
            &chosen_alg,
            Some(expires_at),
        )
    }

    /// Optional: refresh an access token for a given issuer
    pub async fn refresh_access_token(&self, issuer: &str) -> Result<String, OIDCError> {
        let refresh_token = {
            let tokens_guard = self.tokens.read().await;
            tokens_guard.get(issuer).cloned()
        };

        let refresh_token = match refresh_token {
            Some(t) => RefreshToken::new(t),
            None => return Err(OIDCError::MissingRefreshToken),
        };

        let token_response = self
            .client_for(issuer)
            .await?
            .exchange_refresh_token(&refresh_token)
            .await?;

        // Update stored refresh token if rotated
        if let Some(new_refresh_token) = token_response.refresh_token() {
            let mut tokens_guard = self.tokens.write().await;
            tokens_guard.insert(issuer.to_string(), new_refresh_token.secret().to_string());
        }

        Ok(token_response.access_token().secret().to_string())
    }

    /// Builds the authentication state by initializing the OIDC client
    /// and token validator from the given configuration.
    ///
    /// Returns `AuthState` on success.
    pub async fn from_oidc_config(config: OIDCConfig) -> Result<AuthState, OIDCError> {
        Self::from_oidc_configs(vec![config]).await
    }

    pub async fn from_oidc_configs(configs: Vec<OIDCConfig>) -> Result<Self, OIDCError> {
        //let (_client, validator) = OIDCClient::from_oidc_config(&config).await?;

        let clients = AuthClient::from_oidc_configs(&configs).await?;

        let clients = Arc::new(RwLock::new(clients));

        Ok(AuthState {
            client: clients,
            tokens: Arc::new(RwLock::new(HashMap::new())),
            hmac_secret: generate_hmac_secret(),
        })
    }

    /// a way to add OIDC providers after the server is already running.
    pub async fn extend_from_oidc_configs(
        &self,
        configs: Vec<OIDCConfig>,
    ) -> Result<(), OIDCError> {
        let new_clients = AuthClient::from_oidc_configs(&configs).await?;
        self.client.write().await.extend(new_clients);
        Ok(())
    }
}
