#![allow(non_snake_case)]
#![allow(non_local_definitions)]
#![allow(unused_variables)]
/*!
```rust
use serde_derive::{Serialize, Deserialize};
use rocket::{catch, catchers, routes, launch, get};
use rocket::Build;
use rocket::State;
use rocket::fs::FileServer;
use rocket::response::{Redirect, content::RawHtml};
use rocket_oidc::{OIDCConfig, CoreClaims, OIDCGuard};

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserGuard {
    pub email: String,
    pub sub: String,
    pub picture: Option<String>,
    pub email_verified: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserClaims {
    guard: UserGuard,
    pub iss: String,
    pub aud: String,
    exp: i64,
    iat: i64,
}

impl CoreClaims for UserClaims {
    fn subject(&self) -> &str {
        self.guard.sub.as_str()
    }

    fn issuer(&self) -> &str {
        self.iss.as_str()
    }

    fn audience(&self) -> &str {
        self.aud.as_str()
    }

    fn issued_at(&self) -> i64 {
        self.iat
    }

    fn expiration(&self) -> i64 {
        self.exp
    }
}

pub type Guard = OIDCGuard<UserClaims>;

#[catch(401)]
fn unauthorized() -> Redirect {
    Redirect::to("/")
}

#[get("/")]
async fn index() -> RawHtml<String> {
    RawHtml(format!("<h1>Hello World</h1>"))
}

#[get("/protected")]
async fn protected(guard: Guard) -> RawHtml<String> {
    let userinfo = guard.userinfo;
    RawHtml(format!("<h1>Hello {} {}</h1>", userinfo.given_name(), userinfo.family_name()))
}

#[launch]
async fn rocket() -> rocket::Rocket<Build> {
    let mut rocket = rocket::build()
        .mount("/", routes![index])
        .register("/", catchers![unauthorized]);
    let config = OIDCConfig::from_env().unwrap();
    rocket_oidc::setup(rocket, config)
        .await
        .unwrap()
}
```
## Auth Only
you can use an AuthGuard<Claims> type which only validates the claims in the json web token and doesn't rely on a full OIDC implementation
```rust
use rocket_oidc::OIDCConfig;
use rocket::{catchers, routes, catch, launch, get};
use jsonwebtoken::DecodingKey;

#[get("/")]
async fn index() -> &'static str {
    "Hello, world!"
}

#[catch(401)]
fn unauthorized() -> &'static str {
    "Unauthorized"
}

#[launch]
async fn rocket() -> rocket::Rocket<rocket::Build> {
    let config = OIDCConfig::from_env().unwrap();
    let decoding_key: DecodingKey = DecodingKey::from_rsa_pem(include_str!("public.pem").as_bytes()).ok().unwrap();

        let validator = rocket_oidc::client::Validator::from_pubkey(
            config.issuer_url.to_string(),
            "storyteller".to_string(),
            "RS256".to_string(),
            decoding_key,
        )
        .unwrap();
    let mut rocket = rocket::build()
        .mount("/", routes![index])
        .manage(validator)
        .register("/", catchers![unauthorized]);

    rocket
}
```
*/
#[macro_use]
extern crate rocket;

use std::fmt::Debug;
pub mod auth;
pub mod client;
pub mod errors;
pub mod routes;
#[cfg(feature = "server")]
pub mod server;
#[cfg(not(feature = "server"))]
pub mod sign;
pub mod utils;

use errors::{OIDCError, UserInfoErr};
/// Utilities for acting as an OIDC token signer.
#[cfg(feature = "server")]
pub use server::sign;
pub mod token;

use crate::client::WorkingConfig;
use crate::client::WorkingSessionConfig;
use crate::client::{IssuerData, KeyID};
use client::{OIDCClient, Validator};
use rocket::http::Cookie;
use rocket::response::Redirect;
use rocket::{
    Build, Request, Rocket,
    http::Status,
    request::{FromRequest, Outcome},
};
use serde::de::DeserializeOwned;
use serde_json::{Map, Number, Value};
use std::collections::HashMap;
use std::collections::HashSet;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use time::Duration;
use time::OffsetDateTime;
use tokio::sync::RwLock;
use utils::*;
use uuid::Uuid;

use openidconnect::AdditionalClaims;
use openidconnect::*;
use rocket::http::CookieJar;
use rocket::http::SameSite;
use serde::{Deserialize, Serialize};

/// Sets an i64 value on a serde_json::Value object by key.
/// If the Value is not already an object, it will be replaced with an empty object first.
pub fn set_i64(value: &mut Value, key: &str, val: i64) {
    // Ensure the Value is an object
    if !value.is_object() {
        *value = Value::Object(Map::new());
    }

    if let Value::Object(map) = value {
        map.insert(key.to_string(), Value::Number(val.into()));
    }
}

/// Sets a string value on a serde_json::Value object by key.
/// If the Value is not already an object, it will be replaced with an empty object first.
pub fn set_str(value: &mut Value, key: &str, val: &str) {
    // Ensure the Value is an object
    if !value.is_object() {
        *value = Value::Object(Map::new());
    }

    if let Value::Object(map) = value {
        map.insert(key.to_string(), Value::String(val.to_string()));
    }
}

pub fn get_i64(value: &Value, key: &str) -> Result<i64, OIDCError> {
    Ok(value
        .get("exp")
        .map(|v| v.as_i64())
        .flatten()
        .ok_or(OIDCError::MissingClaims("exp".to_string()))?)
}

pub(crate) fn sign_session_token(
    claims: &Value,
    session: &WorkingSessionConfig,
) -> Result<(String, OffsetDateTime), OIDCError> {
    let mut new_claims = claims.clone();
    let now = OffsetDateTime::now_utc();
    let new_exp = now + Duration::seconds(session.expiration_seconds as i64);
    let new_iss = &session.issuer_url;
    let new_sid = Uuid::new_v4().to_string();
    // sets a new expiration based off of iat
    set_i64(&mut new_claims, "exp", new_exp.unix_timestamp());
    // sets the new iat claim (initiated at)
    set_i64(&mut new_claims, "iat", now.unix_timestamp());
    // sets the issuer to self
    set_str(&mut new_claims, "iss", new_iss);
    // sets a new session ID
    set_str(&mut new_claims, "sid", &new_sid);
    let token = session.signing_key().sign(&new_claims)?;
    Ok((token, new_exp))
}

/// Holds the authentication state used by the application.
///
/// Contains:
/// - The OIDC token validator.
/// - The OpenID Connect client for user info requests.
/// - The static OIDC configuration.
#[derive(Clone)]
pub struct AuthState {
    pub validator: Validator,
    pub client: OIDCClient,
    pub config: WorkingConfig,
    // a collection of refresh tokens identified by iss
    pub tokens: Arc<RwLock<HashMap<String, String>>>,
}

impl AuthState {
    pub async fn handle_callback(
        &self,
        jar: &CookieJar<'_>,
        code: String,
        issuer: String,
    ) -> Result<Redirect, OIDCError> {
        // ── 1. Short-circuit if valid access_token exists
        if let Some(cookie) = jar.get_private("access_token") {
            let (_, expired) = check_expiration(&cookie);
            if !expired {
                return Ok(Redirect::to(self.config.post_login().to_string()));
            }
        }

        let iss = match self.config.session_config() {
            Some(session) => &session.issuer_url,
            None => &issuer,
        };

        // ── 2. Exchange authorization code for tokens
        let token_response = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .await?;

        // ── 3. Store the refresh token in self.tokens
        if let Some(refresh_token) = token_response.refresh_token() {
            let mut tokens_guard = self.tokens.write().await;
            tokens_guard.insert(iss.clone(), refresh_token.secret().to_string());
        }

        // ── 4. Determine expiration of access token
        let expires_at = match token_response.expires_in() {
            Some(expires_in) => OffsetDateTime::now_utc() + expires_in,
            None => {
                let token_data = self
                    .validator
                    .decode::<Value>(token_response.access_token().secret())?;

                OffsetDateTime::from_unix_timestamp(get_i64(&token_data.claims, "exp")?)
                    .unwrap_or_else(|_| OffsetDateTime::now_utc())
            }
        };

        // ── 5. Select algorithm for issuer
        let supported_algs = self
            .validator
            .get_supported_algorithms_for_issuer(&iss)
            .ok_or(OIDCError::MissingIssuerUrl)?;

        let chosen_alg = if supported_algs.iter().any(|a| a == "RS256") {
            "RS256".to_string()
        } else {
            supported_algs
                .first()
                .cloned()
                .ok_or(OIDCError::MissingAlgoForIssuer(iss.clone()))?
        };

        // ── 7. Finalize login
        let redirect = self.config.post_login().to_string();
        crate::login(
            redirect.clone(),
            jar,
            token_response.access_token().secret().to_string(),
            &iss,
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
            .client
            .exchange_refresh_token(&refresh_token)
            .await?;

        // Update stored refresh token if rotated
        if let Some(new_refresh_token) = token_response.refresh_token() {
            let mut tokens_guard = self.tokens.write().await;
            tokens_guard.insert(issuer.to_string(), new_refresh_token.secret().to_string());
        }

        Ok(token_response.access_token().secret().to_string())
    }
}
/// Represents a localized claim value, such as a name or address
/// that may have an associated language.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalizedClaim {
    language: Option<String>,
    value: String,
}

/// Basic user profile information returned from the userinfo endpoint.
///
/// This includes names, locale, picture URL, and optional fields like address or gender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    address: Option<String>,
    family_name: String,
    given_name: String,
    gender: Option<String>,
    picture: String,
    locale: Option<String>,
}

impl UserInfo {
    pub fn family_name(&self) -> &str {
        &self.family_name
    }

    pub fn given_name(&self) -> &str {
        &self.given_name
    }
}

/// Guard type used in Rocket request handling that holds validated JWT claims
/// and fetched user info.
///
/// Generic over claim type `T` which must implement `CoreClaims`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "T: Serialize + DeserializeOwned")]
pub struct OIDCGuard<T: CoreClaims>
where
    T: Serialize + DeserializeOwned + Debug + Clone,
{
    pub claims: T,
    pub userinfo: Option<UserInfo>,
    pub access_token: String,
    // Include other claims you care about here
}

impl<T: CoreClaims + Serialize + DeserializeOwned + Debug + Clone> OIDCGuard<T> {
    pub fn access_token(&self) -> &str {
        &self.access_token
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaseClaims {
    exp: i64,
    sub: String,
    #[serde(deserialize_with = "string_or_vec")]
    iss: Vec<String>,
    #[serde(deserialize_with = "string_or_vec")]
    aud: Vec<String>,
    iat: i64,
}

impl CoreClaims for BaseClaims {
    fn subject(&self) -> &str {
        &self.sub
    }

    fn issuer(&self) -> Vec<String> {
        self.iss.clone()
    }

    fn audience(&self) -> Vec<String> {
        self.aud.clone()
    }

    fn issued_at(&self) -> i64 {
        self.iat
    }

    fn exp(&self) -> i64 {
        self.exp
    }
}

/// Trait for extracting the subject identifier from any set of claims.
/// this is also used as a marker trait
pub trait CoreClaims: Clone {
    fn subject(&self) -> &str;
    fn issuer(&self) -> Vec<String>;
    fn audience(&self) -> Vec<String>;
    fn issued_at(&self) -> i64;
    fn exp(&self) -> i64;
}

/// this impl intentionally leaks memory and should thus only ever be used for testing
impl CoreClaims for Value {
    fn subject(&self) -> &str {
        self.get("sub").and_then(Value::as_str).unwrap_or("")
    }

    fn issuer(&self) -> Vec<String> {
        match self.get("iss") {
            Some(val) => value_to_str_slice(val),
            None => Vec::new(),
        }
    }

    fn audience(&self) -> Vec<String> {
        match self.get("aud") {
            Some(val) => value_to_str_slice(val),
            None => Vec::new(),
        }
    }

    fn issued_at(&self) -> i64 {
        self.get("iat").and_then(Value::as_i64).unwrap_or(0)
    }

    fn exp(&self) -> i64 {
        self.get("exp").and_then(Value::as_i64).unwrap_or(3600)
    }
}

impl<AC: AdditionalClaims, GC: GenderClaim> TryFrom<UserInfoClaims<AC, GC>> for UserInfo {
    type Error = UserInfoErr;
    fn try_from(info: UserInfoClaims<AC, GC>) -> Result<UserInfo, Self::Error> {
        let locale = info.locale();
        let given_name = match info.given_name() {
            Some(given_name) => match given_name.get(locale) {
                Some(name) => name.as_str().to_string(),
                None => return Err(UserInfoErr::MissingGivenName),
            },
            None => return Err(UserInfoErr::MissingGivenName),
        };
        let family_name = match info.family_name() {
            Some(family_name) => match family_name.get(locale) {
                Some(name) => name.as_str().to_string(),
                None => return Err(UserInfoErr::MissingFamilyName),
            },
            None => return Err(UserInfoErr::MissingFamilyName),
        };
        let picture = match info.given_name() {
            Some(picture) => match picture.get(locale) {
                Some(pic) => pic.as_str().to_string(),
                None => return Err(UserInfoErr::MissingPicture),
            },
            None => return Err(UserInfoErr::MissingPicture),
        };
        Ok(UserInfo {
            address: None,
            gender: None,
            locale: locale.map_or_else(|| None, |v| Some(v.as_str().to_string())),
            given_name,
            family_name,
            picture,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddClaims {}
impl AdditionalClaims for AddClaims {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PronounClaim {}

impl GenderClaim for PronounClaim {}

/*
#[rocket::async_trait]
impl<'r, T: Serialize + Debug + DeserializeOwned + std::marker::Send + CoreClaims> FromRequest<'r>
    for OIDCGuard<T>
{
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let cookies = req.cookies();
        let auth = req.rocket().state::<AuthState>().unwrap().clone();

        if let Some(access_token) = cookies.get_private("access_token") {
            let token_result = if let Some(issuer_cookie) = cookies.get_private("issuer_data") {
                // Parse issuer_data JSON
                match serde_json::from_str::<IssuerData>(issuer_cookie.value()) {
                    Ok(issuer_data) => auth.validator.decode_with_iss_alg::<T>(
                        &issuer_data.issuer,
                        &issuer_data.algorithm,
                        access_token.value(),
                    ),
                    Err(err) => {
                        eprintln!("Failed to parse issuer_data cookie: {:?}", err);
                        cookies.remove(Cookie::build("access_token"));
                        return Outcome::Forward(Status::Unauthorized);
                    }
                }
            } else {
                // Fall back to default decode
                auth.validator.decode::<T>(access_token.value())
            };

            match token_result {
                Ok(data) => {
                    // Try to fetch userinfo claims from userinfo endpoint
                    let userinfo_result: Result<UserInfoClaims<AddClaims, PronounClaim>, _> = auth
                        .client
                        .user_info(
                            AccessToken::new(access_token.value().to_string()),
                            Some(SubjectIdentifier::new(data.claims.subject().to_string())),
                        )
                        .await;

                    match userinfo_result {
                        Ok(userinfo) => Outcome::Success(OIDCGuard {
                            claims: data.claims,
                            userinfo: UserInfo::try_from(userinfo).unwrap(),
                        }),
                        Err(e) => {
                            eprintln!("Failed to fetch userinfo: {:?}", e);
                            Outcome::Forward(Status::Unauthorized)
                        }
                    }
                }
                Err(err) => {
                    eprintln!("Token decode failed: {:?}", err);
                    cookies.remove(Cookie::build("access_token"));
                    Outcome::Forward(Status::Unauthorized)
                }
            }
        } else {
            eprintln!("No access token found");
            Outcome::Forward(Status::Unauthorized)
        }
    }
}*/

#[rocket::async_trait]
impl<'r, T: Serialize + Debug + DeserializeOwned + std::marker::Send + CoreClaims> FromRequest<'r>
    for OIDCGuard<T>
{
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let cookies = req.cookies();
        let auth = req.rocket().state::<AuthState>().unwrap().clone();

        // Extract issuer information
        let issuer_data: Option<IssuerData> = cookies
            .get_private("issuer_data")
            .and_then(|c| serde_json::from_str(c.value()).ok());

        let issuer = match &issuer_data {
            Some(data) => &data.issuer,
            None => {
                eprintln!("No issuer_data cookie");
                return Outcome::Forward(Status::Unauthorized);
            }
        };

        let alg = match &issuer_data {
            Some(data) => &data.algorithm,
            None => {
                eprintln!("No issuer_data cookie");
                return Outcome::Forward(Status::Unauthorized);
            }
        };

        // Attempt to read access token from cookies
        let mut access_token_value = cookies
            .get_private("access_token")
            .map(|c| c.value().to_string());

        // Check expiration if token exists
        let token_needs_refresh = if let Some(ref token_val) = access_token_value {
            match auth.validator.decode_with_iss_alg::<T>(
                issuer,
                &issuer_data.as_ref().unwrap().algorithm,
                token_val,
            ) {
                Ok(data) => {
                    let exp = OffsetDateTime::from_unix_timestamp(data
                        .claims.exp()).unwrap_or(OffsetDateTime::now_utc());
                    exp <= OffsetDateTime::now_utc()
                }
                Err(_) => true,
            }
        } else {
            true
        };

        if !token_needs_refresh {
            let claims = match auth.validator.decode_with_iss_alg(
                issuer,
                alg,
                access_token_value.as_ref().unwrap(),
            ) {
                Ok(claims) => claims,
                Err(e) => {
                    eprintln!("failed to decode claims: {e}");
                    return Outcome::Forward(Status::Unauthorized);
                }
            };
            return Outcome::Success(OIDCGuard {
                claims: claims.claims,
                access_token: access_token_value.unwrap(),
                userinfo: None,
            });
        }

        // Get stored refresh token for this issuer
        let refresh_token_str = {
            let tokens_guard = auth.tokens.read().await;
            tokens_guard.get(issuer).cloned()
        };

        let refresh_token_str = match refresh_token_str {
            Some(t) => t,
            None => {
                eprintln!("No refresh token stored for issuer: {}", issuer);
                return Outcome::Forward(Status::Unauthorized);
            }
        };

        let refresh_token = RefreshToken::new(refresh_token_str.clone());

        // Refresh access token if needed
        if token_needs_refresh {
            /*let try_refresh = match auth.client.exchange_refresh_token(&refresh_token).await {
                Ok(val) => val,
                Err(e) => {
                    eprintln!("failed to refresh token {e}");
                    return Outcome::Forward(Status::Unauthorized);
                }
            };*/
            match auth.client.exchange_refresh_token(&refresh_token).await
            {
                Ok(new_token) => {
                    // Update refresh token if rotated
                    if let Some(new_refresh) = new_token.refresh_token() {
                        let mut tokens_guard = auth.tokens.write().await;
                        tokens_guard.insert(issuer.clone(), new_refresh.secret().to_string());
                    }
                    access_token_value = Some(new_token.access_token().secret().to_string());
                    // Update cookie
                    cookies.add_private(
                        Cookie::build(("access_token", access_token_value.clone().unwrap()))
                            .http_only(true)
                            .finish(),
                    );
                }
                Err(err) => {
                    eprintln!("Failed to refresh access token: {:?}", err);
                    return Outcome::Forward(Status::Unauthorized);
                }
            }
        }

        // Decode access token now
        let access_token_val = access_token_value.unwrap();
        let claims = match auth.validator.decode_with_iss_alg::<T>(
            issuer,
            &issuer_data.as_ref().unwrap().algorithm,
            &access_token_val,
        ) {
            Ok(data) => data.claims,
            Err(err) => {
                eprintln!("Token decode failed: {:?}", err);
                return Outcome::Forward(Status::Unauthorized);
            }
        };

        // Optionally fetch userinfo
        let userinfo = match auth
            .client
            .user_info(
                AccessToken::new(access_token_val.clone()),
                None::<SubjectIdentifier>,
            )
            .await
        {
            Ok(info) => Some(UserInfo::try_from(info).unwrap()),
            Err(err) => {
                eprintln!("Failed to fetch userinfo: {:?}", err);
                None
            }
        };

        Outcome::Success(OIDCGuard {
            claims,
            userinfo,
            access_token: access_token_val,
        })
    }
}

/// Builds the authentication state by initializing the OIDC client
/// and token validator from the given configuration.
///
/// Returns `AuthState` on success.
pub async fn from_provider_oidc_config(
    config: OIDCConfig,
) -> Result<AuthState, Box<dyn std::error::Error>> {
    let (client, validator) = OIDCClient::from_oidc_config(&config).await?;

    Ok(AuthState {
        client,
        validator,
        config: (&config).try_into()?,
        tokens: Arc::new(RwLock::new(HashMap::new())),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SessionConfig {
    pub signing_key_path: PathBuf,
    pub issuer_url: String,
    pub expiration_seconds: Option<u64>,
}

impl SessionConfig {
    pub fn from_env() -> Option<Self> {
        let signing_key_path = match env::var("SESSION_SIGNING_KEY") {
            Ok(path) => PathBuf::from(path),
            _ => return None,
        };

        let issuer_url = match env::var("SESSION_ISSUER_URL") {
            Ok(url) => url,
            _ => return None,
        };

        let expiration_seconds = match env::var("SESSION_EXPIRATION_SECONDS") {
            Ok(seconds_str) => match seconds_str.parse::<u64>() {
                Ok(seconds) => Some(seconds),
                _ => None,
            },
            _ => None,
        };

        Some(Self {
            signing_key_path,
            issuer_url,
            expiration_seconds,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OIDCConfig {
    pub client_id: String,
    pub client_secret: PathBuf,
    pub issuer_url: String,
    pub redirect: String,
    pub post_login: Option<String>,
    pub session: Option<SessionConfig>,
}

/// please note this is just an example, and should not be used in production builds
/// rather `from_env` should be used instead.
impl Default for OIDCConfig {
    fn default() -> OIDCConfig {
        Self {
            client_id: "storyteller".to_string(),
            client_secret: "./secret".into(),
            issuer_url: "http://keycloak.com/realms/master".to_string(),
            redirect: "http://localhost:8000/".to_string(),
            post_login: None,
            session: None,
        }
    }
}

/// Represents configuration parameters for OpenID Connect authentication.
///
/// Typically loaded from environment variables at runtime.
impl OIDCConfig {
    /// Returns the URL to redirect to after login has completed.
    ///
    /// If `post_login` is set, returns its value; otherwise defaults to `/`.
    pub fn post_login(&self) -> &str {
        match &self.post_login {
            Some(url) => &url,
            None => "/",
        }
    }

    /// Constructs an `OIDCConfig` from environment variables.
    ///
    /// Required variables:
    /// - `CLIENT_ID`: The OAuth2 client identifier.
    /// - `CLIENT_SECRET`: The OAuth2 client secret.
    /// - `ISSUER_URL`: The base URL of the OpenID Connect issuer.
    ///
    /// Optional variable:
    /// - `REDIRECT_URL`: Redirect URI after login (defaults to `/profile` if unset).
    ///
    /// Returns an error if any required variable is missing.
    pub fn from_env() -> Result<Self, OIDCError> {
        let client_id = match env::var("CLIENT_ID") {
            Ok(client_id) => client_id,
            _ => return Err(OIDCError::MissingClientId),
        };
        let client_secret = match env::var("CLIENT_SECRET") {
            Ok(secret) => secret.into(),
            _ => return Err(OIDCError::MissingClientSecret),
        };
        let issuer_url = match env::var("ISSUER_URL") {
            Ok(url) => url,
            _ => return Err(OIDCError::MissingIssuerUrl),
        };

        let redirect = match env::var("REDIRECT_URL") {
            Ok(redirect) => redirect,
            _ => String::from("/profile"),
        };

        let session_signing_key = match env::var("SESSION_SIGNING_KEY") {
            Ok(path) => Some(PathBuf::from(path)),
            _ => None,
        };

        let session_issuer_url = match env::var("SESSION_ISSUER_URL") {
            Ok(url) => Some(url),
            _ => None,
        };

        Ok(Self {
            client_id,
            client_secret,
            issuer_url,
            redirect,
            post_login: None,
            session: SessionConfig::from_env(),
        })
    }
}

/// Initializes the Rocket application with OpenID Connect authentication support.
///
/// This function:
/// - Loads OIDC configuration from the given `config`.
/// - Calls `from_provider_oidc_config` to build the authentication state.
/// - Registers authentication-related routes under the `/auth` path.
/// - Attaches the authentication state as managed state in Rocket.
///
/// Returns the updated Rocket instance, or an error if the setup failed.
pub async fn setup(
    rocket: rocket::Rocket<Build>,
    config: OIDCConfig,
) -> Result<Rocket<Build>, Box<dyn std::error::Error>> {
    let auth_state = from_provider_oidc_config(config).await?;
    if cfg!(debug_assertions) {
        println!("using validator: {:?}", auth_state.validator);
    }
    Ok(rocket
        .manage(auth_state.validator.clone())
        .manage(auth_state)
        .mount("/auth", routes::get_routes()))
}

/// Stores authentication cookies in the user's browser after successful login.
///
/// This function:
/// - Adds an `access_token` cookie (HTTP-only).
/// - Serializes `IssuerData` containing the issuer URL and algorithm,
///   and adds it as an `issuer_data` cookie (optionally readable by JavaScript).
///
/// # Parameters
/// - `jar`: The Rocket cookie jar.
/// - `access_token`: The signed JSON Web Token received after login.
/// - `issuer`: The issuer URL (e.g., `http://localhost:8442`).
/// - `algorithm`: The signing algorithm (e.g., `RS256`).
/// - `expiration`: An optional expiration specification, if none provided this method uses 1 hour
///
/// Returns `Ok(Redirect)` on success, or an error if JSON serialization fails.
pub fn login(
    redirect: String,
    jar: &CookieJar<'_>,
    access_token: String,
    issuer: &str,
    algorithm: &str,
    expiration: Option<OffsetDateTime>,
) -> Result<Redirect, OIDCError> {
    let expires = match expiration {
        Some(expires) => expires,
        None => OffsetDateTime::now_utc()
            .checked_add(Duration::new(3600, 0))
            .expect("failed to add 1 hour"),
    };
    // Add the access_token cookie
    jar.add_private(
        Cookie::build(("access_token", access_token.clone()))
            .secure(false)
            .expires(expires)
            .http_only(true)
            .same_site(SameSite::Lax),
    );

    // Build issuer_data JSON
    let issuer_data = IssuerData {
        issuer: issuer.to_string(),
        algorithm: algorithm.to_string(),
    };

    let issuer_data_json = serde_json::to_string(&issuer_data)?;

    // Add issuer_data cookie
    jar.add_private(
        Cookie::build(("issuer_data", issuer_data_json))
            .secure(false)
            .http_only(false) // if you don't want JS access, set to true
            .same_site(SameSite::Lax),
    );

    // Check for request_id cookie
    let redirect_url = if let Some(cookie) = jar.get("request_id") {
        let request_id = cookie.value();
        format!(
            "{}?state={}&access_token={}",
            redirect, request_id, &access_token
        )
    } else {
        format!("{}?access_token={}", redirect, &access_token)
    };

    Ok(Redirect::to(redirect_url))
}
