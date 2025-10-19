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

impl CoreClaims for UserGuard {
    fn subject(&self) -> &str {
        self.sub.as_str()
    }
}

pub type Guard = OIDCGuard<UserGuard>;

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
#[macro_use]
extern crate err_derive;

use std::fmt::Debug;
pub mod auth;
pub mod client;
pub mod routes;
/// Utilities for acting as an OIDC token signer.
pub mod sign;
pub mod token;
use crate::client::{IssuerData, KeyID};
use client::{OIDCClient, Validator};
use rocket::http::ContentType;
use rocket::http::Cookie;
use rocket::response;
use rocket::response::Redirect;
use rocket::response::Responder;
use rocket::{
    Build, Request, Rocket,
    http::Status,
    request::{FromRequest, Outcome},
};
use serde::de::DeserializeOwned;
use std::env;
use std::io::Cursor;
use std::path::PathBuf;

use openidconnect::AdditionalClaims;
use openidconnect::reqwest;
use openidconnect::*;
use rocket::http::CookieJar;
use rocket::http::SameSite;
use serde::{Deserialize, Serialize};

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
    pub config: OIDCConfig,
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

/// Errors that can occur when parsing or converting user info claims.
#[derive(Debug, Clone, Error)]
#[error(display = "failed to parse user info: ", _0)]
pub enum UserInfoErr {
    #[error(display = "missing given name")]
    MissingGivenName,
    #[error(display = "missing family name")]
    MissingFamilyName,
    #[error(display = "missing profile picture url")]
    MissingPicture,
}

/// Guard type used in Rocket request handling that holds validated JWT claims
/// and fetched user info.
///
/// Generic over claim type `T` which must implement `CoreClaims`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "T: Serialize + DeserializeOwned")]
pub struct OIDCGuard<T: CoreClaims>
where
    T: Serialize + DeserializeOwned + Debug,
{
    pub claims: T,
    pub userinfo: UserInfo,
    // Include other claims you care about here
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BaseClaims {
    exp: i64,
    sub: String,
}

impl CoreClaims for BaseClaims {
    fn subject(&self) -> &str {
        &self.sub
    }
}

/// Trait for extracting the subject identifier from any set of claims.
/// this is also used as a marker trait
pub trait CoreClaims: Clone {
    fn subject(&self) -> &str;
}

impl CoreClaims for serde_json::Value {
    fn subject(&self) -> &str {
        self.get("sub").and_then(|v| v.as_str()).unwrap_or_default()
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

#[rocket::async_trait]
impl<'r, T: Serialize + Debug + DeserializeOwned + std::marker::Send + CoreClaims> FromRequest<'r>
    for OIDCGuard<T>
{
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let cookies = req.cookies();
        let auth = req.rocket().state::<AuthState>().unwrap().clone();

        if let Some(access_token) = cookies.get("access_token") {
            let token_result = if let Some(issuer_cookie) = cookies.get("issuer_data") {
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
        config,
    })
}

pub type TokenErr = RequestTokenError<
    HttpClientError<reqwest::Error>,
    openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
>;

/// Top-level error type for the authentication layer.
///
/// Includes missing configuration, HTTP errors, token validation failures,
/// and JSON parsing issues.
#[derive(Debug, Error)]
#[error(display = "failed to start rocket OIDC routes: {}", _0)]
pub enum Error {
    #[error(display = "missing client id")]
    MissingClientId,
    #[error(display = "missing client secret")]
    MissingClientSecret,
    #[error(display = "missing issuer url")]
    MissingIssuerUrl,
    #[error(display = "missing algorithim for issuer")]
    MissingAlgoForIssuer(String),
    #[error(display = "failed to fetch: {}", _0)]
    Reqwest(#[error(source)] reqwest::Error),
    #[error(display = "openidconnect configuration error: {}", _0)]
    ConfigurationError(#[error(source)] ConfigurationError),
    #[error(display = "token validation error: {}", _0)]
    TokenError(#[error(source)] TokenErr),
    #[error(display = "pubkey not found when trying to decode access token")]
    PubKeyNotFound(KeyID),
    #[error(display = "failed to parse json web key: {}", _0)]
    JsonWebToken(#[source] jsonwebtoken::errors::Error),
    #[error(display = "failed to parse or serialize json: {}", _0)]
    JsonErr(serde_json::Error),
}

impl<'r> Responder<'r, 'static> for Error {
    fn respond_to(self, _request: &'r Request<'_>) -> response::Result<'static> {
        let body = self.to_string();
        let status = match &self {
            Error::MissingClientId | Error::MissingClientSecret | Error::MissingIssuerUrl => {
                Status::BadRequest
            }
            Error::Reqwest(_) | Error::ConfigurationError(_) | Error::JsonErr(_) => {
                Status::InternalServerError
            }
            Error::TokenError(_) | Error::MissingAlgoForIssuer(_) => Status::Unauthorized,
            Error::PubKeyNotFound(_) | Error::JsonWebToken(_) => Status::Unauthorized,
        };

        response::Response::build()
            .status(status)
            .header(ContentType::Plain)
            .sized_body(body.len(), Cursor::new(body))
            .ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OIDCConfig {
    pub client_id: String,
    pub client_secret: PathBuf,
    pub issuer_url: String,
    pub redirect: String,
    pub post_login: Option<String>,
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
    pub fn from_env() -> Result<Self, Error> {
        let client_id = match env::var("CLIENT_ID") {
            Ok(client_id) => client_id,
            _ => return Err(Error::MissingClientId),
        };
        let client_secret = match env::var("CLIENT_SECRET") {
            Ok(secret) => secret.into(),
            _ => return Err(Error::MissingClientSecret),
        };
        let issuer_url = match env::var("ISSUER_URL") {
            Ok(url) => url,
            _ => return Err(Error::MissingIssuerUrl),
        };

        let redirect = match env::var("REDIRECT_URL") {
            Ok(redirect) => redirect,
            _ => String::from("/profile"),
        };

        Ok(Self {
            client_id,
            client_secret,
            issuer_url,
            redirect,
            post_login: None,
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
    Ok(rocket
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
///
/// Returns `Ok(Redirect)` on success, or an error if JSON serialization fails.
pub fn login(
    redirect: String,
    jar: &CookieJar<'_>,
    access_token: String,
    issuer: &str,
    algorithm: &str,
) -> Result<Redirect, crate::Error> {
    // Add the access_token cookie
    jar.add(
        Cookie::build(("access_token", access_token))
            .secure(false)
            .http_only(true)
            .same_site(SameSite::Lax),
    );

    // Build issuer_data JSON
    let issuer_data = IssuerData {
        issuer: issuer.to_string(),
        algorithm: algorithm.to_string(),
    };

    let issuer_data_json = serde_json::to_string(&issuer_data).map_err(crate::Error::JsonErr)?;

    // Add issuer_data cookie
    jar.add(
        Cookie::build(("issuer_data", issuer_data_json))
            .secure(false)
            .http_only(false) // if you don't want JS access, set to true
            .same_site(SameSite::Lax),
    );

    // Check for request_id cookie
    let redirect_url = if let Some(cookie) = jar.get("request_id") {
        let request_id = cookie.value();
        format!("{}?state={}", redirect, request_id)
    } else {
        redirect
    };

    Ok(Redirect::to(redirect_url))
}
