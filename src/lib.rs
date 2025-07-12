#![allow(non_snake_case)]
#![allow(non_local_definitions)]
#![allow(unused_variables)]
/*!
```rust
use serde_derive::{Serialize, Deserialize};
use rocket::{catch, catchers, routes, launch, get};

use rocket::State;
use rocket::fs::FileServer;
use rocket::response::{Redirect, content::RawHtml};
use rocket_oidc::{OIDCConfig, CoreClaims, OIDCGuard};

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug)]
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
async fn rocket() -> _ {
    let mut rocket = rocket::build()
        .mount("/", routes![index])
        .register("/", catchers![unauthorized]);

    rocket_oidc::setup(rocket, config.oidc().clone())
        .await
        .unwrap()
}
```
## Auth Only
you can use an AuthGuard<Claims> type which only validates the claims in the json web token and doesn't rely on a full OIDC implementation
```
#[launch]
async fn rocket() -> _ {
    let decoding_key = api.get_jwt_pubkey().await.unwrap();
        let validator = rocket_oidc::client::Validator::from_pubkey(
            config.api_endpoint().to_string(),
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
pub mod token;
use crate::client::{IssuerData, KeyID};
use client::{OIDCClient, Validator};
use rocket::http::ContentType;
use rocket::http::Cookie;
use rocket::response;
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
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct AuthState {
    pub validator: Validator,
    pub client: OIDCClient,
    pub config: OIDCConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalizedClaim {
    language: Option<String>,
    value: String,
}

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
    aud: String,
    sub: String,
}

impl CoreClaims for BaseClaims {
    fn subject(&self) -> &str {
        &self.sub
    }
}

pub trait CoreClaims {
    fn subject(&self) -> &str;
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

pub async fn from_keycloak_oidc_config(
    config: OIDCConfig,
) -> Result<AuthState, Box<dyn std::error::Error>> {
    let (client, validator) = OIDCClient::from_oidc_config(&config).await?;

    Ok(AuthState {
        client,
        validator,
        config,
    })
}

#[derive(Debug, Error, Responder)]
#[error(display = "encountered error during route handling: {}", _0)]
pub enum RouteError {
    #[error(display = "reqwest error: {}", _0)]
    #[response(status = 500)]
    Reqwest(String),
    #[error(display = "OIDC configuration error: {}", _0)]
    #[response(status = 500)]
    ConfigurationError(String),
}

pub type TokenErr = RequestTokenError<
    HttpClientError<reqwest::Error>,
    openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
>;

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
}

impl<'r> Responder<'r, 'static> for Error {
    fn respond_to(self, _request: &'r Request<'_>) -> response::Result<'static> {
        let body = self.to_string();
        let status = match &self {
            Error::MissingClientId | Error::MissingClientSecret | Error::MissingIssuerUrl => {
                Status::BadRequest
            }
            Error::Reqwest(_) | Error::ConfigurationError(_) => Status::InternalServerError,
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

impl OIDCConfig {
    pub fn post_login(&self) -> &str {
        match &self.post_login {
            Some(url) => &url,
            None => "/",
        }
    }
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

pub async fn setup(
    rocket: rocket::Rocket<Build>,
    config: OIDCConfig,
) -> Result<Rocket<Build>, Box<dyn std::error::Error>> {
    let auth_state = from_keycloak_oidc_config(config).await?;
    Ok(rocket
        .manage(auth_state)
        .mount("/auth", routes::get_routes()))
}

pub fn register_validator(
    rocket: rocket::Rocket<Build>,
    validator: crate::client::Validator,
) -> Rocket<Build> {
    rocket.manage(validator)
}
