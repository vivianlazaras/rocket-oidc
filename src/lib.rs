#![allow(non_snake_case)]
#![allow(non_local_definitions)]
#[macro_use]
extern crate rocket;
#[macro_use]
extern crate err_derive;

use std::fmt::Debug;
pub mod routes;

use jsonwebtoken::*;
use openidconnect::core::CoreGenderClaim;
use openidconnect::core::*;
use rocket::http::ContentType;
use rocket::response;
use rocket::response::Responder;
use rocket::{
    Build, Request, Rocket,
    http::Status,
    request::{FromRequest, Outcome},
};
use serde::de::DeserializeOwned;
use std::collections::HashSet;
use std::env;
use std::io::Cursor;

use openidconnect::AdditionalClaims;
use openidconnect::reqwest;
use openidconnect::*;
use serde::{Deserialize, Serialize};

type OpenIDClient<
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasAuthUrl = EndpointSet,
    HasTokenUrl = EndpointMaybeSet,
    HasUserInfoUrl = EndpointMaybeSet,
> = openidconnect::Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    CoreTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
    HasUserInfoUrl,
>;

pub struct Config {}

#[derive(Clone)]
pub struct AuthState {
    pub client: OpenIDClient,
    pub public_key: DecodingKey,
    pub validation: Validation,
    pub config: OIDCConfig,
    pub reqwest_client: reqwest::Client,
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

#[derive(Debug, Clone, Copy, Error)]
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
            let token_data = decode::<T>(access_token.value(), &auth.public_key, &auth.validation);

            match token_data {
                Ok(data) => {
                    let userinfo_result: Result<UserInfoClaims<AddClaims, PronounClaim>, _> = auth
                        .client
                        .user_info(
                            AccessToken::new(access_token.value().to_string()),
                            Some(SubjectIdentifier::new(data.claims.subject().to_string())),
                        )
                        .unwrap()
                        .request_async(&auth.reqwest_client)
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
                    let _ExpiredSignature = err;
                    {
                        cookies.remove("access_token");
                        Outcome::Forward(Status::Unauthorized)
                    }
                }
            }
        } else {
            Outcome::Forward(Status::Unauthorized)
        }
    }
}

pub async fn from_keycloak_oidc_config(
    config: OIDCConfig,
) -> Result<AuthState, Box<dyn std::error::Error>> {
    let client_id = config.client_id.clone();
    let client_secret = config.client_secret.clone();
    let issuer_url = config.issuer_url.clone();

    let client_id = ClientId::new(client_id);
    let client_secret = ClientSecret::new(client_secret);
    let issuer_url = IssuerUrl::new(issuer_url)?;

    let http_client = match reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => client,
        Err(e) => return Err(Box::new(e)),
    };

    // fetch discovery document
    let provider_metadata =
        match CoreProviderMetadata::discover_async(issuer_url.clone(), &http_client).await {
            Ok(provider_metadata) => provider_metadata,
            Err(e) => return Err(Box::new(e)),
        };

    let jwks_uri = provider_metadata.jwks_uri().to_string();

    // Fetch JSON Web Key Set (JWKS) from the provider
    let jwks: serde_json::Value =
        serde_json::from_str(&reqwest::get(jwks_uri).await.unwrap().text().await.unwrap()).unwrap();

    // Assuming you have the correct key in JWKS for verification
    //let jwk = &jwks["keys"][0]; // Adjust based on the actual structure of the JWKS

    // Decode and verify the JWT
    let mut validation = Validation::new(Algorithm::RS256);
    //validation.insecure_disable_signature_validation();
    {
        validation.leeway = 100; // Optionally, allow some leeway
        validation.validate_exp = true;
        validation.validate_aud = true;
        validation.validate_nbf = true;
        validation.aud = Some(hashset_from(vec!["account".to_string()])); // The audience should match your client ID
        validation.iss = Some(hashset_from(vec![issuer_url.to_string()])); // Validate the issuer
        validation.algorithms = vec![Algorithm::RS256];
    };

    let mut jwtkeys = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v["alg"] == "RS256")
        .collect::<Vec<&serde_json::Value>>();
    println!("keys: {:?}", jwtkeys);
    let jwk = jwtkeys.pop().unwrap();
    // Public key from the JWKS
    let public_key =
        DecodingKey::from_rsa_components(jwk["n"].as_str().unwrap(), jwk["e"].as_str().unwrap())
            .unwrap();
    // Set up the config for the GitLab OAuth2 process.
    let client =
        CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
            // This example will be running its own server at localhost:8080.
            // See below for the server implementation.
            .set_redirect_uri(
                RedirectUrl::new(format!("http://{}/auth/callback/", config.redirect))
                    .unwrap_or_else(|_err| {
                        unreachable!();
                    }),
            );

    Ok(AuthState {
        client,
        public_key,
        validation,
        config,
        reqwest_client: http_client,
    })
}

fn hashset_from<T: std::cmp::Eq + std::hash::Hash>(vals: Vec<T>) -> HashSet<T> {
    let mut set = HashSet::new();
    for val in vals.into_iter() {
        set.insert(val);
    }
    set
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
    #[error(display = "failed to fetch: {}", _0)]
    Reqwest(#[error(source)] reqwest::Error),
    #[error(display = "openidconnect configuration error: {}", _0)]
    ConfigurationError(#[error(source)] ConfigurationError),
    #[error(display = "token validation error: {}", _0)]
    TokenError(#[error(source)] TokenErr),
}

impl<'r> Responder<'r, 'static> for Error {
    fn respond_to(self, _request: &'r Request<'_>) -> response::Result<'static> {
        let body = self.to_string();
        let status = match &self {
            Error::MissingClientId | Error::MissingClientSecret | Error::MissingIssuerUrl => {
                Status::BadRequest
            }
            Error::Reqwest(_) | Error::ConfigurationError(_) => Status::InternalServerError,
            Error::TokenError(_) => Status::Unauthorized,
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
    pub client_secret: String,
    pub issuer_url: String,
    pub redirect: String,
}

impl OIDCConfig {
    pub fn from_env() -> Result<Self, Error> {
        let client_id = match env::var("CLIENT_ID") {
            Ok(client_id) => client_id,
            _ => return Err(Error::MissingClientId),
        };
        let client_secret = match env::var("CLIENT_SECRET") {
            Ok(secret) => secret,
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
