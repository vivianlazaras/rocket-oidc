#[macro_use]
extern crate rocket;
pub mod routes;

use std::collections::HashSet;

use jsonwebtoken::*;
use openidconnect::core::*;
use openidconnect::core::CoreGenderClaim;

use rocket::{
    http::Status,
    request::{FromRequest, Outcome},
    Request
};

use openidconnect::reqwest;
use openidconnect::AdditionalClaims;
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

pub struct Config {
    
}

#[derive(Clone)]
pub struct AuthState {
    client: OpenIDClient,
    public_key: DecodingKey,
    validation: Validation,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeycloakClaim {
    groups: Vec<String>,
}

impl AdditionalClaims for KeycloakClaim {}

/// list of claims
#[derive(Debug, Deserialize, Serialize)]
pub struct OIDCGuard {
    pub exp: usize,
    pub aud: Vec<String>,
    pub sub: String,
    // Include other claims you care about here
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for OIDCGuard {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let cookies = req.cookies();
        let auth = req.rocket().state::<AuthState>().unwrap().clone();

        if let Some(access_token) = cookies.get("access_token") {
            let token_data =
                decode::<OIDCGuard>(access_token.value(), &auth.public_key, &auth.validation);

            match token_data {
                Ok(data) => Outcome::Success(data.claims),
                Err(err) => {
                    eprintln!(
                        "Token validation failed: {}, {:?}, {}",
                        err,
                        auth.validation,
                        access_token.value()
                    );
                    Outcome::Forward(Status::Forbidden)
                }
            }
        } else {
            Outcome::Forward(Status::Unauthorized)
        }
    }
}

pub async fn keycloak_oidc_auth(client_id: String, client_secret: String, issuer_url: String) -> Result<AuthState, Box<dyn std::error::Error>> {

    let client_id = ClientId::new(
        client_id
    );
    let client_secret = ClientSecret::new(
        client_secret
    );
    let issuer_url = IssuerUrl::new(issuer_url)?;

    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_err| {
            unreachable!();
        });

    // Fetch GitLab's OpenID Connect discovery document.
    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url.clone(), &http_client)
        .await
        .unwrap_or_else(|_err| {
            unreachable!();
        });

    let jwks_uri = provider_metadata.jwks_uri().to_string();
    
    // Fetch JSON Web Key Set (JWKS) from the provider
    let jwks: serde_json::Value = serde_json::from_str(&reqwest::get(jwks_uri).await.unwrap().text().await.unwrap()).unwrap();
    
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

    let mut jwtkeys = jwks["keys"].as_array().unwrap().iter().filter(|v| v["alg"] == "RS256").collect::<Vec<&serde_json::Value>>();
    println!("keys: {:?}", jwtkeys);
    let jwk = jwtkeys.pop().unwrap();
    // Public key from the JWKS
    let public_key = DecodingKey::from_rsa_components(
        jwk["n"].as_str().unwrap(),
        jwk["e"].as_str().unwrap(),
    ).unwrap();
    // Set up the config for the GitLab OAuth2 process.
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        client_id,
        Some(client_secret),
    )
    // This example will be running its own server at localhost:8080.
    // See below for the server implementation.
    .set_redirect_uri(
        RedirectUrl::new("http://qrespite.org:8000/callback/".to_string()).unwrap_or_else(|_err| {
            unreachable!();
        }),
    );

    Ok(AuthState { client, public_key, validation })
}

fn hashset_from<T: std::cmp::Eq + std::hash::Hash>(vals: Vec<T>) -> HashSet<T> {
    let mut set = HashSet::new();
    for val in vals.into_iter() {
        set.insert(val);
    }
    set
}