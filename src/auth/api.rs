//! This module is intended to provide utilities for parsing OIDC tokens from Authorization: Bearer headers
use super::*;
use serde::{Serialize, de::DeserializeOwned};
use std::fmt::Debug;

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
            eprintln!("failed to fetch validator {e}");
            return Outcome::Forward(Status::Unauthorized);
        }
    };
    match validator.decode_with_iss_alg::<T>(&idclaims.iss, &idclaims.alg, &api_key) {
        Ok(data) => Outcome::Success(ApiKeyGuard {
            claims: data.claims,
            access_token: api_key.to_string(),
        }),
        Err(err) => {
            eprintln!("API key invalid with iss/alg: {}", err);
            Outcome::Forward(Status::Unauthorized)
        }
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
