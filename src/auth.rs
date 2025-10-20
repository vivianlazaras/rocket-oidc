//! This module provides `AuthGuard` which doesn't request user info, but simply validates server public key
//! this is useful for implementing local only login systems that don't rely on full OIDC support from the authorization server

use crate::CoreClaims;
use crate::client::IssuerData;
use rocket::Request;
use rocket::http::{Cookie, Status};
use rocket::request::{FromRequest, Outcome};
use serde::{Serialize, de::DeserializeOwned};
use std::fmt::Debug;

#[derive(Debug, Clone)]
pub struct AuthGuard<T: Serialize + DeserializeOwned + Debug> {
    pub claims: T,
    access_token: String,
}

impl<T: Serialize + DeserializeOwned + Debug> AuthGuard<T> {
    pub fn access_token(&self) -> &str {
        &self.access_token
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

        if let Some(access_token) = cookies.get("access_token") {
            if let Some(issuer_cookie) = cookies.get("issuer_data") {
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
                                eprintln!("token expired or invalid: {}, issuer: {}, algorithm: {}", err, issuer_data.issuer, issuer_data.algorithm);
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
                // Fall back to normal decode
                match validator.decode::<T>(access_token.value()) {
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
