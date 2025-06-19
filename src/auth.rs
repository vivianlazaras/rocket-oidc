//! This module provides `AuthGuard` which doesn't request user info, but simply validates server public key
//! this is useful for implementing local only login systems that don't rely on full OIDC support from the authorization server

use serde::{Serialize, de::DeserializeOwned};

use crate::CoreClaims;
use rocket::Request;
use rocket::http::{Cookie, Status};
use rocket::request::{FromRequest, Outcome};
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
            .unwrap()
            .clone();

        if let Some(access_token) = cookies.get("access_token") {
            let token_data = validator.decode::<T>(access_token.value());

            match token_data {
                Ok(data) => Outcome::Success(AuthGuard {
                    claims: data.claims,
                    access_token: access_token.value().to_string(),
                }),
                Err(err) => {
                    eprintln!("assuming token expired with error: {}", err);
                    let _ExpiredSignature = err;
                    {
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
