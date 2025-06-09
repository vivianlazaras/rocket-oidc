//! This module provides `AuthGuard` which doesn't request user info, but simply validates server public key
//! this is useful for implementing local only login systems that don't rely on full OIDC support from the authorization server

use serde::{Serialize, de::DeserializeOwned};

use rocket::http::{Status, Cookie};
use rocket::request::{FromRequest, Outcome};
use rocket::Request;
use crate::CoreClaims;
use std::fmt::Debug;

pub struct AuthGuard<T: Serialize + DeserializeOwned> {
    pub claims: T,
}


#[rocket::async_trait]
impl<'r, T: Serialize + Debug + DeserializeOwned + std::marker::Send + CoreClaims> FromRequest<'r>
    for AuthGuard<T>
{
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let cookies = req.cookies();
        let validator = req.rocket().state::<crate::Validator>().unwrap().clone();

        if let Some(access_token) = cookies.get("access_token") {
            let token_data = validator.decode::<T>(access_token.value());

            match token_data {
                Ok(data) => {
                    Outcome::Success(AuthGuard {
                        claims: data.claims,
                    })
                }
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