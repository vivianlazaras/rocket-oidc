//! This module provides `AuthGuard` which doesn't request user info, but simply validates server public key
//! this is useful for implementing local only login systems that don't rely on full OIDC support from the authorization server

use crate::CoreClaims;
use crate::client::IssuerData;
use rocket::Request;
use rocket::http::{Cookie, Status};
use rocket::request::{FromRequest, Outcome};
use serde::{Serialize, de::DeserializeOwned};
use std::fmt::Debug;

use crate::client::Validator;

#[derive(Debug, Clone)]
pub struct AuthGuard<T: Serialize + DeserializeOwned + Debug> {
    pub claims: T,
    access_token: String,
}

struct IDClaims {
    pub iss: String,
    pub alg: String,
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

fn get_iss_alg(token: &str) -> Option<IDClaims> {
    let alg = match jsonwebtoken::decode_header(token) {
        Ok(header) => alg_to_string(&header.alg),
        Err(e) => {
            eprintln!("error decoding algorithim: {}", e);
            return None;
        }
    };
    let claims: serde_json::Value = match jsonwebtoken::dangerous::insecure_decode(token) {
        Ok(data) => data.claims,
        Err(_) => return None,
    };
    let iss = claims.get("iss")?.as_str()?.to_string();
    println!("Extracted iss: {}, alg: {}", iss, alg);
    Some(IDClaims { iss, alg })
}

fn extract_key_from_authorization_header(header: &str) -> Option<String> {
    if header.starts_with("Bearer ") {
        Some(header[7..].to_string())
    } else {
        None
    }
}

fn parse_authorization_header<
    T: Serialize + Debug + DeserializeOwned + std::marker::Send + CoreClaims,
>(
    header: &str,
    validator: &Validator,
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

    println!(
        "Validating token with iss: {}, alg: {}",
        idclaims.iss, idclaims.alg
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::OidcSigner;
    use serde_derive::Deserialize;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn iat_to_exp() -> (i64, i64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp = now + 3600; // Default to 1 hour expiry
        (now as i64, exp as i64)
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
    struct TestClaims {
        sub: String,
        iss: String,
        // include other typical fields if needed by your validator (exp/aud/etc.)
        exp: i64,
        iat: i64,
        aud: String,
    }

    impl CoreClaims for TestClaims {
        fn subject(&self) -> &str {
            &self.sub
        }

        fn issuer(&self) -> &str {
            &self.iss
        }

        fn expiration(&self) -> i64 {
            self.exp as i64
        }

        fn issued_at(&self) -> i64 {
            self.iat // Not used in tests
        }

        fn audience(&self) -> &str {
            &self.aud
        }
    }

    // Helper to generate a validator and a signer for a simple issuer + algorithm
    fn make_signer_and_validator() -> (OidcSigner, Validator, String) {
        let (privkey, pubkey) = crate::sign::generate_rsa_pkcs8_pair();
        let issuer = "http://test-issuer.local";

        let signer = OidcSigner::from_rsa_pem(&privkey, "RS256").expect("create signer");
        let validator = Validator::from_rsa_pubkey_pem(
            issuer.to_string(),
            "test".to_string(),
            "RS256".to_string(),
            &pubkey,
        )
        .expect("create validator");
        (signer, validator, issuer.to_string())
    }

    #[test]
    fn parse_authorization_header_valid_token_returns_success() {
        let (signer, validator, issuer) = make_signer_and_validator();

        let (iat, exp) = iat_to_exp();
        let claims = TestClaims {
            sub: "user123".to_string(),
            iss: issuer.clone(),
            exp,
            iat,
            aud: "test".to_string(),
        };

        println!("validator: {:?}", validator);

        let token = signer.sign(&claims).expect("sign token");
        let header = format!("Bearer {}", token);

        let outcome = crate::auth::parse_authorization_header::<TestClaims>(&header, &validator);

        match outcome {
            Outcome::Success(g) => {
                assert_eq!(g.claims.sub, "user123");
                assert_eq!(g.claims.iss, issuer);
                assert_eq!(g.access_token, token);
            }
            other => panic!("expected Success, got {:?}", other),
        }
    }

    #[test]
    fn parse_authorization_header_missing_bearer_prefix_forwards() {
        let (_signer, validator, issuer) = make_signer_and_validator();

        // token-like string but missing "Bearer " prefix
        let header = "not-bearer-token-string";

        let outcome = crate::auth::parse_authorization_header::<TestClaims>(header, &validator);

        match outcome {
            Outcome::Forward(status) => assert_eq!(status, Status::Unauthorized),
            other => panic!("expected Forward(Status::Unauthorized), got {:?}", other),
        }
    }

    #[test]
    fn parse_authorization_header_invalid_token_forwards() {
        let (_signer, validator, issuer) = make_signer_and_validator();

        // malformed token
        let header = "Bearer this.is.not.a.valid.jwt";

        let outcome = crate::auth::parse_authorization_header::<TestClaims>(header, &validator);

        match outcome {
            Outcome::Forward(status) => assert_eq!(status, Status::Unauthorized),
            other => panic!("expected Forward(Status::Unauthorized), got {:?}", other),
        }
    }

    #[test]
    fn parse_authorization_header_wrong_issuer_or_alg_forwards() {
        let (signer_a, validator_a, issuer) = make_signer_and_validator();

        let (iat, exp) = iat_to_exp();

        // create a different signer (different issuer/alg) to produce a token that will not validate
        let (signer_b, _validator_b, issuer_b) = make_signer_and_validator();
        let token = signer_b
            .sign(&TestClaims {
                aud: "test".to_string(),
                iat,
                sub: "userX".to_string(),
                iss: issuer_b,
                exp,
            })
            .expect("sign token b");

        let header = format!("Bearer {}", token);

        // try to validate with signer_a's validator (should fail due to issuer/key mismatch)

        let outcome = crate::auth::parse_authorization_header::<TestClaims>(&header, &validator_a);

        match outcome {
            Outcome::Forward(status) => assert_eq!(status, Status::Unauthorized),
            other => panic!("expected Forward(Status::Unauthorized), got {:?}", other),
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

        let validator = req
            .rocket()
            .state::<crate::client::Validator>()
            .expect("validator managed state not found")
            .clone();

        parse_authorization_header(api_key, &validator)
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
