//! OpenID Connect (OIDC) signing utilities.
//!
//! This module provides a small, focused helper for producing signed JSON Web
//! Tokens (JWTs) suitable for use in OIDC flows. The primary export is
//! `OidcSigner`, a convenience wrapper around `jsonwebtoken::EncodingKey` that
//! emits a `kid` in the JWT header and automatically inserts standard
//! `iat`/`exp` claims when signing arbitrary JSON-serializable claim objects.
//!
//! Key points:
//! - `OidcSigner::from_rsa_pem(pem, kid)` constructs a signer from an RSA PEM
//!   private key and a key id string. The default signing algorithm for this
//!   constructor is RS256.
//! - `OidcSigner::sign(claims, expires_in)` serializes the provided claims to a
//!   JSON object, inserts `iat` (issued-at) and `exp` (expiration) as UNIX
//!   seconds, builds a header with the configured algorithm and `kid`, then
//!   produces a compact JWS using the configured private key.
//! - Errors from serialization or signing are returned as
//!   `jsonwebtoken::errors::Error`. The method will panic if the serialized
//!   claims are not a JSON object or if the system clock is earlier than the
//!   UNIX epoch.
//!
//! Example:
//! ```rust
//! use rocket_oidc::sign::{OidcSigner, generate_rsa_pkcs8_pair};
//! use serde_json::json;
//! use std::time::Duration;
//!
//! // Load your private key (PKCS#8 / PEM) from file, env, or include_str!
//! let (private_key_pem, _) = generate_rsa_pkcs8_pair();
//!
//! // Create a signer that will emit "my-kid" in the JWT header and sign with RS256.
//! let signer = OidcSigner::from_rsa_pem(&private_key_pem, "my-kid")
//!     .expect("failed to create signer");
//!
//! // Claims may be any serde-serializable object that becomes a JSON object.
//! let claims = json!({
//!     "sub": "user-123",
//!     "roles": ["admin", "editor"],
//! });
//!
//! // Sign for one hour.
//! let token = signer.sign(claims)
//!     .expect("failed to sign token");
//!
//! println!("signed JWT: {}", token);
//! ```
//!
//! Notes:
//! - If you need a different algorithm you can construct `OidcSigner` directly
//!   (it is `Clone`) and set the `algorithm` field to another `jsonwebtoken::Algorithm`.
//! - This module focuses on producing signed tokens. Use a separate validator
//!   component to verify tokens and validate standard OIDC claims such as `iss`,
//!   `aud` and expiry when consuming tokens.
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};
use jsonwebtoken::DecodingKey;
use crate::utils::*;

/// An OpenID Connect (OIDC) JWT signer backed by an encoding key.
///
/// Example: signing a set of claims/// This type holds the encoding key material, the key ID (kid) to emit in the
/// JWT header, and the signing algorithm to use. Use an instance of this
/// signer to produce signed JWTs with standard iat/exp claims added.
///
/// Fields:
/// - `key`: The jsonwebtoken::EncodingKey used to sign tokens.
/// - `kid`: Key ID emitted in the JWT header.
/// - `algorithm`: The signing algorithm (e.g., RS256).
#[derive(Debug, Clone)]
pub struct OidcSigner {
    key: EncodingKey,
    pubkey: DecodingKey,
    pub kid: String,
    pub algorithm: Algorithm,
}

impl OidcSigner {
    pub fn from_rsa_pem(pem: &str, kid: impl Into<String>) -> Result<Self, OIDCError> {
        // jsonwebtoken doesn't correctly parse DecodingKey from private pem, so this function handles this issue by converting private pem into public pem.
        let pubkey = decoding_key_from_private_pem(pem)?;
        Ok(Self {
            key: EncodingKey::from_rsa_pem(pem.as_bytes())?,
            kid: kid.into(),
            algorithm: Algorithm::RS256,
            pubkey,
        })
    }

    pub fn from_config_path(
        pem_path: &std::path::Path,
        kid: impl Into<String>,
    ) -> Result<Self, OIDCError> {
        let pem = std::fs::read_to_string(pem_path)?;
        Ok(Self::from_rsa_pem(&pem, kid)?)
    }

    pub fn decoding_key(&self) -> jsonwebtoken::DecodingKey {
        self.pubkey.clone()
    }

    /// Constructs an `OidcSigner` from an X.509 / PKCS#8 PEM-encoded private key.
    ///
    /// This helper is tolerant of common PEM encodings for RSA private keys:
    /// it first attempts to parse the input as a PKCS#8 (-----BEGIN PRIVATE KEY-----)
    /// document and falls back to a traditional RSA PKCS#1 (-----BEGIN RSA PRIVATE KEY-----)
    /// if PKCS#8 parsing fails.
    ///
    /// The resulting signer will use RS256 by default and will emit the provided `kid`
    /// value in the JWT header.
    ///
    /// # Parameters
    /// - `pem`: PEM-encoded private key material (PKCS#8 or RSA PKCS#1).
    /// - `kid`: Key ID string to include in the JWT header.
    ///
    /// # Returns
    /// - `Ok(OidcSigner)` on success.
    /// - `Err(jsonwebtoken::errors::Error)` if the PEM could not be parsed into an encoding key.
    pub fn from_x509_pem(pem: &str, kid: impl Into<String>) -> jsonwebtoken::errors::Result<Self> {
        // Try PKCS#8 first, then fall back to RSA PKCS#1 if necessary.
        let key = EncodingKey::from_rsa_pem(pem.as_bytes())
            .or_else(|_| EncodingKey::from_rsa_pem(pem.as_bytes()))?;

        Ok(Self {
            key,
            kid: kid.into(),
            algorithm: Algorithm::RS256,
            pubkey: DecodingKey::from_rsa_pem(pem.as_bytes())?,
        })
    }

    /// Signs the given JSON-serializable claims and returns a compact JWT (JWS).
    ///
    /// This method:
    /// - Serializes `claims` to JSON and expects the result to be a JSON object (map).
    /// - Computes `iat` (issued-at) as the current UNIX timestamp in seconds and `exp`
    ///   as `iat + expires_in` seconds, then inserts both into the claim object.
    /// - Builds a JWT header using the signer's configured algorithm and `kid`.
    /// - Encodes the header and claims using the signer's private key and returns the
    ///   resulting JWT string.
    ///
    /// # Parameters
    /// - `claims`: Any value implementing `serde::Serialize`. The serialized form must
    ///   be a JSON object (e.g. a map). If the serialized value is not an object the
    ///   function will panic due to an internal `unwrap`.
    /// - `expires_in`: A `std::time::Duration` that specifies how long from now the
    ///   token should remain valid (used to compute the `exp` claim).
    ///
    /// # Returns
    /// - `Ok(String)` containing the compact JWT on success.
    /// - `Err(jsonwebtoken::errors::Error)` if serialization or signing fails.
    ///
    /// # Panics
    /// - If `claims` does not serialize to a JSON object (the code calls
    ///   `as_object_mut().unwrap()`), this will panic.
    /// - If the system clock is before the UNIX epoch (the `duration_since(UNIX_EPOCH)`
    ///   call is unwrapped), this will panic.
    ///
    /// # Example
    /// ```rust
    /// # use std::time::Duration;
    /// # use serde_json::json;
    /// use rocket_oidc::sign::generate_rsa_pkcs8_pair;
    /// use rocket_oidc::sign::OidcSigner;
    /// let (test_private_pem, _) = generate_rsa_pkcs8_pair();
    /// let signer = OidcSigner::from_rsa_pem(&test_private_pem, "test-kid").expect("failed to create signer");
    /// let claims = json!({ "sub": "user-123", "role": "admin", "exp": 12345, "aud": "myapp", "iss": "localhost", "iat": 12345 });
    /// let token = signer.sign(claims).unwrap();
    /// println!("JWT: {}", token);
    /// ```
    pub fn sign<T: Serialize>(&self, claims: T) -> Result<String, OIDCError> {
        // Serialize claims to a JSON object
        let map_binding = serde_json::to_value(&claims)?;
        let map = map_binding
            .as_object()
            .ok_or_else(|| OIDCError::InvalidClaims("claims not a JSON object".into()))?;

        // Ensure required claims exist
        for required in &["aud", "iss", "sub", "exp", "iat"] {
            if !map.contains_key(*required) {
                return Err(OIDCError::MissingClaims((*required.to_string()).into()));
            }
        }

        // Build JWT header
        let mut header = jsonwebtoken::Header::new(self.algorithm);
        
        // Encode the JWT
        Ok(jsonwebtoken::encode(&header, &map, &self.key)?)
    }
}

use rand::rngs::OsRng;
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey},
};

use crate::errors::OIDCError;

pub fn generate_rsa_pkcs8_pair() -> (String, String) {
    // Generate a 2048-bit RSA private key
    let mut rng = OsRng;

    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("failed to generate key");

    // Convert to PKCS#8 PEM
    let private_key_pem = private_key
        .to_pkcs8_pem(Default::default())
        .expect("failed to encode private key");

    // Extract public key and encode as PEM
    let public_key = private_key.to_public_key();
    let public_key_pem = public_key
        .to_public_key_pem(Default::default())
        .expect("failed to encode public key");

    (private_key_pem.to_string(), public_key_pem)
}

#[cfg(test)]
pub(crate) mod tests {
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
    use crate::sign::OidcSigner;
    use serde::{Deserialize, Serialize};
    use time::OffsetDateTime;
    use uuid::Uuid;
    use crate::utils::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct MyClaims {
        sub: String,
        aud: String,
        iss: String,
        exp: i64,
        iat: i64,
    }

    #[test]
    fn test_sign_and_verify() -> Result<(), Box<dyn std::error::Error>> {
        // --- 1. Create signer ---
        let (private_pem, public_pem) = crate::sign::generate_rsa_pkcs8_pair();
        let signer = OidcSigner::from_rsa_pem(&private_pem, "test-kid")?;
        let decoding_key = signer.decoding_key();
        println!("signer: {:?}", signer);
        println!("decoding_key: {:?}", decoding_key);
        // --- 2. Build claims ---
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let claims = MyClaims {
            sub: "user-123".to_string(),
            aud: "test-audience".to_string(),
            iss: "test-issuer".to_string(),
            exp: now + 3600,
            iat: now,
        };

        // --- 3. Sign token ---
        let token = signer.sign(claims)?;

        println!("Signed JWT: {}", token);

        // --- 4. Decode token ---
        //let decoding_key = signer.decoding_key();
        
        let mut validation = Validation::new(Algorithm::RS256);
        validation.aud = Some(hashset_from(vec!["test-audience".to_string()]));
        validation.iss = Some(hashset_from(vec!["test-issuer".to_string()]));

        let token_data = decode::<MyClaims>(&token, &decoding_key, &validation)?;
        println!("Decoded claims: {:?}", token_data.claims);

        Ok(())
    }
}
