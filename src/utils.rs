//! Convenience functions throughout the crate go here
use cookie::Expiration;
use rocket::http::Cookie;
use time::OffsetDateTime;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use jsonwebtoken::DecodingKey;
use crate::errors::OIDCError;
use rsa::pkcs1::DecodeRsaPrivateKey;

use std::collections::HashSet;
use serde_json::Value;

pub fn string_or_array_to_set(value: Option<&Value>) -> HashSet<String> {
    let mut set = HashSet::new();

    match value {
        Some(Value::String(s)) => {
            set.insert(s.clone());
        }
        Some(Value::Array(arr)) => {
            for v in arr {
                if let Some(s) = v.as_str() {
                    set.insert(s.to_owned());
                }
            }
        }
        _ => {}
    }

    set
}



/// Load an RSA private key (PKCS#1 or PKCS#8 PEM),
/// extract the public key, and build a DecodingKey from it.
pub fn decoding_key_from_private_pem(
    private_pem: &str,
) -> Result<DecodingKey, OIDCError> {
    // Load private key (handles PKCS#1 and PKCS#8)
    let private = RsaPrivateKey::from_pkcs8_pem(private_pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(private_pem))?;

    // Derive public key
    let public = RsaPublicKey::from(&private);

    // Serialize public key to PEM (SubjectPublicKeyInfo)
    let public_pem = public.to_public_key_pem(pkcs8::LineEnding::LF)?;

    // Build DecodingKey strictly from public material
    Ok(DecodingKey::from_rsa_pem(public_pem.as_bytes())?)
}


pub fn check_expiration(cookie: &Cookie<'_>) -> (Option<OffsetDateTime>, bool) {
    match cookie.expires() {
        Some(Expiration::Session) => (None, false),
        Some(Expiration::DateTime(offset)) => {
            let ts = OffsetDateTime::now_utc();
            if offset > ts {
                return (Some(offset), false);
            } else {
                return (Some(offset), true);
            }
        }
        None => (None, false),
    }
}

pub fn hashset_from<T: std::cmp::Eq + std::hash::Hash>(vals: Vec<T>) -> HashSet<T> {
    vals.into_iter().collect()
}