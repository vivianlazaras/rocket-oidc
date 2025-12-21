//! Convenience functions throughout the crate go here
use cookie::Expiration;
use rocket::http::Cookie;
use time::OffsetDateTime;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use jsonwebtoken::DecodingKey;
use crate::errors::OIDCError;
use rsa::pkcs1::DecodeRsaPrivateKey;
use serde::{Deserialize, Deserializer};

use std::collections::HashSet;
use serde_json::Value;

/// a convience method to handle singleton or sequence when deserializing values with serde.
pub fn string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Helper {
        One(String),
        Many(Vec<String>),
    }

    Ok(match Helper::deserialize(deserializer)? {
        Helper::One(s) => [s].into_iter().collect(),
        Helper::Many(v) => v.into_iter().collect(),
    })
}


/// this function intentionally leaks memory.
pub fn value_to_str_slice(value: &Value) -> Vec<String> {
    // static empty slice for fallback
    static EMPTY_SLICE: &[String] = &[];

    match value {
        Value::String(s) => vec![s.to_string()],
        Value::Array(arr) => {
            // collect &str references from array
            // store in a temporary Vec, then leak it for 'static lifetime
            // (this is the simplest if you must return a slice)
            // Alternative is to return Cow<[&str]> to avoid leaking
            let mut temp: Vec<String> = Vec::with_capacity(arr.len());
            for v in arr {
                temp.push(v.to_string());
            }
            if temp.is_empty() {
                EMPTY_SLICE.to_vec()
            } else {
                temp
            }
        }
        _ => EMPTY_SLICE.to_vec(),
    }
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