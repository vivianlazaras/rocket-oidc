//! This module provides a few claims definitions for convience, but can be overridden.

use crate::string_or_vec;

use serde::{Deserialize, Serialize};

use openidconnect::{GenderClaim, AdditionalClaims};

/// Trait for extracting the subject identifier from any set of claims.
/// this is also used as a marker trait
pub trait CoreClaims: Clone {
    fn subject(&self) -> &str;
    fn issuer(&self) -> Vec<String>;
    fn audience(&self) -> Vec<String>;
    fn issued_at(&self) -> i64;
    fn exp(&self) -> i64;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    // --- Required OIDC / OAuth2 base claims ---
    pub exp: i64,
    pub iat: i64,
    pub sub: String,

    #[serde(deserialize_with = "string_or_vec")]
    pub iss: Vec<String>,

    #[serde(deserialize_with = "string_or_vec")]
    pub aud: Vec<String>,

    // --- Identity / profile claims (all optional) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>, // first name

    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>, // last name

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>, // full display name (OIDC standard)

    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>, // URL to profile image

    // --- Optional custom fields ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pronouns: Option<String>,
}

use chrono::Utc;

impl AccessTokenClaims {
    pub fn new(sub: String, iss: Vec<String>, aud: Vec<String>, exp_offset: i64) -> Self {
        let now = Utc::now().timestamp();

        let iat = now;
        let exp = now + exp_offset;

        Self {
            sub,
            iss,
            aud,
            iat,
            exp,

            given_name: None,
            family_name: None,
            name: None,
            email: None,
            preferred_username: None,
            picture: None,
            pronouns: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddClaims {}
impl AdditionalClaims for AddClaims {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PronounClaim {}

impl GenderClaim for PronounClaim {}