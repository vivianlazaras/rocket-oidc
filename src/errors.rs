use crate::KeyID;
use openidconnect::{ConfigurationError, HttpClientError, RequestTokenError};
use rocket::Request;
use rocket::http::ContentType;
use rocket::http::Status;
use rocket::response;
use std::io::Cursor;
use thiserror::Error;

pub type TokenErr = RequestTokenError<
    HttpClientError<reqwest::Error>,
    openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
>;

/// Errors that can occur when parsing or converting user info claims.
#[derive(Debug, Clone, Error)]
pub enum UserInfoErr {
    #[error("missing given name")]
    MissingGivenName,
    #[error("missing family name")]
    MissingFamilyName,
    #[error("missing profile picture url")]
    MissingPicture,
}

#[derive(Debug, Error)]
pub enum OIDCError {
    #[error("IO Error: {0}")]
    IO(#[from] std::io::Error),
    #[error("JSON web token error: {0}")]
    JsonWebToken(#[from] jsonwebtoken::errors::Error),
    #[error("serde JSON error: {0}")]
    JSONErr(#[from] serde_json::Error),
    #[error("discovery error: {0}")]
    OIDCDiscoveryErr(
        #[from] openidconnect::DiscoveryError<openidconnect::HttpClientError<reqwest::Error>>,
    ),
    #[error("reqwest error: {0}")]
    RequestErr(#[from] reqwest::Error),
    #[error("url parsing error: {0}")]
    UrlErr(#[from] openidconnect::url::ParseError),

    #[error("missing client id")]
    MissingClientId,
    #[error("missing client secret")]
    MissingClientSecret,
    #[error("missing issuer url")]
    MissingIssuerUrl,
    #[error("missing algorithim for issuer")]
    MissingAlgoForIssuer(String),

    #[error("openidconnect configuration error: {0}")]
    ConfigurationError(#[from] ConfigurationError),

    #[error("token validation error: {0}")]
    TokenError(#[from] TokenErr),

    #[error("pubkey {0:?} not found when trying to decode access token")]
    PubKeyNotFound(KeyID),

    #[error("time component range error: {0}")]
    TimeRangeErr(#[from] time::error::ComponentRange),
    #[error("missing required claim: {0}")]
    MissingClaims(String),

    #[error("claims error: {0}")]
    InvalidClaims(String),

    #[error("PKCS8 error: {0}")]
    PKCS8Err(#[from] pkcs8::spki::Error),

    #[error("missing refresh token")]
    MissingRefreshToken,

    #[error("PKCS1 error: {0}")]
    PKCS1Err(#[from] rsa::pkcs1::Error),
    #[error("{0}")]
    Custom(String),
}

impl From<&str> for OIDCError {
    fn from(val: &str) -> OIDCError {
        OIDCError::Custom(val.to_string())
    }
}

impl<'r> response::Responder<'r, 'static> for OIDCError {
    fn respond_to(self, _request: &'r Request<'_>) -> response::Result<'static> {
        let body = self.to_string();
        let status = match &self {
            OIDCError::MissingClientId
            | OIDCError::MissingClientSecret
            | OIDCError::MissingIssuerUrl => Status::BadRequest,
            OIDCError::RequestErr(_) | OIDCError::ConfigurationError(_) | OIDCError::JSONErr(_) => {
                Status::InternalServerError
            }
            OIDCError::TokenError(_) | OIDCError::MissingAlgoForIssuer(_) => Status::Unauthorized,
            OIDCError::PubKeyNotFound(_) | OIDCError::JsonWebToken(_) => Status::Unauthorized,
            _ => Status::InternalServerError,
        };

        response::Response::build()
            .status(status)
            .header(ContentType::Plain)
            .sized_body(body.len(), Cursor::new(body))
            .ok()
    }
}
