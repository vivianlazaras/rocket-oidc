use futures::future::BoxFuture;
use std::collections::HashMap;
use std::sync::Arc;

/// Type alias for a generic async endpoint handler
/// `Input` is the request data type
/// `Output` is the response type
pub type AsyncHandler<Input, Output> =
    Arc<dyn Fn(Input) -> BoxFuture<'static, Output> + Send + Sync>;

pub struct DiscoveryDocumentCallbacks {
    // Example endpoints with strongly-typed async handlers
    pub authorization_endpoint: AsyncHandler<AuthorizationRequest, AuthorizationResponse>,
    pub token_endpoint: AsyncHandler<TokenRequest, TokenResponse>,
    pub introspection_endpoint: AsyncHandler<IntrospectionRequest, IntrospectionResponse>,
    pub userinfo_endpoint: Option<AsyncHandler<UserInfoRequest, UserInfoResponse>>,
    pub end_session_endpoint: Option<AsyncHandler<EndSessionRequest, EndSessionResponse>>,

    // Example for MTLS endpoint aliases
    pub mtls_endpoint_aliases: Option<AsyncHandler<(), HashMap<String, String>>>,
}

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents an incoming authorization request (from the client to the /authorize endpoint)
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<String>,
    pub response_type: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub prompt: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub acr_values: Option<Vec<String>>,
    pub claims: Option<HashMap<String, String>>,
    pub login_hint: Option<String>,
}

/// Response from the /authorize endpoint (usually a redirect)
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    pub redirect_uri: String,
    pub code: Option<String>,
    pub id_token: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// Represents an incoming token request (to the /token endpoint)
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,   // e.g., "authorization_code", "refresh_token", etc.
    pub code: Option<String>, // for authorization_code flow
    pub redirect_uri: Option<String>,
    pub refresh_token: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
}

/// Response from the /token endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,      // e.g., "Bearer"
    pub expires_in: Option<u64>, // seconds
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub id_token: Option<String>,
}

/// Request to the /introspection endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct IntrospectionRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

/// Response from /introspection
#[derive(Debug, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    pub active: bool,
    pub scope: Option<String>,
    pub client_id: Option<String>,
    pub username: Option<String>,
    pub token_type: Option<String>,
    pub exp: Option<u64>,
    pub iat: Option<u64>,
    pub nbf: Option<u64>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub iss: Option<String>,
    pub jti: Option<String>,
}

/// Request to /userinfo
#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfoRequest {
    pub access_token: String,
}

/// Response from /userinfo
#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub sub: String,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub other_claims: Option<HashMap<String, String>>,
}

/// Request to /logout (end-session endpoint)
#[derive(Debug, Serialize, Deserialize)]
pub struct EndSessionRequest {
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

/// Response from /logout
#[derive(Debug, Serialize, Deserialize)]
pub struct EndSessionResponse {
    pub success: bool,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
}
