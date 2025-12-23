pub mod callbacks;
pub mod config;
pub mod routes;
pub mod sign;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Comprehensive Keycloak OIDC discovery document.
/// This struct is designed to capture all endpoints, features, and supported options
/// that a Keycloak realm exposes via `.well-known/openid-configuration`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    /// Issuer identifier: unique string representing the OIDC provider.
    /// Clients must verify that tokens are issued by this issuer.
    pub issuer: String,

    /// Authorization endpoint URL.
    /// Used by clients to initiate the OAuth2 / OIDC authorization flow.
    /// For example, `/protocol/openid-connect/auth`.
    pub authorization_endpoint: String,

    /// Token endpoint URL.
    /// Used to exchange authorization codes, perform client credentials grant, refresh tokens, etc.
    pub token_endpoint: String,

    /// Token introspection endpoint URL.
    /// Clients or protected resources can use this endpoint to verify opaque access tokens.
    pub introspection_endpoint: String,

    /// Userinfo endpoint URL.
    /// Clients can fetch claims about the authenticated user here.
    pub userinfo_endpoint: String,

    /// End-session (logout) endpoint URL.
    /// Allows clients or users to terminate the session and optionally propagate logout to clients.
    pub end_session_endpoint: String,

    /// Indicates whether frontchannel logout with session support is available.
    /// Enables the OP to notify client sessions via frontchannel mechanisms.
    pub frontchannel_logout_session_supported: bool,

    /// Indicates whether frontchannel logout is supported at all.
    pub frontchannel_logout_supported: bool,

    /// URL of the JSON Web Key Set (JWKS) for signature verification of tokens.
    pub jwks_uri: String,

    /// URL for the session check iframe (frontchannel session management).
    /// Clients can embed this iframe to detect if the user’s session is still active.
    pub check_session_iframe: String,

    /// List of supported grant types.
    /// Examples: `authorization_code`, `client_credentials`, `password`, `refresh_token`, `device_code`, `token-exchange`, `uma-ticket`, `ciba`.
    /// Determines which OAuth2 flows the server accepts.
    pub grant_types_supported: Vec<String>,

    /// Supported Authentication Context Class References (ACRs).
    /// Typically used to specify authentication strength/level.
    pub acr_values_supported: Vec<String>,

    /// Supported response types in authorization requests.
    /// Examples: `code`, `id_token`, `token`, `code id_token token`.
    /// Dictates which combination of tokens can be returned by the authorization endpoint.
    pub response_types_supported: Vec<String>,

    /// Supported subject identifier types for users.
    /// Examples: `public` (same sub for all clients), `pairwise` (unique per client).
    pub subject_types_supported: Vec<String>,

    /// Supported prompt values in auth requests.
    /// Examples: `none`, `login`, `consent`.
    /// Controls whether login or consent prompts are enforced.
    pub prompt_values_supported: Vec<String>,

    /// Supported signing algorithms for ID tokens.
    /// Clients use this to validate JWT signatures.
    pub id_token_signing_alg_values_supported: Vec<SigningAlg>,

    /// Supported encryption algorithms for ID tokens.
    pub id_token_encryption_alg_values_supported: Vec<EncryptionAlg>,

    /// Supported encryption encoding algorithms for ID tokens.
    pub id_token_encryption_enc_values_supported: Vec<ContentEncryptionAlg>,

    /// Supported signing algorithms for userinfo responses.
    pub userinfo_signing_alg_values_supported: Vec<String>,

    /// Supported encryption algorithms for userinfo responses.
    pub userinfo_encryption_alg_values_supported: Vec<String>,

    /// Supported encryption encodings for userinfo responses.
    pub userinfo_encryption_enc_values_supported: Vec<String>,

    /// Supported signing algorithms for request objects.
    /// Used when clients send signed JWT request objects instead of parameters.
    pub request_object_signing_alg_values_supported: Vec<String>,

    /// Supported encryption algorithms for request objects.
    pub request_object_encryption_alg_values_supported: Vec<String>,

    /// Supported encryption encodings for request objects.
    pub request_object_encryption_enc_values_supported: Vec<String>,

    /// Supported response modes in authorization requests.
    /// Examples: `query`, `fragment`, `form_post`, `query.jwt`.
    /// Determines how the authorization response is returned to the client.
    pub response_modes_supported: Vec<String>,

    /// Registration endpoint URL.
    /// Clients can dynamically register themselves here.
    pub registration_endpoint: String,

    /// Supported authentication methods for the token endpoint.
    /// Examples: `client_secret_basic`, `private_key_jwt`.
    pub token_endpoint_auth_methods_supported: Vec<String>,

    /// Supported signing algorithms for token endpoint authentication.
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,

    /// Supported authentication methods for the introspection endpoint.
    pub introspection_endpoint_auth_methods_supported: Vec<String>,

    /// Supported signing algorithms for introspection endpoint authentication.
    pub introspection_endpoint_auth_signing_alg_values_supported: Vec<String>,

    /// Supported signing algorithms for authorization responses.
    pub authorization_signing_alg_values_supported: Vec<String>,

    /// Supported encryption algorithms for authorization responses.
    pub authorization_encryption_alg_values_supported: Vec<String>,

    /// Supported encryption encodings for authorization responses.
    pub authorization_encryption_enc_values_supported: Vec<String>,

    /// List of supported claims (e.g., `sub`, `aud`, `email`).
    /// Clients can request these via `scope` or `claims` parameter.
    pub claims_supported: Vec<String>,

    /// Supported claim types.
    /// Usually `normal`.
    pub claim_types_supported: Vec<String>,

    /// Whether the `claims` parameter is supported in authorization requests.
    pub claims_parameter_supported: bool,

    /// Supported scopes (e.g., `openid`, `profile`, `email`).
    pub scopes_supported: Vec<String>,

    /// Whether the `request` parameter is supported in authorization requests.
    pub request_parameter_supported: bool,

    /// Whether the `request_uri` parameter is supported in authorization requests.
    pub request_uri_parameter_supported: bool,

    /// Whether pre-registration of request URIs is required.
    pub require_request_uri_registration: bool,

    /// Supported code challenge methods (PKCE).
    /// Examples: `plain`, `S256`.
    pub code_challenge_methods_supported: Vec<String>,

    /// Indicates if access tokens can be bound to client TLS certificates.
    pub tls_client_certificate_bound_access_tokens: bool,

    /// URL of the revocation endpoint.
    /// Clients can revoke access or refresh tokens here.
    pub revocation_endpoint: String,

    /// Supported authentication methods for revocation endpoint.
    pub revocation_endpoint_auth_methods_supported: Vec<String>,

    /// Supported signing algorithms for revocation endpoint authentication.
    pub revocation_endpoint_auth_signing_alg_values_supported: Vec<String>,

    /// Whether backchannel logout is supported.
    pub backchannel_logout_supported: bool,

    /// Whether backchannel logout with session support is supported.
    pub backchannel_logout_session_supported: bool,

    /// Device authorization endpoint (for OAuth2 device flow).
    pub device_authorization_endpoint: String,

    /// Supported delivery modes for backchannel token delivery.
    /// Examples: `poll`, `ping`.
    pub backchannel_token_delivery_modes_supported: Vec<String>,

    /// Backchannel authentication endpoint (CIBA).
    pub backchannel_authentication_endpoint: String,

    /// Supported signing algorithms for backchannel authentication requests.
    pub backchannel_authentication_request_signing_alg_values_supported: Vec<String>,

    /// Whether pushed authorization requests (PAR) are required.
    pub require_pushed_authorization_requests: bool,

    /// Pushed authorization request endpoint.
    pub pushed_authorization_request_endpoint: String,

    /// Map of MTLS endpoint aliases for various endpoints.
    pub mtls_endpoint_aliases: HashMap<String, String>,

    /// Indicates whether the `iss` parameter is returned in authorization responses.
    pub authorization_response_iss_parameter_supported: bool,

    /// This is not part of spec but is useful to standardized secure session representation.
    pub start_session_endpoint: Option<String>,
}

/// Supported ID token signing algorithms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum SigningAlg {
    PS256,
    PS384,
    PS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES384,
    ES512,
    EdDSA,
    HS256,
    HS384,
    HS512,
    None,
    Other(String),
}

/// Supported ID token encryption algorithms (key management).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionAlg {
    #[serde(rename = "RSA1_5")]
    Rsa1_5,
    #[serde(rename = "RSA-OAEP")]
    RsaOaep,
    #[serde(rename = "RSA-OAEP-256")]
    RsaOaep256,
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
    #[serde(rename = "ECDH-ES+A128KW")]
    EcdhEsA128Kw,
    #[serde(rename = "ECDH-ES+A192KW")]
    EcdhEsA192Kw,
    #[serde(rename = "ECDH-ES+A256KW")]
    EcdhEsA256Kw,
    Other(String),
}

/// Supported encryption content encryption algorithms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContentEncryptionAlg {
    #[serde(rename = "A128CBC-HS256")]
    A128CbcHs256,
    #[serde(rename = "A192CBC-HS384")]
    A192CbcHs384,
    #[serde(rename = "A256CBC-HS512")]
    A256CbcHs512,
    #[serde(rename = "A128GCM")]
    A128Gcm,
    #[serde(rename = "A192GCM")]
    A192Gcm,
    #[serde(rename = "A256GCM")]
    A256Gcm,
    Other(String),
}

/// Supported client authentication methods at the token endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    /// Client authenticates using HTTP Basic (Authorization header) with client secret.
    ClientSecretBasic,
    /// Client authenticates by including `client_id` and `client_secret` in the request body.
    ClientSecretPost,
    /// Client authenticates using a signed JWT with a shared secret.
    ClientSecretJwt,
    /// Client authenticates using a signed JWT with a private key (asymmetric crypto).
    PrivateKeyJwt,
    /// Client authenticates via a TLS client certificate.
    TlsClientAuth,
    /// Client authenticates using a PAKE-based Opaque protocol.
    PakeOpaque,
}

pub struct OIDCServer {
    routes: Vec<Route>,
    doc: DiscoveryDocument,
}

pub struct OIDCServerBuilder {
    issuer: Option<String>,

    authorization: Option<Route>,
    token: Option<Route>,
    userinfo: Option<Route>,
    introspection: Option<Route>,
    jwks: Option<Route>,
    end_session: Option<Route>,
}

impl OIDCServerBuilder {
    pub fn new() -> Self {
        Self {
            issuer: None,
            authorization: None,
            token: None,
            userinfo: None,
            introspection: None,
            jwks: None,
            end_session: None,
        }
    }

    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    pub fn authorization_route(mut self, route: Route) -> Self {
        self.authorization = Some(route);
        self
    }

    pub fn token_route(mut self, route: Route) -> Self {
        self.token = Some(route);
        self
    }

    pub fn userinfo_route(mut self, route: Route) -> Self {
        self.userinfo = Some(route);
        self
    }

    pub fn jwks_route(mut self, route: Route) -> Self {
        self.jwks = Some(route);
        self
    }

    pub fn end_session_route(mut self, route: Route) -> Self {
        self.end_session = Some(route);
        self
    }

    pub fn build(self, base_url: &str) -> OIDCServer {
        let mut routes = Vec::new();

        let authorization = self
            .authorization
            .unwrap_or_else(|| default_authorize.into());

        let token = self.token.unwrap_or_else(|| default_token.into());

        let userinfo = self.userinfo.unwrap_or_else(|| default_userinfo.into());

        let jwks = self.jwks.unwrap_or_else(|| default_jwks.into());

        let logout = self.end_session.unwrap_or_else(|| default_logout.into());

        routes.extend([
            authorization.clone(),
            token.clone(),
            userinfo.clone(),
            jwks.clone(),
            logout.clone(),
        ]);

        let issuer = self.issuer.unwrap_or_else(|| base_url.to_string());

        let doc = DiscoveryDocument {
            issuer,
            authorization_endpoint: format!("{base_url}{}", authorization.uri),
            token_endpoint: format!("{base_url}{}", token.uri),
            userinfo_endpoint: format!("{base_url}{}", userinfo.uri),
            jwks_uri: format!("{base_url}{}", jwks.uri),
            end_session_endpoint: format!("{base_url}{}", logout.uri),

            // sensible defaults
            grant_types_supported: vec!["authorization_code".into(), "refresh_token".into()],
            response_types_supported: vec!["code".into()],
            subject_types_supported: vec!["public".into()],
            scopes_supported: vec!["openid".into(), "profile".into()],
            code_challenge_methods_supported: vec!["S256".into()],

            frontchannel_logout_supported: true,
            frontchannel_logout_session_supported: true,

            // rest omitted for brevity
            ..Default::default()
        };

        OIDCServer { routes, doc }
    }
}
