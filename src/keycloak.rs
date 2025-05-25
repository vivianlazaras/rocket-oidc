//!
//! This module provides types for creating realm files for keycloak


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KCClient {
    pub clientId: String,
    pub enabled: bool,
    pub publicClient: bool,
    pub clientAuthenticatorType: Option<String>, // "client-secret", // optional
    pub secret: Option<String>,       // the static secret you want
    pub protocol: Option<String>, // "openid-connect",
    pub redirectUris: Vec<String>, // ["https://backend.local/*"]
    pub webOrigins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KCCredential {
    pub r#type: String,
    pub value: String,
    pub temporary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KCUser {
    pub username: String,
    pub enabled: bool,
    pub emailVerified: bool,
    pub firstName: String,
    pub lastName: String,
    pub email: String,
    pub credentials: Vec<KCCredential>,
}

/// This struct is used to make defining realms in keycloak easier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Realm {
    pub realm: String,
    pub enabled: bool,
    pub displayName: String,
    pub clients: Vec<KCClient>,
    pub users: Vec<KCUser>,
}