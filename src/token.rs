use crate::CoreClaims;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::sync::RwLock;

/// token provider information.
pub trait TokenProvider: Clone + Debug {
    fn token_endpoint(&self) -> &str;
    fn client_id(&self) -> &str;
    fn client_secret(&self) -> Option<&str>;
}

/// provides functionality for caching exchanged tokens
#[derive(Debug, Clone)]
pub struct SessionBearer<P: TokenProvider> {
    tokens: Arc<RwLock<HashMap<String, String>>>,
    provider: P,
}

impl<P: TokenProvider> SessionBearer<P> {
    pub fn new(provider: P) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(HashMap::new())),
            provider,
        }
    }

    /// Perform (or retrieve cached) OAuth 2.0 Token Exchange (RFC 8693)
    pub async fn exchange<S: CoreClaims>(
        &self,
        claims: S,
        audience: &str,
    ) -> Result<String, reqwest::Error> {
        let subject_token = claims.subject();

        let cache_key = format!("{}::{}", subject_token, audience);

        // Fast path: cache hit
        if let Some(token) = self.tokens.read().await.get(&cache_key).cloned() {
            return Ok(token);
        }

        // Client secret is required for this flow
        let client_secret = self
            .provider
            .client_secret()
            .expect("client_secret required for token exchange");

        let response = perform_token_exchange(
            self.provider.token_endpoint(),
            self.provider.client_id(),
            client_secret,
            subject_token,
            audience,
        )
        .await?;

        let access_token = response.access_token().to_string();

        // Store in cache
        self.tokens
            .write()
            .await
            .insert(cache_key, access_token.clone());

        Ok(access_token)
    }
}

#[derive(Deserialize, Debug)]
pub struct TokenExchangeResponse {
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: Option<String>,
    issued_token_type: Option<String>,
}

impl TokenExchangeResponse {
    pub fn access_token(&self) -> &str {
        &self.access_token
    }

    pub fn token_type(&self) -> &str {
        &self.token_type
    }

    pub fn issued_token_type(&self) -> &Option<String> {
        &self.issued_token_type
    }

    pub fn expires(&self) -> u64 {
        self.expires_in
    }

    pub fn scope(&self) -> &Option<String> {
        &self.scope
    }
}

///
/// # Arguments
/// token_endpoint: issuer token endpoint from discovery document
/// client_id: current client id
/// current client secret
/// subject_token: the access token
/// audiance: new audiance
pub(crate) async fn perform_token_exchange(
    token_endpoint: &str,
    client_id: &str,
    client_secret: &str,
    subject_token: &str,
    audience: &str,
) -> Result<TokenExchangeResponse, reqwest::Error> {
    let client = Client::new();

    let mut params = HashMap::new();
    params.insert(
        "grant_type",
        "urn:ietf:params:oauth:grant-type:token-exchange",
    );
    params.insert("subject_token", subject_token);
    params.insert(
        "subject_token_type",
        "urn:ietf:params:oauth:token-type:access_token",
    );
    params.insert("client_id", client_id);
    params.insert("client_secret", client_secret);
    // Optional, test with or without audience
    params.insert("audience", audience);

    println!("params: {:?}", params);
    let resp = client
        .post(token_endpoint)
        .form(&params)
        .send()
        .await?
        .error_for_status()?
        .json::<TokenExchangeResponse>()
        .await?;

    Ok(resp)
}
