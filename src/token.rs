use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

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
    params.insert("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
    params.insert("subject_token", subject_token);
    params.insert("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
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
