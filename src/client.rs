use crate::{AddClaims, PronounClaim};
use jsonwebtoken::*;
use openidconnect::core::CoreGenderClaim;
use openidconnect::core::*;
use reqwest::Url;

use crate::CoreClaims;
use std::fmt::Debug;

use crate::OIDCConfig;

use crate::token::*;
use serde::de::DeserializeOwned;
use std::collections::HashSet;
use std::path::Path;
use tokio::{fs::File, io::AsyncReadExt};

use openidconnect::reqwest;
use openidconnect::*;
use serde::Serialize;

pub type OpenIDClient<
    HasDeviceAuthUrl = EndpointNotSet,
    HasIntrospectionUrl = EndpointNotSet,
    HasRevocationUrl = EndpointNotSet,
    HasAuthUrl = EndpointSet,
    HasTokenUrl = EndpointMaybeSet,
    HasUserInfoUrl = EndpointMaybeSet,
> = openidconnect::Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    CoreTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    HasAuthUrl,
    HasDeviceAuthUrl,
    HasIntrospectionUrl,
    HasRevocationUrl,
    HasTokenUrl,
    HasUserInfoUrl,
>;

fn join_url(root: &str, route: &str) -> Result<String, url::ParseError> {
    let base = Url::parse(root)?;
    let joined = base.join(route)?;
    Ok(joined.into())
}

fn trim_trailing_whitespace(s: &str) -> String {
    s.trim_end().to_string()
}

async fn laod_client_secret<P: AsRef<Path>>(
    secret_file: P,
) -> Result<ClientSecret, std::io::Error> {
    let mut file = File::open(secret_file.as_ref()).await?;
    let mut contents = String::new();

    file.read_to_string(&mut contents).await?;
    let secret = trim_trailing_whitespace(&contents);
    #[cfg(debug_assertions)]
    println!("using secret: {}", secret);
    Ok(ClientSecret::new(secret))
}

fn hashset_from<T: std::cmp::Eq + std::hash::Hash>(vals: Vec<T>) -> HashSet<T> {
    let mut set = HashSet::new();
    for val in vals.into_iter() {
        set.insert(val);
    }
    set
}

#[derive(Debug, Clone, Serialize)]
struct WorkingConfig {
    client_secret: ClientSecret,
    client_id: ClientId,
    issuer_url: IssuerUrl,
    redirect: String,
}

impl WorkingConfig {
    pub async fn from_oidc_config(config: &OIDCConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let client_id = config.client_id.clone();
        let issuer_url = config.issuer_url.clone();

        let client_id = ClientId::new(client_id);
        let client_secret = laod_client_secret(&config.client_secret).await?;
        let issuer_url = IssuerUrl::new(issuer_url)?;

        Ok(Self {
            client_id,
            client_secret,
            issuer_url,
            redirect: config.redirect.clone(),
        })
    }
}

#[derive(Clone)]
pub struct Validator {
    validation: Validation,
    public_key: DecodingKey,
}

impl Validator {
    pub async fn from_pubkey(url: &str, public_key: DecodingKey) -> Result<Self, Box<dyn std::error::Error>> {
        let mut validation = Validation::new(Algorithm::RS256);
        //validation.insecure_disable_signature_validation();
        {
            validation.leeway = 100; // Optionally, allow some leeway
            validation.validate_exp = true;
            validation.validate_aud = true;
            validation.validate_nbf = true;
            validation.aud = Some(hashset_from(vec!["account".to_string()])); // The audience should match your client ID
            validation.iss = Some(hashset_from(vec![url.to_string()])); // Validate the issuer
            validation.algorithms = vec![Algorithm::RS256];
        };
        Ok(Self {
            validation,
            public_key,
        })
    }
    pub async fn new(
        validation: Validation,
        provider_metadata: &CoreProviderMetadata,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let jwks_uri = provider_metadata.jwks_uri().to_string();

        // Fetch JSON Web Key Set (JWKS) from the provider
        let jwks: serde_json::Value =
            serde_json::from_str(&reqwest::get(jwks_uri).await.unwrap().text().await.unwrap())
                .unwrap();

        // Assuming you have the correct key in JWKS for verification
        //let jwk = &jwks["keys"][0]; // Adjust based on the actual structure of the JWKS
        let mut jwtkeys = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["alg"] == "RS256")
            .collect::<Vec<&serde_json::Value>>();
        println!("keys: {:?}", jwtkeys);
        let jwk = jwtkeys.pop().unwrap();
        // Public key from the JWKS
        let public_key = DecodingKey::from_rsa_components(
            jwk["n"].as_str().unwrap(),
            jwk["e"].as_str().unwrap(),
        )
        .unwrap();

        Ok(Self {
            validation,
            public_key,
        })
    }

    pub fn decode<T: Serialize + Debug + DeserializeOwned + std::marker::Send + CoreClaims>(
        &self,
        access_token: &str,
    ) -> Result<TokenData<T>, jsonwebtoken::errors::Error> {
        decode::<T>(access_token, &self.public_key, &self.validation)
    }
}

#[derive(Debug, Clone)]
pub struct OIDCClient {
    pub client: OpenIDClient,
    reqwest_client: reqwest::Client,
    config: WorkingConfig,
}

impl OIDCClient {
    pub async fn from_oidc_config(
        config: &OIDCConfig,
    ) -> Result<(Self, Validator), Box<dyn std::error::Error>> {
        let config = WorkingConfig::from_oidc_config(config).await?;

        let http_client = match reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(client) => client,
            Err(e) => return Err(Box::new(e)),
        };

        let provider_metadata =
            match CoreProviderMetadata::discover_async(config.issuer_url.clone(), &http_client)
                .await
            {
                Ok(provider_metadata) => provider_metadata,
                Err(e) => return Err(Box::new(e)),
            };

        // Decode and verify the JWT
        let mut validation = Validation::new(Algorithm::RS256);
        //validation.insecure_disable_signature_validation();
        {
            validation.leeway = 100; // Optionally, allow some leeway
            validation.validate_exp = true;
            validation.validate_aud = true;
            validation.validate_nbf = true;
            validation.aud = Some(hashset_from(vec!["account".to_string()])); // The audience should match your client ID
            validation.iss = Some(hashset_from(vec![config.issuer_url.to_string()])); // Validate the issuer
            validation.algorithms = vec![Algorithm::RS256];
        };

        let validator = Validator::new(validation, &provider_metadata).await?;

        // Set up the config for the GitLab OAuth2 process.
        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            config.client_id.clone(),
            Some(config.client_secret.clone()),
        )
        // This example will be running its own server at localhost:8080.
        // See below for the server implementation.
        .set_redirect_uri(
            RedirectUrl::new(join_url(&config.redirect, "/auth/callback/").unwrap())
                .unwrap_or_else(|_err| {
                    unreachable!();
                }),
        );

        Ok((
            Self {
                client,
                config,
                reqwest_client: http_client,
            },
            validator,
        ))
    }

    pub async fn user_info(
        &self,
        access_token: AccessToken,
        subject: Option<SubjectIdentifier>,
    ) -> Result<
        UserInfoClaims<AddClaims, PronounClaim>,
        UserInfoError<openidconnect::HttpClientError<reqwest::Error>>,
    > {
        self.client
            .user_info(
                access_token, // AccessToken::new(access_token.value().to_string())
                subject,      //Some(SubjectIdentifier::new(data.claims.subject().to_string()))
            )
            .unwrap()
            .request_async(&self.reqwest_client)
            .await
    }

    pub async fn exchange_code(
        &self,
        code: AuthorizationCode,
    ) -> Result<CoreTokenResponse, crate::Error> {
        Ok(self
            .client
            .exchange_code(code)?
            .request_async(&self.reqwest_client)
            .await?)
    }

    pub async fn exchange_token_for_audience(
        &self,
        subject_token: &str,
        audience: &str,
    ) -> Result<TokenExchangeResponse, reqwest::Error> {
        crate::token::perform_token_exchange(
            self.client.token_uri().unwrap().as_str(),
            self.config.client_id.as_str(),
            self.config.client_secret.secret().as_str(),
            subject_token,
            audience,
        )
        .await
    }

    
}
