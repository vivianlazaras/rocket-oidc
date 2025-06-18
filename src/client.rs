use crate::{AddClaims, PronounClaim};
use jsonwebtoken::*;
use openidconnect::core::CoreGenderClaim;
use openidconnect::core::*;
use reqwest::Url;
use serde_derive::*;
use std::str::FromStr;

use crate::CoreClaims;
use crate::Error;
use crate::OIDCConfig;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Debug;

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

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct KeyID {
    issuer: String,
    alg: String,
}

impl KeyID {
    pub fn new(issuer: &str, alg: &str) -> Self {
        KeyID {
            issuer: issuer.to_string(),
            alg: alg.to_string(),
        }
    }
}

#[derive(Clone)]
pub struct Endpoint {
    validation: Validation,
    pubkey: DecodingKey,
}

impl Endpoint {
    pub fn new(validation: Validation, pubkey: DecodingKey) -> Self {
        Self { validation, pubkey }
    }
}

#[derive(Clone)]
pub struct Validator {
    pubkeys: HashMap<KeyID, Endpoint>,
    default_iss: String,
}

fn parse_jwks(
    issuer: &str,
    jwks_json: &str,
    validation: Validation,
) -> Result<HashMap<KeyID, Endpoint>, Box<dyn std::error::Error>> {
    let jwks: Value = serde_json::from_str(jwks_json)?;
    let keys_array = jwks["keys"]
        .as_array()
        .ok_or("JWKS does not contain a 'keys' array")?;

    let mut keys = HashMap::new();

    for jwk in keys_array {
        let alg = jwk["alg"].as_str().ok_or("Missing 'alg' in JWK")?;
        let kid = jwk["kid"].as_str().unwrap_or("default");

        let decoding_key = match alg {
            "RS256" | "RS384" | "RS512" => {
                let n = jwk["n"].as_str().ok_or("Missing 'n' in RSA JWK")?;
                let e = jwk["e"].as_str().ok_or("Missing 'e' in RSA JWK")?;
                DecodingKey::from_rsa_components(n, e)?
            }

            "ES256" | "ES384" | "ES512" => {
                let x = jwk["x"].as_str().ok_or("Missing 'x' in EC JWK")?;
                let y = jwk["y"].as_str().ok_or("Missing 'y' in EC JWK")?;
                DecodingKey::from_ec_components(x, y)?
            }

            "HS256" | "HS384" | "HS512" => {
                let k = jwk["k"].as_str().ok_or("Missing 'k' in symmetric JWK")?;
                DecodingKey::from_base64_secret(k)?
            }

            other => {
                eprintln!("Unsupported algorithm: {}", other);
                continue; // skip this key
            }
        };

        let key_id = KeyID::new(issuer, alg);
        keys.insert(key_id, Endpoint::new(validation.clone(), decoding_key));
    }

    Ok(keys)
}

impl Validator {
    pub fn from_pubkey(
        url: String,
        audiance: String,
        algorithm: String,
        public_key: DecodingKey,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pubkeys = HashMap::new();
        let mut validator = Self {
            pubkeys,
            default_iss: url.clone(),
        };

        validator.insert_pubkey(url, audiance, algorithm, public_key)?;
        Ok(
            validator
        )
    }

    pub async fn new(
        validation: Validation,
        provider_metadata: &CoreProviderMetadata,
        issuer_url: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let jwks_uri = provider_metadata.jwks_uri().to_string();

        let jwks_json = reqwest::get(jwks_uri).await?.text().await?;
        let keys = parse_jwks(&issuer_url, &jwks_json, validation)?;
        Ok(Self {
            pubkeys: keys,
            default_iss: issuer_url,
        })
    }

    pub fn insert_endpoint(&mut self, keyid: KeyID, endpoint: Endpoint) {
        self.pubkeys.insert(keyid, endpoint);
    }

    pub fn insert_pubkey(
        &mut self,
        url: String,
        audiance: String,
        algorithm: String,
        public_key: DecodingKey,
    ) -> Result<(), crate::Error> {
        let algo = Algorithm::from_str(&algorithm)?;
        let mut validation = Validation::new(algo);
        //validation.insecure_disable_signature_validation();
        {
            validation.leeway = 100; // Optionally, allow some leeway
            validation.validate_exp = true;
            validation.validate_aud = true;
            validation.validate_nbf = true;
            validation.aud = Some(hashset_from(vec![audiance])); // The audience should match your client ID
            validation.iss = Some(hashset_from(vec![url.clone()])); // Validate the issuer
            validation.algorithms = vec![algo];
        };

        let keyid = KeyID::new(&url, &algorithm);
        self.pubkeys.insert(keyid, Endpoint::new(validation, public_key));
        Ok(())
    }

    pub fn decode_with_iss_alg<
        T: Serialize + Debug + DeserializeOwned + std::marker::Send + CoreClaims,
    >(
        &self,
        issuer: &str,
        algorithm: &str,
        access_token: &str,
    ) -> Result<TokenData<T>, crate::Error> {
        let keyid = KeyID::new(issuer, algorithm);
        if let Some(endpoint) = self.pubkeys.get(&keyid) {
            Ok(decode::<T>(
                access_token,
                &endpoint.pubkey,
                &endpoint.validation,
            )?)
        } else {
            Err(Error::PubKeyNotFound(keyid))
        }
    }

    /// this function is deprecated because it uses the default issuer rule
    /// which may not be the right url to lookup a key by if using multiple provider endpoints.
    #[deprecated]
    pub fn decode<T: Serialize + Debug + DeserializeOwned + std::marker::Send + CoreClaims>(
        &self,
        access_token: &str,
    ) -> Result<TokenData<T>, crate::Error> {
        self.decode_with_iss_alg::<T>(&self.default_iss, "RS256", access_token)
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

        let validator = Validator::new(
            validation,
            &provider_metadata,
            config.issuer_url.to_string(),
        )
        .await?;

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
