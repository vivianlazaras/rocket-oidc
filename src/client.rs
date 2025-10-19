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

/// Configuration used internally by the OIDC client to manage static values.
///
/// Contains client credentials and metadata loaded from a higher-level `OIDCConfig`.
#[derive(Debug, Clone, Serialize)]
pub struct WorkingConfig {
    client_secret: ClientSecret,
    client_id: ClientId,
    issuer_url: IssuerUrl,
    redirect: String,
}

impl WorkingConfig {
    /// Constructs a new `WorkingConfig` from a high-level `OIDCConfig`.
    ///
    /// Loads the client secret asynchronously (e.g., from a file or secure vault).
    ///
    /// # Arguments
    /// * `config` - The high-level configuration containing static strings and secret references.
    ///
    /// # Returns
    /// * `Ok(WorkingConfig)` on success.
    /// * `Err` if loading or parsing fails.
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

/// Identifier for a public key used in token validation.
///
/// Combines the issuer and algorithm to uniquely reference a key in a multi-issuer or multi-algorithm environment.
/// This is not that same as what's used within openidconnect crate, just used by this crates validator.
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct KeyID {
    issuer: String,
    alg: String,
}

impl KeyID {
    /// Creates a new `KeyID` from issuer and algorithm strings.
    ///
    /// # Arguments
    /// * `issuer` - The key issuer.
    /// * `alg` - The signing algorithm.
    pub fn new(issuer: &str, alg: &str) -> Self {
        KeyID {
            issuer: issuer.to_string(),
            alg: alg.to_string(),
        }
    }
}

/// Represents a manually configured public key endpoint for token validation.
///
/// Contains validation rules and the decoding key used to verify signatures.
#[derive(Clone)]
pub struct Endpoint {
    validation: Validation,
    pubkey: DecodingKey,
}

impl Endpoint {
    /// Creates a new `Endpoint` with the given validation rules and decoding key.
    ///
    /// # Arguments
    /// * `validation` - Validation settings (audience, issuer, leeway, etc.).
    /// * `pubkey` - The public key used to verify signatures.
    pub fn new(validation: Validation, pubkey: DecodingKey) -> Self {
        Self { validation, pubkey }
    }
}

/// A helper type for validating JSON Web Tokens (JWTs) against multiple issuers and algorithms.
///
/// `Validator` manages a collection of public keys and associated validation rules
/// (wrapped in `Endpoint` structs) that can be used to decode and verify tokens.
/// It supports loading keys dynamically from JWKS endpoints or inserting them manually.
///
/// Typically used when your application needs to accept tokens from multiple providers
/// (e.g., multiple OpenID Connect issuers) or support multiple signing algorithms.
#[derive(Clone)]
pub struct Validator {
    // A mapping from composite key identifiers (`KeyID`) — usually derived from issuer and algorithm —
    // to the corresponding validation endpoint (`Endpoint`) containing the decoding key and validation rules.
    pubkeys: HashMap<KeyID, Endpoint>,

    // Default issuer URL, used by legacy or simplified decoding methods.
    // Note: this may not always be correct if your validator handles multiple issuers.
    default_iss: String,
}

fn parse_jwks(
    issuer: &str,
    jwks_json: &str,
    mut validation: Validation,
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
        validation.algorithms = vec![Algorithm::from_str(alg)?];
        keys.insert(key_id, Endpoint::new(validation.clone(), decoding_key));
    }

    Ok(keys)
}

impl Validator {
    /// Creates a new `Validator` from a single public key.
    ///
    /// This is useful when you already have a known key (for example, configured statically)
    /// and want to build a validator around it.
    ///
    /// * `url` - Issuer URL.
    /// * `audiance` - Expected audience claim (usually your client ID).
    /// * `algorithm` - Signing algorithm (e.g., "RS256").
    /// * `public_key` - Decoding key used to verify signatures.
    pub fn from_pubkey(
        url: String,
        audiance: String,
        algorithm: String,
        public_key: DecodingKey,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let pubkeys = HashMap::new();
        let algo = Algorithm::from_str(&algorithm)?;
        //let validation = Validation::new(algo);
        //validation.insecure_disable_signature_validation();
        let mut validator = Self {
            pubkeys,
            default_iss: url.clone(),
        };

        validator.insert_pubkey(url, audiance, algorithm, public_key)?;
        Ok(validator)
    }

    /// Creates a new `Validator` from an RSA PEM encoded public key.
    ///
    /// This is a convenience wrapper around `from_pubkey` that accepts a PEM string
    /// (PKCS#1 / PKCS#8 public key) and builds the `DecodingKey` for you.
    ///
    /// * `url` - Issuer URL (used to construct the KeyID).
    /// * `audiance` - Expected audience claim.
    /// * `algorithm` - Signing algorithm (e.g., "RS256").
    /// * `pem` - RSA public key in PEM format.
    pub fn from_rsa_pem(
        url: String,
        audiance: String,
        algorithm: String,
        pem: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let decoding_key = DecodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Self::from_pubkey(url, audiance, algorithm, decoding_key)
    }

    /// Returns a sorted list of unique algorithms supported for the given issuer,
    /// based on the pubkeys map.
    pub fn get_supported_algorithms_for_issuer(&self, issuer: &str) -> Option<Vec<String>> {
        let mut algs: Vec<String> = self
            .pubkeys
            .keys()
            .filter(|key_id| key_id.issuer == issuer)
            .map(|key_id| key_id.alg.clone())
            .collect();

        // Remove duplicates & sort
        algs.sort();
        algs.dedup();

        if algs.is_empty() { None } else { Some(algs) }
    }

    pub fn empty() -> Self {
        Self {
            pubkeys: HashMap::new(),
            default_iss: "".to_string(),
        }
    }

    /// Loads public keys dynamically from a JWKS endpoint discovered from provider metadata.
    ///
    /// Fetches the JWKS, parses it, and builds validation rules for each key.
    ///
    /// * `validation` - Template validation rules to apply for each key.
    /// * `provider_metadata` - OpenID Connect provider metadata (must include JWKS URI).
    /// * `issuer_url` - The expected issuer URL.
    pub async fn new(
        validation: Validation,
        provider_metadata: &CoreProviderMetadata,
        issuer_url: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let jwks_uri = provider_metadata.jwks_uri().to_string();

        let jwks_json = reqwest::get(jwks_uri).await?.text().await?;
        let keys = parse_jwks(&issuer_url, &jwks_json, validation.clone())?;
        Ok(Self {
            pubkeys: keys,
            default_iss: issuer_url,
        })
    }

    fn default_validation(
        url: &str,
        audiance: &str,
        algorithm: &str,
    ) -> Result<Validation, Box<dyn std::error::Error>> {
        let algo = Algorithm::from_str(&algorithm)?;
        let mut validation = Validation::new(algo);
        //validation.insecure_disable_signature_validation();
        {
            validation.leeway = 100; // Optionally, allow some leeway
            validation.validate_exp = true;
            validation.validate_aud = true;
            validation.validate_nbf = true;
            validation.aud = Some(hashset_from(vec![audiance.to_string()])); // The audience should match your client ID
            validation.iss = Some(hashset_from(vec![url.to_string()])); // Validate the issuer
            validation.algorithms = vec![algo];
        };

        Ok(validation)
    }

    /// Extends the validator by dynamically discovering and importing public keys (JWKS)
    /// from the OpenID Connect (OIDC) discovery endpoint of the given issuer.
    ///
    /// This method performs the following steps:
    /// 1. Initializes an HTTP client with redirect-following disabled for security reasons.
    /// 2. Fetches the OpenID Connect provider metadata from the issuer's well-known discovery endpoint.
    /// 3. Retrieves the JWKS (JSON Web Key Set) URI from the provider metadata.
    /// 4. Downloads the JWKS document and parses the keys.
    /// 5. Inserts the discovered keys into the validator's `pubkeys` map, associating them with the issuer.
    ///
    /// # Parameters
    /// - `issuer_url`: The base URL of the OIDC issuer (e.g., `https://accounts.example.com`).
    /// - `validation`: The validation params used for this endpoint (make sure iss, aud, alg are set correctly)
    /// # Returns
    /// - `Ok(())` if the keys were successfully fetched and added.
    /// - `Err(Box<dyn std::error::Error>)` if any network, parsing, or validation step fails.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The HTTP client could not be created.
    /// - The issuer URL is invalid.
    /// - The provider metadata discovery fails.
    /// - The JWKS document cannot be fetched or parsed.
    ///
    /// # Security
    /// - Redirects are explicitly disabled to prevent SSRF attacks when contacting the discovery endpoint.
    ///
    /// # Example
    /// ```ignore
    /// use rocket_oidc::client::Validator;
    /// let mut validator = Validator::empty();
    /// validator.extend_from_oidc("https://accounts.example.com").await?;
    /// ```
    pub async fn extend_from_oidc(
        &mut self,
        issuer_url: &str,
        audiance: &str,
        default_algorithm: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let http_client = match reqwest::ClientBuilder::new()
            // Following redirects opens the client up to SSRF vulnerabilities.
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(client) => client,
            Err(e) => return Err(Box::new(e)),
        };

        let provider_metadata = match CoreProviderMetadata::discover_async(
            IssuerUrl::new(issuer_url.to_string())?,
            &http_client,
        )
        .await
        {
            Ok(provider_metadata) => provider_metadata,
            Err(e) => return Err(Box::new(e)),
        };
        let validation = Self::default_validation(issuer_url, audiance, default_algorithm)?;

        let jwks_uri = provider_metadata.jwks_uri().to_string();
        let jwks_json = reqwest::get(jwks_uri).await?.text().await?;
        let keys = parse_jwks(&issuer_url, &jwks_json, validation.clone())?;
        for (key, value) in keys.into_iter() {
            self.pubkeys.insert(key, value);
        }
        Ok(())
    }

    /// Extends the validator by parsing and adding public keys from a JWKS JSON document
    /// associated with the given issuer.
    ///
    /// # Parameters
    /// - `issuer_url`: The base URL of the OIDC issuer (e.g., `https://accounts.example.com`).
    /// - `jwks_json`: The raw JWKS JSON string.
    ///
    /// # Returns
    /// - `Ok(())` if the keys were successfully parsed and added.
    /// - `Err(crate::Error)` if parsing fails.
    ///
    /// # Example
    /// ```ignore
    /// let mut validator = Validator::empty();
    /// let jwks_json = std::fs::read_to_string("keys.json")?;
    /// validator.extend_from_jwks("https://accounts.example.com", &jwks_json)?;
    /// ```
    pub fn extend_from_jwks(
        &mut self,
        issuer_url: &str,
        jwks_json: &str,
        validation: Validation,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Parse the keys, associating them with the issuer and current validation config
        let keys = parse_jwks(issuer_url, jwks_json, validation.clone())?;

        // Insert them into the validator's pubkeys map
        for (key_id, endpoint) in keys {
            self.pubkeys.insert(key_id, endpoint);
        }

        Ok(())
    }

    /// Inserts a new validation endpoint directly by its `KeyID`.
    ///
    /// Useful when you already constructed an `Endpoint` yourself.
    pub fn insert_endpoint(&mut self, keyid: KeyID, endpoint: Endpoint) {
        self.pubkeys.insert(keyid, endpoint);
    }

    /// Inserts a new public key and automatically builds its validation rules.
    ///
    /// * `url` - Issuer URL.
    /// * `audiance` - Expected audience claim.
    /// * `algorithm` - Signing algorithm.
    /// * `public_key` - Decoding key.
    pub fn insert_pubkey(
        &mut self,
        url: String,
        audiance: String,
        algorithm: String,
        public_key: DecodingKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let algo = Algorithm::from_str(&algorithm)?;
        let validation = Self::default_validation(&url, &audiance, &algorithm)?;

        let keyid = KeyID::new(&url, &algorithm);
        self.pubkeys
            .insert(keyid, Endpoint::new(validation, public_key));
        Ok(())
    }

    /// Decodes and validates an access token for a specific issuer and algorithm.
    ///
    /// * `issuer` - Issuer URL.
    /// * `algorithm` - Signing algorithm (e.g., "RS256").
    /// * `access_token` - The JWT string to decode.
    ///
    /// Returns the token's claims if valid, or an error otherwise.
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
            #[cfg(debug_assertions)]
            {
                let mut emptyvalidation = Validation::new(Algorithm::from_str(algorithm)?);
                emptyvalidation.validate_aud = false;
                emptyvalidation.validate_exp = false;
                emptyvalidation.validate_nbf = false;
                match jsonwebtoken::decode::<serde_json::Value>(
                    access_token,
                    &endpoint.pubkey,
                    &emptyvalidation,
                ) {
                    Ok(data) => {
                        eprintln!("DEBUG: Unvalidated token claims: {:#?}", data.claims);
                    }
                    Err(e) => {
                        eprintln!("DEBUG: Failed to decode unvalidated token: {:?}", e);
                    }
                }
            }
            Ok(decode::<T>(
                access_token,
                &endpoint.pubkey,
                &endpoint.validation,
            )?)
        } else {
            Err(Error::PubKeyNotFound(keyid))
        }
    }

    /// Decodes and validates an access token using the default issuer and a default algorithm ("RS256").
    ///
    /// ⚠️ **Deprecated:** May not be correct if you handle multiple issuers or algorithms.
    #[deprecated]
    pub fn decode<T: Serialize + Debug + DeserializeOwned + std::marker::Send + CoreClaims>(
        &self,
        access_token: &str,
    ) -> Result<TokenData<T>, crate::Error> {
        self.decode_with_iss_alg::<T>(&self.default_iss, "RS256", access_token)
    }
}

/// A high-level OpenID Connect (OIDC) client abstraction for performing common flows:
/// - Discovering provider metadata
/// - Exchanging authorization codes for tokens
/// - Fetching user information
/// - Performing token exchange
///
/// Internally, `OIDCClient` combines:
/// - An OpenID Connect client (`OpenIDClient`)
/// - A reqwest HTTP client (`reqwest::Client`)
/// - Local configuration (`WorkingConfig`)
///
/// This design allows dynamic discovery from OIDC configuration,
/// while keeping a ready-to-use validator for verifying ID tokens or access tokens.
#[derive(Debug, Clone)]
pub struct OIDCClient {
    // The OpenID Connect client instance, created from discovered provider metadata.
    pub client: OpenIDClient,

    // The reqwest HTTP client used for token and userinfo requests.
    reqwest_client: reqwest::Client,

    // Local, working configuration values (e.g., client ID, secret, redirect URL, issuer).
    config: WorkingConfig,
}

impl OIDCClient {
    /// Creates a new `OIDCClient` by dynamically discovering the provider metadata
    /// and preparing a `Validator` to verify tokens.
    ///
    /// This method:
    /// - Builds a safe reqwest HTTP client (with redirect following disabled).
    /// - Discovers the OpenID provider metadata from the issuer URL.
    /// - Constructs default validation rules (audience, issuer, leeway).
    /// - Loads the JWKS keys into a `Validator`.
    /// - Initializes the OpenID Connect client with the discovered metadata.
    ///
    /// # Arguments
    /// * `config` - High-level OIDC configuration.
    ///
    /// # Returns
    /// A tuple of:
    /// - `OIDCClient` (for performing login and userinfo flows)
    /// - `Validator` (for verifying ID tokens or access tokens)
    ///
    /// # Errors
    /// Returns an error if discovery fails, the JWKS endpoint cannot be fetched,
    /// or if the HTTP client cannot be built.
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

    /// Fetches user information from the provider's UserInfo endpoint.
    ///
    /// # Arguments
    /// * `access_token` - The access token obtained after login.
    /// * `subject` - Optionally, the subject (user ID) to query.
    ///
    /// # Returns
    /// The claims returned by the UserInfo endpoint.
    ///
    /// # Errors
    /// Returns an error if the request fails or the response is invalid.
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

    /// Exchanges an authorization code (received after user login) for a token response.
    ///
    /// # Arguments
    /// * `code` - The authorization code.
    ///
    /// # Returns
    /// The token response, including access token and optionally ID token or refresh token.
    ///
    /// # Errors
    /// Returns an error if the token request fails or the response is invalid.
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

    /// Performs OAuth2 token exchange to obtain a token scoped for a different audience.
    ///
    /// # Arguments
    /// * `subject_token` - The current access token or ID token.
    /// * `audience` - The target audience for the exchanged token.
    ///
    /// # Returns
    /// The token exchange response, containing the new token.
    ///
    /// # Errors
    /// Returns a reqwest error if the request fails.
    ///
    /// # Note
    /// I haven't tested this in a full flow.
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

    /// Like `from_oidc_config`, but allows the caller to provide a custom `Validation` template.
    ///
    /// This can be used to:
    /// - Disable signature verification for testing.
    /// - Adjust expiration leeway, audience, issuer, etc.
    /// - Support different algorithms.
    pub async fn from_oidc_config_with_validation(
        config: &OIDCConfig,
        custom_validation: Validation,
    ) -> Result<(Self, Validator), Box<dyn std::error::Error>> {
        let config = WorkingConfig::from_oidc_config(config).await?;
        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let provider_metadata =
            CoreProviderMetadata::discover_async(config.issuer_url.clone(), &http_client).await?;

        let validator = Validator::new(
            custom_validation,
            &provider_metadata,
            config.issuer_url.to_string(),
        )
        .await?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            config.client_id.clone(),
            Some(config.client_secret.clone()),
        )
        .set_redirect_uri(
            RedirectUrl::new(join_url(&config.redirect, "/auth/callback/").unwrap()).unwrap(),
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
}

/// this struct provides extra data stored in a cookie that's used to identify
/// which issuer provided the json web token so it can be properly constructed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerData {
    pub issuer: String,
    pub algorithm: String,
}
