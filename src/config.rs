//! A module for handling configuration.
use crate::client::trim_trailing_whitespace;
use crate::errors::OIDCError;
use openidconnect::ClientId;
use secret_ref::{SecretError, SecretPolicy, SecretRef};
use serde_derive::{Deserialize, Serialize};

use std::env;
use std::path::PathBuf;

use openidconnect::{ClientSecret, IssuerUrl};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OIDCConfig {
    pub name: String,
    pub client_id: String,
    pub client_secret: SecretRef,
    pub issuer_url: String,
    pub redirect: String,
    pub post_login: Option<String>,
    pub privkey: Option<SecretRef>,
}

/// please note this is just an example, and should not be used in production builds
/// rather `from_env` should be used instead.
impl Default for OIDCConfig {
    fn default() -> OIDCConfig {
        Self {
            name: "Unnamed OIDC Provider".to_string(),
            client_id: "storyteller".to_string(),
            client_secret: "./secret".into(),
            issuer_url: "http://keycloak.com/realms/master".to_string(),
            redirect: "http://localhost:8000/".to_string(),
            post_login: None,
            privkey: None,
        }
    }
}

/// Represents configuration parameters for OpenID Connect authentication.
///
/// Typically loaded from environment variables at runtime.
impl OIDCConfig {
    /// Returns the URL to redirect to after login has completed.
    ///
    /// If `post_login` is set, returns its value; otherwise defaults to `/`.
    pub fn post_login(&self) -> &str {
        match &self.post_login {
            Some(url) => url,
            None => "/",
        }
    }

    pub fn privkey(&self) -> &Option<SecretRef> {
        &self.privkey
    }

    /// Constructs an `OIDCConfig` from environment variables.
    ///
    /// Required variables:
    /// - `CLIENT_ID`: The OAuth2 client identifier.
    /// - `CLIENT_SECRET`: The OAuth2 client secret.
    /// - `ISSUER_URL`: The base URL of the OpenID Connect issuer.
    ///
    /// Optional variable:
    /// - `REDIRECT_URL`: Redirect URI after login (defaults to `/profile` if unset).
    ///
    /// Returns an error if any required variable is missing.
    pub fn from_env() -> Result<Self, OIDCError> {
        let name = match env::var("OIDC_PROVIDER_NAME") {
            Ok(name) => name,
            _ => return Err(OIDCError::MissingProviderName),
        };
        let client_id = match env::var("CLIENT_ID") {
            Ok(client_id) => client_id,
            _ => return Err(OIDCError::MissingClientId),
        };
        let client_secret = match env::var("CLIENT_SECRET") {
            Ok(secret) => secret.into(),
            _ => return Err(OIDCError::MissingClientSecret),
        };
        let issuer_url = match env::var("ISSUER_URL") {
            Ok(url) => url,
            _ => return Err(OIDCError::MissingIssuerUrl),
        };

        let redirect = match env::var("REDIRECT_URL") {
            Ok(redirect) => redirect,
            _ => String::from("/profile"),
        };

        let privkey = match env::var("SIGNING_KEY") {
            Ok(secret) => Some(secret.into()),
            _ => None,
        };

        Ok(Self {
            name,
            client_id,
            client_secret,
            issuer_url,
            redirect,
            post_login: None,
            privkey,
        })
    }

    pub fn as_ref(&self) -> OIDCConfigRef<'_> {
        OIDCConfigRef {
            name: &self.name,
            client_id: &self.client_id,
            issuer_url: &self.issuer_url,
            redirect: &self.redirect,
            post_login: self.post_login.as_deref(),
        }
    }

    pub async fn try_load(&self) -> Result<WorkingConfig, OIDCError> {
        WorkingConfig::from_oidc_config(self).await
    }
}

async fn load_client_secret(secret: &SecretRef) -> Result<ClientSecret, SecretError> {
    let value = secret.fetch(SecretPolicy::default()).await?;
    let secret = trim_trailing_whitespace(value.expose());

    Ok(ClientSecret::new(secret))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OIDCConfigRef<'a> {
    pub name: &'a str,
    pub client_id: &'a str,
    pub issuer_url: &'a str,
    pub redirect: &'a str,
    pub post_login: Option<&'a str>,
}

impl<'a> OIDCConfigRef<'a> {
    /// Converts this borrowed `OIDCConfigRef` into an owned `OIDCConfig`.
    ///
    /// # Important
    ///
    /// The `client_secret` field of the resulting `OIDCConfig` is **intentionally left empty** (`PathBuf::new()`).
    /// This is because `OIDCConfigRef` does not contain the secret value.  
    /// If you need a `OIDCConfig` with a real secret, you must explicitly set it after calling `to_owned`,
    /// for example by loading it from a file or secret store.
    ///
    pub fn to_owned(&self) -> OIDCConfig {
        OIDCConfig {
            name: self.name.to_owned(),
            client_id: self.client_id.to_owned(),
            client_secret: SecretRef::File(PathBuf::new()),
            issuer_url: self.issuer_url.to_owned(),
            redirect: self.redirect.to_owned(),
            post_login: self.post_login.map(str::to_owned),
            privkey: None,
        }
    }
}

/// Configuration used internally by the OIDC client to manage static values.
///
/// Contains client credentials and metadata loaded from a higher-level `OIDCConfig`.
#[derive(Debug, Clone)]
pub struct WorkingConfig {
    pub(crate) name: String,
    pub(crate) client_secret: ClientSecret,
    pub(crate) client_id: ClientId,
    pub(crate) issuer_url: IssuerUrl,
    pub(crate) redirect: String,
    pub(crate) post_login: Option<String>,
}

/*impl TryFrom<&OIDCConfig> for WorkingConfig {
    type Error = OIDCError;
    fn try_from(config: &OIDCConfig) -> Result<WorkingConfig, Self::Error> {
        WorkingConfig::from_oidc_config(&config).await
    }
}

impl TryFrom<OIDCConfig> for WorkingConfig {
    type Error = OIDCError;
    fn try_from(config: OIDCConfig) -> Result<WorkingConfig, Self::Error> {
        (&config).try_into()
    }
}*/

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
    pub async fn from_oidc_config(config: &OIDCConfig) -> Result<Self, OIDCError> {
        let name = config.name.clone();
        let client_id = config.client_id.clone();
        let issuer_url = config.issuer_url.clone();

        let client_id = ClientId::new(client_id);
        let client_secret = load_client_secret(&config.client_secret).await?;
        let issuer_url = IssuerUrl::new(issuer_url)?;

        /*let session_config = if let Some(session) = &config.session {
            let signer = OidcSigner::from_config_path(&session.signing_key_path, "session-key")?;
            let iss = session.issuer_url.clone();
            let session_expiration_seconds = session.expiration_seconds.unwrap_or(3600);
            Some(WorkingSessionConfig::new(
                signer,
                iss,
                session_expiration_seconds,
            ))
        } else {
            None
        };*/

        Ok(Self {
            name,
            client_id,
            client_secret,
            issuer_url,
            redirect: config.redirect.clone(),
            post_login: config.post_login.clone(),
        })
    }

    /*
    pub fn session_config(&self) -> &Option<WorkingSessionConfig> {
        &self.session_config
    }

    pub fn session_provider(&self) -> Option<Validator> {
        if let Some(session) = &self.session_config {
            let keyid = KeyID::new(&session.issuer_url, "RS256");
            let decoding_key = session.signing_key.decoding_key();
            let mut validation = Validation::new(Algorithm::RS256);
            validation.validate_exp = true;
            validation.validate_aud = false;
            validation.validate_nbf = true;
            validation.leeway = 100;
            validation.iss = Some(hashset_from(vec![session.issuer_url.to_string()]));
            let mut validator = Validator::with_session(session.clone());
            validator.insert_endpoint(keyid, Endpoint::new(validation, decoding_key));
            Some(validator)
        } else {
            None
        }
    }*/
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns a borrowed `OIDCConfigRef` containing the non-secret fields of this config.
    ///
    /// # Important
    ///
    /// This method **intentionally omits** the `client_secret` field.  
    /// The resulting `OIDCConfigRef` is safe to pass to templates, logs, or other non-privileged contexts.  
    /// If you need access to the secret value, use the appropriate method on `OIDCConfig` (e.g., `load_client_secret`).
    ///
    pub fn as_oidc_config<'a>(&'a self) -> OIDCConfigRef<'a> {
        OIDCConfigRef {
            name: &self.name,
            issuer_url: self.issuer_url.as_str(),
            client_id: self.client_id.as_str(),
            redirect: &self.redirect,
            post_login: self.post_login.as_deref(),
        }
    }
    pub fn post_login(&self) -> &str {
        match &self.post_login {
            Some(url) => url,
            None => "/",
        }
    }
}
