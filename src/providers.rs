use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OIDCProvider {
    pub name: String,
    pub issuer_url: String,
    /// raw bytes of the icon file.
    pub icon: Option<Vec<u8>>,
    pub brand_color: Option<String>,
}

impl OIDCProvider {
    pub fn new(name: String, issuer_url: String) -> Self {
        Self {
            name,
            issuer_url,
            icon: None,
            brand_color: None,
        }
    }

    pub fn icon(self, icon: Vec<u8>) -> Self {
        self.icon = Some(icon);
        self
    }

    pub fn brand_color(self, color: String) -> Self {
        self.brand_color = Some(color);
        self
    }


}

/// Preset OIDC providers
pub mod presets {
    use super::*;

    // Example placeholders for icons; replace with include_bytes!() if available
    const GOOGLE_ICON: &[u8] = include_bytes!("assets/google_button.svg");
    const MICROSOFT_ICON: &[u8] = include_bytes!("assets/microsoft_button.png");
    const GITHUB_ICON: &[u8] = include_bytes!("assets/github_button.png");
    const APPLE_ICON: &[u8] = include_bytes!("assets/apple_button.png");
    const FACEBOOK_ICON: &[u8] = include_bytes!("assets/meta_button.jpg");
    const LINKEDIN_ICON: &[u8] = include_bytes!("assets/linkedin_button.png");
    const KEYCLOAK_ICON: &[u8] = include_bytes!("assets/keycloak_button.svg");
    const GITLAB_ICON: &[u8] = include_bytes!("assets/gitlab_button.svg");
    const OKTA_ICON: &[u8] = include_bytes!("assets/okta_button.png");
    
    const AUTH0_ICON: &[u8] = include_bytes!("assets/auth0.png");

    /// Google OIDC provider preset
    pub fn google() -> OIDCProvider {
        OIDCProvider::new("Google", "https://accounts.google.com")
            .icon(GOOGLE_ICON.to_vec())
            .brand_color("#4285F4")
    }

    /// Microsoft / Azure OIDC provider preset
    pub fn microsoft() -> OIDCProvider {
        OIDCProvider::new("Microsoft", "https://login.microsoftonline.com/common/v2.0")
            .icon(MICROSOFT_ICON.to_vec())
            .brand_color("#0078D4")
    }

    /// GitHub OIDC provider preset
    pub fn github() -> OIDCProvider {
        OIDCProvider::new("GitHub", "https://github.com/login/oauth")
            .icon(GITHUB_ICON.to_vec())
            .brand_color("#181717")
    }

    /// Apple OIDC provider preset
    pub fn apple() -> OIDCProvider {
        OIDCProvider::new("Apple", "https://appleid.apple.com")
            .icon(APPLE_ICON.to_vec())
            .brand_color("#000000")
    }

    pub fn facebook() -> OIDCProvider {
        OIDCProvider::new("Facebook", "https://www.facebook.com/dialog/oauth")
            .icon(FACEBOOK_ICON.to_vec())
            .brand_color("#1877F2")
    }

    pub fn linkedin() -> OIDCProvider {
        OIDCProvider::new("LinkedIn", "https://www.linkedin.com/oauth/v2/authorization")
            .icon(LINKEDIN_ICON.to_vec())
            .brand_color("#0077B5")
    }

    // Enterprise / B2B
    pub fn okta() -> OIDCProvider {
        OIDCProvider::new("Okta", "https://{yourOktaDomain}/oauth2/default")
            .icon(OKTA_ICON.to_vec())
            .brand_color("#007DC1")
    }

    pub fn auth0() -> OIDCProvider {
        OIDCProvider::new("Auth0", "https://{yourAuth0Domain}/")
            .icon(AUTH0_ICON.to_vec())
            .brand_color("#EB5424")
    }

    pub fn keycloak() -> OIDCProvider {
        OIDCProvider::new("Keycloak", "https://{yourKeycloakDomain}/realms/{realm}")
            .icon(KEYCLOAK_ICON.to_vec())
            .brand_color("#AA2E25")
    }

    // Developer / Git providers
    pub fn gitlab() -> OIDCProvider {
        OIDCProvider::new("GitLab", "https://gitlab.com/oauth/authorize")
            .icon(GITLAB_ICON.to_vec())
            .brand_color("#FC6D26")
    }

    /// Return all presets as a vector
    pub fn all() -> Vec<OIDCProvider> {
        vec![
            google(),
            microsoft(),
            github(),
            apple(),
            facebook(),
            linkedin(),
            okta(),
            auth0(),
            keycloak(),
            gitlab(),
        ]
    }
}