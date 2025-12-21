use crate::AuthState;
use crate::BaseClaims;
use crate::client::IssuerData;
use cookie::Expiration;
use crate::check_expiration;
use openidconnect::{AuthenticationFlow, CsrfToken, Nonce, Scope};
use openidconnect::{AuthorizationCode, OAuth2TokenResponse, core::CoreResponseType};
use rocket::http::SameSite;
use rocket::http::{Cookie, CookieJar};
/// This Module will contain routes for 3pid verification through OIDC
use rocket::{Route, State, response::Redirect, routes};
use time::OffsetDateTime;

#[get("/keycloak")]
pub async fn keycloak(auth_state: &State<AuthState>) -> Redirect {
    let (authorize_url, _csrf_state, _nonce) = auth_state
        .client
        .client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // This example is requesting access to the the user's profile including email.
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();
    Redirect::to(authorize_url.to_string())
}

#[get("/callback?<code>&<state>&<iss>&<session_state>")]
pub async fn callback(
    jar: &CookieJar<'_>,
    auth_state: &State<AuthState>,
    code: String,
    state: String,
    session_state: String,
    iss: String,
) -> Result<Redirect, crate::errors::OIDCError> {
    // ── 1. Short-circuit if valid access_token is already there
    if let Some(cookie) = jar.get("access_token") {
        let (expiration, expired) = check_expiration(&cookie);
        if !expired {
            return Ok(Redirect::to(auth_state.config.post_login().to_string()));
        }
    }

    // ── 2. Exchange code for token
    let token = auth_state
        .client
        .exchange_code(AuthorizationCode::new(code))
        .await?;

    let expires_at: OffsetDateTime = match token.expires_in() {
        Some(expires_in) => OffsetDateTime::now_utc() + expires_in,
        None => {
            let token_data = auth_state
                .validator
                .decode::<BaseClaims>(token.access_token().secret())
                .unwrap();
            OffsetDateTime::from_unix_timestamp(token_data.claims.exp as i64)
                .unwrap_or_else(|_| OffsetDateTime::now_utc())
        }
    };

    // ── 3. Find matching algorithm from validator for this issuer
    let validator = &auth_state.validator;
    let supported_algs = validator
        .get_supported_algorithms_for_issuer(&iss)
        .ok_or_else(|| {
            eprintln!("unknown issuer: {}", iss);
            crate::errors::OIDCError::MissingIssuerUrl
        })?;

    // For this example: prefer RS256 if available, else pick the first supported
    let chosen_alg = if supported_algs.contains(&"RS256".to_string()) {
        "RS256".to_string()
    } else if let Some(first) = supported_algs.first() {
        first.clone()
    } else {
        return Err(crate::errors::OIDCError::MissingAlgoForIssuer(iss.into()));
    };

    // ── 4. Store access_token
    jar.add(
        Cookie::build(("access_token", token.access_token().secret().to_string()))
            .secure(false)
            .expires(expires_at)
            .http_only(true)
            .same_site(SameSite::Lax),
    );

    // ── 5. Store issuer_data JSON
    let issuer_data = IssuerData {
        issuer: iss,
        algorithm: chosen_alg,
    };
    let json = serde_json::to_string(&issuer_data).unwrap();

    jar.add(
        Cookie::build(("issuer_data", json))
            .secure(false)
            .expires(expires_at)
            .http_only(true)
            .same_site(SameSite::Lax),
    );

    Ok(Redirect::to(auth_state.config.post_login().to_string()))
}

pub fn get_routes() -> Vec<Route> {
    routes![keycloak, callback]
}
