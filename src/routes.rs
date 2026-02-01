use crate::AuthState;
use crate::BaseClaims;
use crate::OIDCKeyGuard;
use crate::check_expiration;
use crate::client::IssuerData;
use base64::Engine;
use hmac::{Hmac, Mac};
use openidconnect::RedirectUrl;
use openidconnect::{AuthenticationFlow, CsrfToken, Nonce, Scope};
use openidconnect::{AuthorizationCode, OAuth2TokenResponse, core::CoreResponseType};
use rocket::http::SameSite;
use rocket::http::{Cookie, CookieJar};
/// This Module will contain routes for 3pid verification through OIDC
use rocket::{Route, State, response::Redirect, routes};
use serde::Serialize;
use serde_derive::Deserialize;
use sha2::Sha256;
use std::borrow::Cow;
use std::time::{SystemTime, UNIX_EPOCH};
use time::OffsetDateTime;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize)]
struct CsrfState {
    r: Option<String>,
    iat: u64,
    exp: u64,
}

fn build_state(return_path: Option<String>, secret: &[u8]) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let payload = CsrfState {
        r: return_path,
        iat: now,
        exp: now + 300,
    };

    let json = serde_json::to_vec(&payload).unwrap();
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&json);

    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(payload_b64.as_bytes());

    let sig = mac.finalize().into_bytes();
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);

    format!("{payload_b64}.{sig_b64}")
}

#[deprecated]
#[get("/keycloak?<redirect>")]
pub async fn keycloak(auth_state: &State<AuthState>, redirect: Option<String>) -> Redirect {
    let state = build_state(redirect, &auth_state.hmac_secret);

    #[cfg(not(debug_assertions))]
    panic!(
        "this route is no longer supported on release builds, please use /auth/authorize instead"
    );
    #[cfg(debug_assertions)]
    eprintln!(
        "this function is enabled for debugging but should be replaced by /authorize as this route randomly chooses a provider to use"
    );

    let client_lock = auth_state.client.read().await;
    let client = client_lock.values().next().unwrap();
    let mut req = client
        .client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            || CsrfToken::new(state),
            Nonce::new_random,
        )
        // This example is requesting access to the the user's profile including email.
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()));

    let (authorize_url, _csrf_state, _nonce) = req.url();
    Redirect::to(authorize_url.to_string())
}

#[get("/authorize?<issuer_url>&<redirect>")]
pub async fn authorize(
    auth_state: &State<AuthState>,
    issuer_url: String,
    redirect: Option<String>,
) -> Redirect {
    let state = build_state(redirect, &auth_state.hmac_secret);
    let client = match auth_state.client_for(&issuer_url).await {
        Ok(lock) => lock,
        Err(e) => {
            panic!(
                "error occured trying to fetch client for issuer: {}",
                issuer_url
            );
        }
    };
    let mut req = client
        .client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            || CsrfToken::new(state),
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()));

    let (authorize_url, csrf_state, _nonce) = req.url();
    Redirect::to(authorize_url.to_string())
}

fn verify_state(state: &str, secret: &[u8]) -> Result<CsrfState, &'static str> {
    let (payload_b64, sig_b64) = state.split_once('.').ok_or("bad format")?;

    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| "bad payload")?;

    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| "bad sig")?;

    let mut mac = HmacSha256::new_from_slice(secret).unwrap();
    mac.update(payload_b64.as_bytes());
    mac.verify_slice(&sig).map_err(|_| "bad signature")?;

    let state: CsrfState = serde_json::from_slice(&payload).map_err(|_| "bad json")?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if now > state.exp {
        return Err("expired");
    }

    Ok(state)
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
    let state = verify_state(&state, &auth_state.hmac_secret)?;
    auth_state.handle_callback(jar, code, iss, state.r).await
}

pub fn get_routes() -> Vec<Route> {
    routes![authorize, callback, keycloak]
}
