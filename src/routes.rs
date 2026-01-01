use crate::AuthState;
use crate::BaseClaims;
use crate::OIDCKeyGuard;
use crate::check_expiration;
use crate::client::IssuerData;
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
    auth_state.handle_callback(jar, code, iss).await
}

/// used for an API route to tell a server to fetch / load a refresh token for an access token.
pub async fn refresh(auth: &State<AuthState>, guard: OIDCKeyGuard<BaseClaims>) {
    
}

pub fn get_routes() -> Vec<Route> {
    routes![keycloak, callback]
}
