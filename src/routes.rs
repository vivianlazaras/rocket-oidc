use crate::AuthState;
use crate::BaseClaims;
use cookie::Expiration;
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

fn check_expiration(cookie: &Cookie<'_>) -> (Option<OffsetDateTime>, bool) {
    match cookie.expires() {
        Some(Expiration::Session) => (None, false),
        Some(Expiration::DateTime(offset)) => {
            let ts = OffsetDateTime::now_utc();
            if offset > ts {
                return (Some(offset), false);
            } else {
                return (Some(offset), true);
            }
        }
        None => (None, false),
    }
}

#[get("/callback?<code>&<state>&<iss>&<session_state>")]
pub async fn callback(
    jar: &CookieJar<'_>,
    auth_state: &State<AuthState>,
    code: String,
    state: String,
    session_state: String,
    iss: String,
) -> Result<Redirect, crate::Error> {
    // ── 1.  If we already have a *non-expired* access_token cookie, short-circuit.
    if let Some(cookie) = jar.get("access_token") {
        let (expiration, expired) = check_expiration(&cookie);
        if !expired {
            return Ok(Redirect::to(auth_state.config.post_login().to_string()));
        }
    }

    // ── 2.  Exchange the authorization code for an access token.
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

            // Convert Unix timestamp (exp) to OffsetDateTime
            OffsetDateTime::from_unix_timestamp(token_data.claims.exp as i64)
                .unwrap_or_else(|_| OffsetDateTime::now_utc())
        }
    };

    // ── 4.  Store the access token in a cookie with an Expires attribute.
    jar.add(
        Cookie::build((
            "access_token",
            token.access_token().secret().to_string().to_owned(),
        ))
        .secure(false)
        .expires(expires_at)
        .http_only(true) // good practice
        .same_site(SameSite::Lax), // or SameSite::Strict, if you prefer
    );

    Ok(Redirect::to(auth_state.config.post_login().to_string()))
}

pub fn get_routes() -> Vec<Route> {
    routes![keycloak, callback]
}
