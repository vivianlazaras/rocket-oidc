/// This Module will contain routes for 3pid verification through OIDC
use rocket::{Route, State, response::Redirect, routes};

use crate::AuthState;
use openidconnect::{AuthorizationCode, OAuth2TokenResponse, core::CoreResponseType};

use rocket::http::{Cookie, CookieJar};

use openidconnect::{AuthenticationFlow, CsrfToken, Nonce, Scope};

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

#[get("/callback?<code>&<_state>")]
pub async fn callback(
    jar: &CookieJar<'_>,
    auth_state: &State<AuthState>,
    code: String,
    _state: String,
) -> Result<Redirect, crate::Error> {
    if let Some(_access_token) = jar.get("access_token") {
        // I should check to make sure the token hasn't expired
        Ok(Redirect::to(auth_state.config.redirect.clone()))
    } else {

        let token = auth_state
            .client
            .exchange_code(AuthorizationCode::new(code))
            .await?;

        jar.add(
            Cookie::build(("access_token", token.access_token().secret().to_string()))
                .expires(None),
        );
        Ok(Redirect::to(auth_state.config.redirect.clone()))
    }
}

pub fn get_routes() -> Vec<Route> {
    routes![keycloak, callback]
}
