/// This Module will contain routes for 3pid verification through OIDC
use rocket::{response::Redirect, State};

use crate::AuthState;

use openidconnect::{AuthorizationCode, OAuth2TokenResponse, core::CoreResponseType};

use rocket::http::{Cookie, CookieJar};

use openidconnect::{
    AuthenticationFlow, CsrfToken, Nonce, Scope,
};

#[get("/keycloak")]
pub async fn keycloak(auth_state: &State<AuthState>) -> Redirect {
    let (authorize_url, _csrf_state, _nonce) = auth_state
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

#[get("/callback?<code>&<state>")]
pub async fn callback(
    jar: &CookieJar<'_>,
    auth_state: &State<AuthState>,
    code: String,
    state: String,
) -> Redirect {
    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_else(|_err| {
            unreachable!();
        });

    let token = auth_state
        .client
        .exchange_code(AuthorizationCode::new(code))
        .unwrap()
        .request_async(&http_client)
        .await
        .unwrap_or_else(|_err| {
            unreachable!();
        });

    jar.add(
        Cookie::build(("access_token", token.access_token().secret().to_string())).expires(None),
    );
    Redirect::to("/profile/")
}