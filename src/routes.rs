/// This Module will contain routes for 3pid verification through OIDC
use rocket::{response::Redirect, State};

use crate::AuthState;

use jsonwebtoken::*;
use openidconnect::core::*;
use openidconnect::core::{CoreGenderClaim, CoreResponseType};

use rocket::{
    http::{Cookie, CookieJar, Status},
    request::{FromRequest, Outcome},
    Request,
};

use openidconnect::reqwest;
use openidconnect::AdditionalClaims;
use openidconnect::*;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse, Scope,
};
use serde::{Deserialize, Serialize};

#[get("/keycloak")]
async fn keycloak(auth_state: &State<AuthState>) -> Redirect {
    let (authorize_url, csrf_state, nonce) = auth_state
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