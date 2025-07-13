# Rocket OpenID Connect (OIDC)
This crate provides OIDC authentication for rocket, and the routes needed to accomplish this goal.

This is a simple utility crate that provides a FromRequest implementation, including fetching user data.

## Supported Features
1. Handle Basic Authentication Claims
2. Request User Info for User Info EndPoint
3. Implement a FromRequest type to use in rocket routes.
4. Handle JavaScript Web Token Validation

### Supported OIDC Providers
1. Keycloak.

## Usage

```rust

use serde_derive::{Serialize, Deserialize};
use rocket::{catch, catchers, routes, launch, get};

use rocket::State;
use rocket::fs::FileServer;
use rocket::response::{Redirect, content::RawHtml};
use rocket_oidc::{OIDCConfig, CoreClaims, OIDCGuard};

#[non_exhaustive]
#[derive(Serialize, Deserialize, Debug)]
pub struct UserGuard {
    pub email: String,
    pub sub: String,
    pub picture: Option<String>,
    pub email_verified: Option<bool>,
}

impl CoreClaims for UserGuard {
    fn subject(&self) -> &str {
        self.sub.as_str()
    }
}

pub type Guard = OIDCGuard<UserGuard>;

#[catch(401)]
fn unauthorized() -> Redirect {
    Redirect::to("/")
}

#[get("/")]
async fn index() -> RawHtml<String> {
    RawHtml(format!("<h1>Hello World</h1>"))
}

#[get("/protected")]
async fn protected(guard: Guard) -> RawHtml<String> {
    let userinfo = guard.userinfo;
    RawHtml(format!("<h1>Hello {} {}</h1>", userinfo.given_name(), userinfo.family_name()))
}

#[launch]
async fn rocket() -> _ {
    let mut rocket = rocket::build()
        .mount("/", routes![index, use_api])
        .register("/", catchers![unauthorized]);
        
    rocket_oidc::setup(rocket, OIDCConfig::from_env().unwrap())
        .await
        .unwrap()
}
```

## Environment Setup

```sh
export ISSUER_URL="https://keycloak.com/realms/master" 
export CLIENT_ID="my_app_client_id"
export CLIENT_SECRET="/path/to/client/secret"
export REDIRECT_URI="http://callback_url.com/"
```

## Change Log
1. Refactor so OIDCConfig uses a path to secret rather than storing the secret itself.
2. Refactor to add client module, and make code more modular.
3. Added support for token exchange.
4. Fixed token expiration issue.
5. Refactor to allow for multiple identity providers.

## Security
This crate is not audited, and is very much as work in progress, as such its security cannot be garunteed.