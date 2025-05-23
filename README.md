# Rocket OpenID Connect (OIDC)
This crate provides OIDC authentication for rocket, and the routes needed to accomplish this goal.

This is a simple utility crate that provides a FromRequest implementation, including fetching user data.

## Usage

```rust

use storyteller::stories::{AccountBtn, StoryTitle};
use storyteller::ApiClient;
use rocket::State;
use rocket::fs::FileServer;
use rocket::response::{Redirect, content::RawHtml};
use rocket_dyn_templates::{Template, context};
use rocket_oidc::OIDCConfig;
use sled::Tree;
use std::str::FromStr;
use uuid::Uuid;

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
    RawHtml(foramt!("<h1>Hello {} {}</h1>", userinfo.given_name, userinfo.family_nameR))
}

use rocket_oidc::{OIDCConfig, }
#[launch]
async fn rocket() -> _ {
    let mut rocket = rocket::build()
        .manage(api)
        .mount("/", routes![index])
        .register("/", catchers![unauthorized])
        
    rocket_oidc::setup(rocket, OIDCConfig::from_env().unwrap())
        .await
        .unwrap()
}
```

## Environment Setup

```sh
export ISSUER_URL="https://keycloak.com/realms/master" 
export CLIENT_ID="my_app_client_id"
export CLIENT_SECRET="<my_super_secret_client_secret>"
export REDIRECT_URI="http://callback_url.com/"
```