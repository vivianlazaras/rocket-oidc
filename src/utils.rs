//! Convenience functions throughout the crate go here
use cookie::Expiration;
use time::OffsetDateTime;
use rocket::http::Cookie;

pub fn check_expiration(cookie: &Cookie<'_>) -> (Option<OffsetDateTime>, bool) {
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
