use openidconnect::JsonWebKeyId;
use openidconnect::core::{CoreJsonCurveType, CoreJsonWebKey};

#[derive(Clone)]
pub enum PublicKeyMaterial {
    /// RSA key with modulus `n` and exponent `e`
    Rsa {
        n: Vec<u8>, // base64url-encoded modulus
        e: Vec<u8>, // base64url-encoded exponent
    },
    /// EC key with curve and coordinates
    Ec {
        crv: CoreJsonCurveType, // e.g. "P-256"
        x: Vec<u8>,             // base64url-encoded x coordinate
        y: Vec<u8>,             // base64url-encoded y coordinate
    },
    /// EdDSA (e.g., Ed25519)
    Okp {
        crv: CoreJsonCurveType, // e.g. "Ed25519"
        x: Vec<u8>,
    },
}

pub(crate) fn build_json_web_key(kid: String, material: PublicKeyMaterial) -> CoreJsonWebKey {
    let key_id = JsonWebKeyId::new(kid);

    match material {
        PublicKeyMaterial::Rsa { n, e, .. } => CoreJsonWebKey::new_rsa(n, e, Some(key_id)),
        PublicKeyMaterial::Ec { crv, x, y, .. } => CoreJsonWebKey::new_ec(x, y, crv, Some(key_id)),
        PublicKeyMaterial::Okp { crv, x, .. } => CoreJsonWebKey::new_okp(x, crv, Some(key_id)),
    }
}
