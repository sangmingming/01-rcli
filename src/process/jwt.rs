use anyhow::Result;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    aud: String,
    exp: u64,
}

pub fn process_jwt_generate(sub: String, aud: String, exp: u64) -> Result<String> {
    let claims = Claims {
        sub: sub.to_owned(),
        aud: aud.to_owned(),
        exp: exp.to_owned(),
    };
    let header = Header::new(Algorithm::HS256);
    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_secret("secret".as_ref()),
    )?;
    Ok(token)
}

pub fn process_jwt_verify(token: String, aud: String) -> Result<String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[aud]);
    let x = decode::<Claims>(
        &token,
        &DecodingKey::from_secret("secret".as_ref()),
        &validation,
    )?;
    Ok(format!(
        "sub: {} aud: {} exp: {}",
        x.claims.sub, x.claims.aud, x.claims.exp
    ))
}
