use jsonwebtoken::{decode, encode, Header, Algorithm, DecodingKey, EncodingKey, Validation};
use actix_web_httpauth::extractors::{bearer, AuthenticationError};
use serde::{Deserialize, Serialize};
use actix_web::dev::ServiceRequest;
use crate::config;
use chrono::Utc;

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub id: uuid::Uuid,
    pub user: String,
    pub role: String,
    pub iat: i64,
    pub exp: i64
}

pub fn create_jwt(username: &String, acc_type: &String, user_id: &uuid::Uuid) -> String {
    let claims = Claims {
        iss: String::from(&config::TOMLCONFIG.domain),
        id: *user_id,
        user: username.to_owned(),
        role: acc_type.to_owned(),
        iat: Utc::now().timestamp(),
        exp: Utc::now().timestamp() + config::TOMLCONFIG.token_duration
    };
    encode(&Header::new(Algorithm::HS256), &claims, &EncodingKey::from_secret(config::TOMLCONFIG.token_secret.as_ref())).unwrap()
}

pub fn decode_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 3;
    validation.set_issuer(&[&config::TOMLCONFIG.domain]);

    match decode::<Claims>(token, &DecodingKey::from_secret(config::TOMLCONFIG.token_secret.as_ref()), &validation) {
        Ok(jwt) => Ok(jwt.claims),
        Err(error) => Err(error) 
    }
}

pub async fn validator(req: ServiceRequest, auth: bearer::BearerAuth) -> Result<ServiceRequest, (actix_web::Error, ServiceRequest)> {
    match decode_jwt(auth.token()) {
        Ok(_) => Ok(req),
        Err(_) => {
            let config = req.app_data::<bearer::Config>()
                .cloned()
                .unwrap_or_default();
            Err((AuthenticationError::from(config).with_error_description("Invalid Token").into(), req))
        }
    }
}