use actix_web_httpauth::extractors::bearer::BearerAuth;
use actix_web::{web, get, post, delete, HttpResponse};
use deadpool_postgres::Pool;
use regex::Regex;
use crate::models;
use crate::errors;
use crate::token;
use chrono::Utc;
use crate::db;

// Case insensitive alphanumeric
// Allowed: '-' & '_' 
// Range: 3-15 Chars
fn validate_username(value: &str) -> Result<bool, errors::Error> {
    let re = Regex::new(r"^[a-z-A-Z-0-9-_]{3,15}$").unwrap();
    if re.is_match(value) {
        Ok(true)
    } else {
        Err(errors::Error::CredsFormat)
    }
}

// Require one uppercase letter, lowercase letter, number, and special character 
// Range: 10-30 Chars
fn validate_password(value: &str) -> Result<bool, errors::Error> {
    let re = Regex::new(r"^(.{0,9}|[^0-9]*|[^A-Z]*|[^a-z]*|[a-zA-Z0-9]*)$").unwrap();
    if !re.is_match(value) && value.len() <= 30 {
        Ok(true)
    } else {
        Err(errors::Error::CredsFormat)
    }
}

fn get_identifier(payload: &mut String) -> Result<models::api::Identifier, errors::Error> {
    match uuid::Uuid::try_parse(payload) {
        Ok(uuid) => Ok(models::api::Identifier::Uuid(uuid)),
        Err(_) => {
            validate_username(payload)?;
            Ok(models::api::Identifier::Username(std::mem::take(payload)))
        }
    }
}

// Route: /auth
#[post("/auth")]
async fn auth(payload: web::Json<models::api::Creds>, db_pool: web::Data<Pool>) -> Result<HttpResponse, errors::Error> {
    let creds: models::api::Creds = payload.into_inner();
    validate_username(&creds.username)
        .and(validate_password(&creds.password))?;

    let client = db_pool.get()
        .await
        .map_err(errors::pool_error)?;

    db::auth(&client, creds).await
}

// Route: /register
#[post("/register")]
async fn register(payload: web::Json<models::api::Creds>, db_pool: web::Data<Pool>) -> Result<HttpResponse, errors::Error> {
    let creds: models::api::Creds = payload.into_inner();
    validate_username(&creds.username)
        .and(validate_password(&creds.password))?;

    let client = db_pool.get()
        .await
        .map_err(errors::pool_error)?;

    db::register(&client, creds, "s").await
}

// Route: /utils/refresh
#[get("/refresh")]
async fn refresh(auth_header: BearerAuth) -> Result<HttpResponse, errors::Error> {
    let claims = token::decode_jwt(auth_header.token()).unwrap();
    if claims.exp - Utc::now().timestamp() <= 30 {
        let jwt = models::api::Responses::Jwt {
            access_token: token::create_jwt(&claims.user, &claims.role, &claims.id)
        };
        Ok(HttpResponse::Ok().json(jwt))
    } else {
        Err(errors::Error::TokenDuration)
    }
}

// utils/update_password
#[post("/update_password")]
async fn update_password(payload: web::Json<models::api::Password>, db_pool: web::Data<Pool>, auth_header: BearerAuth) -> Result<HttpResponse, errors::Error> {
    let passwords: models::api::Password = payload.into_inner();
    let claims = token::decode_jwt(auth_header.token()).unwrap();
    validate_password(&passwords.password)
        .and(validate_password(&passwords.new_password))?;
    
    let client = db_pool.get()
        .await
        .map_err(errors::pool_error)?;

    db::update_password(&client, passwords, &claims.user).await
}

/////////////////////////////////////////////////////////////////////////////////
// This route only serves a symbolic purpose
// Implementation for real transactions is absent
// There is no extensive validation for legal names, addresses, and card formats
// There are no specific errors returned for each noncompliant form
// Implementation Resources: 
//     https://stripe.com/docs/api
//     https://stripe.com/docs/testing
/////////////////////////////////////////////////////////////////////////////////

// Route: /utils/upgrade
#[post("/upgrade")]
async fn upgrade(payload: web::Json<models::api::Payment>, db_pool: web::Data<Pool>, auth_header: BearerAuth) -> Result<HttpResponse, errors::Error> {
    let payment_info: models::api::Payment = payload.into_inner();
    let re_name = Regex::new(r"^[a-z-A-Z]{1,50}$").unwrap();                    // Only chars                                      |  Range: 1-50
    let re_address = Regex::new(r"^[a-z-A-Z-0-9-,-.-\s]{1,125}$").unwrap();     // Only Chars, numbers, white space, ',', and '.'  |  Range: 1-125
    let re_cc_number = Regex::new(r"^[0-9]{13,16}$").unwrap();                  // Only numbers                                    |  Range: 13-16
    let re_cvc_number = Regex::new(r"^[0-9]{3,4}$").unwrap();                   // Only numbers                                    |  Range: 3-4
    let re_exp_month = Regex::new(r"(^1[0-2]$|^0[1-9]|^[1-9])$").unwrap();      // Only numbers                                    |  Range: 1-2 (Format: [1-9 or 01-09] and 10-12)
    let re_exp_year = Regex::new(r"^[0-9]{2}$").unwrap();                       // Only numbers                                    |  Length: 2
    
    let compliant = {
        re_name.is_match(&payment_info.first_name) && 
        re_name.is_match(&payment_info.last_name) && 
        re_address.is_match(&payment_info.address) &&
        re_cc_number.is_match(&payment_info.card_number) &&
        re_cvc_number.is_match(&payment_info.cvc) &&
        re_exp_month.is_match(&payment_info.exp_month) &&
        re_exp_year.is_match(&payment_info.exp_year)
    };
    
    if compliant {
        let mut claims = token::decode_jwt(auth_header.token()).unwrap();
        if claims.role == "s" {
            let mut client = db_pool.get()
                .await
                .map_err(errors::pool_error)?;
            db::upgrade(&mut client, &payment_info, &mut claims.user, &claims.id).await
        } else {
            Err(errors::Error::Upgraded)
        }
    } else {
        Err(errors::Error::PaymentDetails)
    }
}

// Route: /utils/save
#[post("/save")]
async fn save(payload: web::Json<models::api::Save>, db_pool: web::Data<Pool>, auth_header: BearerAuth) -> Result<HttpResponse, errors::Error> {
    let data: models::api::Save = payload.into_inner();
    let claims = token::decode_jwt(auth_header.token()).unwrap();
    if claims.role == "u" || claims.role == "a" {
       let opt = match data.opt {
            1 => "one",
            2 => "two",
            3 => "three",
            _ => return Err(errors::Error::InvalidOpt)
        };
        let client = db_pool.get()
            .await
            .map_err(errors::pool_error)?;
        db::save(&client, data, &claims.id, opt).await
    } else {
        Err(errors::Error::NotUpgraded)
    }
}

// Route: /utils/load
#[get("/load")]
async fn load(db_pool: web::Data<Pool>, auth_header: BearerAuth) -> Result<HttpResponse, errors::Error> {
    let claims = token::decode_jwt(auth_header.token()).unwrap();
    if claims.role == "u" || claims.role == "a" {
        let client = db_pool.get()
            .await
            .map_err(errors::pool_error)?;
        db::load(&client, &claims.id).await
    } else {
        Err(errors::Error::NotUpgraded)
    }
}

// Route: /admin/create
#[post("/create_admin")]
async fn create_admin(payload: web::Json<models::api::Creds>, db_pool: web::Data<Pool>, auth_header: BearerAuth) -> Result<HttpResponse, errors::Error> {
    let claims = token::decode_jwt(auth_header.token()).unwrap();
    if claims.role == "a" {
        let creds: models::api::Creds = payload.into_inner();
        validate_username(&creds.username)
            .and(validate_password(&creds.password))?;
        let client = db_pool.get()
            .await
            .map_err(errors::pool_error)?;
        db::register(&client, creds, "a").await
    } else {
        Err(errors::Error::NoPermission)
    }
}

// Route: /admin/users?page=Page Number
#[get("/users")]
async fn get_users(payload: web::Query<models::api::Page>, db_pool: web::Data<Pool>, auth_header: BearerAuth) -> Result<HttpResponse, errors::Error> {
    let claims = token::decode_jwt(auth_header.token()).unwrap();
    if claims.role == "a" {
        if payload.page > 0 {
            let client = db_pool.get()
                .await
                .map_err(errors::pool_error)?;
            db::get_users(&client, payload.page).await
        } else {
            Err(errors::Error::Parameter)
        }
    } else {
        Err(errors::Error::NoPermission)
    }
}

// Route: /admin/user?identifier=Username/UUID
#[get("/user")]
async fn get_user(mut payload: web::Query<models::api::User>, db_pool: web::Data<Pool>, auth_header: BearerAuth) -> Result<HttpResponse, errors::Error> {
    let claims = token::decode_jwt(auth_header.token()).unwrap();
    if claims.role == "a" {
        let identifier = get_identifier(&mut payload.identifier)
            .map_err(|_| errors::Error::CredsFormat)?;
        let client = db_pool.get()
            .await
            .map_err(errors::pool_error)?;
        db::get_user(&client, &identifier).await
    } else {
        Err(errors::Error::NoPermission)
    }
}

// Route: /admin/delete?identifier=Username/UUID
#[delete("/delete")]
async fn delete(mut payload: web::Query<models::api::User>, db_pool: web::Data<Pool>, auth_header: BearerAuth) -> Result<HttpResponse, errors::Error> {
    let claims = token::decode_jwt(auth_header.token()).unwrap();
    if claims.role == "a" {
        let identifier = get_identifier(&mut payload.identifier)
            .map_err(|_| errors::Error::CredsFormat)?;
        let client = db_pool.get()
            .await
            .map_err(errors::pool_error)?;
        db::del_user(&client, &identifier).await
    } else {
        Err(errors::Error::NoPermission)
    }
}

// Route: /admin/unban
#[post("/unban")]
async fn unban(mut payload: web::Json<models::api::User>, db_pool: web::Data<Pool>, auth_header: BearerAuth) -> Result<HttpResponse, errors::Error> {
    let claims = token::decode_jwt(auth_header.token()).unwrap();
    if claims.role == "a" {
        let identifier = get_identifier(&mut payload.identifier)
            .map_err(|_| errors::Error::CredsFormat)?;
        let client = db_pool.get()
            .await
            .map_err(errors::pool_error)?;
        db::unban(&client, &identifier).await
    } else {
        Err(errors::Error::NoPermission)
    }
}

// Route: /admin/ban
#[post("/ban")]
async fn ban(mut payload: web::Json<models::api::User>, db_pool: web::Data<Pool>, auth_header: BearerAuth) -> Result<HttpResponse, errors::Error> {
    let claims = token::decode_jwt(auth_header.token()).unwrap();
    if claims.role == "a" {
        let identifier = get_identifier(&mut payload.identifier)
            .map_err(|_| errors::Error::CredsFormat)?;
        let client = db_pool.get()
            .await
            .map_err(errors::pool_error)?;
        db::ban(&client, &identifier).await
    } else {
        Err(errors::Error::NoPermission)
    }
}