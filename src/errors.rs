use actix_web::{HttpResponse, http::StatusCode, error::ResponseError};
use derive_more::Display;
use serde::Serialize;

#[derive(Serialize)]
struct Response {
    error: String,
}

#[derive(Debug, Display)]
pub enum Error {
    Pool,
    Page,
    Banned,
    Payload,
    Upgraded,
    PriorBan,
    NotBanned,
    Parameter,
    InvalidOpt,
    NotUpgraded,
    CredsFormat,
    UserNotFound,
    NoPermission,
    DBTransaction,
    UsernameTaken,
    TokenDuration,
    PaymentDetails,
    DbError(String)
}

impl Error {
    pub fn info(&self) -> String {
        match self {
            Self::Pool => String::from("Database Unreachable"),
            Self::Page => String::from("Nonexistent Page"),
            Self::Banned => String::from("Account Banned"),
            Self::Payload => String::from("Invalid Payload"),
            Self::Upgraded => String::from("Account Already Upgraded"),
            Self::Parameter => String::from("Invalid Parameter"),
            Self::InvalidOpt => String::from("Invalid Option"),
            Self::PriorBan => String::from("User Already Banned"),
            Self::NotBanned => String::from("User Is Not Banned"),
            Self::NotUpgraded => String::from("Account Is Not Upgraded"),
            Self::CredsFormat => String::from("Credential Format Requirements"),
            Self::DBTransaction => String::from("Interal Server Error"),
            Self::UserNotFound => String::from("Supplied Values Dont Match A User"),
            Self::NoPermission => String::from("Unauthorized"),
            Self::UsernameTaken => String::from("Username Taken"),
            Self::TokenDuration => String::from("Duration Not Met"),
            Self::PaymentDetails => String::from("Payment Details Formatting"),
            Self::DbError(code) => {
                [String::from("Database Error:"), code.to_owned()].join(" ")
            }
        }
    }
}

impl ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        match *self {
            Self::Pool => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Page => StatusCode::BAD_REQUEST,
            Self::Banned => StatusCode::UNAUTHORIZED,
            Self::Payload => StatusCode::BAD_REQUEST,
            Self::Upgraded => StatusCode::FORBIDDEN,
            Self::Parameter => StatusCode::BAD_REQUEST,
            Self::InvalidOpt => StatusCode::BAD_REQUEST,
            Self::PriorBan => StatusCode::BAD_REQUEST,
            Self::NotBanned => StatusCode::BAD_REQUEST,
            Self::NotUpgraded => StatusCode::FORBIDDEN,
            Self::CredsFormat => StatusCode::BAD_REQUEST,
            Self::DBTransaction => StatusCode::INTERNAL_SERVER_ERROR,
            Self::UserNotFound => StatusCode::UNAUTHORIZED,
            Self::NoPermission => StatusCode::FORBIDDEN,
            Self::UsernameTaken => StatusCode::BAD_REQUEST,
            Self::TokenDuration => StatusCode::BAD_REQUEST,
            Self::PaymentDetails => StatusCode::BAD_REQUEST,
            Self::DbError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn error_response(&self) -> HttpResponse {
        let error_response = Response {
            error: self.info(),
        };
        HttpResponse::build(self.status_code()).json(error_response)
    }
}

pub fn pool_error(_error: deadpool_postgres::PoolError) -> Error {
    Error::Pool
}

pub fn transaction_error(_error: tokio_postgres::Error) -> Error {
    Error::DBTransaction
}

pub fn db_error(error: tokio_postgres::error::Error) -> Error {
    if error.code().is_none() {
        Error::UserNotFound
    } else if error.code().unwrap() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION {
        Error::UsernameTaken
    } else {
        Error::DbError(String::from(error.code().unwrap().code()))
    }
}