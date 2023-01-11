use actix_web::{web, guard, App, HttpServer, ResponseError, error::InternalError};
use actix_web_httpauth::middleware::HttpAuthentication;

mod config;
mod routes;
mod models;
mod errors;
mod token;
mod db;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let pool = config::DbConfig::from_env()
        .pg.create_pool(None, tokio_postgres::NoTls)
        .unwrap();
    let jwt_auth = HttpAuthentication::bearer(token::validator);
    let json_cfg = web::JsonConfig::default()
        .limit(2048)
        .error_handler(|err, _req| {
            InternalError::from_response(err, errors::Error::Payload.error_response()).into()
        });
    let query_cfg = web::QueryConfig::default()
        .error_handler(|err, _req| {
            InternalError::from_response(err, errors::Error::Parameter.error_response()).into()
        });

    HttpServer::new(move || {
        App::new()
            .app_data(json_cfg.clone())
            .app_data(query_cfg.clone())
            .app_data(web::Data::new(pool.clone()))
            .service(
                web::scope("/admin")
                    .wrap(jwt_auth.clone())
                    .guard(guard::All(guard::Header("Host", &config::TOMLCONFIG.domain)))
                    .service(routes::create_admin).guard(guard::Post())
                    .service(routes::get_users).guard(guard::Get())
                    .service(routes::get_user).guard(guard::Get())
                    .service(routes::delete).guard(guard::Delete())
                    .service(routes::unban).guard(guard::Post())
                    .service(routes::ban).guard(guard::Post())
            )
            .service(
                web::scope("/utils")
                    .wrap(jwt_auth.clone())
                    .guard(guard::All(guard::Header("Host", &config::TOMLCONFIG.domain)))
                    .service(routes::refresh).guard(guard::Get())
                    .service(routes::update_password).guard(guard::Post())
                    .service(routes::upgrade).guard(guard::Post())
                    .service(routes::save).guard(guard::Post())
                    .service(routes::load).guard(guard::Get())
            )
            .service(
                web::scope("")
                    .guard(
                        guard::All(guard::Post())
                        .and(guard::Header("Host", &config::TOMLCONFIG.domain))
                        .and(guard::Header("content-type", "application/json"))
                    )
                    .service(routes::auth)
                    .service(routes::register)
            )
    })
    .bind(("0.0.0.0", 80))?
    .workers(10)
    .run()
    .await
}