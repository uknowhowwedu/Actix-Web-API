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
                    .route("/create_admin", web::post().to(routes::create_admin))
                    .route("/users", web::get().to(routes::get_users))
                    .route("/user", web::get().to(routes::get_user))
                    .route("/delete", web::delete().to(routes::delete))
                    .route("/unban", web::post().to(routes::unban))
                    .route("/ban", web::post().to(routes::ban))
            )
            .service(
                web::scope("/utils")
                    .wrap(jwt_auth.clone())
                    .guard(guard::All(guard::Header("Host", &config::TOMLCONFIG.domain)))
                    .route("/refresh", web::get().to(routes::refresh))
                    .route("/update_password", web::post().to(routes::update_password))
                    .route("/upgrade", web::post().to(routes::upgrade))
                    .route("/save", web::post().to(routes::save))
                    .route("/load", web::get().to(routes::load))
            )
            .service(
                web::scope("")
                    .guard(
                        guard::All(guard::Post())
                        .and(guard::Header("Host", &config::TOMLCONFIG.domain))
                        .and(guard::Header("content-type", "application/json"))
                    )
                    .route("/auth", web::post().to(routes::auth))
                    .route("/register", web::post().to(routes::register))
            )
    })
    .bind(("0.0.0.0", 80))?
    .workers(10)
    .run()
    .await
}