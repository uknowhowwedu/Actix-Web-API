use tokio_pg_mapper::FromTokioPostgresRow;
use deadpool_postgres::Client;
use actix_web::HttpResponse;
use rand::{thread_rng, Rng};
use postgres_types::Json;
use std::borrow::Borrow;
use crate::config;
use crate::models;
use crate::errors;
use crate::token;
use tokio::task;
use chrono::Utc;

fn create_hash(password: &String) -> (String, String) {
    let salt = password_hash::SaltString::generate(&mut rand_core::OsRng).to_string();
    let hash = argon2::hash_raw(password.as_bytes(), salt.as_bytes(), &config::ARGON2_CONFIG).unwrap();
    let db_form: String = hash
        .iter()
        .map(ToString::to_string)
        .collect();

    (db_form, salt)
}

fn match_hash(supplied_password: &String, db_password: &String, salt: &String) -> bool {
    let hash = argon2::hash_raw(supplied_password.as_bytes(), salt.as_bytes(), &config::ARGON2_CONFIG).unwrap();
    let db_form: String = hash
        .iter()
        .map(ToString::to_string)
        .collect();
    
    &db_form == db_password
}

async fn query_user(client: &Client, identifier: &models::api::Identifier) -> Result<models::db::User, tokio_postgres::Error> {
    match identifier {
        models::api::Identifier::Username(username) => {
            client.query_one(
                &String::from("SELECT * FROM main.users WHERE LOWER(username) = LOWER($1);"),
                &[&username]
            )
            .await
            .map(|row| models::db::User::from_row_ref(&row).unwrap())
        },
        models::api::Identifier::Uuid(uuid) => {
            client.query_one(
                &String::from("SELECT * FROM main.users WHERE id = $1;"),
                &[&uuid]
            )
            .await
            .map(|row| models::db::User::from_row_ref(&row).unwrap())
        }
    }
}

pub async fn auth(client: &Client, payload: models::api::Creds) -> Result<HttpResponse, errors::Error> {
    let user = query_user(client, &models::api::Identifier::Username(payload.username))
        .await
        .map_err(errors::db_error)?;

    if !user.banned {
        let res = task::spawn_blocking(move || {
            match_hash(&payload.password, &user.password.unwrap(), &user.salt.unwrap())
        })
        .await
        .unwrap();

        if res {
            let resp = models::api::Responses::Auth {
                success: true,
                access_token: token::create_jwt(&user.username, &user.acc_type, &user.id)
            };
            Ok(HttpResponse::Ok().json(resp))
        } else {
            Err(errors::Error::UserNotFound)
        }
    } else {
        Err(errors::Error::Banned)
    }
}

pub async fn register(client: &Client, payload: models::api::Creds, acc_type: &str) -> Result<HttpResponse, errors::Error> {
    let taken: bool = client.query_one(
        &String::from(
            "SELECT EXISTS(
                SELECT 1 FROM main.users WHERE LOWER(username) = LOWER($1)
            )"
            ), 
        &[
            &payload.username
        ]
    )
    .await
    .map_err(errors::db_error)?
    .get(0);

    if taken {
        Err(errors::Error::UsernameTaken)
    } else {
        let id = uuid::Uuid::new_v4();
        let hash_and_salt = task::spawn_blocking(move || {
            create_hash(&payload.password)
        })
        .await
        .unwrap();
        
        client.execute(
            &String::from(
                "INSERT INTO main.users (id, username, acc_type, password, salt, creation_date)
                VALUES ($1, $2, $3, $4, $5, $6);"
                ),
            &[
                &id,
                &payload.username,
                &acc_type,
                &hash_and_salt.0,
                &hash_and_salt.1,
                &Utc::now().timestamp()
            ]
        )
        .await
        .map_err(errors::db_error)?;

        if acc_type == "a" {
            client.execute(
                &String::from(
                    "INSERT INTO main.data (id)
                    VALUES ($1);"
                    ),
                &[
                    &id
                ]
            )
            .await
            .map_err(errors::db_error)?;

            let resp = models::api::Responses::RegisterAdmin {
                success: true
            };

            Ok(HttpResponse::Ok().json(resp))
        } else {
            let resp = models::api::Responses::Register {
                success: true,
                access_token: token::create_jwt(&payload.username, &String::from(acc_type), &id)
            };

            Ok(HttpResponse::Ok().json(resp))
        }
    }
}

pub async fn update_password(client: &Client, payload: models::api::Password, username: &String) -> Result<HttpResponse, errors::Error> {
    let user = query_user(client, &models::api::Identifier::Username(String::from(username)))
        .await
        .map_err(errors::db_error)?;

    let result = task::spawn_blocking(move || {
        if match_hash(&payload.password, &user.password.unwrap(), &user.salt.unwrap()) {
            Ok(create_hash(&payload.new_password))
        } else {
            Err(errors::Error::UserNotFound)
        }
    })
    .await
    .unwrap();

    match result {
        Ok(result) => {
            client.execute(
                &String::from(
                    "UPDATE main.users SET password = $1, SALT = $2
                    WHERE LOWER(username) = LOWER($3);"
                    ),
                &[
                    &result.0,
                    &result.1,
                    &username
                ]
            )
            .await
            .map_err(errors::db_error)?;

            let resp = models::api::Responses::NewPassword {
                success: true
            };
            Ok(HttpResponse::Ok().json(resp))
        },
        Err(result) => Err(result)
    }
}

// This function only serves a symbolic purpose
// Implementation for real transactions is absent
// There is no extensive validation for legal names, addresses, and card formats
// Implementation Resources: 
//     https://stripe.com/docs/api
//     https://stripe.com/docs/testing
pub async fn upgrade(client: &mut Client, payload: &models::api::Payment, username: &mut String, id: &uuid::Uuid) -> Result<HttpResponse, errors::Error> {
    //// Generation of tx_id is handled by Stripe. This is just a placeholder to maintain functionality of the route
    let mut rng = thread_rng();
    let tx_id = ["tx_", &rng.gen_range(10000..99999).to_string(),
                &id.to_string()[..6], 
                &id.to_string()[id.to_string().len()-6..]]
                .join("");
    //////////////////////////////////////////////////////

    let user = query_user(client, &models::api::Identifier::Username(std::mem::take(username)))             // Incase recently upgraded user interacts with the endpoint again with outdated "s" token (standard account) | Token Revocation Unimplemented
        .await
        .map_err(errors::db_error)?;

    match user.acc_type.as_str() {                                                                          // Incase recently upgraded user interacts with the endpoint again with outdated "s" token (standard account) | Token Revocation Unimplemented
        "s" => {
            
            // Stripe API implementation would go here
            // If successful transaction then execute the two queries below using the real tx_id
            // else return an error generated by Stripe

            let db_tx = client.transaction()
                .await
                .map_err(errors::transaction_error)?;

            db_tx.execute(
                &String::from(
                    "INSERT INTO main.transactions (tx_id, id, first_name, last_name, address, tx_timestamp)
                    VALUES ($1, $2, $3, $4, $5, $6);"
                    ),
                &[
                    &tx_id,
                    &id,
                    &payload.first_name,
                    &payload.last_name,
                    &payload.address,
                    &Utc::now().timestamp()
                ]
            )
            .await
            .map_err(errors::db_error)?;

            db_tx.execute(
                &String::from(
                    "UPDATE main.users SET acc_type = $1
                    WHERE id = $2;"
                    ),
                &[
                    &"u",
                    &id
                ]
            )
            .await
            .map_err(errors::db_error)?;

            db_tx.execute(
                &String::from(
                    "INSERT INTO main.data (id)
                    VALUES ($1);"
                    ),
                &[
                    &id
                ]
            )
            .await
            .map_err(errors::db_error)?;

            db_tx.commit()
                .await
                .map_err(errors::transaction_error)?;

            let resp = models::api::Responses::Upgrade {
                success: true,
                access_token: token::create_jwt(&user.username, &String::from("u"), id)
            };
            Ok(HttpResponse::Ok().json(resp))

        },
        _ => Err(errors::Error::Upgraded)
    }
}

pub async fn save(client: &Client, payload: models::api::Save, id: &uuid::Uuid, opt: &str) -> Result<HttpResponse, errors::Error> {
    client.execute(
        &format!(
            "UPDATE main.data SET save_{opt} = $1, timestamp_{opt} = $2
            WHERE id = $3;",
            opt = opt),
        &[
            &Json::<models::game::SaveData>(*payload.data),
            &Utc::now().timestamp(),
            &id
        ]
    )
    .await
    .map_err(errors::db_error)?;

    let resp = models::api::Responses::Save {
        success: true
    };
    Ok(HttpResponse::Ok().json(resp))
}

pub async fn load(client: &Client, id: &uuid::Uuid) -> Result<HttpResponse, errors::Error> {
    fn get_col(row: &tokio_postgres::row::Row, index: usize) -> Option<models::game::SaveData> {
        let json: Option<serde_json::Value> = row.get(index);
        match json {
            Some(json) => serde_json::from_value(json).unwrap(),
            None => None
        }
    }

    let row = client.query_one(
        &String::from(
            "SELECT save_one, save_two, save_three, timestamp_one, timestamp_two, timestamp_three
            FROM main.data
            WHERE id = $1;"
            ),
        &[
            &id
        ]
    )
    .await
    .map_err(errors::db_error)?;

    let game_data = models::db::Data {
        save_one: get_col(row.borrow(), 0),
        save_two: get_col(row.borrow(), 1),
        save_three: get_col(row.borrow(), 2),
        timestamp_one: row.get(3),
        timestamp_two: row.get(4),
        timestamp_three: row.get(5)
    };

    let resp = models::api::Responses::Load {
        data: Box::new(game_data)
    };
    Ok(HttpResponse::Ok().json(resp))
}

pub async fn get_users(client: &Client, page_num: i32) -> Result<HttpResponse, errors::Error> {
    let count = client.query_one(
        &String::from("SELECT COUNT(*) FROM main.users"), 
        &[]
    )
    .await
    .map_err(errors::db_error)?;

    let count: i64 = count.get(0);
    let pages = (count as f64 / 20_f64).ceil() as i32;
    if page_num <= pages {
        let offset = (page_num - 1) * 20_i32;
        let stmt = client.prepare_typed("SELECT * FROM main.users LIMIT 20 OFFSET $1;", &[tokio_postgres::types::Type::INT4])
            .await
            .unwrap();
        
        let page = client.query(
            &stmt, 
            &[&offset]
        )
        .await
        .unwrap()
        .iter()
        .map(|row| 
            models::db::User::from_row_ref(row)
                .unwrap()
                .displayable()
        )
        .collect::<Vec<models::db::User>>();

        let resp = models::api::Responses::Page {
            page: page_num,
            pages,
            count: page.len(),
            users: page
        };
        Ok(HttpResponse::Ok().json(resp))
    } else {
        Err(errors::Error::Page)
    }
}

pub async fn get_user(client: &Client, identifier: &models::api::Identifier) -> Result<HttpResponse, errors::Error> {
    let user = query_user(client, identifier)
        .await
        .map_err(errors::db_error)?
        .displayable();
    
    let resp = models::api::Responses::User {
        user
    };
    Ok(HttpResponse::Ok().json(resp))
}

pub async fn del_user(client: &Client, identifier: &models::api::Identifier) -> Result<HttpResponse, errors::Error> {
    let user = query_user(client, identifier)
        .await
        .map_err(errors::db_error)?;
    
    client.execute(
        &String::from(
            "DELETE FROM main.users
            WHERE id = $1;"
            ),
        &[
            &user.id
        ]
    )
    .await
    .map_err(errors::db_error)?;
    
    let resp = models::api::Responses::Delete {
        deleted: user.username,
        success: true
    };
    Ok(HttpResponse::Ok().json(resp))
}

pub async fn unban(client: &Client, identifier: &models::api::Identifier) -> Result<HttpResponse, errors::Error> {
    let user = query_user(client, identifier)
        .await
        .map_err(errors::db_error)?;
    
    if user.banned {
        client.execute(
            &String::from(
                "UPDATE main.users SET banned = $1, ban_date = $2
                WHERE id = $3;"
                ),
            &[
                &false,
                &None::<i64>,
                &user.id
            ]
        )
        .await
        .map_err(errors::db_error)?;

        let resp = models::api::Responses::Unban {
            unbanned: user.username,
            success: true
        };
        Ok(HttpResponse::Ok().json(resp))
    } else {
        Err(errors::Error::NotBanned)
    }
}

pub async fn ban(client: &Client, identifier: &models::api::Identifier) -> Result<HttpResponse, errors::Error> {
    let user = query_user(client, identifier)
        .await
        .map_err(errors::db_error)?;
    
    if !user.banned {
        client.execute(
            &String::from(
                "UPDATE main.users SET banned = $1, ban_date = $2
                WHERE id = $3;"
                ),
            &[
                &true,
                &Utc::now().timestamp(),
                &user.id
            ]
        )
        .await
        .map_err(errors::db_error)?;

        let resp = models::api::Responses::Ban {
            banned: user.username,
            success: true
        };
        Ok(HttpResponse::Ok().json(resp))
    } else {
        Err(errors::Error::PriorBan)
    }
}