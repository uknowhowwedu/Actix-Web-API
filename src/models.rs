pub mod game {
    use serde::{Serialize, Deserialize};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct SaveData {
        #[serde(rename = "player-can_dash")]
        player_can_dash: bool,
        #[serde(rename = "player-hp")]
        player_hp: f64,
        #[serde(rename = "player-x")]
        player_x: f64,
        #[serde(rename = "room0obj_weapon_light64672")]
        room0_obj_weapon_light64672: bool,
        #[serde(rename = "player-items")]
        player_items: Vec<Player>,
        #[serde(rename = "power-up-2")]
        power_up_2: bool,
        #[serde(rename = "player-equipped")]
        player_equipped: Player,
        room: String,
        #[serde(rename = "power-up-4")]
        power_up_4: bool,
        #[serde(rename = "player-y")]
        player_y: f64,
        #[serde(rename = "player-can_wall_jump")]
        player_can_wall_jump: bool,
        #[serde(rename = "power-up-3")]
        power_up_3: bool,
        #[serde(rename = "power-up-1")]
        power_up_1: bool
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Player {
        key: String,
        desc: String,
        bullet_type: f64,
        value: f64,
        #[serde(rename = "type")]
        player_type: f64,
        name: String,
    }
}

pub mod api {
    use crate::models::db::{Data, User as DbUser};
    use serde::{Serialize, Deserialize};
    use crate::models::game::SaveData;

    #[derive(Serialize)]
    #[serde(untagged)]
    pub enum Responses {
        Auth {
            success: bool,
            access_token: String
        },
        Register {
            success: bool,
            access_token: String
        },
        NewPassword {
            success: bool
        },
        Jwt {
            access_token: String
        },
        Upgrade {
            success: bool,
            access_token: String
        },
        Save {
            success: bool
        },
        Load {
            data: Box<Data>
        },
        Page {
            page: i32,
            pages: i32,
            count: usize,
            users: Vec<DbUser>
        },
        User {
            user: DbUser
        },
        Delete {
            deleted: String,
            success: bool
        },
        Unban {
            unbanned: String,
            success: bool
        },
        Ban {
            banned: String,
            success: bool
        }
    }

    #[derive(Deserialize, Serialize)]
    pub enum Identifier {
        Username(String),
        Uuid(uuid::Uuid)
    }

    #[derive(Deserialize)]
    pub struct User {
        pub identifier: String                              //Type: UUID or Username
    }

    #[derive(Deserialize)]
    pub struct Page {
        pub page: i32
    }

    #[derive(Deserialize)]
    pub struct Creds {
        pub username: String,
        pub password: String
    }

    #[derive(Deserialize)]
    pub struct Password {
        pub password: String,
        pub new_password: String
    }

    #[derive(Deserialize)]
    pub struct Payment {
        pub first_name: String,
        pub last_name: String,
        pub address: String,
        pub card_number: String,                            // This dosent get stored in DB
        pub cvc: String,                                    // This dosent get stored in DB
        pub exp_month: String,                              // This dosent get stored in DB
        pub exp_year: String                                // This dosent get stored in DB
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Save {
        pub opt: u8,                                        // Slot: 1, 2, or 3
        pub data: Box<SaveData>
    }
}

pub mod db {
    use tokio_pg_mapper_derive::PostgresMapper;
    use serde::{Serialize, Deserialize};
    use crate::models::game::SaveData;
    
    #[derive(Serialize)]
    pub struct Data {
        pub save_one: Option<SaveData>,
        pub save_two: Option<SaveData>,
        pub save_three: Option<SaveData>,
        pub timestamp_one: Option<i64>,
        pub timestamp_two: Option<i64>,
        pub timestamp_three: Option<i64>
    }

    #[derive(Serialize, Deserialize, PostgresMapper)]
    #[pg_mapper(table = "users")]
    pub struct User {
        pub id: uuid::Uuid,
        pub username: String,
        pub acc_type: String,                               // Standard: s, Upgraded: u, Admin: a
        #[serde(skip_serializing_if = "Option::is_none")]   // Never NULL in DB, only an Option to prevent disclosure of values when using get_user(s) routes
        pub password: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]   // Never NULL in DB, only an Option to prevent disclosure of values when using get_user(s) routes
        pub salt: Option<String>,
        pub creation_date: i64,
        pub banned: bool,
        pub ban_date: Option<i64>
    }

    impl User {
        pub fn displayable(mut self) -> Self {
            self.password = None;
            self.salt = None;
            self
        }
    }
}