use lazy_static::lazy_static;
use serde::Deserialize;
use std::fs::File;
use std::io::Read;

#[derive(Deserialize)]
pub struct DbConfig {
    pub pg: deadpool_postgres::Config
}

impl DbConfig {
    pub fn from_env() -> Self {
        let config = config::Config::builder()
           .add_source(config::Environment::default().separator("__"))
           .build()
           .expect("Bad Database Environment Variables");
        config
            .try_deserialize()
            .expect("Bad Database Environment Variables")
    }
}

#[derive(Deserialize)]
pub struct TomlConfig {
    pub domain: String,
    #[serde(rename = "token-secret")]
    pub token_secret: String,
    #[serde(rename = "token-duration")]
    pub token_duration: i64,
    #[serde(rename = "token-leeway")]
    pub token_leeway: i64,
}

lazy_static! {
    pub static ref TOMLCONFIG: TomlConfig = {
        let mut file = File::open("Config.toml").unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();

        let config: TomlConfig = toml::from_str(&contents).unwrap();
        config
    };
}

pub const ARGON2_CONFIG: argon2::Config = argon2::Config {
    variant: argon2::Variant::Argon2d,
    version: argon2::Version::Version13,
    mem_cost: 32768, // 131072 128 Mb (460 ms) | 65536 64 Mb (240ms) | 32768 32 Mb (130ms)
    time_cost: 1,
    lanes: 8,
    thread_mode: argon2::ThreadMode::Parallel,
    secret: &[],
    ad: &[],
    hash_length: 64
};