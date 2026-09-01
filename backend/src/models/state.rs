use bollard::Docker;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

use reqwest::Client;
use serde_json::Value;

use crate::config::Config;
use crate::models::models::ActiveBan;

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub demo_mode: bool,
    pub history_db_path: String,
    pub public_target_ip: Arc<RwLock<String>>,
    pub geoip_reader: Arc<RwLock<Option<Arc<maxminddb::Reader<Vec<u8>>>>>>,
    pub asnip_reader: Arc<RwLock<Option<Arc<maxminddb::Reader<Vec<u8>>>>>>,
    pub attacks_cache: Arc<tokio::sync::Mutex<HashMap<String, CachedAttacks>>>,
    pub active_bans_cache: Arc<tokio::sync::Mutex<Option<CachedActiveBans>>>,
    pub client: Client,
    pub docker_client: Option<Arc<Docker>>,
}

#[derive(Clone)]
pub struct CachedAttacks {
    pub expires_at: Instant,
    pub payload: Value,
}

#[derive(Clone)]
pub struct CachedActiveBans {
    pub expires_at: Instant,
    pub items: Arc<Vec<ActiveBan>>,
}
