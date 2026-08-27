use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use reqwest::Client;
use serde_json::Value;

use crate::config::Config;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) config: Config,
    pub(crate) history_db_path: String,
    pub(crate) public_target_ip: String,
    pub(crate) geoip_reader: Arc<RwLock<Option<Arc<maxminddb::Reader<Vec<u8>>>>>>,
    pub(crate) attacks_cache: Arc<tokio::sync::Mutex<HashMap<String, CachedAttacks>>>,
    pub(crate) client: Client,
}

#[derive(Clone)]
pub(crate) struct CachedAttacks {
    pub(crate) expires_at: Instant,
    pub(crate) payload: Value,
}
