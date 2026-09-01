use std::collections::{HashMap, HashSet};
use std::env;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use axum::Router;
use axum::routing::get;
use bollard::Docker;
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use glob::glob;
use serde_json::{Value, json};
use std::io::Read;
use tokio::fs;
use tokio::sync::{Mutex, RwLock};
use tower_http::services::{ServeDir, ServeFile};

mod config;
mod crowdsec_api;
mod models;
mod utils;

use crate::crowdsec_api::{read_lapi_alerts, send_lapi_presence};
use crate::models::models::{ActiveBan, Alert};
use crate::utils::docker_client::{read_active_bans, read_cscli_alerts};
use crate::utils::logger;
use crate::utils::normaliser::normalize_alert_payload;
use crate::utils::normaliser::to_cidr24;
use crate::utils::normaliser::{expand_pattern, normalize_decisions_as_bans};
use crate::utils::os_tools::discover_public_ip;
pub use config::Config;
pub use models::state::{AppState, CachedAttacks};

const GEOIP_DATABASE_FILE: &str = "/app/data/dbip-country.mmdb";
const APP_VERSION: &str = "v0.5.0";
static STARTUP_TIMESTAMP: OnceLock<i64> = OnceLock::new();
const BRANCH_NAME: &str = match option_env!("BRANCH_NAME") {
    Some(val) => val,
    None => "main",
};
const REPO_URL: &str = "arman511/crowdsec-map";

#[tokio::main]
async fn main() {
    logger::init();

    let config = Config::from_env();
    crate::info!(
        port = config.port,
        data_source = %config.data_source,
        demo_mode = config.demo_mode,
        refresh_seconds = config.refresh_seconds,
        protection_refresh_seconds = config.protection_refresh_seconds,
        crowdsec_container = %config.crowdsec_container,
        lapi_url = %config.lapi_url,
        lapi_login_configured = !config.lapi_login.is_empty(),
        lapi_password_configured = !config.lapi_password.is_empty(),
        lapi_api_key_configured = !config.lapi_api_key.is_empty(),
        investigation_paths = ?config.investigation_log_paths,
        protection_paths = ?config.protection_log_paths,
        investigation_max_lines = config.investigation_max_lines,
        investigation_timeout_ms = config.investigation_timeout_ms,
        access_log_enabled = config.access_log_enabled,
        "runtime configuration loaded"
    );
    let client = reqwest::Client::builder()
        .user_agent(format!(
            "crowdsec-map/{APP_VERSION} {}",
            std::env::consts::OS
        ))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("http client");
    ensure_geoip_database(&config, &client).await;
    let initial_ip = discover_public_ip(&client).await;
    let public_target_ip = Arc::new(RwLock::new(initial_ip));

    let mut demo_mode = config.demo_mode
        || matches!(
            config.data_source.as_str(),
            "demo" | "demo-snapshot" | "sample"
        );

    let docker_client = match Docker::connect_with_local_defaults() {
        Ok(docker) => match docker.ping().await {
            Ok(_) => {
                crate::info!("Docker is available");
                Some(Arc::new(docker))
            }
            Err(err) => {
                crate::warn!(
                    error = %err,
                    "Docker daemon is unavailable; switching to demo mode"
                );

                demo_mode = true;
                None
            }
        },

        Err(err) => {
            crate::warn!(
                error = %err,
                "Docker connection could not be created; switching to demo mode"
            );

            demo_mode = true;
            None
        }
    };
    let state = AppState {
        config: config.clone(),
        demo_mode,
        history_db_path: config.history_database_file.clone(),
        public_target_ip: public_target_ip.clone(),
        geoip_reader: Arc::new(RwLock::new(load_geoip_reader(&config))),
        attacks_cache: Arc::new(Mutex::new(HashMap::new())),
        client: client.clone(),
        docker_client,
    };
    let client_clone = client.clone();
    let ip_clone = public_target_ip.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30 * 60));
        // Skip the first immediate tick since we already discovered it initially
        interval.tick().await;

        loop {
            interval.tick().await;
            let new_ip = discover_public_ip(&client_clone).await;
            if !new_ip.is_empty() {
                let mut writer = ip_clone.write().await;
                if *writer != new_ip {
                    crate::info!(
                        old_ip = %writer,
                        new_ip = %new_ip,
                        "Public IP updated successfully"
                    );
                    *writer = new_ip;
                }
            }
        }
    });

    let api = Router::new()
        .route("/health", get(crowdsec_api::api_health))
        .route("/attacks", get(crowdsec_api::api_attacks))
        .route("/bans", get(crowdsec_api::api_bans))
        .route("/history", get(crowdsec_api::api_history))
        .route("/history/group", get(crowdsec_api::api_history_group))
        .route("/history/ip/{ip}", get(crowdsec_api::api_history_ip))
        .route("/decisions", get(crowdsec_api::api_decisions))
        .route("/reputation/stats", get(crowdsec_api::api_reputation_stats))
        .route("/reputation/ip/{ip}", get(crowdsec_api::api_reputation_ip))
        .route(
            "/lapi/credentials/status",
            get(crowdsec_api::api_lapi_status),
        )
        .route(
            "/investigation/sources",
            get(crowdsec_api::api_investigation_sources),
        )
        .route(
            "/investigation/ip/{ip}",
            get(crowdsec_api::api_investigation_ip),
        )
        .route(
            "/investigation/ip/{ip}/log-lines",
            get(crowdsec_api::api_investigation_log_lines),
        )
        .route("/protection", get(crowdsec_api::api_protection))
        .route(
            "/system/update-status",
            get(crowdsec_api::api_update_status),
        )
        .route(
            "/access-log/summary",
            get(crowdsec_api::api_access_log_summary),
        );

    let static_dir = config.static_dir.clone();
    let app = Router::new()
        .nest("/api", api)
        .fallback_service(
            ServeDir::new(static_dir.clone())
                .not_found_service(ServeFile::new(format!("{static_dir}/index.html"))),
        )
        .with_state(state.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    crate::info!(port = config.port, "CrowdSec Map listening");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    let startup_state = state.clone();
    tokio::spawn(async move {
        initialize_history_db(&startup_state).await;
        crowdsec_api::refresh_protection_cache(&startup_state).await;
    });
    let refresh_state = state.clone();
    tokio::spawn(async move {
        let interval =
            std::time::Duration::from_secs(refresh_state.config.protection_refresh_seconds.max(1));
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            crowdsec_api::refresh_protection_cache(&refresh_state).await;
        }
    });
    let lapi_state = state.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        ticker.tick().await;
        loop {
            send_lapi_presence(&lapi_state).await;
            ticker.tick().await;
        }
    });
    let geoip_state = state.clone();
    let geoip_client = geoip_state.client.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(7 * 86_400));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            ensure_geoip_database(&geoip_state.config, &geoip_client).await;
            let mut current = geoip_state.geoip_reader.write().await;
            *current = load_geoip_reader(&config);
        }
    });
    axum::serve(listener, app).await.expect("server");
}

async fn ensure_geoip_database(_config: &Config, client: &reqwest::Client) {
    let path = GEOIP_DATABASE_FILE;
    let fresh = match fs::metadata(path)
        .await
        .and_then(|metadata| metadata.modified())
    {
        Ok(modified) => modified
            .elapsed()
            .map(|age| age < std::time::Duration::from_secs(7 * 86_400))
            .unwrap_or(false),
        Err(_) => false,
    };
    if fresh {
        crate::debug!(path, "GeoIP database is less than seven days old");
        return;
    }

    let url = env::var("GEOIP_DB_URL").unwrap_or_else(|_| {
        format!(
            "https://download.db-ip.com/free/dbip-country-lite-{}.mmdb.gz",
            Utc::now().format("%Y-%m")
        )
    });
    crate::info!(path, %url, "downloading GeoIP database");
    let response = match client.get(&url).send().await {
        Ok(response) => response,
        Err(err) => {
            crate::warn!(error = %err, "GeoIP database download failed; using existing data if available");
            return;
        }
    };
    if !response.status().is_success() {
        crate::warn!(status = %response.status(), "GeoIP database download returned an error; using existing data if available");
        return;
    }
    let compressed = match response.bytes().await {
        Ok(bytes) if bytes.len() > 1024 => bytes,
        Ok(_) => {
            crate::warn!("GeoIP database download was unexpectedly small; keeping existing data");
            return;
        }
        Err(err) => {
            crate::warn!(error = %err, "GeoIP database response could not be read; using existing data if available");
            return;
        }
    };
    let bytes = match GzDecoder::new(compressed.as_ref())
        .bytes()
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(bytes) if bytes.len() > 1024 => bytes,
        Ok(_) => {
            crate::warn!(
                "decompressed GeoIP database was unexpectedly small; keeping existing data"
            );
            return;
        }
        Err(err) => {
            crate::warn!(error = %err, "GeoIP database archive could not be decompressed; using existing data if available");
            return;
        }
    };
    if let Some(parent) = Path::new(path).parent()
        && let Err(err) = fs::create_dir_all(parent).await
    {
        crate::warn!(path, error = %err, "unable to create GeoIP database directory");
        return;
    }
    let temporary_path = format!("{path}.download");
    if let Err(err) = fs::write(&temporary_path, &bytes).await {
        crate::warn!(path = %temporary_path, error = %err, "unable to write downloaded GeoIP database");
        return;
    }
    if let Err(err) = fs::rename(&temporary_path, path).await {
        crate::warn!(path, error = %err, "unable to activate downloaded GeoIP database");
        let _ = fs::remove_file(&temporary_path).await;
        return;
    }
    crate::info!(path, bytes = bytes.len(), "GeoIP database updated");
}

fn load_geoip_reader(_config: &Config) -> Option<Arc<maxminddb::Reader<Vec<u8>>>> {
    match maxminddb::Reader::open_readfile(GEOIP_DATABASE_FILE) {
        Ok(reader) => {
            crate::info!(path = GEOIP_DATABASE_FILE, "GeoIP database loaded");
            Some(Arc::new(reader))
        }
        Err(err) => {
            crate::warn!(path = GEOIP_DATABASE_FILE, error = %err, "GeoIP database unavailable; decision countries will use alert history");
            None
        }
    }
}

async fn initialize_history_db(state: &AppState) {
    crate::info!(path = %state.history_db_path, "initializing history database");
    if let Some(parent) = Path::new(&state.history_db_path).parent()
        && let Err(err) = fs::create_dir_all(parent).await
    {
        crate::error!(path = %parent.display(), error = %err, "unable to create history database directory");
        return;
    }
    let initialized = match open_history_connection(state) {
        Ok(conn) => {
            crate::info!(path = %state.history_db_path, "history database opened");
            if let Err(err) = conn.execute(
            r#"CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                seen_at TEXT NOT NULL,
                seen_at_ms INTEGER NOT NULL,
                ip TEXT NOT NULL,
                cidr24 TEXT NOT NULL,
                as_name TEXT NOT NULL DEFAULT '',
                country TEXT NOT NULL DEFAULT '??',
                scenario TEXT NOT NULL DEFAULT 'unknown',
                event_count INTEGER NOT NULL DEFAULT 1
            )"#,
            (),
            ).and_then(|_| conn.execute(
                "CREATE TABLE IF NOT EXISTS protection_cache (days INTEGER PRIMARY KEY, generated_at_ms INTEGER NOT NULL, expires_at_ms INTEGER NOT NULL, payload TEXT NOT NULL)",
                (),
            )).and_then(|_| conn.execute(
                "CREATE TABLE IF NOT EXISTS protection_scan_files (path TEXT PRIMARY KEY, bytes INTEGER NOT NULL, modified_ms INTEGER NOT NULL)",
                (),
            )) {
                crate::error!(path = %state.history_db_path, error = %err, "unable to initialize history database");
                false
            } else {
                true
            }
        }
        Err(err) => {
            crate::error!(path = %state.history_db_path, error = %err, "unable to open history database; check /app/data volume permissions");
            false
        }
    };
    if initialized {
        let (alerts, source, warning) = read_crowdsec_data(state, "auto").await;
        crate::info!(source = %source, alerts = alerts.len(), warning = %warning, "startup history ingestion completed");
        record_history(state, &alerts).await;
    }
}

fn open_history_connection(state: &AppState) -> rusqlite::Result<rusqlite::Connection> {
    rusqlite::Connection::open(&state.history_db_path)
}

async fn read_crowdsec_data(state: &AppState, source: &str) -> (Vec<Alert>, String, String) {
    let configured = if source == "auto" {
        state.config.data_source.as_str()
    } else {
        source
    };
    let configured = match configured {
        "sample" | "demo-snapshot" => "demo",
        configured => configured,
    };
    let candidates = if configured == "auto" {
        vec!["lapi-alerts", "cscli", "demo"]
    } else {
        vec![configured]
    };
    crate::debug!(requested_source = %source, configured_source = %configured, candidates = ?candidates, "starting CrowdSec data load");
    let mut warnings = Vec::new();
    for candidate in candidates {
        crate::debug!(candidate, "trying CrowdSec data source");
        match candidate {
            "demo" => {
                let alerts = read_demo_snapshot_alerts(state)
                    .await
                    .unwrap_or_else(sample_alerts);
                crate::info!(
                    source = candidate,
                    alerts = alerts.len(),
                    "CrowdSec data source loaded"
                );
                return (alerts, "demo".to_string(), warnings.join(" | "));
            }
            "cscli" => {
                if let Some(alerts) = read_cscli_alerts(state).await {
                    crate::info!(
                        source = candidate,
                        alerts = alerts.len(),
                        "CrowdSec data source loaded"
                    );
                    return (alerts, "cscli".to_string(), warnings.join(" | "));
                }
                crate::warn!(source = candidate, "CrowdSec data source returned no data");
                warnings.push("cscli: failed to read alerts".to_string());
            }
            "lapi-alerts" => {
                if let Some(alerts) = read_lapi_alerts(state).await {
                    crate::info!(
                        source = candidate,
                        alerts = alerts.len(),
                        "CrowdSec data source loaded"
                    );
                    return (alerts, "lapi-alerts".to_string(), warnings.join(" | "));
                }
                crate::warn!(source = candidate, "CrowdSec data source returned no data");
                warnings.push("lapi-alerts: failed to read alerts".to_string());
            }
            _ => {}
        }
    }
    (
        sample_alerts(),
        "demo".to_string(),
        if warnings.is_empty() {
            "No data source returned data".to_string()
        } else {
            warnings.join(" | ")
        },
    )
}

async fn read_demo_snapshot_alerts(state: &AppState) -> Option<Vec<Alert>> {
    let text = fs::read_to_string(&state.config.demo_snapshot_file)
        .await
        .ok()?;
    let payload: Value = serde_json::from_str(&text).ok()?;
    Some(normalize_alert_payload(&payload, "demo"))
}

fn sample_alerts() -> Vec<Alert> {
    let now = Utc::now();
    vec![
        Alert {
            id: "sample-1".to_string(),
            ip: "45.155.205.233".to_string(),
            country: "RU".to_string(),
            city: "Moscow".to_string(),
            latitude: Some(55.7558),
            longitude: Some(37.6173),
            scenario: "crowdsecurity/ssh-bf".to_string(),
            decision_type: "ban".to_string(),
            value: "45.155.205.233".to_string(),
            created_at: (now - chrono::Duration::minutes(8)).to_rfc3339(),
            count: 8,
            as_name: "".to_string(),
            origin: "crowdsec".to_string(),
            scope: "Ip".to_string(),
            duration: "".to_string(),
            until: "".to_string(),
        },
        Alert {
            id: "sample-2".to_string(),
            ip: "185.220.101.31".to_string(),
            country: "DE".to_string(),
            city: "Frankfurt".to_string(),
            latitude: Some(50.1109),
            longitude: Some(8.6821),
            scenario: "crowdsecurity/http-probing".to_string(),
            decision_type: "captcha".to_string(),
            value: "185.220.101.31".to_string(),
            created_at: (now - chrono::Duration::minutes(18)).to_rfc3339(),
            count: 4,
            as_name: "".to_string(),
            origin: "crowdsec".to_string(),
            scope: "Ip".to_string(),
            duration: "".to_string(),
            until: "".to_string(),
        },
    ]
}

async fn record_history(state: &AppState, alerts: &[Alert]) {
    let conn = match open_history_connection(state) {
        Ok(c) => c,
        Err(err) => {
            crate::error!(error = %err, "unable to open history database for alert recording");
            return;
        }
    };
    let mut inserted = 0;
    for alert in alerts {
        let seen_at = if alert.created_at.is_empty() {
            Utc::now().to_rfc3339()
        } else {
            alert.created_at.clone()
        };
        let seen_ms = DateTime::parse_from_rfc3339(&seen_at)
            .map(|d| d.timestamp_millis())
            .unwrap_or_else(|_| Utc::now().timestamp_millis());
        match conn.execute(
            "INSERT OR IGNORE INTO alerts (id, seen_at, seen_at_ms, ip, cidr24, as_name, country, scenario, event_count) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            [
                alert.id.clone(),
                seen_at,
                seen_ms.to_string(),
                alert.ip.clone(),
                to_cidr24(&alert.ip),
                alert.as_name.clone(),
                if alert.country.is_empty() { "??".to_string() } else { alert.country.clone() },
                if alert.scenario.is_empty() { "unknown".to_string() } else { alert.scenario.clone() },
                alert.count.to_string(),
            ],
        ) {
            Ok(count) => inserted += count,
            Err(err) => crate::warn!(alert_id = %alert.id, ip = %alert.ip, error = %err, "unable to record alert in history"),
        }
    }
    let cutoff =
        Utc::now().timestamp_millis() - (state.config.history_retention_days as i64) * 86_400_000;
    let pruned = conn
        .execute(
            "DELETE FROM alerts WHERE seen_at_ms < ?1",
            [cutoff.to_string()],
        )
        .unwrap_or_else(|err| {
            crate::warn!(error = %err, "unable to prune alert history");
            0
        });
    crate::info!(
        alerts_received = alerts.len(),
        rows_inserted = inserted,
        rows_pruned = pruned,
        "alert history recording completed"
    );
}

async fn read_demo_decisions(state: &AppState) -> Vec<ActiveBan> {
    let text = fs::read_to_string(&state.config.demo_snapshot_file)
        .await
        .unwrap_or_default();
    if let Ok(payload) = serde_json::from_str::<Value>(&text)
        && let Some(decisions) = payload.get("decisions")
    {
        return normalize_decisions_as_bans(decisions);
    }
    Vec::new()
}

async fn read_active_bans_for_ip(state: &AppState, ip: &str) -> Value {
    let items = read_active_bans(state)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter(|x| x.ip == ip || x.value == ip)
        .collect::<Vec<_>>();
    let since = items
        .iter()
        .filter_map(|x| {
            if x.created_at.is_empty() {
                None
            } else {
                Some(x.created_at.clone())
            }
        })
        .min()
        .unwrap_or_default();
    let remaining = items
        .iter()
        .map(|x| x.duration.clone())
        .find(|x| !x.is_empty())
        .unwrap_or_default();
    json!({
        "count": items.len(),
        "since": since,
        "remaining": remaining,
        "items": items
    })
}

fn build_totals(alerts: &[Alert], active_bans: i64) -> Value {
    let countries = alerts
        .iter()
        .map(|x| x.country.clone())
        .filter(|x| !x.is_empty())
        .collect::<HashSet<_>>()
        .len();
    let scenarios = alerts
        .iter()
        .map(|x| x.scenario.clone())
        .filter(|x| !x.is_empty())
        .collect::<HashSet<_>>()
        .len();
    let bans = alerts.iter().filter(|x| x.decision_type == "ban").count();
    json!({
        "alerts": alerts.len(),
        "countries": countries,
        "scenarios": scenarios,
        "bans": bans,
        "activeBans": active_bans
    })
}

fn group_counts_json(alerts: &[Alert], field: &str, limit: usize) -> Vec<Value> {
    let mut map: HashMap<String, i64> = HashMap::new();
    for alert in alerts {
        let key = match field {
            "country" => alert.country.clone(),
            "scenario" => alert.scenario.clone(),
            _ => String::new(),
        };
        let key = if key.is_empty() {
            "unknown".to_string()
        } else {
            key
        };
        *map.entry(key).or_insert(0) += 1;
    }
    map_counts(map, limit)
}

fn map_counts(map: HashMap<String, i64>, limit: usize) -> Vec<Value> {
    let mut items = map
        .into_iter()
        .map(|(label, count)| json!({"label": label, "count": count}))
        .collect::<Vec<_>>();
    items.sort_by(|a, b| {
        b["count"]
            .as_i64()
            .unwrap_or(0)
            .cmp(&a["count"].as_i64().unwrap_or(0))
    });
    items.truncate(limit);
    items
}

fn count_decision_field<F>(items: &[ActiveBan], accessor: F) -> Vec<Value>
where
    F: Fn(&ActiveBan) -> String,
{
    let mut map: HashMap<String, i64> = HashMap::new();
    for item in items {
        let key = accessor(item);
        if key.is_empty() {
            continue;
        }
        *map.entry(key).or_insert(0) += 1;
    }
    map_counts(map, 8)
}

fn decision_field(item: &ActiveBan, field: &str) -> String {
    match field {
        "value" => {
            if item.value.is_empty() {
                item.ip.clone()
            } else {
                item.value.clone()
            }
        }
        "ip" => item.ip.clone(),
        "scope" => item.scope.clone(),
        "country" => item.country.clone(),
        "scenario" => item.scenario.clone(),
        "origin" => item.origin.clone(),
        "duration" => {
            if item.duration.is_empty() {
                item.until.clone()
            } else {
                item.duration.clone()
            }
        }
        "until" => item.until.clone(),
        _ => String::new(),
    }
}

async fn resolve_log_sources(patterns: &[String]) -> Vec<Value> {
    let mut files = Vec::new();
    let mut seen = HashSet::new();
    for pattern in patterns {
        let absolute = expand_pattern(pattern);
        crate::debug!(pattern = %pattern, expanded_pattern = %absolute, "discovering log source");
        if let Ok(paths) = glob(&absolute) {
            for entry in paths {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(err) => {
                        crate::warn!(pattern = %absolute, error = %err, "unable to inspect log source match");
                        continue;
                    }
                };
                if !entry.is_file() {
                    crate::debug!(path = %entry.display(), "ignoring non-file log source match");
                    continue;
                }
                let canonical = std::fs::canonicalize(&entry).unwrap_or_else(|_| entry.clone());
                let key = canonical.to_string_lossy().to_string();
                if seen.insert(key.clone()) {
                    crate::debug!(path = %key, pattern = %pattern, "log source discovered");
                    let name = entry
                        .file_name()
                        .and_then(|x| x.to_str())
                        .unwrap_or("log")
                        .to_string();
                    files.push(json!({
                        "name": name,
                        "path": key,
                        "location": "CrowdSec Map container"
                    }));
                }
            }
        }
    }
    files.sort_by(|a, b| {
        let a_path = a["path"].as_str().unwrap_or("");
        let b_path = b["path"].as_str().unwrap_or("");
        let a_is_current = !a_path.ends_with(".gz");
        let b_is_current = !b_path.ends_with(".gz");
        b_is_current
            .cmp(&a_is_current)
            .then_with(|| b_path.cmp(a_path))
    });
    crate::info!(
        configured_patterns = patterns.len(),
        discovered_files = files.len(),
        "log source discovery completed"
    );
    files
}

async fn read_cti_cache(state: &AppState) -> Value {
    let path = Path::new(&state.config.cti_cache_file);
    if let Ok(text) = fs::read_to_string(path).await
        && let Ok(value) = serde_json::from_str::<Value>(&text)
    {
        return value;
    }
    let period = Utc::now().format("%Y-%m").to_string();
    json!({
        "version": 1,
        "items": {},
        "stats": {
            "period": period,
            "networkRequests": 0,
            "cacheHits": 0
        }
    })
}

fn bump_cti_stats(cache: &mut Value, field: &str) {
    let period = Utc::now().format("%Y-%m").to_string();
    if cache["stats"]["period"] != json!(period) {
        cache["stats"] = json!({
            "period": period,
            "networkRequests": 0,
            "cacheHits": 0
        });
    }
    let current = cache["stats"][field].as_i64().unwrap_or(0);
    cache["stats"][field] = json!(current + 1);
}

async fn write_cti_cache(state: &AppState, cache: &Value) -> Result<(), String> {
    if let Some(parent) = Path::new(&state.config.cti_cache_file).parent() {
        let _ = fs::create_dir_all(parent).await;
    }
    let text = serde_json::to_string_pretty(cache).map_err(|e| e.to_string())?;
    fs::write(&state.config.cti_cache_file, format!("{text}\n"))
        .await
        .map_err(|e| e.to_string())
}
