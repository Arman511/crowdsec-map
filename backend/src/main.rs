use std::collections::{HashMap, HashSet};
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Instant;

use axum::Router;
use axum::routing::get;
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use glob::glob;
use regex::Regex;
use serde_json::{Value, json};
use std::io::Read;
use tokio::fs;
use tokio::process::Command;
use tokio::sync::Mutex;
use tower_http::services::{ServeDir, ServeFile};

mod api;
mod config;
mod logger;
mod models;
mod state;

pub(crate) use config::Config;
pub(crate) use models::*;
pub(crate) use state::{AppState, CachedAttacks};

const GEOIP_DATABASE_FILE: &str = "/app/data/dbip-country.mmdb";
const APP_VERSION: &str = "v0.4.2";
static STARTUP_TIMESTAMP: OnceLock<i64> = OnceLock::new();

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
        cscli_command = %config.cscli_command,
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
        .build()
        .expect("http client");
    ensure_geoip_database(&config, &client).await;
    let public_target_ip = discover_public_ip(&config, &client).await;
    let demo_mode = config.demo_mode
        || matches!(
            config.data_source.as_str(),
            "demo" | "demo-snapshot" | "sample"
        );
    let state = AppState {
        config: config.clone(),
        demo_mode,
        history_db_path: config.history_database_file.clone(),
        public_target_ip,
        geoip_reader: Arc::new(RwLock::new(load_geoip_reader(&config))),
        attacks_cache: Arc::new(Mutex::new(HashMap::new())),
        client,
    };

    let api = Router::new()
        .route("/health", get(api::api_health))
        .route("/attacks", get(api::api_attacks))
        .route("/history", get(api::api_history))
        .route("/history/group", get(api::api_history_group))
        .route("/history/ip/{ip}", get(api::api_history_ip))
        .route("/decisions", get(api::api_decisions))
        .route("/reputation/stats", get(api::api_reputation_stats))
        .route("/reputation/ip/{ip}", get(api::api_reputation_ip))
        .route("/lapi/credentials/status", get(api::api_lapi_status))
        .route(
            "/investigation/sources",
            get(api::api_investigation_sources),
        )
        .route("/investigation/ip/{ip}", get(api::api_investigation_ip))
        .route(
            "/investigation/ip/{ip}/log-lines",
            get(api::api_investigation_log_lines),
        )
        .route("/protection", get(api::api_protection))
        .route("/system/update-status", get(api::api_update_status))
        .route("/access-log/summary", get(api::api_access_log_summary));

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
        api::refresh_protection_cache(&startup_state).await;
    });
    let refresh_state = state.clone();
    tokio::spawn(async move {
        let interval =
            std::time::Duration::from_secs(refresh_state.config.protection_refresh_seconds.max(1));
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            api::refresh_protection_cache(&refresh_state).await;
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
            let reader = load_geoip_reader(&geoip_state.config);
            if let Ok(mut current) = geoip_state.geoip_reader.write() {
                *current = reader;
            }
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

async fn read_lapi_alerts(state: &AppState) -> Option<Vec<Alert>> {
    let token = lapi_token(state).await?;

    let mut url = format!("{}/v1/alerts", state.config.lapi_url.trim_end_matches('/'));
    if state.config.lapi_limit > 0 {
        url.push_str(&format!("?limit={}", state.config.lapi_limit));
    }
    let alerts_response = state.client.get(url).bearer_auth(token).send().await.ok()?;
    crate::debug!(network = "outbound", service = "lapi", operation = "alerts", status = %alerts_response.status(), "network request completed");
    if !alerts_response.status().is_success() {
        return None;
    }
    let payload: Value = alerts_response.json().await.ok()?;
    Some(normalize_alert_payload(&payload, "lapi-alerts"))
}

async fn lapi_token(state: &AppState) -> Option<String> {
    if state.config.lapi_login.is_empty() || state.config.lapi_password.is_empty() {
        crate::debug!(
            service = "lapi",
            "skipping LAPI request because credentials are not configured"
        );
        return None;
    }
    let login_url = format!(
        "{}/v1/watchers/login",
        state.config.lapi_url.trim_end_matches('/')
    );
    let started = Instant::now();
    crate::debug!(network = "outbound", service = "lapi", operation = "login", url = %login_url, "sending LAPI request");
    let response = state
        .client
        .post(login_url)
        .json(&json!({
            "machine_id": state.config.lapi_login,
            "password": state.config.lapi_password
        }))
        .send()
        .await
        .map_err(|err| {
            crate::warn!(network = "outbound", service = "lapi", operation = "login", error = %err, "LAPI request failed");
            err
        })
        .ok()?;
    crate::debug!(network = "outbound", service = "lapi", operation = "login", status = %response.status(), elapsed_ms = started.elapsed().as_millis(), "LAPI request completed");
    if !response.status().is_success() {
        return None;
    }
    response
        .json::<Value>()
        .await
        .ok()?
        .get("token")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

async fn send_lapi_presence(state: &AppState) {
    let Some(token) = lapi_token(state).await else {
        return;
    };
    let base_url = state.config.lapi_url.trim_end_matches('/');
    let heartbeat = state
        .client
        .get(format!("{base_url}/v1/heartbeat"))
        .bearer_auth(&token)
        .send()
        .await;
    match heartbeat {
        Ok(response) if response.status().is_success() => {
            crate::debug!(network = "outbound", service = "lapi", operation = "heartbeat", status = %response.status(), "LAPI heartbeat sent");
        }
        Ok(response) => {
            crate::warn!(network = "outbound", service = "lapi", operation = "heartbeat", status = %response.status(), "LAPI heartbeat failed");
        }
        Err(err) => {
            crate::warn!(network = "outbound", service = "lapi", operation = "heartbeat", error = %err, "LAPI heartbeat request failed");
        }
    }

    let (os_name, os_version) = read_os_release();
    let metrics = json!({
        "log_processors": [{
            "name": "crowdsec-map",
            "version": APP_VERSION,
            "os": { "name": os_name, "family": std::env::consts::OS, "version": os_version },
            "utc_startup_timestamp": *STARTUP_TIMESTAMP.get_or_init(|| Utc::now().timestamp()),
            "metrics": [],
            "feature_flags": [],
            "datasources": {},
            "hub_items": {}
        }],
        "remediation_components": []
    });
    let response = state
        .client
        .post(format!("{base_url}/v1/usage-metrics"))
        .bearer_auth(token)
        .json(&metrics)
        .send()
        .await;
    match response {
        Ok(response) if response.status().is_success() => {
            crate::debug!(network = "outbound", service = "lapi", operation = "usage-metrics", status = %response.status(), "LAPI machine metadata sent");
        }
        Ok(response) => {
            crate::warn!(network = "outbound", service = "lapi", operation = "usage-metrics", status = %response.status(), "LAPI machine metadata failed");
        }
        Err(err) => {
            crate::warn!(network = "outbound", service = "lapi", operation = "usage-metrics", error = %err, "LAPI machine metadata request failed");
        }
    }
}

fn read_os_release() -> (String, String) {
    let contents = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let value = |key: &str| {
        contents
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .map(|value| value.trim_matches('"').to_string())
            .unwrap_or_else(|| "unknown".to_string())
    };
    (value("NAME"), value("VERSION_ID"))
}

async fn read_cscli_alerts(state: &AppState) -> Option<Vec<Alert>> {
    let (cmd, args) = if state
        .config
        .cscli_command
        .trim_start()
        .starts_with("docker exec ")
    {
        (
            "sh".to_string(),
            vec!["-lc".to_string(), state.config.cscli_command.clone()],
        )
    } else if state.config.crowdsec_container.is_empty() {
        (
            "sh".to_string(),
            vec!["-lc".to_string(), state.config.cscli_command.clone()],
        )
    } else {
        (
            "docker".to_string(),
            vec![
                "exec".to_string(),
                state.config.crowdsec_container.clone(),
                "sh".to_string(),
                "-lc".to_string(),
                state.config.cscli_command.clone(),
            ],
        )
    };
    let command_line = format!("{} {}", cmd, args.join(" "));
    let started = Instant::now();
    crate::debug!(command = %command_line, "starting cscli alerts command");
    let output = match Command::new(&cmd).args(&args).output().await {
        Ok(output) => output,
        Err(err) => {
            crate::warn!(command = %cmd, error = %err, "cscli alerts command failed");
            return None;
        }
    };
    crate::debug!(command = %command_line, status = ?output.status.code(), success = output.status.success(), stdout_bytes = output.stdout.len(), stderr_bytes = output.stderr.len(), elapsed_ms = started.elapsed().as_millis(), "cscli alerts command completed");
    crate::debug!(command = %command_line, stdout_preview = %truncate_line(&String::from_utf8_lossy(&output.stdout), 1000), stderr_preview = %truncate_line(&String::from_utf8_lossy(&output.stderr), 1000), "cscli alerts command output");
    if !output.status.success() {
        crate::warn!(status = ?output.status.code(), stderr = %String::from_utf8_lossy(&output.stderr), "cscli alerts returned an error");
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let payload: Value = match serde_json::from_str(&text) {
        Ok(payload) => payload,
        Err(err) => {
            crate::warn!(error = %err, output = %text.trim(), "cscli alerts returned invalid JSON");
            return None;
        }
    };
    Some(normalize_alert_payload(&payload, "cscli"))
}

async fn read_demo_snapshot_alerts(state: &AppState) -> Option<Vec<Alert>> {
    let text = fs::read_to_string(&state.config.demo_snapshot_file)
        .await
        .ok()?;
    let payload: Value = serde_json::from_str(&text).ok()?;
    Some(normalize_alert_payload(&payload, "demo"))
}

fn normalize_alert_payload(payload: &Value, source_label: &str) -> Vec<Alert> {
    let items = payload
        .as_array()
        .cloned()
        .or_else(|| payload.get("items").and_then(Value::as_array).cloned())
        .or_else(|| payload.get("alerts").and_then(Value::as_array).cloned())
        .or_else(|| payload.get("decisions").and_then(Value::as_array).cloned())
        .unwrap_or_default();
    let now = Utc::now().to_rfc3339();
    let mut alerts = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let source = item.get("source").unwrap_or(item);
        let first_decision = item
            .get("decisions")
            .and_then(Value::as_array)
            .and_then(|x| x.first())
            .cloned()
            .unwrap_or_else(|| json!({}));
        let scenario = item
            .get("scenario")
            .and_then(Value::as_str)
            .or_else(|| item.get("reason").and_then(Value::as_str))
            .or_else(|| item.get("type").and_then(Value::as_str))
            .unwrap_or("unknown")
            .replace("crowdsecurity/", "");
        if is_feed_update(&scenario) {
            continue;
        }
        let ip = source
            .get("ip")
            .and_then(Value::as_str)
            .or_else(|| item.get("ip").and_then(Value::as_str))
            .or_else(|| item.get("value").and_then(Value::as_str))
            .or_else(|| first_decision.get("value").and_then(Value::as_str))
            .unwrap_or("")
            .to_string();
        if ip.is_empty() {
            continue;
        }
        let created_at = item
            .get("created_at")
            .and_then(Value::as_str)
            .or_else(|| item.get("start_at").and_then(Value::as_str))
            .or_else(|| item.get("createdAt").and_then(Value::as_str))
            .unwrap_or_else(|| {
                if source_label == "lapi-decisions" {
                    ""
                } else {
                    &now
                }
            })
            .to_string();
        let id = item
            .get("id")
            .and_then(|x| x.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| format!("{ip}-{created_at}-{index}"));
        alerts.push(Alert {
            id,
            ip: ip.clone(),
            country: source
                .get("cn")
                .and_then(Value::as_str)
                .or_else(|| source.get("country").and_then(Value::as_str))
                .or_else(|| item.get("country").and_then(Value::as_str))
                .unwrap_or("")
                .to_string(),
            city: source
                .get("city")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            latitude: as_f64(source.get("latitude")).or_else(|| as_f64(source.get("lat"))),
            longitude: as_f64(source.get("longitude"))
                .or_else(|| as_f64(source.get("lon")))
                .or_else(|| as_f64(source.get("lng"))),
            scenario,
            decision_type: first_decision
                .get("type")
                .and_then(Value::as_str)
                .or_else(|| item.get("decisionType").and_then(Value::as_str))
                .or_else(|| item.get("type").and_then(Value::as_str))
                .unwrap_or("alert")
                .to_string(),
            value: first_decision
                .get("value")
                .and_then(Value::as_str)
                .or_else(|| item.get("value").and_then(Value::as_str))
                .unwrap_or(&ip)
                .to_string(),
            created_at,
            count: item
                .get("events_count")
                .and_then(Value::as_i64)
                .or_else(|| item.get("count").and_then(Value::as_i64))
                .unwrap_or(1),
            as_name: source
                .get("as_name")
                .and_then(Value::as_str)
                .or_else(|| source.get("asName").and_then(Value::as_str))
                .unwrap_or("")
                .to_string(),
            origin: item
                .get("origin")
                .and_then(Value::as_str)
                .or_else(|| first_decision.get("origin").and_then(Value::as_str))
                .unwrap_or("")
                .to_string(),
            scope: item
                .get("scope")
                .and_then(Value::as_str)
                .or_else(|| first_decision.get("scope").and_then(Value::as_str))
                .unwrap_or("Ip")
                .to_string(),
            duration: item
                .get("duration")
                .and_then(Value::as_str)
                .or_else(|| first_decision.get("duration").and_then(Value::as_str))
                .unwrap_or("")
                .to_string(),
            until: item
                .get("until")
                .and_then(Value::as_str)
                .or_else(|| item.get("expires_at").and_then(Value::as_str))
                .or_else(|| first_decision.get("until").and_then(Value::as_str))
                .unwrap_or("")
                .to_string(),
        });
    }
    alerts
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

async fn read_active_bans(state: &AppState) -> Option<Vec<ActiveBan>> {
    crate::debug!(
        lapi_configured = !state.config.lapi_api_key.is_empty(),
        "loading active decisions"
    );
    if !state.config.lapi_api_key.is_empty() {
        if let Some(decisions) = read_lapi_decisions(state).await {
            crate::info!(
                source = "lapi",
                decisions = decisions.len(),
                "active decisions loaded"
            );
            return Some(decisions);
        }
        crate::warn!("LAPI decisions request failed; falling back to cscli");
    }
    let (cmd, args) = if state.config.crowdsec_container.is_empty() {
        (
            "cscli".to_string(),
            vec![
                "decisions".to_string(),
                "list".to_string(),
                "-o".to_string(),
                "json".to_string(),
                "--limit".to_string(),
                "0".to_string(),
            ],
        )
    } else {
        (
            "docker".to_string(),
            vec![
                "exec".to_string(),
                state.config.crowdsec_container.clone(),
                "cscli".to_string(),
                "decisions".to_string(),
                "list".to_string(),
                "-o".to_string(),
                "json".to_string(),
                "--limit".to_string(),
                "0".to_string(),
            ],
        )
    };
    let command_line = format!("{} {}", cmd, args.join(" "));
    let started = Instant::now();
    crate::debug!(command = %command_line, "starting cscli decisions command");
    let output = match Command::new(&cmd).args(&args).output().await {
        Ok(output) => output,
        Err(err) => {
            crate::warn!(command = %cmd, error = %err, "cscli decisions command failed");
            return None;
        }
    };
    crate::debug!(command = %command_line, status = ?output.status.code(), success = output.status.success(), stdout_bytes = output.stdout.len(), stderr_bytes = output.stderr.len(), elapsed_ms = started.elapsed().as_millis(), "cscli decisions command completed");
    crate::debug!(command = %command_line, stdout_preview = %truncate_line(&String::from_utf8_lossy(&output.stdout), 1000), stderr_preview = %truncate_line(&String::from_utf8_lossy(&output.stderr), 1000), "cscli decisions command output");
    if !output.status.success() {
        crate::warn!(status = ?output.status.code(), stderr = %String::from_utf8_lossy(&output.stderr), "cscli decisions returned an error");
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let payload: Value = match serde_json::from_str(&text) {
        Ok(payload) => payload,
        Err(err) => {
            crate::warn!(error = %err, output = %text.trim(), "cscli decisions returned invalid JSON");
            return None;
        }
    };
    let bans = normalize_decisions_as_bans(&payload);
    crate::info!(command = %cmd, decisions = bans.len(), "cscli decisions loaded");
    Some(bans)
}

async fn read_lapi_decisions(state: &AppState) -> Option<Vec<ActiveBan>> {
    let mut url = format!(
        "{}/v1/decisions",
        state.config.lapi_url.trim_end_matches('/')
    );
    if state.config.lapi_limit > 0 {
        url.push_str(&format!("?limit={}", state.config.lapi_limit));
    }
    let started = Instant::now();
    crate::debug!(network = "outbound", service = "lapi", operation = "decisions", url = %url, "sending LAPI request");
    let response = state
        .client
        .get(url)
        .header("X-Api-Key", &state.config.lapi_api_key)
        .send()
        .await
        .map_err(|err| { crate::warn!(network = "outbound", service = "lapi", operation = "decisions", error = %err, "LAPI request failed"); err }).ok()?;
    crate::debug!(network = "outbound", service = "lapi", operation = "decisions", status = %response.status(), elapsed_ms = started.elapsed().as_millis(), "LAPI request completed");
    if !response.status().is_success() {
        return None;
    }
    let payload: Value = response.json().await.ok()?;
    Some(normalize_decisions_as_bans(&payload))
}

async fn read_decisions_from_cscli(state: &AppState) -> Vec<ActiveBan> {
    read_active_bans(state).await.unwrap_or_default()
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

async fn read_cscli_ip_details(state: &AppState, ip: &str) -> (String, String, String) {
    let (cmd, args) = if state.config.crowdsec_container.is_empty() {
        (
            "cscli".to_string(),
            vec![
                "alerts".to_string(),
                "list".to_string(),
                "-o".to_string(),
                "human".to_string(),
                "--ip".to_string(),
                ip.to_string(),
                "--limit".to_string(),
                "0".to_string(),
            ],
        )
    } else {
        (
            "docker".to_string(),
            vec![
                "exec".to_string(),
                state.config.crowdsec_container.clone(),
                "cscli".to_string(),
                "alerts".to_string(),
                "list".to_string(),
                "-o".to_string(),
                "human".to_string(),
                "--ip".to_string(),
                ip.to_string(),
                "--limit".to_string(),
                "0".to_string(),
            ],
        )
    };
    let command_line = format!("{} {}", cmd, args.join(" "));
    let started = Instant::now();
    crate::debug!(ip = %ip, command = %command_line, "starting cscli IP details command");
    match Command::new(&cmd).args(&args).output().await {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8(output.stdout)
                .unwrap_or_default()
                .trim()
                .to_string();
            crate::debug!(ip = %ip, command = %command_line, status = ?output.status.code(), stdout_bytes = text.len(), stderr_bytes = output.stderr.len(), elapsed_ms = started.elapsed().as_millis(), "cscli IP details command completed");
            (text, command_line, String::new())
        }
        Ok(output) => {
            let error =
                String::from_utf8(output.stderr).unwrap_or_else(|_| "cscli failed".to_string());
            crate::warn!(ip = %ip, command = %command_line, status = ?output.status.code(), stderr = %error, elapsed_ms = started.elapsed().as_millis(), "cscli IP details command failed");
            (String::new(), command_line, error)
        }
        Err(err) => {
            crate::error!(ip = %ip, command = %command_line, error = %err, elapsed_ms = started.elapsed().as_millis(), "unable to start cscli IP details command");
            (String::new(), command_line, err.to_string())
        }
    }
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

fn normalize_decisions_as_bans(value: &Value) -> Vec<ActiveBan> {
    let items = value
        .as_array()
        .cloned()
        .or_else(|| value.get("data").and_then(Value::as_array).cloned())
        .or_else(|| value.get("items").and_then(Value::as_array).cloned())
        .or_else(|| value.get("decisions").and_then(Value::as_array).cloned())
        .unwrap_or_default();
    let mut out = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let ip = item
            .get("ip")
            .and_then(Value::as_str)
            .or_else(|| item.get("value").and_then(Value::as_str))
            .unwrap_or("")
            .to_string();
        let value_field = item
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or(&ip)
            .to_string();
        out.push(ActiveBan {
            id: item
                .get("id")
                .and_then(Value::as_i64)
                .map(|x| x.to_string())
                .unwrap_or_else(|| format!("decision-{index}")),
            ip,
            value: value_field,
            country: item
                .get("country")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            scenario: item
                .get("scenario")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            origin: item
                .get("origin")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            scope: item
                .get("scope")
                .and_then(Value::as_str)
                .unwrap_or("Ip")
                .to_string(),
            duration: item
                .get("duration")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            until: item
                .get("until")
                .and_then(Value::as_str)
                .or_else(|| item.get("expires_at").and_then(Value::as_str))
                .unwrap_or("")
                .to_string(),
            ban_type: item
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("ban")
                .to_string(),
            created_at: item
                .get("created_at")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        });
    }
    out
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

async fn read_runtime_revision() -> Result<(String, String), String> {
    let hostname = env::var("HOSTNAME").unwrap_or_default();
    if hostname.is_empty() {
        return Err("HOSTNAME is empty".to_string());
    }
    crate::debug!(hostname = %hostname, "inspecting runtime container revision");
    let output = Command::new("docker")
        .args([
            "inspect",
            "--format",
            "{{.Config.Image}}\t{{index .Config.Labels \"org.opencontainers.image.revision\"}}",
            &hostname,
        ])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    crate::debug!(hostname = %hostname, status = ?output.status.code(), stdout_bytes = output.stdout.len(), stderr_bytes = output.stderr.len(), "runtime container inspection completed");
    if !output.status.success() {
        return Err(String::from_utf8(output.stderr)
            .unwrap_or_else(|_| "docker inspect failed".to_string()));
    }
    let text = String::from_utf8(output.stdout).map_err(|e| e.to_string())?;
    let parts = text.trim().split('\t').collect::<Vec<_>>();
    if parts.len() < 2 {
        return Err("The running image does not expose a Git revision label".to_string());
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

async fn read_remote_revision(state: &AppState) -> Result<(String, String), String> {
    let response = state
        .client
        .get("https://api.github.com/repos/arman511/crowdsec-map/commits/dev")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| e.to_string())?;
    crate::debug!(network = "outbound", service = "github", operation = "revision", status = %response.status(), "network request completed");
    if !response.status().is_success() {
        return Err(format!("GitHub returned HTTP {}", response.status()));
    }
    let commit: Value = response.json().await.map_err(|e| e.to_string())?;
    let sha = commit
        .get("sha")
        .and_then(Value::as_str)
        .ok_or_else(|| "GitHub did not return a dev commit".to_string())?
        .to_string();
    let url = commit
        .get("html_url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    Ok((sha, url))
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

async fn read_json_file(path: &str) -> Option<Value> {
    let text = fs::read_to_string(path).await.ok()?;
    serde_json::from_str::<Value>(&text).ok()
}

async fn discover_public_ip(config: &Config, client: &reqwest::Client) -> String {
    if !config.public_target_ip.is_empty() {
        crate::debug!(source = "configured", ip = %config.public_target_ip, "using configured public IP");
        return config.public_target_ip.clone();
    }
    let providers = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ];
    for provider in providers {
        let response = client.get(provider).send().await;
        crate::debug!(
            network = "outbound",
            service = "public_ip",
            provider,
            result = if response.is_ok() { "success" } else { "error" },
            "network request completed"
        );
        if let Ok(response) = response
            && response.status().is_success()
            && let Ok(text) = response.text().await
        {
            let ip = text.trim().to_string();
            if ip.parse::<std::net::IpAddr>().is_ok() {
                crate::info!(network = "outbound", service = "public_ip", provider, ip = %ip, "public IP discovered");
                return ip;
            }
            crate::warn!(network = "outbound", service = "public_ip", provider, response = %truncate_line(&ip, 100), "public IP provider returned invalid data");
        }
    }
    String::new()
}

fn parse_line_timestamp(line: &str) -> Option<DateTime<Utc>> {
    static ZORAXY: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\]").unwrap()
    });
    static ISO: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)")
            .unwrap()
    });
    static APACHE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
        Regex::new(r"(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})").unwrap()
    });
    if let Some(cap) = ZORAXY.captures(line) {
        let raw = cap.get(1)?.as_str();
        if let Ok(ts) = chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f") {
            return Some(DateTime::<Utc>::from_naive_utc_and_offset(ts, Utc));
        }
    }
    if let Some(cap) = ISO.captures(line) {
        let raw = cap.get(1)?.as_str().replace(' ', "T");
        if let Ok(ts) = DateTime::parse_from_rfc3339(&raw) {
            return Some(ts.with_timezone(&Utc));
        }
    }
    if let Some(cap) = APACHE.captures(line)
        && let Ok(ts) = DateTime::parse_from_str(cap.get(1)?.as_str(), "%d/%b/%Y:%H:%M:%S %z")
    {
        return Some(ts.with_timezone(&Utc));
    }
    None
}

fn parse_host(line: &str) -> Option<String> {
    static HOST: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"\bhost=([^\s]+)|\borigin:([^\s\]]+)").unwrap());
    HOST.captures(line).and_then(|c| {
        c.get(1)
            .or_else(|| c.get(2))
            .map(|m| m.as_str().to_string())
    })
}

fn truncate_line(line: &str, max: usize) -> String {
    if line.len() <= max {
        return line.to_string();
    }
    let mut out = line.chars().take(max).collect::<String>();
    out.push_str("...");
    out
}

fn to_cidr24(ip: &str) -> String {
    let parts = ip.split('.').collect::<Vec<_>>();
    if parts.len() == 4 {
        return format!("{}.{}.{}.*", parts[0], parts[1], parts[2]);
    }
    ip.to_string()
}

fn pct(a: i64, b: i64) -> f64 {
    if b <= 0 {
        return 0.0;
    }
    ((a as f64 / b as f64) * 1000.0).round() / 10.0
}

fn top_count_label(map: &HashMap<String, i64>) -> String {
    map.iter()
        .max_by_key(|(_, count)| *count)
        .map(|(label, _)| label.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

fn first_number(values: &[Option<&Value>]) -> f64 {
    for value in values {
        if let Some(number) = value.and_then(Value::as_f64) {
            return number;
        }
        if let Some(number) = value.and_then(Value::as_i64) {
            return number as f64;
        }
        if let Some(number) = value.and_then(Value::as_u64) {
            return number as f64;
        }
    }
    0.0
}

fn collect_strings(values: &[Option<&Value>]) -> Vec<String> {
    let mut out = HashSet::new();
    for value in values {
        if let Some(array) = value.and_then(Value::as_array) {
            for item in array {
                if let Some(text) = item.as_str() {
                    let trimmed = text.trim();
                    if !trimmed.is_empty() {
                        out.insert(trimmed.to_string());
                    }
                }
            }
        }
    }
    let mut vec = out.into_iter().collect::<Vec<_>>();
    vec.sort();
    vec
}

fn is_feed_update(scenario: &str) -> bool {
    Regex::new(r"(?i)^update\s*:\s*\+\d+/-\d+\s+ips?$")
        .ok()
        .map(|r| r.is_match(scenario.trim()))
        .unwrap_or(false)
}

fn clamp_u64(value: Option<&str>, fallback: u64, min: u64, max: u64) -> u64 {
    let parsed = value
        .and_then(|x| x.parse::<u64>().ok())
        .unwrap_or(fallback);
    parsed.clamp(min, max)
}

fn clamp_usize(value: Option<&str>, fallback: usize, min: usize, max: usize) -> usize {
    let parsed = value
        .and_then(|x| x.parse::<usize>().ok())
        .unwrap_or(fallback);
    parsed.clamp(min, max)
}

fn normalize_group_by(value: Option<&str>) -> String {
    match value.unwrap_or("cidr24") {
        "ip" | "asn" | "country" | "scenario" | "cidr24" => value.unwrap_or("cidr24").to_string(),
        _ => "cidr24".to_string(),
    }
}

fn sql_escape(value: &str) -> String {
    value.replace('\'', "''")
}

fn expand_pattern(pattern: &str) -> String {
    if pattern.starts_with('~')
        && let Ok(home) = env::var("HOME")
    {
        return format!("{}{}", home, &pattern[1..]);
    }
    if PathBuf::from(pattern).is_absolute() {
        return pattern.to_string();
    }
    if let Ok(cwd) = env::current_dir() {
        return cwd.join(pattern).to_string_lossy().to_string();
    }
    pattern.to_string()
}

fn as_f64(value: Option<&Value>) -> Option<f64> {
    value
        .and_then(Value::as_f64)
        .or_else(|| value.and_then(Value::as_i64).map(|x| x as f64))
}
