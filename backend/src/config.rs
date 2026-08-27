use std::env;

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) port: u16,
    pub(crate) data_source: String,
    pub(crate) demo_mode: bool,
    pub(crate) attacks_cache_seconds: u64,
    pub(crate) refresh_seconds: u64,
    pub(crate) protection_refresh_seconds: u64,
    pub(crate) static_dir: String,
    pub(crate) cscli_command: String,
    pub(crate) crowdsec_container: String,
    pub(crate) lapi_url: String,
    pub(crate) lapi_login: String,
    pub(crate) lapi_password: String,
    pub(crate) lapi_api_key: String,
    pub(crate) lapi_credentials_file: String,
    pub(crate) lapi_limit: usize,
    pub(crate) demo_snapshot_file: String,
    pub(crate) history_database_file: String,
    pub(crate) history_retention_days: u64,
    pub(crate) cti_api_key: String,
    pub(crate) cti_api_url: String,
    pub(crate) cti_cache_file: String,
    pub(crate) cti_cache_hours: u64,
    pub(crate) investigation_log_paths: Vec<String>,
    pub(crate) investigation_max_lines: usize,
    pub(crate) investigation_timeout_ms: u64,
    pub(crate) protection_log_paths: Vec<String>,
    pub(crate) access_log_enabled: bool,
    pub(crate) access_log_file: String,
    pub(crate) access_log_retention_days: u64,
    pub(crate) public_target_ip: String,
}

impl Config {
    pub(crate) fn from_env() -> Self {
        let investigation_default = vec![
            "/var/log/zoraxy/*.log*".to_string(),
            "/opt/security-stack/zoraxy/config/log/*.log*".to_string(),
            "/opt/security-stack/authelia/config/authelia.log".to_string(),
            "/var/log/pveproxy/access.log".to_string(),
        ];
        Self {
            port: env_parse("PORT", 8088_u16),
            data_source: env::var("DATA_SOURCE").unwrap_or_else(|_| "auto".to_string()),
            demo_mode: env_bool("DEMO_MODE", false),
            attacks_cache_seconds: env_parse("ATTACKS_CACHE_SECONDS", 5_u64),
            refresh_seconds: env_parse("REFRESH_SECONDS", 30_u64),
            protection_refresh_seconds: env_parse("PROTECTION_REFRESH_SECONDS", 3600_u64),
            static_dir: env::var("STATIC_DIR").unwrap_or_else(|_| "dist".to_string()),
            cscli_command: env::var("CSCLI_COMMAND")
                .unwrap_or_else(|_| "cscli alerts list -o json --limit 0".to_string()),
            crowdsec_container: env::var("CROWDSEC_CONTAINER").unwrap_or_default(),
            lapi_url: env::var("LAPI_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string()),
            lapi_login: env::var("LAPI_LOGIN").unwrap_or_default(),
            lapi_password: env::var("LAPI_PASSWORD").unwrap_or_default(),
            lapi_api_key: env::var("LAPI_API_KEY").unwrap_or_default(),
            lapi_credentials_file: env::var("LAPI_CREDENTIALS_FILE")
                .unwrap_or_else(|_| "data/lapi-credentials.json".to_string()),
            lapi_limit: env_parse("LAPI_LIMIT", 0_usize),
            demo_snapshot_file: env::var("DEMO_SNAPSHOT_FILE")
                .unwrap_or_else(|_| "demo-data/demo-snapshot.json".to_string()),
            history_database_file: env::var("HISTORY_DATABASE_FILE")
                .unwrap_or_else(|_| "data/history.db".to_string()),
            history_retention_days: env_parse("HISTORY_RETENTION_DAYS", 90_u64),
            cti_api_key: env::var("CTI_API_KEY").unwrap_or_default(),
            cti_api_url: env::var("CTI_API_URL")
                .unwrap_or_else(|_| "https://cti.api.crowdsec.net/v2".to_string()),
            cti_cache_file: env::var("CTI_CACHE_FILE")
                .unwrap_or_else(|_| "data/cti-cache.json".to_string()),
            cti_cache_hours: env_parse("CTI_CACHE_HOURS", 72_u64),
            investigation_log_paths: parse_list(
                &env::var("INVESTIGATION_LOG_PATHS")
                    .unwrap_or_else(|_| investigation_default.join(",")),
            ),
            investigation_max_lines: env_parse("INVESTIGATION_MAX_LINES", 50_usize),
            investigation_timeout_ms: env_parse("INVESTIGATION_TIMEOUT_MS", 30_000_u64),
            protection_log_paths: parse_list(&env::var("PROTECTION_LOG_PATHS").unwrap_or_else(
                |_| {
                    "/var/log/zoraxy/*.log*,/opt/security-stack/zoraxy/config/log/*.log*"
                        .to_string()
                },
            )),
            access_log_enabled: env_bool("ACCESS_LOG_ENABLED", false),
            access_log_file: env::var("ACCESS_LOG_FILE")
                .unwrap_or_else(|_| "data/access-log.jsonl".to_string()),
            access_log_retention_days: env_parse("ACCESS_LOG_RETENTION_DAYS", 30_u64),
            public_target_ip: env::var("PUBLIC_TARGET_IP").unwrap_or_default(),
        }
    }
}

pub(crate) fn parse_list(value: &str) -> Vec<String> {
    value
        .split(['\n', ',', ';'])
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn env_bool(name: &str, fallback: bool) -> bool {
    match env::var(name) {
        Ok(value) => matches!(value.to_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => fallback,
    }
}

fn env_parse<T>(name: &str, fallback: T) -> T
where
    T: std::str::FromStr,
{
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<T>().ok())
        .unwrap_or(fallback)
}
