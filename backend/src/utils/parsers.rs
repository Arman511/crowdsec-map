use chrono::{DateTime, Utc};
use regex::Regex;
use serde_json::Value;
use tokio::fs;

pub async fn read_json_file(path: &str) -> Option<Value> {
    let text = fs::read_to_string(path).await.ok()?;
    serde_json::from_str::<Value>(&text).ok()
}

pub fn parse_line_timestamp(line: &str) -> Option<DateTime<Utc>> {
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

pub fn parse_host(line: &str) -> Option<String> {
    static HOST: std::sync::LazyLock<Regex> =
        std::sync::LazyLock::new(|| Regex::new(r"\bhost=([^\s]+)|\borigin:([^\s\]]+)").unwrap());
    HOST.captures(line).and_then(|c| {
        c.get(1)
            .or_else(|| c.get(2))
            .map(|m| m.as_str().to_string())
    })
}
