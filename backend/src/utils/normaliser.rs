use std::{
    collections::{HashMap, HashSet},
    env,
    path::PathBuf,
};

use crate::{Alert, models::models::ActiveBan};
use chrono::Utc;
use regex::Regex;
use serde_json::{Value, json};

pub fn truncate_line(line: &str, max: usize) -> String {
    if line.len() <= max {
        return line.to_string();
    }
    let mut out = line.chars().take(max).collect::<String>();
    out.push_str("...");
    out
}

pub fn normalize_alert_payload(payload: &Value, source_label: &str) -> Vec<Alert> {
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

pub fn is_feed_update(scenario: &str) -> bool {
    Regex::new(r"(?i)^update\s*:\s*\+\d+/-\d+\s+ips?$")
        .ok()
        .map(|r| r.is_match(scenario.trim()))
        .unwrap_or(false)
}

pub fn as_f64(value: Option<&Value>) -> Option<f64> {
    value
        .and_then(Value::as_f64)
        .or_else(|| value.and_then(Value::as_i64).map(|x| x as f64))
}

pub fn to_cidr24(ip: &str) -> String {
    let parts = ip.split('.').collect::<Vec<_>>();
    if parts.len() == 4 {
        return format!("{}.{}.{}.*", parts[0], parts[1], parts[2]);
    }
    ip.to_string()
}

pub fn pct(a: i64, b: i64) -> f64 {
    if b <= 0 {
        return 0.0;
    }
    ((a as f64 / b as f64) * 1000.0).round() / 10.0
}

pub fn top_count_label(map: &HashMap<String, i64>) -> String {
    map.iter()
        .max_by_key(|(_, count)| *count)
        .map(|(label, _)| label.clone())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn first_number(values: &[Option<&Value>]) -> f64 {
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

pub fn collect_strings(values: &[Option<&Value>]) -> Vec<String> {
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

pub fn clamp_u64(value: Option<&str>, fallback: u64, min: u64, max: u64) -> u64 {
    let parsed = value
        .and_then(|x| x.parse::<u64>().ok())
        .unwrap_or(fallback);
    parsed.clamp(min, max)
}

pub fn clamp_usize(value: Option<&str>, fallback: usize, min: usize, max: usize) -> usize {
    let parsed = value
        .and_then(|x| x.parse::<usize>().ok())
        .unwrap_or(fallback);
    parsed.clamp(min, max)
}

pub fn normalize_group_by(value: Option<&str>) -> String {
    match value.unwrap_or("cidr24") {
        "ip" | "asn" | "country" | "scenario" | "cidr24" => value.unwrap_or("cidr24").to_string(),
        _ => "cidr24".to_string(),
    }
}

pub fn sql_escape(value: &str) -> String {
    value.replace('\'', "''")
}

pub fn expand_pattern(pattern: &str) -> String {
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

pub fn normalize_decisions_as_bans(value: &Value) -> Vec<ActiveBan> {
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
