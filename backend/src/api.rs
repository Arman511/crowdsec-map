use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader as StdBufReader};
use std::net::IpAddr;
use std::time::{Duration, Instant, UNIX_EPOCH};

use axum::Json;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::StatusCode;
use chrono::Utc;
use flate2::read::GzDecoder;
use serde_json::{Value, json};

use tokio::io::{AsyncBufReadExt, BufReader};

use crate::*;

type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;

pub(crate) async fn api_health(State(state): State<AppState>) -> ApiResult {
    let ip = state.public_target_ip.clone();
    Ok(Json(json!({
        "ok": true,
        "source": state.config.data_source,
        "refreshSeconds": state.config.refresh_seconds,
        "publicTargetIp": ip,
        "publicTargetIpSource": if ip.is_empty() { "unavailable" } else { "configured" },
        "publicTargetIpWarning": if ip.is_empty() { "" } else { "" }
    })))
}

pub(crate) async fn api_attacks(
    State(state): State<AppState>,
    Query(query): Query<SourceQuery>,
) -> ApiResult {
    let source = query.source.unwrap_or_else(|| "auto".to_string());
    let started = Instant::now();
    crate::info!(source = %source, "attacks request started");
    let key = source.clone();
    {
        let cache = state.attacks_cache.lock().await;
        if let Some(entry) = cache.get(&key)
            && entry.expires_at > Instant::now()
        {
            return Ok(Json(entry.payload.clone()));
        }
    }

    let (alerts, source_label, warning) = read_crowdsec_data(&state, &source).await;
    let bans = if state.config.demo_mode {
        Vec::new()
    } else {
        read_active_bans(&state).await.unwrap_or_default()
    };
    crate::info!(source = %source_label, alerts = alerts.len(), active_bans = bans.len(), warning = %warning, elapsed_ms = started.elapsed().as_millis(), "attacks request data loaded");
    record_history(&state, &alerts).await;

    let totals = build_totals(&alerts, bans.len() as i64);
    let payload = json!({
        "source": source_label,
        "generatedAt": Utc::now().to_rfc3339(),
        "alerts": alerts,
        "activeBans": bans,
        "refreshSeconds": state.config.refresh_seconds,
        "publicTargetIp": state.public_target_ip,
        "publicTargetIpSource": "configured",
        "demoMode": state.config.demo_mode,
        "warning": warning,
        "totals": totals,
        "topCountries": group_counts_json(&alerts, "country", 8),
        "topScenarios": group_counts_json(&alerts, "scenario", 8)
    });

    {
        let mut cache = state.attacks_cache.lock().await;
        cache.insert(
            key,
            CachedAttacks {
                expires_at: Instant::now()
                    + Duration::from_secs(state.config.attacks_cache_seconds.max(1)),
                payload: payload.clone(),
            },
        );
    }
    Ok(Json(payload))
}

pub(crate) async fn api_history(
    State(state): State<AppState>,
    Query(query): Query<HistoryQuery>,
) -> ApiResult {
    let days = clamp_u64(query.days.as_deref(), 7, 1, 180);
    let group_by = normalize_group_by(query.group_by.as_deref());
    let offset = clamp_usize(query.offset.as_deref(), 0, 0, 1_000_000);
    let limit = clamp_usize(query.limit.as_deref(), 80, 1, 200);
    let since = Utc::now().timestamp_millis() - (days as i64) * 86_400_000;
    let conn = match open_history_connection(&state) {
        Ok(c) => c,
        Err(err) => return err_500(err.to_string()),
    };
    let sql = format!(
        "SELECT ip, cidr24, as_name, country, scenario, seen_at, event_count FROM alerts WHERE seen_at_ms >= {since} ORDER BY seen_at_ms DESC"
    );
    let mut statement = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(err) => return err_500(err.to_string()),
    };
    let rows = match statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, i64>(6)?,
        ))
    }) {
        Ok(r) => r,
        Err(err) => return err_500(err.to_string()),
    };

    #[derive(Default)]
    struct Group {
        alerts: i64,
        events: i64,
        days: HashSet<String>,
        ips: HashSet<String>,
        top_scenario: HashMap<String, i64>,
        top_country: HashMap<String, i64>,
        last_seen: String,
    }
    let mut grouped: HashMap<String, Group> = HashMap::new();
    let mut matched_events: i64 = 0;

    for row in rows.flatten() {
        let (ip, cidr24, as_name, country, scenario, seen_at, count) = row;
        matched_events += 1;
        let key = match group_by.as_str() {
            "ip" => ip.clone(),
            "asn" => as_name.clone(),
            "country" => country.clone(),
            "scenario" => scenario.clone(),
            _ => cidr24.clone(),
        };
        let entry = grouped.entry(key.clone()).or_default();
        entry.alerts += count;
        entry.events += 1;
        entry.ips.insert(ip);
        entry.days.insert(seen_at.chars().take(10).collect());
        *entry.top_scenario.entry(scenario).or_insert(0) += count;
        *entry.top_country.entry(country).or_insert(0) += count;
        if seen_at > entry.last_seen {
            entry.last_seen = seen_at;
        }
    }

    let mut items = Vec::new();
    for (label, g) in grouped {
        items.push(json!({
            "label": label,
            "alerts": g.alerts,
            "events": g.events,
            "daysSeen": g.days.len(),
            "ipCount": g.ips.len(),
            "lastSeen": g.last_seen,
            "topScenario": top_count_label(&g.top_scenario),
            "topCountry": top_count_label(&g.top_country)
        }));
    }
    items.sort_by(|a, b| {
        b["alerts"]
            .as_i64()
            .unwrap_or(0)
            .cmp(&a["alerts"].as_i64().unwrap_or(0))
    });
    let total = items.len();
    let page = items
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "generatedAt": Utc::now().to_rfc3339(),
        "days": days,
        "groupBy": group_by,
        "totalEvents": matched_events,
        "matchedEvents": matched_events,
        "total": total,
        "offset": offset,
        "limit": limit,
        "nextOffset": if offset + limit < total { json!(offset + limit) } else { Value::Null },
        "items": page
    })))
}

pub(crate) async fn api_history_group(
    State(state): State<AppState>,
    Query(query): Query<GroupQuery>,
) -> ApiResult {
    let days = clamp_u64(query.days.as_deref(), 7, 1, 180);
    let group_by = normalize_group_by(query.group_by.as_deref());
    let offset = clamp_usize(query.offset.as_deref(), 0, 0, 1_000_000);
    let limit = clamp_usize(query.limit.as_deref(), 80, 1, 200);
    let label = query.label.unwrap_or_default();
    if label.trim().is_empty() {
        return err_400("Group label is missing");
    }

    let since = Utc::now().timestamp_millis() - (days as i64) * 86_400_000;
    let conn = match open_history_connection(&state) {
        Ok(c) => c,
        Err(err) => return err_500(err.to_string()),
    };

    let column = match group_by.as_str() {
        "ip" => "ip",
        "asn" => "as_name",
        "country" => "country",
        "scenario" => "scenario",
        _ => "cidr24",
    };
    let label_sql = sql_escape(&label);
    let sql = format!(
        "SELECT ip, country, scenario, as_name, seen_at, event_count FROM alerts WHERE seen_at_ms >= {since} AND {column} = '{label_sql}' ORDER BY seen_at_ms DESC"
    );
    let mut statement = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(err) => return err_500(err.to_string()),
    };
    let rows = match statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, i64>(5)?,
        ))
    }) {
        Ok(r) => r,
        Err(err) => return err_500(err.to_string()),
    };

    #[derive(Default)]
    struct IpGroup {
        alerts: i64,
        events: i64,
        days: HashSet<String>,
        top_scenario: HashMap<String, i64>,
        top_country: HashMap<String, i64>,
        top_asn: HashMap<String, i64>,
        last_seen: String,
    }
    let mut ips: HashMap<String, IpGroup> = HashMap::new();
    let mut matched_events: i64 = 0;

    for row in rows.flatten() {
        let (ip, country, scenario, as_name, seen_at, count) = row;
        matched_events += 1;
        let entry = ips.entry(ip.clone()).or_default();
        entry.alerts += count;
        entry.events += 1;
        entry.days.insert(seen_at.chars().take(10).collect());
        *entry.top_scenario.entry(scenario).or_insert(0) += count;
        *entry.top_country.entry(country).or_insert(0) += count;
        *entry.top_asn.entry(as_name).or_insert(0) += count;
        if seen_at > entry.last_seen {
            entry.last_seen = seen_at;
        }
    }

    let mut items = Vec::new();
    for (ip, g) in ips {
        items.push(json!({
            "ip": ip,
            "alerts": g.alerts,
            "events": g.events,
            "daysSeen": g.days.len(),
            "lastSeen": g.last_seen,
            "topScenario": top_count_label(&g.top_scenario),
            "topCountry": top_count_label(&g.top_country),
            "topAsName": top_count_label(&g.top_asn)
        }));
    }
    items.sort_by(|a, b| {
        b["alerts"]
            .as_i64()
            .unwrap_or(0)
            .cmp(&a["alerts"].as_i64().unwrap_or(0))
    });
    let total = items.len();
    let page = items
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "generatedAt": Utc::now().to_rfc3339(),
        "days": days,
        "groupBy": group_by,
        "label": label,
        "matchedEvents": matched_events,
        "total": total,
        "offset": offset,
        "limit": limit,
        "nextOffset": if offset + limit < total { json!(offset + limit) } else { Value::Null },
        "items": page
    })))
}

pub(crate) async fn api_history_ip(
    State(state): State<AppState>,
    AxumPath(ip): AxumPath<String>,
    Query(query): Query<DaysQuery>,
) -> ApiResult {
    if ip.parse::<std::net::IpAddr>().is_err() {
        return err_400("Invalid IP address");
    }
    let days = clamp_u64(query.days.as_deref(), 7, 1, 180);
    let offset = clamp_usize(query.offset.as_deref(), 0, 0, 1_000_000);
    let limit = clamp_usize(query.limit.as_deref(), 50, 1, 200);
    let since = Utc::now().timestamp_millis() - (days as i64) * 86_400_000;
    crate::debug!(ip = %ip, days, offset, limit, "history IP request started");
    let (cscli, cscli_command, cscli_warning) = read_cscli_ip_details(&state, &ip).await;
    crate::debug!(ip = %ip, command = %cscli_command, warning = %cscli_warning, output_bytes = cscli.len(), output_preview = %truncate_line(&cscli, 1000), "history IP cscli details loaded");

    let conn = match open_history_connection(&state) {
        Ok(c) => c,
        Err(err) => return err_500(err.to_string()),
    };
    let ip_sql = sql_escape(&ip);
    let sql = format!(
        "SELECT scenario, country, as_name, seen_at, event_count FROM alerts WHERE seen_at_ms >= {since} AND ip = '{ip_sql}' ORDER BY seen_at_ms DESC"
    );
    let mut statement = match conn.prepare(&sql) {
        Ok(s) => s,
        Err(err) => return err_500(err.to_string()),
    };
    let rows = match statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
        ))
    }) {
        Ok(r) => r,
        Err(err) => return err_500(err.to_string()),
    };

    let mut alerts = 0_i64;
    let mut events = Vec::new();
    let mut days_seen = HashSet::new();
    let mut top_scenario: HashMap<String, i64> = HashMap::new();
    let mut top_country: HashMap<String, i64> = HashMap::new();
    let mut top_asn: HashMap<String, i64> = HashMap::new();
    let mut first_seen = String::new();
    let mut last_seen = String::new();

    for row in rows.flatten() {
        let (scenario, country, as_name, seen_at, count) = row;
        alerts += count;
        days_seen.insert(seen_at.chars().take(10).collect::<String>());
        *top_scenario.entry(scenario.clone()).or_insert(0) += count;
        *top_country.entry(country.clone()).or_insert(0) += count;
        *top_asn.entry(as_name.clone()).or_insert(0) += count;
        if first_seen.is_empty() || seen_at < first_seen {
            first_seen = seen_at.clone();
        }
        if seen_at > last_seen {
            last_seen = seen_at.clone();
        }
        events.push(json!({
            "seenAt": seen_at,
            "scenario": scenario,
            "country": country,
            "asName": as_name,
            "count": count
        }));
    }

    let total_events = events.len();
    let page = events
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "ip": ip,
        "days": days,
        "generatedAt": Utc::now().to_rfc3339(),
        "alerts": alerts,
        "events": total_events,
        "daysSeen": days_seen.len(),
        "firstSeen": first_seen,
        "lastSeen": last_seen,
        "topScenario": top_count_label(&top_scenario),
        "topCountry": top_count_label(&top_country),
        "topAsName": top_count_label(&top_asn),
        "offset": offset,
        "limit": limit,
        "nextOffset": if offset + limit < total_events { json!(offset + limit) } else { Value::Null },
        "recentEvents": page,
        "cscli": cscli,
        "cscliCommand": cscli_command,
        "cscliWarning": cscli_warning,
        "note": "CrowdSec alert records, not active bans. History is filtered by the selected window; raw details depend on CrowdSec alert retention."
    })))
}

pub(crate) async fn api_decisions(
    State(state): State<AppState>,
    Query(query): Query<DecisionsQuery>,
) -> ApiResult {
    let mut items = if state.config.demo_mode {
        read_demo_decisions(&state).await
    } else {
        read_decisions_from_cscli(&state).await
    };
    enrich_decision_countries(&state, &mut items);

    let search = query.search.unwrap_or_default().trim().to_lowercase();
    if !search.is_empty() {
        let parts: Vec<String> = search.split_whitespace().map(ToOwned::to_owned).collect();
        items.retain(|item| {
            let hay = format!(
                "{} {} {} {} {} {} {}",
                item.ip,
                item.value,
                item.scope,
                item.country,
                item.scenario,
                item.origin,
                item.duration
            )
            .to_lowercase();
            parts.iter().all(|p| hay.contains(p))
        });
    }

    let sort = query.sort.unwrap_or_default();
    let direction = if query.direction.as_deref() == Some("desc") {
        -1_i64
    } else {
        1_i64
    };
    if !sort.is_empty() {
        items.sort_by(|a, b| {
            let av = decision_field(a, &sort);
            let bv = decision_field(b, &sort);
            if direction > 0 {
                av.cmp(&bv)
            } else {
                bv.cmp(&av)
            }
        });
    }

    let total = items.len();
    let offset = clamp_usize(query.offset.as_deref(), 0, 0, 1_000_000);
    let limit = clamp_usize(query.limit.as_deref(), 50, 1, 200);
    let page = items
        .iter()
        .skip(offset)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    let countries = items
        .iter()
        .map(|x| x.country.clone())
        .filter(|x| !x.is_empty())
        .collect::<HashSet<_>>()
        .len();
    let scenarios = items
        .iter()
        .map(|x| x.scenario.clone())
        .filter(|x| !x.is_empty())
        .collect::<HashSet<_>>()
        .len();
    let blocked_ips = items
        .iter()
        .filter(|x| x.scope.eq_ignore_ascii_case("ip"))
        .map(|x| x.ip.clone())
        .filter(|x| !x.is_empty())
        .collect::<HashSet<_>>();

    let mut origins: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for item in &items {
        if item.scope.eq_ignore_ascii_case("ip") && !item.ip.is_empty() {
            origins
                .entry(item.origin.to_lowercase())
                .or_default()
                .insert(item.ip.clone());
        }
    }
    let blocked_by_origin = origins
        .into_iter()
        .map(|(key, ips)| {
            json!({
                "key": key,
                "label": if key.is_empty() { "Unknown" } else { &key },
                "count": ips.len()
            })
        })
        .collect::<Vec<_>>();

    Ok(Json(json!({
        "generatedAt": Utc::now().to_rfc3339(),
        "cachedAt": Utc::now().to_rfc3339(),
        "cacheSeconds": 60,
        "total": total,
        "matched": items.len(),
        "countries": countries,
        "scenarios": scenarios,
        "topCountries": count_decision_field(&items, |i| i.country.clone()),
        "topScenarios": count_decision_field(&items, |i| i.scenario.clone()),
        "topOrigins": count_decision_field(&items, |i| i.origin.clone()),
        "uniqueBlockedIps": blocked_ips.len(),
        "blockedIpsByOrigin": blocked_by_origin,
        "sort": sort,
        "direction": if direction > 0 { "asc" } else { "desc" },
        "offset": offset,
        "limit": limit,
        "nextOffset": if offset + limit < items.len() { json!(offset + limit) } else { Value::Null },
        "items": page
    })))
}

pub(crate) async fn api_reputation_stats(State(state): State<AppState>) -> ApiResult {
    let cache = read_cti_cache(&state).await;
    Ok(Json(json!({
        "configured": !state.config.cti_api_key.is_empty(),
        "cacheHours": state.config.cti_cache_hours,
        "period": cache["stats"]["period"].as_str().unwrap_or(""),
        "networkRequests": cache["stats"]["networkRequests"].as_i64().unwrap_or(0),
        "cacheHits": cache["stats"]["cacheHits"].as_i64().unwrap_or(0),
        "cachedIps": cache["items"].as_object().map(|x| x.len()).unwrap_or(0)
    })))
}

pub(crate) async fn api_reputation_ip(
    State(state): State<AppState>,
    AxumPath(ip): AxumPath<String>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    if ip.parse::<std::net::IpAddr>().is_err() {
        return err_400("Invalid IP address");
    }
    let force = query.get("refresh").map(|v| v == "1").unwrap_or(false);
    let mut cache = read_cti_cache(&state).await;
    if state.config.cti_api_key.is_empty() {
        return Ok(Json(json!({
            "configured": false,
            "status": "not_configured",
            "summary": "CrowdSec CTI is not configured.",
            "cacheHours": state.config.cti_cache_hours,
            "stats": cache["stats"]
        })));
    }

    let now = Utc::now().timestamp_millis();
    let cached_entry = cache["items"].get(&ip).cloned();
    if !force
        && let Some(entry) = cached_entry
        && let Some(cached_at) = entry["cachedAt"].as_str()
        && let Ok(ts) = DateTime::parse_from_rfc3339(cached_at)
    {
        let age = now - ts.timestamp_millis();
        if age < (state.config.cti_cache_hours as i64) * 3_600_000 {
            let cached_at_text = cached_at.to_string();
            bump_cti_stats(&mut cache, "cacheHits");
            let _ = write_cti_cache(&state, &cache).await;
            return Ok(Json(json!({
                "configured": true,
                "cached": true,
                "cachedAt": cached_at_text,
                "cacheHours": state.config.cti_cache_hours,
                "stats": cache["stats"],
                "status": entry["data"]["status"],
                "summary": entry["data"]["summary"],
                "maliciousness": entry["data"]["maliciousness"],
                "backgroundNoise": entry["data"]["backgroundNoise"],
                "isFalsePositive": entry["data"]["isFalsePositive"],
                "behaviors": entry["data"]["behaviors"],
                "categories": entry["data"]["categories"],
                "asName": entry["data"]["asName"],
                "country": entry["data"]["country"],
                "firstSeen": entry["data"]["firstSeen"],
                "lastSeen": entry["data"]["lastSeen"],
                "webUrl": format!("https://app.crowdsec.net/cti/{ip}"),
                "shodanUrl": format!("https://www.shodan.io/host/{ip}")
            })));
        }
    }

    let url = format!(
        "{}/smoke/{}",
        state.config.cti_api_url.trim_end_matches('/'),
        ip
    );
    let response = state
        .client
        .get(url)
        .header("x-api-key", &state.config.cti_api_key)
        .send()
        .await;
    crate::debug!(network = "outbound", service = "cti", operation = "reputation", ip = %ip, result = if response.is_ok() { "success" } else { "error" }, "network request completed");
    let response = match response {
        Ok(r) => r,
        Err(err) => return err_502(err.to_string()),
    };
    if !response.status().is_success() {
        return err_502(format!(
            "CrowdSec CTI failed with HTTP {}",
            response.status()
        ));
    }
    let raw: Value = response.json().await.unwrap_or_else(|_| json!({}));
    let maliciousness = first_number(&[
        raw.pointer("/scores/overall/aggressiveness"),
        raw.pointer("/scores/overall/maliciousness"),
        raw.pointer("/maliciousness"),
    ]);
    let behaviors = collect_strings(&[
        raw.get("behaviors"),
        raw.get("classifications"),
        raw.pointer("/reputation/behaviors"),
    ]);
    let status = if raw
        .pointer("/is_false_positive")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        "false_positive"
    } else if maliciousness >= 0.8 || behaviors.len() >= 3 {
        "malicious"
    } else if maliciousness >= 0.35 || !behaviors.is_empty() {
        "suspicious"
    } else {
        "unknown"
    };
    let data = json!({
        "status": status,
        "summary": match status {
            "false_positive" => "Flagged as possible false positive by CrowdSec CTI.",
            "malicious" => "Known aggressive IP in CrowdSec CTI.",
            "suspicious" => "CrowdSec CTI has suspicious behavior context for this IP.",
            _ => "No strong malicious reputation signal returned by CrowdSec CTI."
        },
        "maliciousness": maliciousness,
        "backgroundNoise": first_number(&[raw.pointer("/scores/overall/background_noise"), raw.get("background_noise")]),
        "isFalsePositive": raw.pointer("/is_false_positive").and_then(Value::as_bool).unwrap_or(false),
        "behaviors": behaviors,
        "categories": collect_strings(&[raw.get("categories"), raw.pointer("/reputation/categories")]),
        "asName": raw.get("as_name").and_then(Value::as_str).unwrap_or(""),
        "country": raw.get("country").and_then(Value::as_str).unwrap_or(""),
        "firstSeen": raw.get("first_seen").and_then(Value::as_str).unwrap_or(""),
        "lastSeen": raw.get("last_seen").and_then(Value::as_str).unwrap_or("")
    });

    bump_cti_stats(&mut cache, "networkRequests");
    let cached_at = Utc::now().to_rfc3339();
    if !cache["items"].is_object() {
        cache["items"] = json!({});
    }
    cache["items"][ip.clone()] = json!({ "cachedAt": cached_at, "data": data });
    let _ = write_cti_cache(&state, &cache).await;
    Ok(Json(json!({
        "configured": true,
        "cached": false,
        "cachedAt": cached_at,
        "cacheHours": state.config.cti_cache_hours,
        "stats": cache["stats"],
        "status": data["status"],
        "summary": data["summary"],
        "maliciousness": data["maliciousness"],
        "backgroundNoise": data["backgroundNoise"],
        "isFalsePositive": data["isFalsePositive"],
        "behaviors": data["behaviors"],
        "categories": data["categories"],
        "asName": data["asName"],
        "country": data["country"],
        "firstSeen": data["firstSeen"],
        "lastSeen": data["lastSeen"],
        "webUrl": format!("https://app.crowdsec.net/cti/{ip}"),
        "shodanUrl": format!("https://www.shodan.io/host/{ip}")
    })))
}

pub(crate) async fn api_lapi_status(State(state): State<AppState>) -> ApiResult {
    let stored = read_json_file(&state.config.lapi_credentials_file)
        .await
        .unwrap_or_else(|| json!({}));
    let watcher_env = !state.config.lapi_login.is_empty() && !state.config.lapi_password.is_empty();
    let decisions_env = !state.config.lapi_api_key.is_empty();
    let watcher_file = stored.get("login").and_then(Value::as_str).unwrap_or("") != ""
        && stored.get("password").and_then(Value::as_str).unwrap_or("") != "";
    let decisions_file = stored.get("apiKey").and_then(Value::as_str).unwrap_or("") != "";
    Ok(Json(json!({
        "file": state.config.lapi_credentials_file,
        "watcherConfigured": watcher_env || watcher_file,
        "decisionsConfigured": decisions_env || decisions_file,
        "managed": watcher_file || decisions_file,
        "autoSetupEnabled": false
    })))
}

pub(crate) async fn api_investigation_sources(State(state): State<AppState>) -> ApiResult {
    let sources = resolve_log_sources(&state.config.investigation_log_paths).await;
    crate::debug!(configured_paths = ?state.config.investigation_log_paths, readable_files = sources.len(), "investigation sources request completed");
    Ok(Json(json!({
        "configuredPaths": state.config.investigation_log_paths,
        "autoDetectEnabled": false,
        "crowdsecContainer": state.config.crowdsec_container,
        "sources": sources
    })))
}

pub(crate) async fn api_investigation_ip(
    State(state): State<AppState>,
    AxumPath(ip): AxumPath<String>,
    Query(query): Query<InvestigationQuery>,
) -> ApiResult {
    if ip.parse::<std::net::IpAddr>().is_err() {
        return err_400("Invalid IP address");
    }
    let days = clamp_u64(query.days.as_deref(), 7, 1, 180);
    let max_lines = clamp_usize(
        query.max_lines.as_deref(),
        state.config.investigation_max_lines,
        1,
        200,
    );
    let since = Utc::now() - chrono::Duration::days(days as i64);
    crate::debug!(ip = %ip, days, max_lines, "IP investigation started");
    let sources = resolve_log_sources(&state.config.investigation_log_paths).await;
    let mut out = Vec::new();
    let mut total_hits = 0_i64;
    let mut total_forbidden = 0_i64;

    for source in &sources {
        let path = source["path"].as_str().unwrap_or("");
        let contents = match fs::read_to_string(path).await {
            Ok(contents) => contents,
            Err(err) => {
                crate::warn!(ip = %ip, path = %path, error = %err, "unable to read investigation log");
                continue;
            }
        };
        let mut hits = 0_i64;
        let mut forbidden = 0_i64;
        let mut sampled = Vec::new();
        for line in contents.lines() {
            if !line.contains(&ip) {
                continue;
            }
            if let Some(ts) = parse_line_timestamp(line)
                && ts < since
            {
                continue;
            }
            hits += 1;
            let is_forbidden =
                line.contains("403") || line.contains(" 429 ") || line.contains(" 444 ");
            if is_forbidden {
                forbidden += 1;
            }
            if sampled.len() < max_lines {
                sampled.push(truncate_line(line, 700));
            }
        }
        total_hits += hits;
        total_forbidden += forbidden;
        crate::debug!(ip = %ip, path = %path, bytes = contents.len(), hits, forbidden, "investigation log scanned");
        out.push(json!({
            "name": source["name"],
            "path": source["path"],
            "location": source["location"],
            "hits": hits,
            "forbidden": forbidden,
            "sampledLines": sampled,
            "timedOut": false
        }));
    }

    let active_bans = read_active_bans_for_ip(&state, &ip).await;
    crate::info!(ip = %ip, files = out.len(), total_hits, total_forbidden, "IP investigation completed");
    Ok(Json(json!({
        "ip": ip,
        "days": days,
        "generatedAt": Utc::now().to_rfc3339(),
        "configuredPaths": state.config.investigation_log_paths,
        "availableFiles": sources.len(),
        "scannedFiles": out.len(),
        "totalHits": total_hits,
        "totalForbidden": total_forbidden,
        "activeBans": active_bans,
        "maxLines": max_lines,
        "maxSampleLines": 200,
        "timedOut": false,
        "sources": out,
        "warning": if sources.is_empty() { "No readable log files found." } else { "" }
    })))
}

pub(crate) async fn api_investigation_log_lines(
    State(_state): State<AppState>,
    AxumPath(ip): AxumPath<String>,
    Query(query): Query<InvestigationLinesQuery>,
) -> ApiResult {
    if ip.parse::<std::net::IpAddr>().is_err() {
        return err_400("Invalid IP address");
    }
    let path = query.path.unwrap_or_default();
    if path.is_empty() {
        return err_400("Investigation log source is not configured or readable.");
    }
    let days = clamp_u64(query.days.as_deref(), 7, 1, 180);
    let offset = clamp_usize(query.offset.as_deref(), 0, 0, 1_000_000);
    let limit = clamp_usize(query.limit.as_deref(), 200, 1, 500);
    let filter = query.filter.unwrap_or_else(|| "all".to_string());
    let sort = query.sort.unwrap_or_else(|| "newest".to_string());
    let search = query.search.unwrap_or_default().to_lowercase();
    let since = Utc::now() - chrono::Duration::days(days as i64);

    let contents = match fs::read_to_string(&path).await {
        Ok(contents) => contents,
        Err(err) => {
            crate::warn!(ip = %ip, path = %path, error = %err, "unable to read investigation log lines");
            return err_500(format!("unable to read investigation log: {err}"));
        }
    };
    let mut lines = Vec::new();
    let mut total_hits = 0_i64;
    let mut total_forbidden = 0_i64;

    for line in contents.lines() {
        if !line.contains(&ip) {
            continue;
        }
        if !search.is_empty() && !line.to_lowercase().contains(&search) {
            continue;
        }
        if let Some(ts) = parse_line_timestamp(line)
            && ts < since
        {
            continue;
        }
        let forbidden = line.contains("403") || line.contains(" 429 ") || line.contains(" 444 ");
        total_hits += 1;
        if forbidden {
            total_forbidden += 1;
        }
        if (filter == "forbidden" && !forbidden) || (filter == "non-forbidden" && forbidden) {
            continue;
        }
        lines.push(json!({
            "timestamp": parse_line_timestamp(line).map(|ts| ts.to_rfc3339()).unwrap_or_default(),
            "forbidden": forbidden,
            "line": truncate_line(line, 700)
        }));
    }

    if sort == "newest" {
        lines.reverse();
    }

    let filtered_hits = lines.len();
    let page = lines
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    crate::debug!(ip = %ip, path = %path, days, total_hits, total_forbidden, filtered_hits, returned_lines = page.len(), "investigation log lines request completed");
    let next_offset = if offset + limit < filtered_hits {
        json!(offset + limit)
    } else {
        Value::Null
    };

    Ok(Json(json!({
        "ip": ip,
        "path": path,
        "days": days,
        "totalHits": total_hits,
        "totalForbidden": total_forbidden,
        "filteredHits": filtered_hits,
        "offset": offset,
        "limit": limit,
        "nextOffset": next_offset,
        "lines": page
    })))
}

pub(crate) async fn refresh_protection_cache(state: &AppState) {
    for days in [1_u64, 3, 7] {
        let payload = match scan_protection(state, days).await {
            Ok(Json(payload)) => payload,
            Err(_) => continue,
        };
        let now = Utc::now().timestamp_millis();
        let expires = now + (state.config.protection_refresh_seconds.max(1) as i64 * 1000);
        let conn = match open_history_connection(state) {
            Ok(conn) => conn,
            Err(err) => {
                crate::error!(error = %err, "unable to open protection cache database");
                return;
            }
        };
        if let Err(err) = conn.execute(
            "INSERT INTO protection_cache (days, generated_at_ms, expires_at_ms, payload) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(days) DO UPDATE SET generated_at_ms = excluded.generated_at_ms, expires_at_ms = excluded.expires_at_ms, payload = excluded.payload",
            rusqlite::params![days as i64, now, expires, payload.to_string()],
        ) {
            crate::error!(days, error = %err, "unable to update protection cache");
            return;
        }
    }
}

pub(crate) async fn api_protection(
    State(state): State<AppState>,
    Query(query): Query<DaysQuery>,
) -> ApiResult {
    let days = clamp_u64(query.days.as_deref(), 1, 1, 7);
    if let Ok(conn) = open_history_connection(&state)
        && let Ok(payload) = conn.query_row(
            "SELECT expires_at_ms, payload FROM protection_cache WHERE days = ?1",
            rusqlite::params![days as i64],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )
        && payload.0 > Utc::now().timestamp_millis()
        && let Ok(value) = serde_json::from_str::<Value>(&payload.1)
    {
        return Ok(Json(value));
    }
    scan_protection(&state, days).await
}

async fn scan_protection(state: &AppState, days: u64) -> ApiResult {
    let since = Utc::now() - chrono::Duration::days(days as i64);
    let sources = resolve_log_sources(&state.config.protection_log_paths).await;
    crate::info!(days, configured_paths = ?state.config.protection_log_paths, discovered_files = sources.len(), "starting proxy log scan");

    let source_paths = sources
        .iter()
        .filter_map(|source| source["path"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    let fingerprints = source_paths
        .iter()
        .map(|path| {
            let metadata = std::fs::metadata(path).ok();
            let bytes = metadata
                .as_ref()
                .map(|metadata| metadata.len())
                .unwrap_or(0);
            let modified_ms = metadata
                .and_then(|metadata| metadata.modified().ok())
                .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_millis() as i64)
                .unwrap_or(0);
            (path.clone(), bytes as i64, modified_ms)
        })
        .collect::<Vec<_>>();
    let total_files = source_paths.len();
    let scan = async move {
        let mut timeline: BTreeMap<String, (i64, i64)> = BTreeMap::new();
        let mut hosts: HashMap<String, (i64, i64)> = HashMap::new();
        let mut parsed_requests = 0_i64;
        for (file_index, path) in source_paths.into_iter().enumerate() {
            let started = std::time::Instant::now();
            let bytes = tokio::fs::metadata(&path)
                .await
                .map(|metadata| metadata.len())
                .unwrap_or(0);
            crate::debug!(file = file_index + 1, total_files, path = %path, "scanning proxy access log");
            let is_gzip = path.ends_with(".gz");
            if is_gzip {
                let gzip_path = path.clone();
                let result = match tokio::task::spawn_blocking(move || {
                    let file = std::fs::File::open(&gzip_path)?;
                    let decoder = GzDecoder::new(file);
                    let mut lines = StdBufReader::new(decoder).lines();
                    let mut timeline = BTreeMap::new();
                    let mut hosts = HashMap::new();
                    let mut parsed_requests = 0_i64;
                    while let Some(line) = lines.next() {
                        accumulate_proxy_line(
                            &line?,
                            since,
                            &mut timeline,
                            &mut hosts,
                            &mut parsed_requests,
                        );
                    }
                    Ok::<_, std::io::Error>((timeline, hosts, parsed_requests))
                })
                .await
                {
                    Ok(Ok(result)) => result,
                    Ok(Err(err)) => {
                        crate::warn!(path = %path, bytes, error = %err, "unable to decompress proxy access log");
                        continue;
                    }
                    Err(err) => {
                        crate::warn!(path = %path, bytes, error = %err, "proxy access log decompression task failed");
                        continue;
                    }
                };
                let (file_timeline, file_hosts, file_requests) = result;
                parsed_requests += file_requests;
                for (hour, (requests, blocked)) in file_timeline {
                    let entry = timeline.entry(hour).or_insert((0, 0));
                    entry.0 += requests;
                    entry.1 += blocked;
                }
                for (host, (requests, blocked)) in file_hosts {
                    let entry = hosts.entry(host).or_insert((0, 0));
                    entry.0 += requests;
                    entry.1 += blocked;
                }
                crate::debug!(file = file_index + 1, total_files, path = %path, bytes, file_requests, elapsed_ms = started.elapsed().as_millis(), "compressed proxy access log scanned");
                continue;
            }
            let file = match tokio::fs::File::open(&path).await {
                Ok(file) => file,
                Err(err) => {
                    crate::warn!(file = file_index + 1, total_files, path = %path, bytes, error = %err, "unable to open proxy access log");
                    continue;
                }
            };
            let mut lines = BufReader::new(file).lines();
            loop {
                let line = match lines.next_line().await {
                    Ok(Some(line)) => line,
                    Ok(None) => break,
                    Err(err) => {
                        crate::warn!(path = %path, bytes, error = %err, "unable to read proxy access log");
                        break;
                    }
                };
                accumulate_proxy_line(
                    &line,
                    since,
                    &mut timeline,
                    &mut hosts,
                    &mut parsed_requests,
                );
            }
            crate::debug!(file = file_index + 1, total_files, path = %path, bytes, parsed_requests, elapsed_ms = started.elapsed().as_millis(), "proxy access log scanned");
        }
        (timeline, hosts, parsed_requests)
    };
    let timeout_ms = state.config.investigation_timeout_ms.max(100);
    let (timeline, hosts, parsed_requests) = match tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        scan,
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            crate::error!(
                days,
                files = sources.len(),
                timeout_ms,
                "proxy log scan timed out while streaming files"
            );
            return err_500(
                "proxy log scan timed out; increase INVESTIGATION_TIMEOUT_MS, rotate logs, or check mounted paths",
            );
        }
    };

    let processed_total = hosts.values().map(|(processed, _)| *processed).sum::<i64>();
    let blocked_total = hosts.values().map(|(_, blocked)| *blocked).sum::<i64>();
    let mut host_items = hosts
        .into_iter()
        .map(|(hostname, (processed, blocked))| {
            json!({
                "hostname": hostname,
                "processedRequests": processed,
                "httpBlockedRequests": blocked,
                "blockRate": pct(blocked, processed)
            })
        })
        .collect::<Vec<_>>();
    host_items.sort_by(|a, b| {
        b["httpBlockedRequests"]
            .as_i64()
            .unwrap_or(0)
            .cmp(&a["httpBlockedRequests"].as_i64().unwrap_or(0))
    });
    host_items.truncate(20);

    let timeline_items = timeline
        .into_iter()
        .map(|(timestamp, (processed, blocked))| {
            json!({
                "timestamp": timestamp,
                "processedRequests": processed,
                "httpBlockedRequests": blocked
            })
        })
        .collect::<Vec<_>>();

    let payload = json!({
        "days": days,
        "generatedAt": Utc::now().to_rfc3339(),
        "availableFiles": sources.len(),
        "parsedRequests": parsed_requests,
        "timedOut": false,
        "warning": if sources.is_empty() { "No readable proxy access logs found. Mount Zoraxy logs and configure PROTECTION_LOG_PATHS." } else { "" },
        "totals": {
            "processedRequests": processed_total,
            "httpBlockedRequests": blocked_total,
            "activeHostnames": host_items.len(),
            "blockRate": pct(blocked_total, processed_total)
        },
        "hosts": host_items,
        "timeline": timeline_items
    });
    if let Ok(conn) = open_history_connection(state) {
        let _ = conn.execute("DELETE FROM protection_scan_files", []);
        for (path, bytes, modified_ms) in fingerprints {
            let _ = conn.execute(
                "INSERT INTO protection_scan_files (path, bytes, modified_ms) VALUES (?1, ?2, ?3)",
                rusqlite::params![path, bytes, modified_ms],
            );
        }
    }
    Ok(Json(payload))
}

fn accumulate_proxy_line(
    line: &str,
    since: chrono::DateTime<Utc>,
    timeline: &mut BTreeMap<String, (i64, i64)>,
    hosts: &mut HashMap<String, (i64, i64)>,
    parsed_requests: &mut i64,
) {
    let Some(ts) = parse_line_timestamp(line) else {
        return;
    };
    if ts < since {
        return;
    }
    *parsed_requests += 1;
    let forbidden = line.contains("403") || line.contains(" 429 ") || line.contains(" 444 ");
    let hour = ts.format("%Y-%m-%dT%H:00:00Z").to_string();
    let host = parse_host(line).unwrap_or_else(|| "unknown host".to_string());
    let timeline_entry = timeline.entry(hour).or_insert((0, 0));
    timeline_entry.0 += 1;
    if forbidden {
        timeline_entry.1 += 1;
    }
    let host_entry = hosts.entry(host).or_insert((0, 0));
    host_entry.0 += 1;
    if forbidden {
        host_entry.1 += 1;
    }
}

pub(crate) async fn api_update_status(State(state): State<AppState>) -> ApiResult {
    let runtime = read_runtime_revision().await;
    let remote = read_remote_revision(&state).await;
    let runtime_ok = runtime.as_ref().ok();
    let remote_ok = remote.as_ref().ok();

    if runtime_ok.is_none() || remote_ok.is_none() {
        let runtime_error = runtime.as_ref().err().map(|e| e.to_string());
        let remote_error = remote.as_ref().err().map(|e| e.to_string());
        let unavailable_message = [runtime_error, remote_error]
            .into_iter()
            .flatten()
            .collect::<Vec<String>>()
            .join(" | ");

        return Ok(Json(json!({
            "state": "unavailable",
            "message": unavailable_message,
            "image": runtime_ok.map(|x| x.0.clone()).unwrap_or_default(),
            "runningRevision": runtime_ok.map(|x| x.1.clone()).unwrap_or_default(),
            "devRevision": remote_ok.map(|x| x.0.clone()).unwrap_or_default(),
            "devUrl": remote_ok.map(|x| x.1.clone()).unwrap_or_default()
        })));
    }

    let (image, running_revision) = runtime_ok.cloned().unwrap_or_default();
    let (dev_revision, dev_url) = remote_ok.cloned().unwrap_or_default();
    let current = running_revision == dev_revision;
    Ok(Json(json!({
        "state": if current { "current" } else { "update_available" },
        "image": image,
        "runningRevision": running_revision,
        "devRevision": dev_revision,
        "devUrl": dev_url,
        "message": if current { "Running image matches the GitHub dev branch." } else { "A newer dev image is available. Run Force Update in Unraid." }
    })))
}

pub(crate) async fn api_access_log_summary(
    State(state): State<AppState>,
    Query(query): Query<DaysQuery>,
) -> ApiResult {
    let days = clamp_u64(
        query.days.as_deref(),
        1,
        1,
        state.config.access_log_retention_days.max(1),
    );
    if !state.config.access_log_enabled {
        return Ok(Json(json!({
            "enabled": false,
            "days": days,
            "retentionDays": state.config.access_log_retention_days,
            "total": 0,
            "visits24h": 0,
            "uniqueIps": 0,
            "topIps": [],
            "topCountries": [],
            "recent": []
        })));
    }
    let contents = fs::read_to_string(&state.config.access_log_file)
        .await
        .unwrap_or_default();
    let mut entries = Vec::new();
    let since = Utc::now() - chrono::Duration::days(days as i64);
    let since_24 = Utc::now() - chrono::Duration::hours(24);
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(line) {
            let ts = value.get("ts").and_then(Value::as_str).unwrap_or("");
            if let Ok(parsed) = DateTime::parse_from_rfc3339(ts) {
                if parsed.with_timezone(&Utc) >= since {
                    entries.push(value);
                }
            }
        }
    }
    let visits_24h = entries
        .iter()
        .filter(|v| {
            DateTime::parse_from_rfc3339(v.get("ts").and_then(Value::as_str).unwrap_or(""))
                .map(|d| d.with_timezone(&Utc) >= since_24)
                .unwrap_or(false)
        })
        .count();
    let unique_ips = entries
        .iter()
        .filter_map(|v| v.get("ip").and_then(Value::as_str))
        .collect::<HashSet<_>>()
        .len();

    let mut ip_counts: HashMap<String, i64> = HashMap::new();
    let mut country_counts: HashMap<String, i64> = HashMap::new();
    for item in &entries {
        let ip = item
            .get("ip")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let country = item
            .get("country")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        *ip_counts.entry(ip).or_insert(0) += 1;
        *country_counts.entry(country).or_insert(0) += 1;
    }

    Ok(Json(json!({
        "enabled": true,
        "days": days,
        "retentionDays": state.config.access_log_retention_days,
        "total": entries.len(),
        "visits24h": visits_24h,
        "uniqueIps": unique_ips,
        "topIps": map_counts(ip_counts, 10),
        "topCountries": map_counts(country_counts, 10),
        "recent": entries.into_iter().take(80).collect::<Vec<_>>()
    })))
}

fn err_400(message: impl Into<String>) -> ApiResult {
    Err((
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": message.into() })),
    ))
}

fn err_500(message: impl Into<String>) -> ApiResult {
    let message = message.into();
    crate::error!(error = %message, "api request failed");
    Err((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": message })),
    ))
}

fn err_502(message: impl Into<String>) -> ApiResult {
    Err((
        StatusCode::BAD_GATEWAY,
        Json(json!({ "error": message.into() })),
    ))
}

fn enrich_decision_countries(state: &AppState, items: &mut [ActiveBan]) {
    let mut geoip_matches = 0;
    for item in &mut *items {
        if country_is_missing(&item.country)
            && let Some(country) = lookup_geoip_country(state, &item.ip)
        {
            item.country = country;
            geoip_matches += 1;
        }
    }

    let conn = match open_history_connection(state) {
        Ok(conn) => conn,
        Err(err) => {
            crate::debug!(error = %err, "decision country enrichment unavailable");
            return;
        }
    };
    let mut countries = HashMap::new();
    let mut cidr_countries = HashMap::new();
    let mut statement = match conn.prepare(
        "SELECT ip, cidr24, country FROM alerts WHERE country <> '' AND country <> '??' ORDER BY seen_at_ms DESC",
    ) {
        Ok(statement) => statement,
        Err(err) => {
            crate::debug!(error = %err, "decision country query failed");
            return;
        }
    };
    let rows = match statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    }) {
        Ok(rows) => rows,
        Err(err) => {
            crate::debug!(error = %err, "decision country rows unavailable");
            return;
        }
    };
    for row in rows.flatten() {
        countries.entry(row.0).or_insert_with(|| row.2.clone());
        cidr_countries.entry(row.1).or_insert(row.2);
    }
    for item in &mut *items {
        if country_is_missing(&item.country) {
            let exact_country = countries
                .get(&item.ip)
                .or_else(|| countries.get(&item.value));
            let ip_cidr = to_cidr24(&item.ip);
            let value_cidr = to_cidr24(&item.value);
            let cidr_country = cidr_countries
                .get(ip_cidr.as_str())
                .or_else(|| cidr_countries.get(value_cidr.as_str()));
            if let Some(country) = exact_country.or(cidr_country) {
                item.country = country.clone();
            }
        }
    }
    crate::debug!(
        decisions = items.len(),
        geoip_matches,
        countries = countries.len(),
        cidr_countries = cidr_countries.len(),
        "decision countries enriched"
    );
}

fn country_is_missing(country: &str) -> bool {
    country.trim().is_empty() || country == "??"
}

fn lookup_geoip_country(state: &AppState, value: &str) -> Option<String> {
    let ip = value.parse::<IpAddr>().ok()?;
    let reader = state.geoip_reader.read().ok()?.as_ref()?.clone();
    let record: maxminddb::geoip2::Country = reader.lookup(ip).ok()??;
    record.country?.iso_code.map(str::to_string)
}
