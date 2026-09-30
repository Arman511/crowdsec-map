use std::env;

use askama::Template;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::{Datelike, Duration as ChronoDuration, Utc, Weekday};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use serde_json::{Value, json};
use tokio::fs;

use crate::AppState;
use crate::models::models::Alert;
use crate::models::security_report::{
    BehaviorSummary, EmailMetricRow, SecurityReportEmailTemplate, SecuritySummary,
};

pub(crate) fn parse_email_recipients(value: &str) -> Vec<String> {
    let recipients = value
        .split(['\n', ',', ';'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    crate::debug!(
        raw_value_len = value.len(),
        recipients = recipients.len(),
        "parsed email recipients"
    );
    for recipient in &recipients {
        crate::trace!(recipient = %recipient, "email recipient parsed");
    }

    recipients
}

pub(crate) fn redact_smtp_username(username: &str) -> String {
    let trimmed = username.trim();
    if trimmed.is_empty() {
        crate::trace!("SMTP username is empty; redacting to placeholder");
        return "<empty>".to_string();
    }

    let username_part = trimmed.split('@').next().unwrap_or(trimmed);
    let suffix = trimmed
        .strip_prefix(username_part)
        .unwrap_or("")
        .to_string();
    let prefix = username_part.chars().take(4).collect::<String>();
    let redacted = format!("{prefix}***{suffix}");
    crate::trace!(redacted = %redacted, "SMTP username redacted");
    redacted
}

fn build_email_subject(config: &crate::Config, public_ip: &str, generated_at: &str) -> String {
    let rendered = config.email_subject.trim();
    let date_range = format_date_range_for_last_7_days(generated_at);
    let template = if rendered.is_empty() {
        "Security Report for {{public_ip}} account: {{date_range}}".to_string()
    } else {
        rendered.to_string()
    };
    let subject = substitute_email_subject_template(&template, public_ip, &date_range);
    let final_subject = if subject.trim().is_empty() {
        format!("Security Report for {public_ip} account: {date_range}")
    } else {
        subject
    };

    crate::debug!(
        subject_template = %template,
        public_ip = %public_ip,
        date_range = %date_range,
        final_subject = %final_subject,
        "security report email subject built"
    );
    final_subject
}

pub(crate) fn substitute_email_subject_template(
    template: &str,
    public_ip: &str,
    date_range: &str,
) -> String {
    template
        .replace("{{pub ip}}", public_ip)
        .replace("{{public ip}}", public_ip)
        .replace("{{public_ip}}", public_ip)
        .replace("{{pub_ip}}", public_ip)
        .replace("{{publicIP}}", public_ip)
        .replace("{{date_range}}", date_range)
        .replace("{{range}}", date_range)
}

pub(crate) fn parse_sender_mailbox(value: &str) -> Result<lettre::message::Mailbox, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("email sender is empty".to_string());
    }

    if let Ok(address) = trimmed.parse::<lettre::Address>() {
        return Ok(lettre::message::Mailbox::new(None, address));
    }

    if let Some(open_brace) = trimmed.rfind('<') {
        if let Some(close_brace) = trimmed.rfind('>') {
            if open_brace < close_brace && close_brace == trimmed.len() - 1 {
                let name = trimmed[..open_brace].trim();
                let inner = trimmed[open_brace + 1..close_brace].trim();
                if let Ok(address) = inner.parse::<lettre::Address>() {
                    let mailbox_name = if name.is_empty() {
                        None
                    } else {
                        Some(name.to_string())
                    };
                    return Ok(lettre::message::Mailbox::new(mailbox_name, address));
                }
            }
        }
    }

    Err(format!("invalid sender email address: {trimmed}"))
}

fn format_date_range_for_last_7_days(generated_at: &str) -> String {
    let parsed = chrono::DateTime::parse_from_rfc3339(generated_at)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let end = parsed.date_naive();
    let start = end - chrono::Duration::days(7);
    format!("{} - {}", start.format("%b %d"), end.format("%b %d, %Y"))
}

fn is_authorized_manual_report_request(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
    let configured_tokens = [
        env::var("REPORT_TRIGGER_TOKEN")
            .ok()
            .unwrap_or_default()
            .trim()
            .to_string(),
        env::var("REPORT_API_KEY")
            .ok()
            .unwrap_or_default()
            .trim()
            .to_string(),
    ];
    let configured = configured_tokens
        .iter()
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if configured.is_empty() {
        return false;
    }

    let authorization = headers
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .map(str::trim)
        .unwrap_or_default();
    if let Some(value) = headers
        .get("x-api-key")
        .and_then(|header| header.to_str().ok())
    {
        let token = value.trim();
        if !token.is_empty() && configured.iter().any(|expected| expected.as_str() == token) {
            return true;
        }
    }
    if authorization.to_ascii_lowercase().starts_with("bearer ") {
        let token = authorization[7..].trim();
        if !token.is_empty() && configured.iter().any(|expected| expected.as_str() == token) {
            return true;
        }
    }
    if let Some(rest) = authorization.strip_prefix("Basic ") {
        let decoded = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, rest)
        {
            Ok(bytes) => String::from_utf8(bytes).unwrap_or_default(),
            Err(_) => String::new(),
        };
        let Some((username, password)) = decoded.split_once(':') else {
            return false;
        };
        return !state.config.lapi_login.trim().is_empty()
            && !state.config.lapi_password.trim().is_empty()
            && username == state.config.lapi_login
            && password == state.config.lapi_password;
    }
    false
}

pub async fn api_trigger_security_report(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if !is_authorized_manual_report_request(&state, &headers) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "ok": false,
                "error": "manual security report trigger requires authentication",
            })),
        ));
    }

    crate::debug!(
        email_enabled = state.config.email_enabled,
        smtp_host_configured = !state.config.smtp_host.trim().is_empty(),
        recipients = state
            .config
            .email_recipients
            .len()
            .max(parse_email_recipients(&state.config.email_to).len()),
        "manual security report trigger received"
    );
    match send_security_report_for_last_7_days(&state).await {
        Ok(sent) => Ok(Json(json!({
            "ok": true,
            "sent": sent,
            "enabled": state.config.email_enabled,
            "windowDays": 7,
        }))),
        Err(err) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "ok": false,
                "error": err,
            })),
        )),
    }
}

pub async fn send_weekly_report_if_due(state: &AppState) -> Result<(), String> {
    if !state.config.email_enabled {
        crate::trace!("weekly security report disabled; skipping due check");
        return Ok(());
    }

    let recipients = if !state.config.email_recipients.is_empty() {
        state.config.email_recipients.clone()
    } else {
        parse_email_recipients(&state.config.email_to)
    };
    if state.config.smtp_host.trim().is_empty() || recipients.is_empty() {
        crate::warn!(
            enabled = state.config.email_enabled,
            smtp_host_configured = !state.config.smtp_host.trim().is_empty(),
            recipient_configured = !recipients.is_empty(),
            "email reporting is enabled but SMTP details are incomplete; skipping report"
        );
        return Ok(());
    }

    let now = Utc::now();
    if now.weekday() != Weekday::Mon {
        crate::trace!(weekday = ?now.weekday(), "weekly security report due check skipped because today is not Monday");
        return Ok(());
    }

    let today = now.format("%Y-%m-%d").to_string();
    let stamp_path = weekly_report_stamp_path(state);
    if let Ok(existing) = fs::read_to_string(&stamp_path).await {
        let trimmed = existing.trim();
        if !trimmed.is_empty() && trimmed == today {
            crate::debug!(stamp_path = %stamp_path, sent_on = %today, "weekly security report already sent today; skipping");
            return Ok(());
        }
    }

    crate::debug!(stamp_path = %stamp_path, sent_on = %today, recipients = recipients.len(), "sending weekly security report");
    let report = build_report_for_last_7_days(state).await?;
    if let Err(err) = persist_report_delivery_stamp(&stamp_path, &today).await {
        crate::error!(stamp_path = %stamp_path, sent_on = %today, error = %err, "weekly security report delivery stamp could not be persisted");
        return Err(format!(
            "failed to persist weekly report delivery stamp: {err}"
        ));
    }

    match send_security_report_email(state, &report).await {
        Ok(()) => {
            crate::info!(
                sent_on = %today,
                total_attacks = report.total_attacks,
                "weekly security report email sent"
            );
            Ok(())
        }
        Err(err) => {
            let _ = fs::remove_file(&stamp_path).await;
            Err(err)
        }
    }
}

pub async fn send_security_report_for_last_7_days(state: &AppState) -> Result<bool, String> {
    if !state.config.email_enabled {
        crate::debug!("manual security report requested but email delivery is disabled");
        return Ok(false);
    }

    let recipients = if !state.config.email_recipients.is_empty() {
        state.config.email_recipients.clone()
    } else {
        parse_email_recipients(&state.config.email_to)
    };
    if state.config.smtp_host.trim().is_empty() || recipients.is_empty() {
        crate::warn!(
            smtp_host_configured = !state.config.smtp_host.trim().is_empty(),
            recipient_configured = !recipients.is_empty(),
            "manual security report skipped because SMTP config is incomplete"
        );
        return Err("SMTP host or recipient is not configured".to_string());
    }

    crate::debug!(
        recipients = recipients.len(),
        "building manual security report"
    );
    let report = build_report_for_last_7_days(state).await?;
    send_security_report_email(state, &report).await?;
    crate::info!(
        total_attacks = report.total_attacks,
        "manual security report email sent"
    );
    Ok(true)
}

pub(crate) fn summarize_alerts(alerts: &[Alert], domain: &str) -> SecuritySummary {
    let mut behavior_totals = std::collections::HashMap::new();
    let mut country_totals = std::collections::HashMap::new();
    let mut total_attacks = 0_i64;

    for alert in alerts {
        let count = alert.count.max(0);
        total_attacks += count;
        *behavior_totals
            .entry(clean_behavior_label(&alert.scenario))
            .or_insert(0_i64) += count;

        let country = alert.country.trim();
        if !country.is_empty() && country != "??" {
            *country_totals.entry(country.to_string()).or_insert(0_i64) += count;
        }
    }

    let mut top_behaviors = behavior_totals
        .into_iter()
        .map(|(label, count)| BehaviorSummary { label, count })
        .collect::<Vec<_>>();
    top_behaviors.sort_by(|a, b| b.count.cmp(&a.count));

    let mut top_countries = country_totals
        .into_iter()
        .map(|(label, count)| BehaviorSummary { label, count })
        .collect::<Vec<_>>();
    top_countries.sort_by(|a, b| b.count.cmp(&a.count));

    SecuritySummary {
        total_attacks,
        top_behaviors: top_behaviors.into_iter().take(5).collect(),
        top_countries: top_countries.into_iter().take(5).collect(),
        link: normalize_domain_link(domain),
        generated_at: Utc::now().to_rfc3339(),
    }
}

fn weekly_report_stamp_path(state: &AppState) -> String {
    let history_dir = std::path::Path::new(&state.history_db_path)
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    history_dir
        .join("weekly-report-last-sent.txt")
        .to_string_lossy()
        .into_owned()
}

async fn persist_report_delivery_stamp(
    stamp_path: &str,
    sent_on: &str,
) -> Result<(), std::io::Error> {
    if let Some(parent) = std::path::Path::new(stamp_path).parent() {
        fs::create_dir_all(parent).await?;
    }
    fs::write(stamp_path, sent_on).await
}

pub(crate) fn filter_report_alerts(alerts: Vec<Alert>, source: &str, since_ms: i64) -> Vec<Alert> {
    let normalized = source.trim();
    if normalized.is_empty()
        || normalized.eq_ignore_ascii_case("demo")
        || normalized.eq_ignore_ascii_case("sample")
        || normalized.eq_ignore_ascii_case("demo-snapshot")
    {
        return Vec::new();
    }

    alerts
        .into_iter()
        .filter(|alert| {
            let seen_ms = chrono::DateTime::parse_from_rfc3339(&alert.created_at)
                .map(|dt| dt.timestamp_millis())
                .unwrap_or(i64::MIN);
            seen_ms >= since_ms
        })
        .collect()
}

async fn build_report_for_last_7_days(state: &AppState) -> Result<SecuritySummary, String> {
    let since_ms = (Utc::now() - ChronoDuration::days(7)).timestamp_millis();
    crate::debug!(
        since_ms,
        days = 7,
        "building security report summary from persisted history with any valid live alerts merged in"
    );

    let (alerts, source, _) = crate::read_crowdsec_data(state, "auto").await;
    let recent_live_alerts = filter_report_alerts(alerts, &source, since_ms);

    let conn = crate::open_history_connection(state).map_err(|err| err.to_string())?;
    let mut stmt = conn
        .prepare(
            "SELECT scenario, SUM(CAST(event_count AS INTEGER)) AS total FROM alerts WHERE seen_at_ms >= ?1 GROUP BY scenario ORDER BY total DESC LIMIT 10",
        )
        .map_err(|err| err.to_string())?;

    let rows = stmt
        .query_map([since_ms], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|err| err.to_string())?;

    let mut behavior_totals = std::collections::HashMap::new();
    let mut country_totals = std::collections::HashMap::new();
    let mut total_attacks = 0_i64;
    let mut row_count = 0usize;
    for row in rows {
        let (scenario, count) = row.map_err(|err| err.to_string())?;
        row_count += 1;
        total_attacks += count;
        crate::trace!(scenario = %scenario, count, "security report behavior row loaded");
        *behavior_totals.entry(scenario).or_insert(0_i64) += count;
    }

    for alert in &recent_live_alerts {
        let count = alert.count.max(0);
        total_attacks += count;
        *behavior_totals
            .entry(alert.scenario.clone())
            .or_insert(0_i64) += count;

        let country = alert.country.trim();
        if !country.is_empty() && country != "??" {
            *country_totals.entry(country.to_string()).or_insert(0_i64) += count;
        }
    }

    let mut behaviors = behavior_totals
        .into_iter()
        .map(|(scenario, count)| BehaviorSummary {
            label: clean_behavior_label(&scenario),
            count,
        })
        .collect::<Vec<_>>();

    let mut country_stmt = conn
        .prepare(
            "SELECT country, SUM(CAST(event_count AS INTEGER)) AS total FROM alerts WHERE seen_at_ms >= ?1 AND country <> '' AND country <> '??' GROUP BY country ORDER BY total DESC LIMIT 5",
        )
        .map_err(|err| err.to_string())?;
    let country_rows = country_stmt
        .query_map([since_ms], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|err| err.to_string())?
        .filter_map(|row| row.ok())
        .collect::<Vec<_>>();

    for (country, count) in country_rows {
        *country_totals.entry(country).or_insert(0_i64) += count;
    }

    crate::debug!(
        rows = row_count,
        live_alerts = recent_live_alerts.len(),
        total_attacks,
        "security report behavior rows aggregated"
    );

    behaviors.sort_by(|a, b| b.count.cmp(&a.count));
    let mut top_countries = country_totals
        .into_iter()
        .map(|(country, count)| BehaviorSummary {
            label: country,
            count,
        })
        .collect::<Vec<_>>();
    top_countries.sort_by(|a, b| b.count.cmp(&a.count));
    let top_behaviors = behaviors.into_iter().take(5).collect::<Vec<_>>();
    let top_countries = top_countries.into_iter().take(5).collect::<Vec<_>>();
    let generated_at = Utc::now().to_rfc3339();
    let link = normalize_domain_link(&state.config.crowdsec_map_domain);

    Ok(SecuritySummary {
        total_attacks,
        top_behaviors,
        top_countries,
        link,
        generated_at,
    })
}

pub fn normalize_domain_link(domain: &str) -> String {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return "#".to_string();
    }
    let without_scheme = trimmed
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    let with_scheme =
        if without_scheme.starts_with("http://") || without_scheme.starts_with("https://") {
            without_scheme.to_string()
        } else {
            format!("https://{without_scheme}")
        };
    with_scheme.trim_end_matches('/').to_string()
}

pub(crate) fn clean_behavior_label(scenario: &str) -> String {
    let without_prefix = scenario
        .trim()
        .strip_prefix("crowdsecurity/")
        .unwrap_or(scenario)
        .replace('-', " ")
        .replace('_', " ");
    let mut parts = Vec::new();
    for part in without_prefix.split_whitespace() {
        let lower = part.to_ascii_lowercase();
        let normalized = if matches!(
            lower.as_str(),
            "http"
                | "https"
                | "api"
                | "ip"
                | "tls"
                | "ssl"
                | "ssh"
                | "sql"
                | "dns"
                | "vpn"
                | "tcp"
                | "udp"
                | "json"
                | "xml"
                | "smtp"
                | "imap"
                | "pop3"
        ) {
            lower.to_ascii_uppercase()
        } else {
            let mut chars = part.chars();
            let first = chars
                .next()
                .map(|ch| ch.to_uppercase().next().unwrap_or(ch))
                .unwrap_or_default();
            let rest = chars.collect::<String>();
            format!("{first}{rest}")
        };
        parts.push(normalized);
    }
    parts.join(" ")
}

async fn send_security_report_email(
    state: &AppState,
    report: &SecuritySummary,
) -> Result<(), String> {
    crate::debug!(
        total_attacks = report.total_attacks,
        behaviors = report.top_behaviors.len(),
        generated_at = %report.generated_at,
        "building and sending security report email"
    );
    let html = build_security_email_html(state, report);
    let from_addr = state.config.email_from.trim();
    let recipients = if !state.config.email_recipients.is_empty() {
        state.config.email_recipients.clone()
    } else {
        parse_email_recipients(&state.config.email_to)
    };
    if from_addr.is_empty() || recipients.is_empty() {
        crate::warn!(
            sender_configured = !from_addr.is_empty(),
            recipients = recipients.len(),
            "security report email cannot be sent because sender or recipients are missing"
        );
        return Err("email sender or recipient is not configured".to_string());
    }

    let public_ip = state.public_target_ip.read().await.clone();
    let subject = build_email_subject(&state.config, &public_ip, &report.generated_at);
    let from_mailbox = parse_sender_mailbox(from_addr)?;

    crate::trace!(
        recipient_count = recipients.len(),
        from = %from_addr,
        public_ip = %public_ip,
        "Starting email send attempt"
    );

    let transport = build_transport(&state.config)?;
    let mut last_error = None;

    for recipient in &recipients {
        let Ok(addr) = recipient.parse::<lettre::Address>() else {
            last_error = Some(format!("invalid recipient email address: {recipient}"));
            continue;
        };
        let message = Message::builder()
            .from(from_mailbox.clone())
            .to(addr.into())
            .subject(subject.clone())
            .header(ContentType::TEXT_HTML)
            .body(html.clone())
            .map_err(|err| err.to_string())?;

        crate::trace!("Sending email to recipient: {}", recipient);
        if let Err(err) = transport.send(message).await {
            crate::trace!("Failed to send email to recipient: {}", recipient);
            let detail = err.to_string();
            let detail_lower = detail.to_lowercase();
            let invalid_user = detail_lower.contains("invalid email user")
                || detail_lower.contains("invalid username")
                || detail_lower.contains("authentication failed")
                || detail_lower.contains("535");

            crate::trace!("Logging SMTP email delivery failure details");
            crate::error!(
                smtp_host = %state.config.smtp_host,
                smtp_port = state.config.smtp_port,
                smtp_encryption = %state.config.smtp_encryption,
                smtp_username = %redact_smtp_username(&state.config.smtp_username),
                email_from = %state.config.email_from,
                recipient = %recipient,
                error = %detail,
                invalid_user,
                "SMTP email delivery failed; check SMTP credentials and provider-specific username requirements"
            );

            let friendly_error = if invalid_user {
                format!(
                    "{detail}. SMTP authentication was rejected; check SMTP_USERNAME and provider requirements."
                )
            } else {
                detail
            };

            last_error = Some(friendly_error);
        }
    }

    if let Some(err) = last_error {
        crate::error!(error = %err, "security report email sending failed; no retry configured");
        return Err(format!("mail send failed: {err}"));
    }

    Ok(())
}

fn build_transport(config: &crate::Config) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
    let username = config.smtp_username.trim();
    let password = config.smtp_password.trim();
    let credentials = Credentials::new(username.to_string(), password.to_string());

    let encryption = config.smtp_encryption.trim().to_uppercase();
    let transport = match encryption.as_str() {
        "STARTTLS" => {
            crate::debug!(smtp_host = %config.smtp_host, smtp_port = config.smtp_port, encryption = "STARTTLS", "building SMTP transport");
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
                .map_err(|err| err.to_string())?
                .port(config.smtp_port)
                .credentials(credentials)
                .build()
        }
        "SSL" => {
            crate::debug!(smtp_host = %config.smtp_host, smtp_port = config.smtp_port, encryption = "SSL", "building SMTP transport");
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
                .map_err(|err| err.to_string())?
                .port(config.smtp_port)
                .credentials(credentials)
                .build()
        }
        _ => {
            return Err(format!(
                "unsupported SMTP_ENCRYPTION value: {encryption}; expected STARTTLS or SSL"
            ));
        }
    };
    Ok(transport)
}

fn build_security_email_html(state: &AppState, report: &SecuritySummary) -> String {
    let from = if state.config.crowdsec_map_domain.trim().is_empty() {
        "CrowdSec Map".to_string()
    } else {
        state.config.crowdsec_map_domain.trim().to_string()
    };
    let range_label = format_date_range_7_days();
    let total_count = format_count(report.total_attacks);
    let top_rows = if report.top_behaviors.is_empty() {
        vec![]
    } else {
        report
            .top_behaviors
            .iter()
            .enumerate()
            .map(|(index, item)| EmailMetricRow {
                rank: index + 1,
                label: item.label.clone(),
                count: format_count(item.count),
            })
            .collect::<Vec<_>>()
    };
    let country_rows = if report.top_countries.is_empty() {
        vec![]
    } else {
        report
            .top_countries
            .iter()
            .enumerate()
            .map(|(index, item)| EmailMetricRow {
                rank: index + 1,
                label: item.label.clone(),
                count: format_count(item.count),
            })
            .collect::<Vec<_>>()
    };
    let link_url = report.link.as_str();
    let link_text = if report.link == "#" {
        "No dashboard link configured"
    } else {
        "View Full Report in Console"
    };

    crate::debug!(
        from_name = %from,
        link_url = %link_url,
        behaviors = top_rows.len(),
        total_count = %total_count,
        "rendering security report email template"
    );

    SecurityReportEmailTemplate {
        range_label: &range_label,
        total_count: &total_count,
        top_rows: &top_rows,
        country_rows: &country_rows,
        link_url,
        link_text,
        generated_at: &report.generated_at,
        from_name: &from,
    }
    .render()
    .unwrap_or_else(|err| format!("<html><body><pre>{err}</pre></body></html>"))
}

fn format_date_range_7_days() -> String {
    let end = Utc::now();
    let start = end - ChronoDuration::days(7);
    format!("{} - {}", start.format("%b %d"), end.format("%b %d, %Y"))
}

pub(crate) fn format_count(value: i64) -> String {
    if value < 1_000 {
        return value.to_string();
    }

    let scaled = value as f64 / 1_000.0;
    if scaled >= 100.0 {
        format!("{:.0}k", scaled)
    } else if scaled >= 10.0 {
        format!("{:.1}k", scaled)
    } else {
        format!("{:.2}k", scaled)
    }
}
