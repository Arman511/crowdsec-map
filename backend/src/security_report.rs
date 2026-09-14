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
use tokio::time::sleep;

use crate::AppState;
use crate::models::security_report::{
    BehaviorSummary, EmailMetricRow, SecurityReportEmailTemplate, SecuritySummary,
};

pub(crate) fn parse_email_recipients(value: &str) -> Vec<String> {
    value
        .split(['\n', ',', ';'])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
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
    if subject.trim().is_empty() {
        format!("Security Report for {public_ip} account: {date_range}")
    } else {
        subject
    }
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

fn format_date_range_for_last_7_days(generated_at: &str) -> String {
    let parsed = chrono::DateTime::parse_from_rfc3339(generated_at)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let end = parsed.date_naive();
    let start = end - chrono::Duration::days(7);
    format!("{} - {}", start.format("%b %d"), end.format("%b %d, %Y"))
}

pub async fn api_trigger_security_report(
    State(state): State<AppState>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
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
        return Ok(());
    }

    let today = now.format("%Y-%m-%d").to_string();
    let stamp_path = format!("{}/weekly-report-last-sent.txt", state.config.static_dir);
    if let Ok(existing) = fs::read_to_string(&stamp_path).await {
        let trimmed = existing.trim();
        if !trimmed.is_empty() && trimmed == today {
            return Ok(());
        }
    }

    let report = build_report_for_last_7_days(state).await?;
    match send_security_report_email(state, &report).await {
        Ok(()) => {
            let _ = fs::write(&stamp_path, today.clone()).await;
            crate::info!(
                sent_on = %today,
                total_attacks = report.total_attacks,
                "weekly security report email sent"
            );
            Ok(())
        }
        Err(err) => Err(err),
    }
}

pub async fn send_security_report_for_last_7_days(state: &AppState) -> Result<bool, String> {
    if !state.config.email_enabled {
        return Ok(false);
    }

    let recipients = if !state.config.email_recipients.is_empty() {
        state.config.email_recipients.clone()
    } else {
        parse_email_recipients(&state.config.email_to)
    };
    if state.config.smtp_host.trim().is_empty() || recipients.is_empty() {
        return Err("SMTP host or recipient is not configured".to_string());
    }

    let report = build_report_for_last_7_days(state).await?;
    send_security_report_email(state, &report).await?;
    Ok(true)
}

async fn build_report_for_last_7_days(state: &AppState) -> Result<SecuritySummary, String> {
    let since_ms = (Utc::now() - ChronoDuration::days(7)).timestamp_millis();
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

    let mut behaviors = Vec::new();
    let mut total_attacks = 0_i64;
    for row in rows {
        let (scenario, count) = row.map_err(|err| err.to_string())?;
        total_attacks += count;
        behaviors.push(BehaviorSummary {
            label: clean_behavior_label(&scenario),
            count,
        });
    }

    behaviors.sort_by(|a, b| b.count.cmp(&a.count));
    let top_behaviors = behaviors.into_iter().take(5).collect::<Vec<_>>();
    let generated_at = Utc::now().to_rfc3339();
    let link = normalize_domain_link(&state.config.crowdsec_map_domain);

    Ok(SecuritySummary {
        total_attacks,
        top_behaviors,
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
        let mut chars = part.chars();
        let first = chars
            .next()
            .map(|ch| ch.to_uppercase().next().unwrap_or(ch))
            .unwrap_or_default();
        let rest = chars.collect::<String>();
        parts.push(format!("{first}{rest}"));
    }
    parts.join(" ")
}

async fn send_security_report_email(
    state: &AppState,
    report: &SecuritySummary,
) -> Result<(), String> {
    let html = build_security_email_html(state, report);
    let from_addr = state.config.email_from.trim();
    let recipients = if !state.config.email_recipients.is_empty() {
        state.config.email_recipients.clone()
    } else {
        parse_email_recipients(&state.config.email_to)
    };
    if from_addr.is_empty() || recipients.is_empty() {
        return Err("email sender or recipient is not configured".to_string());
    }

    let public_ip = state.public_target_ip.read().await.clone();
    let subject = build_email_subject(&state.config, &public_ip, &report.generated_at);
    let from_mailbox = lettre::message::Mailbox::new(
        None,
        from_addr
            .parse::<lettre::Address>()
            .map_err(|err| err.to_string())?,
    );

    let mut attempt = 0;
    loop {
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

            if let Err(err) = transport.send(message).await {
                last_error = Some(err.to_string());
            }
        }

        if last_error.is_none() {
            return Ok(());
        }

        attempt += 1;
        if attempt == 1 {
            let err = last_error.unwrap();
            crate::warn!(error = %err, "weekly security report email failed; retrying in 1 minute");
            sleep(std::time::Duration::from_secs(60)).await;
            continue;
        }

        let err = last_error.unwrap();
        crate::error!(error = %err, "weekly security report email failed after retry; not sending");
        return Err(format!("mail send failed: {err}"));
    }
}

fn build_transport(config: &crate::Config) -> Result<AsyncSmtpTransport<Tokio1Executor>, String> {
    let username = config.smtp_username.trim();
    let password = config.smtp_password.trim();
    let credentials = Credentials::new(username.to_string(), password.to_string());

    let transport = match config.smtp_encryption.to_uppercase().as_str() {
        "STARTTLS" => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
            .map_err(|err| err.to_string())?
            .port(config.smtp_port)
            .credentials(credentials)
            .build(),
        "SSL" => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
            .map_err(|err| err.to_string())?
            .port(config.smtp_port)
            .credentials(credentials)
            .build(),
        _ => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.smtp_host)
            .port(config.smtp_port)
            .credentials(credentials)
            .build(),
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
    let link_url = report.link.as_str();
    let link_text = if report.link == "#" {
        "No dashboard link configured"
    } else {
        "View Full Report in Console"
    };

    SecurityReportEmailTemplate {
        range_label: &range_label,
        total_count: &total_count,
        top_rows: &top_rows,
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

fn format_count(value: i64) -> String {
    if value >= 1_000 {
        let rounded = (value as f64 / 1_000.0).round();
        if rounded >= 100.0 {
            format!("{:.0}k", rounded / 1_000.0)
        } else {
            format!("{:.1}k", value as f64 / 1_000.0)
        }
    } else {
        value.to_string()
    }
}
