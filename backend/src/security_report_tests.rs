use chrono::{Datelike, Utc, Weekday};

use crate::models::security_report::{BehaviorSummary, SecuritySummary};
use crate::security_report::{
    clean_behavior_label, normalize_domain_link, parse_email_recipients,
    substitute_email_subject_template,
};
fn should_send_on_weekday(dt: chrono::DateTime<Utc>, weekday: Weekday) -> bool {
    dt.weekday() == weekday
}

#[allow(dead_code)]
pub struct AlertSummary {
    pub id: String,
    pub scenario: String,
    pub ip: String,
    pub country: String,
    pub count: i64,
}

#[test]
fn weekly_summary_counts_total_attacks_and_top_behaviors() {
    let payload = vec![
        AlertSummary {
            id: "a1".to_string(),
            scenario: "crowdsecurity/http-scan".to_string(),
            ip: "1.1.1.1".to_string(),
            country: "US".to_string(),
            count: 19_800,
        },
        AlertSummary {
            id: "a2".to_string(),
            scenario: "crowdsecurity/http-exploit".to_string(),
            ip: "2.2.2.2".to_string(),
            country: "DE".to_string(),
            count: 19_100,
        },
        AlertSummary {
            id: "a3".to_string(),
            scenario: "crowdsecurity/http-crawl".to_string(),
            ip: "3.3.3.3".to_string(),
            country: "FR".to_string(),
            count: 16_800,
        },
    ];

    let summary = build_security_summary(&payload, "https://map.example.com");
    assert_eq!(summary.total_attacks, 55_700);
    assert_eq!(summary.top_behaviors.len(), 3);
    assert_eq!(summary.top_behaviors[0].label, "HTTP Scan");
    assert_eq!(summary.link, "https://map.example.com");
}

#[test]
fn monday_detection_uses_local_weekday() {
    let dt = chrono::DateTime::parse_from_rfc3339("2026-09-14T09:00:00+00:00")
        .unwrap()
        .with_timezone(&chrono::Utc);
    assert!(should_send_on_weekday(dt, Weekday::Mon));
    assert!(!should_send_on_weekday(dt, Weekday::Tue));
}

#[test]
fn email_subject_uses_public_ip_and_report_date_range() {
    let public_ip = "203.0.113.42";
    let subject = substitute_email_subject_template(
        "Security Report for {{pub ip}} account: {{date_range}}",
        public_ip,
        "Sep 07 - Sep 14, 2026",
    );
    assert_eq!(
        subject,
        "Security Report for 203.0.113.42 account: Sep 07 - Sep 14, 2026"
    );
}

#[test]
fn email_recipient_list_supports_multiple_addresses() {
    let recipients =
        parse_email_recipients("a@example.com, b@example.com; c@example.com\n d@example.com");
    assert_eq!(
        recipients,
        vec![
            "a@example.com",
            "b@example.com",
            "c@example.com",
            "d@example.com",
        ]
    );
}

#[test]
fn smtp_username_redaction_keeps_prefix_for_logs() {
    let redacted = crate::security_report::redact_smtp_username("noreply@example.co.uk");
    assert_eq!(redacted, "nore***@example.co.uk");
}

#[test]
fn sender_mailbox_supports_display_names() {
    assert!(
        crate::security_report::parse_sender_mailbox("Crowdsec <noreply@example.co.uk>").is_ok()
    );
    assert!(crate::security_report::parse_sender_mailbox("noreply@example.co.uk").is_ok());
}

#[test]
fn email_auth_env_aliases_are_supported() {
    let old_vars = [
        "SMTP_HOST",
        "EMAIL_SMTP_HOST",
        "EMAIL_HOST",
        "SMTP_PORT",
        "EMAIL_SMTP_PORT",
        "EMAIL_PORT",
        "SMTP_USERNAME",
        "EMAIL_SMTP_USERNAME",
        "EMAIL_USERNAME",
        "SMTP_PASSWORD",
        "EMAIL_SMTP_PASSWORD",
        "EMAIL_PASSWORD",
        "SMTP_ENCRYPTION",
        "EMAIL_SMTP_ENCRYPTION",
        "EMAIL_ENCRYPTION",
        "EMAIL_FROM",
        "EMAIL_TO",
    ];
    for name in old_vars {
        unsafe {
            std::env::remove_var(name);
        }
    }

    unsafe {
        std::env::set_var("EMAIL_HOST", "smtp.example.com");
        std::env::set_var("EMAIL_PORT", "2525");
        std::env::set_var("EMAIL_USERNAME", "alerts@example.com");
        std::env::set_var("EMAIL_PASSWORD", "secret");
        std::env::set_var("EMAIL_ENCRYPTION", "STARTTLS");
        std::env::set_var("EMAIL_FROM", "security@example.com");
        std::env::set_var("EMAIL_TO", "ops@example.com");
    }

    let config = crate::Config::from_env();

    assert_eq!(config.smtp_host, "smtp.example.com");
    assert_eq!(config.smtp_port, 2525);
    assert_eq!(config.smtp_username, "alerts@example.com");
    assert_eq!(config.smtp_password, "secret");
    assert_eq!(config.smtp_encryption, "STARTTLS");
    assert_eq!(config.email_from, "security@example.com");
    assert_eq!(config.email_to, "ops@example.com");

    for name in old_vars {
        unsafe {
            std::env::remove_var(name);
        }
    }
}

fn build_security_summary(payload: &[AlertSummary], domain: &str) -> SecuritySummary {
    let mut items = payload
        .iter()
        .map(|entry| BehaviorSummary {
            label: clean_behavior_label(&entry.scenario),
            count: entry.count,
        })
        .collect::<Vec<_>>();
    items.sort_by(|a, b| b.count.cmp(&a.count));
    let total_attacks = payload.iter().map(|entry| entry.count).sum::<i64>();
    SecuritySummary {
        total_attacks,
        top_behaviors: items,
        link: normalize_domain_link(domain),
        generated_at: chrono::Utc::now().to_rfc3339(),
    }
}
