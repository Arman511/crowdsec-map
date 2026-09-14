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
