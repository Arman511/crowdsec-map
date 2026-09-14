use askama::Template;

#[derive(Clone, Debug)]
pub struct BehaviorSummary {
    pub label: String,
    pub count: i64,
}

#[derive(Clone, Debug)]
pub struct SecuritySummary {
    pub total_attacks: i64,
    pub top_behaviors: Vec<BehaviorSummary>,
    pub link: String,
    pub generated_at: String,
}

#[derive(Clone, Debug)]
pub struct EmailMetricRow {
    pub rank: usize,
    pub label: String,
    pub count: String,
}

#[derive(Template)]
#[template(path = "security_report_email.html")]
pub struct SecurityReportEmailTemplate<'a> {
    pub range_label: &'a str,
    pub total_count: &'a str,
    pub top_rows: &'a [EmailMetricRow],
    pub link_url: &'a str,
    pub link_text: &'a str,
    pub generated_at: &'a str,
    pub from_name: &'a str,
}
