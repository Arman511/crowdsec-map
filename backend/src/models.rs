use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Alert {
    pub(crate) id: String,
    pub(crate) ip: String,
    pub(crate) country: String,
    pub(crate) city: String,
    pub(crate) latitude: Option<f64>,
    pub(crate) longitude: Option<f64>,
    pub(crate) scenario: String,
    #[serde(rename = "decisionType")]
    pub(crate) decision_type: String,
    pub(crate) value: String,
    #[serde(rename = "createdAt")]
    pub(crate) created_at: String,
    pub(crate) count: i64,
    #[serde(rename = "asName")]
    pub(crate) as_name: String,
    pub(crate) origin: String,
    pub(crate) scope: String,
    pub(crate) duration: String,
    pub(crate) until: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ActiveBan {
    pub(crate) id: String,
    pub(crate) ip: String,
    pub(crate) value: String,
    pub(crate) country: String,
    pub(crate) scenario: String,
    pub(crate) origin: String,
    pub(crate) scope: String,
    pub(crate) duration: String,
    pub(crate) until: String,
    #[serde(rename = "type")]
    pub(crate) ban_type: String,
    #[serde(rename = "createdAt")]
    pub(crate) created_at: String,
}

#[derive(Deserialize)]
pub(crate) struct SourceQuery {
    pub(crate) source: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct DaysQuery {
    pub(crate) days: Option<String>,
    pub(crate) offset: Option<String>,
    pub(crate) limit: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct HistoryQuery {
    pub(crate) days: Option<String>,
    #[serde(rename = "groupBy")]
    pub(crate) group_by: Option<String>,
    pub(crate) offset: Option<String>,
    pub(crate) limit: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct GroupQuery {
    pub(crate) days: Option<String>,
    #[serde(rename = "groupBy")]
    pub(crate) group_by: Option<String>,
    pub(crate) label: Option<String>,
    pub(crate) offset: Option<String>,
    pub(crate) limit: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct DecisionsQuery {
    pub(crate) search: Option<String>,
    pub(crate) sort: Option<String>,
    pub(crate) direction: Option<String>,
    pub(crate) offset: Option<String>,
    pub(crate) limit: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct InvestigationQuery {
    pub(crate) days: Option<String>,
    #[serde(rename = "maxLines")]
    pub(crate) max_lines: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct InvestigationLinesQuery {
    pub(crate) days: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) offset: Option<String>,
    pub(crate) limit: Option<String>,
    pub(crate) filter: Option<String>,
    pub(crate) sort: Option<String>,
    pub(crate) search: Option<String>,
}
