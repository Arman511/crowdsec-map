use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub ip: String,
    pub country: String,
    pub city: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub scenario: String,
    #[serde(rename = "decisionType")]
    pub decision_type: String,
    pub value: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub count: i64,
    #[serde(rename = "asName")]
    pub as_name: String,
    pub origin: String,
    pub scope: String,
    pub duration: String,
    pub until: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveBan {
    pub id: String,
    pub ip: String,
    pub value: String,
    pub country: String,
    pub scenario: String,
    pub origin: String,
    pub scope: String,
    pub duration: String,
    pub until: String,
    #[serde(rename = "type")]
    pub ban_type: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}
