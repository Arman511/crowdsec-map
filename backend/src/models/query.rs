use serde::Deserialize;

#[derive(Deserialize)]
pub struct SourceQuery {
    pub source: Option<String>,
}

#[derive(Deserialize)]
pub struct DaysQuery {
    pub days: Option<String>,
    pub offset: Option<String>,
    pub limit: Option<String>,
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    pub days: Option<String>,
    #[serde(rename = "groupBy")]
    pub group_by: Option<String>,
    pub offset: Option<String>,
    pub limit: Option<String>,
}

#[derive(Deserialize)]
pub struct GroupQuery {
    pub days: Option<String>,
    #[serde(rename = "groupBy")]
    pub group_by: Option<String>,
    pub label: Option<String>,
    pub offset: Option<String>,
    pub limit: Option<String>,
}

#[derive(Deserialize)]
pub struct DecisionsQuery {
    pub search: Option<String>,
    pub sort: Option<String>,
    pub direction: Option<String>,
    pub offset: Option<String>,
    pub limit: Option<String>,
}

#[derive(Deserialize)]
pub struct InvestigationQuery {
    pub days: Option<String>,
    #[serde(rename = "maxLines")]
    pub max_lines: Option<String>,
}

#[derive(Deserialize)]
pub struct InvestigationLinesQuery {
    pub days: Option<String>,
    pub path: Option<String>,
    pub offset: Option<String>,
    pub limit: Option<String>,
    pub filter: Option<String>,
    pub sort: Option<String>,
    pub search: Option<String>,
}

#[derive(Deserialize)]
pub struct BansQuery {
    pub offset: Option<String>,
    pub limit: Option<String>,
}
