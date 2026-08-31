use std::{collections::HashMap, net::IpAddr};

use crate::{
    AppState, models::models::ActiveBan, open_history_connection, utils::normaliser::to_cidr24,
};

pub fn enrich_decision_countries(state: &AppState, items: &mut [ActiveBan]) {
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
    let record = reader
        .lookup(ip)
        .ok()?
        .decode::<maxminddb::geoip2::Country>()
        .ok()??;
    record.country.iso_code.map(str::to_string)
}
