use std::{collections::HashMap, net::IpAddr};

use crate::{
    AppState,
    models::models::ActiveBan,
    open_history_connection,
    utils::{logger, normaliser::to_cidr24},
    warn,
};

pub async fn enrich_decision_countries(state: &AppState, items: &mut [ActiveBan]) {
    let mut geoip_matches = 0;
    for item in items.iter_mut() {
        if country_is_missing(&item.country) {
            if let Some(country) = lookup_geoip_country(state, &item.ip).await {
                item.country = country;
                geoip_matches += 1;
            }
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
    country.trim().is_empty() || country == "??" || country == "unknown"
}

async fn lookup_geoip_country(state: &AppState, value: &str) -> Option<String> {
    let ip = value.parse::<IpAddr>().ok()?;
    let reader_guard = state.geoip_reader.read().await;
    let reader = reader_guard.as_ref()?.clone();
    let record = reader
        .lookup(ip)
        .ok()?
        .decode::<maxminddb::geoip2::Country>()
        .ok()??;
    record.country.iso_code.map(str::to_string)
}

pub async fn lookup_geoip_asn(state: &AppState, value: &str) -> Option<String> {
    let ip = value.parse::<IpAddr>().ok()?;
    let reader_guard = state.geoip_reader.read().await;
    let reader = reader_guard.as_ref()?.clone();
    let record = reader
        .lookup(ip)
        .ok()?
        .decode::<maxminddb::geoip2::Asn>()
        .ok()??;
    record.autonomous_system_organization.map(str::to_string)
}

pub async fn enrich_ip_history_fields(
    state: &AppState,
    ip: &str,
    country: &mut String,
    as_name: &mut String,
) {
    if country_is_missing(country) {
        if let Some(enriched_country) = lookup_geoip_country(state, ip).await {
            *country = enriched_country;
        } else {
            warn!(ip = %ip, "Country lookup failed for IP");
        }
    }

    if as_name.trim().is_empty() || as_name == "unknown" {
        if let Some(enriched_asn) = lookup_geoip_asn(state, ip).await {
            *as_name = enriched_asn;
        } else {
            warn!(ip = %ip, "ASN lookup failed for IP");
        }
    }
}
