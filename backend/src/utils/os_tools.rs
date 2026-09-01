use crate::utils::normaliser::truncate_line;

pub fn read_os_release() -> (String, String) {
    let contents = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let value = |key: &str| {
        contents
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .map(|value| value.trim_matches('"').to_string())
            .unwrap_or_else(|| "unknown".to_string())
    };
    (value("NAME"), value("VERSION_ID"))
}

pub async fn discover_public_ip(client: &reqwest::Client) -> String {
    let providers = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ];
    for provider in providers {
        let response = client.get(provider).send().await;
        crate::debug!(
            network = "outbound",
            service = "public_ip",
            provider,
            result = if response.is_ok() { "success" } else { "error" },
            "network request completed"
        );
        if let Ok(response) = response
            && response.status().is_success()
            && let Ok(text) = response.text().await
        {
            let ip = text.trim().to_string();
            if ip.parse::<std::net::IpAddr>().is_ok() {
                crate::info!(network = "outbound", service = "public_ip", provider, ip = %ip, "public IP discovered");
                return ip;
            }
            crate::warn!(network = "outbound", service = "public_ip", provider, response = %truncate_line(&ip, 100), "public IP provider returned invalid data");
        }
    }
    String::new()
}
