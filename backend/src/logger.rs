pub fn init() {
    let configured = std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    let filter = tracing_subscriber::EnvFilter::try_from_env("LOG_LEVEL")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(configured));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(false)
        .try_init();
}

#[macro_export]
macro_rules! error { ($($arg:tt)*) => {{ tracing::error!($($arg)*) }}; }

#[macro_export]
macro_rules! warn { ($($arg:tt)*) => {{ tracing::warn!($($arg)*) }}; }

#[macro_export]
macro_rules! info { ($($arg:tt)*) => {{ tracing::info!($($arg)*) }}; }

#[macro_export]
macro_rules! debug { ($($arg:tt)*) => {{ tracing::debug!($($arg)*) }}; }
