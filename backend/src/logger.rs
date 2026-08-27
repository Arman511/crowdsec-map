use std::fmt;

use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::registry::LookupSpan;

struct LevelOnlyFormatter;

impl<S, N> FormatEvent<S, N> for LevelOnlyFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let metadata = event.metadata();
        let level = match *metadata.level() {
            tracing::Level::ERROR => "\x1b[31mERROR\x1b[0m",
            tracing::Level::WARN => "\x1b[33mWARN\x1b[0m ",
            tracing::Level::INFO => "\x1b[32mINFO\x1b[0m ",
            tracing::Level::DEBUG => "\x1b[34mDEBUG\x1b[0m",
            tracing::Level::TRACE => "TRACE",
        };
        write!(writer, "{} {} ", chrono::Utc::now().to_rfc3339(), level)?;
        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

pub fn init() {
    let configured = std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    let filter = tracing_subscriber::EnvFilter::try_from_env("LOG_LEVEL")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(configured));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(false)
        .event_format(LevelOnlyFormatter)
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
