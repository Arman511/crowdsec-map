use std::fmt::Arguments;
use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Error,
    Warn,
    Info,
    Debug,
}

static LEVEL: OnceLock<Level> = OnceLock::new();

pub fn init() {
    let configured = std::env::var("LOG_LEVEL")
        .unwrap_or_else(|_| "info".to_string())
        .to_lowercase();
    let level = if configured.contains("debug") {
        Level::Debug
    } else if configured.contains("warn") {
        Level::Warn
    } else if configured.contains("error") {
        Level::Error
    } else {
        Level::Info
    };
    let _ = LEVEL.set(level);
}

fn enabled(level: Level) -> bool {
    match LEVEL.get().copied().unwrap_or(Level::Info) {
        Level::Debug => true,
        Level::Info => matches!(level, Level::Error | Level::Info),
        Level::Warn | Level::Error => matches!(level, Level::Error | Level::Warn | Level::Info),
    }
}

pub fn write(level: &str, args: Arguments<'_>) {
    let parsed = match level {
        "ERROR" => Level::Error,
        "WARN" => Level::Warn,
        "DEBUG" => Level::Debug,
        _ => Level::Info,
    };
    if enabled(parsed) {
        eprintln!("[{level}] {args}");
    }
}

pub fn touch<T>(_: &T) {}

#[macro_export]
macro_rules! touch_fields {
    () => {};
    ($message:literal) => {};
    ($key:ident = % $value:expr, $($rest:tt)*) => {{ $crate::logger::touch(&$value); $crate::touch_fields!($($rest)*); }};
    ($key:ident = ? $value:expr, $($rest:tt)*) => {{ $crate::logger::touch(&$value); $crate::touch_fields!($($rest)*); }};
    ($key:ident = $value:expr, $($rest:tt)*) => {{ $crate::logger::touch(&$value); $crate::touch_fields!($($rest)*); }};
    ($key:ident, $($rest:tt)*) => {{ $crate::logger::touch(&$key); $crate::touch_fields!($($rest)*); }};
}

#[macro_export]
macro_rules! error { ($($arg:tt)*) => {{ $crate::touch_fields!($($arg)*); $crate::logger::write("ERROR", format_args!("{}", stringify!($($arg)*))) }}; }

#[macro_export]
macro_rules! warn { ($($arg:tt)*) => {{ $crate::touch_fields!($($arg)*); $crate::logger::write("WARN", format_args!("{}", stringify!($($arg)*))) }}; }

#[macro_export]
macro_rules! info { ($($arg:tt)*) => {{ $crate::touch_fields!($($arg)*); $crate::logger::write("INFO", format_args!("{}", stringify!($($arg)*))) }}; }

#[macro_export]
macro_rules! debug { ($($arg:tt)*) => {{ $crate::touch_fields!($($arg)*); $crate::logger::write("DEBUG", format_args!("{}", stringify!($($arg)*))) }}; }
