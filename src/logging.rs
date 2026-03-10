use std::env;

pub const LOG_LEVEL_ENV: &str = "NEUWERK_LOG_LEVEL";
pub const LOG_FORMAT_ENV: &str = "NEUWERK_LOG_FORMAT";
const DEFAULT_LOG_LEVEL: &str = "info";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Plain,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogConfig {
    pub level: String,
    pub format: LogFormat,
}

impl LogConfig {
    fn from_env() -> Result<Self, String> {
        Self::from_values(
            env::var(LOG_LEVEL_ENV).ok(),
            env::var("RUST_LOG").ok(),
            env::var(LOG_FORMAT_ENV).ok(),
        )
    }

    fn from_values(
        neuwerk_level: Option<String>,
        rust_log: Option<String>,
        format: Option<String>,
    ) -> Result<Self, String> {
        let level = neuwerk_level
            .or(rust_log)
            .unwrap_or_else(|| DEFAULT_LOG_LEVEL.to_string());
        let format = parse_log_format(format.as_deref())?;
        Ok(Self { level, format })
    }
}

pub fn init_logging() -> Result<LogConfig, String> {
    let cfg = LogConfig::from_env()?;
    let filter = tracing_subscriber::EnvFilter::try_new(cfg.level.clone())
        .map_err(|err| format!("invalid log filter '{}': {err}", cfg.level))?;
    match cfg.format {
        LogFormat::Plain => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .compact()
            .with_target(true)
            .try_init()
            .map_err(|err| format!("logging init failed: {err}"))?,
        LogFormat::Json => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .with_current_span(false)
            .with_span_list(false)
            .with_target(true)
            .try_init()
            .map_err(|err| format!("logging init failed: {err}"))?,
    }
    Ok(cfg)
}

pub fn redact_secret(value: &str) -> String {
    if value.is_empty() {
        return "redacted(len=0)".to_string();
    }
    format!("redacted(len={})", value.chars().count())
}

pub fn redact_optional_secret(value: Option<&str>) -> Option<String> {
    value.map(redact_secret)
}

fn parse_log_format(value: Option<&str>) -> Result<LogFormat, String> {
    match value
        .unwrap_or("plain")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "" | "plain" | "text" | "compact" => Ok(LogFormat::Plain),
        "json" => Ok(LogFormat::Json),
        other => Err(format!(
            "invalid {}='{}' (expected plain or json)",
            LOG_FORMAT_ENV, other
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_secret_hides_value_contents() {
        let redacted = redact_secret("super-secret-token");
        assert_eq!(redacted, "redacted(len=18)");
        assert!(!redacted.contains("super-secret-token"));
    }

    #[test]
    fn redact_optional_secret_preserves_none() {
        assert_eq!(redact_optional_secret(None), None);
        assert_eq!(
            redact_optional_secret(Some("abc")).as_deref(),
            Some("redacted(len=3)")
        );
    }

    #[test]
    fn parse_log_format_accepts_plain_and_json() {
        assert_eq!(parse_log_format(None).unwrap(), LogFormat::Plain);
        assert_eq!(parse_log_format(Some("plain")).unwrap(), LogFormat::Plain);
        assert_eq!(parse_log_format(Some("json")).unwrap(), LogFormat::Json);
    }

    #[test]
    fn log_config_prefers_neuwerk_level_over_rust_log() {
        let cfg = LogConfig::from_values(
            Some("debug".to_string()),
            Some("warn".to_string()),
            Some("json".to_string()),
        )
        .unwrap();
        assert_eq!(cfg.level, "debug");
        assert_eq!(cfg.format, LogFormat::Json);
    }
}
