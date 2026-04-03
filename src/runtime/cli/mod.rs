mod args;
mod parse_helpers;
mod types;
mod usage;

#[cfg(test)]
pub use crate::runtime::config::{
    RuntimeDpdkPerfMode as DpdkPerfMode, RuntimeDpdkSingleQueueMode as DpdkSingleQueueMode,
};
pub use args::RUNTIME_STARTUP_UNSUPPORTED_MESSAGE;
pub use parse_helpers::{parse_mac, parse_socket, take_flag_value};
pub use types::{CliConfig, CloudProviderKind, DataPlaneMode, DpdkIovaMode};
#[cfg(test)]
pub use usage::usage;

pub fn load_http_ca(cfg: &CliConfig) -> Result<Vec<u8>, String> {
    let path = cfg
        .http_ca_path
        .clone()
        .unwrap_or_else(|| cfg.http_tls_dir.join("ca.crt"));
    std::fs::read(&path).map_err(|err| format!("read http ca {}: {err}", path.display()))
}
