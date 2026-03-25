mod derived;
mod load;
mod schema;
mod types;
mod validate;

use std::path::Path;

pub type LoadedConfig = types::LoadedConfig;
pub type ValidatedConfig = types::ValidatedConfig;
pub type DerivedRuntimeConfig = derived::DerivedRuntimeConfig;
pub type MetricsBindResolution = derived::MetricsBindResolution;
pub use types::{
    DefaultPolicy, DpdkConfig as RuntimeDpdkConfig, DpdkIovaMode as RuntimeDpdkIovaMode,
    DpdkPerfMode as RuntimeDpdkPerfMode, DpdkSingleQueueMode as RuntimeDpdkSingleQueueMode,
    IntegrationMode as RuntimeIntegrationMode, RuntimeBehaviorConfig as RuntimeBehaviorSettings,
    SnatMode as RuntimeSnatMode,
};

pub fn load_config(path: &Path) -> Result<LoadedConfig, String> {
    load::load_config(path)
}

#[cfg(test)]
pub fn load_config_str(raw: &str) -> Result<LoadedConfig, String> {
    load::load_config_str(raw)
}

pub fn derive_runtime_config(cfg: ValidatedConfig) -> Result<DerivedRuntimeConfig, String> {
    derived::derive_runtime_config(cfg)
}
