mod derived;
mod load;
mod schema;
mod types;
mod validate;

use std::path::Path;

pub type LoadedConfig = types::LoadedConfig;
pub type ValidatedConfig = types::ValidatedConfig;
pub type DerivedRuntimeConfig = derived::DerivedRuntimeConfig;
pub type RuntimeSettings = derived::RuntimeSettings;
pub type MetricsBindResolution = derived::MetricsBindResolution;
pub use types::{
    DefaultPolicy, IntegrationMode as RuntimeIntegrationMode, SnatMode as RuntimeSnatMode,
};

pub fn load_config(path: &Path) -> Result<LoadedConfig, String> {
    load::load_config(path)
}

pub fn load_config_str(raw: &str) -> Result<LoadedConfig, String> {
    load::load_config_str(raw)
}

pub fn derive_runtime_config(cfg: ValidatedConfig) -> Result<DerivedRuntimeConfig, String> {
    derived::derive_runtime_config(cfg)
}
