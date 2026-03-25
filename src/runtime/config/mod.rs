mod load;
mod schema;
mod types;
mod validate;

pub use types::LoadedConfig;

use std::path::Path;

pub fn load_config(path: &Path) -> Result<LoadedConfig, String> {
    load::load_config(path)
}

pub fn load_config_str(raw: &str) -> Result<LoadedConfig, String> {
    load::load_config_str(raw)
}
