use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

const RUNTIME_CONFIG_DIR: &str = "/etc/neuwerk";
const RUNTIME_CONFIG_PATH: &str = "/etc/neuwerk/config.yaml";
const RUNTIME_CONFIG_LOCK_PATH: &str = "/tmp/neuwerk-runtime-config.lock";

pub struct InstalledRuntimeConfig {
    lock_file: File,
    previous: Option<Vec<u8>>,
    created_dir: bool,
}

impl InstalledRuntimeConfig {
    pub fn install_tun(
        tls_dir: &Path,
        http_bind: SocketAddr,
        metrics_bind: SocketAddr,
        dataplane_iface: &str,
        internal_cidr: &str,
    ) -> Result<Self, String> {
        let tls_dir = tls_dir
            .to_str()
            .ok_or_else(|| "tls dir not utf8".to_string())?;
        let yaml = format!(
            r#"version: 1
bootstrap:
  management_interface: lo
  data_interface: {dataplane_iface}
  cloud_provider: none
  data_plane_mode: tun
dns:
  target_ips:
    - 1.1.1.1
  upstreams:
    - 1.1.1.1:53
policy:
  default: deny
  internal_cidr: {internal_cidr}
http:
  bind: {http_bind}
  advertise: {http_bind}
  external_url: https://{http_bind}
  tls_dir: {tls_dir}
metrics:
  bind: {metrics_bind}
dataplane:
  snat:
    mode: none
"#
        );
        Self::install_yaml(&yaml)
    }

    fn install_yaml(yaml: &str) -> Result<Self, String> {
        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(RUNTIME_CONFIG_LOCK_PATH)
            .map_err(|err| format!("open runtime config lock failed: {err}"))?;
        flock_exclusive(&lock_file)?;

        let config_dir = Path::new(RUNTIME_CONFIG_DIR);
        let created_dir = if config_dir.exists() {
            false
        } else {
            fs::create_dir_all(config_dir)
                .map_err(|err| format!("create runtime config dir failed: {err}"))?;
            true
        };

        let config_path = Path::new(RUNTIME_CONFIG_PATH);
        let previous = match fs::read(config_path) {
            Ok(raw) => Some(raw),
            Err(err) if err.kind() == ErrorKind::NotFound => None,
            Err(err) => return Err(format!("read existing runtime config failed: {err}")),
        };

        fs::write(config_path, yaml).map_err(|err| {
            format!(
                "write runtime config {} failed: {err}",
                config_path.display()
            )
        })?;

        Ok(Self {
            lock_file,
            previous,
            created_dir,
        })
    }
}

impl Drop for InstalledRuntimeConfig {
    fn drop(&mut self) {
        let config_path = PathBuf::from(RUNTIME_CONFIG_PATH);
        if let Some(previous) = &self.previous {
            let _ = fs::write(&config_path, previous);
        } else {
            let _ = fs::remove_file(&config_path);
            if self.created_dir {
                let _ = fs::remove_dir(Path::new(RUNTIME_CONFIG_DIR));
            }
        }
        let _ = flock_unlock(&self.lock_file);
    }
}

fn flock_exclusive(file: &File) -> Result<(), String> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "lock runtime config failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

fn flock_unlock(file: &File) -> Result<(), String> {
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if rc == 0 {
        Ok(())
    } else {
        Err(format!(
            "unlock runtime config failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}
