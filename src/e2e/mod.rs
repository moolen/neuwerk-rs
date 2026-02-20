#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(target_os = "linux")]
pub mod services;
#[cfg(target_os = "linux")]
pub mod tests;
#[cfg(target_os = "linux")]
pub mod topology;

#[cfg(not(target_os = "linux"))]
compile_error!("e2e harness is only supported on Linux");
