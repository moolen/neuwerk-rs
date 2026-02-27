use std::env;
use std::path::PathBuf;
use std::process::Command;

fn pkg_config_var(name: &str, var: &str) -> Option<String> {
    let output = Command::new("pkg-config")
        .arg(format!("--variable={var}"))
        .arg(name)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let src_dir = manifest_dir.join("src");

    let dpdk_dir = env::var("DPDK_DIR").ok().map(PathBuf::from);
    let mut include_dirs: Vec<PathBuf> = Vec::new();
    let mut lib_dirs: Vec<PathBuf> = Vec::new();

    if let Some(prefix) = dpdk_dir.clone() {
        include_dirs.push(prefix.join("include"));
        include_dirs.push(prefix.join("include").join("dpdk"));
        let libdir = if prefix.join("lib").exists() {
            prefix.join("lib")
        } else {
            prefix.join("lib64")
        };
        lib_dirs.push(libdir);
    } else if let Some(libdir) = pkg_config_var("libdpdk", "libdir") {
        lib_dirs.push(PathBuf::from(libdir));
        if let Some(includedir) = pkg_config_var("libdpdk", "includedir") {
            let include_path = PathBuf::from(includedir);
            include_dirs.push(include_path.clone());
            include_dirs.push(include_path.join("dpdk"));
        }
    } else {
        include_dirs.push(PathBuf::from("/usr/include/dpdk"));
        lib_dirs.push(PathBuf::from("/usr/lib"));
    }

    let mut cc_build = cc::Build::new();
    cc_build
        .file(src_dir.join("wrappers.c"))
        .flag("-D_GNU_SOURCE")
        .flag("-D_DEFAULT_SOURCE")
        .flag("-mssse3");
    for include in &include_dirs {
        if include.exists() {
            cc_build.include(include);
        }
    }
    cc_build.compile("dpdk_sys_wrappers");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=dpdk_sys_wrappers");
    for libdir in &lib_dirs {
        if libdir.exists() {
            println!("cargo:rustc-link-search=native={}", libdir.display());
        }
    }
    emit_dpdk_link_libs(&lib_dirs);
    println!("cargo:rerun-if-changed={}", src_dir.join("wrappers.c").display());
    println!("cargo:rerun-if-env-changed=DPDK_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
}

fn emit_dpdk_link_libs(lib_dirs: &[PathBuf]) {
    if has_libdpdk(lib_dirs) {
        println!("cargo:rustc-link-lib=dylib=dpdk");
        return;
    }
    for lib in [
        "rte_eal",
        "rte_ethdev",
        "rte_mbuf",
        "rte_mempool",
        "rte_mempool_ring",
        "rte_ring",
        "rte_kvargs",
        "rte_bus_pci",
        "rte_bus_vdev",
        "rte_pci",
        "rte_net",
    ] {
        println!("cargo:rustc-link-lib=dylib={lib}");
    }
}

fn has_libdpdk(lib_dirs: &[PathBuf]) -> bool {
    for dir in lib_dirs {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name == "libdpdk.so" || name == "libdpdk.a" || name.starts_with("libdpdk.so.") {
                    return true;
                }
            }
        }
    }
    false
}
