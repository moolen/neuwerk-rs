fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=PROTOC");
    println!("cargo:rerun-if-changed=ui/dist");

    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let ui_dist_dir = manifest_dir.join("ui/dist");
    std::fs::create_dir_all(&ui_dist_dir)?;
    let placeholder = ui_dist_dir.join(".neuwerk-placeholder");
    if !placeholder.exists() {
        std::fs::write(&placeholder, b"placeholder for compile-only builds\n")?;
    }

    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path()?;
        std::env::set_var("PROTOC", protoc);
    }

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/cluster.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/cluster.proto");
    Ok(())
}
