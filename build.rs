fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=PROTOC");
    println!("cargo:rerun-if-changed=ui/dist");

    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let ui_dist_dir = manifest_dir.join("ui/dist");
    ensure_placeholder_ui_bundle(&ui_dist_dir)?;

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

fn ensure_placeholder_ui_bundle(ui_dist_dir: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(ui_dist_dir)?;
    let placeholder = ui_dist_dir.join(".neuwerk-placeholder");
    if !placeholder.exists() {
        std::fs::write(&placeholder, b"placeholder for compile-only builds\n")?;
    }

    let assets_dir = ui_dist_dir.join("assets");
    let index_path = ui_dist_dir.join("index.html");
    if !index_path.exists() {
        std::fs::create_dir_all(&assets_dir)?;
        std::fs::write(
            assets_dir.join("placeholder.css"),
            placeholder_css(),
        )?;
        std::fs::write(
            assets_dir.join("placeholder.js"),
            placeholder_js(),
        )?;
        std::fs::write(
            &index_path,
            concat!(
                "<!DOCTYPE html>\n",
                "<html lang=\"en\">\n",
                "  <head>\n",
                "    <meta charset=\"UTF-8\" />\n",
                "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\n",
                "    <title>Neuwerk</title>\n",
                "    <script type=\"module\" src=\"/assets/placeholder.js\"></script>\n",
                "    <link rel=\"stylesheet\" href=\"/assets/placeholder.css\" />\n",
                "  </head>\n",
                "  <body>\n",
                "    <div id=\"root\"></div>\n",
                "  </body>\n",
                "</html>\n",
            ),
        )?;
        return Ok(());
    }

    let html = std::fs::read_to_string(&index_path)?;
    let asset_paths = referenced_asset_paths(&html);
    if asset_paths.is_empty() {
        return Ok(());
    }

    std::fs::create_dir_all(&assets_dir)?;
    for asset_path in asset_paths {
        let relative = asset_path.trim_start_matches("/assets/");
        let path = assets_dir.join(relative);
        if path.exists() {
            continue;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let contents = if relative.ends_with(".css") {
            placeholder_css()
        } else if relative.ends_with(".js") {
            placeholder_js()
        } else {
            &[][..]
        };
        std::fs::write(path, contents)?;
    }

    Ok(())
}

fn referenced_asset_paths(html: &str) -> Vec<String> {
    let mut paths = Vec::new();
    let mut start = 0usize;

    while let Some(found) = html[start..].find("/assets/") {
        let absolute = start + found;
        let suffix = &html[absolute..];
        let end = suffix
            .find(|c: char| matches!(c, '"' | '\'' | '<' | '>' | ' ' | '\n' | '\r' | '\t'))
            .unwrap_or(suffix.len());
        let path = &suffix[..end];
        if !paths.iter().any(|existing| existing == path) {
            paths.push(path.to_string());
        }
        start = absolute + "/assets/".len();
    }

    paths
}

fn placeholder_css() -> &'static [u8] {
    b"body{margin:0}.flex{display:flex}.h-screen{height:100vh}.min-h-screen{min-height:100vh}\n"
}

fn placeholder_js() -> &'static [u8] {
    b"const root=document.getElementById('root');if(root&&!root.hasChildNodes()){root.textContent='';}\n"
}
