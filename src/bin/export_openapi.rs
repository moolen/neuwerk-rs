fn main() {
    let mut args = std::env::args().skip(1);
    match args.next() {
        Some(path) => {
            if let Err(err) = neuwerk::controlplane::http_api::openapi::write_openapi_json(&path) {
                eprintln!("failed to export OpenAPI spec to {path}: {err}");
                std::process::exit(1);
            }
        }
        None => match neuwerk::controlplane::http_api::openapi::openapi_json_pretty() {
            Ok(json) => {
                println!("{json}");
            }
            Err(err) => {
                eprintln!("failed to export OpenAPI spec: {err}");
                std::process::exit(1);
            }
        },
    }
}
