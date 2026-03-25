pub fn usage(bin: &str) -> String {
    format!(
        "Usage:\n  {bin}\n  {bin} auth <command>\n  {bin} sysdump [--output <path>]\n\nRuntime Startup:\n  Start the appliance with no runtime CLI flags.\n  Configure the appliance in /etc/neuwerk/config.yaml.\n\nFlags:\n  -h, --help\n\nAuth Commands:\n  {bin} auth key rotate --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key rotate --http-tls-dir <path>\n  {bin} auth key list --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key list --http-tls-dir <path>\n  {bin} auth key retire <kid> --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth key retire <kid> --http-tls-dir <path>\n  {bin} auth token mint --sub <id> [--ttl <dur>] [--kid <kid>] [--roles <csv>] --cluster-addr <ip:port> [--cluster-tls-dir <path>]\n  {bin} auth token mint --sub <id> [--ttl <dur>] [--kid <kid>] [--roles <csv>] --http-tls-dir <path>\n"
    )
}
