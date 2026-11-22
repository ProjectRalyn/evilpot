use clap::{Parser, ValueEnum};
use evilpot_forefront::{
    generate_caddy_sink_config, generate_nginx_sink_config, run_forefront_server, ForefrontConfig,
    ForefrontMode,
};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliMode {
    FrontlineProxy,
    Standalone,
    BehindProxySink,
}

#[derive(Debug, Parser)]
#[command(
    name = "evilpot-forefront",
    about = "Standalone HTTP reverse-proxy & WAF-sink honeypot powered by sigil-filter attack detection and evilpot exploit verification"
)]
struct Cli {
    /// Optional path to a TOML configuration file.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Deployment mode (`frontline-proxy`, `standalone`, or `behind-proxy-sink`).
    #[arg(long, value_enum)]
    mode: Option<CliMode>,

    /// Override the HTTP bind address (e.g. 0.0.0.0:8080).
    #[arg(long)]
    bind: Option<SocketAddr>,

    /// Real upstream HTTP backend URL for `frontline-proxy` mode (e.g. http://127.0.0.1:3000).
    #[arg(long)]
    upstream: Option<String>,

    /// Override the secret admin panel URL prefix (default: "auto" generates a 37-char random path).
    #[arg(long)]
    admin_path: Option<String>,

    /// Override the automatic payload rotation interval in seconds.
    #[arg(long)]
    rotation_secs: Option<u64>,

    /// Print the default TOML configuration and exit.
    #[arg(long)]
    print_default_config: bool,

    /// Print an Nginx `behind_proxy_sink` configuration template and exit.
    #[arg(long)]
    print_nginx_config: bool,

    /// Print a Caddy `behind_proxy_sink` configuration template and exit.
    #[arg(long)]
    print_caddy_config: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if cli.print_default_config {
        let default_cfg = ForefrontConfig::default();
        println!("{}", toml::to_string_pretty(&default_cfg)?);
        return Ok(());
    }

    if cli.print_nginx_config {
        println!(
            "{}",
            generate_nginx_sink_config("127.0.0.1:8080", "127.0.0.1:3000")
        );
        return Ok(());
    }

    if cli.print_caddy_config {
        println!(
            "{}",
            generate_caddy_sink_config("127.0.0.1:8080", "127.0.0.1:3000")
        );
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut config = match cli.config {
        Some(path) => ForefrontConfig::from_toml_file(path)?,
        None => ForefrontConfig::default(),
    };

    if let Some(m) = cli.mode {
        config.http.mode = match m {
            CliMode::FrontlineProxy => ForefrontMode::FrontlineProxy,
            CliMode::Standalone => ForefrontMode::Standalone,
            CliMode::BehindProxySink => ForefrontMode::BehindProxySink,
        };
    }
    if let Some(bind) = cli.bind {
        config.http.bind_addr = bind;
    }
    if let Some(upstream) = cli.upstream {
        config.http.upstream_http_url = Some(upstream);
        if cli.mode.is_none() {
            config.http.mode = ForefrontMode::FrontlineProxy;
        }
    }
    if let Some(admin_path) = cli.admin_path {
        config.evilpot.admin.path_prefix = admin_path;
    }
    if let Some(rot) = cli.rotation_secs {
        config.evilpot.rotation_interval_secs = rot;
    }

    run_forefront_server(config).await?;
    Ok(())
}
