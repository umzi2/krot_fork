//! KROT relay server binary.
//!
//! Deliberately does NOT use `#[tokio::main]`: startup work (loading keys,
//! generating the identity cert or running ACME, binding port 80) happens
//! on a temporary single-threaded runtime, after which the process either:
//!
//! - stays single-core (when `--cores 1`) and drives the existing runtime,
//!   or
//! - spawns `N` OS threads (`--cores N`, default = `available_parallelism`),
//!   each with its own `current_thread` tokio runtime and its own
//!   `SO_REUSEPORT`-bound QUIC endpoint and HTTPS listener.
//!
//! Both paths install a `Ctrl+C` handler on the startup runtime that flips
//! a shared `watch::Sender<bool>`, cascading a graceful shutdown through
//! every worker + session.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use tokio::sync::watch;

use krot_server::config::default_bind;
use krot_server::{DomainTls, Mode, Server, ServerConfig};

/// KROT relay server.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Apex domain to serve. Omit to run in IpMode (see §15.2).
    #[arg(long)]
    domain: Option<String>,

    /// Public host (IP or DNS) to embed in tunnel URLs. Defaults to `--bind`.
    #[arg(long)]
    public_host: Option<String>,

    /// UDP port for the public QUIC endpoint (overrides the port in `--bind`).
    #[arg(long)]
    public_quic: Option<u16>,

    /// UDP socket address to bind the QUIC endpoint on.
    #[arg(long, default_value_t = default_bind())]
    bind: SocketAddr,

    /// Directory used for persistent state (identity cert, admin token hash).
    #[arg(long, default_value = "/var/lib/krot")]
    data_dir: PathBuf,

    /// Path to the authorized_keys file.
    #[arg(long, default_value = "/etc/krot/authorized_keys")]
    authorized_keys: PathBuf,

    /// §16.3.2 static federated-peer list. Missing file = no peers.
    /// Hot-reloaded on file change.
    #[arg(long, default_value = "/etc/krot/peers.txt")]
    peer_list: PathBuf,

    /// §16.1.4 optional TCP+TLS bind for the `krot-tcp/1` fallback
    /// transport. When set, the server accepts connections here in
    /// parallel with the QUIC endpoint; clients whose UDP is blocked
    /// fall through to this. Uses the same rustls config as QUIC.
    #[arg(long)]
    tcp_fallback_bind: Option<SocketAddr>,

    /// TCP port pool used for TCP tunnels (`--tcp-port-pool 10000-19999`).
    #[arg(long, default_value = "10000-19999")]
    tcp_port_pool: PortRange,

    /// Force issuance of a new admin token even if `authorized_keys` is non-empty.
    #[arg(long)]
    issue_admin_token: bool,

    /// Keep admin tokens valid until they expire instead of consuming
    /// them on first enrollment.
    #[arg(long)]
    admin_token_reusable: bool,

    /// Admin token time-to-live in seconds. `0` disables expiry — the
    /// token stays valid until the server restarts (handy for ephemeral
    /// clients that re-enroll on every boot).
    #[arg(long, default_value_t = 600)]
    admin_token_ttl_secs: u64,

    /// Max HTTP tunnels (domains) a single client IP may hold at once.
    #[arg(long, default_value_t = 1)]
    max_http_tunnels_per_ip: usize,

    /// §16.4: TCP bind for the structured admin API. Pass an empty value
    /// (`--admin-bind ""`) to disable the endpoint. Default is loopback
    /// only. Operators exposing this publicly are expected to front it
    /// with a TLS reverse-proxy.
    #[arg(long, default_value = "127.0.0.1:9700")]
    admin_bind: Option<SocketAddr>,

    /// Number of accept-loop worker threads. `0` means
    /// `std::thread::available_parallelism()`.
    #[arg(long, default_value_t = 0)]
    cores: usize,

    /// §7.3 session-resume grace period in seconds. When a client
    /// disconnects abruptly, its tunnels stay reserved for this many
    /// seconds so a reconnect can pick up the same URLs. Default 30.
    /// Lower it for local dev if `Ctrl+C` → immediate re-run cycles
    /// hit "label taken" errors.
    #[arg(long, default_value_t = 30)]
    resume_grace_secs: u64,

    /// DomainMode: PEM-encoded apex certificate chain.
    #[arg(long, requires = "domain")]
    tls_cert: Option<PathBuf>,

    /// DomainMode: PEM-encoded apex private key (PKCS#8).
    #[arg(long, requires = "domain")]
    tls_key: Option<PathBuf>,

    /// DomainMode: ACME contact (e.g. `mailto:admin@example.com`).
    #[arg(long, requires = "domain", conflicts_with = "tls_cert")]
    acme_contact: Option<String>,

    /// DomainMode: ACME directory URL. Defaults to Let's Encrypt **staging**.
    /// Pass `--acme-production` to switch to prod.
    #[arg(long, requires = "acme_contact")]
    acme_directory: Option<String>,

    /// DomainMode: switch to Let's Encrypt production. Overridden by
    /// `--acme-directory` when both are set.
    #[arg(long, requires = "acme_contact")]
    acme_production: bool,

    /// DomainMode: TCP address to bind the plain HTTP router on.
    #[arg(long, default_value = "0.0.0.0:80", requires = "domain")]
    http_bind: SocketAddr,

    /// DomainMode: TCP address to bind the HTTPS SNI-passthrough router on.
    #[arg(long, default_value = "0.0.0.0:443", requires = "domain")]
    https_bind: SocketAddr,
}

#[derive(Debug, Clone)]
struct PortRange {
    lo: u16,
    hi: u16,
}

impl std::str::FromStr for PortRange {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (lo, hi) = s
            .split_once('-')
            .ok_or_else(|| "expected lo-hi".to_string())?;
        let lo: u16 = lo
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        let hi: u16 = hi
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;
        if lo > hi {
            return Err("lo > hi".to_string());
        }
        Ok(Self { lo, hi })
    }
}

impl std::fmt::Display for PortRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.lo, self.hi)
    }
}

#[allow(clippy::too_many_lines)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // §Observability: `KROT_LOG_FORMAT=json` switches to
    // structured JSON logs (one event per line, machine-parseable).
    // Anything else — including the unset case — gives the human
    // pretty-printed format. `RUST_LOG` still controls filtering
    // through the `EnvFilter`.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    match std::env::var("KROT_LOG_FORMAT").as_deref() {
        Ok("json") => {
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .with_current_span(true)
                .with_span_list(false)
                .init();
        }
        _ => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    }

    let args = Args::parse();
    let mut bind = args.bind;
    if let Some(port) = args.public_quic {
        bind.set_port(port);
    }

    let mode = if let Some(apex) = args.domain.clone() {
        let tls = match (
            args.tls_cert.clone(),
            args.tls_key.clone(),
            args.acme_contact.clone(),
        ) {
            (Some(cert), Some(key), None) => DomainTls::PemFile { cert, key },
            (None, None, Some(contact)) => {
                let directory = args.acme_directory.clone().or_else(|| {
                    args.acme_production
                        .then(|| DomainTls::LETSENCRYPT_PRODUCTION.to_string())
                });
                DomainTls::Acme { contact, directory }
            }
            _ => {
                return Err(
                    "DomainMode requires either --tls-cert + --tls-key, or --acme-contact".into(),
                );
            }
        };
        Mode::Domain {
            apex,
            tls,
            http_bind: args.http_bind,
            https_bind: args.https_bind,
            tcp_port_pool: args.tcp_port_pool.lo..=args.tcp_port_pool.hi,
        }
    } else {
        Mode::Ip {
            public_host: args.public_host.unwrap_or_else(|| bind.ip().to_string()),
            port_pool: args.tcp_port_pool.lo..=args.tcp_port_pool.hi,
        }
    };

    let cores = if args.cores == 0 {
        std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
    } else {
        args.cores
    };

    let config = ServerConfig {
        bind,
        data_dir: args.data_dir,
        authorized_keys_path: args.authorized_keys,
        mode,
        issue_admin_token: args.issue_admin_token,
        admin_token_reusable: args.admin_token_reusable,
        admin_token_ttl_secs: args.admin_token_ttl_secs,
        max_http_tunnels_per_ip: args.max_http_tunnels_per_ip,
        admin_bind: args.admin_bind,
        admin_session_ttl: krot_server::admin_api::DEFAULT_SESSION_TTL,
        peer_list_path: args.peer_list,
        tcp_fallback_bind: args.tcp_fallback_bind,
        // §9.2: mirror the actual worker count into the rate-limit
        // partition count so `bw=` caps split evenly per core.
        bw_partitions: cores,
        resume_grace: Some(std::time::Duration::from_secs(args.resume_grace_secs)),
    };

    let startup_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Ctrl+C / SIGTERM handler on the startup runtime. SIGTERM must be
    // handled explicitly: as a container PID 1, default dispositions are
    // ignored, so `docker stop` would otherwise never shut us down
    // gracefully (tini can't help on a scratch image).
    {
        let tx = shutdown_tx.clone();
        startup_rt.handle().spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm =
                    signal(SignalKind::terminate()).expect("install SIGTERM handler");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = sigterm.recv() => {}
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
            tracing::info!("received shutdown signal, initiating graceful shutdown");
            let _ = tx.send(true);
        });
    }

    let server = startup_rt.block_on(async {
        let server = Server::start(config).await?;
        if let Some(token) = server.issue_admin_token_if_needed()? {
            println!("KROT_ADMIN_TOKEN={token}");
        }
        if let Some(fp) = server.fingerprint_hex() {
            println!("KROT_SERVER_FINGERPRINT=sha256:{fp}");
        }
        println!("KROT_QUIC_BIND={}", server.local_addr()?);
        if let Some(addr) = server.http_addr() {
            println!("KROT_HTTP_BIND={addr}");
        }
        if let Some(addr) = server.https_addr() {
            println!("KROT_HTTPS_BIND={addr}");
        }
        Ok::<_, Box<dyn std::error::Error>>(server)
    })?;

    if cores <= 1 {
        startup_rt.block_on(async move {
            server.run_until(shutdown_rx).await;
        });
        return Ok(());
    }

    // Multi-core: keep the startup runtime alive to drive the port-80 HTTP
    // router, ACME renewal timers and the Ctrl+C handler; workers on other
    // threads own their own runtimes.
    let startup_rx = shutdown_rx.clone();
    let mc_result = std::thread::scope(|s| {
        s.spawn(|| {
            startup_rt.block_on(async move {
                let mut rx = startup_rx;
                let _ = rx.wait_for(|v| *v).await;
            });
        });
        server.run_multicore(cores, &shutdown_rx)
    });
    mc_result?;

    // Keep shutdown_tx alive until here so its Receiver clones don't see
    // the channel as closed while the workers are still spinning.
    drop(shutdown_tx);
    Ok(())
}
