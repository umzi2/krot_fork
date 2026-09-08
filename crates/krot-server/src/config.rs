//! Server configuration.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::path::PathBuf;

use krot_proto::consts::DEFAULT_UDP_PORT;

/// Source of the apex-domain TLS certificate (DomainMode only).
#[derive(Debug, Clone)]
pub enum DomainTls {
    /// Read a PEM-encoded cert chain and PKCS#8 key from disk.
    PemFile { cert: PathBuf, key: PathBuf },
    /// Obtain a certificate via ACME HTTP-01.
    ///
    /// `contact` is passed to the ACME account (`mailto:...`).
    /// `directory` selects the ACME server; `None` means Let's Encrypt
    /// **staging** (safer default while iterating).
    Acme {
        contact: String,
        directory: Option<String>,
    },
}

impl DomainTls {
    /// Let's Encrypt production directory URL.
    pub const LETSENCRYPT_PRODUCTION: &'static str =
        "https://acme-v02.api.letsencrypt.org/directory";
    /// Let's Encrypt staging directory URL (default).
    pub const LETSENCRYPT_STAGING: &'static str =
        "https://acme-staging-v02.api.letsencrypt.org/directory";
}

/// Deployment mode (§15).
#[derive(Debug, Clone)]
pub enum Mode {
    /// No domain configured — TCP-only tunnels on a port pool.
    Ip {
        /// Public IP or DNS name to embed in the tunnels' `public_url`.
        public_host: String,
        port_pool: RangeInclusive<u16>,
    },
    /// Apex domain configured — full L7 routing.
    Domain {
        apex: String,
        tls: DomainTls,
        /// TCP address to bind the plain HTTP router on (Host-header
        /// routing plus `/.well-known/acme-challenge/`).
        http_bind: SocketAddr,
        /// TCP address to bind the HTTPS SNI-passthrough router on.
        https_bind: SocketAddr,
        /// Port pool reserved for TCP tunnels registered in DomainMode.
        tcp_port_pool: RangeInclusive<u16>,
    },
}

impl Default for Mode {
    fn default() -> Self {
        Self::Ip {
            public_host: Ipv4Addr::LOCALHOST.to_string(),
            port_pool: 10_000..=19_999,
        }
    }
}

impl Mode {
    #[must_use]
    pub fn tcp_port_pool(&self) -> RangeInclusive<u16> {
        match self {
            Self::Ip { port_pool, .. }
            | Self::Domain {
                tcp_port_pool: port_pool,
                ..
            } => port_pool.clone(),
        }
    }
}

/// Everything the server needs at startup.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// UDP address to bind the QUIC endpoint on.
    pub bind: SocketAddr,
    /// Directory used for persistent state (identity cert, admin_token hash).
    pub data_dir: PathBuf,
    /// Path to the `authorized_keys` file.
    pub authorized_keys_path: PathBuf,
    /// Deployment mode.
    pub mode: Mode,
    /// If true, always print a fresh admin token at startup.
    pub issue_admin_token: bool,
    /// If true, admin tokens stay valid until they expire instead of
    /// being consumed by the first enrollment.
    pub admin_token_reusable: bool,
    /// Admin token time-to-live in seconds; `0` disables expiry.
    pub admin_token_ttl_secs: u64,
    /// Max concurrent HTTP tunnels (domains) per client IP. `usize::MAX`
    /// disables the cap; deployments usually want `1`.
    pub max_http_tunnels_per_ip: usize,
    /// §16.4: TCP bind for the structured admin API. `None` disables
    /// the endpoint. Default is loopback-only (`127.0.0.1:9700`);
    /// operators exposing it publicly are expected to front it with a
    /// TLS reverse-proxy.
    pub admin_bind: Option<SocketAddr>,
    /// §16.4: TTL of admin API session tokens minted from the
    /// enrollment `admin_token`.
    pub admin_session_ttl: std::time::Duration,
    /// §16.3.2: on-disk static peer list. Missing file = empty list
    /// (no federated peers). Hot-reloaded on file change.
    pub peer_list_path: PathBuf,
    /// §16.1.4: optional TCP+TLS bind for the `krot-tcp/1` fallback
    /// transport. `None` disables the fallback listener; clients
    /// with UDP blocked will simply not be able to connect. Default
    /// is `None` — operators opt in.
    pub tcp_fallback_bind: Option<SocketAddr>,
    /// §9.2 per-core rate-limit partitions. Should match the actual
    /// worker count (1 for `Server::run`, `cores` for
    /// `Server::run_multicore`). Each identity's `bw=` cap is
    /// divided evenly across this many buckets so cores don't
    /// contend on a single `governor` bucket. Default 1.
    pub bw_partitions: usize,
    /// §7.3 session-resume grace period. When a client disconnects
    /// abruptly (no ServerBye), its tunnels stay in `Dangling` state
    /// for this long so a reconnecting client can pick up the same
    /// public URLs. `None` = protocol default (30s). Local dev may
    /// want a shorter value so `Ctrl+C` → immediate re-run works.
    pub resume_grace: Option<std::time::Duration>,
}

impl ServerConfig {
    /// A local IpMode config with fresh state in `data_dir`. Useful for tests.
    #[must_use]
    pub fn local_in(data_dir: PathBuf) -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            authorized_keys_path: data_dir.join("authorized_keys"),
            peer_list_path: data_dir.join("peers.txt"),
            data_dir,
            mode: Mode::default(),
            issue_admin_token: false,
            admin_token_reusable: false,
            admin_token_ttl_secs: 600,
            max_http_tunnels_per_ip: usize::MAX,
            // Tests bind the admin API on an ephemeral loopback port so
            // they can drive it without colliding on 9700 across parallel
            // runs.
            admin_bind: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
            admin_session_ttl: crate::admin_api::DEFAULT_SESSION_TTL,
            tcp_fallback_bind: None,
            bw_partitions: 1,
            resume_grace: None,
        }
    }

    #[must_use]
    pub fn with_bind(mut self, bind: SocketAddr) -> Self {
        self.bind = bind;
        self
    }

    #[must_use]
    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    #[must_use]
    pub fn with_issue_admin_token(mut self, issue: bool) -> Self {
        self.issue_admin_token = issue;
        self
    }

    #[must_use]
    pub fn with_admin_token_reusable(mut self, reusable: bool) -> Self {
        self.admin_token_reusable = reusable;
        self
    }

    #[must_use]
    pub fn with_admin_token_ttl_secs(mut self, secs: u64) -> Self {
        self.admin_token_ttl_secs = secs;
        self
    }

    #[must_use]
    pub fn with_tcp_fallback_bind(mut self, addr: SocketAddr) -> Self {
        self.tcp_fallback_bind = Some(addr);
        self
    }

    #[must_use]
    pub fn with_bw_partitions(mut self, n: usize) -> Self {
        self.bw_partitions = n.max(1);
        self
    }
}

/// Default `bind` for CLI construction: wildcard IPv4 on [`DEFAULT_UDP_PORT`].
#[must_use]
pub fn default_bind() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_UDP_PORT)
}
