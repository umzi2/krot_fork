//! [`Server`] — top-level orchestration.
//!
//! Two runtime modes:
//!
//! - **Single-core** (tests, small deployments): [`Server::start`] binds a
//!   single QUIC endpoint on the configured address; [`Server::run`] or
//!   [`Server::run_until`] drives its accept loop.
//! - **Thread-per-core** (production): [`Server::run_multicore`] spawns one
//!   OS thread per core, each running a `current_thread` tokio runtime with
//!   its own `SO_REUSEPORT`-bound QUIC endpoint and HTTPS listener. Shared
//!   state (registry, keys, admin, tls) is `Arc`'d across cores.
//!
//! Both modes accept a `tokio::sync::watch::Receiver<bool>` for graceful
//! shutdown: flipping the watch to `true` causes every open session to emit
//! `ServerBye { SERVER_SHUTDOWN }`, drain its send stream, and exit; the
//! accept loop then closes the endpoint and returns.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use krot_proto::consts::DEFAULT_GRACE_PERIOD;
use krot_proto::ErrorCode;
use krot_transport::{install_crypto_provider, KrotEndpoint};

use crate::admin::AdminTokenStore;
use crate::config::{DomainTls, Mode, ServerConfig};
use crate::domain::acme::{acquire_cert, ChallengeStore};
use crate::domain::{new_challenge_store, run_http_router, run_https_router, TlsSource};
use crate::error::ServerError;
use crate::handshake::{self, HandshakeOutcome};
use crate::identity::ServerIdentity;
use crate::keys::KeyRegistry;
use crate::metrics::ServerMetrics;
use crate::peer_lookup::{NoOpPeerLookup, PeerLabelLookup};
use crate::peers::PeerRegistry;
use crate::rate::RateLimitState;
use crate::registry::TunnelRegistry;
use crate::session::{spawn_revocation_watcher, Session, SessionOutcome};
use crate::sockets::{reuseport_tcp, reuseport_udp};

use krot_proto::PubKey;
use std::collections::HashMap;
use std::sync::Mutex;

/// Per-identity rate-limit table shared across worker threads.
pub type RateTable = Mutex<HashMap<PubKey, Arc<RateLimitState>>>;

/// How long a worker waits for in-flight connection tasks to drain after
/// receiving the shutdown signal.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

/// §10 auth completion deadline. Applies to the entire handshake — from
/// accept_bi() returning the Control stream to `AuthOk`/`EnrollOk` being
/// sent. Prevents DoS-by-idle-handshake.
const AUTH_DEADLINE: Duration = Duration::from_secs(10);

/// How often the §7.3 reaper task walks the registry and drops expired
/// dangling leases. Independent of `DEFAULT_GRACE_PERIOD` — smaller
/// values shorten how long a fully-expired lease lingers in memory but
/// cost more wakeups.
const REAP_INTERVAL: Duration = Duration::from_secs(5);

/// Wait until `rx` observes `true`. Avoids `wait_for`, which returns a
/// `Ref` (`RwLockReadGuard`) that is `!Send` and would poison every future
/// composed with it in `tokio::select!` when spawned onto a `JoinSet`.
pub(crate) async fn wait_shutdown(mut rx: watch::Receiver<bool>) {
    if *rx.borrow() {
        return;
    }
    while rx.changed().await.is_ok() {
        if *rx.borrow() {
            return;
        }
    }
}

/// Everything a worker thread needs from the parent to run an accept loop.
#[derive(Debug)]
pub struct SharedState {
    pub keys: Arc<KeyRegistry>,
    pub admin: Arc<AdminTokenStore>,
    pub registry: Arc<TunnelRegistry>,
    pub config: ServerConfig,
    pub tls: Arc<rustls::ServerConfig>,
    pub apex: Option<String>,
    pub https_bind: Option<SocketAddr>,
    /// §9 per-identity rate-limit state. Populated lazily at handshake
    /// time; entries are keyed by `PubKey`.
    pub rates: Arc<RateTable>,
    /// §16.3.2 static federated-peer list. Hot-reloaded on file change.
    pub peers: Arc<PeerRegistry>,
    /// §16.3.4 peer-label lookup oracle. Defaults to
    /// [`NoOpPeerLookup`] — real deployments plug in an HTTP client
    /// against peer §16.4 admin APIs via
    /// [`Server::with_peer_lookup`]. Wrapped in a `Mutex` so
    /// `with_peer_lookup` can swap the inner `Arc` after
    /// `SharedState` has already been shared with the accept loop.
    pub peer_lookup: Mutex<Arc<dyn PeerLabelLookup>>,
    /// Process-wide counters + gauges surfaced on
    /// `/admin/v1/metrics`. Every code path that observes a
    /// countable event (auth success/failure, session outcome,
    /// resume attempt, rate-limit trip, tunnel registration, admin
    /// API call) does an `Ordering::Relaxed` fetch-add on the
    /// corresponding atomic here.
    pub metrics: Arc<ServerMetrics>,
}

/// A running KROT server: owns the endpoint and all shared state.
#[derive(Debug)]
pub struct Server {
    endpoint: KrotEndpoint,
    shared: Arc<SharedState>,
    identity: Option<ServerIdentity>,
    http_addr: Option<SocketAddr>,
    https_addr: Option<SocketAddr>,
    admin_api_addr: Option<SocketAddr>,
    tcp_fallback_addr: Option<SocketAddr>,
}

impl Server {
    /// Assemble and start a server. Spawns HTTP + HTTPS routers immediately
    /// in DomainMode (so ACME HTTP-01 challenges can be answered during
    /// cert acquisition).
    pub async fn start(config: ServerConfig) -> Result<Self, ServerError> {
        install_crypto_provider();

        let keys = Arc::new(KeyRegistry::open(config.authorized_keys_path.clone())?);
        // §13: hot-reload watcher. Spawned once per server; each mutation
        // to authorized_keys re-parses and broadcasts revoked/changed
        // pubkeys to any live session. Handle is intentionally dropped
        // (detached) — the task lives for the lifetime of the runtime.
        drop(Arc::clone(&keys).spawn_watcher());
        // §16.3.2 static peer list. Same hot-reload pattern as keys.
        let peers = Arc::new(PeerRegistry::open(config.peer_list_path.clone())?);
        drop(Arc::clone(&peers).spawn_watcher());
        let admin = Arc::new(
            AdminTokenStore::new(config.data_dir.clone())
                .with_reusable(config.admin_token_reusable)
                .with_ttl(Duration::from_secs(config.admin_token_ttl_secs)),
        );
        let port_pool = config.mode.tcp_port_pool();
        let registry = Arc::new(
            TunnelRegistry::new(port_pool).with_max_http_per_ip(config.max_http_tunnels_per_ip),
        );
        // §7.3 reaper: drop dangling tunnels whose grace deadline has
        // passed. Runs for the lifetime of the runtime; explicit
        // shutdown is out of scope since exit destroys the runtime.
        spawn_reaper(Arc::clone(&registry));

        let (tls_cfg, identity, http_addr, https_addr, apex, https_bind, https_listener) =
            match &config.mode {
                Mode::Ip { .. } => {
                    let id = ServerIdentity::load_or_create(&config.data_dir)?;
                    let tls = id.clone().into_rustls()?;
                    (tls, Some(id), None, None, None, None, None)
                }
                Mode::Domain {
                    apex,
                    tls,
                    http_bind,
                    https_bind,
                    ..
                } => {
                    let (tls_cfg, http_addr, https_addr, https_listener) = start_domain_plane(
                        apex.clone(),
                        tls.clone(),
                        *http_bind,
                        *https_bind,
                        &config.data_dir,
                        Arc::clone(&registry),
                    )
                    .await?;
                    (
                        tls_cfg,
                        None,
                        Some(http_addr),
                        Some(https_addr),
                        Some(apex.clone()),
                        Some(*https_bind),
                        Some(https_listener),
                    )
                }
            };
        let tls_arc = Arc::new(tls_cfg);

        let endpoint = KrotEndpoint::server(config.bind, (*tls_arc).clone())?;

        let shared = Arc::new(SharedState {
            keys,
            admin,
            registry,
            config,
            tls: tls_arc,
            apex: apex.clone(),
            https_bind,
            rates: Arc::new(Mutex::new(HashMap::new())),
            peers,
            peer_lookup: Mutex::new(Arc::new(NoOpPeerLookup)),
            metrics: Arc::new(ServerMetrics::new()),
        });

        // §16.1.8: spawn the HTTPS router with the ALPN dispatcher
        // now that SharedState exists. The dispatcher needs
        // `SharedState` to plug `krot-tcp/1` connections into
        // `handle_connection`.
        if let (Some(listener), Some(apex)) = (https_listener, apex) {
            let (never_tx, never_rx) = watch::channel(false);
            let shared_https = Arc::clone(&shared);
            tokio::spawn(async move {
                let _never_tx = never_tx;
                run_https_router(listener, apex, shared_https, never_rx).await;
            });
        }

        // §16.4: bring the structured admin API up alongside the KROT
        // accept loop if the config asks for it. Bound before we return
        // Server so callers get the resolved local addr via
        // `admin_api_addr()`.
        let admin_api_addr = if let Some(bind) = shared.config.admin_bind {
            let api_state = Arc::new(crate::admin_api::AdminApiState::new(
                Arc::clone(&shared.keys),
                Arc::clone(&shared.registry),
                Arc::clone(&shared.admin),
                Arc::clone(&shared.rates),
                shared.config.admin_session_ttl,
                Arc::clone(&shared.metrics),
            ));
            Some(crate::admin_api::spawn_admin_api(bind, api_state).await?)
        } else {
            None
        };

        // §16.1.4: optional TCP+TLS fallback listener. Uses the same
        // rustls config as the QUIC endpoint but forces ALPN to
        // `krot-tcp/1`. Bound before we return so tests can pull the
        // ephemeral addr via `tcp_fallback_addr()`.
        let tcp_fallback_addr = if let Some(bind) = shared.config.tcp_fallback_bind {
            let listener =
                krot_transport::TcpFallbackListener::bind(bind, (*shared.tls).clone()).await?;
            let addr = listener.local_addr()?;
            let shared_c = Arc::clone(&shared);
            // Sanity: shutdown-aware accept loops for the QUIC path
            // hook the graceful watch; for TCP fallback we spawn a
            // simple detached loop whose lifetime is the runtime's,
            // matching the admin API and reaper patterns.
            //
            // The watch sender is created ONCE outside the accept
            // loop and kept alive for the loop's lifetime. If we
            // recreated it per iteration, the previous iteration's
            // receiver — moved into the spawned session task —
            // would observe its sender drop between accepts and
            // `wait_shutdown` would return, prematurely tearing
            // down the session.
            let (never_tx, never_rx) = watch::channel(false);
            tokio::spawn(async move {
                // Keep the sender live for the loop's lifetime.
                let _never_tx = never_tx;
                loop {
                    match listener.accept().await {
                        Ok(incoming) => {
                            let shared_conn = Arc::clone(&shared_c);
                            let session_shutdown = never_rx.clone();
                            tokio::spawn(async move {
                                if let Err(e) =
                                    handle_connection(incoming, shared_conn, session_shutdown).await
                                {
                                    warn!("krot-tcp/1 connection ended with error: {e}");
                                }
                            });
                        }
                        Err(e) => {
                            // Transient errors (EMFILE, ECONNABORTED,
                            // ENOBUFS) must not permanently kill the
                            // listener — back off briefly and retry.
                            warn!("krot-tcp/1 listener accept: {e}");
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            });
            Some(addr)
        } else {
            None
        };

        Ok(Self {
            endpoint,
            shared,
            identity,
            http_addr,
            https_addr,
            admin_api_addr,
            tcp_fallback_addr,
        })
    }

    /// §16.1.4: local address the `krot-tcp/1` fallback listener
    /// bound to, when enabled.
    #[must_use]
    pub fn tcp_fallback_addr(&self) -> Option<SocketAddr> {
        self.tcp_fallback_addr
    }

    /// §16.4: local address the admin API bound to, when enabled.
    #[must_use]
    pub fn admin_api_addr(&self) -> Option<SocketAddr> {
        self.admin_api_addr
    }

    /// §16.3.4: swap in a custom [`PeerLabelLookup`] implementation.
    /// The default is [`NoOpPeerLookup`] which never reports a
    /// collision. Tests use this to inject a mock; real deployments
    /// use it to plug in an HTTP client that queries peer §16.4 admin
    /// APIs.
    ///
    /// Safe to call at any point before / during a running server —
    /// the field is `Mutex<Arc<...>>` and this method swaps the inner
    /// `Arc`. Concurrent registrations either see the old value or
    /// the new one, not something torn.
    #[must_use]
    pub fn with_peer_lookup(self, lookup: Arc<dyn PeerLabelLookup>) -> Self {
        *self.shared.peer_lookup.lock().unwrap() = lookup;
        self
    }

    pub fn issue_admin_token(&self) -> Result<String, ServerError> {
        self.shared.admin.issue()
    }

    pub fn issue_admin_token_if_needed(&self) -> Result<Option<String>, ServerError> {
        if self.shared.config.issue_admin_token || self.shared.keys.is_empty() {
            Ok(Some(self.shared.admin.issue()?))
        } else {
            Ok(None)
        }
    }

    pub fn fingerprint_hex(&self) -> Option<&str> {
        self.identity.as_ref().map(|i| i.spki_sha256.as_str())
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_addr
    }

    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.https_addr
    }

    pub fn registry(&self) -> &Arc<TunnelRegistry> {
        &self.shared.registry
    }

    pub fn shared(&self) -> &Arc<SharedState> {
        &self.shared
    }

    /// Single-core accept loop, driven on the current tokio runtime.
    /// Runs forever — for tests where the harness kills the task at the
    /// end. For graceful shutdown, use [`Self::run_until`].
    pub async fn run(&self) {
        let (_never_tx, never_rx) = watch::channel(false);
        self.run_until(never_rx).await;
    }

    /// Single-core accept loop with graceful shutdown: exits cleanly when
    /// `shutdown` flips to `true` (or its sender is dropped).
    pub async fn run_until(&self, shutdown: watch::Receiver<bool>) {
        info!(addr = ?self.local_addr().ok(), "accepting connections");
        let mut tasks: JoinSet<()> = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = wait_shutdown(shutdown.clone()) => {
                    info!("graceful shutdown");
                    break;
                }
                incoming = self.endpoint.accept() => {
                    match incoming {
                        Some(inc) => {
                            let shared = Arc::clone(&self.shared);
                            let shutdown_c = shutdown.clone();
                            tasks.spawn(async move {
                                if let Err(e) = handle_connection(inc, shared, shutdown_c).await {
                                    warn!("connection ended with error: {e}");
                                }
                            });
                        }
                        None => break,
                    }
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        drain(tasks).await;
        self.endpoint.close(0u32.into(), b"server shutdown");
    }

    /// Thread-per-core: spawn `cores` OS threads, each running an
    /// independent `current_thread` tokio runtime with its own
    /// `SO_REUSEPORT`-bound QUIC endpoint and (in DomainMode) its own
    /// HTTPS listener.
    ///
    /// Consumes the initial single-endpoint bound in [`Self::start`] and
    /// releases its socket before the workers rebind with `SO_REUSEPORT`.
    ///
    /// Blocks until all worker threads join. Graceful shutdown is triggered
    /// by flipping `shutdown` to `true`.
    pub fn run_multicore(
        self,
        cores: usize,
        shutdown: &watch::Receiver<bool>,
    ) -> Result<(), ServerError> {
        assert!(cores >= 1, "run_multicore requires at least 1 core");
        let quic_bind = self.shared.config.bind;
        assert!(
            quic_bind.port() != 0,
            "run_multicore requires an explicit QUIC bind port"
        );
        if let Some(https_bind) = self.shared.https_bind {
            assert!(
                https_bind.port() != 0,
                "run_multicore requires an explicit HTTPS bind port"
            );
        }

        let shared = Arc::clone(&self.shared);
        drop(self);

        let mut handles = Vec::with_capacity(cores);
        for core_id in 0..cores {
            let shared = Arc::clone(&shared);
            let shutdown = shutdown.clone();
            let name = format!("krot-worker-{core_id}");
            let handle = std::thread::Builder::new()
                .name(name)
                .spawn(move || {
                    if let Err(e) = worker(core_id, shared, quic_bind, shutdown) {
                        error!(core_id, "worker exited with error: {e}");
                    }
                })
                .map_err(ServerError::Io)?;
            handles.push(handle);
        }
        for h in handles {
            let _ = h.join();
        }
        Ok(())
    }
}

fn worker(
    core_id: usize,
    shared: Arc<SharedState>,
    quic_bind: SocketAddr,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_name(format!("krot-worker-{core_id}"))
        .on_thread_start(move || {
            // §9.2: pin this worker's rate-limit partition. Set on
            // every thread the runtime spawns so blocking-pool tasks
            // also index into their owner-worker's bucket.
            crate::rate::set_worker_id(core_id);
        })
        .build()?;
    // Also set on the current (block_on) thread — `on_thread_start`
    // fires only for tokio-owned threads.
    crate::rate::set_worker_id(core_id);
    rt.block_on(async move {
        let udp = reuseport_udp(quic_bind)?;
        let endpoint = KrotEndpoint::server_on_socket(udp, (*shared.tls).clone())?;
        info!(core_id, addr = ?endpoint.local_addr().ok(), "worker: QUIC endpoint bound");

        let https_task =
            if let (Some(https_bind), Some(apex)) = (shared.https_bind, shared.apex.clone()) {
                let tcp_std = reuseport_tcp(https_bind, 1024)?;
                let tcp = TcpListener::from_std(tcp_std)?;
                info!(core_id, addr = ?tcp.local_addr().ok(), "worker: HTTPS listener bound");
                let (_never_tx, never_rx) = watch::channel(false);
                // Keep the sender alive for the loop's lifetime; see
                // §16.1.4 fallback-loop comment for why per-iter senders
                // cause premature session shutdown.
                let shared_https = Arc::clone(&shared);
                let apex_c = apex.clone();
                let never_rx_c = never_rx.clone();
                let handle = tokio::spawn(async move {
                    let _never_tx = _never_tx;
                    run_https_router(tcp, apex_c, shared_https, never_rx_c).await;
                });
                Some(handle)
            } else {
                None
            };

        let mut tasks: JoinSet<()> = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = wait_shutdown(shutdown.clone()) => {
                    info!(core_id, "worker: graceful shutdown");
                    break;
                }
                incoming = endpoint.accept() => {
                    match incoming {
                        Some(inc) => {
                            let shared = Arc::clone(&shared);
                            let shutdown_c = shutdown.clone();
                            tasks.spawn(async move {
                                if let Err(e) = handle_connection(inc, shared, shutdown_c).await {
                                    warn!("connection ended with error: {e}");
                                }
                            });
                        }
                        None => break,
                    }
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }

        info!(
            core_id,
            active = tasks.len(),
            "worker: draining connections"
        );
        drain(tasks).await;
        endpoint.close(0u32.into(), b"server shutdown");
        if let Some(h) = https_task {
            h.abort();
        }
        Ok::<_, ServerError>(())
    })
}

/// Look up (or lazily create) the [`RateLimitState`] for `pubkey`,
/// initialised from the entry's `bw=` / `quota=`. Existing state is
/// preserved across reconnects so the period-quota counter keeps
/// accumulating across a session drop / resume.
fn ensure_rate_state(
    shared: &SharedState,
    pubkey: &PubKey,
    entry: &crate::keys::AuthorizedEntry,
) -> Arc<RateLimitState> {
    let mut table = shared.rates.lock().unwrap();
    Arc::clone(table.entry(*pubkey).or_insert_with(|| {
        Arc::new(RateLimitState::from_entry_with_metrics(
            entry.bw,
            entry.quota,
            shared.config.bw_partitions,
            Some(Arc::clone(&shared.metrics)),
        ))
    }))
}

/// Spawn the §7.3 lease reaper: a single task that periodically walks
/// the registry and drops any dangling tunnel whose grace deadline has
/// passed. Detached (no handle) — its lifetime is the runtime's.
fn spawn_reaper(registry: Arc<TunnelRegistry>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(REAP_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let n = registry.reap_expired();
            if n > 0 {
                info!(reaped = n, "reaped expired dangling tunnels");
            }
        }
    });
}

/// Wait for `tasks` to complete with a bounded deadline
/// ([`SHUTDOWN_DEADLINE`]).
async fn drain(mut tasks: JoinSet<()>) {
    let drain_fut = async { while tasks.join_next().await.is_some() {} };
    if tokio::time::timeout(SHUTDOWN_DEADLINE, drain_fut)
        .await
        .is_err()
    {
        warn!(remaining = tasks.len(), "shutdown deadline reached");
    }
}

async fn start_domain_plane(
    apex: String,
    tls: DomainTls,
    http_bind: SocketAddr,
    https_bind: SocketAddr,
    data_dir: &std::path::Path,
    registry: Arc<TunnelRegistry>,
) -> Result<
    (
        rustls::ServerConfig,
        SocketAddr,
        SocketAddr,
        // The bound HTTPS listener, handed back to the caller to
        // spawn once `SharedState` exists (the §16.1.8 ALPN
        // dispatcher needs `SharedState`).
        TcpListener,
    ),
    ServerError,
> {
    let http_listener = TcpListener::bind(http_bind).await?;
    let http_addr = http_listener.local_addr()?;
    let https_listener = TcpListener::bind(https_bind).await?;
    let https_addr = https_listener.local_addr()?;

    let challenges: ChallengeStore = new_challenge_store();
    tokio::spawn(run_http_router(
        http_listener,
        apex.clone(),
        Arc::clone(&registry),
        Arc::clone(&challenges),
    ));

    let tls_cfg = match tls {
        DomainTls::PemFile { cert, key } => {
            (*TlsSource::from_pem_files(&cert, &key)?.server_config).clone()
        }
        DomainTls::Acme { contact, directory } => {
            let (chain, key) = acquire_cert(
                &contact,
                &apex,
                directory.as_deref(),
                data_dir,
                Arc::clone(&challenges),
            )
            .await?;
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key)?
        }
    };

    Ok((tls_cfg, http_addr, https_addr, https_listener))
}

/// Public wrapper — same body as `handle_connection`, re-exported so
/// domain-plane code (§16.1.8 HTTPS ALPN dispatcher) can plug an
/// `Incoming` into the same session pipeline as the QUIC / TCP
/// fallback accept loops.
pub async fn handle_connection_public(
    incoming: krot_transport::Incoming,
    shared: Arc<SharedState>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError> {
    handle_connection(incoming, shared, shutdown).await
}

async fn handle_connection(
    incoming: krot_transport::Incoming,
    shared: Arc<SharedState>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ServerError> {
    // Bump per-transport accept counter — before the handshake so a
    // stuck peer that never completes still shows up in transport
    // split, and dashboards can see the ratio.
    use std::sync::atomic::Ordering::Relaxed as MetricRelaxed;
    match incoming.kind() {
        krot_transport::TransportKind::Quic => {
            shared
                .metrics
                .transport_quic_accepted
                .fetch_add(1, MetricRelaxed);
        }
        krot_transport::TransportKind::TcpFallback => {
            shared
                .metrics
                .transport_tcp_fallback_accepted
                .fetch_add(1, MetricRelaxed);
        }
    }
    let connection = incoming.accept().await.map_err(ServerError::Transport)?;

    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(ServerError::Transport)?;

    let handshake_outcome = tokio::time::timeout(
        AUTH_DEADLINE,
        handshake::perform(&mut send, &mut recv, &shared.keys, &shared.admin),
    )
    .await;
    let Ok(res) = handshake_outcome else {
        warn!("handshake exceeded {AUTH_DEADLINE:?}, closing");
        shared
            .metrics
            .handshake_timed_out
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        connection.close(
            u32::from(ErrorCode::AUTHENTICATION_FAILED.raw()),
            b"handshake timeout",
        );
        return Ok(());
    };
    let outcome = res?;
    match outcome {
        HandshakeOutcome::EnrollmentDone { success } => {
            use std::sync::atomic::Ordering::Relaxed;
            if success {
                shared.metrics.enrollment_ok.fetch_add(1, Relaxed);
            } else {
                shared.metrics.enrollment_rejected.fetch_add(1, Relaxed);
            }
            let _ = send.finish();
            connection.close(0, b"enrolled");
            Ok(())
        }
        HandshakeOutcome::Failed(code) => {
            info!(?code, "handshake failed");
            // Bucket the failure by the code the handshake picked.
            let m = &shared.metrics;
            use std::sync::atomic::Ordering::Relaxed;
            if code == ErrorCode::UNKNOWN_IDENTITY {
                m.handshake_unknown_identity.fetch_add(1, Relaxed);
            } else if code == ErrorCode::AUTHENTICATION_FAILED {
                m.handshake_signature_invalid.fetch_add(1, Relaxed);
            } else if code == ErrorCode::TOKEN_EXPIRED || code == ErrorCode::ENROLL_DISABLED {
                m.enrollment_rejected.fetch_add(1, Relaxed);
            } else {
                m.handshake_protocol_violation.fetch_add(1, Relaxed);
            }
            // The enclosed `code` is already the correct QUIC application
            // close code per §5 / §7.1 — handshake::perform picks the right
            // one at each failure site.
            connection.close(u32::from(code.raw()), b"handshake failed");
            Ok(())
        }
        HandshakeOutcome::Auth(ok) => {
            use std::sync::atomic::Ordering::Relaxed;
            shared.metrics.handshake_auth_ok.fetch_add(1, Relaxed);
            let revoked = spawn_revocation_watcher(shared.keys.subscribe_revocations(), ok.pubkey);
            // §9: resolve (or lazily create) the rate-limit state for
            // this identity and install a fresh control-stream sender.
            let rate_state = ensure_rate_state(&shared, &ok.pubkey, &ok.entry);
            let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::unbounded_channel();
            rate_state.attach_ctrl(ctrl_tx);

            let session = Session {
                pubkey: ok.pubkey,
                session_id: ok.session_id,
                connection: connection.clone(),
                registry: Arc::clone(&shared.registry),
                mode: shared.config.mode.clone(),
                shutdown,
                entry: ok.entry,
                revoked,
                rate: Arc::clone(&rate_state),
                ctrl_rx,
                peers: Arc::clone(&shared.peers),
                peer_lookup: Arc::clone(&shared.peer_lookup.lock().unwrap()),
                metrics: Arc::clone(&shared.metrics),
                client_ip: connection.remote_ip(),
            };
            let result = session.run(&mut send, &mut recv).await;
            rate_state.detach_ctrl();
            match &result {
                Ok(SessionOutcome::Dropped) => {
                    shared.metrics.session_dropped.fetch_add(1, Relaxed);
                    // §7.3: preserve the client's tunnels in `Dangling`
                    // state so a fresh QUIC connection can resume them
                    // within the grace window.
                    let grace = shared.config.resume_grace.unwrap_or(DEFAULT_GRACE_PERIOD);
                    shared.registry.mark_dangling(&ok.pubkey, grace);
                }
                Ok(SessionOutcome::Bye) => {
                    shared.metrics.session_bye.fetch_add(1, Relaxed);
                    shared.registry.remove_all_owned_by(&ok.pubkey);
                }
                Ok(SessionOutcome::Terminal) | Err(_) => {
                    shared.metrics.session_terminal.fetch_add(1, Relaxed);
                    shared.registry.remove_all_owned_by(&ok.pubkey);
                }
            }
            connection.close(0, b"bye");
            if let Err(e) = result {
                error!("session error: {e}");
            }
            Ok(())
        }
    }
}
