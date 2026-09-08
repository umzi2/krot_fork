//! Per-connection session loop: dispatch [`ClientFrame`]s to registry
//! actions and reply with [`ServerFrame`]s.
//!
//! Also handles graceful shutdown: when the shared `watch::Receiver<bool>`
//! flips to `true`, the session emits `ServerBye { SERVER_SHUTDOWN }`,
//! finishes its send stream, and exits.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::{broadcast, watch};
use tracing::{info, warn};

use krot_proto::{ClientFrame, ErrorCode, PubKey, ServerFrame, SessionId, TunnelId, TunnelKind};
use krot_transport::{read_frame, write_frame};

use crate::config::Mode;
use crate::error::ServerError;
use crate::keys::AuthorizedEntry;
use crate::metrics::ServerMetrics;
use crate::peer_lookup::{check_collision, CollisionCheck, PeerLabelLookup};
use crate::peers::PeerRegistry;
use crate::rate::RateLimitState;
use crate::registry::{
    is_valid_label, RegisteredKind, ResumeOutcome, ResumedInfo, TunnelInfo, TunnelRegistry,
    TunnelState,
};
use crate::tunnel::run_tcp_tunnel;

/// How a session ended. Drives the disposition of the session's tunnels
/// in `handle_connection`.
#[derive(Debug, Clone, Copy)]
pub enum SessionOutcome {
    /// Client sent `Bye`. Tunnels MUST be removed (§7.5 — resume MUST
    /// NOT succeed for a Bye'd tunnel).
    Bye,
    /// Client's control stream ended without a Bye (network drop,
    /// unexpected close). Tunnels transition to `Dangling` for the
    /// configured grace window.
    Dropped,
    /// Local server shutdown / key revocation / protocol violation. In
    /// all three cases the identity cannot meaningfully resume, so
    /// tunnels are removed immediately.
    Terminal,
}

/// Spawn a per-session filter over the [`KeyRegistry`]'s revocation
/// broadcast: flips the returned watch to `true` when a matching pubkey
/// arrives on the broadcast channel. Terminates itself on any observable
/// broadcast error (closed sender), which is fine — the watch just stays
/// `false` and the session runs until the client Byes it normally.
pub fn spawn_revocation_watcher(
    mut rx: broadcast::Receiver<PubKey>,
    target: PubKey,
) -> watch::Receiver<bool> {
    let (tx, watched) = watch::channel(false);
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(pk) if pk == target => {
                    let _ = tx.send(true);
                    return;
                }
                // Non-matching key or a Lagged (missed) message: keep
                // listening. If the sender has been dropped, the session
                // just runs without revocation — no harm.
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    });
    watched
}

/// State captured after a successful handshake.
#[derive(Debug)]
pub struct Session {
    pub pubkey: PubKey,
    pub session_id: SessionId,
    pub connection: krot_transport::Connection,
    pub registry: Arc<TunnelRegistry>,
    pub mode: Mode,
    pub shutdown: watch::Receiver<bool>,
    /// The client's authorized_keys entry, captured once at handshake so
    /// per-frame permission checks (subdomain allowlist) are lock-free.
    pub entry: AuthorizedEntry,
    /// Flips to `true` when this identity's authorization is removed or
    /// materially changed while the session is live. Populated by the
    /// per-session revocation filter spawned in [`spawn_revocation_watcher`].
    pub revoked: watch::Receiver<bool>,
    /// §9 per-identity rate-limit state, shared with data-path copiers.
    pub rate: Arc<RateLimitState>,
    /// Receiver for `ServerFrame`s produced by data-path tasks (currently
    /// `RateLimit` on quota breach). Forwarded to the client on the
    /// Control stream inside `run`'s `select!`.
    pub ctrl_rx: tokio::sync::mpsc::UnboundedReceiver<ServerFrame>,
    /// §16.3.2 static federated-peer list, shared read-only.
    pub peers: Arc<PeerRegistry>,
    /// §16.3.4 peer-label lookup oracle.
    pub peer_lookup: Arc<dyn PeerLabelLookup>,
    /// Process-wide metrics. `Session` bumps counters for register /
    /// resume outcomes; the aggregate is scraped at `/admin/v1/metrics`.
    pub metrics: Arc<ServerMetrics>,
    /// Public IP of the client (QUIC peer). `None` for transports that
    /// do not expose it (TCP-mux fallback). Used for the per-IP HTTP
    /// tunnel cap.
    pub client_ip: Option<std::net::IpAddr>,
}

impl Session {
    pub async fn run(
        mut self,
        send: &mut krot_transport::SendStream,
        recv: &mut krot_transport::RecvStream,
    ) -> Result<SessionOutcome, ServerError> {
        loop {
            tokio::select! {
                biased;
                () = crate::server::wait_shutdown(self.shutdown.clone()) => {
                    info!(pubkey = ?self.pubkey, "session: graceful shutdown");
                    let _ = write_frame(
                        send,
                        &ServerFrame::ServerBye {
                            code: ErrorCode::SERVER_SHUTDOWN,
                        },
                    )
                    .await;
                    let _ = send.finish();
                    let _ = send.stopped().await;
                    return Ok(SessionOutcome::Terminal);
                }
                () = crate::server::wait_shutdown(self.revoked.clone()) => {
                    info!(pubkey = ?self.pubkey, "session: key revoked");
                    let _ = write_frame(
                        send,
                        &ServerFrame::ServerBye {
                            code: ErrorCode::KEY_REVOKED,
                        },
                    )
                    .await;
                    let _ = send.finish();
                    let _ = send.stopped().await;
                    return Ok(SessionOutcome::Terminal);
                }
                frame_result = read_frame::<ClientFrame>(recv) => {
                    let frame = match frame_result {
                        Ok(f) => f,
                        Err(e) => {
                            info!(pubkey = ?self.pubkey, "control stream ended: {e}");
                            // Ambiguous close (network drop, remote
                            // abort). Treat as Dropped so the client
                            // can resume within the grace window.
                            return Ok(SessionOutcome::Dropped);
                        }
                    };
                    match self.dispatch(send, frame).await? {
                        DispatchOutcome::Continue => {}
                        DispatchOutcome::Stop(reason) => return Ok(reason),
                    }
                }
                // §9: data-path tasks post `RateLimit` frames here on
                // quota breach; forward them to the client.
                Some(outbound) = self.ctrl_rx.recv() => {
                    if let Err(e) = write_frame(send, &outbound).await {
                        warn!(pubkey = ?self.pubkey, "ctrl_rx forward failed: {e}");
                    }
                }
            }
        }
    }

    async fn dispatch(
        &mut self,
        send: &mut krot_transport::SendStream,
        frame: ClientFrame,
    ) -> Result<DispatchOutcome, ServerError> {
        match frame {
            ClientFrame::Ping { nonce } => {
                write_frame(send, &ServerFrame::Pong { nonce }).await?;
                Ok(DispatchOutcome::Continue)
            }
            ClientFrame::RegisterTunnel {
                label,
                kind,
                resume_session_id,
                inspect,
            } => {
                self.register(send, &label, &kind, resume_session_id, inspect)
                    .await?;
                Ok(DispatchOutcome::Continue)
            }
            ClientFrame::UnregisterTunnel { tunnel_id } => {
                self.registry.remove(tunnel_id);
                Ok(DispatchOutcome::Continue)
            }
            ClientFrame::ListPeers => {
                // §16.3.3: intersect the server's static peer list
                // (§16.3.2) with this identity's `federation=`
                // allowlist (§16.3.1). Empty response = no peers
                // this identity is authorized to publish on.
                let allowlist = &self.entry.federation;
                let relays: Vec<String> = self
                    .peers
                    .snapshot()
                    .into_iter()
                    .filter(|apex| allowlist.iter().any(|f| f == apex))
                    .collect();
                write_frame(send, &ServerFrame::Peers { relays }).await?;
                Ok(DispatchOutcome::Continue)
            }
            ClientFrame::Bye => {
                info!(pubkey = ?self.pubkey, "bye received");
                Ok(DispatchOutcome::Stop(SessionOutcome::Bye))
            }
            other => {
                warn!(?other, "unexpected frame during session");
                write_frame(
                    send,
                    &ServerFrame::ServerBye {
                        code: ErrorCode::PROTOCOL_VIOLATION,
                    },
                )
                .await?;
                Ok(DispatchOutcome::Stop(SessionOutcome::Terminal))
            }
        }
    }

    async fn register(
        &mut self,
        send: &mut krot_transport::SendStream,
        label: &str,
        kind: &TunnelKind,
        resume_session_id: Option<SessionId>,
        inspect: bool,
    ) -> Result<(), ServerError> {
        // §7.3: resume path. If a `resume_session_id` is present, look
        // up a dangling tunnel matching (label, session_id, pubkey).
        // On success we DO NOT allocate a new tunnel — we re-attach.
        if let Some(prev) = resume_session_id {
            match self
                .registry
                .try_resume(label, prev, &self.pubkey, self.connection.clone())
            {
                ResumeOutcome::Reattached {
                    tunnel_id,
                    info,
                    inspect: resumed_inspect,
                } => {
                    use std::sync::atomic::Ordering::Relaxed;
                    self.metrics.resume_reattached.fetch_add(1, Relaxed);
                    self.finish_resume(send, tunnel_id, info, resumed_inspect)
                        .await?;
                    return Ok(());
                }
                ResumeOutcome::IdentityMismatch => {
                    use std::sync::atomic::Ordering::Relaxed;
                    self.metrics.resume_identity_mismatch.fetch_add(1, Relaxed);
                    write_frame(
                        send,
                        &ServerFrame::TunnelRejected {
                            code: ErrorCode::RESUME_IDENTITY_MISMATCH,
                            detail: "resume pubkey does not match original owner".into(),
                        },
                    )
                    .await?;
                    return Ok(());
                }
                ResumeOutcome::Unknown => {
                    use std::sync::atomic::Ordering::Relaxed;
                    self.metrics.resume_unknown.fetch_add(1, Relaxed);
                    // Per §7.3: "If either check fails, the server MUST
                    // treat the request as a fresh registration (and
                    // reject if `label` is now taken)." — Fall through
                    // to normal registration. We surface RESUME_UNKNOWN
                    // only when the caller cannot possibly succeed with
                    // a fresh registration (i.e. never — always fall
                    // through). The client learns resume failed via the
                    // fresh `tunnel_id` in TunnelRegistered.
                    //
                    // Emit debug so operator-level logs still show the
                    // resume miss.
                    tracing::debug!(?prev, %label, "resume miss, treating as fresh");
                }
            }
        }

        // §13 conns= cap — pre-flight before either tunnel kind. Applied
        // uniformly so the total number of tunnels for this identity
        // (HTTP + TCP combined, live or dangling) stays within the
        // operator-declared limit.
        if let Some(cap) = self.entry.max_conns {
            let live = self.registry.count_owned_by(&self.pubkey);
            if live >= cap as usize {
                use std::sync::atomic::Ordering::Relaxed;
                self.metrics.tunnel_rejected_conns.fetch_add(1, Relaxed);
                write_frame(
                    send,
                    &ServerFrame::TunnelRejected {
                        code: ErrorCode::TUNNEL_LIMIT_EXCEEDED,
                        detail: format!("{live}/{cap} concurrent tunnels"),
                    },
                )
                .await?;
                return Ok(());
            }
        }
        match kind {
            TunnelKind::Http => self.register_http(send, label, inspect).await,
            TunnelKind::Tcp { remote_port } => {
                self.register_tcp(send, label, *remote_port, inspect).await
            }
        }
    }

    async fn finish_resume(
        &self,
        send: &mut krot_transport::SendStream,
        tunnel_id: TunnelId,
        info: ResumedInfo,
        inspect: bool,
    ) -> Result<(), ServerError> {
        match info {
            ResumedInfo::Http { label } => {
                let apex = match &self.mode {
                    Mode::Domain { apex, .. } => apex.clone(),
                    // A dangling HTTP tunnel can only exist if the server
                    // was in DomainMode when it was created; if we're now
                    // in IpMode this is a config mismatch — treat as
                    // internal error.
                    Mode::Ip { .. } => {
                        write_frame(
                            send,
                            &ServerFrame::TunnelRejected {
                                code: ErrorCode::INTERNAL_ERROR,
                                detail: "resume across mode change".into(),
                            },
                        )
                        .await?;
                        self.registry.remove(tunnel_id);
                        return Ok(());
                    }
                };
                let public_url = format!("https://{label}.{apex}");
                info!(?tunnel_id, %label, "http tunnel resumed");
                write_frame(
                    send,
                    &ServerFrame::TunnelRegistered {
                        tunnel_id,
                        public_url,
                        public_port: None,
                    },
                )
                .await?;
            }
            ResumedInfo::Tcp {
                public_port,
                listener,
            } => {
                let public_host = match &self.mode {
                    Mode::Ip { public_host, .. } => public_host.clone(),
                    Mode::Domain { apex, .. } => apex.clone(),
                };
                let connection = self.connection.clone();
                let rate = Arc::clone(&self.rate);
                let handle = tokio::spawn(async move {
                    run_tcp_tunnel(listener, connection, tunnel_id, rate, inspect).await;
                });
                self.registry
                    .set_tcp_abort(tunnel_id, handle.abort_handle());

                let public_url = format!("tcp://{public_host}:{public_port}");
                info!(?tunnel_id, port = public_port, "tcp tunnel resumed");
                write_frame(
                    send,
                    &ServerFrame::TunnelRegistered {
                        tunnel_id,
                        public_url,
                        public_port: Some(public_port),
                    },
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn register_http(
        &self,
        send: &mut krot_transport::SendStream,
        label: &str,
        inspect: bool,
    ) -> Result<(), ServerError> {
        let Mode::Domain { apex, .. } = &self.mode else {
            write_frame(
                send,
                &ServerFrame::TunnelRejected {
                    code: ErrorCode::HTTP_NOT_AVAILABLE,
                    detail: "server is in IpMode".into(),
                },
            )
            .await?;
            return Ok(());
        };

        use std::sync::atomic::Ordering::Relaxed as MRelax;
        if !is_valid_label(label) {
            self.metrics.tunnel_rejected_label.fetch_add(1, MRelax);
            write_frame(
                send,
                &ServerFrame::TunnelRejected {
                    code: ErrorCode::LABEL_INVALID,
                    detail: "does not match DNS label grammar".into(),
                },
            )
            .await?;
            return Ok(());
        }

        // §13: subdomain allowlist from the client's authorized_keys entry.
        // An entry omitting `subdomain=` grants no HTTP labels at all.
        if !self.entry.allow_any_subdomain
            && !self.entry.allowed_subdomains.iter().any(|s| s == label)
        {
            self.metrics.tunnel_rejected_label.fetch_add(1, MRelax);
            write_frame(
                send,
                &ServerFrame::TunnelRejected {
                    code: ErrorCode::LABEL_FORBIDDEN,
                    detail: format!("`{label}` not permitted for this identity"),
                },
            )
            .await?;
            return Ok(());
        }

        // §16.3.4 cross-relay collision check.
        //
        // The peer set we consult is the intersection of the
        // identity's `federation=` allowlist (§16.3.1) and the
        // server's static peer list (§16.3.2). Peers outside either
        // are irrelevant: this identity isn't authorized to publish
        // on them, and this relay wouldn't federate with them.
        let candidate_peers: Vec<String> = self
            .peers
            .snapshot()
            .into_iter()
            .filter(|apex| self.entry.federation.iter().any(|f| f == apex))
            .collect();
        if !candidate_peers.is_empty() {
            match check_collision(&self.peer_lookup, &candidate_peers, label, &self.pubkey).await {
                CollisionCheck::Conflict { first_conflict } => {
                    self.metrics
                        .tunnel_rejected_peer_collision
                        .fetch_add(1, MRelax);
                    write_frame(
                        send,
                        &ServerFrame::TunnelRejected {
                            code: ErrorCode::LABEL_UNAVAILABLE,
                            detail: format!(
                                "`{label}` already registered on peer {first_conflict} by a different identity"
                            ),
                        },
                    )
                    .await?;
                    return Ok(());
                }
                CollisionCheck::Clear { matched_peers } => {
                    if !matched_peers.is_empty() {
                        info!(
                            %label,
                            peers = ?matched_peers,
                            "same identity already holds this label on federated peers"
                        );
                    }
                }
            }
        }

        let Ok(tunnel_id) = self.registry.allocate_http(label) else {
            self.metrics.tunnel_rejected_label.fetch_add(1, MRelax);
            write_frame(
                send,
                &ServerFrame::TunnelRejected {
                    code: ErrorCode::LABEL_UNAVAILABLE,
                    detail: format!("`{label}` is taken"),
                },
            )
            .await?;
            return Ok(());
        };

        // Per-IP cap: one client address, at most N HTTP (sub)domains.
        if !self.registry.admits_http_for_ip(self.client_ip) {
            self.registry.abort_http(tunnel_id, label);
            self.metrics.tunnel_rejected_label.fetch_add(1, MRelax);
            write_frame(
                send,
                &ServerFrame::TunnelRejected {
                    code: ErrorCode::LABEL_FORBIDDEN,
                    detail: "client IP already holds the maximum number of domains".into(),
                },
            )
            .await?;
            return Ok(());
        }

        self.registry.insert(TunnelInfo {
            id: tunnel_id,
            owner: self.pubkey,
            session_id: self.session_id,
            kind: RegisteredKind::Http {
                label: label.to_string(),
            },
            state: TunnelState::Live {
                connection: self.connection.clone(),
                abort: None,
            },
            client_ip: self.client_ip,
            tcp_listener: None,
            rate: Arc::clone(&self.rate),
            inspect,
        });
        self.metrics.tunnel_registered_http.fetch_add(1, MRelax);

        let public_url = format!("https://{label}.{apex}");
        info!(?tunnel_id, %label, "http tunnel registered");
        write_frame(
            send,
            &ServerFrame::TunnelRegistered {
                tunnel_id,
                public_url,
                public_port: None,
            },
        )
        .await?;
        Ok(())
    }

    async fn register_tcp(
        &self,
        send: &mut krot_transport::SendStream,
        label: &str,
        remote_port: Option<u16>,
        inspect: bool,
    ) -> Result<(), ServerError> {
        let public_host = match &self.mode {
            Mode::Ip { public_host, .. } => public_host.clone(),
            Mode::Domain { apex, .. } => apex.clone(),
        };

        // §13 `ports=` enforcement. When the client requests a specific
        // `remote_port` and this identity has a `ports=` allowlist, the
        // requested port MUST appear in the list — otherwise reject
        // with LABEL_FORBIDDEN. If the client requests no specific port
        // (`remote_port = None`) the pool allocator picks whichever
        // free port is next and the allowlist is unconsulted (the
        // operator restricts by narrowing the pool at server startup).
        use std::sync::atomic::Ordering::Relaxed as MRelax;
        if let (Some(p), Some(allow)) = (remote_port, &self.entry.allowed_ports) {
            if !allow.contains(&p) {
                self.metrics.tunnel_rejected_ports.fetch_add(1, MRelax);
                write_frame(
                    send,
                    &ServerFrame::TunnelRejected {
                        code: ErrorCode::LABEL_FORBIDDEN,
                        detail: format!("port {p} not permitted for this identity"),
                    },
                )
                .await?;
                return Ok(());
            }
        }

        let allowlist = self.entry.allowed_ports.as_deref();
        let Ok((tunnel_id, port)) = self.registry.allocate_tcp(allowlist) else {
            self.metrics.tunnel_rejected_pool.fetch_add(1, MRelax);
            write_frame(
                send,
                &ServerFrame::TunnelRejected {
                    code: ErrorCode::PORT_POOL_EXHAUSTED,
                    detail: "no free ports".into(),
                },
            )
            .await?;
            return Ok(());
        };

        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        let listener = match TcpListener::bind(bind).await {
            Ok(l) => l,
            Err(e) => {
                warn!(?bind, "failed to bind tunnel listener: {e}");
                write_frame(
                    send,
                    &ServerFrame::TunnelRejected {
                        code: ErrorCode::INTERNAL_ERROR,
                        detail: format!("bind failed: {e}"),
                    },
                )
                .await?;
                return Ok(());
            }
        };
        let actual_addr = listener.local_addr()?;
        let public_port = actual_addr.port();
        let listener = Arc::new(listener);

        let listener_task = Arc::clone(&listener);
        let connection = self.connection.clone();
        let rate_task = Arc::clone(&self.rate);
        let handle = tokio::spawn(async move {
            run_tcp_tunnel(listener_task, connection, tunnel_id, rate_task, inspect).await;
        });
        let abort = handle.abort_handle();

        self.registry.insert(TunnelInfo {
            id: tunnel_id,
            owner: self.pubkey,
            session_id: self.session_id,
            kind: RegisteredKind::Tcp { public_port },
            state: TunnelState::Live {
                connection: self.connection.clone(),
                abort: Some(abort),
            },
            tcp_listener: Some(listener),
            rate: Arc::clone(&self.rate),
            inspect,
            client_ip: self.client_ip,
        });
        self.metrics.tunnel_registered_tcp.fetch_add(1, MRelax);

        let public_url = format!("tcp://{public_host}:{public_port}");
        info!(?tunnel_id, port = public_port, %label, "tcp tunnel registered");
        write_frame(
            send,
            &ServerFrame::TunnelRegistered {
                tunnel_id,
                public_url,
                public_port: Some(public_port),
            },
        )
        .await?;
        Ok(())
    }
}

enum DispatchOutcome {
    Continue,
    Stop(SessionOutcome),
}
