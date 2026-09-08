//! Tunnel registry: label-indexed HTTP tunnels + port-pool TCP tunnels.
//!
//! Also owns the **session-resume lease** state machine (wire protocol spec
//! §7.3): when a client's QUIC connection dies without a `Bye`, its
//! tunnels are transitioned to `Dangling` for a bounded grace period
//! instead of being removed. A subsequent `RegisterTunnel` with a
//! matching `resume_session_id` and `pubkey` re-attaches the tunnel to
//! the new connection, preserving both `tunnel_id` and public URL.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tokio::task::AbortHandle;

use krot_proto::{PubKey, SessionId, TunnelId};

use crate::error::ServerError;
use crate::rate::RateLimitState;

/// One live or dangling tunnel.
///
/// A tunnel is `Live` while its owning QUIC connection is up. On
/// abnormal disconnect (no `Bye`) it transitions to `Dangling` with an
/// `expires_at` deadline; a matching resume re-attaches it, otherwise a
/// reaper task removes it.
#[derive(Debug)]
pub struct TunnelInfo {
    pub id: TunnelId,
    pub owner: PubKey,
    /// `SessionId` that originally created this tunnel. Must match on
    /// resume alongside `owner`.
    pub session_id: SessionId,
    pub kind: RegisteredKind,
    pub state: TunnelState,
    /// TCP listener kept alive across resume so the OS-level public
    /// port stays bound throughout the grace window. `None` for HTTP
    /// tunnels.
    pub tcp_listener: Option<Arc<TcpListener>>,
    /// §9 per-identity rate-limit state. Cloned into every data-path
    /// task spawned for this tunnel; on quota breach the shared
    /// `ctrl_tx` inside surfaces a `RateLimit` frame back on the
    /// owner's control stream.
    pub rate: Arc<RateLimitState>,
    /// §16.2: when `true`, every server-opened Data stream MUST
    /// prepend an `InspectionPrelude` between the DataHeader and the
    /// first byte of tunneled payload. Set from `RegisterTunnel.inspect`
    /// at registration time; preserved across §7.3 resume.
    pub inspect: bool,
    /// Public IP of the client that registered the tunnel. `None` for
    /// transports that do not expose a peer address. Used to enforce
    /// the per-IP HTTP tunnel cap.
    pub client_ip: Option<IpAddr>,
}

#[derive(Debug)]
pub enum RegisteredKind {
    Tcp { public_port: u16 },
    Http { label: String },
}

/// Lease state of a tunnel. `Live` is the steady state; `Dangling` is
/// entered on abnormal disconnect.
#[derive(Debug)]
pub enum TunnelState {
    Live {
        connection: krot_transport::Connection,
        /// TCP listener task's abort handle. `None` for HTTP tunnels.
        abort: Option<AbortHandle>,
    },
    Dangling {
        expires_at: Instant,
    },
}

/// Shared, mutable table of all tunnels currently registered on the server.
#[derive(Debug)]
pub struct TunnelRegistry {
    port_pool: RangeInclusive<u16>,
    /// Max concurrent HTTP tunnels per client IP. `usize::MAX` = unlimited.
    max_http_per_ip: usize,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    next_id: u64,
    used_ports: HashSet<u16>,
    used_labels: HashSet<String>,
    tunnels: HashMap<TunnelId, TunnelInfo>,
    /// Fast reverse-index for HTTP routing.
    labels: HashMap<String, TunnelId>,
}

/// Read-only tunnel view for the §16.4 admin API.
#[derive(Debug, Clone)]
pub struct TunnelSnapshot {
    pub tunnel_id: TunnelId,
    pub owner: PubKey,
    pub session_id: SessionId,
    pub inspect: bool,
    pub kind: TunnelSnapshotKind,
    pub live: bool,
}

#[derive(Debug, Clone)]
pub enum TunnelSnapshotKind {
    Http { label: String },
    Tcp { public_port: u16 },
}

/// Live-tunnel data returned by [`TunnelRegistry::resolve_label`].
#[derive(Debug, Clone)]
pub struct ResolvedTunnel {
    pub id: TunnelId,
    pub connection: krot_transport::Connection,
    pub rate: Arc<RateLimitState>,
    pub inspect: bool,
}

/// Outcome of a resume lookup.
#[derive(Debug)]
pub enum ResumeOutcome {
    /// Re-attached successfully.
    Reattached {
        tunnel_id: TunnelId,
        info: ResumedInfo,
        /// §16.2 inspect flag preserved from the original registration.
        inspect: bool,
    },
    /// No matching dangling lease found (or already expired).
    Unknown,
    /// Lease exists but `pubkey` does not match the original owner.
    IdentityMismatch,
}

/// Everything the caller needs to finish a resume: notably, the parked
/// [`TcpListener`] the caller MUST respawn `run_tcp_tunnel` on with the
/// new connection.
#[derive(Debug)]
pub enum ResumedInfo {
    Http {
        label: String,
    },
    Tcp {
        public_port: u16,
        listener: Arc<TcpListener>,
    },
}

impl TunnelRegistry {
    #[must_use]
    pub fn new(port_pool: RangeInclusive<u16>) -> Self {
        Self {
            port_pool,
            max_http_per_ip: usize::MAX,
            state: Mutex::new(State {
                next_id: 1,
                used_ports: HashSet::new(),
                used_labels: HashSet::new(),
                tunnels: HashMap::new(),
                labels: HashMap::new(),
            }),
        }
    }

    /// Cap the number of concurrent HTTP tunnels a single client IP
    /// may hold (default: unlimited).
    #[must_use]
    pub fn with_max_http_per_ip(mut self, max: usize) -> Self {
        self.max_http_per_ip = max.max(1);
        self
    }

    /// Whether a client from `ip` may register one more HTTP tunnel.
    #[must_use]
    pub fn admits_http_for_ip(&self, ip: Option<IpAddr>) -> bool {
        if self.max_http_per_ip == usize::MAX {
            return true;
        }
        let Some(ip) = ip else {
            return true; // transport without peer address: not attributable
        };
        let state = self.state.lock().unwrap();
        state
            .tunnels
            .values()
            .filter(|t| t.client_ip == Some(ip) && matches!(t.kind, RegisteredKind::Http { .. }))
            .count()
            < self.max_http_per_ip
    }

    /// Release a label reserved by [`Self::allocate_http`] without
    /// ever inserting the tunnel (registration rejected afterwards).
    pub fn abort_http(&self, id: TunnelId, label: &str) {
        let mut state = self.state.lock().unwrap();
        state.used_labels.remove(label);
        state.labels.remove(label);
        let _ = id;
    }
    /// `allowlist`, when `Some`, further narrows the pool: only ports
    /// that appear in it are eligible. Used to enforce §13 `ports=`.
    pub fn allocate_tcp(&self, allowlist: Option<&[u16]>) -> Result<(TunnelId, u16), ServerError> {
        let mut state = self.state.lock().unwrap();
        let port = pick_free_port(&self.port_pool, &state.used_ports, allowlist)
            .ok_or(ServerError::PortPoolExhausted)?;
        state.used_ports.insert(port);
        let id = fresh_id(&mut state);
        Ok((id, port))
    }

    /// Reserve a label for a new HTTP tunnel.
    ///
    /// Fails with [`ServerError::Keys`] if the label is already taken; the
    /// caller should surface it as `LABEL_UNAVAILABLE` on the wire.
    pub fn allocate_http(&self, label: &str) -> Result<TunnelId, ServerError> {
        let mut state = self.state.lock().unwrap();
        if state.used_labels.contains(label) {
            return Err(ServerError::Keys(format!("label taken: {label}")));
        }
        state.used_labels.insert(label.to_string());
        Ok(fresh_id(&mut state))
    }

    /// Publish a fully-initialised tunnel into the registry.
    pub fn insert(&self, info: TunnelInfo) {
        let mut state = self.state.lock().unwrap();
        if let RegisteredKind::Http { label } = &info.kind {
            state.labels.insert(label.clone(), info.id);
        }
        state.tunnels.insert(info.id, info);
    }

    /// Look up the QUIC connection, tunnel-id, and rate-limit state
    /// for the given HTTP label. Returns `None` for Dangling tunnels —
    /// traffic in the grace window gets a 404 rather than being routed
    /// to a dead connection.
    pub fn resolve_label(&self, label: &str) -> Option<ResolvedTunnel> {
        let state = self.state.lock().unwrap();
        let id = state.labels.get(label).copied()?;
        let info = state.tunnels.get(&id)?;
        match &info.state {
            TunnelState::Live { connection, .. } => Some(ResolvedTunnel {
                id,
                connection: connection.clone(),
                rate: Arc::clone(&info.rate),
                inspect: info.inspect,
            }),
            TunnelState::Dangling { .. } => None,
        }
    }

    /// Remove a tunnel by id, aborting its listener task (TCP) and freeing
    /// its port/label reservation. Idempotent.
    pub fn remove(&self, id: TunnelId) {
        let mut state = self.state.lock().unwrap();
        remove_locked(&mut state, id);
    }

    /// Immediately remove every tunnel owned by `owner`. Used for `Bye`,
    /// server shutdown, and key revocation — cases where resume MUST NOT
    /// succeed (§7.5).
    pub fn remove_all_owned_by(&self, owner: &PubKey) {
        let mut state = self.state.lock().unwrap();
        let ids: Vec<TunnelId> = state
            .tunnels
            .iter()
            .filter_map(|(id, info)| (info.owner == *owner).then_some(*id))
            .collect();
        for id in ids {
            remove_locked(&mut state, id);
        }
    }

    /// Transition every tunnel owned by `owner` from `Live` to `Dangling`
    /// with `expires_at = now + grace`. Tunnels already dangling are left
    /// untouched.
    ///
    /// For TCP tunnels the task's abort handle is fired (the current
    /// listener task exits) but the [`Arc<TcpListener>`] is preserved
    /// inside `TunnelInfo`, keeping the port bound.
    pub fn mark_dangling(&self, owner: &PubKey, grace: Duration) {
        let mut state = self.state.lock().unwrap();
        let expires_at = Instant::now() + grace;
        let ids: Vec<TunnelId> = state
            .tunnels
            .iter()
            .filter_map(|(id, info)| (info.owner == *owner).then_some(*id))
            .collect();
        for id in ids {
            let Some(info) = state.tunnels.get_mut(&id) else {
                continue;
            };
            if matches!(info.state, TunnelState::Dangling { .. }) {
                continue;
            }
            let old = std::mem::replace(&mut info.state, TunnelState::Dangling { expires_at });
            if let TunnelState::Live { abort: Some(a), .. } = old {
                a.abort();
            }
        }
    }

    /// Called by the reaper to drop every dangling tunnel whose lease has
    /// expired. Returns the number of tunnels removed.
    pub fn reap_expired(&self) -> usize {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();
        let ids: Vec<TunnelId> = state
            .tunnels
            .iter()
            .filter_map(|(id, info)| match &info.state {
                TunnelState::Dangling { expires_at } if *expires_at <= now => Some(*id),
                _ => None,
            })
            .collect();
        let n = ids.len();
        for id in ids {
            remove_locked(&mut state, id);
        }
        n
    }

    /// Try to resume a dangling tunnel by `(label, session_id)` on behalf
    /// of `pubkey`. On success the tunnel is transitioned back to `Live`
    /// with the supplied `connection`. The returned [`ResumedInfo`]
    /// includes any listener the caller has to respawn.
    ///
    /// The `label` is used to disambiguate HTTP tunnels (which reserve
    /// labels); for TCP tunnels the label field carries no routing
    /// meaning (§7.2) so we fall back to finding any dangling TCP
    /// tunnel matching `(session_id, pubkey)`.
    pub fn try_resume(
        &self,
        label: &str,
        session_id: SessionId,
        pubkey: &PubKey,
        connection: krot_transport::Connection,
    ) -> ResumeOutcome {
        let mut state = self.state.lock().unwrap();

        // Prefer an exact label match (HTTP tunnels).
        let mut candidate = state.labels.get(label).copied();
        // Otherwise search for a TCP tunnel owned by this session.
        if candidate.is_none() {
            candidate = state.tunnels.iter().find_map(|(id, info)| {
                if info.session_id != session_id {
                    return None;
                }
                if !matches!(info.state, TunnelState::Dangling { .. }) {
                    return None;
                }
                if !matches!(info.kind, RegisteredKind::Tcp { .. }) {
                    return None;
                }
                Some(*id)
            });
        }

        let Some(id) = candidate else {
            return ResumeOutcome::Unknown;
        };
        let Some(info) = state.tunnels.get(&id) else {
            return ResumeOutcome::Unknown;
        };
        if !matches!(info.state, TunnelState::Dangling { .. }) {
            return ResumeOutcome::Unknown;
        }
        if info.session_id != session_id {
            return ResumeOutcome::Unknown;
        }
        // Bitwise-equal check per §7.3 step 2.
        if info.owner != *pubkey {
            return ResumeOutcome::IdentityMismatch;
        }

        // Re-attach: swap the state to Live. Caller will fill in the
        // TCP abort handle after respawning the listener task via
        // `set_tcp_abort`.
        let info = state.tunnels.get_mut(&id).unwrap();
        info.state = TunnelState::Live {
            connection,
            abort: None,
        };
        let resumed = match &info.kind {
            RegisteredKind::Http { label } => ResumedInfo::Http {
                label: label.clone(),
            },
            RegisteredKind::Tcp { public_port } => {
                let Some(listener) = info.tcp_listener.clone() else {
                    return ResumeOutcome::Unknown;
                };
                ResumedInfo::Tcp {
                    public_port: *public_port,
                    listener,
                }
            }
        };

        ResumeOutcome::Reattached {
            tunnel_id: id,
            info: resumed,
            inspect: info.inspect,
        }
    }

    /// Replace the abort handle stored inside a `Live` tunnel — used
    /// after resume to record the newly spawned TCP listener task.
    pub fn set_tcp_abort(&self, id: TunnelId, new_abort: AbortHandle) {
        let mut state = self.state.lock().unwrap();
        if let Some(info) = state.tunnels.get_mut(&id) {
            if let TunnelState::Live { abort, .. } = &mut info.state {
                *abort = Some(new_abort);
            }
        }
    }

    /// Snapshot of every tunnel currently in the registry. Cheap — clones
    /// only the shallow public fields, not the QUIC connection or listener.
    /// Used by the §16.4 admin API.
    pub fn snapshot(&self) -> Vec<TunnelSnapshot> {
        let state = self.state.lock().unwrap();
        state
            .tunnels
            .values()
            .map(|info| TunnelSnapshot {
                tunnel_id: info.id,
                owner: info.owner,
                session_id: info.session_id,
                inspect: info.inspect,
                kind: match &info.kind {
                    RegisteredKind::Http { label } => TunnelSnapshotKind::Http {
                        label: label.clone(),
                    },
                    RegisteredKind::Tcp { public_port } => TunnelSnapshotKind::Tcp {
                        public_port: *public_port,
                    },
                },
                live: matches!(info.state, TunnelState::Live { .. }),
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.state.lock().unwrap().tunnels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of tunnels (live or dangling) owned by `owner`. Used by
    /// §13 `conns=` cap in `session::register`. Dangling tunnels count:
    /// they still hold a port / label reservation.
    pub fn count_owned_by(&self, owner: &PubKey) -> usize {
        self.state
            .lock()
            .unwrap()
            .tunnels
            .values()
            .filter(|t| t.owner == *owner)
            .count()
    }
}

fn remove_locked(state: &mut State, id: TunnelId) {
    let Some(info) = state.tunnels.remove(&id) else {
        return;
    };
    match info.kind {
        RegisteredKind::Tcp { public_port } => {
            state.used_ports.remove(&public_port);
        }
        RegisteredKind::Http { label } => {
            state.used_labels.remove(&label);
            state.labels.remove(&label);
        }
    }
    if let TunnelState::Live { abort: Some(a), .. } = info.state {
        a.abort();
    }
    // Dropping `info.tcp_listener` (Arc<TcpListener>) here — assuming
    // no other clone survives in a task, releases the OS port.
}

fn fresh_id(state: &mut State) -> TunnelId {
    let id = TunnelId(state.next_id);
    state.next_id = state.next_id.checked_add(1).unwrap_or(1);
    id
}

fn pick_free_port(
    pool: &RangeInclusive<u16>,
    used: &HashSet<u16>,
    allowlist: Option<&[u16]>,
) -> Option<u16> {
    pool.clone().find(|p| {
        if used.contains(p) {
            return false;
        }
        match allowlist {
            Some(list) => list.contains(p),
            None => true,
        }
    })
}

/// Validate a tunnel label against the §7.2 grammar
/// (`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`).
///
/// Also rejects the reserved label `admin` (§12.3).
#[must_use]
pub fn is_valid_label(label: &str) -> bool {
    if label == "admin" {
        return false;
    }
    let len = label.len();
    if !(1..=63).contains(&len) {
        return false;
    }
    let bytes = label.as_bytes();
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[len - 1]) {
        return false;
    }
    if len < 3 {
        return true;
    }
    bytes[1..len - 1].iter().all(|&b| is_alnum(b) || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use krot_proto::SESSION_ID_LEN;
    #[test]
    fn label_grammar() {
        assert!(is_valid_label("alice"));
        assert!(is_valid_label("a"));
        assert!(is_valid_label("a1-b2"));
        assert!(is_valid_label(&"a".repeat(63)));

        assert!(!is_valid_label(""));
        assert!(!is_valid_label("Alice"));
        assert!(!is_valid_label("-alice"));
        assert!(!is_valid_label("alice-"));
        assert!(!is_valid_label("al ice"));
        assert!(!is_valid_label("admin"));
        assert!(!is_valid_label(&"a".repeat(64)));
    }

    fn http_info(id: TunnelId, ip: Option<IpAddr>) -> TunnelInfo {
        TunnelInfo {
            id,
            owner: PubKey([0u8; 32]),
            session_id: SessionId([0u8; SESSION_ID_LEN]),
            kind: RegisteredKind::Http {
                label: format!("label{id:?}"),
            },
            state: TunnelState::Dangling {
                expires_at: Instant::now() + Duration::from_secs(60),
            },
            tcp_listener: None,
            rate: Arc::new(RateLimitState::from_entry(None, None, 1)),
            inspect: false,
            client_ip: ip,
        }
    }

    #[test]
    fn per_ip_http_cap() {
        let reg = TunnelRegistry::new(10_000..=10_001).with_max_http_per_ip(1);
        let ip = Some(IpAddr::from([1, 2, 3, 4]));
        assert!(reg.admits_http_for_ip(ip));
        reg.insert(http_info(TunnelId(1), ip));
        assert!(!reg.admits_http_for_ip(ip)); // cap reached
        let other = Some(IpAddr::from([5, 6, 7, 8]));
        assert!(reg.admits_http_for_ip(other)); // different IP unaffected
        reg.remove(TunnelId(1));
        assert!(reg.admits_http_for_ip(ip));
    }
}
