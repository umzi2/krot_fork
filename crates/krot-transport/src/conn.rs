//! Transport-agnostic wrappers over `quinn::Connection` and its
//! streams (§16.1.2).
//!
//! These types offer the same call surface as their `quinn` counterparts
//! so consumers can stay transport-neutral: today every variant delegates
//! straight to QUIC; §16.1.3 adds a `TcpMux` variant that carries the
//! same methods over TLS-over-TCP with the §16.1.1 mux framing.
//!
//! Error surface: the wrappers return [`crate::TransportError`] for
//! connection-level failures (`open_bi`, `accept_bi`, `finish`,
//! `stopped`), and `std::io::Error` for the byte-level `AsyncRead` /
//! `AsyncWrite` impls — same shape as `quinn` itself.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::TransportError;
use crate::tcp_mux::{TcpMuxConn, TcpMuxRecvStream, TcpMuxSendStream};

/// Transport-neutral connection handle.
#[derive(Debug, Clone)]
pub struct Connection {
    inner: ConnectionInner,
}

#[derive(Debug, Clone)]
enum ConnectionInner {
    Quic(quinn::Connection),
    TcpMux(TcpMuxConn),
}

impl Connection {
    /// Wrap an existing `quinn::Connection`.
    #[must_use]
    pub fn from_quic(c: quinn::Connection) -> Self {
        Self {
            inner: ConnectionInner::Quic(c),
        }
    }

    /// Wrap an already-running `TcpMuxConn` (§16.1.3).
    #[must_use]
    pub fn from_tcp_mux(m: TcpMuxConn) -> Self {
        Self {
            inner: ConnectionInner::TcpMux(m),
        }
    }

    /// Open a new bidirectional stream initiated by this side.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        match &self.inner {
            ConnectionInner::Quic(c) => {
                let (s, r) = c.open_bi().await.map_err(TransportError::Connection)?;
                Ok((SendStream::from_quic(s), RecvStream::from_quic(r)))
            }
            ConnectionInner::TcpMux(m) => {
                let (s, r) = m.open_bi().await?;
                Ok((SendStream::from_tcp_mux(s), RecvStream::from_tcp_mux(r)))
            }
        }
    }

    /// Accept a peer-initiated bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        match &self.inner {
            ConnectionInner::Quic(c) => {
                let (s, r) = c.accept_bi().await.map_err(TransportError::Connection)?;
                Ok((SendStream::from_quic(s), RecvStream::from_quic(r)))
            }
            ConnectionInner::TcpMux(m) => {
                let (s, r) = m.accept_bi().await?;
                Ok((SendStream::from_tcp_mux(s), RecvStream::from_tcp_mux(r)))
            }
        }
    }

    /// Wait for the connection to close (peer-initiated or local abort).
    pub async fn closed(&self) {
        match &self.inner {
            ConnectionInner::Quic(c) => {
                let _ = c.closed().await;
            }
            ConnectionInner::TcpMux(m) => m.closed().await,
        }
    }

    /// Close the connection with an application-level error code
    /// (`u32`) and a short human-readable reason. Idempotent.
    pub fn close(&self, code: u32, reason: &[u8]) {
        match &self.inner {
            ConnectionInner::Quic(c) => c.close(quinn::VarInt::from_u32(code), reason),
            ConnectionInner::TcpMux(m) => {
                let _ = (code, reason); // TCP-mux has no application code channel.
                m.close();
            }
        }
    }

    /// Best-effort remote IP of the underlying connection.
    /// `None` when the transport does not expose a peer address.
    #[must_use]
    pub fn remote_ip(&self) -> Option<std::net::IpAddr> {
        match &self.inner {
            ConnectionInner::Quic(c) => Some(c.remote_address().ip()),
            ConnectionInner::TcpMux(_) => None,
        }
    }
}

/// Bidirectional-stream send half.
#[derive(Debug)]
pub struct SendStream {
    inner: SendStreamInner,
}

#[derive(Debug)]
enum SendStreamInner {
    Quic(quinn::SendStream),
    TcpMux(TcpMuxSendStream),
}

impl SendStream {
    #[must_use]
    pub fn from_quic(s: quinn::SendStream) -> Self {
        Self {
            inner: SendStreamInner::Quic(s),
        }
    }

    #[must_use]
    pub fn from_tcp_mux(s: TcpMuxSendStream) -> Self {
        Self {
            inner: SendStreamInner::TcpMux(s),
        }
    }

    /// Mark the send side as finished (no more bytes will be written).
    /// The peer will observe EOF on the corresponding recv stream.
    ///
    /// Returns `Ok(())` even if the stream was already closed; a
    /// double-finish is a benign no-op at the wire level.
    pub fn finish(&mut self) -> Result<(), TransportError> {
        match &mut self.inner {
            SendStreamInner::Quic(s) => {
                // quinn::ClosedStream from double-finish is not a real
                // failure; treat as success.
                let _ = s.finish();
                Ok(())
            }
            SendStreamInner::TcpMux(s) => s.finish(),
        }
    }

    /// Wait until either the peer has read all bytes or the stream has
    /// been reset. Returns the reset code if any.
    pub async fn stopped(&mut self) -> Result<Option<u64>, TransportError> {
        match &mut self.inner {
            SendStreamInner::Quic(s) => {
                let v = s
                    .stopped()
                    .await
                    .map_err(|_| TransportError::UnexpectedEof)?;
                Ok(v.map(quinn::VarInt::into_inner))
            }
            // TCP-mux has no per-stream reset code; return None
            // immediately (the peer has already accepted all bytes
            // once the writer task's queue is drained).
            SendStreamInner::TcpMux(_) => Ok(None),
        }
    }
}

impl AsyncWrite for SendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            SendStreamInner::Quic(s) => {
                <quinn::SendStream as AsyncWrite>::poll_write(Pin::new(s), cx, buf)
            }
            SendStreamInner::TcpMux(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            SendStreamInner::Quic(s) => {
                <quinn::SendStream as AsyncWrite>::poll_flush(Pin::new(s), cx)
            }
            SendStreamInner::TcpMux(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            SendStreamInner::Quic(s) => {
                <quinn::SendStream as AsyncWrite>::poll_shutdown(Pin::new(s), cx)
            }
            SendStreamInner::TcpMux(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Bidirectional-stream recv half.
#[derive(Debug)]
pub struct RecvStream {
    inner: RecvStreamInner,
}

#[derive(Debug)]
enum RecvStreamInner {
    Quic(quinn::RecvStream),
    TcpMux(TcpMuxRecvStream),
}

impl RecvStream {
    #[must_use]
    pub fn from_quic(r: quinn::RecvStream) -> Self {
        Self {
            inner: RecvStreamInner::Quic(r),
        }
    }

    #[must_use]
    pub fn from_tcp_mux(r: TcpMuxRecvStream) -> Self {
        Self {
            inner: RecvStreamInner::TcpMux(r),
        }
    }

    /// Read exactly `buf.len()` bytes or fail. Mirrors
    /// `quinn::RecvStream::read_exact`.
    pub async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), TransportError> {
        match &mut self.inner {
            RecvStreamInner::Quic(r) => r.read_exact(buf).await.map_err(Into::into),
            RecvStreamInner::TcpMux(_) => {
                // TcpMuxRecvStream only exposes AsyncRead; use it.
                let mut got = 0;
                while got < buf.len() {
                    let n = self.read_via_poll(&mut buf[got..]).await?;
                    if n == 0 {
                        return Err(TransportError::UnexpectedEof);
                    }
                    got += n;
                }
                Ok(())
            }
        }
    }

    /// Read up to `buf.len()` bytes. `Ok(None)` on graceful EOF.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        match &mut self.inner {
            RecvStreamInner::Quic(r) => r.read(buf).await.map_err(Into::into),
            RecvStreamInner::TcpMux(_) => {
                let n = self.read_via_poll(buf).await?;
                Ok(if n == 0 { None } else { Some(n) })
            }
        }
    }

    /// Internal helper for the TcpMux variant that only impls
    /// `AsyncRead`. Uses the tokio-level `read` method to avoid
    /// duplicating the `poll_read` machinery.
    async fn read_via_poll(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        use tokio::io::AsyncReadExt;
        match &mut self.inner {
            RecvStreamInner::Quic(_) => unreachable!("TcpMux path only"),
            RecvStreamInner::TcpMux(r) => r.read(buf).await.map_err(Into::into),
        }
    }
}

impl AsyncRead for RecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            RecvStreamInner::Quic(r) => Pin::new(r).poll_read(cx, buf),
            RecvStreamInner::TcpMux(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}

/// A pending inbound connection. Await via [`Incoming::accept`] to
/// complete the transport handshake and obtain a [`Connection`].
#[derive(Debug)]
pub struct Incoming {
    inner: IncomingInner,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // Quic variant is the hot path;
                                     // boxing it would trade one indirection per accept for a rare size
                                     // win on the TcpMux variant.
enum IncomingInner {
    Quic(quinn::Incoming),
    /// TCP+TLS handshake already done by the listener; the mux is
    /// ready to go.
    TcpMux(TcpMuxConn),
}

/// Transport-kind discriminator for consumers (metrics, logging).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Quic,
    TcpFallback,
}

impl Incoming {
    #[must_use]
    pub fn from_quic(inc: quinn::Incoming) -> Self {
        Self {
            inner: IncomingInner::Quic(inc),
        }
    }

    #[must_use]
    pub fn from_tcp_mux(m: TcpMuxConn) -> Self {
        Self {
            inner: IncomingInner::TcpMux(m),
        }
    }

    /// Which transport family did this connection arrive on. Useful
    /// for per-transport metrics/logging before the handshake starts.
    #[must_use]
    pub fn kind(&self) -> TransportKind {
        match &self.inner {
            IncomingInner::Quic(_) => TransportKind::Quic,
            IncomingInner::TcpMux(_) => TransportKind::TcpFallback,
        }
    }

    /// Complete the transport handshake and return a [`Connection`].
    pub async fn accept(self) -> Result<Connection, TransportError> {
        match self.inner {
            IncomingInner::Quic(inc) => inc
                .await
                .map(Connection::from_quic)
                .map_err(TransportError::Connection),
            // TCP+TLS handshake completed already; hand off.
            IncomingInner::TcpMux(m) => Ok(Connection::from_tcp_mux(m)),
        }
    }
}
