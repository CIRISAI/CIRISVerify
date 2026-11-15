//! Async adapters over `ciris:node/net` (FSD §7).
//!
//! Every adapter follows the ABI's **edge-triggered** readiness: it calls
//! the non-blocking operation first and parks on its token only after the
//! host answered `would-block`, so it never waits for an edge that already
//! passed. Each connection, listener and datagram socket gets its own token
//! (the top byte names the kind; see the crate docs), and the events
//! [`Runtime::on_event`](crate::Runtime::on_event) routes wake it.
//!
//! * [`dial`] / [`Listener::accept`] give a [`Connection`]:
//!   [`conn_info`](Connection::conn_info), stream framing through
//!   [`read`](Connection::read) / [`write`](Connection::write) /
//!   [`write_all`](Connection::write_all) and `futures_io::AsyncRead` /
//!   `AsyncWrite`, message framing through
//!   [`send_message`](Connection::send_message) /
//!   [`recv_message`](Connection::recv_message) (all or nothing).
//! * [`bind`] gives a [`Datagram`] socket (unconnected UDP).
//!
//! One reader and one writer may wait on a connection at a time (each
//! direction has one waker slot; a second waiter replaces the first).

use alloc::string::String;
use alloc::vec::Vec;
use core::cell::Cell;
use core::fmt;
use core::future::poll_fn;
use core::pin::Pin;
use core::task::{Context, Poll};

use ciris_host_abi::net as abi;
pub use ciris_host_abi::net::{can_datagram, can_listen, can_multicast, carriers, interfaces};
pub use ciris_host_abi::types::{
    Carrier, CloseReason, ConnInfo, Errno, FailReason, Framing, ListenOptions, NetInterface,
};

use crate::executor::{Connect, Interest, TokenKind};
use crate::Runtime;

/// A network failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NetError {
    /// The host refused the call (`unsupported`, `invalid`, `denied`, ...).
    Host(Errno),
    /// The dial failed (`event.failed`).
    Failed(FailReason),
    /// The connection closed (`event.closed`, or `closed` from the host).
    Closed(CloseReason),
    /// The listener failed after `listen` returned (`event.listener-failed`).
    ListenerFailed(FailReason),
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host(e) => write!(f, "host refused: {e:?}"),
            Self::Failed(r) => write!(f, "dial failed: {r:?}"),
            Self::Closed(r) => write!(f, "connection closed: {r:?}"),
            Self::ListenerFailed(r) => write!(f, "listener failed: {r:?}"),
        }
    }
}

impl core::error::Error for NetError {}

impl From<NetError> for std::io::Error {
    fn from(e: NetError) -> Self {
        use std::io::ErrorKind as K;
        let kind = match e {
            NetError::Host(Errno::Invalid) => K::InvalidInput,
            NetError::Host(Errno::Denied) | NetError::Failed(FailReason::Denied) => {
                K::PermissionDenied
            },
            NetError::Host(Errno::Unsupported) => K::Unsupported,
            NetError::Failed(FailReason::Refused) | NetError::Host(Errno::Refused) => {
                K::ConnectionRefused
            },
            NetError::Failed(FailReason::Timeout) => K::TimedOut,
            NetError::Closed(_) | NetError::Host(Errno::Closed) => K::ConnectionReset,
            _ => K::Other,
        };
        Self::new(kind, e)
    }
}

/// One connection (dialled or accepted). Dropping it releases the host
/// stream (`[resource-drop]stream`) and its token.
pub struct Connection {
    stream: abi::Stream,
    token: u64,
    rt: Runtime,
    framing: Cell<Option<Framing>>,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("token", &format_args!("{:#x}", self.token))
            .finish_non_exhaustive()
    }
}

/// Dial `target` over `c` and wait for `connected` (or `failed`).
/// `subprotocols` is the ordered WebSocket offer; empty elsewhere.
///
/// # Errors
/// [`NetError::Host`] if the host refused to start, [`NetError::Failed`]
/// with the host's reason, [`NetError::Closed`] if it closed first.
pub async fn dial(
    c: Carrier,
    target: &str,
    subprotocols: &[String],
) -> Result<Connection, NetError> {
    let rt = Runtime::current();
    let token = rt.alloc_token(TokenKind::Conn);
    let stream = match abi::dial(c, target, subprotocols, token) {
        Ok(s) => s,
        Err(e) => {
            rt.unregister(token);
            return Err(NetError::Host(e));
        },
    };
    let conn = Connection {
        stream,
        token,
        rt,
        framing: Cell::new(None),
    };
    poll_fn(|cx| {
        let state = conn
            .rt
            .with_entry(token, |e| (e.connect, e.closed))
            .unwrap_or_default();
        match state {
            (Some(Connect::Connected), _) => Poll::Ready(Ok(())),
            (Some(Connect::Failed(r)), _) => Poll::Ready(Err(NetError::Failed(r))),
            (None, Some(r)) => Poll::Ready(Err(NetError::Closed(r))),
            (None, None) => {
                conn.rt.park(token, Interest::Done, cx.waker());
                Poll::Pending
            },
        }
    })
    .await?;
    Ok(conn)
}

impl Connection {
    /// The token this connection's events carry.
    #[must_use]
    pub fn token(&self) -> u64 {
        self.token
    }

    /// What the host knows about the connection (`stream.info`).
    #[must_use]
    pub fn conn_info(&self) -> ConnInfo {
        self.stream.info()
    }

    fn framing(&self) -> Framing {
        if let Some(f) = self.framing.get() {
            return f;
        }
        let f = self.stream.info().framing;
        self.framing.set(Some(f));
        f
    }

    fn closed_reason(&self) -> Option<CloseReason> {
        self.rt.with_entry(self.token, |e| e.closed).flatten()
    }

    /// Poll a read of up to `buf.len()` bytes (stream framing). `Ok(0)` is
    /// end of stream (the peer closed and everything was read).
    pub fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, NetError>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let max = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        match self.stream.recv(max) {
            Ok(bytes) => {
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Poll::Ready(Ok(n))
            },
            Err(Errno::Closed) => Poll::Ready(Ok(0)),
            Err(Errno::WouldBlock) => {
                self.rt.park(self.token, Interest::Read, cx.waker());
                Poll::Pending
            },
            Err(e) => Poll::Ready(Err(NetError::Host(e))),
        }
    }

    /// Poll a write of a prefix of `buf` (stream framing); returns how many
    /// bytes the host accepted. On a message-framed connection a whole
    /// `buf` is one message and the count is `buf.len()`.
    pub fn poll_write(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, NetError>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.stream.send(buf) {
            Ok(n) => Poll::Ready(Ok(match self.framing() {
                Framing::Message => buf.len(),
                Framing::Stream => n as usize,
            })),
            Err(Errno::WouldBlock) => {
                self.rt.park(self.token, Interest::Write, cx.waker());
                Poll::Pending
            },
            Err(Errno::Closed) => Poll::Ready(Err(NetError::Closed(
                self.closed_reason().unwrap_or(CloseReason::PeerClose),
            ))),
            Err(e) => Poll::Ready(Err(NetError::Host(e))),
        }
    }

    /// Read up to `buf.len()` bytes; `Ok(0)` at end of stream.
    ///
    /// # Errors
    /// The host's failure.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, NetError> {
        poll_fn(|cx| self.poll_read(cx, buf)).await
    }

    /// Write a prefix of `buf`; returns its length.
    ///
    /// # Errors
    /// The host's failure, or the connection closed.
    pub async fn write(&self, buf: &[u8]) -> Result<usize, NetError> {
        poll_fn(|cx| self.poll_write(cx, buf)).await
    }

    /// Write all of `buf`, waiting on `writable` as needed.
    ///
    /// # Errors
    /// The host's failure, or the connection closed part way.
    pub async fn write_all(&self, mut buf: &[u8]) -> Result<(), NetError> {
        while !buf.is_empty() {
            let n = self.write(buf).await?;
            buf = &buf[n..];
        }
        Ok(())
    }

    /// Send one whole message (message framing): accepted entirely or not
    /// at all, never split.
    ///
    /// # Errors
    /// `Host(Invalid)` for a message over `max-message`; closed; the host's
    /// failure.
    pub async fn send_message(&self, msg: &[u8]) -> Result<(), NetError> {
        poll_fn(|cx| match self.stream.send(msg) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(Errno::WouldBlock) => {
                self.rt.park(self.token, Interest::Write, cx.waker());
                Poll::Pending
            },
            Err(Errno::Closed) => Poll::Ready(Err(NetError::Closed(
                self.closed_reason().unwrap_or(CloseReason::PeerClose),
            ))),
            Err(e) => Poll::Ready(Err(NetError::Host(e))),
        })
        .await
    }

    /// Receive one whole message (message framing); `None` once the peer
    /// closed and every message was read.
    ///
    /// # Errors
    /// The host's failure.
    pub async fn recv_message(&self) -> Result<Option<Vec<u8>>, NetError> {
        let max = self.conn_info().max_message.unwrap_or(u32::MAX);
        poll_fn(|cx| match self.stream.recv(max) {
            Ok(m) => Poll::Ready(Ok(Some(m))),
            Err(Errno::Closed) => Poll::Ready(Ok(None)),
            Err(Errno::WouldBlock) => {
                self.rt.park(self.token, Interest::Read, cx.waker());
                Poll::Pending
            },
            Err(e) => Poll::Ready(Err(NetError::Host(e))),
        })
        .await
    }

    /// Close the connection (`stream.close`).
    pub fn close(&self) {
        self.stream.close();
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.rt.unregister(self.token);
    }
}

impl futures_io::AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Connection::poll_read(&self, cx, buf).map_err(Into::into)
    }
}

impl futures_io::AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Connection::poll_write(&self, cx, buf).map_err(Into::into)
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // The host owns send buffering; an accepted `send` is handed off.
        Poll::Ready(Ok(()))
    }
    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.close();
        Poll::Ready(Ok(()))
    }
}

/// A listener. Dropping it calls `unlisten` and releases its token.
pub struct Listener {
    id: u32,
    token: u64,
    rt: Runtime,
    /// The token for the next accepted connection, allocated once and kept
    /// until a connection takes it, so `accept` returning none wastes none.
    next: Cell<Option<u64>>,
}

impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listener")
            .field("id", &self.id)
            .field("token", &format_args!("{:#x}", self.token))
            .finish_non_exhaustive()
    }
}

/// Listen on `c` as `opts` says.
///
/// # Errors
/// The host's refusal (`unsupported` where [`can_listen`] is false).
pub fn listen(c: Carrier, opts: &ListenOptions) -> Result<Listener, NetError> {
    let rt = Runtime::current();
    let token = rt.alloc_token(TokenKind::Listener);
    match abi::listen(c, opts, token) {
        Ok(id) => Ok(Listener {
            id,
            token,
            rt,
            next: Cell::new(None),
        }),
        Err(e) => {
            rt.unregister(token);
            Err(NetError::Host(e))
        },
    }
}

impl Listener {
    /// The token this listener's events carry.
    #[must_use]
    pub fn token(&self) -> u64 {
        self.token
    }

    /// Poll for one connection: `accept` first, park on the listener's
    /// `readable` only after it answered none.
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<Result<Connection, NetError>> {
        if let Some(r) = self
            .rt
            .with_entry(self.token, |e| e.listener_failed)
            .flatten()
        {
            return Poll::Ready(Err(NetError::ListenerFailed(r)));
        }
        let token = match self.next.get() {
            Some(t) => t,
            None => {
                let t = self.rt.alloc_token(TokenKind::Conn);
                self.next.set(Some(t));
                t
            },
        };
        match abi::accept(self.id, token) {
            Ok(Some(stream)) => {
                self.next.set(None);
                Poll::Ready(Ok(Connection {
                    stream,
                    token,
                    rt: self.rt.clone(),
                    framing: Cell::new(None),
                }))
            },
            Ok(None) => {
                self.rt.park(self.token, Interest::Read, cx.waker());
                Poll::Pending
            },
            Err(e) => Poll::Ready(Err(NetError::Host(e))),
        }
    }

    /// Wait for one connection.
    ///
    /// # Errors
    /// The host's failure, or [`NetError::ListenerFailed`].
    pub async fn accept(&self) -> Result<Connection, NetError> {
        poll_fn(|cx| self.poll_accept(cx)).await
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        abi::unlisten(self.id);
        self.rt.unregister(self.token);
        if let Some(t) = self.next.take() {
            self.rt.unregister(t);
        }
    }
}

/// An unconnected datagram socket (`net.datagram`). Dropping it releases
/// the socket and its token.
pub struct Datagram {
    sock: abi::Datagram,
    token: u64,
    rt: Runtime,
}

impl fmt::Debug for Datagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Datagram")
            .field("token", &format_args!("{:#x}", self.token))
            .finish_non_exhaustive()
    }
}

/// Bind a datagram socket on `port` (0 = any) at `bind` (`None` = all).
///
/// # Errors
/// `Host(Unsupported)` unless [`can_datagram`]; the host's refusal.
pub fn bind(bind: Option<&str>, port: u16) -> Result<Datagram, NetError> {
    let rt = Runtime::current();
    let token = rt.alloc_token(TokenKind::Datagram);
    match abi::bind(bind, port, token) {
        Ok(sock) => Ok(Datagram { sock, token, rt }),
        Err(e) => {
            rt.unregister(token);
            Err(NetError::Host(e))
        },
    }
}

impl Datagram {
    /// The token this socket's events carry.
    #[must_use]
    pub fn token(&self) -> u64 {
        self.token
    }

    /// Send one datagram to `addr`, waiting on `writable` if needed.
    ///
    /// # Errors
    /// `Host(Invalid)` over `max-datagram`; the host's failure.
    pub async fn send_to(&self, addr: &str, data: &[u8]) -> Result<(), NetError> {
        poll_fn(|cx| match self.sock.send_to(addr, data) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(Errno::WouldBlock) => {
                self.rt.park(self.token, Interest::Write, cx.waker());
                Poll::Pending
            },
            Err(e) => Poll::Ready(Err(NetError::Host(e))),
        })
        .await
    }

    /// Receive one datagram: `(source address, bytes)`.
    ///
    /// # Errors
    /// The host's failure.
    pub async fn recv_from(&self) -> Result<(String, Vec<u8>), NetError> {
        poll_fn(|cx| match self.sock.recv_from() {
            Ok(v) => Poll::Ready(Ok(v)),
            Err(Errno::WouldBlock) => {
                self.rt.park(self.token, Interest::Read, cx.waker());
                Poll::Pending
            },
            Err(e) => Poll::Ready(Err(NetError::Host(e))),
        })
        .await
    }

    /// The bound address, when the host knows it.
    #[must_use]
    pub fn local_addr(&self) -> Option<String> {
        self.sock.local_addr()
    }

    /// The largest datagram [`send_to`](Self::send_to) accepts.
    #[must_use]
    pub fn max_datagram(&self) -> u32 {
        self.sock.max_datagram()
    }

    /// Join multicast `group`.
    ///
    /// # Errors
    /// `Host(Unsupported)` unless [`can_multicast`].
    pub fn multicast_join(&self, group: &str, interface: Option<&str>) -> Result<(), NetError> {
        self.sock
            .multicast_join(group, interface)
            .map_err(NetError::Host)
    }

    /// Leave multicast `group`.
    ///
    /// # Errors
    /// The host's failure.
    pub fn multicast_leave(&self, group: &str, interface: Option<&str>) -> Result<(), NetError> {
        self.sock
            .multicast_leave(group, interface)
            .map_err(NetError::Host)
    }
}

impl Drop for Datagram {
    fn drop(&mut self) {
        self.rt.unregister(self.token);
    }
}
