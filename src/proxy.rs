use std::collections::HashMap;
use std::error::Error;
use std::net::{SocketAddr, SocketAddrV6};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use proxy_protocol::version2::{ProxyAddresses, ProxyCommand, ProxyTransportProtocol};
use proxy_protocol::EncodeError;
use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::net;

/// Proxy the inbound stream to a target address.
pub async fn proxy(
    inbound: TcpStream,
    proxy_header: ProxyHeader,
    addr_target: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    proxy_with_queue(inbound, proxy_header, addr_target, &[]).await
}

/// Proxy the inbound stream to a target address.
///
/// Send the queue to the target server before proxying.
pub async fn proxy_with_queue(
    inbound: TcpStream,
    proxy_header: ProxyHeader,
    addr_target: SocketAddr,
    queue: &[u8],
) -> Result<(), Box<dyn Error>> {
    // Set up connection to server
    // TODO: on connect fail, ping server and redirect to serve_status if offline
    let mut outbound = TcpStream::connect(addr_target).await?;

    // Add proxy header
    match proxy_header {
        ProxyHeader::None => {}
        ProxyHeader::Local => {
            let header = local_proxy_header()?;
            outbound.write_all(&header).await?;
        }
        ProxyHeader::Proxy => {
            let header = stream_proxy_header(&inbound)?;
            outbound.write_all(&header).await?;
        }
    }

    // Start proxy on both streams
    proxy_inbound_outbound_with_queue(inbound, outbound, &[], queue).await
}

/// Proxy the inbound stream to a target address.
///
/// Send the queue to the target server before proxying.
// TODO: find better name for this
pub async fn proxy_inbound_outbound_with_queue(
    mut inbound: TcpStream,
    mut outbound: TcpStream,
    inbound_queue: &[u8],
    outbound_queue: &[u8],
) -> Result<(), Box<dyn Error>> {
    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();

    // Forward queued bytes to client once writable
    if !inbound_queue.is_empty() {
        wi.writable().await?;
        trace!(target: "lazymc", "Relaying {} queued bytes to client", inbound_queue.len());
        wi.write_all(inbound_queue).await?;
    }

    // Forward queued bytes to server once writable
    if !outbound_queue.is_empty() {
        wo.writable().await?;
        trace!(target: "lazymc", "Relaying {} queued bytes to server", outbound_queue.len());
        wo.write_all(outbound_queue).await?;
    }

    let client_to_server = async {
        io::copy(&mut ri, &mut wo).await?;
        wo.shutdown().await
    };
    let server_to_client = async {
        io::copy(&mut ro, &mut wi).await?;
        wi.shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client)?;

    // Gracefully close connection if not done already
    net::close_tcp_stream(inbound).await?;

    Ok(())
}

/// Proxy header.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ProxyHeader {
    /// Do not add proxy header.
    None,

    /// Header for locally initiated connection.
    #[allow(unused)]
    Local,

    /// Header for proxied connection.
    Proxy,
}

impl ProxyHeader {
    /// Changes to `None` if `false` if given.
    ///
    /// `None` stays `None`.
    pub fn not_none(self, not_none: bool) -> Self {
        if not_none {
            self
        } else {
            Self::None
        }
    }
}

/// Get the proxy header for a locally initiated connection.
///
/// This header may be sent over the outbound stream to signal client information.
pub fn local_proxy_header() -> Result<BytesMut, EncodeError> {
    // Build proxy header
    let header = proxy_protocol::ProxyHeader::Version2 {
        command: ProxyCommand::Local,
        transport_protocol: ProxyTransportProtocol::Stream,
        addresses: ProxyAddresses::Unspec,
    };

    proxy_protocol::encode(header)
}

/// Get the proxy header for the given inbound stream.
///
/// This header may be sent over the outbound stream to signal client information.
pub fn stream_proxy_header(inbound: &TcpStream) -> Result<BytesMut, EncodeError> {
    // Get peer and local address (the real client if a trusted proxy sent it to us)
    let mut peer = real_peer(inbound).expect("Peer address not known for TCP stream");
    let mut local = inbound
        .local_addr()
        .expect("Local address not known for TCP stream");

    // Both must be of the same family: map IPv4 to IPv6 if they differ
    match (peer, local) {
        (SocketAddr::V6(_), SocketAddr::V4(l)) => {
            local = SocketAddr::V6(SocketAddrV6::new(l.ip().to_ipv6_mapped(), l.port(), 0, 0))
        }
        (SocketAddr::V4(p), SocketAddr::V6(_)) => {
            peer = SocketAddr::V6(SocketAddrV6::new(p.ip().to_ipv6_mapped(), p.port(), 0, 0))
        }
        _ => {}
    }

    // Build proxy header
    let header = proxy_protocol::ProxyHeader::Version2 {
        command: ProxyCommand::Proxy,
        transport_protocol: ProxyTransportProtocol::Stream,
        addresses: match (peer, local) {
            (SocketAddr::V4(source), SocketAddr::V4(destination)) => ProxyAddresses::Ipv4 {
                source,
                destination,
            },
            (SocketAddr::V6(source), SocketAddr::V6(destination)) => ProxyAddresses::Ipv6 {
                source,
                destination,
            },
            (_, _) => unreachable!("mapped to the same family above"),
        },
    };

    proxy_protocol::encode(header)
}

/// PROXY protocol v2 signature.
const PROXY_V2_SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

/// Real client addresses of connections that came through a trusted local proxy, by their socket peer address.
///
/// Every new local connection sets or clears its own entry when accepted, so a stale entry is never used.
static REAL_PEERS: LazyLock<Mutex<HashMap<SocketAddr, SocketAddr>>> =
    LazyLock::new(Default::default);

/// Get the real client address of the inbound stream.
///
/// This is the address from a PROXY header sent by a trusted local proxy, or the socket peer address.
pub fn real_peer(inbound: &TcpStream) -> io::Result<SocketAddr> {
    let peer = inbound.peer_addr()?;
    Ok(REAL_PEERS.lock().unwrap().get(&peer).copied().unwrap_or(peer))
}

/// Receive an optional PROXY v2 header at the start of an inbound stream from a trusted proxy.
///
/// Consumes the header if there is one and returns the client address it carries. Without a header, nothing is
/// consumed and the socket peer address is returned. Errors on a malformed header or a closed stream.
pub async fn receive_proxy_header(inbound: &mut TcpStream) -> Result<SocketAddr, ()> {
    let peer = inbound.peer_addr().map_err(|_| ())?;
    REAL_PEERS.lock().unwrap().remove(&peer);

    // Peek until the signature matches or not (a Minecraft handshake never starts with it)
    let mut start = [0u8; 16];
    loop {
        let n = inbound.peek(&mut start).await.map_err(|_| ())?;
        if n == 0 {
            return Err(());
        }
        let m = n.min(PROXY_V2_SIGNATURE.len());
        if start[..m] != PROXY_V2_SIGNATURE[..m] {
            return Ok(peer);
        }
        if n == start.len() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Read and parse the whole header
    let len = u16::from_be_bytes([start[14], start[15]]) as usize;
    let mut header = vec![0u8; start.len() + len];
    inbound.read_exact(&mut header).await.map_err(|_| ())?;
    let real = match proxy_protocol::parse(&mut header.as_slice()) {
        Ok(proxy_protocol::ProxyHeader::Version2 {
            command: ProxyCommand::Proxy,
            addresses,
            ..
        }) => match addresses {
            ProxyAddresses::Ipv4 { source, .. } => SocketAddr::V4(source),
            ProxyAddresses::Ipv6 { source, .. } => {
                SocketAddr::new(source.ip().to_canonical(), source.port())
            }
            _ => peer,
        },
        Ok(_) => peer,
        Err(err) => {
            debug!(target: "lazymc", "Malformed proxy header from {}: {}", peer, err);
            return Err(());
        }
    };

    if real != peer {
        REAL_PEERS.lock().unwrap().insert(peer, real);
    }
    Ok(real)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;
    use tokio::net::TcpListener;

    /// Send `first` on a new local connection, receive the proxy header, return the address and what's left.
    async fn receive(first: Vec<u8>) -> (Result<SocketAddr, ()>, Vec<u8>, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        let (mut inbound, _) = listener.accept().await.unwrap();
        client.write_all(&first).await.unwrap();
        client.shutdown().await.unwrap();
        let real = receive_proxy_header(&mut inbound).await;
        let mut rest = Vec::new();
        inbound.read_to_end(&mut rest).await.unwrap();
        (real, rest, real_peer(&inbound).unwrap())
    }

    fn header(source: SocketAddr) -> Vec<u8> {
        let addresses = match source {
            SocketAddr::V4(source) => ProxyAddresses::Ipv4 {
                source,
                destination: "127.0.0.1:45566".parse().unwrap(),
            },
            SocketAddr::V6(source) => ProxyAddresses::Ipv6 {
                source,
                destination: "[::1]:45566".parse().unwrap(),
            },
        };
        proxy_protocol::encode(proxy_protocol::ProxyHeader::Version2 {
            command: ProxyCommand::Proxy,
            transport_protocol: ProxyTransportProtocol::Stream,
            addresses,
        })
        .unwrap()
        .to_vec()
    }

    #[tokio::test]
    async fn with_header() {
        let real: SocketAddr = SocketAddrV4::new([83, 45, 1, 2].into(), 51234).into();
        let mut data = header(real);
        data.extend_from_slice(b"\x10\x00handshake");
        let (got, rest, peer) = receive(data).await;
        assert_eq!(got, Ok(real));
        assert_eq!(peer, real, "the outgoing header uses the real client");
        assert_eq!(rest, b"\x10\x00handshake");
    }

    #[tokio::test]
    async fn ipv6_and_mapped() {
        let real: SocketAddr = "[2a01:4f8::1]:4000".parse().unwrap();
        assert_eq!(receive(header(real)).await.0, Ok(real));
        let mapped: SocketAddr = "[::ffff:83.45.1.2]:4000".parse().unwrap();
        assert_eq!(receive(header(mapped)).await.0, Ok("83.45.1.2:4000".parse().unwrap()));
    }

    #[tokio::test]
    async fn without_header() {
        // A handshake of length 13 starts with the same byte as the signature
        for data in [b"\x10\x00handshake".to_vec(), b"\x0d\x00handshake....".to_vec()] {
            let (got, rest, peer) = receive(data.clone()).await;
            assert!(got.unwrap().ip().is_loopback());
            assert!(peer.ip().is_loopback());
            assert_eq!(rest, data, "nothing consumed");
        }
    }

    #[tokio::test]
    async fn broken_header() {
        let mut data = PROXY_V2_SIGNATURE.to_vec();
        data.extend_from_slice(&[0x21, 0x11, 0, 2, 1, 2]);
        assert_eq!(receive(data).await.0, Err(()));
        assert_eq!(receive(Vec::new()).await.0, Err(()));
    }

    #[test]
    fn outgoing_header_mixed_families() {
        // Real IPv6 client on an IPv4 socket must not panic
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
            let (mut inbound, _) = listener.accept().await.unwrap();
            client.write_all(&header("[2a01:4f8::1]:4000".parse().unwrap())).await.unwrap();
            receive_proxy_header(&mut inbound).await.unwrap();
            let out = stream_proxy_header(&inbound).unwrap();
            match proxy_protocol::parse(&mut &out[..]).unwrap() {
                proxy_protocol::ProxyHeader::Version2 {
                    addresses: ProxyAddresses::Ipv6 { source, .. },
                    ..
                } => assert_eq!(source.to_string(), "[2a01:4f8::1]:4000"),
                other => panic!("{other:?}"),
            }
        });
    }
}
