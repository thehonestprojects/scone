//! libp2p behaviour of a Scone relay.
//!
//! Composite behaviour:
//!
//! - [`identify`] — peer key/protocol/address discovery (fills
//!   Kademlia's routing table with the addresses peers announce);
//! - [`ping`] — liveness probes;
//! - [`kad`] — DHT of signed DNS records (key = `DomainId` bytes,
//!   value = canonical `SignedDnsRecord` bytes);
//! - [`request_response`] — the scone-protocol messages
//!   (`GetBlocks/Block/GetRecord/Record/Hello/Ping/Pong`) framed with
//!   a 4-byte big-endian length prefix whose payload is the existing
//!   canonical codec.
//!
//! The wire codec ([`SconeCodec`]) bounds every frame to
//! [`MAX_MESSAGE_LEN`] **before** parsing and never panics on remote
//! data.

use std::io;
use std::time::Duration;

use async_trait::async_trait;
use futures::prelude::*;
use libp2p::StreamProtocol;
use libp2p::kad;
use libp2p::kad::store::MemoryStore;
use libp2p::multiaddr::Protocol;
use libp2p::request_response;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{PeerId, identify, ping};
use scone_protocol::Message;
use scone_protocol::codec::Encode;
use scone_protocol::codec::decode_complete;
use scone_protocol::limits::MAX_MESSAGE_LEN;

/// Name of the request-response protocol (version-locked).
pub const SCONE_PROTOCOL_NAME: &str = "/scone/reqres/1";

/// Name of the Kademlia protocol (version-locked).
pub const SCONE_KAD_NAME: &str = "/scone/kad/1";

/// Name of the identify agent string.
pub const SCONE_IDENTIFY: &str = "/scone/id/1";

/// Width of the frame length prefix (u32 big-endian).
const LEN_PREFIX: usize = 4;

/// Protocol descriptor passed to the request-response behaviour.
#[derive(Debug, Clone)]
pub struct SconeProtocol {
    inner: StreamProtocol,
}

impl SconeProtocol {
    /// The scone request-response protocol descriptor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: StreamProtocol::new(SCONE_PROTOCOL_NAME),
        }
    }
}

impl AsRef<str> for SconeProtocol {
    fn as_ref(&self) -> &str {
        self.inner.as_ref()
    }
}

impl Default for SconeProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Frame codec: `len: u32 BE || canonical Message bytes`.
///
/// Decoding reads the length first and rejects anything above
/// [`MAX_MESSAGE_LEN`] **before** reading the body — a malicious peer
/// cannot force a large allocation. The body then goes through the
/// strict canonical decoder; any failure maps to an I/O error (the
/// substream is dropped, the relay keeps running).
#[derive(Debug, Clone, Default)]
pub struct SconeCodec;

impl SconeCodec {
    /// Reads one length-prefixed frame, bounded.
    async fn read_frame<T>(io: &mut T) -> io::Result<Vec<u8>>
    where
        T: AsyncRead + Unpin,
    {
        let mut len_bytes = [0u8; LEN_PREFIX];
        io.read_exact(&mut len_bytes).await?;
        let len = u32::from_be_bytes(len_bytes) as usize;
        if len > MAX_MESSAGE_LEN {
            return Err(io::Error::other(format!(
                "frame of {len} bytes exceeds MAX_MESSAGE_LEN ({MAX_MESSAGE_LEN})"
            )));
        }
        let mut frame = vec![0u8; len];
        io.read_exact(&mut frame).await?;
        Ok(frame)
    }

    /// Writes one length-prefixed frame.
    async fn write_frame<T>(io: &mut T, bytes: &[u8]) -> io::Result<()>
    where
        T: AsyncWrite + Unpin,
    {
        let len = u32::try_from(bytes.len()).map_err(|_| io::Error::other("frame too large"))?;
        io.write_all(&len.to_be_bytes()).await?;
        io.write_all(bytes).await?;
        io.flush().await
    }

    /// Decodes a complete canonical message (strict).
    fn decode_message(bytes: &[u8]) -> io::Result<Message> {
        decode_complete(bytes).map_err(|e| io::Error::other(e.to_string()))
    }

    /// Encodes a message canonically.
    fn encode_message(message: &Message) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        message
            .encode(&mut out)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(out)
    }
}

#[async_trait]
impl request_response::Codec for SconeCodec {
    type Protocol = SconeProtocol;
    type Request = Message;
    type Response = Message;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Message>
    where
        T: AsyncRead + Unpin + Send,
    {
        Self::decode_message(&Self::read_frame(io).await?)
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Message>
    where
        T: AsyncRead + Unpin + Send,
    {
        Self::decode_message(&Self::read_frame(io).await?)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        req: Message,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Self::write_frame(io, &Self::encode_message(&req)?).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Message,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        Self::write_frame(io, &Self::encode_message(&res)?).await
    }
}

/// Composite network behaviour of a relay.
#[derive(NetworkBehaviour)]
pub struct SconeBehaviour {
    /// Connection admission (P1.5): hard caps enforced at the swarm
    /// level — a peer cannot exhaust memory by opening connections.
    pub limits: libp2p::connection_limits::Behaviour,
    /// Identify protocol (address discovery for Kademlia).
    pub identify: identify::Behaviour,
    /// Liveness probes.
    pub ping: ping::Behaviour,
    /// DHT of signed DNS records.
    pub kad: kad::Behaviour<MemoryStore>,
    /// scone request-response (sync + records + handshake).
    pub reqres: request_response::Behaviour<SconeCodec>,
}

/// Builds the composite behaviour (devnet-tuned: no periodic
/// republish, 10 s query timeout, server mode).
#[must_use]
pub fn build_behaviour(key: &libp2p::identity::Keypair) -> SconeBehaviour {
    let peer = PeerId::from(key.public());

    let identify = identify::Behaviour::new(
        identify::Config::new(SCONE_IDENTIFY.to_string(), key.public())
            .with_push_listen_addr_updates(true),
    );

    let ping = ping::Behaviour::new(ping::Config::new());

    let mut kad_config = kad::Config::new(StreamProtocol::new(SCONE_KAD_NAME));
    kad_config.set_query_timeout(Duration::from_secs(10));
    // Records do not expire locally: the chain, not time, governs
    // validity. No periodic republish on the devnet.
    kad_config.set_record_ttl(None);
    kad_config.set_publication_interval(None);
    let store = MemoryStore::new(peer);
    let mut kad = kad::Behaviour::with_config(peer, store, kad_config);
    kad.set_mode(Some(kad::Mode::Server));

    let reqres_config = request_response::Config::default()
        .with_request_timeout(Duration::from_secs(10))
        .with_max_concurrent_streams(64);
    let reqres = request_response::Behaviour::with_codec(
        SconeCodec,
        std::iter::once((
            SconeProtocol::new(),
            request_response::ProtocolSupport::Full,
        )),
        reqres_config,
    );

    // P1.5 — connection admission: a relay keeps at most
    // MAX_TOTAL_CONNECTIONS connections overall (in+out) and
    // MAX_PER_PEER_CONNECTIONS per peer. libp2p refuses the excess
    // (incoming) instead of queueing it — a connection-flood peer
    // gets dropped, never a memory bump. Outbound dials by honest
    // peers still succeed: the total cap leaves headroom.
    let limits = libp2p::connection_limits::Behaviour::new(
        libp2p::connection_limits::ConnectionLimits::default()
            .with_max_established(Some(MAX_TOTAL_CONNECTIONS))
            .with_max_pending_incoming(Some(MAX_PENDING_INCOMING))
            .with_max_established_per_peer(Some(MAX_PER_PEER_CONNECTIONS)),
    );

    SconeBehaviour {
        limits,
        identify,
        ping,
        kad,
        reqres,
    }
}

/// Hard cap on concurrent connections (in + out) per relay (P1.5).
pub const MAX_TOTAL_CONNECTIONS: u32 = 128;
/// Hard cap on concurrent connections to a single peer (P1.5).
pub const MAX_PER_PEER_CONNECTIONS: u32 = 4;
/// Hard cap on pending (handshaking) incoming connections (P1.5) —
/// the slowloris guard: unauthenticated half-connections never queue
/// unboundedly.
pub const MAX_PENDING_INCOMING: u32 = 32;

/// Extracts `(PeerId, Multiaddr)` from a bootstrap multiaddr ending
/// in `/p2p/<id>`.
///
/// # Errors
///
/// [`crate::NetworkError::Peer`] when the address is not parseable or
/// carries no peer id.
pub fn parse_bootstrap_addr(addr: &str) -> crate::error::Result<(PeerId, libp2p::Multiaddr)> {
    let multiaddr: libp2p::Multiaddr = addr
        .parse()
        .map_err(|e| crate::NetworkError::Peer(format!("bad multiaddr '{addr}': {e}")))?;
    let mut address = multiaddr.clone();
    let peer = match address.pop() {
        Some(Protocol::P2p(peer_id)) => peer_id,
        _ => {
            return Err(crate::NetworkError::Peer(format!(
                "bootstrap multiaddr '{addr}' has no /p2p/<peer-id> suffix"
            )));
        }
    };
    Ok((peer, address))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_roundtrips_through_bytes() {
        let message = Message::GetBlocks {
            start_height: 3,
            max_blocks: 16,
        };
        let encoded = SconeCodec::encode_message(&message).expect("encode");
        assert_eq!(SconeCodec::decode_message(&encoded).unwrap(), message);
    }

    #[test]
    fn garbage_does_not_decode() {
        assert!(SconeCodec::decode_message(&[0xff, 0x00]).is_err());
        assert!(SconeCodec::decode_message(&[]).is_err());
    }

    #[test]
    fn protocol_names_are_stable() {
        assert_eq!(SCONE_PROTOCOL_NAME, "/scone/reqres/1");
        assert_eq!(SCONE_KAD_NAME, "/scone/kad/1");
        assert_eq!(SconeProtocol::new().as_ref(), "/scone/reqres/1");
    }

    #[test]
    fn bootstrap_addr_parsing() {
        // No /p2p suffix: rejected.
        assert!(parse_bootstrap_addr("/ip4/127.0.0.1/udp/4001/quic-v1").is_err());
        // Garbage peer id: rejected.
        assert!(parse_bootstrap_addr("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/notapeer").is_err());
        // Valid peer id: split into (peer, address).
        let valid = "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp";
        let (peer, addr) = parse_bootstrap_addr(valid).expect("valid");
        assert_eq!(
            peer.to_string(),
            "12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp"
        );
        assert_eq!(addr.to_string(), "/ip4/127.0.0.1/udp/4001/quic-v1");
    }
}
