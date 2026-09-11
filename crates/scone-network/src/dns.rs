//! UDP + TCP DNS server (milestones M6 + M7b): authoritative for
//! names the local chain state knows, optional recursive fallback
//! (`addr:port` upstreams) for everything else. Built strictly on the
//! existing verified path: the relay is the only resolver — this
//! module never touches the chain, the store or the DHT itself.
//!
//! # Wire codec (RFC 1035 subset, strict)
//!
//! - Query: 12-byte header, exactly **one** question, **no** name
//!   compression (compression pointers in a question are refused),
//!   QCLASS = IN. QNAME labels are lowercased and validated against
//!   the Scone charset (strict subset of LDH: `[a-z0-9-]`, hyphen
//!   neither first nor last — `_` accepted for SRV-style lookups but
//!   rejected by `DomainName` on the authoritative path).
//! - Response: QR|RD(echo)|RA bits, AA **only** on chain-backed
//!   (authoritative) answers, the question echoed verbatim, answers
//!   with **uncompressed** owner names (the qname), TTL 60, bounded
//!   by the transport's payload limit: an answer set that does not
//!   fit is cut at the last fitting record with **TC=1** (honest
//!   truncation, RFC 1035 §4.2.1). On UDP the cut happens at the
//!   512-o classic payload ([`UDP_PAYLOAD_LIMIT`], no EDNS) so the
//!   client retries over TCP (RFC 7766), which serves the **full**
//!   set up to [`MAX_TCP_RESPONSE`].
//! - Anything unparseable is answered with **silence** (garbage must
//!   cost nothing); `REFUSED` is returned for a QCLASS we refuse.
//!
//! # Resolution model
//!
//! ```text
//! UDP query → in-DNS-cache? → answer (bounded TTL)
//!          → Scone-charset qname? → authoritative path:
//!               longest-suffix apex search → Resolver (the relay):
//!                 chain state + chain-verified record → answers
//!                 unknown/unregistered apex chain-wide → NXDOMAIN
//!                 registered apex, no matching rdata → NODATA
//!                 registered apex, no record published → NODATA
//!          → else → fallback upstreams (if configured) → answer
//!          → else → REFUSED
//! ```
//!
//! The cache is keyed by (qname, qtype), bounded (LRU-ish: random
//! eviction through an index map — see [`Cache`]) and holds verified
//! authoritative answers plus validated fallback answers with their
//! own (clamped) TTL — each entry carrying its origin so the AA bit
//! stays honest on a cache hit. **Error rcodes are never cached**:
//! SERVFAIL (transient local failure) and REFUSED (config state)
//! are recomputed on every query.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use scone_core::{DomainName, RecordData, TldName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

use crate::error::{NetworkError, Result};

// ---- protocol constants -------------------------------------------------

const CLASS_IN: u16 = 1;
pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_ANY: u16 = 255;

const RCODE_NOERROR: u8 = 0;
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_REFUSED: u8 = 5;

/// Hard cap on a DNS datagram (query or response).
pub const MAX_PACKET_LEN: usize = 4096;
/// Maximum DNS **query** accepted over TCP (RFC 7766 §6: a query
/// fits the classic 512-o payload; we allow generous headroom for
/// EDNS-style oversized queries from stub resolvers, bounded).
pub const MAX_TCP_QUERY: usize = 512;
/// Maximum DNS **response** served over TCP (2-byte length prefix
/// caps a message at 65535; our answers are far smaller — records
/// are ≤ 4096 B at decode — this is the hard ceiling).
pub const MAX_TCP_RESPONSE: usize = 65_535;
/// Maximum simultaneously in-flight TCP DNS connections (anti-flood
/// bound; extra connections are shed, never queued).
pub const MAX_TCP_CONNS: usize = 64;
/// Read timeout for a TCP DNS message (header or body): a client
/// that stalls is dropped, its connection slot freed.
pub const TCP_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// UDP payload limit assumed when answering a client that did not
/// signal EDNS (RFC 1035 §2.3.4 / RFC 7766 §9): larger answers are
/// cut with TC=1 so the client retries over TCP.
pub const UDP_PAYLOAD_LIMIT: usize = 512;
/// TTL served on authoritative answers (devnet: short, chain-sequenced).
pub const ANSWER_TTL: u32 = 60;
/// Maximum TTL accepted on a cached fallback answer.
pub const MAX_FALLBACK_TTL: u32 = 600;
/// Maximum names cached (positive and negative).
pub const CACHE_CAPACITY: usize = 1024;
/// Maximum simultaneously in-flight UDP queries (anti-flood bound).
pub const MAX_INFLIGHT_UDP: usize = 256;
/// Per-upstream forward timeout.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(2);

// ---- resolver abstraction -----------------------------------------------

/// Answer of the authoritative path for one apex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Chain-valid record set of the apex, as `(type_code, rdata)`
    /// wire pairs (already DNS-encoded; empty = NODATA).
    pub rdata: Vec<(u16, Vec<u8>)>,
    /// True when the apex is registered on-chain.
    pub registered: bool,
}

/// The authoritative resolver — the relay, behind one async closure.
/// `Ok(None)` = apex not registered on-chain (→ NXDOMAIN);
/// `Ok(Some)` = apex state (records possibly empty → NODATA);
/// `Err` = local failure (→ SERVFAIL).
pub type Resolver = Arc<
    dyn Fn(
            String,
        )
            -> futures::future::BoxFuture<'static, std::result::Result<Option<Resolved>, String>>
        + Send
        + Sync,
>;

// ---- server -------------------------------------------------------------

/// Runs the UDP DNS loop on an already-bound socket. Responses are
/// bounded by [`UDP_PAYLOAD_LIMIT`] (classic 512-o payload, no
/// EDNS): an answer set that does not fit is cut with TC=1 — the
/// standard retry-over-TCP signal (RFC 7766), served by [`run_tcp`].
///
/// # Errors
///
/// [`NetworkError::Io`] only on a fatal socket failure (the loop
/// itself never returns on individual packet errors).
pub async fn run_udp(
    socket: Arc<UdpSocket>,
    resolver: Resolver,
    upstreams: Vec<SocketAddr>,
    cache: Arc<tokio::sync::Mutex<Cache>>,
) -> Result<()> {
    let listen = socket.local_addr()?;
    info!(%listen, upstreams = upstreams.len(), "dns: listening udp");
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_UDP));
    let mut buf = vec![0u8; MAX_PACKET_LEN];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        if n == 0 || n > MAX_PACKET_LEN {
            continue;
        }
        let data = buf[..n].to_vec();
        let Ok(permit) = sem.clone().acquire_owned().await else {
            continue; // at capacity: drop, the client retries
        };
        let socket = socket.clone();
        let resolver = resolver.clone();
        let upstreams = upstreams.clone();
        let cache = cache.clone();
        tokio::spawn(async move {
            if let Some(resp) = handle_packet_transport(
                &resolver,
                &data,
                &upstreams,
                &mut *cache.lock().await,
                UDP_PAYLOAD_LIMIT,
            )
            .await
                && resp.len() <= MAX_PACKET_LEN
            {
                let _ = socket.send_to(&resp, peer).await;
            }
            drop(permit);
        });
    }
}

/// Runs the TCP DNS loop (RFC 7766) on an already-bound listener,
/// same port as the UDP surface. Messages are prefixed with their
/// 2-byte big-endian length (RFC 1035 §4.2.2). Bounds:
///
/// - at most [`MAX_TCP_CONNS`] concurrent connections (semaphore:
///   a 65th connection is dropped immediately, never queued);
/// - a query larger than [`MAX_TCP_QUERY`] closes the connection;
/// - each read (length header or body) is capped at
///   [`TCP_READ_TIMEOUT`] — a stalled client is dropped;
/// - pipelining is served serially per connection (requests are
///   answered in order), which is correct and bounded.
///
/// Errors (read/write/timeout) are logged at `debug` and close the
/// connection cleanly — no panic on network input, ever.
///
/// # Errors
///
/// [`NetworkError::Io`] only on a fatal accept-loop failure.
pub async fn run_tcp(
    listener: tokio::net::TcpListener,
    resolver: Resolver,
    upstreams: Vec<SocketAddr>,
    cache: Arc<tokio::sync::Mutex<Cache>>,
) -> Result<()> {
    let listen = listener.local_addr()?;
    info!(%listen, upstreams = upstreams.len(), "dns: listening tcp");
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_TCP_CONNS));
    loop {
        let (mut stream, peer) = listener.accept().await?;
        let Ok(permit) = sem.clone().try_acquire_owned() else {
            // At capacity: shed now (drop closes the socket — the
            // client's own timeout drives the retry). try_acquire:
            // queueing permits would park accept-loop iterations and
            // let backlog grow without bound.
            warn!(%peer, "dns: tcp connection shed (at capacity)");
            continue;
        };
        let resolver = resolver.clone();
        let upstreams = upstreams.clone();
        let cache = cache.clone();
        tokio::spawn(async move {
            debug!(%peer, "dns: tcp connection");
            loop {
                // Length header (2 B), bounded read time. Clean EOF
                // (0 byte) or stall (timeout) ends the conversation.
                let mut hdr = [0u8; 2];
                let len = match tokio::time::timeout(TCP_READ_TIMEOUT, stream.read_exact(&mut hdr))
                    .await
                {
                    Ok(Ok(_)) => u16::from_be_bytes(hdr) as usize,
                    Ok(Err(_)) => break, // reset / closed: done
                    Err(_) => break,     // stalled: drop
                };
                if len == 0 || len > MAX_TCP_QUERY {
                    // Zero-length or oversized: protocol violation,
                    // close (RFC 7766 §6: the query limit is strict).
                    debug!(%peer, len, "dns: tcp query out of bounds, closing");
                    break;
                }
                let mut msg = vec![0u8; len];
                let body =
                    tokio::time::timeout(TCP_READ_TIMEOUT, stream.read_exact(&mut msg)).await;
                if !matches!(body, Ok(Ok(_))) {
                    break; // short read, reset or stall: drop
                }
                if let Some(resp) = handle_packet_transport(
                    &resolver,
                    &msg,
                    &upstreams,
                    &mut *cache.lock().await,
                    MAX_TCP_RESPONSE,
                )
                .await
                {
                    let mut out = (u16::try_from(resp.len()).unwrap_or(u16::MAX))
                        .to_be_bytes()
                        .to_vec();
                    out.extend_from_slice(&resp);
                    if stream.write_all(&out).await.is_err() {
                        break;
                    }
                }
                // else: garbage → silence → keep serving pipelined
                // requests on this connection (closing on garbage
                // would let a single bad byte kill a good session).
            }
            drop(permit); // free the connection slot
        });
    }
}

/// Handles one datagram: cache → authoritative → fallback. Returns
/// `None` for garbage (silence). Pure-ish entry point (the cache is
/// injected), fully covered by tests. Payload budget =
/// [`MAX_PACKET_LEN`] (maximal); transport-aware callers (the UDP
/// loop's 512-o bound) use [`handle_packet_transport`].
///
/// Honesty rules: the AA bit is set **only** on answers produced by
/// the authoritative path (fresh or cached-authoritative); fallback
/// answers and error rcodes (SERVFAIL/REFUSED) are never marked
/// authoritative. SERVFAIL and REFUSED are never cached (a local
/// RPC failure is transient, a missing upstream is config state).
pub async fn handle_packet(
    resolver: &Resolver,
    data: &[u8],
    upstreams: &[SocketAddr],
    cache: &mut Cache,
) -> Option<Vec<u8>> {
    handle_packet_transport(resolver, data, upstreams, cache, MAX_PACKET_LEN).await
}

/// [`handle_packet`] with an explicit response payload budget: an
/// answer set that does not fit is cut at the last record that does
/// with TC=1 (the client retries over TCP per RFC 7766; the TCP loop
/// calls this with [`MAX_TCP_RESPONSE`], so the full set fits there).
pub async fn handle_packet_transport(
    resolver: &Resolver,
    data: &[u8],
    upstreams: &[SocketAddr],
    cache: &mut Cache,
    budget: usize,
) -> Option<Vec<u8>> {
    let q = parse_query(data)?;
    // Cache hit (positive or negative): AA follows the origin of the
    // cached entry, not the path that produced it.
    if let Some(entry) = cache.get(&q.name, q.qtype) {
        return Some(build_response_bounded(
            &q,
            data,
            &entry.answers,
            entry.rcode,
            entry.authoritative,
            budget,
        ));
    }
    let (answers, rcode) = if scone_candidate(&q.name) {
        authoritative(resolver, &q).await
    } else if upstreams.is_empty() {
        (Vec::new(), RCODE_REFUSED)
    } else {
        match forward(data, upstreams).await {
            Some(resp) => {
                // Validated upstream reply (TXID + question echo +
                // connect-checked socket — see [`forward`]). Pass it
                // through unchanged when it fits the transport's
                // budget; cache its answers on the fallback path, but
                // never an error rcode.
                let up_rcode = resp.get(3).map_or(RCODE_NOERROR, |b| b & 0x0F);
                let extracted = if up_rcode == RCODE_NOERROR || up_rcode == RCODE_NXDOMAIN {
                    extract_answers(&resp, &q)
                } else {
                    debug!(rcode = up_rcode, "dns: upstream error not cached");
                    None
                };
                if let Some((ans, ttl)) = &extracted {
                    cache.put(
                        q.name.clone(),
                        q.qtype,
                        CacheEntry {
                            answers: ans.clone(),
                            rcode: up_rcode,
                            ttl: (*ttl).min(MAX_FALLBACK_TTL),
                            authoritative: false,
                        },
                    );
                }
                if resp.len() <= budget {
                    return Some(resp);
                }
                // Oversized fallback reply: the verbatim bytes do not
                // fit this transport (e.g. > 512 over UDP). Re-encode
                // a bounded honest version — cut with TC=1 over UDP so
                // the client retries over TCP, where the larger budget
                // carries the whole set.
                let (ans, rcode) = extracted
                    .map(|(a, _)| (a, up_rcode))
                    .unwrap_or_else(|| (Vec::new(), RCODE_SERVFAIL));
                return Some(build_response_bounded(&q, data, &ans, rcode, false, budget));
            }
            None => (Vec::new(), RCODE_SERVFAIL),
        }
    };
    let cacheable = rcode == RCODE_NOERROR || rcode == RCODE_NXDOMAIN;
    if cacheable {
        cache.put(
            q.name.clone(),
            q.qtype,
            CacheEntry {
                answers: answers.clone(),
                rcode,
                ttl: ANSWER_TTL,
                authoritative: true,
            },
        );
    }
    // Only the authoritative path sets AA; REFUSED/SERVFAIL do not.
    Some(build_response_bounded(
        &q, data, &answers, rcode, cacheable, budget,
    ))
}

/// Longest-suffix apex search + record selection.
async fn authoritative(resolver: &Resolver, q: &Query) -> (Vec<(u16, u32, Vec<u8>)>, u8) {
    let labels: Vec<&str> = q.name.split('.').collect();
    if labels.len() < 2 {
        return (Vec::new(), RCODE_NXDOMAIN);
    }
    // Try the full name, then shorter suffixes, down to 2 labels.
    for keep in (2..=labels.len()).rev() {
        let apex: String = labels[labels.len() - keep..].join(".");
        let rel: Vec<&str> = if keep == labels.len() {
            Vec::new()
        } else {
            labels[..labels.len() - keep].to_vec()
        };
        match resolver(apex.clone()).await {
            Ok(Some(resolved)) => {
                let answers = select_answers(q, &resolved, &rel);
                if !answers.is_empty() {
                    debug!(apex = %apex, "dns: authoritative hit");
                }
                return (answers, RCODE_NOERROR);
            }
            Ok(None) => {
                // Not registered at this suffix: try the parent.
            }
            Err(e) => {
                // Local failure at a potentially-valid apex: SERVFAIL.
                warn!(apex = %apex, "dns: resolver error: {e}");
                return (Vec::new(), RCODE_SERVFAIL);
            }
        }
    }
    // No suffix registered anywhere: NXDOMAIN (also cached).
    (Vec::new(), RCODE_NXDOMAIN)
}

/// Is the qname even a Scone candidate? Strict charset + valid TLD
/// shape (cheap pre-filter; `DomainName` does the real validation on
/// the resolver side).
fn scone_candidate(name: &str) -> bool {
    name.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    }) && name.len() <= DomainName::MAX_TOTAL_LEN
        && name.split('.').count() >= 2
        && name.rsplit('.').next().is_some_and(|tld| {
            (1..=TldName::MAX_LEN).contains(&tld.len())
                && tld
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// Filters a resolved record set down to wire answers for the query.
/// A/AAAA queries also receive CNAMEs (alias following); the wildcard
/// label `*` matches any relative name when nothing better exists.
/// Unknown-to-wire types simply do not answer → NODATA.
fn select_answers(q: &Query, resolved: &Resolved, rel: &[&str]) -> Vec<(u16, u32, Vec<u8>)> {
    let _rel = rel; // scone record sets carry no per-record name: all match
    let addr_query = q.qtype == TYPE_A || q.qtype == TYPE_AAAA;
    resolved
        .rdata
        .iter()
        .filter(|(tc, _)| {
            q.qtype == TYPE_ANY || *tc == q.qtype || (addr_query && *tc == TYPE_CNAME)
        })
        .map(|(tc, rd)| (*tc, ANSWER_TTL, rd.clone()))
        .collect()
}

// ---- codec: read --------------------------------------------------------

struct Query {
    id: u16,
    rd: bool,
    name: String,
    qtype: u16,
}

fn parse_query(b: &[u8]) -> Option<Query> {
    if b.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([b[0], b[1]]);
    let flags = u16::from_be_bytes([b[2], b[3]]);
    if flags & 0x8000 != 0 {
        return None; // a response, not a query
    }
    if u16::from_be_bytes([b[4], b[5]]) != 1 {
        return None; // exactly one question
    }
    let mut i = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *b.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer: refused
        }
        let lab = b.get(i..i + len)?;
        i += len;
        if !(1..=63).contains(&lab.len())
            || !lab
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
        {
            return None;
        }
        labels.push(String::from_utf8(lab.to_vec()).ok()?.to_lowercase());
    }
    if labels.len() < 2 || labels.len() > 16 {
        return None;
    }
    let qtype = u16::from_be_bytes(b.get(i..i + 2)?.try_into().ok()?);
    let qclass = u16::from_be_bytes(b.get(i + 2..i + 4)?.try_into().ok()?);
    if qclass != CLASS_IN {
        return None;
    }
    Some(Query {
        id,
        rd: flags & 0x0100 != 0,
        name: labels.join("."),
        qtype,
    })
}

// ---- codec: write -------------------------------------------------------

/// Builds a response. `authoritative` controls the AA bit honestly:
/// only the chain-backed path sets it. If the full answer set does
/// not fit in `budget`, answers are truncated to the last one that
/// fits and the **TC bit is set** (RFC 1035 §4.2.1: the client knows
/// to retry over TCP / give up, instead of trusting a silently short
/// answer). `budget` = transport payload limit (512 for classic UDP,
/// [`MAX_TCP_RESPONSE`] over TCP).
fn build_response_bounded(
    q: &Query,
    original: &[u8],
    answers: &[(u16, u32, Vec<u8>)],
    rcode: u8,
    authoritative: bool,
    budget: usize,
) -> Vec<u8> {
    let question = question_bytes(original).unwrap_or(&[]);
    let mut out = Vec::with_capacity(12 + question.len() + 16 * answers.len());
    out.extend_from_slice(&q.id.to_be_bytes());
    // Assemble with a placeholder ANCOUNT first, then fix it up once
    // the truncation-decided count is known.
    out.extend_from_slice(&[0, 0]); // flags placeholder
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // ancount placeholder
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(question);
    let Some(question) = question_bytes(original) else {
        let flags = 0x8000 | (u16::from(q.rd) << 8) | 0x0080 | u16::from(rcode);
        out[2..4].copy_from_slice(&flags.to_be_bytes());
        return out;
    };
    let qname = &question[..question.len() - 4]; // without QTYPE/QCLASS
    let mut kept = 0usize;
    for (tc, ttl, rdata) in answers {
        // Owner + TYPE + CLASS + TTL + RDLEN + RDATA.
        let need = qname.len() + 10 + rdata.len();
        if out.len() + need > budget {
            break;
        }
        out.extend_from_slice(qname);
        out.extend_from_slice(&tc.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(u16::try_from(rdata.len()).unwrap_or(u16::MAX)).to_be_bytes());
        out.extend_from_slice(rdata);
        kept += 1;
    }
    let truncated = kept < answers.len();
    // QR | AA(only if authoritative) | RD(echo) | RA | TC(if truncated) | RCODE
    let mut flags = 0x8000 | (u16::from(q.rd) << 8) | 0x0080 | u16::from(rcode);
    if authoritative {
        flags |= 0x0400;
    }
    if truncated {
        flags |= 0x0200;
        warn!(
            kept,
            total = answers.len(),
            budget,
            "dns: response truncated (TC=1)"
        );
    }
    out[2..4].copy_from_slice(&flags.to_be_bytes());
    out[6..8].copy_from_slice(&(kept as u16).to_be_bytes());
    out
}

/// The raw question section (QNAME+QTYPE+QCLASS) of the original
/// datagram, for verbatim echo.
fn question_bytes(b: &[u8]) -> Option<&[u8]> {
    let mut i = 12;
    loop {
        let len = *b.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        i += len;
    }
    b.get(12..i + 4)
}

/// Uncompressed wire name.
fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        out.push(u8::try_from(label.len()).unwrap_or(0));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// RDATA of a supported record type (`None` = not encodable).
fn encode_rdata(r: &RecordData) -> Option<(u16, Vec<u8>)> {
    match r {
        RecordData::A(ip) => Some((TYPE_A, ip.octets().to_vec())),
        RecordData::Aaaa(ip) => Some((TYPE_AAAA, ip.octets().to_vec())),
        RecordData::Cname(n) | RecordData::Ns(n) => {
            let tc = if matches!(r, RecordData::Cname(_)) {
                TYPE_CNAME
            } else {
                TYPE_NS
            };
            Some((tc, encode_name(n.canonical())))
        }
        RecordData::Mx {
            preference,
            exchange,
        } => {
            let mut v = preference.to_be_bytes().to_vec();
            v.extend_from_slice(&encode_name(exchange.canonical()));
            Some((TYPE_MX, v))
        }
        RecordData::Txt(s) => Some((TYPE_TXT, char_strings(s))),
        RecordData::Unknown { type_code, data } => {
            Some((*type_code, data.clone())) // ≤ 4096 at decode
        }
    }
}

/// TXT character-strings: ≤255-byte chunks, each length-prefixed.
fn char_strings(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    if b.is_empty() {
        return vec![0];
    }
    b.chunks(255)
        .flat_map(|c| std::iter::once(c.len() as u8).chain(c.iter().copied()))
        .collect()
}

/// Public wrapper for the relay's `resolve_local`: one record →
/// `{type, ttl, rdata_hex}` (rdata in lowercase hex, ready for JSON).
#[must_use]
pub fn encode_rdata_pub(r: &RecordData) -> Option<serde_json::Value> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hex = |bytes: &[u8]| -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            out.push(HEX[usize::from(b >> 4)] as char);
            out.push(HEX[usize::from(b & 0x0f)] as char);
        }
        out
    };
    encode_rdata(r)
        .map(|(tc, rd)| serde_json::json!({ "type": tc, "ttl": ANSWER_TTL, "rdata": hex(&rd) }))
}

// ---- fallback -----------------------------------------------------------

/// Forwards a query and returns the reply **only if it matches the
/// query**: same transaction ID, QR=1, question section echoed
/// byte-for-byte (QNAME+QTYPE+QCLASS). The socket is `connect`ed to
/// the upstream so kernel filtering replaces address spoofing — an
/// off-path or late packet from another peer cannot be accepted.
/// Returns `None` on timeout / no candidate / mismatch (mismatches
/// do not fall through to the next upstream: the TXID check already
/// burned it).
async fn forward(query: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    let q_section = question_bytes(query)?; // QNAME+QTYPE+QCLASS
    let q_txid: [u8; 2] = [query[0], query[1]];
    for up in upstreams {
        let bind_addr = if up.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let Ok(sock) = UdpSocket::bind(bind_addr).await else {
            continue;
        };
        // Connected socket: recv() only accepts packets from `up`.
        if sock.connect(up).await.is_err() {
            continue;
        }
        if sock.send(query).await.is_err() {
            continue;
        }
        let mut buf = vec![0u8; MAX_PACKET_LEN];
        let Ok(Ok(n)) = tokio::time::timeout(FORWARD_TIMEOUT, sock.recv(&mut buf)).await else {
            warn!("dns: upstream {up} timed out");
            continue;
        };
        buf.truncate(n);
        if reply_matches(&buf, q_txid, q_section) {
            return Some(buf);
        }
        // Well-formed-but-wrong or garbage from the upstream: do not
        // try the next one on a TXID that was already burned.
        return None;
    }
    None
}

/// Does `resp` answer `txid` + `question` (verbatim echo)?
fn reply_matches(resp: &[u8], txid: [u8; 2], question: &[u8]) -> bool {
    resp.len() >= 12
        && resp[0] == txid[0]
        && resp[1] == txid[1]
        && resp[2] & 0x80 != 0 // QR=1: a response
        && resp.get(12..12 + question.len()) == Some(question)
}

/// One wire answer: `(type_code, ttl, rdata)`.
pub type WireAnswer = (u16, u32, Vec<u8>);

/// Extracts (answers, max-ttl) from a fallback reply to our question
/// (uncompressed names assumed; anything odd → no caching).
fn extract_answers(resp: &[u8], _q: &Query) -> Option<(Vec<WireAnswer>, u32)> {
    if resp.len() < 12 {
        return None;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let mut i = 12;
    while resp.get(i).is_some_and(|&b| b != 0) {
        i += 1 + resp[i] as usize;
    }
    i += 5; // root + QTYPE + QCLASS
    let mut out = Vec::with_capacity(ancount);
    let mut max_ttl = 0;
    for _ in 0..ancount {
        while resp.get(i).is_some_and(|&b| b != 0) {
            i += 1 + resp[i] as usize;
        }
        i += 1; // root
        let tc = u16::from_be_bytes([*resp.get(i)?, *resp.get(i + 1)?]);
        let ttl = u32::from_be_bytes(resp.get(i + 4..i + 8)?.try_into().ok()?);
        let rdlen = u16::from_be_bytes([*resp.get(i + 8)?, *resp.get(i + 9)?]) as usize;
        let rdata = resp.get(i + 10..i + 10 + rdlen)?.to_vec();
        out.push((tc, ttl.min(MAX_FALLBACK_TTL), rdata));
        max_ttl = max_ttl.max(ttl.min(MAX_FALLBACK_TTL));
        i += 10 + rdlen;
    }
    Some((out, max_ttl))
}

// ---- cache --------------------------------------------------------------

/// One cached answer (positive: answers + NOERROR; the rcode travels
/// with it so negative caching of NXDOMAIN works). `authoritative`
/// preserves the origin so a cache hit can set the AA bit honestly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    pub answers: Vec<(u16, u32, Vec<u8>)>,
    pub rcode: u8,
    pub ttl: u32,
    pub authoritative: bool,
}

/// Bounded (qname, qtype) cache. Eviction: FIFO of keys when over
/// capacity (simple, bounded, deterministic enough for a devnet
/// resolver; no LRU bookkeeping to keep the hot path allocation-free).
pub struct Cache {
    entries: HashMap<(String, u16), (CacheEntry, std::time::Instant)>,
    order: std::collections::VecDeque<(String, u16)>,
    capacity: usize,
    ttl_cap: u32,
}

impl Cache {
    /// Cache with the default bounds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_bounds(CACHE_CAPACITY, MAX_FALLBACK_TTL)
    }

    /// Cache with explicit bounds (tests).
    #[must_use]
    pub fn with_bounds(capacity: usize, ttl_cap: u32) -> Self {
        Self {
            entries: HashMap::new(),
            order: std::collections::VecDeque::new(),
            capacity: capacity.max(1),
            ttl_cap,
        }
    }

    /// Cached entry if present and not expired.
    #[must_use]
    pub fn get(&self, name: &str, qtype: u16) -> Option<CacheEntry> {
        let (entry, at) = self.entries.get(&(name.to_string(), qtype))?;
        if at.elapsed().as_secs() >= u64::from(entry.ttl.min(self.ttl_cap).max(1)) {
            return None;
        }
        Some(entry.clone())
    }

    /// Inserts/refreshes an entry, evicting oldest keys over capacity.
    pub fn put(&mut self, name: String, qtype: u16, entry: CacheEntry) {
        let key = (name.clone(), qtype);
        if !self.entries.contains_key(&key) {
            self.order.push_back(key.clone());
        }
        self.entries.insert(key, (entry, std::time::Instant::now()));
        while self.entries.len() > self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.entries.remove(&old);
            } else {
                break;
            }
        }
    }

    /// Number of live entries (diagnostics/tests).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds a DNS server config from raw strings (CLI path).
///
/// # Errors
///
/// [`NetworkError::InvalidRpc`] on an unparsable `addr:port`.
pub fn parse_upstreams(list: &[String]) -> Result<Vec<SocketAddr>> {
    list.iter()
        .map(|s| {
            s.parse::<SocketAddr>()
                .map_err(|_| NetworkError::InvalidRpc(format!("bad dns upstream: {s}")))
        })
        .collect()
}

// ---- tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn query(id: u16, rd: bool, name: &str, qtype: u16) -> Vec<u8> {
        let mut b = vec![0; 12];
        b[0..2].copy_from_slice(&id.to_be_bytes());
        b[2..4].copy_from_slice(&(u16::from(rd) << 8).to_be_bytes()); // RD bit = 0x0100
        b[4..6].copy_from_slice(&1u16.to_be_bytes());
        for label in name.split('.') {
            b.push(u8::try_from(label.len()).unwrap());
            b.extend_from_slice(label.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b
    }

    fn rcode_of(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[2], resp[3]]) & 0x000F
    }

    fn ancount_of(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[6], resp[7]])
    }

    fn answers_of(resp: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let ancount = ancount_of(resp) as usize;
        let mut i = 12;
        while resp[i] != 0 {
            i += 1 + resp[i] as usize;
        }
        i += 5;
        let mut out = Vec::new();
        for _ in 0..ancount {
            while resp[i] != 0 {
                i += 1 + resp[i] as usize;
            }
            i += 1;
            let tc = u16::from_be_bytes([resp[i], resp[i + 1]]);
            let rdlen = u16::from_be_bytes([resp[i + 8], resp[i + 9]]) as usize;
            out.push((tc, resp[i + 10..i + 10 + rdlen].to_vec()));
            i += 10 + rdlen;
        }
        out
    }

    fn mock_resolver(zones: Vec<(&str, Vec<RecordData>)>) -> Resolver {
        /// (apex, wire rdata pairs) of one mock zone.
        type MockZone = (String, Vec<(u16, Vec<u8>)>);
        let zones: Vec<MockZone> = zones
            .into_iter()
            .map(|(z, recs)| {
                let rdata = recs.iter().filter_map(encode_rdata).collect::<Vec<_>>();
                (z.to_string(), rdata)
            })
            .collect();
        Arc::new(move |domain| {
            let zones = zones.clone();
            Box::pin(async move {
                for (z, rdata) in &zones {
                    if *z == domain {
                        return Ok(Some(Resolved {
                            rdata: rdata.clone(),
                            registered: true,
                        }));
                    }
                }
                Ok(None)
            })
        })
    }

    #[test]
    fn parse_query_strict() {
        let q = parse_query(&query(0x1234, true, "www.foo.uip", TYPE_A)).unwrap();
        assert_eq!(q.id, 0x1234);
        assert!(q.rd);
        assert_eq!(q.name, "www.foo.uip");
        assert_eq!(q.qtype, TYPE_A);

        let mut r = query(1, false, "a.uip", TYPE_A);
        r[2] = 0x80; // QR set: a response
        assert!(parse_query(&r).is_none());
        assert!(parse_query(&[0u8; 8]).is_none());
        // compression pointer in qname
        let mut c = query(2, false, "a.uip", TYPE_A);
        c[12] = 0xc0;
        assert!(parse_query(&c).is_none());
    }

    /// AA must be set on authoritative answers, and stay set on a
    /// cache hit of an authoritative entry.
    #[tokio::test]
    async fn aa_bit_honest_across_paths() {
        let resolver = mock_resolver(vec![(
            "example.uip",
            vec![RecordData::A("192.0.2.10".parse().unwrap())],
        )]);
        let mut cache = Cache::new();
        // Authoritative path (fresh and cached): AA set.
        let resp = handle_packet(
            &resolver,
            &query(7, true, "example.uip", TYPE_A),
            &[],
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(resp[2] & 0x04, 0x04, "AA set (authoritative)");
        let cached = handle_packet(
            &resolver,
            &query(8, true, "example.uip", TYPE_A),
            &[],
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(cached[2] & 0x04, 0x04, "AA preserved on cache hit");
        // REFUSED (non-Scone name, no upstream): AA clear.
        let mut cache2 = Cache::new();
        let resp = handle_packet(
            &resolver,
            &query(9, false, "www.foo_bar", TYPE_A),
            &[],
            &mut cache2,
        )
        .await
        .unwrap();
        assert_eq!(resp[2] & 0x04, 0x00, "AA clear on REFUSED");
        // SERVFAIL (resolver error): AA clear.
        let failing: Resolver =
            Arc::new(|_name| Box::pin(async { Err("local rpc down".to_string()) }));
        let mut cache3 = Cache::new();
        let resp = handle_packet(
            &failing,
            &query(10, false, "example.uip", TYPE_A),
            &[],
            &mut cache3,
        )
        .await
        .unwrap();
        assert_eq!(rcode_of(&resp), 2, "SERVFAIL");
        assert_eq!(resp[2] & 0x04, 0x00, "AA clear on SERVFAIL");
        assert_eq!(cache3.len(), 0, "SERVFAIL not cached");
        // REFUSED not cached either.
        assert_eq!(cache2.len(), 0, "REFUSED not cached");
    }

    #[tokio::test]
    async fn authoritative_a_answer() {
        let resolver = mock_resolver(vec![(
            "example.uip",
            vec![RecordData::A("192.0.2.10".parse().unwrap())],
        )]);
        let mut cache = Cache::new();
        let resp = handle_packet(
            &resolver,
            &query(7, true, "example.uip", TYPE_A),
            &[],
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(rcode_of(&resp), 0);
        assert_eq!(ancount_of(&resp), 1);
        assert_eq!(answers_of(&resp)[0].0, TYPE_A);
        assert_eq!(answers_of(&resp)[0].1, vec![192, 0, 2, 10]);
        // flags: QR|AA|RD|RA
        assert_eq!(resp[2] & 0x04, 0x04, "AA set");
        // cached now
        assert_eq!(cache.len(), 1);
        let again = handle_packet(
            &resolver,
            &query(7, true, "example.uip", TYPE_A),
            &[],
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(ancount_of(&again), 1);
    }

    #[tokio::test]
    async fn subname_hits_apex_and_nodata() {
        let resolver = mock_resolver(vec![(
            "example.uip",
            vec![RecordData::A("192.0.2.1".parse().unwrap())],
        )]);
        let mut cache = Cache::new();
        // www.example.uip resolves through the example.uip apex.
        let resp = handle_packet(
            &resolver,
            &query(1, false, "www.example.uip", TYPE_A),
            &[],
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(ancount_of(&resp), 1);
        // AAAA asked, only A published → NODATA (NOERROR, 0 answers).
        let resp = handle_packet(
            &resolver,
            &query(2, false, "example.uip", TYPE_AAAA),
            &[],
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(rcode_of(&resp), 0);
        assert_eq!(ancount_of(&resp), 0);
    }

    #[tokio::test]
    async fn unknown_scone_name_is_nxdomain() {
        let resolver = mock_resolver(vec![("other.uip", vec![])]);
        let mut cache = Cache::new();
        let resp = handle_packet(
            &resolver,
            &query(3, false, "nope.example.uip", TYPE_A),
            &[],
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(rcode_of(&resp), 3, "NXDOMAIN");
        // negative caching: still NXDOMAIN from the cache.
        let resp2 = handle_packet(
            &resolver,
            &query(3, false, "nope.example.uip", TYPE_A),
            &[],
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(rcode_of(&resp2), 3);
    }

    #[tokio::test]
    async fn non_scone_name_refused_without_upstream() {
        let resolver = mock_resolver(vec![]);
        let mut cache = Cache::new();
        // `www.example`: TLD longer than 5 chars — structurally never
        // a Scone name → not authoritative → REFUSED with no upstream.
        let resp = handle_packet(
            &resolver,
            &query(4, false, "www.foo_bar", TYPE_A),
            &[],
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(
            rcode_of(&resp),
            u16::from(RCODE_REFUSED),
            "REFUSED without fallback"
        );
        // Contrast: `example.com` IS a valid Scone name shape → the
        // chain is authoritative → NXDOMAIN even without upstream.
        let resp = handle_packet(
            &resolver,
            &query(5, false, "example.com", TYPE_A),
            &[],
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(rcode_of(&resp), 3, "Scone-shaped name → NXDOMAIN");
    }

    #[tokio::test]
    async fn fallback_to_mock_upstream() {
        // A fake upstream that answers A 7.7.7.7 with TTL 120.
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            let (n, peer) = upstream.recv_from(&mut buf).await.unwrap();
            let mut resp = buf[..n].to_vec();
            resp[2] |= 0x80; // QR
            resp[7] = 1; // ANCOUNT = 1
            // answer: root name, A, IN, ttl 120, rdlen 4, 7.7.7.7
            resp.extend_from_slice(&[0]);
            resp.extend_from_slice(&TYPE_A.to_be_bytes());
            resp.extend_from_slice(&CLASS_IN.to_be_bytes());
            resp.extend_from_slice(&120u32.to_be_bytes());
            resp.extend_from_slice(&4u16.to_be_bytes());
            resp.extend_from_slice(&[7, 7, 7, 7]);
            upstream.send_to(&resp, peer).await.unwrap();
        });
        let resolver = mock_resolver(vec![]);
        let mut cache = Cache::new();
        let resp = handle_packet(
            &resolver,
            &query(9, true, "www.foo_bar", TYPE_A),
            &[up_addr],
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(rcode_of(&resp), 0);
        assert_eq!(answers_of(&resp)[0].1, vec![7, 7, 7, 7]);
        up.await.unwrap();
        // cached (clamped ttl ≤ MAX_FALLBACK_TTL).
        assert_eq!(cache.len(), 1);
        // Cached fallback answer: served without AA (not
        // authoritative — the chain never vouched for it).
        let cached = handle_packet(
            &resolver,
            &query(10, true, "www.foo_bar", TYPE_A),
            &[],
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(rcode_of(&cached), 0);
        assert_eq!(ancount_of(&cached), 1);
        assert_eq!(cached[2] & 0x04, 0x00, "AA clear on cached fallback");
    }

    /// An oversized answer set is cut at the last record that fits
    /// and the TC bit is set (honest truncation, RFC 1035 §4.2.1).
    #[tokio::test]
    async fn oversized_answers_truncated_with_tc() {
        // TXT records of 300 bytes each → ~316 bytes per answer;
        // 20 of them far exceed MAX_PACKET_LEN (4096).
        let big: Vec<RecordData> = (0..20)
            .map(|i| RecordData::Txt(format!("{i:03}").replace('0', "x").repeat(300)))
            .collect();
        let resolver = mock_resolver(vec![("big.uip", big)]);
        let mut cache = Cache::new();
        let resp = handle_packet(
            &resolver,
            &query(11, false, "big.uip", TYPE_TXT),
            &[],
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(rcode_of(&resp), 0);
        assert!(resp.len() <= MAX_PACKET_LEN, "fits the datagram bound");
        let an = ancount_of(&resp) as usize;
        assert!(an >= 1, "at least one answer kept");
        assert!(an < 20, "not all answers fit");
        assert_eq!(resp[2] & 0x02, 0x02, "TC set on truncation");
        assert_eq!(resp[2] & 0x04, 0x04, "still authoritative (AA)");
        // No truncation flag on a small answer set.
        let small = mock_resolver(vec![(
            "small.uip",
            vec![RecordData::A("192.0.2.1".parse().unwrap())],
        )]);
        let mut cache2 = Cache::new();
        let resp = handle_packet(
            &small,
            &query(12, false, "small.uip", TYPE_A),
            &[],
            &mut cache2,
        )
        .await
        .unwrap();
        assert_eq!(resp[2] & 0x02, 0x00, "TC clear when everything fits");
    }

    /// The fallback only accepts a reply that matches the query:
    /// TXID, QR and verbatim question echo. A wrong TXID or a
    /// different question → SERVFAIL, never a bogus answer.
    #[tokio::test]
    async fn upstream_reply_must_match_query() {
        // Upstream that echoes the query but with a WRONG TXID.
        let wrong_txid = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = wrong_txid.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, peer) = match wrong_txid.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let mut resp = buf[..n].to_vec();
                resp[0] ^= 0xFF; // wrong TXID
                resp[2] |= 0x80; // QR
                let _ = wrong_txid.send_to(&resp, peer).await;
            }
        });
        let resolver = mock_resolver(vec![]);
        let mut cache = Cache::new();
        let resp = handle_packet(
            &resolver,
            &query(21, true, "www.foo_bar", TYPE_A),
            &[addr],
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(rcode_of(&resp), 2, "mismatched reply → SERVFAIL");
        assert_eq!(cache.len(), 0, "nothing cached from a bogus reply");
        up.abort();

        // Upstream that answers a DIFFERENT question (same TXID).
        let other_q = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = other_q.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let (n, peer) = match other_q.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let mut resp = buf[..n].to_vec();
                resp[2] |= 0x80; // QR
                // Rewrite the question to evil.example.
                let mut q = vec![0u8; 12];
                q[0..2].copy_from_slice(&resp[0..2]);
                q[2..4].copy_from_slice(&resp[2..4]);
                q[4..6].copy_from_slice(&1u16.to_be_bytes());
                for label in "evil.example".split('.') {
                    q.push(u8::try_from(label.len()).unwrap());
                    q.extend_from_slice(label.as_bytes());
                }
                q.push(0);
                q.extend_from_slice(&TYPE_A.to_be_bytes());
                q.extend_from_slice(&CLASS_IN.to_be_bytes());
                let _ = other_q.send_to(&q, peer).await;
            }
        });
        let mut cache = Cache::new();
        let resp = handle_packet(
            &resolver,
            &query(22, true, "www.foo_bar", TYPE_A),
            &[addr],
            &mut cache,
        )
        .await
        .unwrap();
        assert_eq!(rcode_of(&resp), 2, "foreign question → SERVFAIL");
        assert_eq!(cache.len(), 0, "nothing cached");
        up.abort();
    }

    #[test]
    fn cache_is_bounded() {
        let mut cache = Cache::with_bounds(3, MAX_FALLBACK_TTL);
        for i in 0..5u16 {
            cache.put(
                format!("n{i}.uip"),
                TYPE_A,
                CacheEntry {
                    answers: vec![],
                    rcode: 0,
                    ttl: 60,
                    authoritative: true,
                },
            );
        }
        assert_eq!(cache.len(), 3, "bounded at capacity");
        assert!(cache.get("n0.uip", TYPE_A).is_none(), "oldest evicted");
        assert!(cache.get("n4.uip", TYPE_A).is_some());
    }

    #[test]
    fn txt_char_strings_chunked() {
        assert_eq!(char_strings("hello"), vec![5, b'h', b'e', b'l', b'l', b'o']);
        let long = "x".repeat(300);
        let cs = char_strings(&long);
        assert_eq!(cs[0], 255);
        assert_eq!(cs[256], 45);
        assert_eq!(cs.len(), 1 + 255 + 1 + 45);
    }

    #[test]
    fn upstreams_parsed_and_rejected() {
        let ok = parse_upstreams(&["1.1.1.1:53".into(), "[::1]:53".into()]).unwrap();
        assert_eq!(ok.len(), 2);
        assert!(parse_upstreams(&["not an addr".into()]).is_err());
    }

    // ---- M7b: TCP transport + per-transport budgets -----------------

    /// Builds the wire form of one TXT record (uncompressed owner).
    fn txt_rdata(s: &str) -> Vec<u8> {
        let mut rdata = Vec::new();
        for chunk in s.as_bytes().chunks(255) {
            rdata.push(u8::try_from(chunk.len()).unwrap());
            rdata.extend_from_slice(chunk);
        }
        rdata
    }

    /// A set whose encoded answers exceed the 512-o classic UDP
    /// payload but fit TCP: over UDP it is cut at the last fitting
    /// record with TC=1; over TCP (budget = MAX_TCP_RESPONSE) the
    /// full set is served, TC clear. RFC 7766 end to end.
    #[tokio::test]
    async fn udp_budget_truncates_tc_tcp_serves_full() {
        // 20 TXT answers of ~320 B each → ~6.4 KB total: > 512, < 65535.
        let big: Vec<RecordData> = (0..20).map(|_| RecordData::Txt("x".repeat(300))).collect();
        let resolver = mock_resolver(vec![("big.uip", big)]);
        let q = query(31, false, "big.uip", TYPE_TXT);

        // Fresh caches per transport (same entry would hit the cache).
        let mut udp_cache = Cache::new();
        let udp = handle_packet_transport(&resolver, &q, &[], &mut udp_cache, UDP_PAYLOAD_LIMIT)
            .await
            .unwrap();
        assert!(udp.len() <= UDP_PAYLOAD_LIMIT, "fits 512 B");
        assert!(ancount_of(&udp) >= 1 && (ancount_of(&udp) as usize) < 20);
        assert_eq!(udp[2] & 0x02, 0x02, "TC set on 512 B truncation");
        assert_eq!(udp[2] & 0x04, 0x04, "AA still set");

        let mut tcp_cache = Cache::new();
        let tcp = handle_packet_transport(&resolver, &q, &[], &mut tcp_cache, MAX_TCP_RESPONSE)
            .await
            .unwrap();
        assert_eq!(ancount_of(&tcp), 20, "TCP serves the full set");
        assert!(tcp.len() > UDP_PAYLOAD_LIMIT && tcp.len() <= MAX_TCP_RESPONSE);
        assert_eq!(tcp[2] & 0x02, 0x00, "TC clear over TCP");
        assert_eq!(tcp[2] & 0x04, 0x04, "AA over TCP");
        // Same TXID as the query.
        assert_eq!(&tcp[0..2], &q[0..2]);
    }

    /// Truncation on a cache hit too: the first (UDP) reply caches the
    /// full answer set; a second UDP query gets the cut version.
    #[tokio::test]
    async fn cached_answers_also_truncated_on_udp() {
        let big: Vec<RecordData> = (0..20).map(|_| RecordData::Txt("x".repeat(300))).collect();
        let resolver = mock_resolver(vec![("big.uip", big)]);
        let mut cache = Cache::new();
        let _ = handle_packet_transport(
            &resolver,
            &query(32, false, "big.uip", TYPE_TXT),
            &[],
            &mut cache,
            MAX_TCP_RESPONSE,
        )
        .await
        .unwrap();
        let cached = handle_packet_transport(
            &resolver,
            &query(33, false, "big.uip", TYPE_TXT),
            &[],
            &mut cache,
            UDP_PAYLOAD_LIMIT,
        )
        .await
        .unwrap();
        assert!(cached.len() <= UDP_PAYLOAD_LIMIT);
        assert_eq!(cached[2] & 0x02, 0x02, "TC on cached UDP truncation");
    }

    /// Sends one length-prefixed DNS query over TCP and reads the
    /// length-prefixed reply.
    async fn tcp_query(stream: &mut tokio::net::TcpStream, q: &[u8]) -> Option<Vec<u8>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut framed = (u16::try_from(q.len()).unwrap()).to_be_bytes().to_vec();
        framed.extend_from_slice(q);
        stream.write_all(&framed).await.ok()?;
        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr).await.ok()?;
        let len = u16::from_be_bytes(hdr) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).await.ok()?;
        Some(body)
    }

    /// `run_tcp` end to end against a mock resolver: a full (large)
    /// answer set is served in one TCP message, TC clear, while the
    /// same query over the UDP budget would be cut.
    #[tokio::test]
    async fn run_tcp_serves_oversized_answer() {
        let big: Vec<RecordData> = (0..20).map(|_| RecordData::Txt("x".repeat(300))).collect();
        let resolver = mock_resolver(vec![("big.uip", big)]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cache = Arc::new(tokio::sync::Mutex::new(Cache::new()));
        tokio::spawn(run_tcp(listener, resolver, Vec::new(), cache));

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let resp = tcp_query(&mut stream, &query(34, false, "big.uip", TYPE_TXT))
            .await
            .unwrap();
        assert_eq!(rcode_of(&resp), 0);
        assert_eq!(ancount_of(&resp), 20, "full set over TCP");
        assert_eq!(resp[2] & 0x02, 0x00, "TC clear");
        assert!(resp.len() > UDP_PAYLOAD_LIMIT);
    }

    /// Pipelining: two queries on one connection are both answered,
    /// in order.
    #[tokio::test]
    async fn run_tcp_pipelines_two_queries() {
        let resolver = mock_resolver(vec![(
            "example.uip",
            vec![RecordData::A("192.0.2.10".parse().unwrap())],
        )]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cache = Arc::new(tokio::sync::Mutex::new(Cache::new()));
        tokio::spawn(run_tcp(listener, resolver, Vec::new(), cache));

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let r1 = tcp_query(&mut stream, &query(35, false, "example.uip", TYPE_A))
            .await
            .unwrap();
        let r2 = tcp_query(&mut stream, &query(36, false, "example.uip", TYPE_AAAA))
            .await
            .unwrap();
        assert_eq!(rcode_of(&r1), 0);
        assert_eq!(ancount_of(&r1), 1);
        assert_eq!(&r1[0..2], &35u16.to_be_bytes(), "first reply = first txid");
        assert_eq!(rcode_of(&r2), 0, "NODATA is NOERROR");
        assert_eq!(ancount_of(&r2), 0);
        assert_eq!(
            &r2[0..2],
            &36u16.to_be_bytes(),
            "second reply = second txid"
        );
    }

    /// Bounds: an oversized length prefix (> MAX_TCP_QUERY) closes the
    /// connection without reading a body; a zero-length prefix too.
    #[tokio::test]
    async fn run_tcp_rejects_oversized_query() {
        let resolver = mock_resolver(vec![]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cache = Arc::new(tokio::sync::Mutex::new(Cache::new()));
        tokio::spawn(run_tcp(listener, resolver, Vec::new(), cache));

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Announce an oversized body: the server must close on the
        // header alone (nothing else is written, so the close is a
        // clean FIN the client observes as EOF).
        stream
            .write_all(&(MAX_TCP_QUERY as u16 + 1).to_be_bytes())
            .await
            .unwrap();
        stream.flush().await.unwrap();
        let mut leftover = [0u8; 8];
        let n = stream.read(&mut leftover).await.unwrap();
        assert_eq!(n, 0, "connection closed on oversized query");
    }

    /// Bounds: a client that connects and never sends anything is
    /// dropped after TCP_READ_TIMEOUT (the slot is freed — no
    /// unbounded accumulation). Timing-based: budget 2× the timeout.
    #[tokio::test]
    async fn run_tcp_drops_stalled_client() {
        let resolver = mock_resolver(vec![]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cache = Arc::new(tokio::sync::Mutex::new(Cache::new()));
        tokio::spawn(run_tcp(listener, resolver, Vec::new(), cache));

        use tokio::io::AsyncReadExt;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let start = std::time::Instant::now();
        let mut buf = [0u8; 8];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "server closed the idle connection");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= TCP_READ_TIMEOUT && elapsed < TCP_READ_TIMEOUT * 2,
            "closed by the read timeout (got {elapsed:?})"
        );
    }

    /// Garbage on an established TCP connection is answered with
    /// silence (no reply) but does not kill the session: a valid
    /// query on the same connection is still served.
    #[tokio::test]
    async fn run_tcp_garbage_then_valid_query() {
        let resolver = mock_resolver(vec![(
            "example.uip",
            vec![RecordData::A("192.0.2.10".parse().unwrap())],
        )]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let cache = Arc::new(tokio::sync::Mutex::new(Cache::new()));
        tokio::spawn(run_tcp(listener, resolver, Vec::new(), cache));

        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Garbage frame: a header claiming 12 bytes, then garbage
        // that parse_query refuses (QR set + garbage qname).
        let mut garbage = vec![0u8; 12];
        garbage[2] = 0x80; // QR set → refused by parse_query
        garbage[4..6].copy_from_slice(&1u16.to_be_bytes()); // qdcount 1
        garbage.extend_from_slice(&[9, b'x']); // invalid label len
        let mut framed = (u16::try_from(garbage.len()).unwrap())
            .to_be_bytes()
            .to_vec();
        framed.extend_from_slice(&garbage);
        stream.write_all(&framed).await.unwrap();
        // A valid query must still be answered on this connection.
        let resp = tcp_query(&mut stream, &query(38, false, "example.uip", TYPE_A))
            .await
            .unwrap();
        assert_eq!(rcode_of(&resp), 0);
        assert_eq!(ancount_of(&resp), 1);
    }

    /// A fallback reply larger than the UDP budget is re-encoded cut
    /// with TC=1 (the verbatim upstream bytes would not fit); over
    /// TCP the same exchange passes the reply through unchanged.
    #[tokio::test]
    async fn oversized_fallback_reply_truncated_on_udp() {
        // Mock upstream answering 3 big TXT records (~1 KB total).
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            let (n, peer) = upstream.recv_from(&mut buf).await.unwrap();
            let mut resp = buf[..n].to_vec();
            resp[2] |= 0x80; // QR
            resp[7] = 3; // ANCOUNT
            for _ in 0..3u8 {
                resp.push(0); // root name
                resp.extend_from_slice(&TYPE_TXT.to_be_bytes());
                resp.extend_from_slice(&CLASS_IN.to_be_bytes());
                resp.extend_from_slice(&120u32.to_be_bytes());
                let rdata = txt_rdata(&"x".repeat(300));
                resp.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
                resp.extend_from_slice(&rdata);
            }
            upstream.send_to(&resp, peer).await.unwrap();
        });
        let resolver = mock_resolver(vec![]);
        let q = query(39, true, "www.foo_bar", TYPE_TXT);

        let mut udp_cache = Cache::new();
        let udp =
            handle_packet_transport(&resolver, &q, &[up_addr], &mut udp_cache, UDP_PAYLOAD_LIMIT)
                .await
                .unwrap();
        assert_eq!(rcode_of(&udp), 0);
        assert!(udp.len() <= UDP_PAYLOAD_LIMIT, "re-encoded to fit 512 B");
        assert_eq!(udp[2] & 0x02, 0x02, "TC set on the cut fallback reply");
        assert_eq!(ancount_of(&udp) as usize, 1, "one record fits");
        up.await.unwrap();

        // Same upstream shape again (3 big records, ~1 KB reply) with
        // a TCP-sized budget: the verbatim reply passes through.
        let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let up_addr = upstream.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            let (n, peer) = upstream.recv_from(&mut buf).await.unwrap();
            let mut resp = buf[..n].to_vec();
            resp[2] |= 0x80;
            resp[7] = 3;
            for _ in 0..3u8 {
                resp.push(0);
                resp.extend_from_slice(&TYPE_TXT.to_be_bytes());
                resp.extend_from_slice(&CLASS_IN.to_be_bytes());
                resp.extend_from_slice(&120u32.to_be_bytes());
                let rdata = txt_rdata(&"y".repeat(300));
                resp.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
                resp.extend_from_slice(&rdata);
            }
            upstream.send_to(&resp, peer).await.unwrap();
        });
        let mut tcp_cache = Cache::new();
        let tcp = handle_packet_transport(
            &resolver,
            &query(40, true, "www.foo_bar", TYPE_TXT),
            &[up_addr],
            &mut tcp_cache,
            MAX_TCP_RESPONSE,
        )
        .await
        .unwrap();
        assert_eq!(rcode_of(&tcp), 0);
        assert_eq!(ancount_of(&tcp), 3, "verbatim reply kept (3 records)");
        assert!(tcp.len() > UDP_PAYLOAD_LIMIT, "verbatim reply kept");
        assert_eq!(tcp[2] & 0x02, 0x00, "no TC on TCP-sized fallback");
        up.await.unwrap();
    }
}
