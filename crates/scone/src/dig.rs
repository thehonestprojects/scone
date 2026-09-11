//! `scone dig …`: one real UDP DNS round trip against the
//! relay's DNS surface, answer rendered dig-style.

use crate::error::CliError;

/// Default UDP DNS server address for `scone dig`.
const DEFAULT_DNS_ADDR: &str = "127.0.0.1:5353";

/// QTYPE name → wire code.
fn qtype_code(name: &str) -> Option<u16> {
    match name.to_ascii_uppercase().as_str() {
        "A" => Some(1),
        "NS" => Some(2),
        "CNAME" => Some(5),
        "MX" => Some(15),
        "TXT" => Some(16),
        "AAAA" => Some(28),
        "ANY" => Some(255),
        _ => None,
    }
}

/// Runs `scone dig <name>`: one real UDP DNS round trip against the
/// relay's DNS surface, answer rendered dig-style.
pub(crate) fn run_dig(
    name: String,
    dns: Option<String>,
    qtype: String,
) -> Result<Vec<String>, CliError> {
    use std::net::UdpSocket as StdUdp;
    let addr_text = dns.unwrap_or_else(|| DEFAULT_DNS_ADDR.to_string());
    let server: std::net::SocketAddr = addr_text
        .parse()
        .map_err(|_| CliError::InvalidRpcAddr(addr_text.clone()))?;
    let qtc = qtype_code(&qtype)
        .ok_or_else(|| CliError::BadRecordFile(format!("unknown qtype {qtype:?}")))?;
    // Validate the name looks like a DNS name (labels 1..63).
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(CliError::BadRecordFile(format!("bad label in {name:?}")));
        }
    }
    // Build the query (lowercased wire labels).
    let mut query = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.trim_end_matches('.').split('.') {
        query.push(u8::try_from(label.len()).map_err(|_| CliError::BadRecordFile("label".into()))?);
        query.extend_from_slice(label.to_ascii_lowercase().as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtc.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes()); // IN

    let socket = StdUdp::bind(if server.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    })
    .map_err(|e| CliError::RelayUnreachable(e.to_string()))?;
    socket
        .send_to(&query, server)
        .map_err(|e| CliError::RelayUnreachable(e.to_string()))?;
    let mut buf = vec![0u8; 4096];
    let (n, _) = socket
        .recv_from(&mut buf)
        .map_err(|e| CliError::RelayUnreachable(e.to_string()))?;
    buf.truncate(n);
    if buf.len() < 12 || buf[0..2] != [0xab, 0xcd] {
        return Err(CliError::RelayError("malformed dns response".into()));
    }
    let rcode = buf[3] & 0x0f;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    let mut lines = vec![format!("status: {rcode}"), format!("answers: {ancount}")];
    // Walk the answers (uncompressed names).
    let mut i = 12;
    while i < buf.len() && buf[i] != 0 {
        i += 1 + usize::from(buf[i]);
    }
    i = (i + 5).min(buf.len());
    for _ in 0..ancount {
        while i < buf.len() && buf[i] != 0 {
            i += 1 + usize::from(buf[i]);
        }
        i += 1;
        if i + 10 > buf.len() {
            break;
        }
        let tc = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let ttl = u32::from_be_bytes(buf[i + 4..i + 8].try_into().unwrap_or([0; 4]));
        let rdlen = usize::from(u16::from_be_bytes([buf[i + 8], buf[i + 9]]));
        let rdata = buf.get(i + 10..i + 10 + rdlen).unwrap_or(&[]);
        lines.push(format!(
            "record: type {tc} ttl {ttl} rdata {}",
            rdata.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        i += 10 + rdlen;
    }
    Ok(lines)
}
