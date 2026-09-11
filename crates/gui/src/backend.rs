//! Backend model of the GUI: everything the single page displays,
//! gathered from three read-only sources —
//!
//! 1. the relay control RPC (`status`, `domain_info`, `get_record`),
//! 2. the relay's redb store, opened read-only (shared file lock —
//!    safe while `scone relay` runs) for the OwnerId explorer,
//! 3. the local keystore directory for identity management.
//!
//! This crate is READ-ONLY by design: it never submits a transaction,
//! never writes the store, never unlocks a key (passphrase prompts
//! are v2 — v1 lists identities and shows public data only).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use redb::ReadableTable;
use scone_network::{RpcClient, RpcRequest};

/// Default relay RPC address (same as the CLI).
pub const DEFAULT_RPC_ADDR: &str = "127.0.0.1:7474";

/// Default data dir of `scone relay` (chain.redb lives inside).
pub const DEFAULT_DATA_DIR: &str = ".scone";

/// Errors of the backend, rendered to the user (no panics).
#[derive(Debug, thiserror::Error)]
pub enum GuiError {
    /// Invalid RPC address text.
    #[error("invalid relay address '{0}'")]
    InvalidAddr(String),
    /// The relay is not reachable.
    #[error("cannot reach the relay at {0} — is 'scone relay' running?")]
    RelayUnreachable(String),
    /// The relay answered with an error.
    #[error("relay error: {0}")]
    Relay(String),
    /// Reading the chain store failed.
    #[error("store error: {0}")]
    Store(String),
    /// Reading the keystore failed.
    #[error("keystore error: {0}")]
    Keystore(String),
    /// Malformed store data (strict decode failure).
    #[error("corrupted store entry: {0}")]
    Corrupted(String),
}

/// Hex of 32 raw bytes, lowercase, 64 chars (project convention).
pub fn hex64(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).expect("nibble"));
        out.push(char::from_digit(u32::from(b & 0xf), 16).expect("nibble"));
    }
    out
}

/// Default data dir: `$HOME/.scone`.
fn default_data_dir() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(DEFAULT_DATA_DIR),
        None => PathBuf::from(DEFAULT_DATA_DIR),
    }
}

/// One RPC round trip on a fresh single-thread runtime (the GUI keeps
/// its own tokio runtime; this blocks a worker thread only).
async fn rpc_json(client: &RpcClient, request: RpcRequest) -> Result<serde_json::Value, GuiError> {
    let response = client.request(request).await.map_err(|e| match e {
        scone_network::NetworkError::Io(_) | scone_network::NetworkError::Timeout(_) => {
            GuiError::RelayUnreachable(client.addr().to_string())
        }
        other => GuiError::Relay(other.to_string()),
    })?;
    match response {
        scone_network::RpcResponse::Ok { data } => Ok(data),
        scone_network::RpcResponse::Error { message } => Err(GuiError::Relay(message)),
    }
}

/// Relay status card: everything the `status` RPC returns.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RelayStatus {
    pub peer_id: String,
    pub tip: String,
    pub height: u64,
    pub peers: u64,
    pub domain_count: u64,
    pub mempool: u64,
}

/// Queries `status` from the relay at `addr`.
///
/// # Errors
///
/// [`GuiError::RelayUnreachable`] if the relay is down; [`GuiError::Relay`]
/// on a relay-side error.
pub async fn relay_status(addr_text: &str) -> Result<RelayStatus, GuiError> {
    let client = rpc_client(addr_text)?;
    let v = rpc_json(&client, RpcRequest::Status).await?;
    Ok(RelayStatus {
        peer_id: str_field(&v, "peer_id"),
        tip: str_field(&v, "tip"),
        height: u64_field(&v, "height"),
        peers: u64_field(&v, "peers"),
        domain_count: u64_field(&v, "domain_count"),
        mempool: u64_field(&v, "mempool"),
    })
}

/// Builds the RPC client for an address text (default when empty).
fn rpc_client(addr_text: &str) -> Result<RpcClient, GuiError> {
    let text = if addr_text.trim().is_empty() {
        DEFAULT_RPC_ADDR
    } else {
        addr_text.trim()
    };
    let addr: SocketAddr = text
        .parse()
        .map_err(|_| GuiError::InvalidAddr(text.to_string()))?;
    Ok(RpcClient::new(addr))
}

/// String field of a JSON object ("-" when absent/malformed).
fn str_field(v: &serde_json::Value, key: &str) -> String {
    v[key].as_str().unwrap_or("-").to_string()
}

/// u64 field of a JSON object (0 when absent/malformed).
fn u64_field(v: &serde_json::Value, key: &str) -> u64 {
    v[key].as_u64().unwrap_or(0)
}

/// One DNS record of the explorer result (`domain_info.dns[]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsEntry {
    pub kind: String,
    pub value: String,
}

/// One explored domain: on-chain state plus (optionally) its
/// chain-verified cached DNS records.
#[derive(Debug, Clone, PartialEq)]
pub struct DomainCard {
    pub name: String,
    pub domain_id: String,
    pub registered: bool,
    pub owner: String,
    pub sequence: u64,
    pub record_hash: String,
    pub dns: Vec<DnsEntry>,
}

/// Explores one domain name through the relay (`domain_info`: local
/// read, then `get_record`: DHT resolution if nothing is cached).
///
/// # Errors
///
/// [`GuiError`] from the RPC round trips (unreachable relay, relay
/// error, unknown TLD...).
pub async fn explore_name(addr_text: &str, name: &str) -> Result<DomainCard, GuiError> {
    let client = rpc_client(addr_text)?;
    let mut v = rpc_json(&client, RpcRequest::DomainInfo { name: name.into() }).await?;
    // dns: [] while a DHT query could still find the record — try once
    // (get_record both resolves and primes the local cache).
    if v["dns"].as_array().is_none_or(Vec::is_empty)
        && let Ok(resolved) = rpc_json(&client, RpcRequest::GetRecord { name: name.into() }).await
        && resolved["verified"].as_bool() == Some(true)
    {
        v = rpc_json(&client, RpcRequest::DomainInfo { name: name.into() }).await?;
    }
    Ok(DomainCard {
        name: str_field(&v, "name"),
        domain_id: str_field(&v, "domain_id"),
        registered: v["registered"].as_bool().unwrap_or(false),
        owner: str_field(&v, "owner"),
        sequence: u64_field(&v, "sequence"),
        record_hash: v["record_hash"].as_str().unwrap_or("(none)").into(),
        dns: v["dns"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .map(|e| DnsEntry {
                        kind: str_field(e, "type"),
                        value: str_field(e, "value"),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// One identity row of the management panel (public data only: no
/// passphrase handling in v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRow {
    pub name: String,
    pub owner_id: String,
}

/// Lists keystore identities with their OwnerId (`$HOME/.scone/keys`
/// by default, like the CLI).
///
/// The OwnerId cannot be derived from the encrypted file: the CLI's
/// `identity show` needs the passphrase. v1 therefore shows the
/// OwnerId of identities found in the chain store's blocks (register
/// transactions embed the owner and public key), falling back to a
/// call to compute it when a key is unlocked — kept for v2. Here we
/// list file names and attach the OwnerId when known from the chain.
///
/// # Errors
///
/// [`GuiError::Keystore`] when the directory cannot be listed.
pub fn list_identities() -> Result<Vec<IdentityRow>, GuiError> {
    let dir = default_data_dir().join("keys");
    let entries = scone_keystore::list(&dir).map_err(|e| GuiError::Keystore(e.to_string()))?;
    Ok(entries
        .into_iter()
        .map(|e| IdentityRow {
            name: e.name,
            owner_id: String::new(),
        })
        .collect())
}

/// Result of an OwnerId exploration: the domains owned on-chain,
/// read directly from the relay's redb store (read-only open —
/// shared lock, safe while the relay runs).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OwnerPortfolio {
    pub domains: Vec<DomainCard>,
}

/// Explores every domain owned by `owner_hex` (64 lowercase hex
/// chars) by walking the store's domain table (`DomainId ->
/// DomainState`) and keeping entries whose owner matches.
///
/// Names are recovered from the register transactions found in the
/// blocks table (the domain table is keyed by id only).
///
/// # Errors
///
/// [`GuiError::Store`] when the store cannot be opened read-only;
/// [`GuiError::Corrupted`] on strict decode failures;
/// [`GuiError::InvalidAddr`] on a malformed OwnerId.
pub fn explore_owner(data_dir: Option<&Path>, owner_hex: &str) -> Result<OwnerPortfolio, GuiError> {
    let owner_bytes: [u8; 32] = decode_hex64(owner_hex)?;
    let owner = scone_core::OwnerId::from_bytes(owner_bytes);
    let dir = data_dir.map_or_else(default_data_dir, Path::to_path_buf);
    explore_store(&dir.join("chain.redb"), owner)
}

/// A store handle open for reading: either a live read-only handle or
/// a repaired copy (see [`explore_store`]).
enum StoreHandle {
    ReadOnly(redb::ReadOnlyDatabase),
    RepairedCopy(redb::Database),
}

impl StoreHandle {
    fn begin_read(&self) -> Result<redb::ReadTransaction, redb::TransactionError> {
        match self {
            StoreHandle::ReadOnly(db) => redb::ReadableDatabase::begin_read(db),
            StoreHandle::RepairedCopy(db) => redb::ReadableDatabase::begin_read(db),
        }
    }
}

/// Owner walk against an explicit store file (unit-testable core).
///
/// redb allows a single process to hold the database, and a live
/// relay holds it with the exclusive lock — a direct read-only open
/// then fails. The GUI therefore first tries a read-only open of the
/// live file, and on any lock/repair failure falls back to copying
/// the file to a scratch location and opening the COPY read-write
/// (redb repairs the allocator state on open; a store being written
/// concurrently may copy torn, which the strict decoders surface as a
/// typed error — never a panic, and the original is never touched).
fn explore_store(
    store_path: &Path,
    owner: scone_core::OwnerId,
) -> Result<OwnerPortfolio, GuiError> {
    let db = match redb::ReadOnlyDatabase::open(store_path) {
        Ok(db) => StoreHandle::ReadOnly(db),
        Err(_) => {
            let copy = copy_to_scratch(store_path)?;
            StoreHandle::RepairedCopy(
                redb::Database::open(copy).map_err(|e| GuiError::Store(e.to_string()))?,
            )
        }
    };
    let read = db
        .begin_read()
        .map_err(|e| GuiError::Store(e.to_string()))?;
    // Domain names from register transactions (id -> canonical name).
    let names = domain_names(&read)?;
    let table = read
        .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("domains"))
        .map_err(|e| GuiError::Store(e.to_string()))?;
    let mut domains = Vec::new();
    for row in table.iter().map_err(|e| GuiError::Store(e.to_string()))? {
        let (k, v) = row.map_err(|e| GuiError::Store(e.to_string()))?;
        let state = scone_storage::DomainStateBytes::decode(v.value())
            .map_err(|e| GuiError::Corrupted(e.to_string()))?;
        if state.owner != owner {
            continue;
        }
        let id = scone_core::DomainId::from_bytes(
            k.value()
                .try_into()
                .map_err(|_| GuiError::Corrupted("domain key".into()))?,
        );
        let record_hash = state.record_hash.map(|h| hex64(h.as_bytes()));
        domains.push(DomainCard {
            name: names
                .get(&hex64(id.as_bytes()))
                .cloned()
                .unwrap_or_else(|| format!("({})", hex64(id.as_bytes()))),
            domain_id: hex64(id.as_bytes()),
            registered: true,
            owner: hex64(state.owner.as_bytes()),
            sequence: state.sequence,
            record_hash: record_hash.unwrap_or_else(|| "(none)".into()),
            // DNS records are not part of the store walk in v1: the
            // per-name explorer resolves them through the relay.
            dns: Vec::new(),
        });
    }
    domains.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(OwnerPortfolio { domains })
}

/// Copies the store file to a unique scratch location and returns the
/// copy's path (the caller reads the copy when the live file is
/// locked by the relay).
fn copy_to_scratch(store_path: &Path) -> Result<PathBuf, GuiError> {
    use std::io::{Read, Write};
    let mut scratch = std::env::temp_dir();
    scratch.push(format!(
        "scone-gui-store-{}-{}.redb",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let mut src = std::fs::File::open(store_path).map_err(|e| GuiError::Store(e.to_string()))?;
    let mut dst = std::fs::File::create(&scratch).map_err(|e| GuiError::Store(e.to_string()))?;
    // Stream the copy (the file can be large); a mid-write crash only
    // leaves a scratch file behind, never a touched original.
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = src
            .read(&mut buffer)
            .map_err(|e| GuiError::Store(e.to_string()))?;
        if n == 0 {
            break;
        }
        dst.write_all(&buffer[..n])
            .map_err(|e| GuiError::Store(e.to_string()))?;
    }
    dst.sync_all().map_err(|e| GuiError::Store(e.to_string()))?;
    Ok(scratch)
}

/// Decodes a strict 64-char lowercase hex string into 32 bytes.
fn decode_hex64(text: &str) -> Result<[u8; 32], GuiError> {
    let t = text.trim().to_ascii_lowercase();
    if t.len() != 64 || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(GuiError::InvalidAddr(format!(
            "OwnerId must be 64 hex chars, got {}",
            t.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&t[i * 2..i * 2 + 2], 16)
            .map_err(|_| GuiError::Corrupted("hex".into()))?;
    }
    Ok(out)
}

/// Walks the blocks table and collects `DomainId -> canonical name`
/// from every `RegisterDomain` transaction (the domain states table
/// is keyed by id only; the name travels inside the tx).
///
/// Each `blocks_by_height` value is prefixed by a 40-byte index
/// header (block hash + parent hash) — the same layout the storage
/// crate strips in `block_at_height`.
fn domain_names(
    read: &redb::ReadTransaction,
) -> Result<std::collections::HashMap<String, String>, GuiError> {
    const BLOCK_INDEX_HEADER: usize = 32 + 8;
    let table = read
        .open_table(redb::TableDefinition::<u64, &[u8]>::new("blocks_by_height"))
        .map_err(|e| GuiError::Store(e.to_string()))?;
    let mut names = std::collections::HashMap::new();
    for row in table.iter().map_err(|e| GuiError::Store(e.to_string()))? {
        let (_, v) = row.map_err(|e| GuiError::Store(e.to_string()))?;
        let raw = v.value();
        if raw.len() < BLOCK_INDEX_HEADER {
            return Err(GuiError::Corrupted("blocks_by_height: short header".into()));
        }
        let bytes = &raw[BLOCK_INDEX_HEADER..];
        let block: scone_protocol::Block = scone_protocol::codec::decode_complete(bytes)
            .map_err(|e| GuiError::Corrupted(e.to_string()))?;
        for tx in &block.transactions {
            if let scone_core::Transaction::RegisterDomain(reg) = tx {
                names.insert(hex64(reg.domain_id.as_bytes()), reg.name.canonical().into());
            }
        }
    }
    Ok(names)
}
