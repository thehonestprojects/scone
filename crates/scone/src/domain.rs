//! `scone domain …` (rich exploration, one-command
//! register/update) and `scone record put|get …`, plus the
//! strict DNS record file parser they share.

use std::path::Path;

use scone_core::{DomainId, DomainName};

use crate::cli::{DomainCommand, RecordCommand};
use crate::error::CliError;
use crate::identity::{open_identity, owner_id_of};
use crate::rpc::{rpc_call, rpc_client, rpc_json};
use crate::tx::{signed_register_tx, signed_update_tx, tx_hex};
use crate::util::{hex_lower, unix_now};

/// How long `domain register|update` waits for devnet confirmation.
const CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Polling period while waiting for chain confirmation.
const CONFIRM_POLL: std::time::Duration = std::time::Duration::from_millis(300);

/// Waits until the on-chain sequence of `name` reaches `at_least`,
/// then returns the confirming `lookup` data.
fn wait_for_sequence(
    client: &scone_network::RpcClient,
    name: &str,
    at_least: u64,
    what: &str,
) -> Result<serde_json::Value, CliError> {
    let deadline = std::time::Instant::now() + CONFIRM_TIMEOUT;
    loop {
        let info = rpc_json(
            client,
            scone_network::RpcRequest::Lookup { name: name.into() },
        )?;
        if info["sequence"].as_u64().is_some_and(|s| s >= at_least) {
            return Ok(info);
        }
        if std::time::Instant::now() >= deadline {
            return Err(CliError::RelayError(format!(
                "timeout waiting for {what} (chain sequence still < {at_least})"
            )));
        }
        std::thread::sleep(CONFIRM_POLL);
    }
}

/// Parses one DNS record file line into a [`scone_core::RecordData`].
///
/// Supported forms (M5): `A <ipv4>`, `AAAA <ipv6>`, `CNAME <name>`,
/// `NS <name>`, `MX <preference> <name>`, `TXT <free text>`. Empty
/// lines and `#` comments are skipped.
///
/// M5 fix-up (F3): the parser is STRICT. A line with trailing fields
/// after a fixed-arity record (`A 1.2.3.4 extra`) is an error, not a
/// silently-truncated record — a typo'd file must never commit a
/// half-parsed record set on-chain. An empty TXT is rejected too
/// (it cannot round-trip the canonical format, which delimits the
/// text by length).
fn parse_record_line(line_no: usize, line: &str) -> Result<scone_core::RecordData, CliError> {
    let bad = |msg: String| CliError::BadRecordFile(format!("line {line_no}: {msg}"));
    let mut fields = line.split_ascii_whitespace();
    let Some(kind) = fields.next() else {
        return Err(bad("empty line".into()));
    };
    // After a fixed-arity record, nothing may remain on the line.
    let no_trailing = |fields: &mut std::str::SplitAsciiWhitespace<'_>| {
        if fields.next().is_some() {
            Err(bad(format!(
                "{kind} record has trailing fields — one record per line"
            )))
        } else {
            Ok(())
        }
    };
    match kind.to_ascii_uppercase().as_str() {
        "A" => {
            let ip = fields
                .next()
                .ok_or_else(|| bad("A needs an IPv4 address".into()))?;
            let ip: std::net::Ipv4Addr = ip
                .parse()
                .map_err(|_| bad(format!("'{ip}' is not an IPv4 address")))?;
            no_trailing(&mut fields)?;
            Ok(scone_core::RecordData::A(ip))
        }
        "AAAA" => {
            let ip = fields
                .next()
                .ok_or_else(|| bad("AAAA needs an IPv6 address".into()))?;
            let ip: std::net::Ipv6Addr = ip
                .parse()
                .map_err(|_| bad(format!("'{ip}' is not an IPv6 address")))?;
            no_trailing(&mut fields)?;
            Ok(scone_core::RecordData::Aaaa(ip))
        }
        "CNAME" | "NS" => {
            let raw = fields
                .next()
                .ok_or_else(|| bad("needs a domain name".into()))?;
            let name = DomainName::new(raw).map_err(|e| bad(format!("'{raw}': {e}")))?;
            no_trailing(&mut fields)?;
            if kind.eq_ignore_ascii_case("CNAME") {
                Ok(scone_core::RecordData::Cname(name))
            } else {
                Ok(scone_core::RecordData::Ns(name))
            }
        }
        "MX" => {
            let pref = fields
                .next()
                .ok_or_else(|| bad("MX needs a preference".into()))?;
            let pref: u16 = pref
                .parse()
                .map_err(|_| bad(format!("'{pref}' is not a u16 preference")))?;
            let raw = fields
                .next()
                .ok_or_else(|| bad("MX needs an exchange domain name".into()))?;
            let exchange = DomainName::new(raw).map_err(|e| bad(format!("'{raw}': {e}")))?;
            no_trailing(&mut fields)?;
            Ok(scone_core::RecordData::Mx {
                preference: pref,
                exchange,
            })
        }
        "TXT" => {
            // Free-form: everything after the keyword, whitespace
            // collapsed to a single space (canonical form).
            let text = line
                .split_once(char::is_whitespace)
                .map(|(_, rest)| rest.split_ascii_whitespace().collect::<Vec<_>>().join(" "))
                .unwrap_or_default();
            if text.is_empty() {
                return Err(bad("TXT needs a non-empty text value".into()));
            }
            Ok(scone_core::RecordData::Txt(text))
        }
        other => Err(bad(format!("unknown record type '{other}'"))),
    }
}

/// Reads and parses a DNS record file (M5): one record per line,
/// `#` comments, blank lines skipped. The file is the COMPLETE new
/// record set (updates replace, they do not merge).
pub(crate) fn read_record_file(path: &Path) -> Result<Vec<scone_core::RecordData>, CliError> {
    let text = std::fs::read_to_string(path).map_err(CliError::FileRead)?;
    let mut records = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        records.push(parse_record_line(index + 1, line)?);
    }
    if records.is_empty() {
        return Err(CliError::BadRecordFile(
            "no records (empty set is invalid)".into(),
        ));
    }
    if records.len() > scone_protocol::limits::MAX_RECORDS_PER_SET {
        return Err(CliError::BadRecordFile(format!(
            "too many records (max {})",
            scone_protocol::limits::MAX_RECORDS_PER_SET
        )));
    }
    // Duplicate entries would be rejected by the canonical encoder;
    // fail here with a file-oriented message instead.
    let mut canonical = Vec::with_capacity(records.len());
    for record in &records {
        let encoded =
            scone_protocol::encode_to_vec(record).map_err(CliError::MalformedTransaction)?;
        canonical.push(encoded);
    }
    canonical.sort();
    if canonical.windows(2).any(|w| w[0] == w[1]) {
        return Err(CliError::BadRecordFile("duplicate record".into()));
    }
    Ok(records)
}

/// Dispatches `scone domain …` (M5).
pub(crate) fn run_domain(command: DomainCommand) -> Result<Vec<String>, CliError> {
    match command {
        DomainCommand::Register {
            name,
            identity,
            dir,
            passphrase_env,
            rpc,
        } => {
            let domain = DomainName::new(&name).map_err(CliError::Domain)?;
            let client = rpc_client(rpc.as_deref())?;
            // Fail fast on a taken name (the relay re-checks).
            let info = rpc_json(
                &client,
                scone_network::RpcRequest::Lookup { name: name.clone() },
            )?;
            if info["registered"].as_bool() == Some(true) {
                return Err(CliError::DomainState(format!(
                    "domain '{}' is already registered",
                    domain.canonical()
                )));
            }
            let sk = open_identity(&identity, dir.as_deref(), passphrase_env.as_deref())?;
            let tx = signed_register_tx(&sk, &domain, unix_now())?;
            let hex_string = tx_hex(&tx)?;
            let submitted = rpc_json(
                &client,
                scone_network::RpcRequest::SubmitTx { tx_hex: hex_string },
            )?;
            let txid = submitted["txid"].as_str().unwrap_or("?").to_string();
            let confirmed = wait_for_sequence(&client, &name, 0, "registration")?;
            // M5 fix-up (F2): the confirmed owner MUST be the one this
            // command signed with. Between the fail-fast precheck and
            // the confirmation, another racer's Register can land
            // first; our own tx then gets evicted from the mempool.
            // Reporting success here would be a lie — the domain
            // belongs to someone else.
            let owner = hex_lower(owner_id_of(&sk).as_bytes());
            if confirmed["owner"].as_str() != Some(owner.as_str()) {
                return Err(CliError::DomainState(format!(
                    "domain '{}' was registered by a different owner (lost the race)",
                    domain.canonical()
                )));
            }
            Ok(vec![
                format!(
                    "registering {} (owner {})",
                    domain.canonical(),
                    hex_lower(owner_id_of(&sk).as_bytes())
                ),
                format!("txid: {txid}"),
                format!(
                    "confirmed: height {}, sequence {}",
                    confirmed["height"], confirmed["sequence"]
                ),
            ])
        }
        DomainCommand::Update {
            name,
            file,
            identity,
            dir,
            passphrase_env,
            rpc,
        } => {
            let domain = DomainName::new(&name).map_err(CliError::Domain)?;
            let records = read_record_file(&file)?;
            let client = rpc_client(rpc.as_deref())?;

            let info = rpc_json(
                &client,
                scone_network::RpcRequest::Lookup { name: name.clone() },
            )?;
            if info["registered"].as_bool() != Some(true) {
                return Err(CliError::DomainState(format!(
                    "domain '{}' is not registered — register it first",
                    domain.canonical()
                )));
            }
            let current = info["sequence"].as_u64().ok_or_else(|| {
                CliError::RelayError("relay returned no sequence for a registered domain".into())
            })?;
            let Some(next) = current.checked_add(1) else {
                return Err(CliError::DomainState(
                    "domain sequence exhausted (u64::MAX)".into(),
                ));
            };

            let sk = open_identity(&identity, dir.as_deref(), passphrase_env.as_deref())?;
            // Client-side ownership check (the relay enforces it too).
            let owner = hex_lower(owner_id_of(&sk).as_bytes());
            if info["owner"].as_str() != Some(owner.as_str()) {
                return Err(CliError::DomainState(format!(
                    "identity '{identity}' is not the owner of '{}'",
                    domain.canonical()
                )));
            }

            // The record file is the single source of truth: the hash
            // committed on-chain is derived from THESE records at the
            // NEXT sequence — signer and verifier agree by construction.
            let dns = scone_core::DnsRecord {
                domain_id: DomainId::from_name(&domain),
                sequence: next,
                expiration: 0,
                records,
            };
            let record_hash = scone_protocol::record_hash(&dns);

            let tx = signed_update_tx(&sk, &domain, next, record_hash)?;
            let hex_string = tx_hex(&tx)?;
            let submitted = rpc_json(
                &client,
                scone_network::RpcRequest::SubmitTx { tx_hex: hex_string },
            )?;
            let txid = submitted["txid"].as_str().unwrap_or("?").to_string();

            // Wait until the chain carries the new sequence, then
            // publish the signed record (put_record verifies against
            // the chain state — publishing earlier would be rejected).
            wait_for_sequence(&client, &name, next, "update confirmation")?;
            let canonical =
                scone_protocol::encode_to_vec(&dns).map_err(CliError::MalformedTransaction)?;
            let signed = scone_core::SignedDnsRecord {
                record: dns,
                owner: owner_id_of(&sk),
                signature: scone_core::Signature::from_bytes(
                    sk.sign(&canonical).to_bytes().to_vec(),
                ),
            };
            let record_hex = hex_lower(
                &scone_protocol::encode_to_vec(&signed).map_err(CliError::MalformedTransaction)?,
            );
            let published = rpc_json(&client, scone_network::RpcRequest::PutRecord { record_hex })?;
            // M5 fix-up (F4): the publication must concern THE
            // requested domain. The relay echoes the DomainId of the
            // record it verified and stored; anything else (relay
            // bug, mismatched answer) is reported, never assumed.
            let expected_id = format!("{}", DomainId::from_name(&domain));
            if published["published"].as_str() != Some(expected_id.as_str()) {
                return Err(CliError::RelayError(format!(
                    "record published for the wrong domain (expected {expected_id})"
                )));
            }
            Ok(vec![
                format!("updating {} → sequence {next}", domain.canonical()),
                format!("txid: {txid}"),
                format!("record hash: {}", hex_lower(record_hash.as_bytes())),
                "record published in the DHT".to_string(),
            ])
        }
        DomainCommand::Info { name, rpc } => {
            let client = rpc_client(rpc.as_deref())?;
            let info = rpc_json(&client, scone_network::RpcRequest::DomainInfo { name })?;
            let get = |key: &str| info[key].as_str().unwrap_or("-").to_string();
            let mut lines = vec![
                format!("name: {}", get("name")),
                format!("domain_id: {}", get("domain_id")),
                format!(
                    "registered: {}",
                    info["registered"].as_bool().unwrap_or(false)
                ),
            ];
            if info["registered"].as_bool() == Some(true) {
                lines.push(format!("owner: {}", get("owner")));
                lines.push(format!(
                    "sequence: {}",
                    info["sequence"].as_u64().unwrap_or(0)
                ));
                lines.push(format!(
                    "record_hash: {}",
                    info["record_hash"].as_str().unwrap_or("(none)")
                ));
                lines.push("dns:".to_string());
                let dns = info["dns"].as_array().cloned().unwrap_or_default();
                if dns.is_empty() {
                    lines.push("  (no chain-valid record cached locally)".to_string());
                }
                for entry in dns {
                    let kind = entry["type"].as_str().unwrap_or("?");
                    let value = entry["value"].as_str().unwrap_or("");
                    if let Some(pref) = entry["preference"].as_u64() {
                        lines.push(format!("  {kind} {pref} {value}"));
                    } else {
                        lines.push(format!("  {kind} {value}"));
                    }
                }
            }
            Ok(lines)
        }
    }
}

/// Runs `scone record put|get …`.
pub(crate) fn run_record(command: RecordCommand) -> Result<Vec<String>, CliError> {
    match command {
        RecordCommand::Put { name, file, rpc } => {
            let record_hex = std::fs::read_to_string(file)
                .map_err(CliError::FileRead)?
                .trim()
                .to_string();
            // Validate the name early (fail before hitting the relay).
            DomainName::new(&name).map_err(CliError::Domain)?;
            let client = rpc_client(rpc.as_deref())?;
            rpc_call(
                &client,
                scone_network::RpcRequest::PutRecord {
                    record_hex: record_hex.to_lowercase(),
                },
            )
        }
        RecordCommand::Get { name, rpc } => {
            let client = rpc_client(rpc.as_deref())?;
            rpc_call(&client, scone_network::RpcRequest::GetRecord { name })
        }
    }
}
