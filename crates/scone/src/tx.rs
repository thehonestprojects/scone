//! `scone tx …` (offline build/sign/verify) and the shared
//! transaction build/sign helpers used by `scone domain …`.

use scone_core::{DomainId, DomainName, RegisterDomain, UpdateDomain};
use scone_crypto::{Signature, SigningKey};

use crate::cli::{TxCommand, TxKind};
use crate::error::CliError;
use crate::identity::open_identity;
use crate::util::{hex_decode, hex_lower};

/// Dispatches `scone tx …`.
pub(crate) fn run_tx(command: TxCommand) -> Result<Vec<String>, CliError> {
    match command {
        TxCommand::Build { kind } => {
            let (tx, describe) = build_unsigned(kind)?;
            let payload =
                scone_protocol::signing_payload(&tx).map_err(CliError::MalformedTransaction)?;
            Ok(vec![
                describe,
                format!("signing payload: {}", hex_lower(&payload)),
            ])
        }
        TxCommand::Sign {
            tx,
            identity,
            dir,
            passphrase_env,
        } => {
            // Input may be either the raw signing payload (output of
            // `tx build`) or a full transaction hex; both carry the
            // tx fields, the payload just lacks... actually the
            // payload IS prefix+tx-minus-signature. Decode strategy:
            // try transaction first, then payload.
            let bytes = hex_decode("transaction", &tx)?;
            let unsigned = decode_tx_or_payload(&bytes)?;
            let sk = open_identity(&identity, dir.as_deref(), passphrase_env.as_deref())?;
            // Rebind the transaction to this identity: owner and key
            // are recomputed from the signing key (never trusted),
            // then the canonical payload is signed.
            let rebound = rebind(&unsigned, &sk);
            let payload = scone_protocol::signing_payload(&rebound)
                .map_err(CliError::MalformedTransaction)?;
            let signature = sk.sign(&payload);
            let signed = attach_signature(rebound, signature);
            let encoded =
                scone_protocol::encode_to_vec(&signed).map_err(CliError::MalformedTransaction)?;
            Ok(vec![
                format!("signed by identity '{identity}'"),
                format!("transaction: {}", hex_lower(&encoded)),
            ])
        }
        TxCommand::Verify { tx } => {
            let bytes = hex_decode("transaction", &tx)?;
            let decoded = scone_protocol::decode_complete::<scone_core::Transaction>(&bytes)
                .map_err(CliError::MalformedTransaction)?;
            scone_blockchain::validate_transaction(&decoded)
                .map_err(CliError::InvalidTransaction)?;
            let kind = match &decoded {
                scone_core::Transaction::RegisterDomain(r) => {
                    return Ok(vec![
                        "kind: register".to_string(),
                        format!("domain: {}", r.name.canonical()),
                        format!("owner: {}", hex_lower(decoded.owner().as_bytes())),
                        "signature: valid".to_string(),
                    ]);
                }
                scone_core::Transaction::UpdateDomain(_) => "update",
                scone_core::Transaction::RegisterTld(_) => "register-tld",
            };
            Ok(vec![
                format!("kind: {kind}"),
                format!("owner: {}", hex_lower(decoded.owner().as_bytes())),
                "signature: valid".to_string(),
            ])
        }
    }
}

/// Decodes either a full transaction or a signing payload (output of
/// `scone tx build`: `"SCONE-TX-SIG-V1" || unsigned tx`) into the
/// unsigned transaction it describes.
fn decode_tx_or_payload(bytes: &[u8]) -> Result<scone_core::Transaction, CliError> {
    // Try a complete transaction first.
    if let Ok(tx) = scone_protocol::decode_complete::<scone_core::Transaction>(bytes) {
        return Ok(tx);
    }
    // Then a signing payload: strip the prefix and decode the
    // unsigned encoding.
    if let Some(rest) = bytes.strip_prefix(scone_protocol::TX_SIG_PREFIX)
        && let Ok(unsigned) =
            scone_protocol::decode_complete::<scone_protocol::UnsignedTransaction>(rest)
    {
        return Ok(unsigned_into_transaction(unsigned));
    }
    Err(CliError::MalformedTransaction(
        scone_protocol::ProtocolError::Truncated,
    ))
}

/// Converts an [`UnsignedTransaction`] into a placeholder-signed
/// [`scone_core::Transaction`].
fn unsigned_into_transaction(
    unsigned: scone_protocol::UnsignedTransaction,
) -> scone_core::Transaction {
    use scone_core::{RegisterDomain, RegisterTld, UpdateDomain};
    use scone_protocol::UnsignedTransaction as U;
    match unsigned {
        U::RegisterDomain {
            name,
            domain_id: _,
            owner: _,
            timestamp,
            proof,
            public_key,
        } => scone_core::Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
            name,
            timestamp,
            proof,
            public_key,
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
        U::UpdateDomain {
            domain_id,
            owner: _,
            sequence,
            record_hash,
            public_key,
        } => scone_core::Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
            domain_id,
            sequence,
            record_hash,
            public_key,
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
        U::RegisterTld {
            tld_id,
            owner: _,
            timestamp,
            proof,
            public_key,
        } => scone_core::Transaction::RegisterTld(RegisterTld::register_tld_signed(
            tld_id,
            timestamp,
            proof,
            public_key,
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
    }
}

/// Builds an unsigned (placeholder-signature) transaction from CLI
/// args; returns it with a human description line.
fn build_unsigned(kind: TxKind) -> Result<(scone_core::Transaction, String), CliError> {
    use scone_core::{Proof, RecordHash, RegisterDomain, UpdateDomain};
    use scone_crypto::Signature;
    let placeholder = Signature::from_bytes([0; 64]);
    // Any valid key works here: the payload to sign does not include
    // owner/key binding choices of the eventual signer... except it
    // DOES include the public_key field, so `build` uses a fixed
    // derived-from-seed key and `sign` rebinds to the real identity.
    let build_key = SigningKey::from_bytes([0x42; 32]);
    match kind {
        TxKind::RegisterDomain {
            name,
            timestamp,
            proof_hex,
        } => {
            let domain = DomainName::new(&name).map_err(CliError::Domain)?;
            let proof = match proof_hex {
                Some(hex) => Proof::from_bytes(hex_decode("proof", &hex)?),
                None => Proof::from_bytes(Vec::new()),
            };
            let tx =
                scone_core::Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
                    domain.clone(),
                    timestamp,
                    proof,
                    build_key.public_key(),
                    placeholder,
                ));
            Ok((
                tx,
                format!(
                    "unsigned register: {} (timestamp {timestamp})",
                    domain.canonical()
                ),
            ))
        }
        TxKind::RegisterTld {
            tld,
            timestamp,
            proof_hex,
        } => {
            let tld_name = scone_core::TldName::new(&tld).map_err(CliError::Domain)?;
            let proof = match proof_hex {
                Some(hex) => Proof::from_bytes(hex_decode("proof", &hex)?),
                None => Proof::from_bytes(Vec::new()),
            };
            let tx =
                scone_core::Transaction::RegisterTld(scone_core::RegisterTld::register_tld_signed(
                    scone_core::TldId::from_tld(&tld_name),
                    timestamp,
                    proof,
                    build_key.public_key(),
                    placeholder,
                ));
            Ok((
                tx,
                format!("unsigned register-tld: {tld} (timestamp {timestamp})"),
            ))
        }
        TxKind::UpdateDomain {
            name,
            sequence,
            record_hash,
        } => {
            let domain = DomainName::new(&name).map_err(CliError::Domain)?;
            let hash_bytes = hex_decode("record hash", &record_hash)?;
            if hash_bytes.len() != 32 {
                return Err(CliError::InvalidHashLength(hash_bytes.len() * 2));
            }
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&hash_bytes);
            let tx = scone_core::Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
                DomainId::from_name(&domain),
                sequence,
                RecordHash::from_bytes(raw),
                build_key.public_key(),
                placeholder,
            ));
            Ok((
                tx,
                format!(
                    "unsigned update: {} (sequence {sequence})",
                    domain.canonical()
                ),
            ))
        }
    }
}

/// Rebinds a transaction to `sk`: owner and public key are recomputed
/// from the signing key — the values carried by the input are never
/// trusted.
fn rebind(tx: &scone_core::Transaction, sk: &SigningKey) -> scone_core::Transaction {
    match tx {
        scone_core::Transaction::RegisterDomain(r) => {
            scone_core::Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
                r.name.clone(),
                r.timestamp,
                r.proof.clone(),
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            ))
        }
        scone_core::Transaction::UpdateDomain(u) => {
            scone_core::Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
                u.domain_id,
                u.sequence,
                u.record_hash,
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            ))
        }
        scone_core::Transaction::RegisterTld(t) => {
            scone_core::Transaction::RegisterTld(scone_core::RegisterTld::register_tld_signed(
                t.tld_id,
                t.timestamp,
                t.proof.clone(),
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            ))
        }
    }
}

/// Attaches `signature` to an unsigned (placeholder) transaction.
fn attach_signature(
    tx: scone_core::Transaction,
    signature: scone_crypto::Signature,
) -> scone_core::Transaction {
    match tx {
        scone_core::Transaction::RegisterDomain(mut r) => {
            r.signature = signature;
            scone_core::Transaction::RegisterDomain(r)
        }
        scone_core::Transaction::UpdateDomain(mut u) => {
            u.signature = signature;
            scone_core::Transaction::UpdateDomain(u)
        }
        scone_core::Transaction::RegisterTld(mut t) => {
            t.signature = signature;
            scone_core::Transaction::RegisterTld(t)
        }
    }
}

/// Signs an unsigned (placeholder-signature) transaction with `sk`
/// over its canonical payload. Owner/public key of the input are
/// already bound to `sk` by construction (the caller builds with
/// `sk.public_key()`).
fn sign_tx_with(
    unsigned: scone_core::Transaction,
    sk: &SigningKey,
) -> Result<scone_core::Transaction, CliError> {
    let payload =
        scone_protocol::signing_payload(&unsigned).map_err(CliError::MalformedTransaction)?;
    let signature = sk.sign(&payload);
    Ok(attach_signature(unsigned, signature))
}

/// Canonical hex of a signed transaction.
pub(crate) fn tx_hex(tx: &scone_core::Transaction) -> Result<String, CliError> {
    Ok(hex_lower(
        &scone_protocol::encode_to_vec(tx).map_err(CliError::MalformedTransaction)?,
    ))
}

/// Builds and signs a `RegisterDomain` for `domain` with `sk`.
pub(crate) fn signed_register_domain_tx(
    sk: &SigningKey,
    domain: &DomainName,
    timestamp: u64,
) -> Result<scone_core::Transaction, CliError> {
    let unsigned = scone_core::Transaction::RegisterDomain(RegisterDomain::register_domain_signed(
        domain.clone(),
        timestamp,
        scone_core::Proof::from_bytes(Vec::new()),
        sk.public_key(),
        Signature::from_bytes([0; 64]),
    ));
    sign_tx_with(unsigned, sk)
}

/// Builds and signs an `UpdateDomain` committing `record_hash` at
/// `sequence` for `domain` with `sk`.
pub(crate) fn signed_update_domain_tx(
    sk: &SigningKey,
    domain: &DomainName,
    sequence: u64,
    record_hash: scone_core::RecordHash,
) -> Result<scone_core::Transaction, CliError> {
    let unsigned = scone_core::Transaction::UpdateDomain(UpdateDomain::update_domain_signed(
        DomainId::from_name(domain),
        sequence,
        record_hash,
        sk.public_key(),
        Signature::from_bytes([0; 64]),
    ));
    sign_tx_with(unsigned, sk)
}
