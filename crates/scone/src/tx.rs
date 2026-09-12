//! `scone tx …` (offline build/sign/verify) and the shared
//! transaction build/sign helpers used by `scone domain …`.

use scone_core::{
    AssignDomain, DomainId, DomainName, RegisterDomain, RenewDomain, RevokeTld, SetTldOpen,
    TransferTld, UpdateDomain,
};
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
                scone_core::Transaction::Slash(_) => "slash",
                scone_core::Transaction::RegisterTld(_) => "register-tld",
                scone_core::Transaction::TransferTld(_) => "transfer-tld",
                scone_core::Transaction::RevokeTld(_) => "revoke-tld",
                scone_core::Transaction::SetTldOpen(_) => "set-tld-open",
                scone_core::Transaction::AssignDomain(_) => "assign-domain",
                scone_core::Transaction::RenewDomain(_) => "renew-domain",
                scone_core::Transaction::TransferDomain(_) => "transfer-domain",
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
            network,
            name,
            domain_id: _,
            owner: _,
            timestamp,
            proof,
            public_key,
        } => scone_core::Transaction::RegisterDomain(RegisterDomain::register_domain_on(
            network,
            name,
            timestamp,
            proof,
            public_key,
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
        U::UpdateDomain {
            network,
            domain_id,
            owner: _,
            sequence,
            record_hash,
            public_key,
        } => scone_core::Transaction::UpdateDomain(UpdateDomain::update_domain_on(
            network,
            domain_id,
            sequence,
            record_hash,
            public_key,
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
        U::RegisterTld {
            network,
            name: tld_name,
            tld_id: _,
            owner: _,
            timestamp,
            proof,
            public_key,
        } => scone_core::Transaction::RegisterTld(RegisterTld::register_tld_on(
            network,
            tld_name,
            timestamp,
            proof,
            public_key,
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
        U::TransferTld {
            network,
            tld_id,
            owner: _,
            new_owner,
            public_key,
        } => scone_core::Transaction::TransferTld(TransferTld::transfer_tld_on(
            network,
            tld_id,
            new_owner,
            public_key,
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
        U::RevokeTld {
            network,
            tld_id,
            owner: _,
            public_key,
        } => scone_core::Transaction::RevokeTld(RevokeTld::revoke_tld_on(
            network,
            tld_id,
            public_key,
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
        U::SetTldOpen {
            network,
            tld_id,
            owner: _,
            open,
            public_key,
        } => scone_core::Transaction::SetTldOpen(SetTldOpen::set_tld_open_on(
            network,
            tld_id,
            open,
            public_key,
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
        U::AssignDomain {
            network,
            name,
            domain_id: _,
            owner: _,
            assignee,
            public_key,
        } => scone_core::Transaction::AssignDomain(AssignDomain::assign_domain_on(
            network,
            name,
            assignee,
            public_key,
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
        U::RenewDomain {
            network,
            domain_id,
            owner: _,
            valid_until,
            public_key,
        } => scone_core::Transaction::RenewDomain(RenewDomain::renew_domain_on(
            network,
            domain_id,
            valid_until,
            public_key,
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
        U::TransferDomain {
            network,
            domain_id,
            owner: _,
            new_owner,
            public_key,
        } => {
            scone_core::Transaction::TransferDomain(scone_core::TransferDomain::transfer_domain_on(
                network,
                domain_id,
                new_owner,
                public_key,
                scone_crypto::Signature::from_bytes([0; 64]),
            ))
        }
        U::Slash {
            network,
            offender,
            evidence_a,
            sig_a,
            evidence_b,
            sig_b,
            public_key,
        } => scone_core::Transaction::Slash(scone_core::SlashTx::slash_on(
            network,
            offender,
            evidence_a,
            sig_a,
            evidence_b,
            sig_b,
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
                // M8b: registrations require a PoW; without an explicit
                // proof, mine one at the testnet difficulty (symbolic —
                // milliseconds).
                None => crate::pow::mine_domain_proof(scone_core::TESTNET, &name),
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
                // M8b: mine at the testnet difficulty (symbolic).
                None => crate::pow::mine_tld_proof(scone_core::TESTNET, &tld),
            };
            let tx =
                scone_core::Transaction::RegisterTld(scone_core::RegisterTld::register_tld_signed(
                    tld_name.clone(),
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
        // M8b family (offline build; no PoW — none of these is a
        // registration).
        TxKind::SetTldOpen { tld, open } => {
            let tld_name = scone_core::TldName::new(&tld).map_err(CliError::Domain)?;
            let tx = scone_core::Transaction::SetTldOpen(SetTldOpen::set_tld_open_signed(
                scone_core::TldId::from_tld(&tld_name),
                open,
                build_key.public_key(),
                placeholder,
            ));
            Ok((tx, format!("unsigned set-tld-open: {tld} (open={open})")))
        }
        TxKind::AssignDomain { name, assignee } => {
            let domain = DomainName::new(&name).map_err(CliError::Domain)?;
            let bytes = hex_decode("assignee", &assignee)?;
            if bytes.len() != 32 {
                return Err(CliError::InvalidHashLength(bytes.len() * 2));
            }
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&bytes);
            let tx = scone_core::Transaction::AssignDomain(AssignDomain::assign_domain_signed(
                domain.clone(),
                scone_core::OwnerId::from_bytes(raw),
                build_key.public_key(),
                placeholder,
            ));
            Ok((
                tx,
                format!("unsigned assign-domain: {}", domain.canonical()),
            ))
        }
        TxKind::RenewDomain { name, valid_until } => {
            let domain = DomainName::new(&name).map_err(CliError::Domain)?;
            let tx = scone_core::Transaction::RenewDomain(RenewDomain::renew_domain_signed(
                DomainId::from_name(&domain),
                valid_until,
                build_key.public_key(),
                placeholder,
            ));
            Ok((
                tx,
                format!(
                    "unsigned renew-domain: {} (valid_until {valid_until})",
                    domain.canonical()
                ),
            ))
        }
        TxKind::TransferTld { tld, new_owner } => {
            let tld_name = scone_core::TldName::new(&tld).map_err(CliError::Domain)?;
            let bytes = hex_decode("new owner", &new_owner)?;
            if bytes.len() != 32 {
                return Err(CliError::InvalidHashLength(bytes.len() * 2));
            }
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&bytes);
            let tx = scone_core::Transaction::TransferTld(TransferTld::transfer_tld_signed(
                scone_core::TldId::from_tld(&tld_name),
                scone_core::OwnerId::from_bytes(raw),
                build_key.public_key(),
                placeholder,
            ));
            Ok((tx, format!("unsigned transfer-tld: {tld}")))
        }
        TxKind::RevokeTld { tld } => {
            let tld_name = scone_core::TldName::new(&tld).map_err(CliError::Domain)?;
            let tx = scone_core::Transaction::RevokeTld(RevokeTld::revoke_tld_signed(
                scone_core::TldId::from_tld(&tld_name),
                build_key.public_key(),
                placeholder,
            ));
            Ok((tx, format!("unsigned revoke-tld: {tld}")))
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
                t.name.clone(),
                t.timestamp,
                t.proof.clone(),
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            ))
        }
        // M8a family: rebind keeps every carried field, only the
        // signer identity is recomputed.
        scone_core::Transaction::TransferTld(t) => {
            scone_core::Transaction::TransferTld(TransferTld::transfer_tld_signed(
                t.tld_id,
                t.new_owner,
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            ))
        }
        scone_core::Transaction::RevokeTld(t) => scone_core::Transaction::RevokeTld(
            RevokeTld::revoke_tld_signed(t.tld_id, sk.public_key(), Signature::from_bytes([0; 64])),
        ),
        scone_core::Transaction::SetTldOpen(t) => {
            scone_core::Transaction::SetTldOpen(SetTldOpen::set_tld_open_signed(
                t.tld_id,
                t.open,
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            ))
        }
        scone_core::Transaction::AssignDomain(a) => {
            scone_core::Transaction::AssignDomain(AssignDomain::assign_domain_signed(
                a.name.clone(),
                a.assignee,
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            ))
        }
        scone_core::Transaction::TransferDomain(t) => scone_core::Transaction::TransferDomain(
            scone_core::TransferDomain::transfer_domain_signed(
                t.domain_id,
                t.new_owner,
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            ),
        ),
        scone_core::Transaction::RenewDomain(r) => {
            scone_core::Transaction::RenewDomain(RenewDomain::renew_domain_signed(
                r.domain_id,
                r.valid_until,
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            ))
        }
        scone_core::Transaction::Slash(x) => {
            scone_core::Transaction::Slash(scone_core::SlashTx::slash_on(
                x.network,
                x.offender,
                x.evidence_a.clone(),
                x.sig_a,
                x.evidence_b.clone(),
                x.sig_b,
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
        scone_core::Transaction::TransferTld(mut t) => {
            t.signature = signature;
            scone_core::Transaction::TransferTld(t)
        }
        scone_core::Transaction::RevokeTld(mut t) => {
            t.signature = signature;
            scone_core::Transaction::RevokeTld(t)
        }
        scone_core::Transaction::SetTldOpen(mut t) => {
            t.signature = signature;
            scone_core::Transaction::SetTldOpen(t)
        }
        scone_core::Transaction::AssignDomain(mut a) => {
            a.signature = signature;
            scone_core::Transaction::AssignDomain(a)
        }
        scone_core::Transaction::RenewDomain(mut r) => {
            r.signature = signature;
            scone_core::Transaction::RenewDomain(r)
        }
        scone_core::Transaction::TransferDomain(mut t) => {
            t.signature = signature;
            scone_core::Transaction::TransferDomain(t)
        }
        scone_core::Transaction::Slash(mut x) => {
            x.signature = signature;
            scone_core::Transaction::Slash(x)
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
    signed_register_domain_tx_on(scone_core::TESTNET, sk, domain, timestamp)
}

/// [`signed_register_domain_tx`] for an explicit network (M8b): the
/// registration PoW is mined at THAT network's difficulty (symbolic
/// on testnet — milliseconds; real on mainnet).
pub(crate) fn signed_register_domain_tx_on(
    network: scone_core::NetworkParams,
    sk: &SigningKey,
    domain: &DomainName,
    timestamp: u64,
) -> Result<scone_core::Transaction, CliError> {
    let proof = crate::pow::mine_domain_proof(network, domain.canonical());
    let unsigned = scone_core::Transaction::RegisterDomain(RegisterDomain::register_domain_on(
        network.network_id,
        domain.clone(),
        timestamp,
        proof,
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
