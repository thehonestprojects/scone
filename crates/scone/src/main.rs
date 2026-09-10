//! Scone command-line binary.
//!
//! Argument parsing uses clap (derive API); all logic lives in the pure
//! [`run`] function so it can be unit tested without spawning a
//! process; [`main`] only wires arguments, output streams and the exit
//! code. No path through the CLI panics on user input: every failure is
//! a typed error printed to stderr with a non-zero exit code.
//!
//! Keystore layout: identities live as `<dir>/<name>.sconekey` files
//! (default `<dir>` = `$HOME/.scone/keys`), one encrypted Ed25519 seed
//! per file — see `scone-keystore` and `/docs/development/keystore.md`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use scone_core::{DomainId, DomainName, OwnerId, PublicKeyRef, Register, Update};
use scone_crypto::{Signature, SigningKey};
use tracing::{debug, info};
use zeroize::Zeroize;

/// Extension of keystore files (re-exported for path building).
const KEYFILE_EXT: &str = "sconekey";

/// Default keystore directory: `$HOME/.scone/keys`.
fn default_keystore_dir() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".scone").join("keys"),
        // No HOME: fall back to a relative path; operations on it will
        // fail with a clean I/O error rather than a panic.
        None => PathBuf::from(".scone").join("keys"),
    }
}

/// Keystore directory selected by the flags (default: `$HOME/.scone/keys`).
fn keystore_dir(dir: Option<&Path>) -> PathBuf {
    dir.map(|d| d.to_path_buf())
        .unwrap_or_else(default_keystore_dir)
}

/// Path of the keyfile of identity `name` inside `dir`.
///
/// `name` MUST have been validated by [`validate_identity_name`] first:
/// this function blindly joins, so an unchecked `../` component would
/// escape `dir`.
fn keyfile_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.{KEYFILE_EXT}"))
}

/// Validates a local identity name before any path is built from it.
///
/// The name becomes a filename inside the keystore directory; anything
/// that could be interpreted as a path component (`/`, `\`, NUL) or a
/// directory reference (`.`, `..`, empty) is rejected, as are names
/// that would not round-trip through [`scone_keystore::list`] (leading
/// dot, `.sconekey` extension). Windows separators (`\`) are rejected
/// on every platform so a name is portable and cannot traverse on any
/// target.
fn validate_identity_name(name: &str) -> Result<(), CliError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.starts_with('.')
        || name.ends_with(&format!(".{KEYFILE_EXT}"))
    {
        return Err(CliError::InvalidIdentityName(name.to_string()));
    }
    Ok(())
}

/// Top-level `scone` command.
#[derive(Debug, Parser)]
#[command(
    name = "scone",
    version,
    about = "Scone: decentralized DNS command-line tool",
    disable_help_subcommand = true
)]
struct Cli {
    /// Increase logging verbosity (-v: info, -vv: debug, -vvv:
    /// trace). Without -v, commands log at WARN, except `scone
    /// relay` which stays at INFO (a daemon must log its activity).
    /// RUST_LOG, when set, overrides these defaults entirely.
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

/// Subcommands of `scone`.
#[derive(Debug, Subcommand)]
enum Command {
    /// Show the DomainId of a domain name.
    Show {
        /// Domain name (e.g. `example.uip`).
        name: String,
    },

    /// Run a relay node (foreground daemon; logs to stderr).
    Relay {
        /// Data directory (chain database lives here).
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// P2P listen multiaddr (default `/ip4/0.0.0.0/udp/0/quic-v1`).
        #[arg(long)]
        listen: Option<String>,

        /// Bootstrap multiaddr (repeatable); must end with
        /// `/p2p/<peer-id>`.
        #[arg(long = "bootstrap")]
        bootstrap: Vec<String>,

        /// Control RPC bind address (default 127.0.0.1:7474). Two
        /// relays on one machine need distinct ports.
        #[arg(long)]
        rpc: Option<String>,

        /// UDP DNS server bind address (M6); e.g. `127.0.0.1:5353`.
        /// Disabled by default.
        #[arg(long)]
        dns: Option<String>,

        /// Recursive DNS fallback upstream (repeatable, `addr:port`);
        /// only used when `--dns` is set. Names outside the Scone
        /// charset are forwarded there, otherwise REFUSED.
        #[arg(long = "dns-upstream")]
        dns_upstream: Vec<String>,
    },

    /// Relay status (tip, height, peers, domains).
    Status {
        /// RPC address of the relay (default 127.0.0.1:7474).
        #[arg(long)]
        rpc: Option<String>,
    },

    /// Submit a signed transaction (hex) to a relay.
    Submit {
        #[command(subcommand)]
        command: SubmitCommand,
    },

    /// Look up the on-chain state of a domain name.
    Lookup {
        /// Domain name.
        name: String,

        /// RPC address of the relay (default 127.0.0.1:7474).
        #[arg(long)]
        rpc: Option<String>,
    },

    /// Rich domain exploration and one-command register/update (M5).
    Domain {
        #[command(subcommand)]
        command: DomainCommand,
    },

    /// Publish / resolve signed DNS records in the DHT.
    Record {
        #[command(subcommand)]
        command: RecordCommand,
    },

    /// Query the relay's UDP DNS server (M6 acceptance helper).
    Dig {
        /// Domain name to resolve.
        name: String,

        /// UDP address of the DNS server (default 127.0.0.1:5353).
        #[arg(long)]
        dns: Option<String>,

        /// Query type: A, AAAA, TXT, MX, NS, CNAME or ANY (default A).
        #[arg(long, default_value = "A")]
        qtype: String,
    },

    /// Manage local signing identities.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },

    /// Offline transaction tools (build, sign, verify) — testing and
    /// debugging helpers for the signed transaction format v2.
    Tx {
        #[command(subcommand)]
        command: TxCommand,
    },
}

/// Subcommands of `scone submit`.
#[derive(Debug, Subcommand)]
enum SubmitCommand {
    /// Submit a signed transaction given as canonical hex.
    Tx {
        /// Hex of the complete signed transaction.
        #[arg(long = "hex")]
        hex: String,

        /// RPC address of the relay (default 127.0.0.1:7474).
        #[arg(long)]
        rpc: Option<String>,
    },
}

/// Subcommands of `scone domain` (M5).
#[derive(Debug, Subcommand)]
enum DomainCommand {
    /// Claim a domain: build, sign and submit a `Register`
    /// transaction in one command.
    Register {
        /// Domain name to register (e.g. `example.uip`).
        name: String,

        /// Local name of the signing identity.
        #[arg(long)]
        identity: String,

        /// Keystore directory (default: `$HOME/.scone/keys`).
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Read the passphrase from this environment variable instead
        /// of prompting.
        #[arg(long = "passphrase-env", value_name = "VAR")]
        passphrase_env: Option<String>,

        /// RPC address of the relay (default 127.0.0.1:7474).
        #[arg(long)]
        rpc: Option<String>,
    },

    /// Publish a new version of a domain's DNS data: reads the record
    /// file, builds and signs the `Update` (sequence = on-chain
    /// current + 1, record_hash = BLAKE3 of the file's records),
    /// submits it, then publishes the signed record in the DHT.
    Update {
        /// Domain name to update.
        name: String,

        /// DNS record file (`A 192.0.2.1`, `AAAA …`, `TXT …`, one per
        /// line; `#` comments). The WHOLE file becomes the record
        /// set: submitting atomically replaces the previous set.
        #[arg(long)]
        file: PathBuf,

        /// Local name of the signing identity (must be the owner).
        #[arg(long)]
        identity: String,

        /// Keystore directory (default: `$HOME/.scone/keys`).
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Read the passphrase from this environment variable instead
        /// of prompting.
        #[arg(long = "passphrase-env", value_name = "VAR")]
        passphrase_env: Option<String>,

        /// RPC address of the relay (default 127.0.0.1:7474).
        #[arg(long)]
        rpc: Option<String>,
    },

    /// Rich read-only exploration of a domain: on-chain state plus,
    /// when a chain-valid record is locally cached, its DNS records.
    Info {
        /// Domain name.
        name: String,

        /// RPC address of the relay (default 127.0.0.1:7474).
        #[arg(long)]
        rpc: Option<String>,
    },
}

/// Subcommands of `scone record`.
#[derive(Debug, Subcommand)]
enum RecordCommand {
    /// Publish a signed record (canonical hex) in the DHT.
    Put {
        /// Domain name the record belongs to.
        name: String,

        /// File containing the canonical hex of the signed record.
        #[arg(long)]
        file: PathBuf,

        /// RPC address of the relay (default 127.0.0.1:7474).
        #[arg(long)]
        rpc: Option<String>,
    },

    /// Resolve a domain's record from the DHT and verify it.
    Get {
        /// Domain name.
        name: String,

        /// RPC address of the relay (default 127.0.0.1:7474).
        #[arg(long)]
        rpc: Option<String>,
    },
}

/// Subcommands of `scone tx`.
#[derive(Debug, Subcommand)]
enum TxCommand {
    /// Build an unsigned transaction and print the hex payload to
    /// sign (the signing payload, prefix included).
    Build {
        /// Transaction kind: `register` or `update`.
        #[command(subcommand)]
        kind: TxKind,
    },

    /// Sign a built transaction with a keystore identity and print
    /// the complete signed transaction as hex.
    Sign {
        /// Hex output of a previous `scone tx build` (unsigned
        /// payload — actually any transaction hex; the signature is
        /// recomputed over the canonical payload).
        tx: String,

        /// Local name of the signing identity.
        #[arg(long)]
        identity: String,

        /// Keystore directory (default: `$HOME/.scone/keys`).
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Read the passphrase from this environment variable instead
        /// of prompting.
        #[arg(long = "passphrase-env", value_name = "VAR")]
        passphrase_env: Option<String>,
    },

    /// Run the full local validation of a signed transaction hex
    /// (decode, owner/key binding, signature).
    Verify {
        /// Hex of a complete signed transaction.
        tx: String,
    },
}

/// Transaction kinds for `scone tx build`.
#[derive(Debug, Clone, Subcommand)]
enum TxKind {
    /// Claim a domain.
    Register {
        /// Domain name to register.
        #[arg(long)]
        name: String,
        /// Unix timestamp (seconds).
        #[arg(long, default_value_t = 0)]
        timestamp: u64,
        /// Hex of the registration proof (default: empty).
        #[arg(long)]
        proof_hex: Option<String>,
    },
    /// Publish a new version of a domain's DNS data.
    Update {
        /// Domain name to update.
        #[arg(long)]
        name: String,
        /// Sequence number (must be current + 1).
        #[arg(long)]
        sequence: u64,
        /// Hex of the record hash commitment (64 hex chars).
        #[arg(long)]
        record_hash: String,
    },
}

/// Subcommands of `scone identity`.
#[derive(Debug, Subcommand)]
enum IdentityCommand {
    /// Generate a new Ed25519 identity in the keystore.
    Generate {
        /// Local name of the identity (keyfile `<name>.sconekey`).
        #[arg(long)]
        name: String,

        /// Keystore directory (default: `$HOME/.scone/keys`).
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Read the passphrase from this environment variable instead
        /// of prompting (mainly for tests and automation).
        #[arg(long = "passphrase-env", value_name = "VAR")]
        passphrase_env: Option<String>,

        /// Replace the keyfile if it already exists. Without this
        /// flag, generating over an existing name is an error (the
        /// previous key would be lost).
        #[arg(long)]
        force: bool,
    },

    /// List the identities of a keystore directory.
    List {
        /// Keystore directory (default: `$HOME/.scone/keys`).
        #[arg(long)]
        dir: Option<PathBuf>,
    },

    /// Show the public key and OwnerId of a stored identity.
    Show {
        /// Local name of the identity.
        #[arg(long)]
        name: String,

        /// Keystore directory (default: `$HOME/.scone/keys`).
        #[arg(long)]
        dir: Option<PathBuf>,

        /// Read the passphrase from this environment variable instead
        /// of prompting (mainly for tests and automation).
        #[arg(long = "passphrase-env", value_name = "VAR")]
        passphrase_env: Option<String>,
    },
}

/// Errors of the CLI: user-facing messages, no panics.
#[derive(Debug)]
enum CliError {
    /// Invalid domain name (from scone-core).
    Domain(scone_core::SconeError),
    /// Unknown identity in the keystore.
    UnknownIdentity(String),
    /// Invalid local identity name (empty, path component, reserved).
    InvalidIdentityName(String),
    /// `--passphrase-env` variable is not set.
    MissingPassphraseEnv(String),
    /// Reading/writing the keystore failed.
    Keystore(scone_keystore::Error),
    /// Reading the passphrase from the terminal failed.
    PassphraseRead,
    /// Passphrases did not match on `identity generate`.
    PassphraseMismatch,
    /// Invalid hex input.
    InvalidHex(String),
    /// The transaction bytes are malformed (decode failure).
    MalformedTransaction(scone_protocol::ProtocolError),
    /// The transaction failed validation (owner/key binding or
    /// signature).
    InvalidTransaction(scone_blockchain::BlockchainError),
    /// A 32-byte value was expected but the hex length is wrong.
    InvalidHashLength(usize),
    /// The relay is not reachable at its RPC address.
    RelayUnreachable(String),
    /// The relay answered with an error.
    RelayError(String),
    /// An invalid RPC address was given.
    InvalidRpcAddr(String),
    /// A file needed by a command could not be read.
    FileRead(std::io::Error),
    /// A DNS record file is malformed (M5).
    BadRecordFile(String),
    /// A domain is not in the state required by the command (M5):
    /// update of an unregistered domain, register of a taken one.
    DomainState(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(e) => write!(f, "{e}"),
            Self::UnknownIdentity(name) => {
                write!(f, "no identity named '{name}' in the keystore")
            }
            Self::InvalidIdentityName(name) => write!(
                f,
                "invalid identity name '{name}': must be a non-empty file name \
                 without '/', '\\', leading dot or path component"
            ),
            Self::MissingPassphraseEnv(var) => {
                write!(f, "environment variable {var} is not set")
            }
            Self::Keystore(e) => {
                // The keystore layer does not know about the `--force`
                // flag; append the hint where it belongs (CLI layer).
                if matches!(e, scone_keystore::Error::KeyfileExists(_)) {
                    write!(f, "keystore: {e} (use --force to replace it)")
                } else {
                    write!(f, "keystore: {e}")
                }
            }
            Self::PassphraseRead => write!(f, "failed to read the passphrase"),
            Self::PassphraseMismatch => write!(f, "passphrases do not match"),
            Self::InvalidHex(context) => write!(f, "invalid hex ({context})"),
            Self::MalformedTransaction(e) => write!(f, "malformed transaction: {e}"),
            Self::InvalidTransaction(e) => write!(f, "invalid transaction: {e}"),
            Self::InvalidHashLength(len) => {
                write!(f, "expected 64 hex chars (32 bytes), got {len}")
            }
            Self::RelayUnreachable(addr) => write!(
                f,
                "cannot reach the relay at {addr} — is 'scone relay' running?"
            ),
            Self::RelayError(message) => write!(f, "relay: {message}"),
            Self::InvalidRpcAddr(addr) => write!(f, "invalid rpc address '{addr}'"),
            Self::FileRead(e) => write!(f, "cannot read file: {e}"),
            Self::BadRecordFile(msg) => write!(f, "invalid record file: {msg}"),
            Self::DomainState(msg) => write!(f, "{msg}"),
        }
    }
}

/// Lowercase hex of raw bytes (64 chars for 32 bytes) — same textual
/// convention as `DomainId`.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0f)] as char);
    }
    out
}

/// A passphrase buffer that zeroizes itself when dropped.
///
/// `Debug` is implemented by hand and never prints the value: a
/// derived implementation would leak the passphrase into logs and panic
/// messages.
struct Passphrase(String);

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passphrase(\"<redacted>\")")
    }
}

impl Passphrase {
    fn new(s: String) -> Self {
        Self(s)
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Passphrase {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Reads a passphrase from the terminal without echoing it.
fn read_passphrase_hidden(prompt: &str) -> Result<String, CliError> {
    rpassword::prompt_password(prompt).map_err(|_| CliError::PassphraseRead)
}

/// Resolves the passphrase: from `--passphrase-env VAR` if given,
/// otherwise prompts on the terminal with hidden input (twice, with
/// confirmation, when `confirm` is set).
fn get_passphrase(passphrase_env: Option<&str>, confirm: bool) -> Result<Passphrase, CliError> {
    if let Some(var) = passphrase_env {
        let value =
            std::env::var(var).map_err(|_| CliError::MissingPassphraseEnv(var.to_string()))?;
        return Ok(Passphrase::new(value));
    }
    let first = read_passphrase_hidden("passphrase: ")?;
    if confirm {
        let second = read_passphrase_hidden("confirm passphrase: ")?;
        if first != second {
            return Err(CliError::PassphraseMismatch);
        }
    }
    Ok(Passphrase::new(first))
}

/// Computes the OwnerId of a signing key, reusing scone-core (single
/// source of truth — never duplicated here).
fn owner_id_of(signing_key: &SigningKey) -> OwnerId {
    let public = signing_key.public_key();
    let key_ref = PublicKeyRef::from_public_key(&public.to_bytes());
    OwnerId::from_public_key_ref(&key_ref)
}

/// Pure, testable CLI entry point: returns the lines to print on
/// stdout. All side effects (keystore writes) go through `scone-keystore`.
///
/// # Errors
///
/// A typed [`CliError`] for every failure; never panics.
fn run(cli: Cli) -> Result<Vec<String>, CliError> {
    match cli.command {
        Command::Show { name } => {
            let domain = DomainName::new(&name).map_err(CliError::Domain)?;
            let id = DomainId::from_name(&domain);
            Ok(vec![format!("{} → {id}", domain.canonical())])
        }
        Command::Identity { command } => run_identity(command),
        Command::Tx { command } => run_tx(command),
        Command::Relay {
            data_dir,
            listen,
            bootstrap,
            rpc,
            dns,
            dns_upstream,
        } => run_relay(data_dir, listen, bootstrap, rpc, dns, dns_upstream),
        Command::Status { rpc } => run_status(rpc),
        Command::Submit { command } => run_submit(command),
        Command::Lookup { name, rpc } => run_lookup(name, rpc),
        Command::Domain { command } => run_domain(command),
        Command::Record { command } => run_record(command),
        Command::Dig { name, dns, qtype } => run_dig(name, dns, qtype),
    }
}

/// Decodes a lowercase-or-uppercase hex string into bytes.
fn hex_decode(context: &str, hex: &str) -> Result<Vec<u8>, CliError> {
    let hex = hex.trim();
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(CliError::InvalidHex(context.to_string()));
    }
    (0..hex.len() / 2)
        .map(|i| {
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| CliError::InvalidHex(context.to_string()))
        })
        .collect()
}

/// Opens the signing key of a keystore identity (shared by
/// `identity show` and `tx sign`).
fn open_identity(
    name: &str,
    dir: Option<&Path>,
    passphrase_env: Option<&str>,
) -> Result<SigningKey, CliError> {
    validate_identity_name(name)?;
    let dir = keystore_dir(dir);
    let path = keyfile_path(&dir, name);
    if !path.is_file() {
        return Err(CliError::UnknownIdentity(name.to_string()));
    }
    let passphrase = get_passphrase(passphrase_env, false)?;
    scone_keystore::open(&path, passphrase.expose()).map_err(CliError::Keystore)
}

/// Dispatches `scone tx …`.
fn run_tx(command: TxCommand) -> Result<Vec<String>, CliError> {
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
            let kind = match decoded {
                scone_core::Transaction::Register(_) => "register",
                scone_core::Transaction::Update(_) => "update",
            };
            let owner = decoded.owner();
            Ok(vec![
                format!("kind: {kind}"),
                format!("domain: {}", decoded.domain_id()),
                format!("owner: {}", hex_lower(owner.as_bytes())),
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
    use scone_core::{Register, Update};
    use scone_protocol::UnsignedTransaction as U;
    match unsigned {
        U::Register {
            domain_id,
            owner: _,
            timestamp,
            proof,
            public_key,
        } => scone_core::Transaction::Register(Register::register_signed(
            domain_id,
            timestamp,
            proof,
            public_key,
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
        U::Update {
            domain_id,
            owner: _,
            sequence,
            record_hash,
            public_key,
        } => scone_core::Transaction::Update(Update::update_signed(
            domain_id,
            sequence,
            record_hash,
            public_key,
            scone_crypto::Signature::from_bytes([0; 64]),
        )),
    }
}

/// Builds an unsigned (placeholder-signature) transaction from CLI
/// args; returns it with a human description line.
fn build_unsigned(kind: TxKind) -> Result<(scone_core::Transaction, String), CliError> {
    use scone_core::{Proof, RecordHash, Register, Update};
    use scone_crypto::Signature;
    let placeholder = Signature::from_bytes([0; 64]);
    // Any valid key works here: the payload to sign does not include
    // owner/key binding choices of the eventual signer... except it
    // DOES include the public_key field, so `build` uses a fixed
    // derived-from-seed key and `sign` rebinds to the real identity.
    let build_key = SigningKey::from_bytes([0x42; 32]);
    match kind {
        TxKind::Register {
            name,
            timestamp,
            proof_hex,
        } => {
            let domain = DomainName::new(&name).map_err(CliError::Domain)?;
            let proof = match proof_hex {
                Some(hex) => Proof::from_bytes(hex_decode("proof", &hex)?),
                None => Proof::from_bytes(Vec::new()),
            };
            let tx = scone_core::Transaction::Register(Register::register_signed(
                DomainId::from_name(&domain),
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
        TxKind::Update {
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
            let tx = scone_core::Transaction::Update(Update::update_signed(
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
        scone_core::Transaction::Register(r) => {
            scone_core::Transaction::Register(Register::register_signed(
                r.domain_id,
                r.timestamp,
                r.proof.clone(),
                sk.public_key(),
                Signature::from_bytes([0; 64]),
            ))
        }
        scone_core::Transaction::Update(u) => {
            scone_core::Transaction::Update(Update::update_signed(
                u.domain_id,
                u.sequence,
                u.record_hash,
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
        scone_core::Transaction::Register(mut r) => {
            r.signature = signature;
            scone_core::Transaction::Register(r)
        }
        scone_core::Transaction::Update(mut u) => {
            u.signature = signature;
            scone_core::Transaction::Update(u)
        }
    }
}

/// Dispatches `scone identity …`.
fn run_identity(command: IdentityCommand) -> Result<Vec<String>, CliError> {
    match command {
        IdentityCommand::Generate {
            name,
            dir,
            passphrase_env,
            force,
        } => {
            validate_identity_name(&name)?;
            let dir = keystore_dir(dir.as_deref());
            let path = keyfile_path(&dir, &name);

            let passphrase = get_passphrase(passphrase_env.as_deref(), true)?;
            // `create` (no --force) fails with `Error::KeyfileExists`
            // if the file is already there — typed, never a silent
            // overwrite of an existing identity.
            let generated = if force {
                scone_keystore::create_overwriting(&path, passphrase.expose())
            } else {
                scone_keystore::create(&path, passphrase.expose())
            }
            .map_err(CliError::Keystore)?;

            let public = generated.signing_key.public_key();
            let owner = owner_id_of(&generated.signing_key);
            Ok(vec![
                format!("generated identity '{name}'"),
                format!("keyfile: {}", generated.path.display()),
                format!("public key: {public}"),
                format!("owner id: {}", hex_lower(owner.as_bytes())),
            ])
        }
        IdentityCommand::List { dir } => {
            let dir = keystore_dir(dir.as_deref());
            debug!(dir = %dir.display(), "listing identities");
            let entries = scone_keystore::list(&dir).map_err(CliError::Keystore)?;
            if entries.is_empty() {
                return Ok(vec!["no identities".to_string()]);
            }
            Ok(entries
                .into_iter()
                .map(|e| format!("{} {}", e.name, e.path.display()))
                .collect())
        }
        IdentityCommand::Show {
            name,
            dir,
            passphrase_env,
        } => {
            validate_identity_name(&name)?;
            let dir = keystore_dir(dir.as_deref());
            let path = keyfile_path(&dir, &name);
            if !path.is_file() {
                return Err(CliError::UnknownIdentity(name));
            }

            let passphrase = get_passphrase(passphrase_env.as_deref(), false)?;
            let signing_key =
                scone_keystore::open(&path, passphrase.expose()).map_err(CliError::Keystore)?;

            let public = signing_key.public_key();
            let owner = owner_id_of(&signing_key);
            Ok(vec![
                format!("identity: {name}"),
                format!("public key: {public}"),
                format!("owner id: {}", hex_lower(owner.as_bytes())),
            ])
        }
    }
}

/// Default relay RPC address.
const DEFAULT_RPC_ADDR: &str = "127.0.0.1:7474";

/// Builds an RPC client for the given `--rpc` value (or the default).
fn rpc_client(rpc: Option<&str>) -> Result<scone_network::RpcClient, CliError> {
    let text = rpc.unwrap_or(DEFAULT_RPC_ADDR);
    let addr: std::net::SocketAddr = text
        .parse()
        .map_err(|_| CliError::InvalidRpcAddr(text.to_string()))?;
    Ok(scone_network::RpcClient::new(addr))
}

/// Runs one async RPC round trip on a fresh tokio runtime (the CLI
/// stays synchronous everywhere else).
fn rpc_call(
    client: &scone_network::RpcClient,
    request: scone_network::RpcRequest,
) -> Result<Vec<String>, CliError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::RelayUnreachable(e.to_string()))?;
    debug!(addr = %client.addr(), "rpc round trip");
    let response = rt.block_on(client.request(request)).map_err(|e| match e {
        scone_network::NetworkError::Io(_) | scone_network::NetworkError::Timeout(_) => {
            CliError::RelayUnreachable(client_addr(client))
        }
        other => CliError::RelayError(other.to_string()),
    })?;
    match response {
        scone_network::RpcResponse::Ok { data } => Ok(render_json(&data)),
        scone_network::RpcResponse::Error { message } => Err(CliError::RelayError(message)),
    }
}

/// The client's address as a display string.
fn client_addr(client: &scone_network::RpcClient) -> String {
    client.addr().to_string()
}

/// Renders a JSON value as aligned `key: value` lines (objects) or a
/// single line otherwise.
fn render_json(value: &serde_json::Value) -> Vec<String> {
    use serde_json::Value;
    match value {
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| format!("{k}: {}", render_flat(v)))
            .collect(),
        other => vec![render_flat(other)],
    }
}

/// Renders a JSON scalar/array as one flat string.
fn render_flat(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Runs `scone relay …` (foreground daemon).
#[allow(clippy::too_many_arguments)]
fn run_relay(
    data_dir: Option<PathBuf>,
    listen: Option<String>,
    bootstrap: Vec<String>,
    rpc: Option<String>,
    dns: Option<String>,
    dns_upstream: Vec<String>,
) -> Result<Vec<String>, CliError> {
    let data_dir = data_dir.unwrap_or_else(|| match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".scone"),
        None => PathBuf::from(".scone"),
    });
    let mut config = scone_network::Config::new(data_dir);
    if let Some(listen) = listen {
        config.listen = Some(listen);
    }
    config.bootstrap = bootstrap;
    // Devnet defaults: fixed RPC port so the CLI can find us, unless
    // --rpc says otherwise (two relays on one machine).
    let rpc_text = rpc.as_deref().unwrap_or(DEFAULT_RPC_ADDR);
    config.rpc_addr = rpc_text
        .parse()
        .map_err(|_| CliError::InvalidRpcAddr(rpc_text.to_string()))?;
    // M6: optional UDP DNS surface + optional fallback upstreams.
    if let Some(dns_text) = dns.as_deref() {
        config.dns_addr = Some(
            dns_text
                .parse()
                .map_err(|_| CliError::InvalidRpcAddr(dns_text.to_string()))?,
        );
    }
    config.dns_upstreams = dns_upstream;
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::RelayUnreachable(e.to_string()))?;
    rt.block_on(async move {
        let relay =
            scone_network::Relay::new(config).map_err(|e| CliError::RelayError(e.to_string()))?;
        info!(peer = %relay.peer_id(), "starting relay");
        relay
            .run()
            .await
            .map_err(|e| CliError::RelayError(e.to_string()))
    })?;
    Ok(Vec::new())
}

/// Runs `scone status`.
fn run_status(rpc: Option<String>) -> Result<Vec<String>, CliError> {
    let client = rpc_client(rpc.as_deref())?;
    rpc_call(&client, scone_network::RpcRequest::Status)
}

/// Runs `scone submit tx …`.
fn run_submit(command: SubmitCommand) -> Result<Vec<String>, CliError> {
    let SubmitCommand::Tx { hex, rpc } = command;
    let client = rpc_client(rpc.as_deref())?;
    rpc_call(
        &client,
        scone_network::RpcRequest::SubmitTx {
            tx_hex: hex.to_lowercase(),
        },
    )
}

/// Runs `scone lookup <name>`.
fn run_lookup(name: String, rpc: Option<String>) -> Result<Vec<String>, CliError> {
    let client = rpc_client(rpc.as_deref())?;
    rpc_call(&client, scone_network::RpcRequest::Lookup { name })
}

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
fn run_dig(name: String, dns: Option<String>, qtype: String) -> Result<Vec<String>, CliError> {
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

/// Runs one async RPC round trip and returns the raw `data` value.
fn rpc_json(
    client: &scone_network::RpcClient,
    request: scone_network::RpcRequest,
) -> Result<serde_json::Value, CliError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::RelayUnreachable(e.to_string()))?;
    let response = rt.block_on(client.request(request)).map_err(|e| match e {
        scone_network::NetworkError::Io(_) | scone_network::NetworkError::Timeout(_) => {
            CliError::RelayUnreachable(client_addr(client))
        }
        other => CliError::RelayError(other.to_string()),
    })?;
    match response {
        scone_network::RpcResponse::Ok { data } => Ok(data),
        scone_network::RpcResponse::Error { message } => Err(CliError::RelayError(message)),
    }
}

/// How long `domain register|update` waits for devnet confirmation.
const CONFIRM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Polling period while waiting for chain confirmation.
const CONFIRM_POLL: std::time::Duration = std::time::Duration::from_millis(300);

/// Current Unix time (seconds), best effort (0 before the epoch).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
fn tx_hex(tx: &scone_core::Transaction) -> Result<String, CliError> {
    Ok(hex_lower(
        &scone_protocol::encode_to_vec(tx).map_err(CliError::MalformedTransaction)?,
    ))
}

/// Builds and signs a `Register` for `domain` with `sk`.
fn signed_register_tx(
    sk: &SigningKey,
    domain: &DomainName,
    timestamp: u64,
) -> Result<scone_core::Transaction, CliError> {
    let unsigned = scone_core::Transaction::Register(Register::register_signed(
        DomainId::from_name(domain),
        timestamp,
        scone_core::Proof::from_bytes(Vec::new()),
        sk.public_key(),
        Signature::from_bytes([0; 64]),
    ));
    sign_tx_with(unsigned, sk)
}

/// Builds and signs an `Update` committing `record_hash` at
/// `sequence` for `domain` with `sk`.
fn signed_update_tx(
    sk: &SigningKey,
    domain: &DomainName,
    sequence: u64,
    record_hash: scone_core::RecordHash,
) -> Result<scone_core::Transaction, CliError> {
    let unsigned = scone_core::Transaction::Update(Update::update_signed(
        DomainId::from_name(domain),
        sequence,
        record_hash,
        sk.public_key(),
        Signature::from_bytes([0; 64]),
    ));
    sign_tx_with(unsigned, sk)
}

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
fn read_record_file(path: &Path) -> Result<Vec<scone_core::RecordData>, CliError> {
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
fn run_domain(command: DomainCommand) -> Result<Vec<String>, CliError> {
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
fn run_record(command: RecordCommand) -> Result<Vec<String>, CliError> {
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli);
    match run(cli) {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("scone: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Initializes the tracing subscriber (compact format, stderr —
/// stdout stays reserved for command output, which matters for
/// scripting).
///
/// Level selection:
///
/// - `RUST_LOG`, when set, wins outright (env-filter syntax, e.g.
///   `RUST_LOG=debug` or `RUST_LOG=scone_network=trace,info`);
/// - otherwise `-v` selects the level: none → WARN, `-v` → INFO,
///   `-vv` → DEBUG, `-vvv` (and more) → TRACE;
/// - `scone relay` defaults to INFO even without `-v` — a daemon
///   must log its activity to be operable.
fn init_tracing(cli: &Cli) {
    use tracing_subscriber::EnvFilter;

    let is_relay = matches!(cli.command, Command::Relay { .. });
    let default_level = match cli.verbose {
        0 if is_relay => "info",
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(default_level))
        .unwrap_or_else(|_| EnvFilter::new(default_level));
    tracing_subscriber::fmt()
        .compact()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the expected output line for `name`, independently from
    /// the code under test (re-derives the id via scone-core).
    fn expected_line(name: &str) -> String {
        let domain = DomainName::new(name).expect("valid name in test fixture");
        format!("{} → {}", name, DomainId::from_name(&domain))
    }

    fn cli(args: &[&str]) -> Cli {
        Cli::try_parse_from(std::iter::once("scone").chain(args.iter().copied()))
            .expect("valid cli args in test")
    }

    #[test]
    fn show_valid_name_returns_id_line() {
        let out = run(cli(&["show", "example.uip"])).expect("valid invocation");
        assert_eq!(out, vec![expected_line("example.uip")]);
        let hex = out[0].rsplit(" → ").next().expect("hex part");
        assert_eq!(hex.len(), 64);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn show_invalid_name_is_rejected() {
        // Strict validation: uppercase labels must not be silently accepted.
        let err = run(cli(&["show", "EXAMPLE.uip"])).expect_err("invalid name");
        assert!(matches!(
            err,
            CliError::Domain(
                scone_core::SconeError::InvalidDomain(_) | scone_core::SconeError::InvalidTld(_)
            )
        ));
    }

    #[test]
    fn distinct_names_give_distinct_outputs() {
        let a = run(cli(&["show", "example.uip"])).expect("valid");
        let b = run(cli(&["show", "other.uip"])).expect("valid");
        assert_ne!(a, b);
        assert_eq!(b, vec![expected_line("other.uip")]);
    }

    #[test]
    fn owner_id_reuses_scone_core_derivation() {
        // The CLI must not duplicate the OwnerId computation: recompute
        // it via scone-core directly and compare.
        let sk = SigningKey::from_bytes([7u8; 32]);
        let expected = OwnerId::from_public_key_ref(&PublicKeyRef::from_public_key(
            &sk.public_key().to_bytes(),
        ));
        assert_eq!(owner_id_of(&sk), expected);
        assert_ne!(*owner_id_of(&sk).as_bytes(), sk.public_key().to_bytes());
    }

    #[test]
    fn identity_generate_list_show_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_flag = dir.path().to_str().expect("utf-8 path").to_string();
        // SAFETY: single-threaded test process; the variable is restored
        // before returning (the keystore tests below run sequentially).
        // Edition 2024 marks set_var/remove_var unsafe because they are
        // unsound in multithreaded programs.
        unsafe {
            std::env::set_var("SCONE_TEST_PASSPHRASE_UNIT", "unit-test-passphrase");
        }
        let var = "SCONE_TEST_PASSPHRASE_UNIT";

        let lines = run(cli(&[
            "identity",
            "generate",
            "--name",
            "alice",
            "--dir",
            &dir_flag,
            "--passphrase-env",
            var,
        ]))
        .expect("generate works");
        assert_eq!(lines[0], "generated identity 'alice'");

        let listed = run(cli(&["identity", "list", "--dir", &dir_flag])).expect("list works");
        assert_eq!(listed.len(), 1);
        assert!(listed[0].starts_with("alice "));

        let shown = run(cli(&[
            "identity",
            "show",
            "--name",
            "alice",
            "--dir",
            &dir_flag,
            "--passphrase-env",
            var,
        ]))
        .expect("show works");
        // SAFETY: see the comment at the top of this test.
        unsafe { std::env::remove_var(var) };
        assert_eq!(shown.len(), 3);
        assert_eq!(shown[0], "identity: alice");
        let pk_hex = shown[1].strip_prefix("public key: ").expect("pk line");
        assert_eq!(pk_hex.len(), 64);
        assert!(
            pk_hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        let owner_hex = shown[2].strip_prefix("owner id: ").expect("owner line");
        assert_eq!(owner_hex.len(), 64);
    }

    #[test]
    fn identity_show_of_unknown_name_is_a_clean_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_flag = dir.path().to_str().expect("utf-8 path").to_string();
        let err = run(cli(&[
            "identity", "show", "--name", "ghost", "--dir", &dir_flag,
        ]))
        .expect_err("unknown identity");
        assert!(matches!(err, CliError::UnknownIdentity(n) if n == "ghost"));
    }

    #[test]
    fn identity_list_of_empty_keystore_says_so() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_flag = dir.path().to_str().expect("utf-8 path").to_string();
        let out = run(cli(&["identity", "list", "--dir", &dir_flag])).expect("list works");
        assert_eq!(out, vec!["no identities".to_string()]);
    }

    #[test]
    fn identity_generate_with_unset_env_var_is_a_clean_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_flag = dir.path().to_str().expect("utf-8 path").to_string();
        let err = run(cli(&[
            "identity",
            "generate",
            "--name",
            "alice",
            "--dir",
            &dir_flag,
            "--passphrase-env",
            "SCONE_TEST_UNSET_VAR_XYZ",
        ]))
        .expect_err("env var unset");
        assert!(
            matches!(err, CliError::MissingPassphraseEnv(v) if v == "SCONE_TEST_UNSET_VAR_XYZ")
        );
    }

    #[test]
    fn keyfile_path_uses_the_sconekey_extension() {
        let p = keyfile_path(Path::new("/keys"), "alice");
        assert_eq!(p, Path::new("/keys/alice.sconekey"));
    }

    #[test]
    fn identity_names_with_path_components_are_rejected() {
        for bad in [
            ".",
            "..",
            "/",
            "a/b",
            "../x",
            "a/../b",
            "a\\b",
            "..\\x",
            "a\0b",
            ".hidden",
            ".sconekey",
            "name.sconekey",
        ] {
            assert!(
                matches!(
                    run(cli(&["identity", "generate", "--name", bad, "--dir", "/tmp"])),
                    Err(CliError::InvalidIdentityName(n)) if n == bad
                ),
                "'{bad}' must be rejected as an identity name"
            );
        }
        // The empty name cannot go through clap as an empty flag
        // value in this harness; check the validator directly.
        assert!(validate_identity_name("").is_err());
        // `..` and `.` are also caught explicitly (belt and braces
        // with the leading-dot rule).
        assert!(validate_identity_name("..").is_err());
        assert!(validate_identity_name(".").is_err());
    }

    #[test]
    fn valid_identity_names_are_accepted() {
        for good in ["alice", "bob-2", "carol_", "dave.example", "0e8f9d"] {
            assert!(
                validate_identity_name(good).is_ok(),
                "'{good}' should be valid"
            );
        }
    }

    #[test]
    fn identity_generate_refuses_to_overwrite_without_force() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_flag = dir.path().to_str().expect("utf-8 path").to_string();
        unsafe {
            std::env::set_var("SCONE_TEST_PASS_OVERWRITE", "unit-passphrase");
        }
        let var = "SCONE_TEST_PASS_OVERWRITE";

        let first = run(cli(&[
            "identity",
            "generate",
            "--name",
            "alice",
            "--dir",
            &dir_flag,
            "--passphrase-env",
            var,
        ]))
        .expect("first generate works");
        let first_pk = first
            .iter()
            .find(|l| l.starts_with("public key: "))
            .expect("pk");

        // Second generate without --force must fail…
        let err = run(cli(&[
            "identity",
            "generate",
            "--name",
            "alice",
            "--dir",
            &dir_flag,
            "--passphrase-env",
            var,
        ]))
        .expect_err("overwrite must be refused");
        assert!(matches!(err, CliError::Keystore(_)));
        let msg = err.to_string();
        assert!(msg.contains("already exists"), "stderr: {msg}");
        assert!(msg.contains("--force"), "must point at --force: {msg}");

        // …and with --force it succeeds with a NEW key.
        let second = run(cli(&[
            "identity",
            "generate",
            "--name",
            "alice",
            "--dir",
            &dir_flag,
            "--passphrase-env",
            var,
            "--force",
        ]))
        .expect("--force overwrites");
        let second_pk = second
            .iter()
            .find(|l| l.starts_with("public key: "))
            .expect("pk");
        assert_ne!(first_pk, second_pk);

        // Only one keyfile in the directory.
        let entries = scone_keystore::list(&dir).expect("list");
        assert_eq!(entries.len(), 1);

        unsafe { std::env::remove_var(var) }
    }

    #[test]
    fn passphrase_debug_never_prints_the_value() {
        let p = Passphrase::new("super-secret-value".to_string());
        let dbg = format!("{p:?}");
        assert_eq!(dbg, "Passphrase(\"<redacted>\")");
        assert!(!dbg.contains("super-secret-value"));
    }

    #[test]
    fn tx_build_sign_verify_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dir_flag = dir.path().to_str().expect("utf-8 path").to_string();
        unsafe {
            std::env::set_var("SCONE_TEST_PASS_TX", "unit-test-passphrase");
        }
        let var = "SCONE_TEST_PASS_TX";

        run(cli(&[
            "identity",
            "generate",
            "--name",
            "alice",
            "--dir",
            &dir_flag,
            "--passphrase-env",
            var,
        ]))
        .expect("generate works");

        // build
        let built = run(cli(&[
            "tx",
            "build",
            "register",
            "--name",
            "example.uip",
            "--timestamp",
            "42",
        ]))
        .expect("build works");
        let payload = built
            .iter()
            .find(|l| l.starts_with("signing payload: "))
            .expect("payload line")
            .strip_prefix("signing payload: ")
            .expect("hex");
        // The payload starts with the ASCII domain-separation prefix.
        assert!(payload.starts_with("53434f4e452d54582d5349472d5631"));

        // sign
        let signed_lines = run(cli(&[
            "tx",
            "sign",
            payload,
            "--identity",
            "alice",
            "--dir",
            &dir_flag,
            "--passphrase-env",
            var,
        ]))
        .expect("sign works");
        let signed_hex = signed_lines
            .iter()
            .find(|l| l.starts_with("transaction: "))
            .expect("tx line")
            .strip_prefix("transaction: ")
            .expect("hex");

        // verify: the exact tx passes
        let verified = run(cli(&["tx", "verify", signed_hex])).expect("verify works");
        assert!(verified.contains(&"signature: valid".to_string()));

        // verify: a tampered tx fails cleanly
        let mut tampered = signed_hex.to_string();
        tampered.replace_range(4..6, if &tampered[4..6] == "ff" { "00" } else { "ff" });
        let err = run(cli(&["tx", "verify", &tampered])).expect_err("tampered must fail");
        assert!(matches!(
            err,
            CliError::MalformedTransaction(_) | CliError::InvalidTransaction(_)
        ));

        unsafe { std::env::remove_var(var) }
    }

    #[test]
    fn tx_verify_rejects_v1_and_garbage() {
        // Garbage hex.
        assert!(matches!(
            run(cli(&["tx", "verify", "zzzz"])),
            Err(CliError::InvalidHex(_))
        ));
        // Valid hex, garbage bytes.
        assert!(matches!(
            run(cli(&["tx", "verify", "0100"])),
            Err(CliError::MalformedTransaction(_))
        ));
        // Odd length.
        assert!(matches!(
            run(cli(&["tx", "verify", "010"])),
            Err(CliError::InvalidHex(_))
        ));
    }

    #[test]
    fn tx_build_update_requires_32_byte_record_hash() {
        let err = run(cli(&[
            "tx",
            "build",
            "update",
            "--name",
            "example.uip",
            "--sequence",
            "1",
            "--record-hash",
            "aabb",
        ]))
        .expect_err("short hash must fail");
        assert!(matches!(err, CliError::InvalidHashLength(4)));
    }

    // ---- M5: record file parser ------------------------------------

    #[test]
    fn record_file_parses_all_supported_types() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("records.txt");
        std::fs::write(
            &file,
            "# comment\n\nA 192.0.2.1\naaaa 2001:db8::1\ncname www.example.uip\nns ns1.example.uip\nmx 10 mail.example.uip\ntxt   spaced   out   text\n",
        )
        .expect("write");
        let records = read_record_file(&file).expect("parses");
        assert_eq!(records.len(), 6);
        assert_eq!(
            records[0],
            scone_core::RecordData::A("192.0.2.1".parse().unwrap())
        );
        assert_eq!(
            records[1],
            scone_core::RecordData::Aaaa("2001:db8::1".parse().unwrap())
        );
        assert!(matches!(&records[5], scone_core::RecordData::Txt(t) if t == "spaced out text"));
    }

    #[test]
    fn record_file_rejects_unknown_type_with_line_number() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("records.txt");
        std::fs::write(&file, "A 192.0.2.1\nBOGUS x\n").expect("write");
        let err = read_record_file(&file).expect_err("must fail");
        assert!(
            matches!(err, CliError::BadRecordFile(ref m) if m.contains("line 2") && m.contains("BOGUS")),
            "{err}"
        );
    }

    #[test]
    fn record_file_rejects_bad_ip_and_bad_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("records.txt");
        std::fs::write(&file, "A not-an-ip\n").expect("write");
        assert!(matches!(
            read_record_file(&file),
            Err(CliError::BadRecordFile(_))
        ));
        std::fs::write(&file, "CNAME UPPER.uip\n").expect("write");
        assert!(matches!(
            read_record_file(&file),
            Err(CliError::BadRecordFile(_))
        ));
    }

    // ---- M5 fix-up F3: strict parser ----------------------------------

    #[test]
    fn record_file_rejects_trailing_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("records.txt");
        for bad in [
            "A 192.0.2.1 extra",
            "AAAA 2001:db8::1 192.0.2.1",
            "CNAME www.example.uip trailing",
            "NS ns1.example.uip trailing",
            "MX 10 mail.example.uip trailing",
        ] {
            std::fs::write(&file, bad).expect("write");
            let err = match read_record_file(&file) {
                Ok(_) => panic!("'{bad}' must be rejected"),
                Err(err) => err,
            };
            assert!(
                matches!(&err, CliError::BadRecordFile(m) if m.contains("trailing")),
                "'{bad}' → {err}"
            );
        }
    }

    #[test]
    fn record_file_rejects_empty_txt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("records.txt");
        std::fs::write(&file, "TXT\n").expect("write");
        let err = read_record_file(&file).expect_err("empty TXT must fail");
        assert!(
            matches!(&err, CliError::BadRecordFile(m) if m.contains("non-empty")),
            "{err}"
        );
        // A TXT of only whitespace collapses to empty: rejected too.
        std::fs::write(&file, "TXT   \t  \n").expect("write");
        assert!(matches!(
            read_record_file(&file),
            Err(CliError::BadRecordFile(_))
        ));
    }

    #[test]
    fn record_file_accepts_exact_arity_lines() {
        // Each well-formed line parses even after the strictness fix.
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("records.txt");
        std::fs::write(
            &file,
            "A 192.0.2.1\nAAAA 2001:db8::1\nCNAME www.example.uip\nNS ns1.example.uip\nMX 10 mail.example.uip\nTXT one two  three\n",
        )
        .expect("write");
        let records = read_record_file(&file).expect("parses");
        assert_eq!(records.len(), 6);
    }

    #[test]
    fn record_file_rejects_empty_and_duplicate_sets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("records.txt");
        std::fs::write(&file, "# only comments\n").expect("write");
        let err = read_record_file(&file).expect_err("must fail");
        assert!(
            matches!(&err, CliError::BadRecordFile(m) if m.contains("empty")),
            "{err}"
        );
        std::fs::write(&file, "A 192.0.2.1\nA 192.0.2.1\n").expect("write");
        let err = read_record_file(&file).expect_err("must fail");
        assert!(
            matches!(&err, CliError::BadRecordFile(m) if m.contains("duplicate")),
            "{err}"
        );
    }

    #[test]
    fn record_file_missing_file_is_a_clean_error() {
        let err = read_record_file(Path::new("/nonexistent/records.txt")).expect_err("must fail");
        assert!(matches!(err, CliError::FileRead(_)));
    }

    #[test]
    fn record_file_records_roundtrip_through_canonical_encoding() {
        // What the parser produces must be encodable as a DnsRecord:
        // this is the exact type `domain update` hashes and publishes.
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("records.txt");
        std::fs::write(
            &file,
            "A 192.0.2.1\nTXT integration check\nMX 10 mail.example.uip\n",
        )
        .expect("write");
        let records = read_record_file(&file).expect("parses");
        let dns = scone_core::DnsRecord {
            domain_id: DomainId::from_name(&DomainName::new("example.uip").unwrap()),
            sequence: 1,
            expiration: 0,
            records,
        };
        let encoded = scone_protocol::encode_to_vec(&dns).expect("canonical encode");
        let decoded: scone_core::DnsRecord =
            scone_protocol::decode_complete(&encoded).expect("canonical decode");
        // The struct keeps file order while the wire is canonically
        // sorted: compare encodings, and check the re-encode is stable.
        assert_eq!(
            scone_protocol::encode_to_vec(&decoded).expect("re-encode"),
            encoded,
            "canonical round trip"
        );
        // The record hash over the parsed file is stable (the wire
        // order is canonical regardless of file order).
        std::fs::write(
            &file,
            "MX 10 mail.example.uip\nTXT integration check\nA 192.0.2.1\n",
        )
        .expect("rewrite permuted");
        let permuted = scone_core::DnsRecord {
            records: read_record_file(&file).expect("parses"),
            ..dns.clone()
        };
        assert_eq!(
            scone_protocol::record_hash(&dns),
            scone_protocol::record_hash(&permuted),
            "file order must not change the committed hash"
        );
    }

    #[test]
    fn domain_info_of_offline_relay_is_unreachable() {
        // No relay on this port: the typed "relay not running" error.
        let err = run(cli(&[
            "domain",
            "info",
            "example.uip",
            "--rpc",
            "127.0.0.1:1",
        ]))
        .expect_err("unreachable");
        assert!(matches!(err, CliError::RelayUnreachable(_)));
    }
}
