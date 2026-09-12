//! Clap definitions of the `scone` command line: top-level `Cli`,
//! `Command` and every subcommand enum. Parsing only — behaviour
//! lives in the per-command `run_*` modules.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Top-level `scone` command.
#[derive(Debug, Parser)]
#[command(
    name = "scone",
    version,
    about = "Scone: decentralized DNS command-line tool",
    disable_help_subcommand = true
)]
pub(crate) struct Cli {
    /// Increase logging verbosity (-v: info, -vv: debug, -vvv:
    /// trace). Without -v, commands log at WARN, except `scone
    /// relay` which stays at INFO (a daemon must log its activity).
    /// RUST_LOG, when set, overrides these defaults entirely.
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count, global = true)]
    pub(crate) verbose: u8,

    #[command(subcommand)]
    pub(crate) command: Command,
}

/// Subcommands of `scone`.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Show the DomainId of a domain name.
    Show {
        /// Domain name (e.g. `example.uip`).
        name: String,
    },

    /// Run a relay node (foreground daemon; logs to stderr).
    Relay {
        /// Network to join: `testnet` (default while the project is
        /// in development) or `mainnet` (must be explicit). Each
        /// network has its own genesis, its own PoW difficulties and
        /// its own default data directory.
        #[arg(long, default_value = "testnet")]
        network: String,

        /// Data directory (chain database lives here). Default:
        /// `$HOME/.scone/<network>/`.
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
        /// Maximum entries in the DNS cache (default 100000).
        #[arg(long = "dns-cache-limit")]
        dns_cache_limit: Option<usize>,
        /// Anchor keyfile (`.sconekey`) — when set, this relay
        /// participates in the checkpoint loop (proposes, signs,
        /// aggregates) and produces blocks with the anchor identity
        /// (M5: an allowed producer). Requires the passphrase env
        /// var (see `--anchor-passphrase-env`).
        #[arg(long = "anchor-key")]
        anchor_key: Option<PathBuf>,
        /// Environment variable holding the anchor keyfile passphrase
        /// (default `SCONE_ANCHOR_PASS`).
        #[arg(long = "anchor-passphrase-env", default_value = "SCONE_ANCHOR_PASS")]
        anchor_passphrase_env: String,
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
    /// debugging helpers for the signed transaction format.
    Tx {
        #[command(subcommand)]
        command: TxCommand,
    },
}

/// Subcommands of `scone submit`.
#[derive(Debug, Subcommand)]
pub(crate) enum SubmitCommand {
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
pub(crate) enum DomainCommand {
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
pub(crate) enum RecordCommand {
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
pub(crate) enum TxCommand {
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
pub(crate) enum TxKind {
    /// Claim a domain.
    RegisterDomain {
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
    /// Claim a top-level domain (M7b).
    RegisterTld {
        /// TLD to register (e.g. `uip`).
        #[arg(long)]
        tld: String,
        /// Unix timestamp (seconds).
        #[arg(long, default_value_t = 0)]
        timestamp: u64,
        /// Hex of the registration proof (default: empty).
        #[arg(long)]
        proof_hex: Option<String>,
    },
    /// Publish a new version of a domain's DNS data.
    UpdateDomain {
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
    /// Open or close a TLD for self-service registration (M8b).
    SetTldOpen {
        /// TLD whose registration policy changes.
        #[arg(long)]
        tld: String,
        /// `true` = anyone may register (registration PoW still
        /// required); `false` = assign-only.
        #[arg(long, default_value_t = true)]
        open: bool,
    },
    /// Assign a domain directly as the TLD owner (M8b).
    AssignDomain {
        /// Domain name to assign.
        #[arg(long)]
        name: String,
        /// Hex of the assignee's OwnerId (64 hex chars).
        #[arg(long)]
        assignee: String,
    },
    /// Extend a domain registration until `valid_until` (M8b).
    RenewDomain {
        /// Domain name to renew.
        #[arg(long)]
        name: String,
        /// New expiry (Unix seconds; must extend and stay within 3
        /// years).
        #[arg(long)]
        valid_until: u64,
    },
    /// Transfer a TLD to a new owner (M8b).
    TransferTld {
        /// TLD to transfer.
        #[arg(long)]
        tld: String,
        /// Hex of the recipient OwnerId (64 hex chars).
        #[arg(long)]
        new_owner: String,
    },
    /// Relinquish a TLD (M8b).
    RevokeTld {
        /// TLD to relinquish.
        #[arg(long)]
        tld: String,
    },
}

/// Subcommands of `scone identity`.
#[derive(Debug, Subcommand)]
pub(crate) enum IdentityCommand {
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
