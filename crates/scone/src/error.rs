//! The `CliError` type: user-facing error messages of every
//! command, no panics.

/// Errors of the CLI: user-facing messages, no panics.
#[derive(Debug)]
pub(crate) enum CliError {
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
