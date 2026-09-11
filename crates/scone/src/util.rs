//! Small shared helpers: lowercase hex encode/decode, the
//! zeroizing `Passphrase` wrapper and its terminal reading
//! flow, and the current Unix time.

use zeroize::Zeroize;

use crate::error::CliError;

/// Lowercase hex of raw bytes (64 chars for 32 bytes) — same textual
/// convention as `DomainId`.
pub(crate) fn hex_lower(bytes: &[u8]) -> String {
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
pub(crate) struct Passphrase(String);

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passphrase(\"<redacted>\")")
    }
}

impl Passphrase {
    pub(crate) fn new(s: String) -> Self {
        Self(s)
    }

    pub(crate) fn expose(&self) -> &str {
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
pub(crate) fn get_passphrase(
    passphrase_env: Option<&str>,
    confirm: bool,
) -> Result<Passphrase, CliError> {
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

/// Decodes a lowercase-or-uppercase hex string into bytes.
pub(crate) fn hex_decode(context: &str, hex: &str) -> Result<Vec<u8>, CliError> {
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

/// Current Unix time (seconds), best effort (0 before the epoch).
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
