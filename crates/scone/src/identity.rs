//! `scone identity …` and the keystore plumbing behind it:
//! keystore directory/keyfile paths, identity name validation
//! and passphrase-protected key opening.

use std::path::{Path, PathBuf};

use scone_core::{OwnerId, PublicKeyRef};
use scone_crypto::SigningKey;
use tracing::debug;

use crate::cli::IdentityCommand;
use crate::error::CliError;
use crate::util::{get_passphrase, hex_lower};

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
pub(crate) fn keyfile_path(dir: &Path, name: &str) -> PathBuf {
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
pub(crate) fn validate_identity_name(name: &str) -> Result<(), CliError> {
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

/// Computes the OwnerId of a signing key, reusing scone-core (single
/// source of truth — never duplicated here).
pub(crate) fn owner_id_of(signing_key: &SigningKey) -> OwnerId {
    let public = signing_key.public_key();
    let key_ref = PublicKeyRef::from_public_key(&public.to_bytes());
    OwnerId::from_public_key_ref(&key_ref)
}

/// Opens the signing key of a keystore identity (shared by
/// `identity show` and `tx sign`).
pub(crate) fn open_identity(
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

/// Dispatches `scone identity …`.
pub(crate) fn run_identity(command: IdentityCommand) -> Result<Vec<String>, CliError> {
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
