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
use scone_core::{DomainId, DomainName, OwnerId, PublicKeyRef};
use scone_crypto::SigningKey;
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

    /// Manage local signing identities.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
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

fn main() -> ExitCode {
    let cli = Cli::parse();
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
}
