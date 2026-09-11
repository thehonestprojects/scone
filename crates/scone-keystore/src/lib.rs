//! # scone-keystore
//!
//! Encrypted on-disk storage for Ed25519 signing keys (`.sconekey`
//! files).
//!
//! This crate owns the filesystem so `scone-crypto` can stay pure. It
//! does no networking and no async. See `/docs/technical/keystore.md`
//! for the normative keyfile specification.
//!
//! ## Format (v1)
//!
//! ```text
//! "SCONEKEY1" (9 bytes magic)
//! u8       version = 1
//! u8       m_cost in MiB (Argon2id memory; m_cost_kib = value × 1024)
//! u8       t_cost (Argon2id iterations)
//! [u8; 16] Argon2id salt
//! [u8; 24] XChaCha20-Poly1305 nonce
//! [u8; 48] ciphertext || 16-byte Poly1305 tag (encrypted 32-byte seed)
//! ```
//!
//! The Argon2id parameters are stored in the file (not hardcoded at
//! read time) so future versions can raise them while old files remain
//! readable. Values outside the accepted bounds are rejected: a file
//! claiming absurd parameters must not be able to force a node to
//! allocate gigabytes ([`Error::InvalidParams`]).
//!
//! ## Security properties
//!
//! - The seed never hits the disk unencrypted; the passphrase and all
//!   derived key material are [`Zeroizing`]ed after use (Drop-based, so
//!   every error path is covered).
//! - On Unix the keyfile is created with `0600` permissions
//!   (owner read/write only), enforced via `OpenOptions` +
//!   `set_permissions` regardless of the caller's umask.
//! - A wrong passphrase is reported as a distinct error
//!   ([`Error::WrongPassphrase`]) — Poly1305 authentication failure is
//!   the only observable difference, which leaks nothing beyond
//!   "incorrect".
//! - Corrupted or truncated files are rejected with typed errors, never
//!   panics.

use std::path::{Path, PathBuf};

use argon2::Params;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use scone_crypto::SigningKey;
use zeroize::{Zeroize, Zeroizing};

/// File extension of a Scone keyfile.
pub const KEYFILE_EXTENSION: &str = "sconekey";

/// Magic prefix of a v1 keyfile.
const MAGIC: &[u8; 9] = b"SCONEKEY1";

/// Current format version.
const VERSION: u8 = 1;

/// Default Argon2id memory cost: 64 MiB.
///
/// Stored in the file as KiB, so the on-disk byte is 64 (64 * 1024 KiB
/// = 64 MiB).
pub const DEFAULT_M_COST_KIB: u32 = 64 * 1024;

/// Default Argon2id time cost (iterations).
pub const DEFAULT_T_COST: u32 = 3;

/// Argon2id output length: one XChaCha20-Poly1305 key.
const DERIVED_KEY_LEN: usize = 32;

/// Salt length in bytes.
const SALT_LEN: usize = 16;

/// XChaCha20 nonce length in bytes.
const NONCE_LEN: usize = 24;

/// Encrypted seed + Poly1305 tag length in bytes.
const CIPHERTEXT_LEN: usize = scone_crypto::SIGNING_KEY_SIZE + 16;

/// Total keyfile length in bytes.
pub const KEYFILE_LEN: usize = MAGIC.len() + 3 + SALT_LEN + NONCE_LEN + CIPHERTEXT_LEN;

/// Errors of the keystore.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file is not a keyfile at all (bad magic, wrong length…).
    #[error("invalid keyfile: {0}")]
    InvalidFile(String),

    /// The file uses a format version this build does not understand.
    #[error("unsupported keyfile version: {0}")]
    UnsupportedVersion(u8),

    /// The file declares out-of-bounds KDF parameters.
    #[error("invalid keyfile KDF parameters (m_cost={m_cost_kib} KiB, t_cost={t_cost})")]
    InvalidParams {
        /// Memory cost declared by the file, in KiB.
        m_cost_kib: u32,
        /// Time cost declared by the file.
        t_cost: u32,
    },

    /// The passphrase does not decrypt this file.
    #[error("wrong passphrase or corrupted ciphertext")]
    WrongPassphrase,

    /// The KDF rejected the declared parameters.
    #[error("KDF error: {0}")]
    Kdf(#[from] argon2::Error),

    /// The AEAD rejected the declared parameters.
    #[error("cipher error")]
    Cipher,

    /// Underlying filesystem error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// The destination file already exists ([`create`] refuses to
    /// overwrite; use [`create_overwriting`] for an explicit replace).
    #[error("keyfile already exists: {}", .0.display())]
    KeyfileExists(PathBuf),
}

/// Result alias for the keystore.
pub type Result<T> = std::result::Result<T, Error>;

/// A freshly generated keypair, as returned by [`create`].
///
/// The inner [`SigningKey`] zeroizes itself on drop (via the
/// `ed25519-dalek` default `zeroize` feature); no explicit derive is
/// needed here.
#[derive(Debug)]
pub struct GeneratedKey {
    /// The signing key (zeroized on drop by its own implementation).
    pub signing_key: SigningKey,
    /// Where it was persisted (encrypted).
    pub path: PathBuf,
}

/// Parsed header fields of a keyfile: KDF params, salt, nonce and the
/// ciphertext slice.
struct KeyfileParts<'a> {
    m_cost_kib: u32,
    t_cost: u32,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: &'a [u8],
}

/// Parses and validates the fixed-size header fields of a keyfile.
fn parse_keyfile(bytes: &[u8]) -> Result<KeyfileParts<'_>> {
    let invalid = |what: &str| Error::InvalidFile(what.to_string());

    if bytes.len() != KEYFILE_LEN {
        return Err(invalid(&format!(
            "expected {KEYFILE_LEN} bytes, found {}",
            bytes.len()
        )));
    }
    let magic = &bytes[..MAGIC.len()];
    if magic != MAGIC {
        return Err(invalid("bad magic"));
    }
    let mut cursor = MAGIC.len();

    let version = bytes[cursor];
    cursor += 1;
    if version != VERSION {
        return Err(Error::UnsupportedVersion(version));
    }

    // On-disk u8 m_cost = MiB; bounds-checked before any allocation.
    let m_cost_kib = u32::from(bytes[cursor]) * 1024;
    cursor += 1;
    let t_cost = u32::from(bytes[cursor]);
    cursor += 1;
    if m_cost_kib > DEFAULT_M_COST_KIB.max(1024) || t_cost == 0 || t_cost > 10 {
        return Err(Error::InvalidParams { m_cost_kib, t_cost });
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[cursor..cursor + SALT_LEN]);
    cursor += SALT_LEN;

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[cursor..cursor + NONCE_LEN]);
    cursor += NONCE_LEN;

    Ok(KeyfileParts {
        m_cost_kib,
        t_cost,
        salt,
        nonce,
        ciphertext: &bytes[cursor..],
    })
}

/// Derives the AEAD key from the passphrase without panicking.
///
/// The returned key is wrapped in [`Zeroizing`]: Drop wipes it on every
/// path out of the caller, including errors propagated with `?`.
fn try_derive_key(
    passphrase: &str,
    salt: &[u8; SALT_LEN],
    m_cost_kib: u32,
    t_cost: u32,
) -> Result<Zeroizing<[u8; DERIVED_KEY_LEN]>> {
    let params = Params::new(m_cost_kib, t_cost, Params::DEFAULT_P_COST, None)?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; DERIVED_KEY_LEN]);
    // On error, `out` is still zeroized when dropped.
    argon
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .map_err(Error::from)?;
    Ok(out)
}

/// Generates a new keypair and writes it encrypted at `path`.
///
/// Refuses to overwrite an existing file ([`Error::KeyfileExists`]):
/// silently replacing a key could destroy the only copy of an identity
/// the user still holds. Use [`create_overwriting`] for an explicit
/// replacement.
///
/// Creates parent directories as needed. On Unix the keyfile is created
/// with `0600` permissions (owner-only), regardless of the umask.
/// Returns the key material in memory (zeroized on drop of
/// [`GeneratedKey`]) alongside the path.
///
/// # Errors
///
/// See [`Error`]; I/O failures propagate as [`Error::Io`].
pub fn create<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<GeneratedKey> {
    write_keyfile(path.as_ref(), passphrase, CreateMode::NoClobber)
}

/// Like [`create`], but explicitly replaces an existing keyfile at
/// `path`.
///
/// # Errors
///
/// See [`Error`]; I/O failures propagate as [`Error::Io`].
pub fn create_overwriting<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<GeneratedKey> {
    write_keyfile(path.as_ref(), passphrase, CreateMode::Overwrite)
}

/// Whether [`write_keyfile`] may replace an existing file.
enum CreateMode {
    /// Fail with [`Error::KeyfileExists`] if the file exists.
    NoClobber,
    /// Replace the file if it exists.
    Overwrite,
}

/// Shared implementation of [`create`] and [`create_overwriting`].
fn write_keyfile(path: &Path, passphrase: &str, mode: CreateMode) -> Result<GeneratedKey> {
    // Random salt + nonce from the OS CSPRNG.
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    {
        use getrandom::rand_core::{TryRng, UnwrapErr};
        let mut rng = UnwrapErr(getrandom::SysRng);
        rng.try_fill_bytes(&mut salt)
            .map_err(|_| Error::Io(std::io::Error::other("os rng")))?;
        rng.try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Io(std::io::Error::other("os rng")))?;
    }

    let signing_key = SigningKey::generate();
    // Zeroizing: this seed copy is wiped on every path out of the
    // function, including the `?` on `encrypt` below.
    let seed = Zeroizing::new(signing_key.to_bytes());

    // Same as `seed`: wiped on drop, error paths included.
    let key = try_derive_key(passphrase, &salt, DEFAULT_M_COST_KIB, DEFAULT_T_COST)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let nonce = XNonce::from(nonce);
    let ciphertext = cipher
        .encrypt(&nonce, seed.as_slice())
        .map_err(|_| Error::Cipher)?;

    let mut file = Vec::with_capacity(KEYFILE_LEN);
    file.extend_from_slice(MAGIC);
    file.push(VERSION);
    file.push((DEFAULT_M_COST_KIB / 1024) as u8);
    file.push(DEFAULT_T_COST as u8);
    file.extend_from_slice(&salt);
    file.extend_from_slice(&nonce);
    file.extend_from_slice(&ciphertext);

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    write_private_file(path, &file, mode)?;

    Ok(GeneratedKey {
        signing_key,
        path: path.to_path_buf(),
    })
}

/// Writes keyfile `bytes` to `path` with owner-only permissions on Unix.
///
/// With [`CreateMode::NoClobber`] the existence check and the creation
/// are one atomic step (`O_EXCL` via `create_new`), so a concurrent
/// writer cannot be silently replaced either.
fn write_private_file(path: &Path, bytes: &[u8], mode: CreateMode) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true);
    match mode {
        CreateMode::NoClobber => {
            options.create_new(true);
        }
        CreateMode::Overwrite => {
            options.truncate(true);
        }
    }
    let mut file = match options.open(path) {
        Ok(f) => f,
        // `create_new` surfaces "file exists" as a raw io::Error; map
        // it to the typed keystore error.
        Err(e)
            if matches!(mode, CreateMode::NoClobber)
                && e.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            return Err(Error::KeyfileExists(path.to_path_buf()));
        }
        Err(e) => return Err(e.into()),
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // The `open(2)` mode is masked by the umask, so set the
        // permissions explicitly: 0600 (owner read/write only).
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        // Other platforms keep the default `OpenOptions` permissions.
    }

    use std::io::Write as _;
    file.write_all(bytes)?;
    Ok(())
}

/// Opens the keyfile at `path` and decrypts the signing key.
///
/// # Errors
///
/// [`Error::WrongPassphrase`] if the passphrase does not decrypt the
/// file; [`Error::InvalidFile`] / [`Error::UnsupportedVersion`] /
/// [`Error::InvalidParams`] for malformed files; never panics.
pub fn open<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<SigningKey> {
    let bytes = std::fs::read(path)?;
    let parts = parse_keyfile(&bytes)?;

    // Both are wiped by Drop on every path out of this function —
    // including the WrongPassphrase error below, which used to return
    // BEFORE the explicit zeroize (secret material stayed in memory).
    let key = try_derive_key(passphrase, &parts.salt, parts.m_cost_kib, parts.t_cost)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let nonce = XNonce::from(parts.nonce);
    let plaintext = Zeroizing::new(cipher.decrypt(&nonce, parts.ciphertext).map_err(|_| {
        // Authentication failure: wrong passphrase or tampered
        // ciphertext — indistinguishable by design.
        Error::WrongPassphrase
    })?);

    if plaintext.len() != scone_crypto::SIGNING_KEY_SIZE {
        return Err(Error::InvalidFile(format!(
            "decrypted seed has wrong length: {}",
            plaintext.len()
        )));
    }
    let mut seed = [0u8; scone_crypto::SIGNING_KEY_SIZE];
    seed.copy_from_slice(&plaintext);
    let signing_key = SigningKey::from_bytes(seed);
    seed.zeroize();
    Ok(signing_key)
}

/// One entry of a keystore directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyEntry {
    /// File name without the `.sconekey` extension (the identity name).
    pub name: String,
    /// Path of the keyfile.
    pub path: PathBuf,
}

/// Lists the identities stored in `dir` (files with the `.sconekey`
/// extension), sorted by name.
///
/// Non-directory `dir` yields an empty list rather than an error: an
/// absent keystore simply contains no keys yet.
///
/// # Errors
///
/// Only I/O errors from reading the directory propagate.
pub fn list<P: AsRef<Path>>(dir: P) -> Result<Vec<KeyEntry>> {
    let dir = dir.as_ref();
    let mut entries = Vec::new();

    let read_dir = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(entries),
        Err(e) => return Err(e.into()),
    };

    for entry in read_dir {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        if !ext.eq_ignore_ascii_case(KEYFILE_EXTENSION) {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        entries.push(KeyEntry {
            name: stem.to_string(),
            path,
        });
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use scone_crypto::SIGNING_KEY_SIZE;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn create_open_roundtrip() {
        let dir = tempdir();
        let path = dir.path().join("alice.sconekey");

        let generated = create(&path, "correct horse battery staple").expect("create");
        let opened = open(&path, "correct horse battery staple").expect("open");

        assert_eq!(opened.to_bytes(), generated.signing_key.to_bytes());
        assert_eq!(opened.public_key(), generated.signing_key.public_key());
        // Same key ⇒ same signature over a fixed payload.
        let msg = b"canonical payload";
        assert_eq!(
            opened.sign(msg).to_bytes(),
            generated.signing_key.sign(msg).to_bytes()
        );
    }

    #[test]
    fn file_is_not_plaintext_and_has_expected_length() {
        let dir = tempdir();
        let path = dir.path().join("alice.sconekey");
        let generated = create(&path, "passphrase").expect("create");

        let raw = std::fs::read(&path).expect("read");
        assert_eq!(raw.len(), KEYFILE_LEN);
        assert_eq!(&raw[..MAGIC.len()], MAGIC);
        assert_eq!(raw[MAGIC.len()], VERSION);
        // The seed must not appear anywhere in the file.
        let seed = generated.signing_key.to_bytes();
        assert!(!windows(&raw).any(|w| w == seed));

        fn windows(bytes: &[u8]) -> impl Iterator<Item = [u8; 32]> + '_ {
            bytes.windows(SIGNING_KEY_SIZE).map(|w| {
                let mut a = [0u8; 32];
                a.copy_from_slice(w);
                a
            })
        }
    }

    #[test]
    fn wrong_passphrase_is_a_distinct_error() {
        let dir = tempdir();
        let path = dir.path().join("alice.sconekey");
        create(&path, "right").expect("create");

        match open(&path, "wrong") {
            Err(Error::WrongPassphrase) => {}
            other => panic!("expected WrongPassphrase, got {other:?}"),
        }
    }

    #[test]
    fn corrupted_file_is_rejected_without_panic() {
        let dir = tempdir();
        let path = dir.path().join("alice.sconekey");
        create(&path, "pass").expect("create");
        let raw = std::fs::read(&path).expect("read");

        // Truncated file.
        let truncated = &raw[..raw.len() - 1];
        std::fs::write(dir.path().join("trunc.sconekey"), truncated).unwrap();
        assert!(matches!(
            open(dir.path().join("trunc.sconekey"), "pass"),
            Err(Error::InvalidFile(_))
        ));

        // Bit-flipped ciphertext byte → authentication failure.
        let mut flipped = raw.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        std::fs::write(dir.path().join("flip.sconekey"), flipped).unwrap();
        assert!(matches!(
            open(dir.path().join("flip.sconekey"), "pass"),
            Err(Error::WrongPassphrase)
        ));

        // Bit-flipped magic.
        let mut bad_magic = raw.clone();
        bad_magic[0] ^= 0x01;
        std::fs::write(dir.path().join("magic.sconekey"), bad_magic).unwrap();
        assert!(matches!(
            open(dir.path().join("magic.sconekey"), "pass"),
            Err(Error::InvalidFile(_))
        ));

        // Future version.
        let mut future = raw.clone();
        future[MAGIC.len()] = 99;
        std::fs::write(dir.path().join("future.sconekey"), future).unwrap();
        assert!(matches!(
            open(dir.path().join("future.sconekey"), "pass"),
            Err(Error::UnsupportedVersion(99))
        ));

        // Absurd KDF params must be rejected before any allocation.
        let mut greedy = raw;
        greedy[MAGIC.len() + 1] = 255; // 255 MiB
        std::fs::write(dir.path().join("greedy.sconekey"), greedy).unwrap();
        assert!(matches!(
            open(dir.path().join("greedy.sconekey"), "pass"),
            Err(Error::InvalidParams { .. })
        ));
    }

    #[test]
    fn empty_file_and_garbage_are_rejected() {
        let dir = tempdir();
        let p = dir.path().join("empty.sconekey");
        std::fs::write(&p, b"").unwrap();
        assert!(matches!(open(&p, "x"), Err(Error::InvalidFile(_))));

        let p2 = dir.path().join("garbage.sconekey");
        std::fs::write(&p2, vec![0x41; KEYFILE_LEN]).unwrap();
        assert!(matches!(open(&p2, "x"), Err(Error::InvalidFile(_))));
    }

    #[test]
    fn absent_file_is_an_io_error_not_a_panic() {
        let dir = tempdir();
        assert!(matches!(
            open(dir.path().join("missing.sconekey"), "x"),
            Err(Error::Io(_))
        ));
    }

    #[test]
    fn create_makes_parent_directories() {
        let dir = tempdir();
        let path = dir.path().join("nested/deeper/alice.sconekey");
        create(&path, "pass").expect("create");
        assert!(path.is_file());
        assert!(open(&path, "pass").is_ok());
    }

    #[test]
    fn create_refuses_to_overwrite_an_existing_keyfile() {
        let dir = tempdir();
        let path = dir.path().join("alice.sconekey");
        let first = create(&path, "pass").expect("first create");

        match create(&path, "other") {
            Err(Error::KeyfileExists(p)) => assert_eq!(p, path),
            other => panic!("expected KeyfileExists, got {other:?}"),
        }

        // The original key must be intact and still openable.
        let opened = open(&path, "pass").expect("original key intact");
        assert_eq!(opened.to_bytes(), first.signing_key.to_bytes());
    }

    #[test]
    fn create_overwriting_replaces_the_keyfile() {
        let dir = tempdir();
        let path = dir.path().join("alice.sconekey");
        let first = create(&path, "old-pass").expect("first create");

        let second = create_overwriting(&path, "new-pass").expect("overwrite");
        assert_ne!(second.signing_key.to_bytes(), first.signing_key.to_bytes());

        // Old passphrase no longer opens it, new one does.
        assert!(matches!(
            open(&path, "old-pass"),
            Err(Error::WrongPassphrase)
        ));
        let opened = open(&path, "new-pass").expect("new key opens");
        assert_eq!(opened.to_bytes(), second.signing_key.to_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn keyfile_is_created_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir();
        let path = dir.path().join("alice.sconekey");
        create(&path, "pass").expect("create");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "keyfile must be 0600, got {mode:o}");

        // Overwriting an existing (e.g. world-readable) file also
        // tightens the permissions back to 0600.
        let path2 = dir.path().join("bob.sconekey");
        create(&path2, "pass").expect("create");
        std::fs::set_permissions(&path2, std::fs::Permissions::from_mode(0o644)).unwrap();
        create_overwriting(&path2, "pass").expect("overwrite");
        let mode2 = std::fs::metadata(&path2)
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode2 & 0o777, 0o600, "overwritten keyfile must be 0600");
    }

    #[test]
    fn list_scans_sconekey_files_sorted() {
        let dir = tempdir();
        create(dir.path().join("bob.sconekey"), "p").unwrap();
        create(dir.path().join("alice.sconekey"), "p").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"not a key").unwrap();
        std::fs::create_dir(dir.path().join("carol.sconekey")).unwrap();

        let entries = list(dir.path()).expect("list");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["alice", "bob"]);
        assert!(entries[0].path.ends_with("alice.sconekey"));
    }

    #[test]
    fn list_of_absent_dir_is_empty() {
        let entries = list("/nonexistent-scone-keystore-dir").expect("no error");
        assert!(entries.is_empty());
    }

    #[test]
    fn keyfile_length_is_exact() {
        // 9 magic + 3 header + 16 salt + 24 nonce + 32 seed + 16 tag.
        assert_eq!(KEYFILE_LEN, 9 + 3 + 16 + 24 + 32 + 16);
    }
}
