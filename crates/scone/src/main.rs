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
//! per file — see `scone-keystore` and `/docs/technical/keystore.md`.
//!
//! The CLI is split into one module per command family:
//!
//! - `cli`: clap definitions (`Cli`, `Command`, subcommand enums);
//! - `error`: the `CliError` type shared by every command;
//! - `util`: hex helpers, passphrase handling, time;
//! - `identity`: `scone identity …` and keystore path helpers;
//! - `tx`: `scone tx …` and transaction build/sign helpers;
//! - `rpc`: relay RPC client helpers and the thin RPC commands
//!   (`status`, `submit`, `lookup`);
//! - `relay`: `scone relay …` (foreground daemon);
//! - `domain`: `scone domain …` / `scone record …` and the record
//!   file parser;
//! - `dig`: `scone dig …` (UDP DNS query helper).

mod cli;
mod dig;
mod domain;
mod error;
mod identity;
mod pow;
mod relay;
mod rpc;
mod tx;
mod util;

use std::process::ExitCode;

use clap::Parser;
use scone_core::{DomainId, DomainName};

use crate::cli::{Cli, Command};
use crate::dig::run_dig;
use crate::domain::{run_domain, run_record};
use crate::error::CliError;
use crate::identity::run_identity;
use crate::relay::run_relay;
use crate::rpc::{run_lookup, run_status, run_submit};
use crate::tx::run_tx;

// Test-only imports: the `tests` module at the bottom of this file
// exercises helpers from the command modules via `use super::*`.
#[cfg(test)]
use crate::domain::read_record_file;
#[cfg(test)]
use crate::identity::{keyfile_path, owner_id_of, validate_identity_name};
#[cfg(test)]
use crate::util::Passphrase;
#[cfg(test)]
use scone_core::{OwnerId, PublicKeyRef};
#[cfg(test)]
use scone_crypto::SigningKey;
#[cfg(test)]
use std::path::Path;

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
            network,
            data_dir,
            listen,
            bootstrap,
            rpc,
            dns,
            dns_upstream,
            anchor_key,
            anchor_passphrase_env,
        } => run_relay(
            network,
            data_dir,
            listen,
            bootstrap,
            rpc,
            dns,
            dns_upstream,
            anchor_key,
            anchor_passphrase_env,
        ),
        Command::Status { rpc } => run_status(rpc),
        Command::Submit { command } => run_submit(command),
        Command::Lookup { name, rpc } => run_lookup(name, rpc),
        Command::Domain { command } => run_domain(command),
        Command::Record { command } => run_record(command),
        Command::Dig { name, dns, qtype } => run_dig(name, dns, qtype),
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
            "register-domain",
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
            "update-domain",
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
