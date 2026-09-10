//! Integration tests: run the real `scone` binary.

use std::process::Command;

fn scone() -> Command {
    Command::new(env!("CARGO_BIN_EXE_scone"))
}

/// Runs the binary with `HOME` pointing at a temp dir and the given
/// extra environment variables; returns (exit-success, stdout, stderr).
fn run_with_env(
    home: &std::path::Path,
    env_vars: &[(&str, &str)],
    args: &[&str],
) -> (bool, String, String) {
    let mut cmd = scone();
    cmd.args(args).env("HOME", home);
    for (k, v) in env_vars {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("binary runs");
    (
        out.status.success(),
        String::from_utf8(out.stdout).expect("stdout is UTF-8"),
        String::from_utf8(out.stderr).expect("stderr is UTF-8"),
    )
}

#[test]
fn show_valid_name_exits_zero_and_prints_hex() {
    let out = scone()
        .args(["show", "example.uip"])
        .output()
        .expect("binary runs");

    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).expect("stdout is UTF-8");
    let line = stdout.trim_end();
    let (name, hex) = line.split_once(" → ").expect("`name → hex` format");
    assert_eq!(name, "example.uip");
    assert_eq!(hex.len(), 64);
    assert!(
        hex.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
}

#[test]
fn show_invalid_name_fails_on_stderr() {
    let out = scone()
        .args(["show", "EXAMPLE.uip"])
        .output()
        .expect("binary runs");

    assert!(!out.status.success());
    assert!(out.status.code().is_some());
    let stderr = String::from_utf8(out.stderr).expect("stderr is UTF-8");
    assert!(!stderr.is_empty(), "error must be reported on stderr");
}

#[test]
fn bad_usage_fails_with_clap_usage_on_stderr() {
    let out = scone().output().expect("binary runs");

    assert!(!out.status.success());
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8(out.stderr).expect("stderr is UTF-8");
    assert!(stderr.contains("Usage:"), "clap usage expected: {stderr}");
    let stdout = String::from_utf8(out.stdout).expect("stdout is UTF-8");
    assert!(stdout.is_empty(), "no output on stdout for usage errors");
}

#[test]
fn identity_generate_list_show_roundtrip() {
    let home = tempfile::tempdir().expect("tempdir");
    let keystore = home.path().join(".scone/keys");

    // generate
    let (ok, stdout, stderr) = run_with_env(
        home.path(),
        &[("SCONE_TEST_PASS", "integration-passphrase")],
        &[
            "identity",
            "generate",
            "--name",
            "alice",
            "--passphrase-env",
            "SCONE_TEST_PASS",
        ],
    );
    assert!(ok, "generate must succeed (stderr: {stderr})");
    assert!(stdout.contains("generated identity 'alice'"));
    let pk_line = stdout
        .lines()
        .find(|l| l.starts_with("public key: "))
        .expect("public key line");
    let pk_hex = pk_line.strip_prefix("public key: ").expect("pk");
    assert_eq!(pk_hex.len(), 64);
    assert!(
        pk_hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    );
    let owner_line = stdout
        .lines()
        .find(|l| l.starts_with("owner id: "))
        .expect("owner id line");
    let owner_hex = owner_line.strip_prefix("owner id: ").expect("owner");
    assert_eq!(owner_hex.len(), 64);
    assert_ne!(owner_hex, pk_hex);
    assert!(keystore.join("alice.sconekey").is_file());

    // list
    let (ok, stdout, stderr) = run_with_env(home.path(), &[], &["identity", "list"]);
    assert!(ok, "list must succeed (stderr: {stderr})");
    assert!(stdout.contains("alice"), "list output: {stdout}");

    // show
    let (ok, stdout, stderr) = run_with_env(
        home.path(),
        &[("SCONE_TEST_PASS", "integration-passphrase")],
        &[
            "identity",
            "show",
            "--name",
            "alice",
            "--passphrase-env",
            "SCONE_TEST_PASS",
        ],
    );
    assert!(ok, "show must succeed (stderr: {stderr})");
    assert_eq!(stdout.lines().next(), Some("identity: alice"));
    // Same public key as printed at generation time.
    assert!(stdout.contains(pk_line), "stable pk across invocations");
    assert!(stdout.contains(owner_line), "stable owner id");
}

#[test]
fn identity_show_with_wrong_passphrase_fails_cleanly() {
    let home = tempfile::tempdir().expect("tempdir");
    run_with_env(
        home.path(),
        &[("GOOD_PASS", "right-one")],
        &[
            "identity",
            "generate",
            "--name",
            "alice",
            "--passphrase-env",
            "GOOD_PASS",
        ],
    );

    let (ok, _stdout, stderr) = run_with_env(
        home.path(),
        &[("BAD_PASS", "wrong-one")],
        &[
            "identity",
            "show",
            "--name",
            "alice",
            "--passphrase-env",
            "BAD_PASS",
        ],
    );
    assert!(!ok);
    assert!(stderr.contains("wrong passphrase"), "stderr: {stderr}");
    // Exit code 1 (clean failure), not a signal/panic.
    // (Checked implicitly by `ok == false` plus readable stderr.)
}

#[test]
fn identity_show_unknown_name_fails_cleanly() {
    let home = tempfile::tempdir().expect("tempdir");
    let (ok, _stdout, stderr) = run_with_env(
        home.path(),
        &[],
        &[
            "identity",
            "show",
            "--name",
            "ghost",
            "--passphrase-env",
            "SOME_PASS",
        ],
    );
    assert!(!ok);
    assert!(stderr.contains("ghost"), "stderr: {stderr}");
}

#[test]
fn identity_generate_with_unset_env_var_fails_cleanly() {
    let home = tempfile::tempdir().expect("tempdir");
    let (ok, _stdout, stderr) = run_with_env(
        home.path(),
        &[],
        &[
            "identity",
            "generate",
            "--name",
            "alice",
            "--passphrase-env",
            "SCONE_DEFINITELY_UNSET_VAR",
        ],
    );
    assert!(!ok);
    assert!(
        stderr.contains("SCONE_DEFINITELY_UNSET_VAR"),
        "stderr: {stderr}"
    );
    // No keyfile must have been written.
    assert!(!home.path().join(".scone/keys/alice.sconekey").exists());
}

#[test]
fn default_keystore_dir_respects_home() {
    // Covered end-to-end by `identity_generate_list_show_roundtrip`,
    // which relies on the default `$HOME/.scone/keys` directory.
}

#[test]
fn show_is_still_available_alongside_identity() {
    let home = tempfile::tempdir().expect("tempdir");
    let (ok, stdout, _stderr) = run_with_env(home.path(), &[], &["show", "other.uip"]);
    assert!(ok);
    assert!(stdout.trim_end().starts_with("other.uip → "));
}

#[test]
fn identity_generate_rejects_path_traversal_names() {
    let home = tempfile::tempdir().expect("tempdir");
    let keys = home.path().join(".scone/keys");
    std::fs::create_dir_all(&keys).expect("mkdir");

    for bad in ["../escaped", "..\\escaped", "a/b", "..", "."] {
        let (ok, _stdout, stderr) = run_with_env(
            home.path(),
            &[("SCONE_TEST_PASS", "p")],
            &[
                "identity",
                "generate",
                "--name",
                bad,
                "--passphrase-env",
                "SCONE_TEST_PASS",
            ],
        );
        assert!(!ok, "'{bad}' must be rejected (exit != 0)");
        assert!(stderr.contains("invalid identity name"), "stderr: {stderr}");
    }

    // Nothing written outside the keystore directory, and nothing
    // inside it either (all generations were refused).
    assert!(
        !home.path().join("escaped.sconekey").exists(),
        "traversal must not write outside the keys dir"
    );
    let stray: Vec<_> = std::fs::read_dir(&keys)
        .expect("keys dir readable")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("sconekey"))
        .collect();
    assert!(stray.is_empty(), "no keyfile must be created: {stray:?}");

    // The parent of the keystore must contain no keyfile either.
    let parent_entries: Vec<String> = std::fs::read_dir(home.path())
        .expect("home readable")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !parent_entries.iter().any(|n| n.ends_with(".sconekey")),
        "no keyfile escaped: {parent_entries:?}"
    );
}

#[test]
fn identity_generate_refuses_overwrite_and_force_replaces() {
    let home = tempfile::tempdir().expect("tempdir");
    let keyfile = home.path().join(".scone/keys/alice.sconekey");
    let env = &[("SCONE_TEST_PASS", "integration-passphrase")];
    let generate = |args: &[&str]| {
        let mut all = vec!["identity", "generate", "--name", "alice"];
        all.extend_from_slice(args);
        run_with_env(home.path(), env, &all)
    };

    // First generate: OK.
    let (ok, stdout, stderr) = generate(&["--passphrase-env", "SCONE_TEST_PASS"]);
    assert!(ok, "first generate (stderr: {stderr})");
    let first_pk = stdout
        .lines()
        .find(|l| l.starts_with("public key: "))
        .expect("pk line");

    // Second generate without --force: refused, keyfile untouched.
    let (ok, _stdout, stderr) = generate(&["--passphrase-env", "SCONE_TEST_PASS"]);
    assert!(!ok, "second generate must fail");
    assert!(stderr.contains("already exists"), "stderr: {stderr}");
    assert!(stderr.contains("--force"), "stderr: {stderr}");

    // The key still opens with the original passphrase: not replaced.
    let (ok, stdout, stderr) = run_with_env(
        home.path(),
        env,
        &[
            "identity",
            "show",
            "--name",
            "alice",
            "--passphrase-env",
            "SCONE_TEST_PASS",
        ],
    );
    assert!(ok, "original key intact (stderr: {stderr})");
    assert!(stdout.contains(first_pk), "same public key as before");

    // With --force: OK, new key material.
    let (ok, stdout, stderr) = generate(&["--passphrase-env", "SCONE_TEST_PASS", "--force"]);
    assert!(ok, "--force must succeed (stderr: {stderr})");
    let second_pk = stdout
        .lines()
        .find(|l| l.starts_with("public key: "))
        .expect("pk line");
    assert_ne!(first_pk, second_pk, "--force must generate a new key");
    assert!(keyfile.is_file());

    // The new key opens fine.
    let (ok, stdout, stderr) = run_with_env(
        home.path(),
        env,
        &[
            "identity",
            "show",
            "--name",
            "alice",
            "--passphrase-env",
            "SCONE_TEST_PASS",
        ],
    );
    assert!(ok, "replaced key opens (stderr: {stderr})");
    assert!(stdout.contains(second_pk));
}

#[cfg(unix)]
#[test]
fn identity_generate_creates_keyfile_with_0600_permissions() {
    let home = tempfile::tempdir().expect("tempdir");
    let (ok, _stdout, stderr) = run_with_env(
        home.path(),
        &[("SCONE_TEST_PASS", "p")],
        &[
            "identity",
            "generate",
            "--name",
            "alice",
            "--passphrase-env",
            "SCONE_TEST_PASS",
        ],
    );
    assert!(ok, "generate (stderr: {stderr})");

    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(home.path().join(".scone/keys/alice.sconekey"))
        .expect("keyfile exists")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "keyfile must be 0600, got {mode:o}");
}

// ---- relay / rpc commands -------------------------------------------

/// A port that is (almost certainly) closed: bind + drop.
fn closed_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind probe")
        .local_addr()
        .expect("local addr")
        .port()
}

#[test]
fn status_without_relay_is_a_clear_error() {
    let port = closed_port();
    let out = scone()
        .args(["status", "--rpc", &format!("127.0.0.1:{port}")])
        .output()
        .expect("binary runs");
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).expect("stderr is UTF-8");
    assert!(
        stderr.contains("cannot reach the relay") && stderr.contains("scone relay"),
        "stderr must point at the missing relay: {stderr}"
    );
}

#[test]
fn submit_without_relay_is_a_clear_error() {
    let port = closed_port();
    let out = scone()
        .args([
            "submit",
            "tx",
            "--hex",
            "00",
            "--rpc",
            &format!("127.0.0.1:{port}"),
        ])
        .output()
        .expect("binary runs");
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).expect("stderr is UTF-8");
    assert!(
        stderr.contains("cannot reach the relay"),
        "stderr: {stderr}"
    );
}

#[test]
fn lookup_without_relay_is_a_clear_error() {
    let port = closed_port();
    let out = scone()
        .args([
            "lookup",
            "example.uip",
            "--rpc",
            &format!("127.0.0.1:{port}"),
        ])
        .output()
        .expect("binary runs");
    assert!(!out.status.success());
    assert!(
        String::from_utf8(out.stderr)
            .expect("stderr")
            .contains("cannot reach the relay")
    );
}

#[test]
fn record_get_without_relay_is_a_clear_error() {
    let port = closed_port();
    let out = scone()
        .args([
            "record",
            "get",
            "example.uip",
            "--rpc",
            &format!("127.0.0.1:{port}"),
        ])
        .output()
        .expect("binary runs");
    assert!(!out.status.success());
    assert!(
        String::from_utf8(out.stderr)
            .expect("stderr")
            .contains("cannot reach the relay")
    );
}

#[test]
fn invalid_rpc_address_is_rejected_before_dialing() {
    let out = scone()
        .args(["status", "--rpc", "not-an-addr"])
        .output()
        .expect("binary runs");
    assert!(!out.status.success());
    assert!(
        String::from_utf8(out.stderr)
            .expect("stderr")
            .contains("invalid rpc address")
    );
}

#[test]
fn record_put_reads_the_file_or_fails_cleanly() {
    let port = closed_port();
    let out = scone()
        .args([
            "record",
            "put",
            "example.uip",
            "--file",
            "/nonexistent/record.hex",
            "--rpc",
            &format!("127.0.0.1:{port}"),
        ])
        .output()
        .expect("binary runs");
    assert!(!out.status.success());
    assert!(
        String::from_utf8(out.stderr)
            .expect("stderr")
            .contains("cannot read file")
    );
}

#[test]
fn relay_rejects_a_bad_bootstrap_multiaddr() {
    let home = tempfile::tempdir().expect("tempdir");
    let out = scone()
        .args([
            "relay",
            "--data-dir",
            home.path().to_str().expect("utf-8 path"),
            "--bootstrap",
            "not-a-multiaddr",
        ])
        .output()
        .expect("binary runs");
    assert!(!out.status.success());
    assert!(
        String::from_utf8(out.stderr)
            .expect("stderr")
            .contains("multiaddr")
    );
}

// ---- logging: -v/-vv levels, RUST_LOG override, clean stdout ----

/// The default level for one-shot commands is WARN: a plain
/// `scone identity list` must produce NO debug/info logs on stderr.
#[test]
fn default_identity_list_emits_no_logs_on_stderr() {
    let home = tempfile::tempdir().expect("tempdir");
    let (ok, stdout, stderr) = run_with_env(home.path(), &[], &["identity", "list"]);
    assert!(ok, "stderr: {stderr}");
    assert_eq!(stdout, "no identities\n");
    assert!(
        stderr.is_empty(),
        "no logs expected at WARN default: {stderr}"
    );
}

/// `-vv` (DEBUG) makes the debug-level logs of a simple command
/// appear on stderr — and still NOT on stdout.
#[test]
fn vv_makes_debug_logs_appear_on_stderr_only() {
    let home = tempfile::tempdir().expect("tempdir");
    let (ok, stdout, stderr) = run_with_env(home.path(), &[], &["-vv", "identity", "list"]);
    assert!(ok, "stderr: {stderr}");
    assert_eq!(stdout, "no identities\n");
    assert!(
        stderr.contains("DEBUG") && stderr.contains("listing identities"),
        "debug logs expected on stderr with -vv: {stderr}"
    );
}

/// `-v` (INFO) is below DEBUG: the same command stays quiet.
#[test]
fn v_info_level_stays_quiet_for_debug_events() {
    let home = tempfile::tempdir().expect("tempdir");
    let (ok, _stdout, stderr) = run_with_env(home.path(), &[], &["-v", "identity", "list"]);
    assert!(ok, "stderr: {stderr}");
    assert!(
        !stderr.contains("listing identities"),
        "no DEBUG logs at INFO level: {stderr}"
    );
}

/// `RUST_LOG=debug` overrides the flag-derived level, even without
/// any -v.
#[test]
fn rust_log_overrides_the_level_without_flags() {
    let home = tempfile::tempdir().expect("tempdir");
    let (ok, _stdout, stderr) =
        run_with_env(home.path(), &[("RUST_LOG", "debug")], &["identity", "list"]);
    assert!(ok, "stderr: {stderr}");
    assert!(
        stderr.contains("DEBUG") && stderr.contains("listing identities"),
        "RUST_LOG=debug must enable debug logs: {stderr}"
    );
}

/// `RUST_LOG` takes precedence over -vv too (here: silencing it).
#[test]
fn rust_log_takes_precedence_over_flags() {
    let home = tempfile::tempdir().expect("tempdir");
    let (ok, _stdout, stderr) = run_with_env(
        home.path(),
        &[("RUST_LOG", "error")],
        &["-vv", "identity", "list"],
    );
    assert!(ok, "stderr: {stderr}");
    assert!(
        !stderr.contains("listing identities"),
        "RUST_LOG=error must win over -vv: {stderr}"
    );
}

/// `-v` is accepted after the subcommand as well (global flag).
#[test]
fn verbose_flag_is_global_and_works_after_subcommand() {
    let home = tempfile::tempdir().expect("tempdir");
    let (ok, _stdout, stderr) = run_with_env(home.path(), &[], &["identity", "list", "-vv"]);
    assert!(ok, "stderr: {stderr}");
    assert!(
        stderr.contains("listing identities"),
        "global -vv after subcommand must work: {stderr}"
    );
}
