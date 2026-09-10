//! Integration tests: run the real `scone` binary.

use std::process::Command;

fn scone() -> Command {
    Command::new(env!("CARGO_BIN_EXE_scone"))
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
fn bad_usage_fails_with_usage_on_stderr() {
    let out = scone().output().expect("binary runs");

    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).expect("stderr is UTF-8");
    assert!(stderr.contains("usage: scone show <name>"));
    let stdout = String::from_utf8(out.stdout).expect("stdout is UTF-8");
    assert!(stdout.is_empty(), "no output on stdout for usage errors");
}
