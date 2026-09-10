//! Scone command-line binary.
//!
//! The whole logic lives in the pure [`run`] function so it can be unit
//! tested without spawning a process; [`main`] only wires arguments,
//! output streams and the exit code.

use std::process::ExitCode;

use scone_core::{DomainId, DomainName, SconeError};

/// Usage line reported on malformed arguments.
const USAGE: &str = "usage: scone show <name>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args) {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("scone: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Pure, testable CLI entry point.
///
/// Expected arguments: exactly `["show", <name>]`. Returns the line to
/// print on stdout, in the stable `name → hex64` format (the hex being
/// the [`Display`](std::fmt::Display) form of the [`DomainId`]).
///
/// # Errors
///
/// - [`SconeError::InvalidFormat`] on wrong arity, unknown subcommand or
///   missing name (usage error);
/// - the [`SconeError`] returned by [`DomainName::new`] for an invalid
///   name.
fn run(args: Vec<String>) -> Result<String, SconeError> {
    match args.as_slice() {
        [sub, name] if sub == "show" => {
            let domain = DomainName::new(name)?;
            let id = DomainId::from_name(&domain);
            Ok(format!("{} → {id}", domain.canonical()))
        }
        _ => Err(SconeError::InvalidFormat(USAGE.to_string())),
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

    #[test]
    fn show_valid_name_returns_id_line() {
        let out = run(vec!["show".into(), "example.uip".into()]).expect("valid invocation");
        assert_eq!(out, expected_line("example.uip"));
        let hex = out.rsplit(" → ").next().expect("hex part");
        assert_eq!(hex.len(), 64);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
    }

    #[test]
    fn show_invalid_name_is_rejected() {
        // Strict validation: uppercase labels must not be silently accepted.
        let err = run(vec!["show".into(), "EXAMPLE.uip".into()]).expect_err("invalid name");
        assert!(matches!(
            err,
            SconeError::InvalidDomain(_) | SconeError::InvalidTld(_)
        ));
    }

    #[test]
    fn usage_errors_are_rejected() {
        // No argument at all.
        assert!(run(Vec::new()).is_err());
        // Missing name.
        assert!(run(vec!["show".into()]).is_err());
        // Unknown subcommand.
        assert!(run(vec!["bogus".into(), "example.uip".into()]).is_err());
        // Too many arguments.
        assert!(run(vec!["show".into(), "example.uip".into(), "extra".into()]).is_err());
        // No subcommand, just a name.
        assert!(run(vec!["example.uip".into()]).is_err());
    }

    #[test]
    fn distinct_names_give_distinct_outputs() {
        let a = run(vec!["show".into(), "example.uip".into()]).expect("valid");
        let b = run(vec!["show".into(), "other.uip".into()]).expect("valid");
        assert_ne!(a, b);
        assert_eq!(b, expected_line("other.uip"));
    }

    #[test]
    fn usage_error_message_documents_the_interface() {
        let err = run(Vec::new()).expect_err("usage error");
        assert!(err.to_string().contains("usage: scone show <name>"));
    }
}
