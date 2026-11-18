//! The phantom CLI exit-code table, documented in `phantom --help` and the
//! README.
//!
//! Agents branch on the process exit status instead of parsing human output.
//! The numbers keep the codes the CLI already used — clap's own status 2 for
//! usage errors and 1 for every other failure — so no script sees a status
//! move under it, and the new specific codes follow them. A failure carries
//! its code as a [`CodedError`] anywhere in its error chain, so later
//! `.context(...)` wrapping never hides it, and [`code_of`] is the one
//! lookup `main` performs.

use anyhow::Error;

/// The command failed for a reason without a more specific code: a finding
/// was reported (`phantom check`, `phantom audit verify`,
/// `phantom expiry enforce`), or an unexpected error.
pub(crate) const FAILURE: i32 = 1;

/// The arguments could not be used (unknown command, flag, or value), or a
/// `--strict` report found issues (`doctor --strict`, `why --strict`,
/// `fleet-status --strict`, `agent doctor --strict`).
pub(crate) const USAGE: i32 = 2;

/// Something named on the command line does not exist: a secret name, a
/// protected key, or the project's `.phantom.toml`.
pub(crate) const NOT_FOUND: i32 = 3;

/// The action was refused by policy before any effect: a headless run where
/// a trusted-terminal ceremony is required, a positional secret value, or a
/// cross-owner copy without its flag.
pub(crate) const NOT_ALLOWED: i32 = 4;

/// A required local service is unavailable: the encrypted-file vault is
/// locked, the local proxy could not start, or clipboard access failed.
pub(crate) const UNAVAILABLE: i32 = 5;

/// The plain-words table printed at the end of `phantom --help`.
pub(crate) const HELP_SECTION: &str = "Exit codes:
  0  success
  1  command failed (a finding was reported, or an unexpected error)
  2  bad usage (unknown command, flag, or value), or a --strict report found issues
  3  not found (no such secret, key, or .phantom.toml)
  4  refused by policy before any change (trusted-terminal ceremony, positional
     secret value, cross-owner copy without --allow-cross-owner)
  5  a needed local service is unavailable (locked vault, proxy could not
     start, clipboard refused)
141  the reader of stdout went away (phantom list | head)

phantom exec passes the wrapped command's own exit status through unchanged.";

/// A command failure that carries its documented exit code.
///
/// `Display` is the plain error text, so human output is unchanged; only the
/// process exit status moves.
#[derive(Debug)]
pub(crate) struct CodedError {
    code: i32,
    message: String,
    source: Option<Error>,
}

impl std::fmt::Display for CodedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CodedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref()
    }
}

impl CodedError {
    fn new(code: i32, message: impl Into<String>, source: Option<Error>) -> Self {
        Self {
            code,
            message: message.into(),
            source,
        }
    }
}

/// `not found` failure (exit [`NOT_FOUND`]): a named secret, key, or the
/// project's `.phantom.toml` does not exist.
pub(crate) fn not_found(message: impl Into<String>) -> Error {
    Error::from(CodedError::new(NOT_FOUND, message, None))
}

/// `refused` failure (exit [`NOT_ALLOWED`]): policy refused the action
/// before any effect.
pub(crate) fn not_allowed(message: impl Into<String>) -> Error {
    Error::from(CodedError::new(NOT_ALLOWED, message, None))
}

/// `unavailable` failure (exit [`UNAVAILABLE`]): a required local service is
/// unavailable.
pub(crate) fn unavailable(message: impl Into<String>) -> Error {
    Error::from(CodedError::new(UNAVAILABLE, message, None))
}

/// The documented code carried anywhere in `error`'s chain, if any.
pub(crate) fn code_of(error: &Error) -> Option<i32> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<CodedError>())
        .map(|coded| coded.code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_keep_the_documented_numbers() {
        assert_eq!(FAILURE, 1);
        assert_eq!(USAGE, 2);
        assert_eq!(NOT_FOUND, 3);
        assert_eq!(NOT_ALLOWED, 4);
        assert_eq!(UNAVAILABLE, 5);
    }

    #[test]
    fn help_section_lists_every_code_in_the_table() {
        for line in ["0  ", "1  ", "2  ", "3  ", "4  ", "5  ", "141  "] {
            assert!(
                HELP_SECTION.lines().any(|row| row.starts_with(line)),
                "the help table is missing code {line}"
            );
        }
    }

    #[test]
    fn coded_errors_classify_from_any_chain_depth() {
        let plain = anyhow::Error::new(std::io::Error::other("boom")).context("outer");
        assert_eq!(code_of(&plain), None, "unclassified stays unclassified");

        let deep = anyhow::Error::from(not_found("Secret 'NAME' not found in vault"))
            .context("Removal preflight failed; no secret value was read and no state changed");
        assert_eq!(code_of(&deep), Some(NOT_FOUND));
    }

    #[test]
    fn coded_error_display_is_the_plain_message_and_keeps_the_cause() {
        let coded = CodedError::new(
            UNAVAILABLE,
            "Clipboard access failed; refusing to fall back to plaintext stdout",
            Some(anyhow::Error::msg("clipboard busy")),
        );
        assert_eq!(
            coded.to_string(),
            "Clipboard access failed; refusing to fall back to plaintext stdout"
        );
        assert_eq!(
            coded
                .source()
                .map(|cause| cause.to_string())
                .as_deref(),
            Some("clipboard busy")
        );
    }
}
