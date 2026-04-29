use std::io;

use clap::CommandFactory;
use clap_complete::{generate, Shell};

use crate::Cli;

/// Print a shell-completion script for `shell` to stdout.
///
/// The generated script is meant to be sourced from the user's shell rc.
/// See the README's "Shell completion" section for the recommended
/// per-shell paths.
pub fn run(shell: Shell) -> anyhow::Result<()> {
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "phantom", &mut io::stdout());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `phantom completion <shell>` should print a non-empty script for every
    /// `Shell` variant that `clap_complete` knows about, without panicking
    /// or returning an error. We don't try to parse the generated text —
    /// that's `clap_complete`'s contract — but the smoke ensures the
    /// command stays wired up as the `Cli` definition evolves.
    #[test]
    fn completion_runs_for_every_shell_variant() {
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ] {
            run(shell).unwrap_or_else(|err| panic!("phantom completion {shell:?} failed: {err}"));
        }
    }
}
