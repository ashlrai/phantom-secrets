use crate::{AgentAction, Cli, Commands};
use clap::Parser;

#[test]
fn setup_requires_one_intent() {
    assert!(Cli::try_parse_from(["phantom", "agent", "setup", "--apply", "--dry-run"]).is_err());
    for flag in ["--apply", "--dry-run"] {
        assert!(Cli::try_parse_from(["phantom", "agent", "setup", flag]).is_ok());
    }
}

#[test]
fn doctor_preserves_explicit_probe_and_exit_policy() {
    let cli = Cli::try_parse_from([
        "phantom", "agent", "doctor", "--json", "--vault", "--strict",
    ])
    .unwrap();
    assert!(cli.json);
    assert!(matches!(
        cli.command,
        Commands::Agent {
            action: AgentAction::Doctor {
                vault: true,
                strict: true,
                ..
            }
        }
    ));
}
