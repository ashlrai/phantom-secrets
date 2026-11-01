use crate::{Cli, Commands, ValidateAction};
use clap::Parser;

#[test]
fn schedule_read_and_write_intents_are_exclusive() {
    for args in [vec!["hourly", "--status"], vec!["hourly", "--disable"]] {
        let mut argv = vec!["phantom", "validate", "schedule"];
        argv.extend(args);
        assert!(Cli::try_parse_from(argv).is_err());
    }
    for flag in ["--status", "--disable"] {
        assert!(Cli::try_parse_from(["phantom", "validate", "schedule", flag]).is_ok());
    }
}

#[test]
fn schedule_retains_interval_without_execution() {
    let cli = Cli::try_parse_from(["phantom", "validate", "schedule", "daily@2am"]).unwrap();
    assert!(matches!(
        cli.command,
        Commands::Validate {
            action: Some(ValidateAction::Schedule {
                interval: Some(interval),
                status: false,
                disable: false,
            }),
            ..
        } if interval == "daily@2am"
    ));
}
