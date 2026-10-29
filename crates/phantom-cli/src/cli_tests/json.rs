use crate::Cli;
use clap::{CommandFactory, Parser};
/// Every visible command path, with placeholder values for its required
/// arguments, so `--json` routing can be checked command by command.
fn command_paths() -> Vec<(String, Vec<String>)> {
    fn required_args(command: &clap::Command) -> Vec<String> {
        let mut argv = Vec::new();
        for arg in command.get_arguments() {
            if !arg.is_required_set() || arg.is_global_set() {
                continue;
            }
            let value = arg
                .get_possible_values()
                .first()
                .map(|value| value.get_name().to_string())
                // "1" parses as both a string and a number.
                .unwrap_or_else(|| "1".to_string());
            if let Some(long) = arg.get_long() {
                argv.push(format!("--{long}"));
            }
            // Required switches such as `redact --stream` have no value.
            if arg.get_action().takes_values() {
                argv.push(value);
            }
        }
        argv
    }
    fn walk(command: &clap::Command, prefix: Vec<String>, out: &mut Vec<(String, Vec<String>)>) {
        let subs: Vec<&clap::Command> = command
            .get_subcommands()
            .filter(|sub| !sub.is_hide_set() && sub.get_name() != "help")
            .collect();
        if subs.is_empty() || !command.is_subcommand_required_set() {
            let mut argv = prefix.clone();
            argv.extend(required_args(command));
            out.push((prefix.join(" "), argv));
        }
        for sub in subs {
            let mut next = prefix.clone();
            next.push(sub.get_name().to_string());
            walk(sub, next, out);
        }
    }
    let mut command = Cli::command();
    command.build();
    let mut out = Vec::new();
    for sub in command.get_subcommands().filter(|sub| !sub.is_hide_set()) {
        if sub.get_name() == "help" {
            continue;
        }
        walk(sub, vec![sub.get_name().to_string()], &mut out);
    }
    out
}

/// Classify every command for the global `--json` flag. A new command, or
/// one that gains or loses JSON output, must update this list on purpose.
#[test]
fn global_json_is_routed_or_rejected_for_every_command() {
    let supported: &[&str] = &[
        "agent doctor",
        "agent report",
        "agent status",
        "audit alerts",
        "audit analytics",
        "audit anomalies",
        "audit export",
        "audit export-range",
        "audit incidents",
        "audit report",
        "audit show",
        "audit stats",
        "audit verify",
        "check",
        "cloud status",
        "crypto inventory",
        "doctor",
        "expiry enforce",
        // Not JSON output: its hidden legacy `--json` fails closed with
        // "Plaintext JSON export is disabled".
        "export",
        "grant add",
        "grant list",
        "grant revoke",
        "grant status",
        "leaks plan",
        "list",
        "secrets-expiring-soon",
        "status",
        "sync",
        "team list",
        "validate",
        "validate history",
        "validate schedule",
        "vault migrate-linux",
        "workspace plan",
        "why",
        "workspace status",
    ];
    let mut seen = Vec::new();
    for (name, path) in command_paths() {
        let mut argv = vec!["phantom".to_string(), "--json".to_string()];
        argv.extend(path.iter().cloned());
        // Conditionally required positionals (`import <FILE>`) are not
        // marked required; supply one when the bare form does not parse.
        let mut cli = crate::Cli::try_parse_from(&argv)
            .or_else(|_| {
                argv.push("1".to_string());
                crate::Cli::try_parse_from(&argv)
            })
            .unwrap_or_else(|error| panic!("{argv:?} must parse: {error}"));
        assert!(cli.json, "{argv:?}");
        let routed = crate::cli_json::apply_global_json(&mut cli.command);
        assert_eq!(
            routed.is_ok(),
            supported.contains(&name.as_str()),
            "`phantom {name} --json` classification changed: {routed:?}"
        );
        if let Err(message) = routed {
            assert!(
                message.starts_with(&format!("phantom {name}")),
                "rejection must name the command: {message}"
            );
        }
        seen.push(name);
    }
    for name in supported {
        assert!(seen.iter().any(|s| s == name), "unknown command `{name}`");
    }
    assert!(seen.iter().any(|s| s == "why"), "walk must reach `why`");
}

#[test]
fn global_json_sets_a_commands_own_json_flag() {
    let mut cli = crate::Cli::try_parse_from(["phantom", "--json", "list"]).unwrap();
    crate::cli_json::apply_global_json(&mut cli.command).unwrap();
    assert!(matches!(
        cli.command,
        crate::Commands::List { json: true, .. }
    ));
}
