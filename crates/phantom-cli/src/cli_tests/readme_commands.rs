//! Inspect documentation against clap metadata only; never dispatch a command.
use crate::Cli;
use clap::{Command, CommandFactory};

// Check names rather than parsing argv: README placeholders and omitted required
// values are documentation, and must never become executable invocations.
fn check_example(root: &Command, example: &str) -> Result<(), String> {
    let mut command = root;
    let mut words = example.split_whitespace();
    if words.next() != Some("phantom") {
        return Ok(());
    }
    while let Some(word) = words.next() {
        let word = word.trim_matches(['[', ']', ',', ';']);
        if word == "--" {
            break; // The rest belongs to the child process.
        }
        if word.starts_with('-') {
            let flag = word.split('=').next().unwrap();
            let arg = command.get_arguments().find(|arg| {
                arg.get_long()
                    .is_some_and(|long| flag == format!("--{long}"))
                    || arg
                        .get_short()
                        .is_some_and(|short| flag == format!("-{short}"))
            });
            let arg = arg.ok_or_else(|| format!("unknown flag {flag} in {example}"))?;
            if arg.get_action().takes_values() && !word.contains('=') {
                words.next();
            }
        } else if let Some(sub) = command.find_subcommand(word) {
            command = sub;
        } else if command.get_subcommands().next().is_some()
            && !word.starts_with(['<', '['])
            && command.get_positionals().next().is_none()
        {
            return Err(format!("unknown subcommand {word} in {example}"));
        }
    }
    Ok(())
}

fn examples(markdown: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut fenced = false;
    for line in markdown.lines() {
        if line.starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            // Also catches commands after a pipe; shell comments are not examples.
            let line = line.split('#').next().unwrap();
            for part in line.split('|') {
                let part = part.trim().trim_start_matches("$ ");
                if part.starts_with("phantom ") {
                    result.push(part.to_owned());
                }
            }
        } else {
            // Table descriptions document flags separately from the command cell.
            if line.starts_with("| `phantom ") {
                let (command_cell, description) = line[1..].split_once('|').unwrap();
                let command = command_cell.split('`').nth(1).unwrap();
                for code in description.split('`').skip(1).step_by(2) {
                    if code.starts_with('-') {
                        result.push(format!("{command} {code}"));
                    }
                }
            }
            result.extend(
                line.split('`')
                    .skip(1)
                    .step_by(2)
                    .filter(|code| code.starts_with("phantom "))
                    .map(str::to_owned),
            );
        }
    }
    result
}

#[test]
fn readme_commands_and_flags_exist() {
    let mut root = Cli::command();
    root.build(); // Include inherited global flags and generated help/version flags.
    let examples = examples(include_str!("../../../../README.md"));
    assert!(
        examples.len() > 100,
        "README extraction unexpectedly lost coverage"
    );
    let errors: Vec<_> = examples
        .iter()
        .filter_map(|example| check_example(&root, example).err())
        .collect();
    assert!(errors.is_empty(), "{}", errors.join("\n"));
}

#[test]
fn readme_checker_rejects_unknown_commands_and_flags() {
    let mut root = Cli::command();
    root.build();
    for example in [
        "phantom nonexistent",
        "phantom team nonexistent",
        "phantom init --nonexistent",
        "phantom team list --nonexistent",
        "phantom status --staged", // A real flag on the wrong command.
    ] {
        assert!(check_example(&root, example).is_err(), "{example}");
    }
    for example in [
        "phantom exec -- child --nonexistent",
        "phantom workspace status --request <ID> [--json]",
        "phantom init --from example.env --dry-run",
    ] {
        assert!(check_example(&root, example).is_ok(), "{example}");
    }
    assert_eq!(
        examples("| `phantom status` | Output with `--nonexistent` |"),
        ["phantom status --nonexistent", "phantom status"]
    );
    assert_eq!(
        examples("`phantom typo`\n```sh\n$ phantom team typo # comment\n```"),
        ["phantom typo", "phantom team typo"]
    );
}

#[test]
fn every_command_has_help_text() {
    fn walk(command: &Command, path: &str, missing: &mut Vec<String>) {
        if command
            .get_about()
            .is_none_or(|about| about.to_string().trim().is_empty())
        {
            missing.push(path.to_owned());
        }
        for sub in command.get_subcommands() {
            walk(sub, &format!("{path} {}", sub.get_name()), missing);
        }
    }
    let mut missing = Vec::new();
    walk(&Cli::command(), "phantom", &mut missing);
    assert!(missing.is_empty(), "Missing help: {}", missing.join(", "));
}
