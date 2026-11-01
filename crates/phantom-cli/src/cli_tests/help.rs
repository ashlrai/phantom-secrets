use crate::Cli;
use clap::{CommandFactory, Parser};

#[test]
fn add_line_flags_require_stdin_and_exclude_each_other() {
    for args in [
        &["phantom", "add", "NAME", "--multiline"][..],
        &["phantom", "add", "NAME", "--first-line"][..],
        &[
            "phantom",
            "add",
            "NAME",
            "--stdin",
            "--multiline",
            "--first-line",
        ][..],
    ] {
        assert!(
            Cli::try_parse_from(args).is_err(),
            "{args:?} must be rejected"
        );
    }
    for args in [
        &["phantom", "add", "NAME", "--stdin"][..],
        &["phantom", "add", "NAME", "--stdin", "--multiline"][..],
        &["phantom", "add", "NAME", "--stdin", "--first-line"][..],
    ] {
        assert!(Cli::try_parse_from(args).is_ok(), "{args:?} must parse");
    }
}

fn grouped_section(about: &str) -> &str {
    about
        .split("Commands by task:")
        .nth(1)
        .expect("long help must list commands by task")
}

#[test]
fn every_visible_subcommand_appears_in_the_task_groups() {
    let command = Cli::command();
    let about = command
        .get_long_about()
        .expect("phantom has long help")
        .to_string();
    let groups = grouped_section(&about);
    let listed: Vec<&str> = groups
        .split(|c: char| c.is_whitespace() || c == '·')
        .filter(|word| !word.is_empty())
        .collect();

    for subcommand in command.get_subcommands() {
        if subcommand.is_hide_set() {
            continue;
        }
        let name = subcommand.get_name();
        assert!(
            listed.contains(&name),
            "`phantom {name}` is missing from the grouped --help overview"
        );
    }
}

#[test]
fn grouped_overview_lists_only_real_subcommands() {
    let command = Cli::command();
    let about = command.get_long_about().unwrap().to_string();
    let names: Vec<String> = command
        .get_subcommands()
        .map(|subcommand| subcommand.get_name().to_string())
        .collect();
    for line in grouped_section(&about)
        .lines()
        .filter(|l| !l.trim().is_empty())
    {
        // Drop the group label ("Setup", "Daily use", "Sync & teams", ...).
        let commands = line
            .trim()
            .split_once("  ")
            .map_or("", |(_, rest)| rest)
            .trim();
        for word in commands.split('·').map(str::trim).filter(|w| !w.is_empty()) {
            assert!(
                names.iter().any(|name| name == word),
                "unknown command `{word}` in --help"
            );
        }
    }
}

/// Example blocks in doc comments are indented one-per-line. Without
/// `verbatim_doc_comment`, clap reflows them into one paragraph, so
/// `phantom import --help` printed every example on a single line.
#[test]
fn help_example_blocks_keep_one_example_per_line() {
    fn walk(command: &mut clap::Command, path: &str) {
        let rendered = command.render_long_help().to_string();
        for line in rendered.lines() {
            assert!(
                line.matches(path).count() <= 1,
                "`{path} --help` reflowed several examples into one line: {line}"
            );
        }
        let names: Vec<String> = command
            .get_subcommands()
            .filter(|sub| !sub.is_hide_set())
            .map(|sub| sub.get_name().to_string())
            .collect();
        for name in names {
            let sub = command
                .find_subcommand_mut(&name)
                .expect("listed subcommand");
            walk(sub, &format!("{path} {name}"));
        }
    }
    let mut command = Cli::command();
    command.build();
    let names: Vec<String> = command
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set())
        .map(|sub| sub.get_name().to_string())
        .collect();
    for name in names {
        let sub = command
            .find_subcommand_mut(&name)
            .expect("listed subcommand");
        walk(sub, &format!("phantom {name}"));
    }
}

#[test]
fn quick_start_commands_parse() {
    for argv in [
        vec!["phantom", "init"],
        vec!["phantom", "agent", "doctor"],
        vec!["phantom", "setup", "--client", "codex"],
        vec!["phantom", "exec", "--", "true"],
    ] {
        Cli::command()
            .try_get_matches_from(&argv)
            .unwrap_or_else(|error| panic!("{argv:?} must parse: {error}"));
    }
}
