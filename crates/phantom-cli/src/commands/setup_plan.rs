//! `phantom setup --client <c> --dry-run`: a read-only plan of what setup
//! would write for Cursor, Windsurf, Gemini CLI and Codex.
//!
//! Nothing here writes, creates, locks or chmods anything. The plan reads the
//! config file once (refusing symlinks) and reports one of:
//! `add`, `unchanged`, `conflict` (a differing `phantom` entry exists) or
//! `invalid` (the file cannot be parsed or has an unexpected shape).
//!
//! The diff prints only the `command` and `args` of the entry. Other keys in
//! the file, including any `env` values, are never printed (only the names of
//! extra keys inside a conflicting entry).

use anyhow::{bail, Result};
use colored::Colorize;
use serde_json::Value;
use std::path::{Path, PathBuf};

use super::setup::{Client, McpCommand};

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Action {
    Add,
    Unchanged,
    Conflict {
        existing: String,
        extra_keys: Vec<String>,
    },
    Invalid(String),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Plan {
    pub path: PathBuf,
    pub exists: bool,
    pub action: Action,
    /// The entry setup would write, `command arg arg`.
    pub wanted: String,
}

fn render(command: &str, args: &[String]) -> String {
    let mut parts = vec![command.to_string()];
    parts.extend(args.iter().cloned());
    parts.join(" ")
}

fn relative_path(client: Client) -> Option<&'static str> {
    match client {
        Client::Cursor => Some(".cursor/mcp.json"),
        Client::Windsurf => Some(".codeium/windsurf/mcp_config.json"),
        Client::Gemini => Some(".gemini/settings.json"),
        Client::Codex => Some(".codex/config.toml"),
        Client::ClaudeCode => None,
    }
}

fn read_regular(path: &Path) -> Result<Option<String>, String> {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot stat: {e}")),
        Ok(m) if !m.is_file() => Err("not a regular file (symlinks are refused)".to_string()),
        Ok(_) => match std::fs::read(path) {
            Ok(bytes) => String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| "not valid UTF-8".to_string()),
            Err(e) => Err(format!("cannot read: {e}")),
        },
    }
}

fn judge(existing: Option<(String, Vec<String>, Vec<String>)>, mcp: &McpCommand) -> Action {
    match existing {
        None => Action::Add,
        Some((cmd, args, extra)) => {
            if cmd == mcp.command && args == mcp.args && extra.is_empty() {
                Action::Unchanged
            } else {
                Action::Conflict {
                    existing: render(&cmd, &args),
                    extra_keys: extra,
                }
            }
        }
    }
}

/// Plan for one non-Claude client under `home`. Read-only.
pub(crate) fn plan_client(home: &Path, client: Client, mcp: &McpCommand) -> Result<Plan> {
    let Some(rel) = relative_path(client) else {
        bail!("--dry-run is not available for Claude Code yet; use `phantom setup --client claude --print`");
    };
    let path = home.join(rel);
    let wanted = render(&mcp.command, &mcp.args);
    let invalid = |exists: bool, why: String| Plan {
        path: path.clone(),
        exists,
        action: Action::Invalid(why),
        wanted: wanted.clone(),
    };
    let text = match read_regular(&path) {
        Ok(t) => t,
        Err(why) => return Ok(invalid(true, why)),
    };
    let exists = text.is_some();
    let existing = match (client, text) {
        (_, None) => None,
        (Client::Codex, Some(t)) => {
            let doc: toml::Table = match toml::from_str(&t) {
                Ok(d) => d,
                Err(_) => return Ok(invalid(true, "not valid TOML".to_string())),
            };
            match doc.get("mcp_servers") {
                None => None,
                Some(toml::Value::Table(s)) => match s.get("phantom") {
                    None => None,
                    Some(toml::Value::Table(e)) => Some(entry_toml(e)),
                    Some(_) => {
                        return Ok(invalid(true, "mcp_servers.phantom is not a table".into()))
                    }
                },
                Some(_) => return Ok(invalid(true, "mcp_servers is not a table".into())),
            }
        }
        (_, Some(t)) => {
            let v: Value = match serde_json::from_str(&t) {
                Ok(v) => v,
                Err(_) => return Ok(invalid(true, "not valid JSON".to_string())),
            };
            let Some(obj) = v.as_object() else {
                return Ok(invalid(true, "top level is not an object".into()));
            };
            match obj.get("mcpServers") {
                None => None,
                Some(Value::Object(s)) => match s.get("phantom") {
                    None => None,
                    Some(Value::Object(e)) => Some(entry_json(e)),
                    Some(_) => {
                        return Ok(invalid(true, "mcpServers.phantom is not an object".into()))
                    }
                },
                Some(_) => return Ok(invalid(true, "mcpServers is not an object".into())),
            }
        }
    };
    Ok(Plan {
        path: path.clone(),
        exists,
        action: judge(existing, mcp),
        wanted,
    })
}

fn entry_json(e: &serde_json::Map<String, Value>) -> (String, Vec<String>, Vec<String>) {
    let cmd = e
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let args = e
        .get("args")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let mut extra: Vec<String> = e
        .keys()
        .filter(|k| k.as_str() != "command" && k.as_str() != "args")
        .cloned()
        .collect();
    extra.sort();
    (cmd, args, extra)
}

fn entry_toml(e: &toml::Table) -> (String, Vec<String>, Vec<String>) {
    let cmd = e
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let args = e
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let mut extra: Vec<String> = e
        .keys()
        .filter(|k| k.as_str() != "command" && k.as_str() != "args")
        .cloned()
        .collect();
    extra.sort();
    (cmd, args, extra)
}

pub(crate) fn print_plan(client: Client, plan: &Plan) {
    println!(
        "{} Dry run for {} ({}). Nothing will be written.",
        "->".blue().bold(),
        client.label().bold(),
        plan.path.display()
    );
    match &plan.action {
        Action::Add => {
            if !plan.exists {
                println!("   {} would create the file", "+".green().bold());
            }
            println!("   {} phantom: {}", "+".green().bold(), plan.wanted);
        }
        Action::Unchanged => println!("   {} already configured, no change", "-".dimmed()),
        Action::Conflict {
            existing,
            extra_keys,
        } => {
            println!("   {} phantom: {}", "-".red().bold(), existing);
            println!("   {} phantom: {}", "+".green().bold(), plan.wanted);
            if !extra_keys.is_empty() {
                println!(
                    "   {} extra keys in the existing entry (values not shown): {}",
                    "!".yellow().bold(),
                    extra_keys.join(", ")
                );
            }
            println!(
                "   {} `phantom setup --client` would replace this entry",
                "!".yellow().bold()
            );
        }
        Action::Invalid(why) => println!(
            "   {} config not usable ({}); setup would refuse and leave it untouched",
            "!".yellow().bold(),
            why
        ),
    }
}

/// Entry point for `--dry-run`. Never writes.
pub fn run_dry_run(client: Option<Client>) -> Result<()> {
    let client = client.unwrap_or(Client::ClaudeCode);
    let mcp = super::setup::mcp_command_spec()?;
    let home = phantom_core::home::home_dir_with_platform_fallback()?;
    let plan = plan_client(&home, client, &mcp)?;
    print_plan(client, &plan);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn mcp() -> McpCommand {
        McpCommand::for_test("/usr/local/bin/phantom", &["mcp", "serve"])
    }

    fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = vec![];
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push((p.clone(), std::fs::read(&p).unwrap()));
                }
            }
        }
        out.sort();
        out
    }

    #[test]
    fn missing_file_plans_add_and_creates_nothing() {
        let t = tempdir().unwrap();
        let p = plan_client(t.path(), Client::Cursor, &mcp()).unwrap();
        assert_eq!(p.action, Action::Add);
        assert!(!p.exists);
        assert!(snapshot(t.path()).is_empty());
    }

    #[test]
    fn differing_entry_is_a_conflict_and_file_is_untouched() {
        let t = tempdir().unwrap();
        let f = t.path().join(".gemini/settings.json");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(
            &f,
            r#"{"theme":"x","mcpServers":{"phantom":{"command":"/old","args":["a"],"env":{"K":"v"}}}}"#,
        )
        .unwrap();
        let before = snapshot(t.path());
        let p = plan_client(t.path(), Client::Gemini, &mcp()).unwrap();
        assert_eq!(
            p.action,
            Action::Conflict {
                existing: "/old a".into(),
                extra_keys: vec!["env".into()]
            }
        );
        assert_eq!(snapshot(t.path()), before);
    }

    #[test]
    fn identical_entry_is_unchanged() {
        let t = tempdir().unwrap();
        let f = t.path().join(".cursor/mcp.json");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(
            &f,
            r#"{"mcpServers":{"phantom":{"command":"/usr/local/bin/phantom","args":["mcp","serve"]}}}"#,
        )
        .unwrap();
        assert_eq!(
            plan_client(t.path(), Client::Cursor, &mcp())
                .unwrap()
                .action,
            Action::Unchanged
        );
    }

    #[test]
    fn invalid_json_and_wrong_shapes_are_invalid_and_preserved() {
        for body in [
            "",
            "{not json",
            "[]",
            r#"{"mcpServers":[]}"#,
            r#"{"mcpServers":{"phantom":1}}"#,
        ] {
            let t = tempdir().unwrap();
            let f = t.path().join(".codeium/windsurf/mcp_config.json");
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, body).unwrap();
            let p = plan_client(t.path(), Client::Windsurf, &mcp()).unwrap();
            assert!(matches!(p.action, Action::Invalid(_)), "body {body:?}");
            assert_eq!(std::fs::read_to_string(&f).unwrap(), body);
        }
    }

    #[test]
    fn codex_toml_add_conflict_unchanged() {
        let t = tempdir().unwrap();
        let f = t.path().join(".codex/config.toml");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, "model = \"x\"\n").unwrap();
        assert_eq!(
            plan_client(t.path(), Client::Codex, &mcp()).unwrap().action,
            Action::Add
        );
        std::fs::write(&f, "[mcp_servers.phantom]\ncommand = \"/old\"\nargs = []\n").unwrap();
        assert!(matches!(
            plan_client(t.path(), Client::Codex, &mcp()).unwrap().action,
            Action::Conflict { .. }
        ));
        std::fs::write(
            &f,
            "[mcp_servers.phantom]\ncommand = \"/usr/local/bin/phantom\"\nargs = [\"mcp\", \"serve\"]\n",
        )
        .unwrap();
        assert_eq!(
            plan_client(t.path(), Client::Codex, &mcp()).unwrap().action,
            Action::Unchanged
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_config_is_invalid() {
        let t = tempdir().unwrap();
        let real = t.path().join("real.json");
        std::fs::write(&real, "{}").unwrap();
        let f = t.path().join(".cursor/mcp.json");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&real, &f).unwrap();
        let p = plan_client(t.path(), Client::Cursor, &mcp()).unwrap();
        assert!(matches!(p.action, Action::Invalid(_)));
    }

    #[test]
    fn claude_is_refused() {
        let t = tempdir().unwrap();
        assert!(plan_client(t.path(), Client::ClaudeCode, &mcp()).is_err());
    }
}
