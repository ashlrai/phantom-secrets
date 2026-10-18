//! Read-only `phantom setup --status`: reports which AI clients have the
//! Phantom MCP server wired into their config.
//!
//! This module never writes, creates or locks anything. It only reads each
//! client's config file and looks for a `phantom` server entry.
//!
//! Gemini CLI config location and format: user settings are
//! `~/.gemini/settings.json` with a top-level `mcpServers` object (source:
//! https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md).

use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Format {
    /// JSON object with `mcpServers.<name>`.
    JsonMcpServers,
    /// TOML table `[mcp_servers.<name>]`.
    TomlMcpServers,
}

#[derive(Copy, Clone, Debug)]
enum Root {
    Home,
    Project,
}

struct ClientSpec {
    id: &'static str,
    label: &'static str,
    root: Root,
    relative: &'static str,
    format: Format,
}

/// Clients reported by `--status`. Order is the display order.
const CLIENTS: &[ClientSpec] = &[
    ClientSpec {
        id: "claude",
        label: "Claude Code",
        root: Root::Project,
        relative: ".mcp.json",
        format: Format::JsonMcpServers,
    },
    ClientSpec {
        id: "cursor",
        label: "Cursor",
        root: Root::Home,
        relative: ".cursor/mcp.json",
        format: Format::JsonMcpServers,
    },
    ClientSpec {
        id: "windsurf",
        label: "Windsurf",
        root: Root::Home,
        relative: ".codeium/windsurf/mcp_config.json",
        format: Format::JsonMcpServers,
    },
    ClientSpec {
        id: "codex",
        label: "Codex",
        root: Root::Home,
        relative: ".codex/config.toml",
        format: Format::TomlMcpServers,
    },
    ClientSpec {
        id: "gemini",
        label: "Gemini CLI",
        root: Root::Home,
        relative: ".gemini/settings.json",
        format: Format::JsonMcpServers,
    },
];

#[derive(Copy, Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum State {
    /// Config file has a `phantom` MCP server entry.
    Wired,
    /// Config file exists and parses, but has no `phantom` entry.
    NotWired,
    /// No config file at the expected path.
    NoConfig,
    /// Config file exists but could not be read or parsed.
    Unreadable,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct ClientStatus {
    pub id: &'static str,
    pub client: &'static str,
    pub state: State,
    pub config_path: String,
}

fn probe(spec: &ClientSpec, home: &Path, project: &Path) -> ClientStatus {
    let base: &Path = match spec.root {
        Root::Home => home,
        Root::Project => project,
    };
    let path: PathBuf = base.join(spec.relative);
    let state = match std::fs::read_to_string(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::NoConfig,
        Err(_) => State::Unreadable,
        Ok(text) => match has_phantom(spec.format, &text) {
            Some(true) => State::Wired,
            Some(false) => State::NotWired,
            None => State::Unreadable,
        },
    };
    ClientStatus {
        id: spec.id,
        client: spec.label,
        state,
        config_path: path.display().to_string(),
    }
}

/// `Some(wired)` when the document parsed, `None` when it did not.
fn has_phantom(format: Format, text: &str) -> Option<bool> {
    match format {
        Format::JsonMcpServers => {
            let v: serde_json::Value = serde_json::from_str(text).ok()?;
            let obj = v.as_object()?;
            Some(
                obj.get("mcpServers")
                    .and_then(|s| s.as_object())
                    .is_some_and(|s| s.contains_key("phantom")),
            )
        }
        Format::TomlMcpServers => {
            let t: toml::Table = toml::from_str(text).ok()?;
            Some(
                t.get("mcp_servers")
                    .and_then(|s| s.as_table())
                    .is_some_and(|s| s.contains_key("phantom")),
            )
        }
    }
}

/// Every client's config path in display order, as `(id, path, global)`.
/// `phantom doctor` checks exactly these clients; home-rooted ones are
/// skipped when there is no home directory.
pub(crate) fn client_config_paths(
    home: Option<&Path>,
    project: &Path,
) -> Vec<(&'static str, PathBuf, bool)> {
    CLIENTS
        .iter()
        .filter_map(|spec| match spec.root {
            Root::Project => Some((spec.id, project.join(spec.relative), false)),
            Root::Home => home.map(|home| (spec.id, home.join(spec.relative), true)),
        })
        .collect()
}

pub(crate) fn collect(home: &Path, project: &Path) -> Vec<ClientStatus> {
    CLIENTS.iter().map(|c| probe(c, home, project)).collect()
}

pub fn run(json: bool) -> Result<()> {
    let home = phantom_core::home::home_dir_with_platform_fallback()?;
    let project = std::env::current_dir()?;
    let rows = collect(&home, &project);
    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    println!("{} Phantom MCP wiring", "->".blue().bold());
    for r in &rows {
        let tag = match r.state {
            State::Wired => "wired".green().bold(),
            State::NotWired => "not wired".yellow().bold(),
            State::NoConfig => "no config".dimmed(),
            State::Unreadable => "unreadable".red().bold(),
        };
        println!("   {:<12} {:<10} {}", r.client, tag, r.config_path.dimmed());
    }
    let wired = rows.iter().filter(|r| r.state == State::Wired).count();
    println!("\n{wired}/{} clients wired", rows.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn state_of(rows: &[ClientStatus], id: &str) -> State {
        rows.iter().find(|r| r.id == id).unwrap().state
    }

    #[test]
    fn lists_all_five_clients() {
        let (h, p) = (tempdir().unwrap(), tempdir().unwrap());
        let rows = collect(h.path(), p.path());
        let ids: Vec<_> = rows.iter().map(|r| r.id).collect();
        assert_eq!(ids, ["claude", "cursor", "windsurf", "codex", "gemini"]);
        assert!(rows.iter().all(|r| r.state == State::NoConfig));
    }

    #[test]
    fn detects_wired_and_not_wired() {
        let (h, p) = (tempdir().unwrap(), tempdir().unwrap());
        std::fs::create_dir_all(h.path().join(".gemini")).unwrap();
        std::fs::write(
            h.path().join(".gemini/settings.json"),
            r#"{"theme":"x","mcpServers":{"phantom":{"command":"phantom","args":["mcp","serve"]}}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(h.path().join(".cursor")).unwrap();
        std::fs::write(
            h.path().join(".cursor/mcp.json"),
            r#"{"mcpServers":{"other":{"command":"x"}}}"#,
        )
        .unwrap();
        std::fs::create_dir_all(h.path().join(".codex")).unwrap();
        std::fs::write(
            h.path().join(".codex/config.toml"),
            "[mcp_servers.phantom]\ncommand = \"phantom\"\nargs = [\"mcp\", \"serve\"]\n",
        )
        .unwrap();
        std::fs::write(
            p.path().join(".mcp.json"),
            r#"{"mcpServers":{"phantom":{"command":"phantom"}}}"#,
        )
        .unwrap();
        let rows = collect(h.path(), p.path());
        assert_eq!(state_of(&rows, "gemini"), State::Wired);
        assert_eq!(state_of(&rows, "cursor"), State::NotWired);
        assert_eq!(state_of(&rows, "codex"), State::Wired);
        assert_eq!(state_of(&rows, "claude"), State::Wired);
        assert_eq!(state_of(&rows, "windsurf"), State::NoConfig);
    }

    #[test]
    fn invalid_config_is_unreadable_and_untouched() {
        let (h, p) = (tempdir().unwrap(), tempdir().unwrap());
        let f = h.path().join(".gemini/settings.json");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, "{ not json").unwrap();
        let rows = collect(h.path(), p.path());
        assert_eq!(state_of(&rows, "gemini"), State::Unreadable);
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "{ not json");
    }

    #[test]
    fn status_never_creates_files() {
        let (h, p) = (tempdir().unwrap(), tempdir().unwrap());
        let _ = collect(h.path(), p.path());
        assert_eq!(std::fs::read_dir(h.path()).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(p.path()).unwrap().count(), 0);
    }

    #[test]
    fn json_shape_is_stable() {
        let (h, p) = (tempdir().unwrap(), tempdir().unwrap());
        let rows = collect(h.path(), p.path());
        let v = serde_json::to_value(&rows).unwrap();
        assert_eq!(v[4]["id"], "gemini");
        assert_eq!(v[4]["state"], "no_config");
        assert!(v[4]["config_path"]
            .as_str()
            .unwrap()
            .ends_with(".gemini/settings.json"));
    }

    /// Contract with the phantom (TS) shared client table. The fixture is a
    /// vendored copy of phantom's `docs/client-table.json`; refresh it when that
    /// file changes. Claude Code is compared by id only: the Rust side reports
    /// the project `.mcp.json`, the TS side `~/.claude.json`.
    #[test]
    fn matches_phantom_client_table_contract() {
        let table: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/client-table.json")).unwrap();
        assert_eq!(table["version"], 1);
        let clients = table["clients"].as_array().unwrap();
        let mut table_ids: Vec<&str> = clients.iter().map(|c| c["id"].as_str().unwrap()).collect();
        let mut rust_ids: Vec<&str> = CLIENTS.iter().map(|c| c.id).collect();
        table_ids.sort();
        rust_ids.sort();
        assert_eq!(rust_ids, table_ids, "client id lists drifted");
        for spec in CLIENTS.iter().filter(|c| c.id != "claude") {
            let row = clients.iter().find(|c| c["id"] == spec.id).unwrap();
            assert_eq!(row["displayName"], spec.label, "{}", spec.id);
            let segs: Vec<&str> = row["configPath"]["linux"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap())
                .collect();
            assert_eq!(segs.join("/"), spec.relative, "{} path", spec.id);
            let fmt = match spec.format {
                Format::JsonMcpServers => "json-mcpServers",
                Format::TomlMcpServers => "toml-mcp_servers",
            };
            assert_eq!(row["format"], fmt, "{} format", spec.id);
        }
    }
}
