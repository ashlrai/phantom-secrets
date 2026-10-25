//! Doc-facts drift tests.
//!
//! Agent-facing docs restate facts that live in code: the MCP tool count, the
//! MCP tool names and parameters, the CLI command reference, the import
//! sources, the `phantom setup --client` values, and the completion shells.
//! These tests derive each fact from its source of truth (the clap command
//! tree, the importer dispatcher, and `mcp-registry/server.json`, which CI
//! pins to the runtime `tools/list`) and fail with the doc line to fix.
//! They read local files only: no network, no binary spawn.

use super::Cli;
use clap::CommandFactory;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_doc(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel))
        .unwrap_or_else(|error| panic!("read {rel}: {error}"))
        .replace("\r\n", "\n")
}

/// Runtime MCP catalog as mirrored into the registry: tool name -> parameter names.
fn registry_tools() -> BTreeMap<String, BTreeSet<String>> {
    let registry: serde_json::Value = serde_json::from_str(&read_doc("mcp-registry/server.json"))
        .expect("mcp-registry/server.json is JSON");
    registry["tools"]
        .as_array()
        .expect("registry has a tools array")
        .iter()
        .map(|tool| {
            let name = tool["name"].as_str().expect("tool name").to_string();
            let params = tool["inputSchema"]["properties"]
                .as_object()
                .map(|props| props.keys().cloned().collect())
                .unwrap_or_default();
            (name, params)
        })
        .collect()
}

/// The single line in `rel` containing `marker`, with its 1-based line number.
fn unique_line<'a>(rel: &str, doc: &'a str, marker: &str) -> (usize, &'a str) {
    let hits: Vec<(usize, &str)> = doc
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains(marker))
        .map(|(index, line)| (index + 1, line))
        .collect();
    assert_eq!(
        hits.len(),
        1,
        "{rel}: expected exactly one line containing {marker:?}, found {}; update this test's marker if the doc was reworded",
        hits.len()
    );
    hits[0]
}

/// Text between `start` and the next `end` on `line`.
fn between<'a>(rel: &str, line_no: usize, line: &'a str, start: &str, end: &str) -> &'a str {
    let rest = line
        .split_once(start)
        .unwrap_or_else(|| panic!("{rel}:{line_no}: missing {start:?}"))
        .1;
    rest.split_once(end)
        .unwrap_or_else(|| panic!("{rel}:{line_no}: missing {end:?} after {start:?}"))
        .0
}

fn words(list: &str, separators: &[char]) -> BTreeSet<String> {
    list.split(|c: char| separators.contains(&c))
        .map(|word| word.trim())
        .map(|word| word.strip_prefix("or ").unwrap_or(word))
        .map(|word| word.trim().trim_matches('`').trim())
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn assert_list(rel: &str, line_no: usize, claimed: BTreeSet<String>, truth: &BTreeSet<String>) {
    assert_eq!(
        &claimed, truth,
        "{rel}:{line_no} lists {claimed:?} but the code has {truth:?}; fix that doc line"
    );
}

fn possible_values(subcommand: &str, arg: &str) -> BTreeSet<String> {
    let command = Cli::command();
    command
        .find_subcommand(subcommand)
        .and_then(|sub| sub.get_arguments().find(|a| a.get_id() == arg))
        .unwrap_or_else(|| panic!("phantom {subcommand} has no `{arg}` argument"))
        .get_possible_values()
        .iter()
        .filter(|value| !value.is_hide_set())
        .map(|value| value.get_name().to_string())
        .collect()
}

/// Number immediately preceding `at` in `text`, if any (skipping one space or hyphen).
fn number_before(text: &str, at: usize) -> Option<usize> {
    let head = text[..at].strip_suffix([' ', '-', '\n'])?;
    let digits: String = head
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    digits.parse().ok()
}

/// Docs that state the MCP tool count in prose. Blog posts are dated
/// publications and stay out; every doc here must keep at least one claim.
const TOOL_COUNT_DOCS: &[&str] = &[
    "CLAUDE.md",
    "AGENTS.md",
    "README.md",
    "CONTRIBUTING.md",
    "ROADMAP.md",
    "mcp-registry/README.md",
    "npm/README.md",
    "npm-mcp/README.md",
    "docs/claude-code.md",
    "docs/codex.md",
    "docs/cursor.md",
    "docs/windsurf.md",
    "docs/llms-full.txt",
];

const TOOL_COUNT_SUFFIXES: &[&str] = &[
    "tool compatibility catalog",
    "tool MCP registry",
    "tool names",
    "tool schema",
    "unique tools",
    "unique tool names",
    "unique MCP tool names",
    "release-checked tools",
    "tools enforced",
];

#[test]
fn mcp_tool_count_claims_match_the_registry() {
    let expected = registry_tools().len();
    for rel in TOOL_COUNT_DOCS {
        let doc = read_doc(rel);
        let mut claims = 0;
        for suffix in TOOL_COUNT_SUFFIXES {
            for (at, _) in doc.match_indices(suffix) {
                if let Some(count) = number_before(&doc, at) {
                    let line_no = doc[..at].lines().count();
                    assert_eq!(
                        count, expected,
                        "{rel}:{line_no} says {count} MCP tools ({suffix:?}) but mcp-registry/server.json has {expected}; fix that doc line"
                    );
                    claims += 1;
                }
            }
        }
        for (at, _) in doc.match_indices("mcp-stdio-smoke.mjs target/debug/phantom-mcp ") {
            let rest = &doc[at + "mcp-stdio-smoke.mjs target/debug/phantom-mcp ".len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            let line_no = doc[..at].lines().count();
            assert_eq!(
                digits.parse::<usize>().ok(),
                Some(expected),
                "{rel}:{line_no} runs the MCP smoke with tool count {digits:?} but mcp-registry/server.json has {expected}; fix that doc line"
            );
            claims += 1;
        }
        assert!(
            claims > 0,
            "{rel} no longer states an MCP tool count this test recognizes; remove it from TOOL_COUNT_DOCS or update TOOL_COUNT_SUFFIXES"
        );
    }
}

/// Docs with `| Tool | Description | Parameters |` tables or `| Tool | ... |` lists.
const TOOL_TABLE_DOCS: &[&str] = &["AGENTS.md", "codex.md", "docs/claude-code.md"];

fn parse_params(cell: &str) -> BTreeSet<String> {
    let mut params = BTreeSet::new();
    let mut depth = 0usize;
    let mut item = String::new();
    for c in cell.chars().chain(std::iter::once(',')) {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                let name: String = item
                    .trim()
                    .chars()
                    .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    params.insert(name);
                }
                item.clear();
                continue;
            }
            _ => {}
        }
        if depth == 0 {
            item.push(c);
        }
    }
    params
}

#[test]
fn mcp_tool_tables_name_real_tools_with_exact_parameters() {
    let tools = registry_tools();
    for rel in TOOL_TABLE_DOCS {
        let doc = read_doc(rel);
        let mut has_params_column = false;
        let mut rows = 0;
        for (index, line) in doc.lines().enumerate() {
            let line_no = index + 1;
            if line.starts_with("| Tool ") {
                has_params_column = line.trim_end().ends_with("| Parameters |");
                continue;
            }
            let Some(rest) = line.strip_prefix("| `") else {
                continue;
            };
            let Some((name, _)) = rest.split_once('`') else {
                continue;
            };
            if !name.starts_with("phantom_") {
                continue;
            }
            rows += 1;
            let params = tools.get(name).unwrap_or_else(|| {
                panic!("{rel}:{line_no} documents MCP tool `{name}`, which is not in mcp-registry/server.json; fix or remove that row")
            });
            if has_params_column {
                let cells: Vec<&str> = line.trim_end().trim_end_matches('|').split(" | ").collect();
                let documented = parse_params(cells.last().copied().unwrap_or(""));
                assert_eq!(
                    &documented, params,
                    "{rel}:{line_no} lists parameters {documented:?} for `{name}` but its runtime schema has {params:?}; fix that row"
                );
            }
        }
        assert!(
            rows > 0,
            "{rel} has no MCP tool table rows; update TOOL_TABLE_DOCS"
        );
    }
}

#[test]
fn readme_command_reference_matches_the_cli() {
    let rel = "README.md";
    let doc = read_doc(rel);
    let section = doc
        .split_once("## Command Reference")
        .expect("README has a Command Reference section")
        .1;
    let section = section.split("\n## ").next().unwrap_or(section);
    let offset = doc.len() - doc.split_once("## Command Reference").unwrap().1.len();
    let first_line = doc[..offset].lines().count();

    let command = Cli::command();
    let visible: BTreeSet<String> = command
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set())
        .map(|sub| sub.get_name().to_string())
        .collect();

    let mut documented = BTreeSet::new();
    for (index, line) in section.lines().enumerate() {
        if !line.starts_with("| `phantom ") {
            continue;
        }
        let line_no = first_line + index;
        let first_cell = line.split(" | ").next().unwrap_or("");
        for invocation in first_cell.split("`phantom ").skip(1) {
            let invocation = invocation.split('`').next().unwrap_or("");
            let mut parts = invocation.split_whitespace();
            let top = parts.next().unwrap_or("");
            let sub = command.find_subcommand(top).unwrap_or_else(|| {
                panic!("{rel}:{line_no} documents `phantom {top}`, which is not a CLI command; fix that row")
            });
            documented.insert(top.to_string());
            if sub.has_subcommands() {
                if let Some(next) = parts
                    .next()
                    .filter(|w| w.starts_with(|c: char| c.is_ascii_lowercase()))
                {
                    for name in next.split('/') {
                        assert!(
                            sub.find_subcommand(name).is_some(),
                            "{rel}:{line_no} documents `phantom {top} {name}`, which is not a CLI command; fix that row"
                        );
                    }
                }
            }
        }
    }
    let missing: Vec<&String> = visible.difference(&documented).collect();
    assert!(
        missing.is_empty(),
        "README.md Command Reference (line {first_line}) is missing rows for {missing:?}; add them"
    );
}

#[test]
fn import_source_lists_match_the_importer_dispatcher() {
    let unknown = phantom_core::importers::import_from(
        "__doc_facts_unknown__",
        std::path::Path::new("missing"),
    )
    .expect_err("unknown source is rejected")
    .to_string();
    let supported = unknown
        .split_once("Supported: ")
        .expect("unknown-source error names the supported sources")
        .1;
    let truth = words(supported, &[',']);
    for source in &truth {
        let error = phantom_core::importers::import_from(
            source,
            &repo_root().join("__doc_facts_missing_file__"),
        )
        .expect_err("missing file is rejected")
        .to_string();
        assert!(
            !error.contains("Unknown import source"),
            "importer error lists `{source}` but the dispatcher rejects it"
        );
    }

    let agents = read_doc("AGENTS.md");
    let (no, line) = unique_line("AGENTS.md", &agents, "phantom import --from ");
    assert_list(
        "AGENTS.md",
        no,
        words(between("AGENTS.md", no, line, "--from ", " "), &['|']),
        &truth,
    );
    let (no, line) = unique_line("AGENTS.md", &agents, "importers (");
    assert_list(
        "AGENTS.md",
        no,
        words(between("AGENTS.md", no, line, "importers (", ")"), &['/']),
        &truth,
    );

    let claude = read_doc("CLAUDE.md");
    let (no, line) = unique_line("CLAUDE.md", &claude, "Each format (");
    assert_list(
        "CLAUDE.md",
        no,
        words(between("CLAUDE.md", no, line, "Each format (", ")"), &[',']),
        &truth,
    );

    let readme = read_doc("README.md");
    let (no, line) = unique_line("README.md", &readme, "| `phantom import` |");
    assert_list(
        "README.md",
        no,
        words(
            between("README.md", no, line, " or importing ", " data"),
            &[','],
        ),
        &truth,
    );

    // The troubleshooting format table has exactly one row per source.
    let rel = "docs/troubleshooting.md";
    let troubleshooting = read_doc(rel);
    let (header, _) = unique_line(rel, &troubleshooting, "| Source | Expected format |");
    let rows: Vec<String> = troubleshooting
        .lines()
        .skip(header + 1)
        .take_while(|line| line.starts_with('|'))
        .filter_map(|line| line.split('|').nth(1))
        .map(|cell| cell.trim().trim_matches('`').to_ascii_lowercase())
        .filter(|cell| !cell.is_empty() && !cell.starts_with('-'))
        .collect();
    let claimed: BTreeSet<String> = rows.iter().cloned().collect();
    assert_eq!(
        rows.len(),
        claimed.len(),
        "{rel}:{header} format table repeats a source"
    );
    assert_list(rel, header, claimed, &truth);
}

#[test]
fn setup_client_lists_match_the_cli() {
    let truth = possible_values("setup", "client");

    let readme = read_doc("README.md");
    let (no, line) = unique_line("README.md", &readme, "| `phantom setup` |");
    let list = between("README.md", no, line, "`--client ", ". ").replace("(default)", "");
    assert_list("README.md", no, words(&list, &[',']), &truth);

    let agents = read_doc("AGENTS.md");
    let (no, line) = unique_line(
        "AGENTS.md",
        &agents,
        "phantom setup --client claude           #",
    );
    let mut claimed = words(between("AGENTS.md", no, line, "(or ", ")"), &['|']);
    claimed.insert("claude".to_string());
    assert_list("AGENTS.md", no, claimed, &truth);
}

#[test]
fn completion_shell_list_matches_the_cli() {
    let truth = possible_values("completion", "shell");
    let readme = read_doc("README.md");
    let (no, line) = unique_line("README.md", &readme, "| `phantom completion <shell>` |");
    assert_list(
        "README.md",
        no,
        words(between("README.md", no, line, "(", ")"), &[',']),
        &truth,
    );
}
