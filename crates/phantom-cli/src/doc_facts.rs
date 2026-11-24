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
const TOOL_TABLE_DOCS: &[&str] = &["AGENTS.md", "docs/claude-code.md"];

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

/// Every visible command path in the clap tree, nested ones included
/// (`init`, `audit show`, `vault migrate-linux`). Hidden commands and clap's
/// built-in `help` are not user-facing and are left out.
fn cli_command_paths() -> BTreeSet<String> {
    fn walk(command: &clap::Command, prefix: &str, out: &mut BTreeSet<String>) {
        for sub in command.get_subcommands() {
            let name = sub.get_name();
            if sub.is_hide_set() || name == "help" {
                continue;
            }
            let path = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix} {name}")
            };
            out.insert(path.clone());
            walk(sub, &path, out);
        }
    }
    let mut out = BTreeSet::new();
    walk(&Cli::command(), "", &mut out);
    out
}

/// Each `phantom ...` invocation the README shows, as (line, text after `phantom `).
/// Covers fenced code lines (with an optional `$ ` prompt) and inline code spans.
fn readme_invocations(doc: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut in_block = false;
    for (index, line) in doc.lines().enumerate() {
        let line_no = index + 1;
        if line.trim_start().starts_with("```") {
            in_block = !in_block;
            continue;
        }
        if in_block {
            let code = line.trim_start().trim_start_matches("$ ");
            if let Some(rest) = code.strip_prefix("phantom ") {
                found.push((line_no, rest.to_string()));
            }
            continue;
        }
        // Odd-indexed pieces of a split on backticks are the code spans.
        for span in line.split('`').skip(1).step_by(2) {
            if let Some(rest) = span.strip_prefix("phantom ") {
                found.push((line_no, rest.to_string()));
            }
        }
    }
    found
}

/// The command path an invocation names, e.g. `audit show --last 5` -> `audit show`,
/// and the clap commands along that path (root first) for checking its flags.
/// Stops at the first flag, `--`, placeholder or argument that is not a subcommand.
/// Errors when a lowercase word sits where a subcommand is required but missing.
fn invocation_path<'a>(
    rest: &str,
    root: &'a clap::Command,
) -> Result<(String, Vec<&'a clap::Command>), String> {
    let mut chain = vec![root];
    let mut path: Vec<&str> = Vec::new();
    for token in rest.split_whitespace() {
        if !token.starts_with(|c: char| c.is_ascii_lowercase()) {
            break;
        }
        let current = chain[chain.len() - 1];
        if !current.has_subcommands() {
            break;
        }
        match current.find_subcommand(token) {
            Some(sub) => {
                path.push(sub.get_name());
                chain.push(sub);
            }
            None if path.is_empty() => {
                return Err(format!("`{token}` is not a phantom command"));
            }
            None => {
                return Err(format!(
                    "`{token}` is not a subcommand of `phantom {}`",
                    path.join(" ")
                ));
            }
        }
    }
    Ok((path.join(" "), chain))
}

/// Long flags an invocation passes before any standalone `--` or `# comment`.
fn invocation_flags(rest: &str) -> Vec<String> {
    rest.split_whitespace()
        .take_while(|t| *t != "--" && !t.starts_with('#'))
        .filter_map(|t| t.strip_prefix("--"))
        .filter(|f| f.starts_with(|c: char| c.is_ascii_lowercase()))
        .map(|f| {
            f.split('=')
                .next()
                .unwrap_or(f)
                .trim_end_matches(['.', ',', ';', ':', ')'])
                .to_string()
        })
        .collect()
}

/// Every command path must be documented in the README, and every documented
/// `phantom ...` invocation must name a real command. Catches both a new
/// command the README never mentions and a README line for a removed or
/// renamed one. Reads only local files and the in-process clap tree.
#[test]
fn readme_lists_every_cli_command_and_no_others() {
    let problems = readme_cli_drift(&read_doc("README.md"));
    assert!(
        problems.is_empty(),
        "README.md and the CLI disagree:\n{}",
        problems.join("\n")
    );
}

/// Drift between a README body and the clap tree: one line per problem.
/// Empty when every command path is shown and every shown invocation is real.
fn readme_cli_drift(doc: &str) -> Vec<String> {
    let command = Cli::command();
    let cli = cli_command_paths();
    assert!(
        cli.len() >= 60,
        "only {} command paths found in the clap tree; scan is broken",
        cli.len()
    );

    let mut documented = BTreeSet::new();
    let mut problems = Vec::new();
    for (line_no, rest) in readme_invocations(doc) {
        let (path, chain) = match invocation_path(&rest, &command) {
            Ok(found) => found,
            Err(error) => {
                problems.push(format!("README.md:{line_no}: {error}: `phantom {rest}`"));
                continue;
            }
        };
        for flag in invocation_flags(&rest) {
            // clap adds --help, and --version when a version is set, outside get_arguments().
            let built_in = flag == "help" || (flag == "version" && command.get_version().is_some());
            let known = built_in
                || chain.iter().any(|c| {
                    c.get_arguments()
                        .any(|arg| arg.get_long() == Some(flag.as_str()))
                });
            if !known {
                problems.push(format!(
                    "README.md:{line_no}: `--{flag}` is not a flag of `phantom {path}`: `phantom {rest}`"
                ));
            }
        }
        if !path.is_empty() {
            documented.insert(path);
        }
    }
    for path in &cli {
        let covered = documented
            .iter()
            .any(|d| d == path || d.starts_with(&format!("{path} ")));
        if !covered {
            problems.push(format!(
                "`phantom {path}` exists in the CLI but README.md never shows it; add it to the Command Reference"
            ));
        }
    }
    problems
}

#[test]
fn readme_drift_check_fails_both_ways() {
    // Missing: a README that shows only `init` must flag the other commands.
    let missing = readme_cli_drift("```bash\nphantom init\n```\n");
    assert!(
        missing
            .iter()
            .any(|p| p.contains("`phantom status` exists")),
        "{missing:?}"
    );
    assert!(!missing.iter().any(|p| p.contains("`phantom init` exists")));

    // Reverse: a README line for a command that was removed or renamed.
    let stale =
        readme_cli_drift("| `phantom frobnicate` | gone |\n| `phantom audit bogus` | gone |\n");
    assert!(
        stale
            .iter()
            .any(|p| p.contains("`frobnicate` is not a phantom command")),
        "{stale:?}"
    );
    assert!(
        stale
            .iter()
            .any(|p| p.contains("`bogus` is not a subcommand of `phantom audit`")),
        "{stale:?}"
    );
    let root = Cli::command();
    assert_eq!(
        invocation_path("audit show --last 5", &root).map(|(path, _)| path),
        Ok("audit show".to_string())
    );

    // Flags: a real flag (including one from the root, like the global --json)
    // passes; a stale one is named.
    let flags = readme_cli_drift(
        "```bash\nphantom check --log agent.jsonl --json\nphantom exec --scrub-output -- tool --nope\nphantom check --bogus-flag\n```\n",
    );
    assert!(
        flags
            .iter()
            .any(|p| p.contains("`--bogus-flag` is not a flag of `phantom check`")),
        "{flags:?}"
    );
    assert!(
        !flags.iter().any(|p| p.contains("`--json`")
            || p.contains("`--scrub-output`")
            || p.contains("`--nope`")),
        "{flags:?}"
    );
}

/// The README's one get-started path is numbered, has at most five steps, and
/// comes before the command list. Its commands are checked by the drift test above.
#[test]
fn readme_get_started_is_five_steps_or_fewer() {
    let doc = read_doc("README.md");
    let (_, after_heading) = doc
        .split_once("\n### Get started\n")
        .expect("README has a `### Get started` section under Quick start");
    let body = after_heading
        .split("\n### ")
        .next()
        .unwrap_or(after_heading);
    let steps = body
        .lines()
        .filter(|line| {
            line.split_once(". ").is_some_and(|(number, _)| {
                !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit())
            })
        })
        .count();
    assert!(
        (1..=5).contains(&steps),
        "README `### Get started` has {steps} numbered steps; keep it to five or fewer"
    );
    let quick_start = doc.split_once("\n## Quick start\n").expect("Quick start").1;
    assert!(
        quick_start
            .split("\n## ")
            .next()
            .unwrap_or(quick_start)
            .contains("### Everyday commands"),
        "README Quick start should keep the command list after Get started"
    );
}

/// Import sources as the importer dispatcher names them.
fn import_sources() -> BTreeSet<String> {
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
    words(supported, &[','])
}

#[test]
fn import_source_lists_match_the_importer_dispatcher() {
    let truth = import_sources();
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
fn import_help_states_each_source_format_and_a_1password_example_that_parses() {
    // `phantom import --help` is where the 1Password parse error sends users,
    // so it must state the expected format for every source, and the
    // 1Password example it shows must be accepted by the real parser.
    use phantom_core::importers::Importer;

    let truth = import_sources();
    let mut command = Cli::command();
    let help = command
        .find_subcommand_mut("import")
        .expect("phantom import exists")
        .render_long_help()
        .to_string();
    let rel = "phantom import --help";
    let (header, _) = unique_line(rel, &help, "Expected --file format per source");
    let listed: BTreeSet<String> = help
        .lines()
        .skip(header + 1)
        .take_while(|line| line.starts_with("  ") && !line.trim().is_empty())
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_ascii_lowercase)
        .collect();
    assert_list(rel, header, listed, &truth);

    let (no, line) = unique_line(rel, &help, "{\"STRIPE_SECRET_KEY\"");
    let parsed =
        phantom_core::importers::onepassword::OnePasswordImporter::parse(line.trim().as_bytes());
    assert!(
        parsed.is_ok_and(|map| map.len() == 2),
        "{rel}:{no} shows a 1Password example the importer refuses; fix it"
    );
    for fact in ["[A-Za-z_][A-Za-z0-9_]*", "op item get", "UTF-16"] {
        assert!(help.contains(fact), "{rel} no longer states {fact:?}");
    }

    // The jq flattening filter is printed in the help and in
    // docs/troubleshooting.md; the two copies must not drift apart.
    let jq_marker = "map({(.label): .value})";
    let (_, help_jq) = unique_line(rel, &help, jq_marker);
    let doc = "docs/troubleshooting.md";
    let troubleshooting = read_doc(doc);
    let (no, doc_jq) = unique_line(doc, &troubleshooting, jq_marker);
    assert_eq!(
        help_jq.trim(),
        doc_jq.trim(),
        "{doc}:{no} jq filter differs from `phantom import --help`"
    );

    // The troubleshooting 1Password row states the same contract.
    let (no, row) = unique_line(doc, &troubleshooting, "| `1password` |");
    for fact in [
        "{\"KEY\": \"value\"}",
        "[A-Za-z_][A-Za-z0-9_]*",
        "op item get",
    ] {
        assert!(
            row.contains(fact),
            "{doc}:{no} 1password row lacks {fact:?}"
        );
    }
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

/// Every visible top-level command must appear in the changelog (released
/// sections plus unfolded `changelog.d` fragments), so a shipped command never
/// goes unrecorded.
#[test]
fn changelog_records_every_visible_cli_command() {
    let mut history = read_doc("CHANGELOG.md");
    let fragments = repo_root().join("changelog.d");
    for entry in std::fs::read_dir(&fragments).expect("read changelog.d") {
        let path = entry.expect("fragment entry").path();
        if path.extension().is_some_and(|ext| ext == "md") {
            history.push_str(&std::fs::read_to_string(&path).expect("read fragment"));
        }
    }
    let missing: Vec<String> = Cli::command()
        .get_subcommands()
        .filter(|sub| !sub.is_hide_set())
        .map(|sub| sub.get_name().to_string())
        .filter(|name| !history.contains(&format!("phantom {name}")))
        .collect();
    assert!(
        missing.is_empty(),
        "CHANGELOG.md or changelog.d/ never mention these commands as `phantom <name>`: {missing:?}; add a fragment"
    );
}

/// Every `--flag` written after a `phantom <command> [subcommand]` invocation
/// in a code span or fenced block of the reader docs must be a real flag of
/// that command (or a global one), so a renamed or removed flag cannot stay
/// documented.
#[test]
fn documented_cli_flags_exist() {
    let root = Cli::command();
    let mut docs = vec!["README.md".to_string(), "llms.txt".to_string()];
    for entry in std::fs::read_dir(repo_root().join("docs")).expect("read docs") {
        let path = entry.expect("docs entry").path();
        if path.extension().is_some_and(|ext| ext == "md") {
            docs.push(format!(
                "docs/{}",
                path.file_name().unwrap().to_string_lossy()
            ));
        }
    }
    let mut problems = Vec::new();
    for rel in docs {
        let doc = read_doc(&rel);
        let mut fenced = false;
        for (index, line) in doc.lines().enumerate() {
            if line.trim_start().starts_with("```") {
                fenced = !fenced;
                continue;
            }
            // Inside a fence the whole line is code; outside, only backtick spans.
            let spans: Vec<&str> = if fenced {
                vec![line]
            } else {
                line.split('`').skip(1).step_by(2).collect()
            };
            for span in spans {
                for segment in span.split("phantom ").skip(1) {
                    if !span.contains(&format!("phantom {segment}")) {
                        continue;
                    }
                    let mut cmd = &root;
                    let mut words = segment.split_whitespace().peekable();
                    while let Some(word) = words.peek() {
                        match cmd.find_subcommand(word) {
                            Some(sub) => {
                                cmd = sub;
                                words.next();
                            }
                            None => break,
                        }
                    }
                    if std::ptr::eq(cmd, &root) {
                        continue;
                    }
                    // Everything after a bare `--` belongs to the wrapped command.
                    for word in words.take_while(|w| *w != "--") {
                        let Some(long) = word.strip_prefix("--") else {
                            continue;
                        };
                        let long = long
                            .split(['=', ',', ')', ';', '|', '>', '"', '\'', '.'])
                            .next()
                            .unwrap_or("");
                        if long.is_empty()
                            || !long.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                        {
                            continue;
                        }
                        let known = cmd.get_arguments().chain(root.get_arguments()).any(|arg| {
                            arg.get_long() == Some(long)
                                || arg.get_all_aliases().is_some_and(|a| a.contains(&long))
                        });
                        if !known && long != "help" && long != "version" {
                            problems.push(format!(
                                "{rel}:{} `phantom {} --{long}`: unknown flag",
                                index + 1,
                                cmd.get_name()
                            ));
                        }
                    }
                }
            }
        }
    }
    assert!(
        problems.is_empty(),
        "stale documented flags:\n{}",
        problems.join("\n")
    );
}
