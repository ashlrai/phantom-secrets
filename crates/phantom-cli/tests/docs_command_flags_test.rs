//! Docs drift guard for every place that shows phantom-secrets CLI commands.
//!
//! - README.md and top-level docs/*.md: `phantom ...` lines inside fenced
//!   code blocks.
//! - Web app sources (apps/web/src/**/*.ts, *.tsx) and the published
//!   apps/web/public/llms*.txt: every inline `phantom <command> ...` command,
//!   cut at the first quote, backtick, `<`, `{`, `|`, `;` or `)`.
//!
//! Each `--flag` must be accepted by that command's `--help`, and a second
//! word under a command that has subcommands must be one of them. Arguments
//! after ` -- ` (a wrapped program) and `# comments` are ignored, and so is a
//! `phantom` that is a `cargo --bin` target or part of a path or package name.
//! Internal and design notes (docs/internal, docs/design) are excluded on
//! purpose: they discuss proposed or removed flags.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn md_files() -> Vec<PathBuf> {
    let root = repo_root();
    let mut files = vec![root.join("README.md")];
    let mut docs: Vec<PathBuf> = std::fs::read_dir(root.join("docs"))
        .expect("read docs/")
        .map(|e| e.expect("docs entry").path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "md"))
        .collect();
    docs.sort();
    files.extend(docs);
    files
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|x| x == "ts" || x == "tsx") {
            out.push(path);
        }
    }
}

fn web_files() -> Vec<PathBuf> {
    let web = repo_root().join("apps/web");
    let mut files = Vec::new();
    walk(&web.join("src"), &mut files);
    for name in ["llms.txt", "llms-full.txt"] {
        files.push(web.join("public").join(name));
    }
    files.sort();
    files
}

struct Helper {
    home: tempfile::TempDir,
    cache: HashMap<Vec<String>, Option<String>>,
}

fn subcommands(help: &str) -> HashSet<String> {
    let Some(start) = help.find("Commands:") else {
        return HashSet::new();
    };
    help[start + "Commands:".len()..]
        .lines()
        .skip(1)
        .take_while(|l| l.starts_with("  "))
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

impl Helper {
    fn help(&mut self, words: &[String]) -> Option<String> {
        if let Some(hit) = self.cache.get(words) {
            return hit.clone();
        }
        let out = Command::new(env!("CARGO_BIN_EXE_phantom"))
            .args(words)
            .arg("--help")
            .env("HOME", self.home.path())
            .env("NO_COLOR", "1")
            .output()
            .expect("run phantom --help");
        let text = out
            .status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned());
        self.cache.insert(words.to_vec(), text.clone());
        text
    }

    /// Help text for the longest command path (up to two words) that exists.
    fn help_for(&mut self, words: &[String]) -> Option<String> {
        for n in (0..=words.len().min(2)).rev() {
            if let Some(text) = self.help(&words[..n]) {
                return Some(text);
            }
        }
        None
    }

    /// Check one `phantom ...` command. Returns problems; adds to `checked`.
    fn check(&mut self, words: &[String], flags: &[String], checked: &mut usize) -> Vec<String> {
        let mut problems = Vec::new();
        let Some(help) = self.help_for(words) else {
            return vec![format!("no help for `phantom {}`", words.join(" "))];
        };
        if words.len() >= 2 && is_word(&words[1]) {
            let parent = self.help(&words[..1]).unwrap_or_default();
            let subs = subcommands(&parent);
            if !subs.is_empty() && !subs.contains(&words[1]) {
                problems.push(format!(
                    "`{}` is not a subcommand of `phantom {}`",
                    words[1], words[0]
                ));
            }
        }
        for flag in flags {
            *checked += 1;
            if !mentions_flag(&help, flag) {
                problems.push(format!(
                    "`{flag}` not in `phantom {} --help`",
                    words.join(" ")
                ));
            }
        }
        problems
    }
}

fn is_word(t: &str) -> bool {
    t.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && t.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn mentions_flag(help: &str, flag: &str) -> bool {
    help.match_indices(flag).any(|(i, _)| {
        help[i + flag.len()..]
            .chars()
            .next()
            .is_none_or(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
    })
}

/// Split the text after `phantom ` into leading command words and `--flags`.
fn parse_args(rest: &str) -> (Vec<String>, Vec<String>) {
    let rest = rest.split(" #").next().unwrap_or(rest);
    let rest = rest.split(" -- ").next().unwrap_or(rest);
    let tokens: Vec<&str> = rest.split_whitespace().collect();
    let words = tokens
        .iter()
        .take_while(|t| !t.starts_with('-'))
        .map(|t| t.to_string())
        .collect();
    let flags = tokens
        .iter()
        .filter(|t| {
            t.strip_prefix("--")
                .and_then(|f| f.chars().next())
                .is_some_and(|c| c.is_ascii_lowercase())
        })
        .map(|t| {
            t.split('=')
                .next()
                .unwrap_or(t)
                .trim_end_matches(['.', ',', ':'])
                .to_string()
        })
        .collect();
    (words, flags)
}

fn doc_flags(line: &str) -> Option<(Vec<String>, Vec<String>)> {
    let line = line.trim();
    let line = line.strip_prefix("$ ").unwrap_or(line);
    let rest = line.strip_prefix("phantom ")?;
    Some(parse_args(rest))
}

/// Every inline `phantom <word> ...` command in a line of source or text.
fn inline_commands(line: &str) -> Vec<(String, Vec<String>, Vec<String>)> {
    let mut found = Vec::new();
    for (i, _) in line.match_indices("phantom ") {
        let before = &line[..i];
        let prev = before.chars().next_back();
        if prev.is_some_and(|c| c.is_ascii_alphanumeric() || "/.@-_".contains(c))
            || before.ends_with("--bin ")
        {
            continue;
        }
        let rest = &line[i + "phantom ".len()..];
        let end = rest
            .find(|c: char| "\"'`<>{}|;)\\".contains(c))
            .unwrap_or(rest.len());
        let (words, flags) = parse_args(&rest[..end]);
        found.push((format!("phantom {}", rest[..end].trim()), words, flags));
    }
    found
}

#[test]
fn documented_phantom_commands_match_cli_help() {
    let mut helper = Helper {
        home: tempfile::tempdir().expect("tempdir"),
        cache: HashMap::new(),
    };
    let top = subcommands(&helper.help(&[]).expect("phantom --help"));
    assert!(top.contains("copy"), "top-level command list not parsed");
    let mut checked = 0;
    let mut web_checked = 0;
    let mut drift = Vec::new();

    for file in md_files() {
        let text = std::fs::read_to_string(&file).expect("read doc");
        let rel = file
            .strip_prefix(repo_root())
            .unwrap_or(&file)
            .display()
            .to_string();
        let mut in_block = false;
        for (index, line) in text.lines().enumerate() {
            if line.trim_start().starts_with("```") {
                in_block = !in_block;
                continue;
            }
            if !in_block {
                continue;
            }
            let Some((words, flags)) = doc_flags(line) else {
                continue;
            };
            for p in helper.check(&words, &flags, &mut checked) {
                drift.push(format!("{rel}:{}: {p}: {}", index + 1, line.trim()));
            }
        }
    }

    for file in web_files() {
        let text = std::fs::read_to_string(&file).expect("read web source");
        let rel = file
            .strip_prefix(repo_root())
            .unwrap_or(&file)
            .display()
            .to_string();
        for (index, line) in text.lines().enumerate() {
            for (shown, words, flags) in inline_commands(line) {
                // Only commands that are clearly the CLI: first word is a real
                // top-level command. Prose such as "phantom tokens" is skipped.
                if words.first().is_none_or(|w| !top.contains(w)) {
                    continue;
                }
                for p in helper.check(&words, &flags, &mut web_checked) {
                    drift.push(format!("{rel}:{}: {p}: {shown}", index + 1));
                }
            }
        }
    }

    assert!(
        drift.is_empty(),
        "docs show commands the CLI does not accept:\n{}",
        drift.join("\n")
    );
    // Guard against a scan that silently matches nothing.
    assert!(
        checked >= 100,
        "only {checked} documented flags checked in markdown; scan is broken"
    );
    assert!(
        web_checked >= 20,
        "only {web_checked} flags checked in web sources; scan is broken"
    );
}

#[test]
fn flag_matcher_needs_a_whole_flag() {
    assert!(mentions_flag("      --rename <RENAME>  Rename", "--rename"));
    assert!(!mentions_flag("      --rename <RENAME>", "--ren"));
    assert!(!mentions_flag("      --to <TO>", "--as"));
    let (words, flags) = doc_flags("$ phantom copy KEY --to ../x --as Y # note --bogus").unwrap();
    assert_eq!(words, ["copy", "KEY"]);
    assert_eq!(flags, ["--to", "--as"]);
    let (_, flags) = doc_flags("phantom exec -- litellm --config c.yaml").unwrap();
    assert!(flags.is_empty());
    assert!(doc_flags("echo phantom --x").is_none());
}

#[test]
fn inline_extraction_skips_paths_and_cargo_targets() {
    let found = inline_commands(
        r#"<code>phantom setup --client claude</code> and "phantom check --staged.""#,
    );
    let shown: Vec<_> = found.iter().map(|f| f.0.as_str()).collect();
    assert_eq!(
        shown,
        ["phantom setup --client claude", "phantom check --staged."]
    );
    assert_eq!(found[1].2, ["--staged"]);
    assert!(inline_commands("cargo build --bin phantom --bin phantom-mcp").is_empty());
    assert!(inline_commands("see ashlrai/phantom secrets and @ashlr/phantom docs").is_empty());
    let mut helper = Helper {
        home: tempfile::tempdir().expect("tempdir"),
        cache: HashMap::new(),
    };
    let mut n = 0;
    let bad = helper.check(&["team".into(), "bogus-cmd".into()], &[], &mut n);
    assert_eq!(bad.len(), 1, "{bad:?}");
    assert!(
        helper.check(&["cloud".into(), "pull".into()], &["--env".into()], &mut n)[0]
            .contains("--env")
    );
}
