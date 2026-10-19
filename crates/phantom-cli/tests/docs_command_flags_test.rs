//! Docs drift guard: every `--flag` on a `phantom ...` line inside a fenced
//! code block of README.md or a top-level docs/*.md page must be accepted by
//! that command's `--help`. Internal and design notes (docs/internal,
//! docs/design) are excluded on purpose: they discuss proposed or removed
//! flags. Arguments after a ` -- ` separator belong to the wrapped program and
//! are ignored, as are `# comments`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn doc_files() -> Vec<PathBuf> {
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

struct Helper {
    home: tempfile::TempDir,
    cache: HashMap<Vec<String>, Option<String>>,
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
}

fn mentions_flag(help: &str, flag: &str) -> bool {
    help.match_indices(flag).any(|(i, _)| {
        help[i + flag.len()..]
            .chars()
            .next()
            .is_none_or(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
    })
}

fn doc_flags(line: &str) -> Option<(Vec<String>, Vec<String>)> {
    let line = line.trim();
    let line = line.strip_prefix("$ ").unwrap_or(line);
    let rest = line.strip_prefix("phantom ")?;
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
        .map(|t| t.split('=').next().unwrap_or(t).to_string())
        .collect();
    Some((words, flags))
}

#[test]
fn documented_phantom_flags_exist_in_cli_help() {
    let mut helper = Helper {
        home: tempfile::tempdir().expect("tempdir"),
        cache: HashMap::new(),
    };
    let mut checked = 0;
    let mut drift = Vec::new();
    for file in doc_files() {
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
            let Some(help) = helper.help_for(&words) else {
                drift.push(format!(
                    "{rel}:{}: no help for `phantom {}`",
                    index + 1,
                    words.join(" ")
                ));
                continue;
            };
            for flag in flags {
                checked += 1;
                if !mentions_flag(&help, &flag) {
                    drift.push(format!(
                        "{rel}:{}: `{flag}` not in `phantom {} --help`: {}",
                        index + 1,
                        words.join(" "),
                        line.trim()
                    ));
                }
            }
        }
    }
    assert!(
        drift.is_empty(),
        "docs use flags the CLI does not accept:\n{}",
        drift.join("\n")
    );
    // Guard against the scan silently matching nothing (140 at the time of writing).
    assert!(
        checked >= 100,
        "only {checked} documented flags checked; scan is broken"
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
