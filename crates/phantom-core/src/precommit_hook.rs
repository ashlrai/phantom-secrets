//! Canonical, network-free Phantom pre-commit hook generation.
//!
//! Git executes hooks through a POSIX-compatible shell on Phantom's supported
//! platforms (including Git for Windows). The generated block deliberately
//! resolves only an already-installed `phantom` executable from `PATH`; it
//! never invokes a package runner that could download code during a commit.

/// Start marker used to find and safely repair Phantom-owned hook blocks.
pub const HOOK_MARKER: &str = "# Phantom Secrets pre-commit hook";

/// End marker used by current generators to bound future repairs.
pub const HOOK_END_MARKER: &str = "# End Phantom Secrets pre-commit hook";

const LEGACY_NPX_COMMAND: &str = "npx phantom-secrets check --staged";

/// The current Phantom-owned hook block.
pub const HOOK_BLOCK: &str = r#"# Phantom Secrets pre-commit hook
# Uses an installed local Phantom binary; never downloads packages.
if ! command -v phantom >/dev/null 2>&1; then
  echo "Phantom pre-commit hook: 'phantom' is required but was not found on PATH." >&2
  echo "Install a verified Phantom release, then retry the commit." >&2
  exit 1
fi
phantom check --staged || exit $?
# End Phantom Secrets pre-commit hook"#;

/// Describes whether a caller needs to write the returned hook content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookChange {
    Unchanged,
    Installed,
    Repaired,
}

/// Result of ensuring a hook contains exactly one current Phantom block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookUpdate {
    pub content: String,
    pub change: HookChange,
}

/// Return true only when the complete current block is the first executable
/// content in the hook. Merely finding the block is insufficient: a user hook
/// can contain an earlier `exit`, making an appended Phantom check unreachable.
pub fn is_current(content: &str) -> bool {
    let lines: Vec<&str> = content.lines().collect();
    let block_lines: Vec<&str> = HOOK_BLOCK.lines().collect();
    lines.first().is_some_and(|line| line.starts_with("#!"))
        && lines.get(1..1 + block_lines.len()) == Some(block_lines.as_slice())
        && lines
            .iter()
            .filter(|line| line.trim() == HOOK_MARKER)
            .count()
            == 1
        && !lines
            .iter()
            .any(|line| is_network_capable_phantom_line(line))
}

/// Return true when a known current or legacy Phantom block is present.
pub fn has_phantom_block(content: &str) -> bool {
    content.contains(HOOK_MARKER)
        || content
            .lines()
            .any(|line| line.trim() == LEGACY_NPX_COMMAND || is_network_capable_phantom_line(line))
}

/// Install the canonical block, or replace a known stale Phantom block.
///
/// Non-Phantom hook content is retained in its original order. The canonical
/// block is placed immediately after the shebang so it cannot be bypassed by an
/// earlier `exit`. Current blocks are idempotent. Legacy marker blocks and
/// network-capable Phantom runner lines are removed before the canonical block
/// is installed.
pub fn ensure(content: &str) -> HookUpdate {
    if is_current(content) {
        return HookUpdate {
            content: content.to_string(),
            change: HookChange::Unchanged,
        };
    }

    let lines: Vec<&str> = content.lines().collect();
    let had_phantom = has_phantom_block(content) || content.contains(HOOK_BLOCK);
    let mut preserved = Vec::new();
    let mut index = usize::from(lines.first().is_some_and(|line| line.starts_with("#!")));
    while index < lines.len() {
        let line = lines[index];
        if line.trim() == HOOK_MARKER {
            index = stale_block_end(&lines, index, true);
            continue;
        }
        if line.trim() == LEGACY_NPX_COMMAND || is_network_capable_phantom_line(line) {
            index = stale_block_end(&lines, index, false);
            continue;
        }
        preserved.push(line);
        index += 1;
    }

    let shebang = lines
        .first()
        .filter(|line| line.starts_with("#!"))
        .copied()
        .unwrap_or("#!/bin/sh");
    let mut output = format!("{shebang}\n{HOOK_BLOCK}\n");
    if !preserved.is_empty() {
        output.push('\n');
        append_lines(&mut output, &preserved);
    }
    let change = if had_phantom {
        HookChange::Repaired
    } else {
        HookChange::Installed
    };

    HookUpdate {
        content: output,
        change,
    }
}

fn append_lines(output: &mut String, lines: &[&str]) {
    for line in lines {
        output.push_str(line);
        output.push('\n');
    }
}

fn stale_block_end(lines: &[&str], start: usize, has_marker: bool) -> usize {
    if has_marker {
        if let Some(relative_end) = lines[start..]
            .iter()
            .position(|line| line.trim() == HOOK_END_MARKER)
        {
            return start + relative_end + 1;
        }
    }

    let mut end = start + 1;
    if has_marker {
        while end < lines.len() && is_owned_legacy_line(lines[end]) {
            end += 1;
        }
    } else if end < lines.len() && lines[end].trim() == "exit $?" {
        end += 1;
    }
    end
}

fn is_network_capable_phantom_line(line: &str) -> bool {
    let normalized = line.trim().to_ascii_lowercase();
    normalized.contains("phantom")
        && normalized
            .split_whitespace()
            .map(|token| token.trim_matches(|c: char| !c.is_ascii_alphanumeric()))
            .any(|token| matches!(token, "npx" | "npm" | "curl"))
}

fn is_owned_legacy_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty()
        || trimmed.starts_with("# Scans staged files for unprotected secrets")
        || trimmed == LEGACY_NPX_COMMAND
        || trimmed == "phantom check --staged"
        || trimmed == "phantom check --staged || exit $?"
        || trimmed == "exit $?"
        || trimmed == "if ! command -v phantom >/dev/null 2>&1; then"
        || trimmed == "else"
        || trimmed == "fi"
        || trimmed == "exit 1"
        || trimmed.starts_with("echo \"Phantom pre-commit hook:")
        || trimmed.starts_with("echo \"Install a verified Phantom release,")
        || trimmed.starts_with("# Uses an installed local Phantom binary")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_hook_is_network_free_and_fails_closed_without_local_binary() {
        let update = ensure("");
        assert_eq!(update.change, HookChange::Installed);
        assert!(update.content.starts_with("#!/bin/sh\n"));
        assert!(update.content.contains("command -v phantom"));
        assert!(update.content.contains("phantom check --staged || exit $?"));
        assert!(update.content.contains("exit 1"));
        assert!(!update.content.contains("npx"));
        assert!(!update.content.contains("npm"));
    }

    #[test]
    fn current_hook_is_idempotent() {
        let existing = format!("#!/bin/sh\n{HOOK_BLOCK}\n");
        let update = ensure(&existing);
        assert_eq!(update.change, HookChange::Unchanged);
        assert_eq!(update.content, existing);
    }

    #[test]
    fn block_after_prior_exit_is_repaired_to_first_executable_position() {
        let existing = format!("#!/bin/sh\necho before\nexit 0\n{HOOK_BLOCK}\n");
        assert!(!is_current(&existing));

        let update = ensure(&existing);

        assert_eq!(update.change, HookChange::Repaired);
        assert!(is_current(&update.content));
        assert!(update.content.find(HOOK_BLOCK).unwrap() < update.content.find("exit 0").unwrap());
        assert!(update.content.contains("echo before\nexit 0"));
    }

    #[test]
    fn repairs_network_capable_phantom_runner() {
        let existing = "#!/bin/sh\ncurl -fsSL https://example.invalid/phantom | sh\necho after\n";
        let update = ensure(existing);
        assert_eq!(update.change, HookChange::Repaired);
        assert!(is_current(&update.content));
        assert!(!update.content.contains("curl"));
        assert!(update.content.contains("echo after"));
    }

    #[test]
    fn repairs_legacy_generated_block_and_preserves_other_commands() {
        let existing = "#!/bin/sh\necho before\n\n# Phantom Secrets pre-commit hook\n# Scans staged files for unprotected secrets\n\nnpx phantom-secrets check --staged\nexit $?\necho after\n";
        let update = ensure(existing);
        assert_eq!(update.change, HookChange::Repaired);
        assert!(update.content.contains("echo before"));
        assert!(update.content.contains("echo after"));
        assert_eq!(update.content.matches(HOOK_MARKER).count(), 1);
        assert!(!update.content.contains(LEGACY_NPX_COMMAND));
    }

    #[test]
    fn repairs_unmarked_legacy_command_without_removing_neighbors() {
        let existing = "#!/bin/sh\necho before\nnpx phantom-secrets check --staged\necho after\n";
        let update = ensure(existing);
        assert_eq!(update.change, HookChange::Repaired);
        assert!(update.content.contains("echo before"));
        assert!(update.content.contains("echo after"));
        assert!(!update.content.contains(LEGACY_NPX_COMMAND));
    }

    #[cfg(unix)]
    #[test]
    fn generated_hook_fails_clearly_when_phantom_is_unavailable() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let directory = tempfile::tempdir().unwrap();
        let hook = directory.path().join("pre-commit");
        std::fs::write(&hook, ensure("").content).unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

        let output = Command::new("/bin/sh")
            .arg(&hook)
            .env_clear()
            .env("PATH", directory.path())
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(1));
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("required but was not found on PATH"));
        assert!(stderr.contains("Install a verified Phantom release"));
    }

    #[cfg(unix)]
    #[test]
    fn generated_hook_invokes_local_binary_and_propagates_failure() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let directory = tempfile::tempdir().unwrap();
        let phantom = directory.path().join("phantom");
        std::fs::write(&phantom, "#!/bin/sh\nexit 7\n").unwrap();
        std::fs::set_permissions(&phantom, std::fs::Permissions::from_mode(0o755)).unwrap();
        let hook = directory.path().join("pre-commit");
        std::fs::write(&hook, ensure("").content).unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();

        let status = Command::new("/bin/sh")
            .arg(&hook)
            .env_clear()
            .env("PATH", directory.path())
            .status()
            .unwrap();

        assert_eq!(status.code(), Some(7));
    }
}
