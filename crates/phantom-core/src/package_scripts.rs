//! Shared rules for `phantom wrap` (CLI) and MCP `phantom_wrap`.
//!
//! A wrapped script is `phantom exec -- <original>`. The package manager runs
//! that line through a shell, and `phantom exec` then runs its own argv
//! directly, without a second shell. That is only equivalent to the original
//! when the original is one simple command. A shell command line such as
//! `NODE_ENV=production node server.js` or `next build && next start` would
//! instead hand `NODE_ENV=production` to `phantom exec` as the program (the
//! script fails), or run only its first command under the proxy while the
//! rest runs without it. Such scripts are left unchanged and reported.

/// Why `script` cannot be prefixed with `phantom exec --`, or `None` when it
/// is one simple command.
///
/// Quoting is honored, so operators inside quotes (`node -e "a && b"`) are
/// arguments, not shell syntax. Redirections and substitutions only shape the
/// one command's arguments or output and are allowed.
pub fn wrap_blocker(script: &str) -> Option<&'static str> {
    let trimmed = script.trim_start();
    if trimmed.trim_end().is_empty() {
        return Some("it is empty");
    }
    if starts_with_env_assignment(trimmed) {
        return Some("it starts with an environment assignment (VAR=value)");
    }

    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    let mut previous = None;
    let mut chars = trimmed.chars().peekable();
    while let Some(ch) = chars.next() {
        let before = previous.replace(ch);
        if escaped {
            escaped = false;
            // An escaped character never forms an operator with its neighbour.
            previous = None;
            continue;
        }
        if single {
            single = ch != '\'';
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => double = !double,
            _ if double => {}
            '\'' => single = true,
            // File-descriptor redirections (`2>&1`, `<&0`, `&>log`) stay
            // within the one command.
            '&' if matches!(before, Some('>' | '<')) || chars.peek() == Some(&'>') => {}
            ';' | '&' | '|' | '\n' | '\r' => {
                return Some("it chains several shell commands (&&, ||, |, ; or &)")
            }
            '(' | ')' => return Some("it uses a shell subshell or grouping"),
            _ => {}
        }
    }
    None
}

/// `NAME=...` as the first word: a shell variable assignment, not a program.
fn starts_with_env_assignment(script: &str) -> bool {
    let mut chars = script.char_indices();
    match chars.next() {
        Some((_, first)) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    for (_, ch) in chars {
        if ch == '=' {
            return true;
        }
        if !(ch.is_ascii_alphanumeric() || ch == '_') {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_commands_can_be_wrapped() {
        for script in [
            "next dev",
            "node server.js --port 3000",
            "cross-env NODE_ENV=production node server.js",
            "env NODE_ENV=production node server.js",
            "node -e \"console.log('a && b; c | d (e)')\"",
            "node -e 'process.exit(0); // && ||'",
            "echo a\\&\\&b",
            "node server.js > server.log 2>&1",
            "node server.js &> server.log",
            "node --flag=value server.js",
            "./bin/run.sh",
        ] {
            assert_eq!(wrap_blocker(script), None, "{script}");
        }
    }

    #[test]
    fn shell_command_lines_are_not_wrapped() {
        for script in [
            "",
            "   ",
            "NODE_ENV=production node server.js",
            "  PORT=3000 next start",
            "_X=1 node a.js",
            "next build && next start",
            "next build || exit 1",
            "node server.js | pino-pretty",
            "vite build; vite preview",
            "node worker.js & node server.js",
            "node a.js\nnode b.js",
            "(cd web && next dev)",
            "node a.js 2>&1 && node b.js",
            "node a.js \\\\&& node b.js",
        ] {
            assert!(wrap_blocker(script).is_some(), "{script:?}");
        }
    }

    #[test]
    fn assignment_detection_needs_a_name_before_equals() {
        assert!(!starts_with_env_assignment("=x node"));
        assert!(!starts_with_env_assignment("1X=2 node"));
        assert!(!starts_with_env_assignment("node --x=1"));
        assert!(!starts_with_env_assignment("./x=1"));
        assert!(starts_with_env_assignment("A_1=b node"));
    }
}
