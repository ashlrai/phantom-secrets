//! Does `.gitignore` actually keep the project's dotenv file out of Git?
//!
//! Doctor and `phantom agent` used to answer that by looking for one literal
//! `.env` line. Git is not that literal: `/.env` and `.env*` ignore the file
//! just as well, and a later `!.env` un-ignores it however many times it was
//! listed above. So the old checks warned about projects that were already
//! safe (and appended a duplicate line when fixing them) and passed projects
//! whose `.env` Git would happily commit.
//!
//! This is deliberately a small, conservative reader rather than a gitignore
//! engine: it answers one question, for one file name at the repository root.
//! A pattern it does not understand (character classes, escapes) counts as not
//! covering the file, which errs toward a warning rather than a false all-clear.

/// What the project's ignore file says about a root dotenv file, after every
/// rule in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotenvIgnore {
    /// A rule ignores the file and nothing below it takes it back.
    Ignored,
    /// The file was ignored, then a later `!` rule un-ignored it.
    Negated,
    /// No rule in the file covers it at all.
    NotCovered,
}

/// `*` and `?` glob match within one path segment, as gitignore applies them.
///
/// Greedy with a single backtrack point, so a hostile `.gitignore` full of
/// stars costs O(pattern × name), never exponential time.
fn glob_matches(pattern: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while n < name.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p, n));
            p += 1;
        } else if let Some((star_p, star_n)) = star {
            p = star_p + 1;
            n = star_n + 1;
            star = Some((star_p, star_n + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&ch| ch == b'*')
}

/// Whether `pattern` (already stripped of any `!`) covers `name` at the root.
fn covers_root_file(pattern: &str, name: &str) -> bool {
    // A trailing slash means "directory only", which a file never matches.
    if pattern.ends_with('/') || pattern.contains(['[', '\\']) {
        return false;
    }
    // A leading `/` anchors to the root; a leading `**/` (or `/**/`) matches
    // any depth, the root included. Either way the rest must name the file
    // itself.
    let pattern = pattern
        .strip_prefix("/**/")
        .or_else(|| pattern.strip_prefix("**/"))
        .or_else(|| pattern.strip_prefix('/'))
        .unwrap_or(pattern);
    // Any other separator addresses a path below the root.
    if pattern.contains('/') {
        return false;
    }
    glob_matches(pattern.as_bytes(), name.as_bytes())
}

/// Read a `.gitignore` body and report what it does to the root file `name`.
///
/// Git applies the last matching rule, so the file is read in order and the
/// final verdict wins.
pub fn dotenv_ignore_state(content: &str, name: &str) -> DotenvIgnore {
    let mut state = DotenvIgnore::NotCovered;
    for line in content.lines() {
        // Git drops trailing spaces (not tabs) unless escaped.
        let line = line.trim_end_matches(' ');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (negated, pattern) = match line.strip_prefix('!') {
            Some(rest) => (true, rest),
            None => (false, line),
        };
        if !covers_root_file(pattern, name) {
            continue;
        }
        state = if negated {
            DotenvIgnore::Negated
        } else {
            DotenvIgnore::Ignored
        };
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_and_equivalent_patterns_all_count_as_ignored() {
        for body in [
            ".env\n",
            "/.env\n",
            "**/.env\n",
            "/**/.env\n",
            ".env*\n",
            ".e?v\n",
            "node_modules\n.env  \n",
            "# comment\n\n.env\n",
            ".*\n",
            "*\n",
        ] {
            assert_eq!(
                dotenv_ignore_state(body, ".env"),
                DotenvIgnore::Ignored,
                "body: {body:?}"
            );
        }
        assert_eq!(
            dotenv_ignore_state(".env*\n", ".env.development"),
            DotenvIgnore::Ignored
        );
        assert_eq!(
            dotenv_ignore_state(".env.*\n", ".env.development"),
            DotenvIgnore::Ignored
        );
    }

    #[test]
    fn a_later_negation_wins_and_an_earlier_one_does_not() {
        assert_eq!(
            dotenv_ignore_state(".env\n!.env\n", ".env"),
            DotenvIgnore::Negated
        );
        assert_eq!(
            dotenv_ignore_state("!.env\n.env\n", ".env"),
            DotenvIgnore::Ignored
        );
        assert_eq!(
            dotenv_ignore_state("*\n!.env\n", ".env"),
            DotenvIgnore::Negated
        );
        assert_eq!(
            dotenv_ignore_state(".env*\n!.env.example\n", ".env"),
            DotenvIgnore::Ignored
        );
    }

    #[test]
    fn patterns_for_other_paths_do_not_cover_the_root_file() {
        for body in [
            "",
            "node_modules\n",
            ".env.local\n",
            ".env.*\n",
            ".env/\n",
            "./.env\n",
            "config/.env\n",
            "api/.env\n",
            "env\n",
            "[.]env\n",
            "\\.env\n",
            ".env\t\n",
        ] {
            assert_eq!(
                dotenv_ignore_state(body, ".env"),
                DotenvIgnore::NotCovered,
                "body: {body:?}"
            );
        }
        assert_eq!(
            dotenv_ignore_state(".env\n", ".env.development"),
            DotenvIgnore::NotCovered
        );
    }
}
