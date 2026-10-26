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
//!
//! [`wrap_scripts`] and [`unwrap_scripts`] are the one decision both callers
//! apply, so a person and an agent get the same scripts wrapped.
//! [`rewrite_scripts_in_place`] writes the result back without reformatting
//! the rest of package.json.

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

/// The prefix `phantom wrap` puts in front of a script.
pub const WRAP_PREFIX: &str = "phantom exec -- ";

/// The prefix `phantom wrap` and MCP `phantom_wrap` wrote before 0.7.4.
/// [`unwrap_scripts`] still restores scripts wrapped that way.
pub const LEGACY_WRAP_PREFIX: &str = "npx phantom-secrets exec -- ";

/// The script `phantom wrap` writes for `original`.
pub fn wrapped_script_command(original: &str) -> String {
    format!("{WRAP_PREFIX}{original}")
}

/// Script names `phantom wrap` selects when no explicit list is given: they
/// usually run the app and so need its credentials.
const DEFAULT_WRAP_KEYWORDS: [&str; 5] = ["dev", "start", "serve", "build", "deploy"];

/// Script names never selected by default, even when they also match a wrap
/// keyword (`build:types`, `dev:fmt`, `test:start`): tooling that does not
/// call a provider.
const DEFAULT_SKIP_KEYWORDS: [&str; 12] = [
    "lint",
    "test",
    "format",
    "fmt",
    "check",
    "type",
    "typecheck",
    "prettier",
    "eslint",
    "clean",
    "prepare",
    "postinstall",
];

/// Whether `phantom wrap` selects script `name` when no explicit list is
/// given. Case-insensitive; a skip keyword always wins over a wrap keyword.
pub fn selected_by_default(name: &str) -> bool {
    let lower = name.to_lowercase();
    !DEFAULT_SKIP_KEYWORDS.iter().any(|kw| lower.contains(kw))
        && DEFAULT_WRAP_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Whether `script` already runs through Phantom, so wrapping it again would
/// nest `phantom exec` inside itself.
///
/// True only when one of the script's commands invokes `phantom exec`: the
/// `phantom` or `phantom-secrets` program (any path, optionally behind
/// `npx`, `pnpx`, `bunx`, `bun x`, `pnpm dlx|exec`, `yarn [dlx|exec]` or
/// `npm exec`, and Phantom's global flags) followed by `exec`. That covers
/// [`WRAP_PREFIX`] and [`LEGACY_WRAP_PREFIX`]. A script that merely mentions
/// Phantom (`npx phantom-secrets init`, `echo phantom-secrets`,
/// `phantomjs render.js`, `./phantom-tools/build.sh`) does not run its
/// command through the proxy and is not wrapped yet.
pub fn already_wrapped(script: &str) -> bool {
    shell_commands(script).iter().any(|words| {
        let words: Vec<&str> = words.iter().map(String::as_str).collect();
        invokes_phantom_exec(&words)
    })
}

/// Phantom's global flags, which may come before the subcommand.
const PHANTOM_GLOBAL_FLAGS: [&str; 5] = ["-v", "--verbose", "-q", "--quiet", "--json"];

/// Whether one command's words run `phantom exec`.
fn invokes_phantom_exec(mut words: &[&str]) -> bool {
    while let Some((first, rest)) = words.split_first() {
        if !starts_with_env_assignment(first) {
            break;
        }
        words = rest;
    }
    let launcher = match words {
        ["npx" | "pnpx" | "bunx", ..] => 1,
        ["pnpm" | "yarn", "dlx" | "exec", ..] | ["npm", "exec", ..] | ["bun", "x", ..] => 2,
        ["yarn", ..] => 1,
        _ => 0,
    };
    words = &words[launcher..];
    if launcher > 0 {
        while words.first().is_some_and(|word| word.starts_with('-')) {
            words = &words[1..];
        }
    }
    let Some((program, mut rest)) = words.split_first() else {
        return false;
    };
    let name = program.rsplit('/').next().unwrap_or(program);
    let is_phantom = name == "phantom"
        || name == "phantom-secrets"
        || (launcher > 0 && name.starts_with("phantom-secrets@"));
    if !is_phantom {
        return false;
    }
    while rest
        .first()
        .is_some_and(|flag| PHANTOM_GLOBAL_FLAGS.contains(flag))
    {
        rest = &rest[1..];
    }
    rest.first() == Some(&"exec")
}

/// `script` split into its shell commands, each as unquoted words. Quoting is
/// honored, so `echo "phantom exec"` is one argument, not a command.
/// Operators and grouping (`;`, `&`, `|`, newlines, `(`, `)`) end a command.
fn shell_commands(script: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for ch in script.chars() {
        if escaped {
            escaped = false;
            word.push(ch);
            in_word = true;
            continue;
        }
        if single {
            if ch == '\'' {
                single = false;
            } else {
                word.push(ch);
            }
            continue;
        }
        if double {
            match ch {
                '"' => double = false,
                '\\' => escaped = true,
                _ => word.push(ch),
            }
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '\'' => {
                single = true;
                in_word = true;
            }
            '"' => {
                double = true;
                in_word = true;
            }
            ';' | '&' | '|' | '\n' | '\r' | '(' | ')' => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
                if !words.is_empty() {
                    commands.push(std::mem::take(&mut words));
                }
            }
            _ if ch.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            _ => {
                word.push(ch);
                in_word = true;
            }
        }
    }
    if in_word {
        words.push(word);
    }
    if !words.is_empty() {
        commands.push(words);
    }
    commands
}

/// What [`wrap_scripts`] changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct WrapOutcome {
    /// Scripts now prefixed with [`WRAP_PREFIX`], in package.json key order.
    pub wrapped: Vec<String>,
    /// Selected scripts left unchanged because they are a shell command line,
    /// with the [`wrap_blocker`] reason.
    pub unwrapped: Vec<(String, &'static str)>,
}

/// `name:raw` already exists and belongs to the user, so wrapping `name`
/// would overwrite it. Nothing was changed.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "Refusing to wrap '{name}': package.json already contains user-owned script '{raw_name}'. Rename or remove that script explicitly before retrying. No scripts were changed."
)]
pub struct RawScriptConflict {
    pub name: String,
    pub raw_name: String,
}

/// The one decision both `phantom wrap` and MCP `phantom_wrap` apply to a
/// parsed package.json: which scripts to wrap, and the edit.
///
/// A script is a candidate when it is a string, is not a `:raw` backup, is
/// not [`already_wrapped`], is not in `skip`, and is either in `only` or,
/// when `only` is empty, [`selected_by_default`]. A candidate that is a shell
/// command line ([`wrap_blocker`]) is reported in `unwrapped` and left alone.
/// The others are saved as `name:raw` and replaced by
/// [`wrapped_script_command`]. If any `name:raw` already exists, nothing is
/// changed.
pub fn wrap_scripts(
    pkg: &mut serde_json::Value,
    only: &[String],
    skip: &[String],
) -> Result<WrapOutcome, RawScriptConflict> {
    let Some(scripts) = pkg
        .get_mut("scripts")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return Ok(WrapOutcome::default());
    };
    let mut candidates = Vec::new();
    let mut unwrapped = Vec::new();
    for (name, value) in scripts.iter() {
        let Some(original) = value.as_str() else {
            continue;
        };
        if name.ends_with(":raw")
            || already_wrapped(original)
            || skip.iter().any(|skipped| skipped == name)
        {
            continue;
        }
        let selected = if only.is_empty() {
            selected_by_default(name)
        } else {
            only.iter().any(|chosen| chosen == name)
        };
        if !selected {
            continue;
        }
        if let Some(reason) = wrap_blocker(original) {
            unwrapped.push((name.clone(), reason));
            continue;
        }
        let raw_name = format!("{name}:raw");
        if scripts.contains_key(&raw_name) {
            return Err(RawScriptConflict {
                name: name.clone(),
                raw_name,
            });
        }
        candidates.push((name.clone(), raw_name, original.to_string()));
    }
    for (name, raw_name, original) in &candidates {
        scripts.insert(
            raw_name.clone(),
            serde_json::Value::String(original.clone()),
        );
        scripts.insert(
            name.clone(),
            serde_json::Value::String(wrapped_script_command(original)),
        );
    }
    Ok(WrapOutcome {
        wrapped: candidates.into_iter().map(|(name, _, _)| name).collect(),
        unwrapped,
    })
}

/// The inverse of [`wrap_scripts`], shared by `phantom unwrap` and MCP
/// `phantom_unwrap`: every `name:raw` whose `name` is exactly
/// [`wrapped_script_command`] of it, or [`LEGACY_WRAP_PREFIX`] followed by
/// it (what releases before 0.7.4 wrote), is restored and removed. Any other
/// `:raw` script is the user's and is left alone. Returns the restored
/// names in package.json key order.
pub fn unwrap_scripts(pkg: &mut serde_json::Value) -> Vec<String> {
    let Some(scripts) = pkg
        .get_mut("scripts")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return Vec::new();
    };
    let owned = scripts
        .iter()
        .filter_map(|(raw_name, raw_value)| {
            let base_name = raw_name.strip_suffix(":raw")?;
            let original = raw_value.as_str()?;
            let current = scripts.get(base_name).and_then(serde_json::Value::as_str)?;
            let wrapped_by_phantom = current == wrapped_script_command(original)
                || current.strip_prefix(LEGACY_WRAP_PREFIX) == Some(original);
            wrapped_by_phantom.then(|| {
                (
                    base_name.to_string(),
                    raw_name.clone(),
                    original.to_string(),
                )
            })
        })
        .collect::<Vec<_>>();
    for (base_name, raw_name, original) in &owned {
        scripts.insert(
            base_name.clone(),
            serde_json::Value::String(original.clone()),
        );
        scripts.remove(raw_name);
    }
    owned
        .into_iter()
        .map(|(base_name, _, _)| base_name)
        .collect()
}

/// Why package.json could not be edited in place.
#[derive(Debug, thiserror::Error)]
#[error("package.json could not be edited in place: {0}")]
pub struct PackageJsonEditError(&'static str);

/// Rewrite `source` (a package.json) so it parses to `desired`, touching
/// only the members of its top-level `scripts` object that differ.
///
/// Everything else keeps its bytes: key order, indentation (spaces or tabs,
/// any width), the space after each colon, string escapes, and whether the
/// file ends with a newline. A changed script keeps its position; a new
/// `NAME:raw` member goes right after `NAME`, laid out like it; a removed
/// member takes its separator with it. Script values are copied from the
/// original text where possible, so `phantom unwrap` restores the original
/// literal byte for byte.
///
/// `desired` may differ from `source` only inside `scripts`. The result is
/// parsed again and must equal `desired`, so a layout this editor does not
/// understand is an error, never a silent change.
pub fn rewrite_scripts_in_place(
    source: &str,
    desired: &serde_json::Value,
) -> Result<String, PackageJsonEditError> {
    use serde_json::Value;

    let parsed: Value = serde_json::from_str(source)
        .map_err(|_| PackageJsonEditError("the file is not valid JSON"))?;
    if &parsed == desired {
        return Ok(source.to_string());
    }
    let (Some(original_scripts), Some(desired_scripts)) = (
        parsed.get("scripts").and_then(Value::as_object),
        desired.get("scripts").and_then(Value::as_object),
    ) else {
        return Err(PackageJsonEditError("\"scripts\" is not an object"));
    };

    let bytes = source.as_bytes();
    let start = skip_ws(bytes, 0);
    let root = parse_object(source, start)?.0;
    let scripts_member = unique_member(&root, "scripts")?;
    let scripts = parse_object(source, scripts_member.value_start)?.0;
    for (index, member) in scripts.members.iter().enumerate() {
        if scripts.members[..index]
            .iter()
            .any(|other| other.key == member.key)
        {
            return Err(PackageJsonEditError("\"scripts\" has a duplicate key"));
        }
    }

    let removed: Vec<bool> = scripts
        .members
        .iter()
        .map(|member| !desired_scripts.contains_key(&member.key))
        .collect();
    let mut edits: Vec<(usize, usize, String)> = Vec::new();

    // Changed values keep their position.
    for member in &scripts.members {
        let Some(new_value) = desired_scripts.get(&member.key) else {
            continue;
        };
        if original_scripts.get(&member.key) == Some(new_value) {
            continue;
        }
        let literal = value_literal(source, &scripts, &member.key, new_value)?;
        edits.push((member.value_start, member.value_end, literal));
    }

    // New members go after their base script (`NAME` for `NAME:raw`), or
    // after the last kept member.
    let last_kept = removed.iter().rposition(|gone| !gone);
    for (key, new_value) in desired_scripts {
        if original_scripts.contains_key(key) {
            continue;
        }
        let anchor = key
            .strip_suffix(":raw")
            .and_then(|base| scripts.members.iter().position(|m| m.key == base))
            .filter(|&index| !removed[index])
            .or(last_kept)
            .ok_or(PackageJsonEditError(
                "\"scripts\" would have no member left",
            ))?;
        let anchor_member = &scripts.members[anchor];
        let key_literal = serde_json::to_string(key)
            .map_err(|_| PackageJsonEditError("a script name cannot be encoded"))?;
        let literal = value_literal(source, &scripts, key, new_value)?;
        let inserted = format!(
            ",{}{}{}{}",
            &source[anchor_member.leading_start..anchor_member.key_start],
            key_literal,
            &source[anchor_member.key_end..anchor_member.value_start],
            literal
        );
        edits.push((anchor_member.value_end, anchor_member.value_end, inserted));
    }

    // Removed members take one separator with them, so the rest of the
    // object keeps its layout.
    let mut index = 0;
    while index < removed.len() {
        if !removed[index] {
            index += 1;
            continue;
        }
        let run_start = index;
        while index < removed.len() && removed[index] {
            index += 1;
        }
        let members = &scripts.members;
        let span = if run_start > 0 {
            (
                members[run_start - 1].value_end,
                members[index - 1].value_end,
            )
        } else if index < members.len() {
            (members[0].key_start, members[index].key_start)
        } else {
            (scripts.open + 1, scripts.close)
        };
        edits.push((span.0, span.1, String::new()));
    }

    edits.sort_by_key(|&(start, end, _)| (start, end));
    let mut output = String::with_capacity(source.len() + 64);
    let mut cursor = 0;
    for (start, end, text) in edits {
        if start < cursor {
            return Err(PackageJsonEditError("overlapping script edits"));
        }
        output.push_str(&source[cursor..start]);
        output.push_str(&text);
        cursor = end;
    }
    output.push_str(&source[cursor..]);

    let reparsed: Value = serde_json::from_str(&output)
        .map_err(|_| PackageJsonEditError("the edited file would not be valid JSON"))?;
    if &reparsed != desired {
        return Err(PackageJsonEditError(
            "the change is not limited to \"scripts\" values",
        ));
    }
    Ok(output)
}

/// The JSON text for `value` as the script `key`, reusing an original
/// literal so escapes and spelling survive a wrap/unwrap round trip.
fn value_literal(
    source: &str,
    scripts: &JsonObject,
    key: &str,
    value: &serde_json::Value,
) -> Result<String, PackageJsonEditError> {
    let base = key.strip_suffix(":raw");
    let raw_key = format!("{key}:raw");
    let names = [Some(key), Some(raw_key.as_str()), base];
    let related = || {
        names
            .into_iter()
            .flatten()
            .filter_map(|name| scripts.members.iter().find(|m| m.key == name))
    };
    for member in related() {
        let literal = &source[member.value_start..member.value_end];
        if serde_json::from_str::<serde_json::Value>(literal)
            .ok()
            .as_ref()
            == Some(value)
        {
            return Ok(literal.to_string());
        }
    }
    if let Some(text) = value.as_str() {
        for member in related() {
            let literal = &source[member.value_start..member.value_end];
            let Ok(serde_json::Value::String(original)) = serde_json::from_str(literal) else {
                continue;
            };
            if text.strip_prefix(WRAP_PREFIX) == Some(original.as_str()) {
                // The prefix needs no escaping, so it can go straight after
                // the opening quote of the original literal.
                return Ok(format!("\"{WRAP_PREFIX}{}", &literal[1..]));
            }
        }
    }
    serde_json::to_string(value).map_err(|_| PackageJsonEditError("a script cannot be encoded"))
}

/// One `"key": value` member of a JSON object, as byte offsets into the
/// source.
struct JsonMember {
    key: String,
    /// Just after the `{` or `,` that precedes this member.
    leading_start: usize,
    key_start: usize,
    key_end: usize,
    value_start: usize,
    value_end: usize,
}

struct JsonObject {
    open: usize,
    close: usize,
    members: Vec<JsonMember>,
}

const MALFORMED: PackageJsonEditError = PackageJsonEditError("unexpected JSON layout");

fn unique_member<'a>(
    object: &'a JsonObject,
    key: &str,
) -> Result<&'a JsonMember, PackageJsonEditError> {
    let mut found = object.members.iter().filter(|member| member.key == key);
    match (found.next(), found.next()) {
        (Some(member), None) => Ok(member),
        (None, _) => Err(PackageJsonEditError("there is no \"scripts\" member")),
        (Some(_), Some(_)) => Err(PackageJsonEditError("\"scripts\" appears more than once")),
    }
}

fn skip_ws(bytes: &[u8], mut pos: usize) -> usize {
    while matches!(bytes.get(pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        pos += 1;
    }
    pos
}

/// Parse the object starting at `open` (a `{`); returns it and the offset
/// just after its `}`.
fn parse_object(source: &str, open: usize) -> Result<(JsonObject, usize), PackageJsonEditError> {
    let bytes = source.as_bytes();
    if bytes.get(open) != Some(&b'{') {
        return Err(MALFORMED);
    }
    let mut members = Vec::new();
    let mut leading_start = open + 1;
    let mut pos = skip_ws(bytes, leading_start);
    if bytes.get(pos) == Some(&b'}') {
        return Ok((
            JsonObject {
                open,
                close: pos,
                members,
            },
            pos + 1,
        ));
    }
    loop {
        let key_start = pos;
        let key_end = skip_string(bytes, key_start)?;
        let key: String =
            serde_json::from_str(&source[key_start..key_end]).map_err(|_| MALFORMED)?;
        pos = skip_ws(bytes, key_end);
        if bytes.get(pos) != Some(&b':') {
            return Err(MALFORMED);
        }
        let value_start = skip_ws(bytes, pos + 1);
        let value_end = skip_value(source, value_start)?;
        members.push(JsonMember {
            key,
            leading_start,
            key_start,
            key_end,
            value_start,
            value_end,
        });
        pos = skip_ws(bytes, value_end);
        match bytes.get(pos) {
            Some(b',') => {
                leading_start = pos + 1;
                pos = skip_ws(bytes, leading_start);
            }
            Some(b'}') => {
                return Ok((
                    JsonObject {
                        open,
                        close: pos,
                        members,
                    },
                    pos + 1,
                ))
            }
            _ => return Err(MALFORMED),
        }
    }
}

/// The offset just after the string literal starting at `start`.
fn skip_string(bytes: &[u8], start: usize) -> Result<usize, PackageJsonEditError> {
    if bytes.get(start) != Some(&b'"') {
        return Err(MALFORMED);
    }
    let mut pos = start + 1;
    loop {
        match bytes.get(pos) {
            Some(b'\\') => pos += 2,
            Some(b'"') => return Ok(pos + 1),
            Some(_) => pos += 1,
            None => return Err(MALFORMED),
        }
    }
}

/// The offset just after the JSON value starting at `start`.
fn skip_value(source: &str, start: usize) -> Result<usize, PackageJsonEditError> {
    let bytes = source.as_bytes();
    match bytes.get(start) {
        Some(b'"') => skip_string(bytes, start),
        Some(b'{') => parse_object(source, start).map(|(_, end)| end),
        Some(b'[') => {
            let mut pos = skip_ws(bytes, start + 1);
            if bytes.get(pos) == Some(&b']') {
                return Ok(pos + 1);
            }
            loop {
                pos = skip_ws(bytes, skip_value(source, pos)?);
                match bytes.get(pos) {
                    Some(b',') => pos = skip_ws(bytes, pos + 1),
                    Some(b']') => return Ok(pos + 1),
                    _ => return Err(MALFORMED),
                }
            }
        }
        Some(_) => {
            let mut pos = start;
            while let Some(byte) = bytes.get(pos) {
                if matches!(byte, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r') {
                    break;
                }
                pos += 1;
            }
            if pos == start {
                Err(MALFORMED)
            } else {
                Ok(pos)
            }
        }
        None => Err(MALFORMED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_selection_keeps_the_narrower_of_the_former_cli_and_mcp_rules() {
        for name in [
            "dev",
            "start",
            "serve",
            "build",
            "deploy",
            "dev:local",
            "Start",
            "predev",
        ] {
            assert!(selected_by_default(name), "{name}");
        }
        // `preview` was CLI-only; `type` and `fmt` were CLI-only skips.
        for name in [
            "preview",
            "build:types",
            "dev:fmt",
            "typegen:dev",
            "test",
            "test:start",
            "lint",
            "format",
            "typecheck",
            "check:build",
            "clean:build",
            "prepare",
            "postinstall",
            "",
        ] {
            assert!(!selected_by_default(name), "{name}");
        }
    }

    #[test]
    fn already_wrapped_scripts_are_recognized() {
        assert!(already_wrapped("phantom exec -- next dev"));
        assert!(already_wrapped("npx phantom-secrets exec -- next dev"));
        assert!(!already_wrapped("next dev"));
    }

    #[test]
    fn only_scripts_that_run_through_phantom_exec_count_as_wrapped() {
        for script in [
            "npx phantom-secrets init",
            "phantom-secrets doctor",
            "phantom doctor",
            "echo phantom-secrets",
            "grep -r phantom-secrets .",
            "./phantom-tools/build.sh",
            "phantomjs render.js",
            "node ./phantom-secrets-demo/server.js",
            "node phantom-exec.js",
            "echo \"phantom exec -- node server.js\"",
            "node -e 'phantom exec'",
            "npx phantom-secrets@0.7.9 check",
            "npx phantomjs exec",
            "phantom",
        ] {
            assert!(!already_wrapped(script), "{script}");
        }
    }

    #[test]
    fn every_form_that_runs_through_phantom_exec_counts_as_wrapped() {
        for script in [
            "phantom exec -- next dev",
            "phantom exec --env staging -- next dev",
            "phantom --quiet exec -- next dev",
            "phantom-secrets exec -- next dev",
            "npx phantom-secrets exec -- next dev",
            "npx -y phantom-secrets@0.7.9 exec -- next dev",
            "npx phantom exec -- next dev",
            "pnpx phantom-secrets exec -- next dev",
            "bunx phantom-secrets exec -- next dev",
            "bun x phantom-secrets exec -- next dev",
            "pnpm dlx phantom-secrets exec -- next dev",
            "pnpm exec phantom exec -- next dev",
            "yarn dlx phantom-secrets exec -- next dev",
            "yarn exec phantom exec -- next dev",
            "yarn phantom exec -- next dev",
            "npm exec -- phantom exec -- next dev",
            "./node_modules/.bin/phantom exec -- next dev",
            "  phantom   exec -- next dev",
            "'phantom' exec -- next dev",
            "NODE_ENV=production phantom exec -- node server.js",
            "cd web && phantom exec -- next dev",
            "npm run gen; npx phantom-secrets exec -- node server.js",
        ] {
            assert!(already_wrapped(script), "{script}");
        }
        // Whatever `phantom wrap` writes, now or in releases before 0.7.4.
        assert!(already_wrapped(&wrapped_script_command("next dev")));
        assert!(already_wrapped(&format!("{LEGACY_WRAP_PREFIX}next dev")));
    }

    #[test]
    fn scripts_that_only_mention_phantom_are_still_wrapped() {
        let mut pkg = serde_json::json!({
            "scripts": {
                "build": "./phantom-tools/build.sh",
                "dev": "phantomjs render.js",
                "start": "npx phantom-secrets exec -- node server.js",
                "serve": "node ./phantom-secrets-demo/server.js"
            }
        });
        let outcome = wrap_scripts(&mut pkg, &[], &[]).unwrap();
        assert_eq!(outcome.wrapped, vec!["build", "dev", "serve"]);
        assert_eq!(pkg["scripts"]["dev"], "phantom exec -- phantomjs render.js");
        assert_eq!(
            pkg["scripts"]["start"],
            "npx phantom-secrets exec -- node server.js"
        );
        assert!(pkg["scripts"].get("start:raw").is_none());
    }

    #[test]
    fn unwrap_restores_scripts_wrapped_by_releases_before_0_7_4() {
        let original = serde_json::json!({
            "scripts": {
                "dev": "next dev",
                "start": "node server.js",
                "build:raw": "user-owned",
                "build": "npx phantom-secrets exec -- next build"
            }
        });
        let mut pkg = serde_json::json!({
            "scripts": {
                "dev": "npx phantom-secrets exec -- next dev",
                "dev:raw": "next dev",
                "start": "phantom exec -- node server.js",
                "start:raw": "node server.js",
                "build:raw": "user-owned",
                "build": "npx phantom-secrets exec -- next build"
            }
        });
        assert_eq!(unwrap_scripts(&mut pkg), vec!["dev", "start"]);
        assert_eq!(pkg, original);
    }

    #[test]
    fn wrap_selects_wraps_and_never_double_wraps() {
        let mut pkg = serde_json::json!({
            "name": "demo",
            "scripts": {
                "build": "next build",
                "dev": "next dev",
                "lint": "eslint .",
                "preview": "vite preview",
                "serve": "node a.js && node b.js",
                "start": "phantom exec -- node server.js",
                "deploy": 7
            }
        });
        let outcome = wrap_scripts(&mut pkg, &[], &[]).unwrap();
        assert_eq!(outcome.wrapped, vec!["build", "dev"]);
        let blocked: Vec<&str> = outcome.unwrapped.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(blocked, vec!["serve"]);
        assert_eq!(pkg["scripts"]["dev"], "phantom exec -- next dev");
        assert_eq!(pkg["scripts"]["dev:raw"], "next dev");
        assert_eq!(pkg["scripts"]["preview"], "vite preview");
        assert_eq!(pkg["scripts"]["deploy"], 7);
        assert!(pkg["scripts"].get("start:raw").is_none());

        // A second run finds nothing left to wrap.
        let after_first = pkg.clone();
        let again = wrap_scripts(&mut pkg, &[], &[]).unwrap();
        assert!(again.wrapped.is_empty());
        assert_eq!(pkg, after_first);
        // Naming a wrapped script explicitly does not nest the prefix either.
        let explicit = wrap_scripts(&mut pkg, &["dev".to_string()], &[]).unwrap();
        assert!(explicit.wrapped.is_empty());
        assert_eq!(pkg, after_first);
    }

    #[test]
    fn explicit_only_and_skip_override_the_default_selection() {
        let mut pkg = serde_json::json!({
            "scripts": { "dev": "next dev", "preview": "vite preview", "test": "vitest" }
        });
        let only = ["preview", "test", "dev", "missing", "dev:raw"].map(String::from);
        let outcome = wrap_scripts(&mut pkg, &only, &["dev".to_string()]).unwrap();
        assert_eq!(outcome.wrapped, vec!["preview", "test"]);
        assert_eq!(pkg["scripts"]["dev"], "next dev");
    }

    #[test]
    fn raw_conflict_changes_nothing() {
        let mut pkg = serde_json::json!({
            "scripts": { "build": "next build", "dev": "next dev", "dev:raw": "mine" }
        });
        let before = pkg.clone();
        let conflict = wrap_scripts(&mut pkg, &[], &[]).unwrap_err();
        assert_eq!(conflict.name, "dev");
        assert_eq!(conflict.raw_name, "dev:raw");
        assert_eq!(pkg, before);
    }

    #[test]
    fn unwrap_is_the_exact_inverse_and_keeps_user_raw_scripts() {
        let original = serde_json::json!({
            "scripts": {
                "build": "next build",
                "dev": "next dev",
                "lint": "eslint .",
                "start:raw": "user-owned",
                "start": "node server.js"
            }
        });
        let mut pkg = original.clone();
        wrap_scripts(&mut pkg, &["build".into(), "dev".into()], &[]).unwrap();
        assert_eq!(unwrap_scripts(&mut pkg), vec!["build", "dev"]);
        assert_eq!(pkg, original);
        assert!(unwrap_scripts(&mut pkg).is_empty());
        assert!(unwrap_scripts(&mut serde_json::json!({ "name": "x" })).is_empty());
    }

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

    fn edited(
        source: &str,
        edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
    ) -> Result<String, PackageJsonEditError> {
        let mut desired: serde_json::Value = serde_json::from_str(source).unwrap();
        edit(desired["scripts"].as_object_mut().unwrap());
        rewrite_scripts_in_place(source, &desired)
    }

    fn wrap(scripts: &mut serde_json::Map<String, serde_json::Value>, name: &str) {
        let original = scripts[name].as_str().unwrap().to_string();
        scripts.insert(format!("{name}:raw"), original.clone().into());
        scripts.insert(name.to_string(), wrapped_script_command(&original).into());
    }

    fn unwrap(scripts: &mut serde_json::Map<String, serde_json::Value>, name: &str) {
        let original = scripts.remove(&format!("{name}:raw")).unwrap();
        scripts.insert(name.to_string(), original);
    }

    #[test]
    fn wrap_round_trip_keeps_escapes_crlf_and_compact_layout() {
        for (source, expected) in [
            (
                "{\r\n  \"scripts\": {\r\n    \"start\": \"node \\u0073erver.js --title \\\"x\\\"\",\r\n    \"a\": 1\r\n  }\r\n}\r\n",
                "{\r\n  \"scripts\": {\r\n    \"start\": \"phantom exec -- node \\u0073erver.js --title \\\"x\\\"\",\r\n    \"start:raw\": \"node \\u0073erver.js --title \\\"x\\\"\",\r\n    \"a\": 1\r\n  }\r\n}\r\n",
            ),
            (
                "{\"z\":0,\"scripts\":{\"start\":\"node s.js\"},\"a\":[1,{\"b\":null}]}",
                "{\"z\":0,\"scripts\":{\"start\":\"phantom exec -- node s.js\",\"start:raw\":\"node s.js\"},\"a\":[1,{\"b\":null}]}",
            ),
            (
                "{\n\t\"scripts\" : {\n\t\t\"start\" :\"node s.js\"\n\t}\n}\n",
                "{\n\t\"scripts\" : {\n\t\t\"start\" :\"phantom exec -- node s.js\",\n\t\t\"start:raw\" :\"node s.js\"\n\t}\n}\n",
            ),
        ] {
            let wrapped = edited(source, |scripts| wrap(scripts, "start")).unwrap();
            assert_eq!(wrapped, expected);
            let unwrapped = edited(&wrapped, |scripts| unwrap(scripts, "start")).unwrap();
            assert_eq!(unwrapped, source);
        }
    }

    #[test]
    fn removing_the_first_member_keeps_the_next_members_layout() {
        let source = "{\n  \"scripts\": {\n    \"a:raw\": \"x\",\n    \"b\": \"y\"\n  }\n}\n";
        let output = edited(source, |scripts| {
            scripts.remove("a:raw");
        })
        .unwrap();
        assert_eq!(output, "{\n  \"scripts\": {\n    \"b\": \"y\"\n  }\n}\n");
    }

    #[test]
    fn changes_outside_scripts_and_duplicate_keys_are_refused() {
        let source = "{\"name\":\"a\",\"scripts\":{\"dev\":\"next dev\"}}";
        let mut desired: serde_json::Value = serde_json::from_str(source).unwrap();
        desired["name"] = "b".into();
        desired["scripts"]["dev"] = "phantom exec -- next dev".into();
        assert!(rewrite_scripts_in_place(source, &desired).is_err());

        let duplicate = "{\"scripts\":{\"dev\":\"x\",\"dev\":\"next dev\"}}";
        assert!(edited(duplicate, |scripts| wrap(scripts, "dev")).is_err());
        let duplicate = "{\"scripts\":{},\"scripts\":{\"dev\":\"next dev\"}}";
        assert!(edited(duplicate, |scripts| wrap(scripts, "dev")).is_err());
    }

    #[test]
    fn unchanged_package_is_returned_verbatim() {
        let source = "{ \"scripts\" : { } }";
        assert_eq!(edited(source, |_| {}).unwrap(), source);
    }
}
