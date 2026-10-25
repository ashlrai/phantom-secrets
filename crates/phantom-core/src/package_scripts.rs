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

/// The script `phantom wrap` writes for `original`.
pub fn wrapped_script_command(original: &str) -> String {
    format!("{WRAP_PREFIX}{original}")
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
