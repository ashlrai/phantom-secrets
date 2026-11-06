use std::{fs, path::Path};

fn section<'a>(manifest: &'a str, name: &str) -> &'a str {
    let header = format!("[{name}]");
    let mut offset = 0;
    let mut start = None;
    for line in manifest.split_inclusive('\n') {
        let trimmed = line.trim();
        if let Some(start) = start.filter(|_| trimmed.starts_with('[')) {
            return &manifest[start..offset];
        }
        offset += line.len();
        if trimmed == header {
            start = Some(offset);
        }
    }
    &manifest[start.unwrap_or_else(|| panic!("missing {header} section"))..]
}

fn quoted_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.split(',').find_map(|field| {
        let (name, value) = field
            .trim()
            .trim_start_matches('{')
            .trim()
            .split_once('=')?;
        if name.trim() != key {
            return None;
        }
        value
            .trim()
            .strip_prefix('"')?
            .split_once('"')
            .map(|(value, _)| value)
    })
}

fn check_manifest(manifest: &str) {
    let version = section(manifest, "workspace.package")
        .lines()
        .find_map(|line| quoted_value(line, "version"))
        .expect("missing workspace package version");
    let workspace = section(manifest, "workspace");
    let members = workspace
        .split_once("members")
        .and_then(|(_, rest)| rest.split_once('['))
        .and_then(|(_, rest)| rest.split_once(']'))
        .expect("missing workspace members")
        .0
        .split(',')
        .filter_map(|member| {
            member
                .trim()
                .strip_prefix('"')?
                .split_once('"')
                .map(|(s, _)| s)
        })
        .collect::<Vec<_>>();

    let mut count = 0;
    for line in section(manifest, "workspace.dependencies").lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((name, fields)) = line.split_once('=') else {
            continue;
        };
        let Some(path) = quoted_value(fields, "path") else {
            continue;
        };
        if !path.starts_with("crates/") {
            continue;
        }
        count += 1;
        assert_eq!(
            quoted_value(fields, "version"),
            Some(version),
            "{} has an incorrect or missing version",
            name.trim()
        );
        assert!(
            members.contains(&path),
            "{} path {path} is not a workspace member",
            name.trim()
        );
    }
    assert!(count > 0, "no internal workspace dependencies found");
}

#[test]
fn internal_workspace_dependencies_match_workspace() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Cargo.toml");
    check_manifest(&fs::read_to_string(path).expect("read root Cargo.toml"));
}
