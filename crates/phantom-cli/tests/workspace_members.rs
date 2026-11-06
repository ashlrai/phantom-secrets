use std::fs;
use std::path::Path;

#[test]
fn workspace_members_have_manifests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("CLI crate must be two levels below the workspace root");
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read workspace manifest");
    let workspace = manifest
        .split_once("[workspace]")
        .expect("workspace section is missing")
        .1
        .split("\n[")
        .next()
        .expect("workspace section is missing");
    let members = workspace
        .split_once("members = [")
        .expect("workspace members list is missing")
        .1
        .split_once(']')
        .expect("workspace members list is not closed")
        .0;

    let mut count = 0;
    for line in members.lines() {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let member = line
            .trim_end_matches(',')
            .trim()
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .expect("workspace member must be a quoted path");
        assert!(
            root.join(member).join("Cargo.toml").is_file(),
            "workspace member {member:?} has no Cargo.toml"
        );
        count += 1;
    }
    assert!(count > 0, "workspace members list is empty");
}
