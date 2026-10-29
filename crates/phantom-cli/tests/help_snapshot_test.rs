use std::process::Command;

#[test]
fn top_level_help_matches_snapshot_without_project_state() {
    let home = tempfile::tempdir().expect("create isolated home");
    let project = tempfile::tempdir().expect("create isolated project");
    let output = Command::new(env!("CARGO_BIN_EXE_phantom"))
        .arg("--help")
        .current_dir(project.path())
        .env_clear()
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("run top-level help");

    assert!(output.status.success(), "help must exit successfully");
    assert!(output.stderr.is_empty(), "help must not write to stderr");
    let help = String::from_utf8(output.stdout)
        .expect("help must be UTF-8")
        .replace("\r\n", "\n");
    let snapshot = include_str!("snapshots/top_level_help.txt").replace("\r\n", "\n");
    assert_eq!(help, snapshot);
    assert!(std::fs::read_dir(home.path()).unwrap().next().is_none());
    assert!(std::fs::read_dir(project.path()).unwrap().next().is_none());
}
