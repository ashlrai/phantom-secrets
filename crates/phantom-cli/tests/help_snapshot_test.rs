use std::process::Command;

fn normalize_help(help: &str) -> String {
    help.replace("\r\n", "\n")
        .replace("Usage: phantom.exe ", "Usage: phantom ")
}

#[test]
fn help_normalization_only_changes_line_endings_and_usage_binary() {
    let canonical = "Usage: phantom [OPTIONS] <COMMAND>\n  phantom.exe is a filename\n";
    assert_eq!(normalize_help(canonical), canonical);
    assert_eq!(
        normalize_help("Usage: phantom.exe [OPTIONS] <COMMAND>\r\n  phantom.exe is a filename\r\n"),
        canonical
    );
}

#[test]
fn top_level_help_matches_snapshot_without_project_state() {
    let home = tempfile::tempdir().expect("create isolated home");
    let project = tempfile::tempdir().expect("create isolated project");
    // Coverage-instrumented binaries (cargo llvm-cov) write a default
    // *.profraw into the current directory when LLVM_PROFILE_FILE is absent,
    // which would falsify the no-side-effects assertions below.
    let profile = tempfile::tempdir().expect("create coverage profile dir");
    let output = Command::new(env!("CARGO_BIN_EXE_phantom"))
        .arg("--help")
        .current_dir(project.path())
        .env_clear()
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("NO_COLOR", "1")
        .env(
            "LLVM_PROFILE_FILE",
            profile.path().join("phantom-%p.profraw"),
        )
        .output()
        .expect("run top-level help");

    assert!(output.status.success(), "help must exit successfully");
    assert!(output.stderr.is_empty(), "help must not write to stderr");
    let help = normalize_help(&String::from_utf8(output.stdout).expect("help must be UTF-8"));
    let snapshot = include_str!("snapshots/top_level_help.txt").replace("\r\n", "\n");
    assert_eq!(help, snapshot);
    assert!(std::fs::read_dir(home.path()).unwrap().next().is_none());
    assert!(std::fs::read_dir(project.path()).unwrap().next().is_none());
}
