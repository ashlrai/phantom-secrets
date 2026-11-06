//! An unknown global flag must fail fast with a non-zero exit and an error
//! that names the flag, so the user (or an agent) can see what to fix.

use std::process::Command;

const UNKNOWN_FLAG: &str = "--no-such-flag";

#[test]
fn unknown_flag_exits_nonzero_and_names_the_flag() {
    let home = tempfile::tempdir().expect("create isolated home");
    let project = tempfile::tempdir().expect("create isolated project");
    let output = Command::new(env!("CARGO_BIN_EXE_phantom"))
        .arg(UNKNOWN_FLAG)
        .current_dir(project.path())
        .env_clear()
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .env("NO_COLOR", "1")
        .output()
        .expect("run phantom with an unknown flag");

    assert!(
        output.status.code().is_some_and(|code| code != 0),
        "unknown flag must exit non-zero, got {:?}",
        output.status
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr must be UTF-8");
    assert!(
        stderr.contains(UNKNOWN_FLAG),
        "error output must name the unknown flag {UNKNOWN_FLAG}, got:\n{stderr}"
    );
}
