use assert_cmd::Command;

#[test]
fn unknown_command_exits_nonzero() {
    let output = Command::cargo_bin("phantom")
        .expect("binary not found")
        .arg("definitely-not-a-phantom-command")
        .output()
        .expect("run phantom");

    assert!(
        output.status.code().is_some_and(|code| code != 0),
        "unknown command did not exit with a non-zero code"
    );
}
