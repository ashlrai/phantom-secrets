use std::process::Command;

#[test]
fn help_exits_zero_and_lists_a_command() {
    let home = tempfile::tempdir().expect("create isolated home");
    let project = tempfile::tempdir().expect("create isolated project");
    let output = Command::new(env!("CARGO_BIN_EXE_phantom"))
        .arg("--help")
        .current_dir(project.path())
        .env_clear()
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .output()
        .expect("run phantom --help");

    assert_eq!(output.status.code(), Some(0), "help must exit 0");
    let help = String::from_utf8(output.stdout).expect("help must be UTF-8");
    assert!(
        help.lines()
            .any(|line| line.split_whitespace().next() == Some("init")),
        "help must list the init command"
    );
}
