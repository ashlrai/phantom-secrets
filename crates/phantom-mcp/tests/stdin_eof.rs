use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn exits_within_five_seconds_when_host_closes_stdin() {
    let home = tempfile::tempdir().expect("create isolated home");
    let mut child = Command::new(env!("CARGO_BIN_EXE_phantom-mcp"))
        .env_clear()
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .current_dir(home.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn built phantom-mcp binary");

    let deadline = Instant::now() + Duration::from_secs(5);
    // Dropping the host's pipe closes stdin without sending a shutdown request.
    drop(child.stdin.take().expect("host owns stdin pipe"));
    loop {
        match child.try_wait() {
            // EOF during initialization may produce an error exit; either status
            // must terminate the process rather than leave an orphan behind.
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            result => {
                // Reap the process on failure so the regression cannot orphan it.
                let _ = child.kill();
                let _ = child.wait();
                panic!("phantom-mcp did not exit within five seconds of stdin EOF: {result:?}");
            }
        }
    }
}
