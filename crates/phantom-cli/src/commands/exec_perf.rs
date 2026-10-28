//! Exercise real exec startup without touching the runner's environment or vault.

#![cfg(unix)]

use phantom_core::config::PhantomConfig;
use phantom_core::token::PhantomToken;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const ISOLATED_ENV: &str = "PHANTOM_TEST_EXEC_PERF_ISOLATED_V1";
const PROBE_ENV: &str = "PHANTOM_TEST_EXEC_PERF_PROBE_V1";
const TIMED_TEST: &str = "commands::exec::perf_tests::exec_startup_has_a_generous_warm_ceiling";
const PROBE_TEST: &str = "commands::exec::perf_tests::exec_child_can_reach_its_authenticated_proxy";

fn fixture(protected: bool) -> tempfile::TempDir {
    let project = tempfile::tempdir().unwrap();
    let path = crate::test_support::canonical_tempdir_path(&project);
    let config_path = path.join(".phantom.toml");
    PhantomConfig::new_with_defaults("exec-performance-fixture".to_owned())
        .save(&config_path)
        .unwrap();
    // Reload so the fixture uses the same directory-derived vault namespace
    // as exec, rather than the repository-controlled serialized project id.
    let config = PhantomConfig::load(&config_path).unwrap();
    let vault = phantom_vault::try_create_vault(config.local_project_id()).unwrap();
    let dotenv = if protected {
        vault
            .store("OPENAI_API_KEY", "synthetic-exec-performance-value")
            .unwrap();
        format!("OPENAI_API_KEY={}\n", PhantomToken::generate().as_str())
    } else {
        "APP_MODE=performance-fixture\n".to_owned()
    };
    std::fs::write(path.join(".env"), dotenv).unwrap();
    project
}

fn median_startup(cmd: &[String]) -> Duration {
    // Warm the executable, filesystem, and TLS initialization before sampling.
    super::run(cmd, None, None, true).unwrap();
    let mut samples = [Duration::ZERO; 5];
    for sample in &mut samples {
        let started = Instant::now();
        super::run(cmd, None, None, true).unwrap();
        *sample = started.elapsed();
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

#[test]
fn exec_startup_has_a_generous_warm_ceiling() {
    if std::env::var(ISOLATED_ENV).as_deref() != Ok("1") {
        // Both cwd and environment are process-global. Re-enter only this
        // test so unrelated parallel tests cannot select a different vault.
        let home = tempfile::tempdir().unwrap();
        let home_path = crate::test_support::canonical_tempdir_path(&home);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TIMED_TEST, "--nocapture"])
            .env_clear()
            .env("HOME", &home_path)
            .env("USERPROFILE", &home_path)
            .env("XDG_CONFIG_HOME", home_path.join("config"))
            .env("XDG_DATA_HOME", home_path.join("data"))
            .env("PATH", "/usr/bin:/bin")
            .env("NO_COLOR", "1")
            .env("PHANTOM_VAULT_PASSPHRASE", "synthetic-exec-perf-passphrase")
            .env(ISOLATED_ENV, "1")
            .env(PROBE_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "isolated exec performance test failed");
                return;
            }
            if Instant::now() >= deadline {
                child.kill().ok();
                child.wait().ok();
                panic!("isolated exec performance test exceeded its watchdog");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    let protected = fixture(true);
    std::env::set_current_dir(crate::test_support::canonical_tempdir_path(&protected)).unwrap();
    let true_command = ["true".to_owned()];
    let proxy_median = median_startup(&true_command);
    // The release target is <50 ms on a warm machine. The regression ceiling
    // deliberately permits hardened Argon2 unlocks in debug builds and busy
    // shared CI runners; it does not relax production KDF parameters.
    assert!(
        proxy_median < Duration::from_secs(2),
        "proxy-backed exec median exceeded 2 seconds: {proxy_median:?}"
    );

    // A current-thread runtime must keep serving requests while it waits for
    // the child; a quick child alone would not establish that property.
    super::run(
        &[
            std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            "--exact".to_owned(),
            PROBE_TEST.to_owned(),
            "--nocapture".to_owned(),
        ],
        None,
        None,
        true,
    )
    .unwrap();

    let direct = fixture(false);
    std::env::set_current_dir(crate::test_support::canonical_tempdir_path(&direct)).unwrap();
    let direct_median = median_startup(&true_command);
    assert!(
        direct_median < Duration::from_secs(2),
        "direct exec median exceeded 2 seconds: {direct_median:?}"
    );
    eprintln!("exec warm medians: proxy={proxy_median:?}, direct={direct_median:?}");

    // Leave both project directories before their cleanup on Windows-like
    // filesystems, and avoid leaving this isolated process in a removed cwd.
    std::env::set_current_dir(PathBuf::from(std::env::var_os("HOME").unwrap())).unwrap();
}

#[test]
fn exec_child_can_reach_its_authenticated_proxy() {
    if std::env::var(PROBE_ENV).as_deref() != Ok("1") {
        return;
    }
    let port = std::env::var("PHANTOM_PROXY_PORT")
        .expect("exec must supply its proxy port")
        .parse::<u16>()
        .expect("exec proxy port must be numeric");
    let token = zeroize::Zeroizing::new(
        std::env::var("PHANTOM_PROXY_TOKEN").expect("exec must supply its proxy authentication"),
    );
    assert!(
        std::env::var_os("PHANTOM_VAULT_PASSPHRASE").is_none(),
        "exec must scrub the vault passphrase"
    );
    let mut stream = TcpStream::connect_timeout(
        &SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into(),
        Duration::from_secs(5),
    )
    .expect("child must connect to its live proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let request = zeroize::Zeroizing::new(format!(
        "GET /phantom/health HTTP/1.1\r\nHost: localhost\r\nX-Phantom-Proxy-Token: {}\r\nConnection: close\r\n\r\n",
        token.as_str()
    ));
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.take(8192).read_to_string(&mut response).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 200 "),
        "authenticated proxy health request must succeed while exec waits"
    );
}
