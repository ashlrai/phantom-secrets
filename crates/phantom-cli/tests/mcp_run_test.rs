//! Configured stdio MCP servers inherit a value-blind Phantom proxy session.
//! Assertions deliberately report only exit codes, never child environments,
//! argument dumps, credentials, or the persistent/session mappings.
#![cfg(unix)]

mod common;

use std::fs;
use std::io::Write;
use std::process::{Command, Output, Stdio};

use phantom_core::dotenv::DotenvFile;
use rand::RngCore;
use serde_json::{json, Value};
use tempfile::TempDir;

const VAULT_PASS: &str = "mcp-run-disposable-test-unlock-phrase";

struct Fixture {
    project: TempDir,
    home: TempDir,
    vault_value: String,
    persistent_mapping: String,
}

impl Fixture {
    fn new() -> Self {
        let project = common::canonical_tempdir();
        let home = common::canonical_tempdir();
        let mut random = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut random);
        let vault_value = format!("sk-test-mcp-vault-{}", hex::encode(random));
        fs::write(
            project.path().join(".env"),
            format!("OPENAI_API_KEY={vault_value}\n"),
        )
        .unwrap();
        let mut fixture = Self {
            project,
            home,
            vault_value,
            persistent_mapping: String::new(),
        };
        let output = fixture
            .command()
            .args(["init", "--from", ".env"])
            .output()
            .unwrap();
        fixture.assert_value_blind(&output);
        assert!(output.status.success(), "disposable project init failed");
        let dotenv = DotenvFile::parse_file(&fixture.project.path().join(".env")).unwrap();
        fixture.persistent_mapping = dotenv
            .entries()
            .into_iter()
            .find(|entry| entry.key == "OPENAI_API_KEY")
            .expect("protected key is present")
            .value
            .clone();
        assert!(fixture.persistent_mapping.starts_with("phm_"));
        fixture
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_phantom"));
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", self.home.path())
            .env("USERPROFILE", self.home.path())
            .env("NO_COLOR", "1")
            .env("PHANTOM_VAULT_PASSPHRASE", VAULT_PASS)
            .current_dir(self.project.path());
        command
    }

    fn config(&self, server: Value) {
        fs::write(
            self.project.path().join(".mcp.json"),
            serde_json::to_vec(&json!({"mcpServers": {"fixture": server}})).unwrap(),
        )
        .unwrap();
    }

    fn script(&self, script: &str) {
        fs::write(self.project.path().join("mcp-child.sh"), script).unwrap();
    }

    fn run(&self) -> Output {
        self.command()
            .args(["mcp", "run", "fixture"])
            .output()
            .unwrap()
    }

    fn assert_value_blind(&self, output: &Output) {
        for stream in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(stream);
            assert!(!text.contains(&self.vault_value), "vault value escaped");
            assert!(!text.contains(VAULT_PASS), "vault unlock phrase escaped");
            if !self.persistent_mapping.is_empty() {
                assert!(
                    !text.contains(&self.persistent_mapping),
                    "persistent mapping escaped"
                );
            }
        }
    }

    fn assert_refused_before_spawn(&self, output: &Output) {
        self.assert_value_blind(output);
        assert!(!output.status.success(), "unsafe launch was accepted");
        assert!(
            !self.project.path().join("child-started").exists(),
            "refusal happened after child launch"
        );
    }
}

#[test]
fn mcp_child_receives_fresh_placeholders_proxy_urls_and_no_vault_values() {
    let fixture = Fixture::new();
    fixture.script(
        r#"set -eu
case "$OPENAI_API_KEY" in phm_*) ;; *) exit 11 ;; esac
case "$OPENAI_BASE_URL" in http://127.0.0.1:*/openai/_phantom/*) ;; *) exit 12 ;; esac
test -n "$PHANTOM_PROXY_TOKEN" || exit 13
test -z "${PHANTOM_VAULT_PASSPHRASE+x}" || exit 14
test -z "${MCP_RAW_ALIAS+x}" || exit 15
test "$MODE" = fixture-mode || exit 16
test "$#" -eq 1 && test "$1" = safe-marker || exit 17
for arg do case "$arg" in *sk-test-mcp-vault-*) exit 18 ;; esac; done
# Inspect every inherited environment value inside the child, emitting none.
awk 'BEGIN { for (name in ENVIRON) if (index(ENVIRON[name], "sk-test-mcp-vault-") != 0) exit 20 }'
# Compare inside the child, without printing either mapping. The managed file
# contains only a persistent placeholder after init, never the vaulted value.
session_key=$OPENAI_API_KEY
. ./.env
test "$session_key" != "$OPENAI_API_KEY" || exit 19
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protected":true}}'
"#,
    );
    fixture.config(json!({
        "command": "sh",
        "args": ["mcp-child.sh", "safe-marker"],
        "env": {
            "MODE": "fixture-mode",
            "OPENAI_API_KEY": fixture.persistent_mapping,
        },
    }));
    let output = fixture
        .command()
        .args(["mcp", "run", "fixture"])
        .env("OPENAI_API_KEY", &fixture.vault_value)
        .env(
            "MCP_RAW_ALIAS",
            format!("prefix:{}:suffix", fixture.vault_value),
        )
        .env("OPENAI_BASE_URL", "https://stale.example.invalid")
        .output()
        .unwrap();
    fixture.assert_value_blind(&output);
    assert!(
        output.status.success(),
        "protected child assertion failed with {:?}",
        output.status.code()
    );
    assert_eq!(
        output.stdout,
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protected\":true}}\n"
    );
}

#[test]
fn mcp_preserves_stdio_and_supports_an_explicit_config_path() {
    let fixture = Fixture::new();
    fixture.config(json!({"command": "sh", "args": ["-c", "cat"]}));
    fs::rename(
        fixture.project.path().join(".mcp.json"),
        fixture.project.path().join("servers.json"),
    )
    .unwrap();
    let mut child = fixture
        .command()
        .args(["mcp", "run", "fixture", "--config", "servers.json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"initialize\"}\n";
    child.stdin.take().unwrap().write_all(request).unwrap();
    let output = child.wait_with_output().unwrap();
    fixture.assert_value_blind(&output);
    assert!(output.status.success(), "stdio child failed");
    assert_eq!(output.stdout, request);
}

#[test]
fn mcp_propagates_child_exit_status_without_protocol_chatter() {
    let fixture = Fixture::new();
    fixture.config(json!({"command": "sh", "args": ["-c", "exit 37"]}));
    let output = fixture.run();
    fixture.assert_value_blind(&output);
    assert_eq!(output.status.code(), Some(37));
    assert!(output.stdout.is_empty());
}

#[test]
fn mcp_refuses_vault_values_in_arguments_before_spawning() {
    let fixture = Fixture::new();
    fixture.script("touch child-started\n");
    fixture.config(json!({
        "command": "sh",
        "args": ["mcp-child.sh", format!("--credential={}", fixture.vault_value)],
    }));
    fixture.assert_refused_before_spawn(&fixture.run());
}

#[test]
fn mcp_refuses_vault_values_in_configured_environment_aliases() {
    let fixture = Fixture::new();
    fixture.script("touch child-started\n");
    fixture.config(json!({
        "command": "sh",
        "args": ["mcp-child.sh"],
        "env": {"MCP_CONFIG_ALIAS": format!("prefix:{}:suffix", fixture.vault_value)},
    }));
    fixture.assert_refused_before_spawn(&fixture.run());
}

#[test]
fn mcp_refuses_plaintext_literals_for_protected_environment_keys() {
    let fixture = Fixture::new();
    fixture.script("touch child-started\n");
    for value in [
        &fixture.vault_value,
        &"different-plaintext-literal".to_string(),
    ] {
        fixture.config(json!({
            "command": "sh",
            "args": ["mcp-child.sh"],
            "env": {"OPENAI_API_KEY": value},
        }));
        fixture.assert_refused_before_spawn(&fixture.run());
    }
}

#[test]
fn mcp_refuses_internal_and_route_environment_overrides() {
    let fixture = Fixture::new();
    fixture.script("touch child-started\n");
    for key in [
        "OPENAI_BASE_URL",
        "PHANTOM_PROXY_TOKEN",
        "PHANTOM_VAULT_PASSPHRASE",
        "PHANTOM_MCP_EFFECTS",
    ] {
        let mut environment = serde_json::Map::new();
        environment.insert(key.to_string(), json!("rejected-override"));
        fixture.config(json!({
            "command": "sh",
            "args": ["mcp-child.sh"],
            "env": environment,
        }));
        fixture.assert_refused_before_spawn(&fixture.run());
    }
}

#[test]
fn mcp_refuses_persistent_mapping_arguments_without_echoing_them() {
    let fixture = Fixture::new();
    fixture.script("touch child-started\n");
    fixture.config(json!({
        "command": "sh",
        "args": ["mcp-child.sh", fixture.persistent_mapping],
    }));
    fixture.assert_refused_before_spawn(&fixture.run());
}

#[test]
fn mcp_missing_config_or_server_fails_without_disclosing_other_entries() {
    let fixture = Fixture::new();
    fixture.assert_refused_before_spawn(&fixture.run());
    fixture.config(json!({"command": "sh", "args": ["-c", "touch child-started"]}));
    let output = fixture
        .command()
        .args(["mcp", "run", "missing-server"])
        .output()
        .unwrap();
    fixture.assert_refused_before_spawn(&output);
    // A malformed selected entry must not echo its source JSON value either.
    fixture.config(json!({"command": fixture.vault_value, "args": "invalid-args"}));
    fixture.assert_refused_before_spawn(&fixture.run());
}

#[test]
fn mcp_refuses_symlinked_and_oversized_configuration_before_spawn() {
    use std::os::unix::fs::symlink;

    let fixture = Fixture::new();
    fixture.script("touch child-started\n");
    fixture.config(json!({"command": "sh", "args": ["mcp-child.sh"]}));
    let config = fixture.project.path().join(".mcp.json");
    let target = fixture.project.path().join("servers-target.json");
    fs::rename(&config, &target).unwrap();
    symlink(&target, &config).unwrap();
    fixture.assert_refused_before_spawn(&fixture.run());
    fs::remove_file(&config).unwrap();
    fs::write(
        &config,
        vec![b' '; phantom_mcp::launch::MAX_CONFIG_BYTES + 1],
    )
    .unwrap();
    fixture.assert_refused_before_spawn(&fixture.run());
}

#[test]
fn mcp_refuses_an_unopenable_file_vault_before_spawn() {
    let fixture = Fixture::new();
    fixture.script("touch child-started\n");
    fixture.config(json!({"command": "sh", "args": ["mcp-child.sh"]}));
    // Keep explicit file-vault selection. Unsetting the phrase would allow
    // the platform OS keychain to be selected despite the disposable HOME.
    let output = fixture
        .command()
        .args(["mcp", "run", "fixture"])
        .env(
            "PHANTOM_VAULT_PASSPHRASE",
            "incorrect-disposable-unlock-phrase",
        )
        .output()
        .unwrap();
    fixture.assert_refused_before_spawn(&output);
}

#[test]
fn mcp_refuses_a_protected_mapping_without_its_vault_entry() {
    fn remove_fixture_vault_files(directory: &std::path::Path) -> usize {
        let mut removed = 0;
        for item in fs::read_dir(directory).unwrap() {
            let item = item.unwrap();
            let kind = item.file_type().unwrap();
            if kind.is_dir() {
                removed += remove_fixture_vault_files(&item.path());
            } else if kind.is_file() && item.path().extension().is_some_and(|ext| ext == "vault") {
                fs::remove_file(item.path()).unwrap();
                removed += 1;
            }
        }
        removed
    }

    let fixture = Fixture::new();
    fixture.script("touch child-started\n");
    fixture.config(json!({"command": "sh", "args": ["mcp-child.sh"]}));
    // Delete only this test's encrypted fixture, without opening or reading
    // its stored values. The managed dotenv still declares a protected key.
    assert_eq!(remove_fixture_vault_files(fixture.home.path()), 1);
    fixture.assert_refused_before_spawn(&fixture.run());
}

#[test]
fn mcp_refuses_repository_controlled_proxy_route_changes() {
    let fixture = Fixture::new();
    fixture.script("touch child-started\n");
    fixture.config(json!({"command": "sh", "args": ["mcp-child.sh"]}));
    let config_path = fixture.project.path().join(".phantom.toml");
    let mut config = phantom_core::config::PhantomConfig::load(&config_path).unwrap();
    config
        .services
        .get_mut("openai")
        .expect("fixture has the OpenAI route")
        .pattern = Some("unapproved.example.invalid".to_string());
    config.save(&config_path).unwrap();
    fixture.assert_refused_before_spawn(&fixture.run());
}

#[test]
fn mcp_preserves_shell_convention_codes_for_spawn_failures() {
    let fixture = Fixture::new();
    fixture.config(json!({"command": "phantom-mcp-fixture-command-that-does-not-exist"}));
    let output = fixture.run();
    fixture.assert_value_blind(&output);
    assert_eq!(output.status.code(), Some(127));
    assert!(output.stdout.is_empty());

    fixture.script("exit 0\n");
    fixture.config(json!({"command": "./mcp-child.sh"}));
    let output = fixture.run();
    fixture.assert_value_blind(&output);
    assert_eq!(output.status.code(), Some(126));
    assert!(output.stdout.is_empty());
}

/// Reexecuted by the outer test as the configured MCP command. The ordinary
/// test-suite invocation is inert; only a disposable fixture supplies this
/// private marker. Neither environment values nor HTTP requests are printed.
#[test]
fn mcp_http_child_fixture() {
    use std::io::{BufRead, BufReader};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
    use std::time::Duration;

    let Some(directory) = std::env::var_os("MCP_HTTP_FIXTURE_DIR") else {
        return;
    };
    for (_, value) in std::env::vars_os() {
        assert!(
            !value.to_string_lossy().contains("sk-test-mcp-vault-"),
            "child environment contains a raw fixture credential"
        );
    }
    for argument in std::env::args_os() {
        assert!(
            !argument.to_string_lossy().contains("sk-test-mcp-vault-"),
            "child argument contains a raw fixture credential"
        );
    }
    assert!(
        std::env::var_os("PHANTOM_VAULT_PASSPHRASE").is_none(),
        "vault unlock phrase reached the child"
    );
    let key = std::env::var("OPENAI_API_KEY")
        .unwrap_or_else(|_| panic!("protected child key is absent or invalid"));
    assert!(key.starts_with("phm_"), "child key is not a placeholder");
    let port = std::env::var("PHANTOM_PROXY_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .expect("session port is absent or invalid");
    let token = std::env::var("PHANTOM_PROXY_TOKEN")
        .unwrap_or_else(|_| panic!("session authentication is absent or invalid"));
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    for authenticated in [false, true] {
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3))
            .expect("cannot connect to child session proxy");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let authentication = if authenticated {
            format!("x-phantom-proxy-token: {token}\r\n")
        } else {
            String::new()
        };
        let request = format!(
            "GET /phantom/health HTTP/1.1\r\nHost: 127.0.0.1\r\n{authentication}Connection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .expect("cannot write local health request");
        let mut status = String::new();
        BufReader::new(stream)
            .read_line(&mut status)
            .expect("cannot read local health status");
        if authenticated {
            assert!(
                status.starts_with("HTTP/1.1 200 "),
                "authenticated session health request was refused"
            );
        } else {
            assert!(
                status.starts_with("HTTP/1.1 401 "),
                "unauthenticated session health request was accepted"
            );
        }
    }
    fs::write(
        std::path::Path::new(&directory).join("proxy-port"),
        port.to_string(),
    )
    .unwrap();
}

#[test]
fn mcp_session_proxy_requires_authentication_and_stops_with_child() {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
    use std::time::Duration;

    let fixture = Fixture::new();
    let executable = std::env::current_exe().unwrap();
    fixture.config(json!({
        "command": executable,
        "args": ["--exact", "mcp_http_child_fixture", "--nocapture", "--test-threads=1"],
        "env": {"MCP_HTTP_FIXTURE_DIR": fixture.project.path()},
    }));
    let output = fixture
        .command()
        .args(["mcp", "run", "fixture"])
        .env(
            "MCP_RAW_ALIAS",
            format!("prefix:{}:suffix", fixture.vault_value),
        )
        .output()
        .unwrap();
    fixture.assert_value_blind(&output);
    assert!(
        output.status.success(),
        "local HTTP child assertion failed with {:?}",
        output.status.code()
    );
    let port: u16 = fs::read_to_string(fixture.project.path().join("proxy-port"))
        .expect("child did not record its nonsecret proxy port")
        .parse()
        .unwrap();
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    assert!(
        TcpStream::connect_timeout(&address, Duration::from_secs(3)).is_err(),
        "session proxy remained reachable after the MCP child exited"
    );
}

#[test]
fn mcp_never_uses_framework_plaintext_environment_passthrough() {
    let fixture = Fixture::new();
    let dotenv_path = fixture.project.path().join(".env");
    let managed_dotenv = fs::read_to_string(&dotenv_path).unwrap();
    fs::write(
        &dotenv_path,
        format!(
            "{managed_dotenv}\nNEXT_PUBLIC_FIXTURE={}\n",
            fixture.vault_value
        ),
    )
    .unwrap();
    fs::write(
        fixture.project.path().join("package.json"),
        br#"{"dependencies":{"next":"*"}}"#,
    )
    .unwrap();
    fixture.script(
        r#"set -eu
test -z "${NEXT_PUBLIC_FIXTURE+x}" || exit 31
awk 'BEGIN { for (name in ENVIRON) if (index(ENVIRON[name], "sk-test-mcp-vault-") != 0) exit 32 }'
printf '%s\n' 'framework-passthrough-disabled'
"#,
    );
    fixture.config(json!({"command": "sh", "args": ["mcp-child.sh"]}));
    let output = fixture.run();
    fixture.assert_value_blind(&output);
    assert!(
        output.status.success(),
        "framework passthrough child assertion failed with {:?}",
        output.status.code()
    );
    assert_eq!(output.stdout, b"framework-passthrough-disabled\n");
}

#[test]
fn mcp_refuses_protected_markers_under_proxy_owned_variable_names() {
    let fixture = Fixture::new();
    fixture.script("touch child-started\n");
    fixture.config(json!({"command": "sh", "args": ["mcp-child.sh"]}));
    let dotenv_path = fixture.project.path().join(".env");
    let managed_dotenv = fs::read_to_string(&dotenv_path).unwrap();
    for name in ["PHANTOM_PROXY_TOKEN", "OPENAI_BASE_URL"] {
        let marker = phantom_core::token::PhantomToken::generate();
        fs::write(
            &dotenv_path,
            format!("{managed_dotenv}\n{name}={}\n", marker.as_str()),
        )
        .unwrap();
        let output = fixture.run();
        fixture.assert_refused_before_spawn(&output);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(
                "MCP protected keys cannot use Phantom internal or proxy URL variable names"
            ),
            "owned variable did not receive the specific launch refusal"
        );
        for stream in [&output.stdout, &output.stderr] {
            assert!(
                !String::from_utf8_lossy(stream).contains(marker.as_str()),
                "protected marker escaped in launch diagnostics"
            );
        }
    }
}
