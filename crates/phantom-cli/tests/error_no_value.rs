//! Runtime-generated sentinels catch plaintext in Display, Debug and source chains.
use phantom_core::importers::{
    doppler::DopplerImporter, dotenvx::DotenvxImporter, infisical::InfisicalImporter,
    onepassword::OnePasswordImporter, Importer,
};
use phantom_vault::{file::FileVault, VaultBackend};

fn canary() -> String {
    use rand::RngCore;
    let mut bytes = [0; 24];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn assert_value_blind(error: &(impl std::fmt::Display + std::fmt::Debug), value: &str) {
    for rendered in [
        format!("{error}"),
        format!("{error:#}"),
        format!("{error:?}"),
        format!("{error:#?}"),
    ] {
        // Never include a potentially leaking diagnostic in assertion output.
        assert!(
            !rendered.contains(value),
            "diagnostic disclosed runtime canary"
        );
        assert!(!rendered.is_empty());
    }
}

#[test]
fn importer_type_errors_do_not_retain_plaintext_sources() {
    let value = canary();
    let scalar = serde_json::to_vec(&value).unwrap();
    for error in [
        DopplerImporter::parse(&scalar).err().unwrap(),
        OnePasswordImporter::parse(&scalar).err().unwrap(),
        DotenvxImporter::parse(format!("{{\"KEY\":\"{value}\",}} ").as_bytes())
            .err()
            .unwrap(),
        InfisicalImporter::parse(format!("[\"{value}\"]").as_bytes())
            .err()
            .unwrap(),
        InfisicalImporter::parse(
            format!("[{{\"key\":\"KEY\",\"value\":\"{value}\",\"value\":0}}]").as_bytes(),
        )
        .err()
        .unwrap(),
    ] {
        assert_value_blind(&error.context("Failed to parse import data"), &value);
    }
}

#[test]
fn decrypted_vault_type_errors_do_not_quote_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let value = canary();
    let passphrase = canary();
    let vault = FileVault::new(dir.path(), "error-canary", passphrase.clone()).unwrap();
    let plaintext = format!("{{\"secrets\":\"{value}\"}}");
    let encrypted = phantom_vault::crypto::encrypt(plaintext.as_bytes(), &passphrase).unwrap();
    let path = dir.path().join("vaults/error-canary.vault");
    std::fs::write(&path, encrypted).unwrap();
    let error = vault.list().expect_err("corrupt schema must fail");
    assert_value_blind(&error, &value);
    assert_value_blind(&error, &passphrase);
    assert!(error.to_string().contains("Corrupt vault data"));
}

#[test]
fn malformed_dotenv_and_config_errors_are_value_blind() {
    let value = canary();
    let dotenv = phantom_core::dotenv::DotenvFile::parse_str(&format!("KEY=\"{value}\n"));
    assert_value_blind(&dotenv.validate_for_mutation().unwrap_err(), &value);
    let dir = tempfile::tempdir().unwrap();
    for content in [
        format!("[phantom]\nproject_id = \"valid\"\n[[sync]]\nplatform = \"{value}\"\n"),
        format!("[phantom]\nproject_id = \"{value}\n"),
    ] {
        let error = phantom_core::config::PhantomConfig::load_from_bytes(
            &dir.path().join(".phantom.toml"),
            content.as_bytes(),
        )
        .unwrap_err();
        assert_value_blind(&error, &value);
    }
}

#[test]
fn command_failures_never_print_plaintext_from_malformed_project() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let value = canary();
    std::fs::write(
        dir.path().join(".phantom.toml"),
        format!("[phantom]\nproject_id = \"{value}\n"),
    )
    .unwrap();
    let cases: &[&[&str]] = &[
        &["exec", "--", "phantom-error-canary-child"],
        &["add", "KEY", "--stdin"],
        &["import", "--from", "env", "--file", "missing.env"],
        &["pull", "--from", "vercel", "--project", "test-project"],
        &["sync", "--platform", "vercel"],
        &["rotate"],
    ];
    for args in cases {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_phantom"))
            .args(*args)
            .current_dir(dir.path())
            .env_clear()
            .env("HOME", home.path())
            .env("NO_COLOR", "1")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success(), "expected command refusal");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("unexpected argument"),
            "fixture must reach command handler"
        );
        assert!(
            !stderr.contains("required arguments"),
            "fixture must reach command handler"
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains(&value),
            "stdout disclosed canary"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains(&value),
            "stderr disclosed canary"
        );
    }
}

#[test]
fn shadow_metadata_type_errors_do_not_retain_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let store = phantom_vault::shadowing::ShadowStore::new(dir.path()).unwrap();
    let value = canary();
    std::fs::write(
        dir.path().join("KEY.shadow.json"),
        format!("{{\"name\":\"KEY\",\"status\":\"{value}\"}}"),
    )
    .unwrap();
    let error = store
        .load_meta("KEY")
        .expect_err("invalid status must fail");
    assert_value_blind(&error, &value);
}

#[tokio::test]
async fn proxy_route_errors_do_not_echo_request_plaintext() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let value = canary();
    let token = canary();
    let proxy = phantom_proxy::ProxyServer::start(
        phantom_proxy::ProxyConfig {
            proxy_token: token.clone(),
            ..Default::default()
        },
        phantom_proxy::ServiceRegistry::new(),
        phantom_proxy::Interceptor::new(Default::default()),
    )
    .await
    .unwrap();
    let mut connection = tokio::net::TcpStream::connect(("127.0.0.1", proxy.port()))
        .await
        .unwrap();
    connection.write_all(format!("GET /{value} HTTP/1.1\r\nHost: localhost\r\nX-Phantom-Proxy-Token: {token}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        connection.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    proxy.shutdown().await;
    let response = String::from_utf8(response).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 404"),
        "expected route refusal"
    );
    assert!(
        !response.contains(&value),
        "proxy error disclosed request canary"
    );
    assert!(
        !response.contains(&token),
        "proxy error disclosed auth canary"
    );
}

#[test]
fn legacy_vault_migration_errors_do_not_quote_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("vaults")).unwrap();
    let value = canary();
    std::fs::write(
        dir.path().join("vaults/error-canary.json"),
        format!("{{\"secrets\":\"{value}\"}}"),
    )
    .unwrap();
    let error = FileVault::new(dir.path(), "error-canary", canary())
        .err()
        .expect("invalid legacy schema must fail");
    assert_value_blind(&error, &value);
}

#[test]
fn cryptographic_failures_do_not_quote_ciphertext_or_passphrase() {
    let value = canary();
    let passphrase = canary();
    let encrypted = phantom_vault::crypto::encrypt(value.as_bytes(), &passphrase).unwrap();
    let error = phantom_vault::crypto::decrypt(&encrypted, &canary()).unwrap_err();
    assert_value_blind(&error, &value);
    assert_value_blind(&error, &passphrase);
    let error = phantom_vault::crypto::decrypt(value.as_bytes(), &passphrase).unwrap_err();
    assert_value_blind(&error, &value);
    assert_value_blind(&error, &passphrase);
}
