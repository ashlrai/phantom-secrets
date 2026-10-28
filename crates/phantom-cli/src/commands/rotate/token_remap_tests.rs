use super::*;
use phantom_core::error::{PhantomError, Result as PhantomResult};
use phantom_core::validator::ValidationMetadata;
use phantom_vault::SecretMetadata;
use tempfile::tempdir;
use zeroize::Zeroizing;

fn sample_plan() -> LocalTokenRemapPlan {
    let project_dir = PathBuf::from("/canonical/project");
    let config_before = b"[phantom]\nversion = \"1\"\n".to_vec();
    let env_before = format!("A=phm_{}\nB=phm_{}\n", "a".repeat(64), "b".repeat(64)).into_bytes();
    let names = vec!["A".to_string(), "B".to_string()];
    LocalTokenRemapPlan {
        project_identity: TrustedAnchor::open_canonical(std::env::current_dir().unwrap())
            .unwrap()
            .identity(),
        config_path: project_dir.join(".phantom.toml"),
        config_digest: digest_bytes(b"phantom-local-token-remap-config-v1\0", &config_before),
        config_before,
        local_project_id: "local-project-id".to_string(),
        env_path: project_dir.join(".env"),
        env_identity: TrustedAnchor::open_canonical(std::env::current_dir().unwrap())
            .unwrap()
            .identity(),
        env_permissions: AnchoredFilePermissions::private(),
        env_digest: digest_bytes(b"phantom-local-token-remap-dotenv-v1\0", &env_before),
        env_before,
        names_digest: names_digest(&names),
        names,
        project_dir,
    }
}

struct ListOnlyVault {
    names: Vec<String>,
}

impl VaultBackend for ListOnlyVault {
    fn store(&self, _name: &str, _value: &str) -> PhantomResult<()> {
        unreachable!("token-remap verification must not store a vault value")
    }
    fn retrieve(&self, _name: &str) -> PhantomResult<Zeroizing<String>> {
        unreachable!("token-remap verification must not retrieve a vault value")
    }
    fn delete(&self, _name: &str) -> PhantomResult<()> {
        unreachable!("token-remap verification must not delete a vault value")
    }
    fn list(&self) -> PhantomResult<Vec<String>> {
        Ok(self.names.clone())
    }
    fn backend_name(&self) -> &str {
        "list-only"
    }
}

fn filesystem_plan() -> (tempfile::TempDir, LocalTokenRemapPlan, PhantomConfig) {
    let dir = tempdir().unwrap();
    let project_dir = dir.path().canonicalize().unwrap();
    let config_path = project_dir.join(".phantom.toml");
    PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(&project_dir))
        .save(&config_path)
        .unwrap();
    let config_before = phantom_core::fs::read_regular_file(&config_path)
        .unwrap()
        .unwrap();
    let config = PhantomConfig::load_from_bytes(&config_path, &config_before).unwrap();
    let env_path = project_dir.join(".env");
    let env_before = format!("A=phm_{}\nB=phm_{}\n", "a".repeat(64), "b".repeat(64)).into_bytes();
    std::fs::write(&env_path, &env_before).unwrap();
    let env_path = env_path.canonicalize().unwrap();
    let project_anchor = TrustedAnchor::open(&project_dir).unwrap();
    let env_review = project_anchor
        .target(".env")
        .unwrap()
        .read_regular()
        .unwrap()
        .unwrap();
    let names = vec!["A".to_string(), "B".to_string()];
    let plan = LocalTokenRemapPlan {
        project_identity: project_anchor.identity(),
        project_dir,
        config_path,
        config_digest: digest_bytes(b"phantom-local-token-remap-config-v1\0", &config_before),
        config_before,
        local_project_id: config.local_project_id().to_string(),
        env_path,
        env_identity: env_review.identity(),
        env_permissions: env_review.permissions(),
        env_digest: digest_bytes(b"phantom-local-token-remap-dotenv-v1\0", &env_before),
        env_before,
        names_digest: names_digest(&names),
        names,
    };
    (dir, plan, config)
}

#[test]
fn trusted_terminal_challenge_is_exact_and_snapshot_bound() {
    let plan = sample_plan();
    let challenge = plan.challenge().unwrap();
    let mut input = std::io::Cursor::new(format!("{challenge}\n"));
    let mut output = Vec::new();
    require_trusted_terminal_rotate_with(&plan, &mut input, &mut output).unwrap();
    let rendered = String::from_utf8(output).unwrap();
    assert!(rendered.contains(&challenge));
    assert!(rendered.contains("Protected names (sorted, JSON escaped): [\"A\",\"B\"]"));

    let mut changed_config = sample_plan();
    changed_config.config_before.push(b'#');
    changed_config.config_digest = digest_bytes(
        b"phantom-local-token-remap-config-v1\0",
        &changed_config.config_before,
    );
    assert_ne!(challenge, changed_config.challenge().unwrap());

    let mut changed_dotenv = sample_plan();
    changed_dotenv.env_before.push(b'\n');
    changed_dotenv.env_digest = digest_bytes(
        b"phantom-local-token-remap-dotenv-v1\0",
        &changed_dotenv.env_before,
    );
    assert_ne!(challenge, changed_dotenv.challenge().unwrap());

    let mut changed_names = sample_plan();
    changed_names.names.push("C".to_string());
    changed_names.names_digest = names_digest(&changed_names.names);
    assert_ne!(challenge, changed_names.challenge().unwrap());
}

#[test]
fn trusted_terminal_challenge_rejects_non_exact_response() {
    let plan = sample_plan();
    let mut input = std::io::Cursor::new(format!("{} \n", plan.challenge().unwrap()));
    let error =
        require_trusted_terminal_rotate_with(&plan, &mut input, &mut Vec::new()).unwrap_err();
    assert!(error
        .to_string()
        .contains("confirmation did not match exactly"));
}

#[test]
fn trusted_terminal_challenge_rejects_control_bearing_paths() {
    let mut plan = sample_plan();
    plan.project_dir = PathBuf::from("/tmp/project\nFORGED CHALLENGE");
    let error = plan.challenge().unwrap_err();
    assert!(error
        .to_string()
        .contains("control characters from the project path"));

    let mut plan = sample_plan();
    plan.env_path = PathBuf::from("/tmp/.env\u{1b}[2J");
    let error = plan.challenge().unwrap_err();
    assert!(error
        .to_string()
        .contains("control characters from the managed dotenv path"));
}

#[test]
fn approved_plan_rejects_name_set_drift_before_dotenv_mutation() {
    let (_dir, plan, config) = filesystem_plan();
    let dotenv_before = std::fs::read(&plan.env_path).unwrap();
    let transaction_lock =
        phantom_vault::acquire_project_transaction_lock(&plan.project_dir).unwrap();
    let error = plan
        .commit_with_verified_config(
            &transaction_lock,
            &config,
            &ListOnlyVault {
                names: vec!["A".to_string(), "C".to_string()],
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("protected-name set changed"));
    assert_eq!(std::fs::read(&plan.env_path).unwrap(), dotenv_before);
}

#[test]
fn approved_plan_rejects_dotenv_drift_and_preserves_other_writer() {
    let (_dir, plan, config) = filesystem_plan();
    let concurrent = format!("A=phm_{}\nB=phm_{}\n", "c".repeat(64), "d".repeat(64)).into_bytes();
    std::fs::write(&plan.env_path, &concurrent).unwrap();
    let transaction_lock =
        phantom_vault::acquire_project_transaction_lock(&plan.project_dir).unwrap();
    let error = plan
        .commit_with_verified_config(
            &transaction_lock,
            &config,
            &ListOnlyVault {
                names: plan.names.clone(),
            },
        )
        .unwrap_err();
    assert!(error.to_string().contains("managed dotenv changed"));
    assert_eq!(std::fs::read(&plan.env_path).unwrap(), concurrent);
}

#[cfg(windows)]
#[test]
fn windows_token_remap_accepts_verified_namespace_commit() {
    let (_dir, plan, config) = filesystem_plan();
    let before = plan.env_before.clone();
    let transaction_lock =
        phantom_vault::acquire_project_transaction_lock(&plan.project_dir).unwrap();

    plan.commit_with_verified_config(
        &transaction_lock,
        &config,
        &ListOnlyVault {
            names: plan.names.clone(),
        },
    )
    .unwrap();

    let after = std::fs::read(&plan.env_path).unwrap();
    assert_ne!(after, before);
    validate_protected_placeholders(&plan.env_path, &plan.names, &after).unwrap();
}

#[cfg(unix)]
#[test]
fn approved_plan_rejects_byte_identical_dotenv_decoy() {
    let (_dir, plan, config) = filesystem_plan();
    let moved = plan.project_dir.join(".env.reviewed");
    std::fs::rename(&plan.env_path, &moved).unwrap();
    std::fs::write(&plan.env_path, &plan.env_before).unwrap();
    let transaction_lock =
        phantom_vault::acquire_project_transaction_lock(&plan.project_dir).unwrap();
    let error = plan
        .commit_with_verified_config(
            &transaction_lock,
            &config,
            &ListOnlyVault {
                names: plan.names.clone(),
            },
        )
        .unwrap_err();

    assert!(error.to_string().contains("managed dotenv changed"));
    assert_eq!(std::fs::read(&plan.env_path).unwrap(), plan.env_before);
    assert_eq!(std::fs::read(moved).unwrap(), plan.env_before);
}

#[cfg(unix)]
#[test]
fn reviewed_project_lock_rejects_same_path_replacement() {
    let container = tempdir().unwrap();
    let container = container.path().canonicalize().unwrap();
    let project = container.join("project");
    let moved = container.join("moved");
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join(".phantom.toml"), b"approved\n").unwrap();
    let reviewed = TrustedAnchor::open(&project).unwrap();

    let error = acquire_reviewed_project_lock(
        &project,
        &reviewed,
        || {
            std::fs::rename(&project, &moved).unwrap();
            std::fs::create_dir(&project).unwrap();
            std::fs::write(project.join(".phantom.toml"), b"decoy\n").unwrap();
        },
        "provider rotation",
    )
    .err()
    .expect("same-path replacement must be rejected");

    assert!(error.to_string().contains("Project root was replaced"));
    assert_eq!(
        std::fs::read(moved.join(".phantom.toml")).unwrap(),
        b"approved\n"
    );
    assert_eq!(
        std::fs::read(project.join(".phantom.toml")).unwrap(),
        b"decoy\n"
    );
}

#[test]
fn provider_call_is_ordered_after_strict_dotenv_revalidation() {
    let source = concat!(include_str!("mod.rs"), include_str!("provider.rs"));
    let provider = source
        .split("pub fn run_with_provider")
        .nth(1)
        .unwrap()
        .split("pub fn")
        .next()
        .unwrap();
    let provider_edge = provider.find("config_at_provider_edge").unwrap();
    let strict_revalidation = provider[provider_edge..]
        .find("validate_managed_dotenv_for_mutation")
        .unwrap()
        + provider_edge;
    let provider_call = provider[provider_edge..]
        .find("let new_value = auto_sync_rotation_with_bootstrap")
        .unwrap()
        + provider_edge;
    assert!(provider_edge < strict_revalidation && strict_revalidation < provider_call);
}

#[test]
fn vault_resolution_precedes_project_lock_source_contract() {
    let source = concat!(include_str!("mod.rs"), include_str!("provider.rs"));
    let provider = source
        .split("pub fn run_with_provider")
        .nth(1)
        .unwrap()
        .split("pub fn")
        .next()
        .unwrap();
    let anchor = provider.find("TrustedAnchor::open").unwrap();
    let vault = provider.find("open_vault(").unwrap();
    let project_lock = provider.find("acquire_reviewed_project_lock").unwrap();
    assert!(anchor < vault && vault < project_lock);

    let commit = source
        .split("fn commit_with_before_project_lock")
        .nth(1)
        .unwrap()
        .split("fn commit_with_verified_config")
        .next()
        .unwrap();
    let approved_identity = commit.find("self.project_identity").unwrap();
    let dotenv_identity = commit.find("self.env_identity").unwrap();
    let vault = commit.find("try_create_vault").unwrap();
    let project_lock = commit.find("acquire_reviewed_project_lock").unwrap();
    assert!(approved_identity < dotenv_identity);
    assert!(dotenv_identity < vault && vault < project_lock);
}

#[test]
fn remap_changes_only_requested_protected_placeholder() {
    let dir = tempdir().unwrap();
    let env_path = dir.path().join(".env");
    let old = format!("phm_{}", "a".repeat(64));
    let untouched = format!("phm_{}", "b".repeat(64));
    std::fs::write(
        &env_path,
        format!("TARGET={old}\nOTHER={untouched}\nPUBLIC=yes\n"),
    )
    .unwrap();

    remap_phantom_tokens(&env_path, &["TARGET".to_string()]).unwrap();

    let rewritten = std::fs::read_to_string(&env_path).unwrap();
    assert!(!rewritten.contains(&format!("TARGET={old}")));
    assert!(rewritten.contains("TARGET=phm_"));
    assert!(rewritten.contains(&format!("OTHER={untouched}")));
    assert!(rewritten.contains("PUBLIC=yes"));
}

#[test]
fn remap_fails_closed_for_plaintext_and_preserves_file() {
    let dir = tempdir().unwrap();
    let env_path = dir.path().join(".env");
    let before = "TARGET=real-provider-value\n";
    std::fs::write(&env_path, before).unwrap();

    let error = remap_phantom_tokens(&env_path, &["TARGET".to_string()]).unwrap_err();

    assert!(error.to_string().contains("not a protected phm_ token"));
    assert_eq!(std::fs::read_to_string(&env_path).unwrap(), before);
}

#[test]
fn remap_detects_concurrent_file_change_and_preserves_the_other_writer() {
    let dir = tempdir().unwrap();
    let env_path = dir.path().join(".env");
    let old = format!("phm_{}", "a".repeat(64));
    std::fs::write(&env_path, format!("TARGET={old}\n")).unwrap();

    let error = remap_phantom_tokens_with(&env_path, &["TARGET".to_string()], || {
        std::fs::write(&env_path, b"TARGET=concurrent-owner\n").unwrap();
    })
    .unwrap_err();

    assert!(error.to_string().contains("changed after review"));
    assert_eq!(
        std::fs::read(&env_path).unwrap(),
        b"TARGET=concurrent-owner\n"
    );
}

#[test]
fn locked_remap_rejects_dotenv_outside_project_root() {
    let project = tempdir().unwrap();
    let outside = tempdir().unwrap();
    let env_path = outside.path().join(".env");
    let old = format!("phm_{}", "a".repeat(64));
    std::fs::write(&env_path, format!("TARGET={old}\n")).unwrap();
    let transaction_lock = phantom_vault::acquire_project_transaction_lock(project.path()).unwrap();

    let error = remap_phantom_tokens_locked(&transaction_lock, &env_path, &["TARGET".to_string()])
        .unwrap_err();

    assert!(format!("{error:#}").contains("outside canonical project root"));
    assert_eq!(
        std::fs::read_to_string(env_path).unwrap(),
        format!("TARGET={old}\n")
    );
}

#[cfg(unix)]
#[test]
fn locked_remap_uses_retained_root_after_ambient_decoy_swap() {
    let container = tempdir().unwrap();
    let project = container.path().join("project");
    let moved = container.path().join("moved");
    std::fs::create_dir(&project).unwrap();
    let env_path = project.join(".env");
    let old = format!("phm_{}", "a".repeat(64));
    let before = format!("TARGET={old}\n");
    std::fs::write(&env_path, &before).unwrap();
    let transaction_lock = phantom_vault::acquire_project_transaction_lock(&project).unwrap();

    remap_phantom_tokens_locked_with(
        &transaction_lock,
        &env_path,
        &["TARGET".to_string()],
        || {
            std::fs::rename(&project, &moved).unwrap();
            std::fs::create_dir(&project).unwrap();
            std::fs::write(project.join(".env"), b"TARGET=decoy-owner\n").unwrap();
        },
    )
    .unwrap();

    let committed = std::fs::read_to_string(moved.join(".env")).unwrap();
    assert!(committed.starts_with("TARGET=phm_"));
    assert_ne!(committed, before);
    assert_eq!(
        std::fs::read(project.join(".env")).unwrap(),
        b"TARGET=decoy-owner\n"
    );
}

struct MetadataFailingVault {
    fail_read: bool,
}

impl VaultBackend for MetadataFailingVault {
    fn store(&self, _name: &str, _value: &str) -> PhantomResult<()> {
        Ok(())
    }
    fn retrieve(&self, name: &str) -> PhantomResult<Zeroizing<String>> {
        Err(PhantomError::SecretNotFound(name.to_string()))
    }
    fn delete(&self, _name: &str) -> PhantomResult<()> {
        Ok(())
    }
    fn list(&self) -> PhantomResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn backend_name(&self) -> &str {
        "metadata-failure"
    }
    fn get_metadata(&self, _name: &str) -> PhantomResult<Option<SecretMetadata>> {
        if self.fail_read {
            Err(PhantomError::VaultError(
                "injected metadata read failure".into(),
            ))
        } else {
            Ok(Some(SecretMetadata::default()))
        }
    }
    fn set_metadata(&self, _name: &str, _meta: SecretMetadata) -> PhantomResult<()> {
        Err(PhantomError::VaultError(
            "injected metadata write failure".into(),
        ))
    }
    fn get_validation_metadata(&self, _name: &str) -> PhantomResult<ValidationMetadata> {
        Ok(ValidationMetadata::default())
    }
}

#[test]
fn provider_metadata_read_and_write_errors_fail_closed() {
    let read_error =
        read_expiry_metadata(&MetadataFailingVault { fail_read: true }, "TARGET").unwrap_err();
    assert!(read_error
        .to_string()
        .contains("Failed to read rotation metadata"));

    let write_error = persist_provider_rotation_metadata(
        &MetadataFailingVault { fail_read: false },
        "TARGET",
        None,
    )
    .unwrap_err();
    assert!(write_error
        .to_string()
        .contains("rotation metadata could not be persisted"));
    assert!(write_error
        .to_string()
        .contains("cleanup and deployment sync were not attempted"));
}

#[test]
fn local_remap_rejects_ttl_sync_and_schedule_claims_before_mutation() {
    assert!(run_with_expiry(true, None)
        .unwrap_err()
        .to_string()
        .contains("no new provider credential"));
    assert!(run_with_expiry(false, Some(30))
        .unwrap_err()
        .to_string()
        .contains("TTL cannot be renewed"));
    assert!(run_with_schedule_strategy("daily", false, None)
        .unwrap_err()
        .to_string()
        .contains("deprecated and disabled"));
}

#[test]
fn legacy_shadow_create_and_promote_are_hard_denials() {
    let create_error = run_shadow("OPENAI_API_KEY").unwrap_err().to_string();
    assert!(create_error.contains("deprecated and disabled"));
    assert!(create_error.contains("No candidate was created or stored"));

    let promote_error = run_validate_promote("OPENAI_API_KEY", true)
        .unwrap_err()
        .to_string();
    assert!(promote_error.contains("deprecated and disabled"));
    assert!(promote_error.contains("No credential or metadata was changed"));
}

/// `phantom rotate --batch` answered "No secrets in vault." with exit 0
/// when the project's secrets were in an encrypted-file vault this
/// process could not open; it now refuses with the unlock step, as
/// `phantom secrets-expiring-soon` and MCP `phantom_secret_rotation_due`
/// do.
#[cfg(unix)]
#[test]
fn batch_rotation_report_refuses_a_locked_file_vault() {
    let _project =
        crate::util::test_seam::LockedProject::new(crate::util::test_seam::empty_keychain);
    let error = run_batch(30, false, true).unwrap_err().to_string();
    assert!(error.starts_with("Vault locked:"), "{error}");
    assert!(error.contains("PHANTOM_VAULT_PASSPHRASE"), "{error}");
}

/// Write a managed dotenv holding a protected placeholder for the
/// file-vault entry and for the keychain stub's entry.
#[cfg(unix)]
fn write_locked_project_dotenv(dir: &Path) -> Vec<u8> {
    let body = format!(
        "OPENAI_API_KEY={}\nKEYCHAIN_ONLY_KEY={}\nPUBLIC=yes\n",
        phantom_core::token::PhantomToken::generate().as_str(),
        phantom_core::token::PhantomToken::generate().as_str(),
    );
    std::fs::write(dir.join(".env"), &body).unwrap();
    body.into_bytes()
}

/// `phantom rotate` answered "No Phantom tokens to remap." with exit 0
/// when the project's secrets were in an encrypted-file vault this
/// process could not open and the OS keychain it fell back to was empty.
#[cfg(unix)]
#[test]
fn token_remap_refuses_an_empty_keychain_beside_a_locked_file_vault() {
    let project =
        crate::util::test_seam::LockedProject::new(crate::util::test_seam::empty_keychain);
    let before = write_locked_project_dotenv(&project.dir);
    let outcome = prepare_local_token_remap(&project.dir);
    assert!(
        outcome.is_err(),
        "remap planning must refuse a locked file vault"
    );
    let error = outcome.err().unwrap().to_string();
    assert!(error.starts_with("Vault locked:"), "{error}");
    assert!(error.contains("PHANTOM_VAULT_PASSPHRASE"), "{error}");
    assert_eq!(std::fs::read(project.dir.join(".env")).unwrap(), before);
}

/// A keychain-only listing beside a locked file vault planned a remap of
/// the keychain names alone while the challenge claimed every mapping is
/// invalidated, leaving the file-vault entries' tokens unchanged.
#[cfg(unix)]
#[test]
fn token_remap_refuses_a_keychain_only_inventory_beside_a_locked_file_vault() {
    let project =
        crate::util::test_seam::LockedProject::new(crate::util::test_seam::keychain_with_one);
    let before = write_locked_project_dotenv(&project.dir);
    let outcome = prepare_local_token_remap(&project.dir);
    assert!(
        outcome.is_err(),
        "remap planning must refuse a keychain-only inventory"
    );
    let error = outcome.err().unwrap().to_string();
    assert!(
        error.starts_with("Refusing to remap Phantom tokens from a partial inventory"),
        "{error}"
    );
    assert!(error.contains("PHANTOM_VAULT_PASSPHRASE"), "{error}");
    assert_eq!(std::fs::read(project.dir.join(".env")).unwrap(), before);
}

/// `phantom rotate --name <KEY>` answered "Secret '<KEY>' not found in
/// vault." when the secret was in an encrypted-file vault this process
/// could not open and the OS keychain it fell back to did not hold it.
/// It now names the locked vault and the unlock step.
#[cfg(unix)]
#[test]
fn provider_rotation_names_a_locked_file_vault_not_a_missing_secret() {
    let project =
        crate::util::test_seam::LockedProject::new(crate::util::test_seam::empty_keychain);
    let before = write_locked_project_dotenv(&project.dir);
    let error = run_with_provider(Some("stripe"), "OPENAI_API_KEY", false, true)
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("Vault locked:"));
    assert!(error.contains("PHANTOM_VAULT_PASSPHRASE"));
    assert!(!error.contains("not found"));
    assert_eq!(std::fs::read(project.dir.join(".env")).unwrap(), before);
}

/// A GitHub grant may create a target the vault does not hold yet, but
/// beside a locked encrypted-file vault the target is most likely in that
/// file: the run refuses with the unlock step instead of planning a mint
/// into the OS keychain beside it.
#[cfg(unix)]
#[test]
fn github_grant_rotation_refuses_beside_a_locked_file_vault() {
    let project =
        crate::util::test_seam::LockedProject::new(crate::util::test_seam::empty_keychain);
    let config_path = project.dir.join(".phantom.toml");
    let mut config = std::fs::read_to_string(&config_path).unwrap();
    config
        .push_str("\n[phantom.secrets.OPENAI_API_KEY.rotation_provider]\nprovider = \"github\"\n");
    std::fs::write(&config_path, config).unwrap();
    let before = write_locked_project_dotenv(&project.dir);
    let error = run_with_provider(None, "OPENAI_API_KEY", false, true)
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("Vault locked:"));
    assert!(error.contains("PHANTOM_VAULT_PASSPHRASE"));
    assert_eq!(std::fs::read(project.dir.join(".env")).unwrap(), before);
}
