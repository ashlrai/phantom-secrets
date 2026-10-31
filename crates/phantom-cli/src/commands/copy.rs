use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_vault::{InitFile, InitSecret, SecretMetadata};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use super::add::{
    load_config_exact, rewrite_dotenv, snapshot_regular_file, snapshot_secret, validate_secret_name,
};

struct CopyTargetPlan {
    mutation: InitSecret,
    files: Vec<InitFile>,
    env_path: PathBuf,
}

/// Copy the source value observed during preflight into a distinct target
/// project. Only the target is mutated; the commit holds both projects'
/// canonical locks in one global order, so a reverse copy waits instead of
/// deadlocking and a cooperating source writer cannot change the source
/// mid-commit. The source snapshot remains zeroizing through target commit.
pub fn run(
    name: &str,
    target_dir: &Path,
    rename: &Option<String>,
    allow_cross_owner: bool,
) -> Result<()> {
    validate_secret_name(name)?;
    let target_name = rename.as_deref().unwrap_or(name);
    validate_secret_name(target_name)?;

    let source_dir = std::env::current_dir()?
        .canonicalize()
        .context("Failed to resolve source project directory")?;
    let target_dir = resolve_target(&source_dir, target_dir)?;
    if source_dir == target_dir {
        anyhow::bail!(
            "Source and target resolve to the same project. Refusing an ambiguous self-copy; use `phantom add` for an intentional replacement."
        );
    }
    let source_config_path = source_dir.join(".phantom.toml");
    let target_config_path = target_dir.join(".phantom.toml");
    let (source_config, _) = load_config_exact(&source_config_path).with_context(|| {
        format!(
            "Source project is not safely initialized at {}. Run `phantom init --empty` there first.",
            source_dir.display()
        )
    })?;
    let (target_config, target_config_before) = load_config_exact(&target_config_path)
        .with_context(|| {
            format!(
                "Target project is not safely initialized at {}. Run `phantom init --empty` there first.",
                target_dir.display()
            )
        })?;

    check_owner_boundary(
        source_config.phantom.owner.as_deref(),
        target_config.phantom.owner.as_deref(),
        allow_cross_owner,
    )?;

    let target_preflight =
        phantom_core::managed_dotenv::resolve_dotenv(&target_dir, &target_config, &[])?;
    if let Some(dotenv) = target_preflight.file.as_ref() {
        dotenv.validate_for_mutation().context(
            "Target managed dotenv is malformed; copy stopped before opening either vault",
        )?;
    }

    let target_vault = phantom_vault::try_create_vault(target_config.local_project_id())?;

    // Complete every target collision and filesystem check before retrieving
    // the source plaintext. Copy has no overwrite flag, so any existing target
    // ownership is an explicit hard refusal rather than a silent clobber.
    let target_vault_names =
        list_copy_target_names(target_vault.as_ref(), target_config.local_project_id())?;
    if snapshot_secret(target_vault.as_ref(), target_name)?.is_some() {
        anyhow::bail!(
            "Target secret '{target_name}' already exists. Copy refuses ambiguous overwrite; remove it explicitly or choose --rename."
        );
    }
    if target_config.phantom.secrets.contains_key(target_name) {
        anyhow::bail!(
            "Target config already owns metadata for '{target_name}'. Copy refuses to create a value with ambiguous lifecycle policy; choose --rename or reconcile the target first."
        );
    }
    let resolved = phantom_core::managed_dotenv::resolve_dotenv(
        &target_dir,
        &target_config,
        &target_vault_names,
    )?;
    let target_env_path = resolved.path;
    let env_before = snapshot_regular_file(&target_env_path)?;
    if dotenv_has_key(env_before.as_deref(), target_name)? {
        anyhow::bail!(
            "Target managed dotenv already contains '{target_name}'. Copy refuses to overwrite an existing mapping; remove it explicitly or choose --rename."
        );
    }

    // An overdue enforced source secret is known from names and metadata
    // alone: refuse before the challenge so the user is never asked to
    // confirm a copy that will be refused. Judged again before the read.
    let source_vault = phantom_vault::try_create_vault(source_config.local_project_id())?;
    super::rotation_gate::enforce_rotation_on_entries(
        &source_config,
        source_vault.as_ref(),
        [name],
        "copy",
        super::rotation_gate::now_secs(),
    )?;

    // Consent is bound to the exact canonical path, names, and machine-local
    // vault identity observed during target preflight. The config exact-before
    // file guard below prevents that approved identity from drifting at commit.
    require_trusted_terminal_copy(
        name,
        target_name,
        &target_dir,
        target_config.local_project_id(),
    )?;

    let (source_metadata, secret_value) = retrieve_gated_copy_source(
        &source_config,
        source_vault.as_ref(),
        name,
        super::rotation_gate::now_secs(),
    )?;
    let plan = prepare_target_plan(
        &target_dir,
        &target_config_path,
        target_config,
        target_config_before,
        target_vault_names,
        target_env_path,
        env_before,
        target_name,
        secret_value.as_str(),
        name,
        source_metadata.as_ref(),
    )?;

    // The source project and vault are passed so the transaction holds the
    // source project's lock (with the target's, in Phantom's global lock
    // order) and the source entry to the exact value and metadata read above
    // until the copy commits.
    phantom_vault::commit_init_with_source_vault(
        &target_dir,
        target_vault.as_ref(),
        &source_dir,
        source_vault.as_ref(),
        vec![plan.mutation],
        plan.files,
    )
    .context(
        "Copy transaction failed; exact transaction-owned target state was rolled back where verifiable. Inspect the target vault and managed dotenv before retrying.",
    )?;

    println!(
        "{} Copied {} as {} into {} and updated {} (value never printed)",
        "ok".green().bold(),
        name.bold(),
        target_name.bold(),
        target_dir.display(),
        plan.env_path
            .file_name()
            .and_then(|part| part.to_str())
            .unwrap_or("managed dotenv")
            .cyan()
    );
    Ok(())
}

/// Refuse copies between projects labelled with different owners unless the
/// operator explicitly allows it. Unlabelled projects keep legacy behavior.
pub(crate) fn check_owner_boundary(
    source_owner: Option<&str>,
    target_owner: Option<&str>,
    allow_cross_owner: bool,
) -> Result<()> {
    if let (Some(source), Some(target)) = (source_owner, target_owner) {
        if source != target && !allow_cross_owner {
            anyhow::bail!(
                "Refusing to copy across owners: source and target owner labels differ. \
                 Re-run with --allow-cross-owner only if this key may intentionally be shared."
            );
        }
    }
    Ok(())
}

/// The target vault's names, which decide collisions and the target dotenv.
/// Beside a target encrypted-file vault this process cannot open, the listing
/// covers only the OS keychain: a name in the locked file would read as free
/// and the copy would store it in the keychain beside it, so the copy is
/// refused before the trusted-terminal challenge.
fn list_copy_target_names(
    target_vault: &dyn phantom_vault::VaultBackend,
    target_project_id: &str,
) -> Result<Vec<String>> {
    let names = target_vault
        .list()
        .context("Failed to list target vault entries")?;
    crate::util::require_complete_inventory(
        target_vault,
        target_project_id,
        names.len(),
        "copy a secret into the target project",
    )?;
    Ok(names)
}

/// `enforce_rotation_on_access`, then the source read: the target project
/// does not carry this project's rotation policy, so an overdue enforced
/// source secret is refused before its value is read, as `phantom exec`
/// would refuse it. The source metadata is read before the value, so the
/// rotation anchor the copy inherits is never newer than the copied value;
/// the copy transaction then refuses if either changed before it commits.
fn retrieve_gated_copy_source(
    source_config: &PhantomConfig,
    source_vault: &dyn phantom_vault::VaultBackend,
    name: &str,
    now_secs: u64,
) -> Result<(Option<SecretMetadata>, zeroize::Zeroizing<String>)> {
    super::rotation_gate::enforce_rotation_on_entries(
        source_config,
        source_vault,
        [name],
        "copy",
        now_secs,
    )?;
    let metadata = source_vault
        .get_metadata(name)
        .context("Failed to read source secret metadata")?;
    let value = retrieve_copy_source(source_vault, source_config.local_project_id(), name)?;
    Ok((metadata, value))
}

/// Read the approved source secret. Beside a source encrypted-file vault this
/// process cannot open, a name the OS keychain lacks is refused with the
/// unlock step instead of being reported as not found.
fn retrieve_copy_source(
    source_vault: &dyn phantom_vault::VaultBackend,
    source_project_id: &str,
    name: &str,
) -> Result<zeroize::Zeroizing<String>> {
    crate::util::retrieve_secret(source_vault, source_project_id, name, || {
        format!("Secret '{name}' not found in source vault")
    })
}

fn require_trusted_terminal_copy(
    name: &str,
    target_name: &str,
    target_dir: &Path,
    target_local_project_id: &str,
) -> Result<()> {
    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || !std::io::stderr().is_terminal()
    {
        anyhow::bail!(
            "`phantom copy` requires attached stdin, stdout, and stderr terminals and cannot run headlessly. No source secret was read and no target state changed. Use the approved MCP copy flow when the calling agent cannot be excluded from terminal authority."
        );
    }
    let challenge = format!(
        "COPY {name} AS {target_name} TO {} ID {target_local_project_id}",
        target_dir.display()
    );
    eprintln!(
        "Secret copy is an exfiltration-capable operation.\nTarget: {}\nTarget vault fingerprint: {}\nSource name: {}\nTarget name: {}\nType this exact challenge to continue:\n{}",
        target_dir.display(),
        target_local_project_id,
        name,
        target_name,
        challenge
    );
    eprint!("> ");
    std::io::stderr().flush()?;
    let mut response = String::new();
    std::io::stdin()
        .read_line(&mut response)
        .context("Failed to read trusted-terminal copy confirmation")?;
    if response.trim_end_matches(['\r', '\n']) != challenge {
        anyhow::bail!("Copy confirmation did not match exactly. No source secret was read and no target state changed.");
    }
    Ok(())
}

fn resolve_target(source_dir: &Path, target: &Path) -> Result<PathBuf> {
    let candidate = if target.is_relative() {
        source_dir.join(target)
    } else {
        target.to_path_buf()
    };
    candidate
        .canonicalize()
        .context("Target directory does not exist or cannot be safely resolved")
}

#[allow(clippy::too_many_arguments)]
fn prepare_target_plan(
    target_dir: &Path,
    config_path: &Path,
    mut config: PhantomConfig,
    config_before: Vec<u8>,
    target_vault_names: Vec<String>,
    env_path: PathBuf,
    env_before: Option<Vec<u8>>,
    target_name: &str,
    value: &str,
    source_name: &str,
    source_metadata: Option<&SecretMetadata>,
) -> Result<CopyTargetPlan> {
    let env_after = rewrite_dotenv(env_before.as_deref(), target_name)?;
    // The copy keeps the source's lifecycle metadata (rotation age, expiry,
    // TTL policy and read-only mode), so a duplicate is never less protected
    // than its source. A source demoted, given an expiry, or rotated after
    // it was read refuses the commit instead.
    let mutation = InitSecret::replace_if_unchanged(target_name, None::<String>, value)
        .inheriting_source_protection(source_name, source_metadata);
    let config_after = if config.phantom.dotenv_path.is_none() && target_vault_names.is_empty() {
        config.phantom.dotenv_path = Some(
            phantom_core::managed_dotenv::dotenv_basename(target_dir, &env_path)
                .context("Failed to persist target managed dotenv mapping")?,
        );
        toml::to_string_pretty(&config)
            .context("Failed to serialize target managed dotenv configuration")?
            .into_bytes()
    } else {
        config_before.clone()
    };
    let mut files = vec![InitFile::replace_if_unchanged(
        config_path,
        Some(config_before),
        config_after,
    )];
    files.push(InitFile::replace_if_unchanged(&env_path, env_before, env_after).commit_last());
    Ok(CopyTargetPlan {
        mutation,
        files,
        env_path,
    })
}

fn dotenv_has_key(before: Option<&[u8]>, name: &str) -> Result<bool> {
    let Some(bytes) = before else {
        return Ok(false);
    };
    let content = std::str::from_utf8(bytes)
        .context("Target managed dotenv is not valid UTF-8; refusing to inspect or rewrite it")?;
    let dotenv = DotenvFile::parse_str(content);
    dotenv.validate_for_mutation().context(
        "Target managed dotenv is malformed; copy made no vault, config, or file changes",
    )?;
    Ok(dotenv.entries().iter().any(|entry| entry.key == name))
}

#[cfg(test)]
mod tests {
    #[test]
    fn owner_boundary_rules() {
        use super::check_owner_boundary as c;
        assert!(c(None, None, false).is_ok());
        assert!(c(Some("personal"), None, false).is_ok());
        assert!(c(Some("client:globex"), Some("client:globex"), false).is_ok());
        assert!(c(Some("client:globex"), Some("personal"), false).is_err());
        assert!(c(Some("company:ashlr"), Some("client:globex"), false).is_err());
        assert!(c(Some("company:ashlr"), Some("client:globex"), true).is_ok());
        assert!(c(None, Some("personal"), false).is_ok());
        let error = c(Some("client:synthetic-credential"), Some("personal"), false)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("client:synthetic-credential"));
    }

    use super::*;
    use phantom_core::error::PhantomError;
    use phantom_vault::file::FileVault;
    use phantom_vault::VaultBackend;

    /// The overdue-source refusal came only after the trusted-terminal
    /// challenge, so the user typed a confirmation for a copy that was then
    /// refused. The gate now also runs before the challenge (names and
    /// metadata only); the challenge itself is unchanged and the gate runs
    /// again just before the value is read.
    #[test]
    fn copy_gates_rotation_before_the_challenge_and_before_the_read() {
        let source = include_str!("copy.rs");
        let run = &source[source.find("pub fn run(").unwrap()..];
        let run = &run[..run.find("fn list_copy_target_names(").unwrap()];
        let gate = run
            .find("enforce_rotation_on_entries(")
            .expect("copy must gate rotation before the challenge");
        let challenge = run.find("require_trusted_terminal_copy(").unwrap();
        let read = run.find("retrieve_gated_copy_source(").unwrap();
        assert!(gate < challenge && challenge < read);
    }

    /// `phantom copy` handed an overdue enforced secret to a project without
    /// this project's rotation policy. The source read is now gated, as
    /// `phantom exec` is; a secret inside its window copies.
    #[test]
    fn copy_source_read_applies_rotation_enforcement() {
        use crate::commands::rotation_gate::fixtures::{aged_vault, enforced_config, NOW};
        let dir = tempfile::tempdir().unwrap();
        let vault = aged_vault(&dir, &[("STALE_KEY", 45), ("FRESH_KEY", 1)]);
        let config = enforced_config(&["STALE_KEY", "FRESH_KEY"]);

        let refused = retrieve_gated_copy_source(&config, &vault, "STALE_KEY", NOW);
        let message = refused
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(message.starts_with("Refusing to copy: rotation enforcement blocked 1 secret(s)."));
        let fresh = retrieve_gated_copy_source(&config, &vault, "FRESH_KEY", NOW);
        assert!(fresh.is_ok_and(|(_, value)| value.as_str() == "fixture-value"));
    }

    /// Commit a copy of `name` from `source` into a fresh target project and
    /// return the target vault with the target directory that owns it.
    fn copy_into_new_target(
        source_config: &PhantomConfig,
        source_dir: &Path,
        source: &FileVault,
        name: &str,
        target_name: &str,
    ) -> (tempfile::TempDir, FileVault) {
        let (dir, vault, plan) =
            plan_copy_into_new_target(source_config, source, name, target_name);
        let target = dir.path().canonicalize().unwrap();
        phantom_vault::commit_init_with_source_vault(
            &target,
            &vault,
            source_dir,
            source,
            vec![plan.mutation],
            plan.files,
        )
        .unwrap();
        (dir, vault)
    }

    /// Read `name` from `source` and plan its copy into a fresh target
    /// project, without committing it.
    fn plan_copy_into_new_target(
        source_config: &PhantomConfig,
        source: &FileVault,
        name: &str,
        target_name: &str,
    ) -> (tempfile::TempDir, FileVault, CopyTargetPlan) {
        use crate::commands::rotation_gate::fixtures::NOW;
        let (metadata, value) =
            retrieve_gated_copy_source(source_config, source, name, NOW).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().canonicalize().unwrap();
        let config_path = target.join(".phantom.toml");
        PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(&target))
            .save(&config_path)
            .unwrap();
        let (config, config_before) = load_config_exact(&config_path).unwrap();
        let vault = FileVault::new(
            &crate::test_support::canonical_tempdir_path(&dir),
            "copy-anchor-target",
            "passphrase".to_string(),
        )
        .unwrap();
        let plan = prepare_target_plan(
            &target,
            &config_path,
            config,
            config_before,
            Vec::new(),
            target.join(".env"),
            None,
            target_name,
            value.as_str(),
            name,
            metadata.as_ref(),
        )
        .unwrap();
        (dir, vault, plan)
    }

    /// The source was demoted to read-only (with an expiry) after `phantom
    /// copy` read its metadata and value. The target would inherit the stale
    /// read-write metadata, so the commit is refused and the target keeps no
    /// vault entry, dotenv mapping or config change.
    #[test]
    fn copy_refuses_a_source_demoted_before_the_commit() {
        use crate::commands::rotation_gate::fixtures::aged_vault;
        let source_dir = tempfile::tempdir().unwrap();
        let source = aged_vault(&source_dir, &[("DEMOTED_KEY", 3)]);
        let source_config = PhantomConfig::new_with_defaults("copy-demoted".to_string());
        let (target_dir, target, plan) =
            plan_copy_into_new_target(&source_config, &source, "DEMOTED_KEY", "COPIED_KEY");
        let mut demoted = source.get_metadata("DEMOTED_KEY").unwrap().unwrap();
        demoted.vault_mode = phantom_vault::metadata::VaultMode::ReadOnly;
        demoted.expires_at = Some(1_700_000_000);
        source.set_metadata("DEMOTED_KEY", demoted.clone()).unwrap();
        let target_path = target_dir.path().canonicalize().unwrap();
        let config_before = std::fs::read(target_path.join(".phantom.toml")).unwrap();

        let outcome = phantom_vault::commit_init_with_source_vault(
            &target_path,
            &target,
            source_dir.path(),
            &source,
            vec![plan.mutation],
            plan.files,
        );

        assert!(outcome.is_err());
        assert!(!target.exists("COPIED_KEY").unwrap());
        assert!(!target_path.join(".env").exists());
        assert_eq!(
            std::fs::read(target_path.join(".phantom.toml")).unwrap(),
            config_before
        );
        assert_eq!(source.get_metadata("DEMOTED_KEY").unwrap(), Some(demoted));
    }

    /// `phantom copy` stored the destination as new, so a secret 29 days
    /// into a 30-day enforced window got a fresh 30-day clock in the target.
    /// The destination now inherits the source's rotation anchor, and the
    /// gate judges it overdue exactly when the source is.
    #[test]
    fn copy_destination_inherits_the_source_rotation_anchor() {
        use crate::commands::rotation_gate::fixtures::{aged_vault, enforced_config, DAY, NOW};
        let source_dir = tempfile::tempdir().unwrap();
        let source = aged_vault(&source_dir, &[("AGING_KEY", 29)]);
        let source_config = enforced_config(&["AGING_KEY"]);

        let (_target_dir, target) = copy_into_new_target(
            &source_config,
            source_dir.path(),
            &source,
            "AGING_KEY",
            "COPIED_KEY",
        );

        let anchor = |vault: &FileVault, entry: &str| {
            phantom_vault::rotation_gate::rotation_anchor(
                vault.get_metadata(entry).unwrap().as_ref(),
            )
        };
        assert_eq!(anchor(&target, "COPIED_KEY"), Some(NOW - 29 * DAY));
        assert_eq!(anchor(&target, "COPIED_KEY"), anchor(&source, "AGING_KEY"));
        let refusals = phantom_vault::rotation_gate::rotation_refusals(
            &enforced_config(&["COPIED_KEY"]),
            &target,
            phantom_vault::rotation_gate::entry_targets(["COPIED_KEY"]),
            NOW + 2 * DAY,
        )
        .unwrap();
        assert_eq!(
            refusals.len(),
            1,
            "the copy must be overdue with its source"
        );
    }

    /// A secret without rotation enforcement still copies, whatever its age,
    /// and keeps that age.
    #[test]
    fn copy_of_an_unenforced_secret_still_works() {
        use crate::commands::rotation_gate::fixtures::{aged_vault, DAY, NOW};
        let source_dir = tempfile::tempdir().unwrap();
        let source = aged_vault(&source_dir, &[("PLAIN_KEY", 400)]);
        let source_config = PhantomConfig::new_with_defaults("copy-unenforced".to_string());

        let (_target_dir, target) = copy_into_new_target(
            &source_config,
            source_dir.path(),
            &source,
            "PLAIN_KEY",
            "PLAIN_KEY",
        );

        assert!(target.exists("PLAIN_KEY").unwrap());
        let copied = target.get_metadata("PLAIN_KEY").unwrap().unwrap();
        assert_eq!(copied.created_at, Some(NOW - 400 * DAY));
    }

    /// `phantom copy` carried only the rotation anchor, so a source demoted
    /// to read-only, past its expiry, or under a TTL policy came out of the
    /// copy as an injectable read-write entry with no expiry. The destination
    /// now carries every protective lifecycle field of its source.
    #[test]
    fn copy_destination_keeps_the_source_protective_metadata() {
        use crate::commands::rotation_gate::fixtures::{aged_vault, DAY, NOW};
        let source_dir = tempfile::tempdir().unwrap();
        let source = aged_vault(&source_dir, &[("DEMOTED_KEY", 40)]);
        let protected = phantom_vault::SecretMetadata {
            created_at: Some(NOW - 40 * DAY),
            rotated_at: Some(NOW - 35 * DAY),
            expires_at: Some(NOW - 5 * DAY),
            rotation_policy: Some(phantom_vault::RotationPolicy {
                days_ttl: 30,
                auto_rotate: false,
            }),
            vault_mode: phantom_vault::metadata::VaultMode::ReadOnly,
        };
        source
            .set_metadata("DEMOTED_KEY", protected.clone())
            .unwrap();
        let source_config = PhantomConfig::new_with_defaults("copy-protected".to_string());

        let (_target_dir, target) = copy_into_new_target(
            &source_config,
            source_dir.path(),
            &source,
            "DEMOTED_KEY",
            "COPIED_KEY",
        );

        let copied = target
            .get_metadata("COPIED_KEY")
            .unwrap()
            .unwrap_or_default();
        assert_eq!(copied.expires_at, protected.expires_at);
        assert_eq!(copied.rotation_policy, protected.rotation_policy);
        assert_eq!(copied.vault_mode, protected.vault_mode);
        assert_eq!(copied, protected);
        assert!(
            target.retrieve_for_injection("COPIED_KEY").is_err(),
            "a copy of a read-only secret must not be injectable"
        );
    }

    /// Beside a target encrypted-file vault this process cannot open, the
    /// target listing came from the OS keychain alone, so a name already in
    /// the locked file read as free to create.
    #[cfg(unix)]
    #[test]
    fn copy_into_a_locked_target_vault_is_refused_before_the_challenge() {
        use crate::util::test_seam::{empty_keychain, keychain_with_one, LockedProject};
        for (make, lead) in [
            (
                empty_keychain as crate::util::test_seam::MakeVault,
                "Vault locked:",
            ),
            (
                keychain_with_one,
                "Refusing to copy a secret into the target project from a partial inventory",
            ),
        ] {
            let project = LockedProject::new(make);
            let vault = crate::util::open_vault(&project.project_id).unwrap();

            let outcome = list_copy_target_names(vault.as_ref(), &project.project_id);

            assert!(outcome.is_err(), "a partial target inventory must refuse");
            let message = outcome.err().unwrap().to_string();
            assert!(message.starts_with(lead));
            assert!(message.contains("PHANTOM_VAULT_PASSPHRASE"));
        }
    }

    /// The source secret beside a locked source file vault was reported as
    /// not found in the source vault.
    #[cfg(unix)]
    #[test]
    fn copy_from_a_locked_source_vault_names_the_lock_not_a_missing_secret() {
        let project =
            crate::util::test_seam::LockedProject::new(crate::util::test_seam::empty_keychain);
        let vault = crate::util::open_vault(&project.project_id).unwrap();

        let outcome = retrieve_copy_source(vault.as_ref(), &project.project_id, "OPENAI_API_KEY");

        assert!(outcome.is_err(), "a locked source must not be read");
        let message = format!("{:#}", outcome.err().unwrap());
        assert!(message.starts_with("Vault locked:"));
        assert!(!message.contains("not found"));
    }

    #[test]
    fn target_key_detection_is_exact() {
        assert!(dotenv_has_key(Some(b"API_KEY=phm_test\n"), "API_KEY").unwrap());
        assert!(!dotenv_has_key(Some(b"OTHER_API_KEY=phm_test\n"), "API_KEY").unwrap());
    }

    #[test]
    fn malformed_target_refuses_collision_decision() {
        let error = dotenv_has_key(
            Some(b"COPIED_KEY=plaintext-must-not-escape\nBROKEN_RECORD\n"),
            "COPIED_KEY",
        )
        .unwrap_err();
        assert!(error.to_string().contains("malformed"));
        assert!(!error.to_string().contains("plaintext-must-not-escape"));
    }

    #[test]
    fn same_project_identity_is_rejected_by_canonical_comparison() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().canonicalize().unwrap();
        assert_eq!(
            resolve_target(&canonical, Path::new(".")).unwrap(),
            canonical
        );
    }

    #[test]
    fn target_config_drift_aborts_before_vault_or_dotenv_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().canonicalize().unwrap();
        let config_path = target.join(".phantom.toml");
        PhantomConfig::new_with_defaults(PhantomConfig::project_id_from_path(&target))
            .save(&config_path)
            .unwrap();
        let (config, config_before) = load_config_exact(&config_path).unwrap();
        let vault = FileVault::new(
            &crate::test_support::canonical_tempdir_path(&dir),
            "copy-target-test",
            "passphrase".to_string(),
        )
        .unwrap();
        let source_dir = tempfile::tempdir().unwrap();
        let source =
            crate::commands::rotation_gate::fixtures::aged_vault(&source_dir, &[("SOURCE_KEY", 1)]);
        let source_metadata = source.get_metadata("SOURCE_KEY").unwrap();
        let env_path = target.join(".env");
        let plan = prepare_target_plan(
            &target,
            &config_path,
            config,
            config_before,
            Vec::new(),
            env_path.clone(),
            None,
            "COPIED_KEY",
            "fixture-value",
            "SOURCE_KEY",
            source_metadata.as_ref(),
        )
        .unwrap();
        let mut concurrent_config = std::fs::read(&config_path).unwrap();
        concurrent_config.extend_from_slice(b"\n# concurrent owner\n");
        std::fs::write(&config_path, &concurrent_config).unwrap();

        let outcome = phantom_vault::commit_init_with_source_vault(
            &target,
            &vault,
            source_dir.path(),
            &source,
            vec![plan.mutation],
            plan.files,
        );
        assert!(matches!(
            outcome,
            Err(phantom_vault::InitTransactionError::ConcurrentChange { .. })
        ));
        assert_eq!(std::fs::read(&config_path).unwrap(), concurrent_config);
        assert!(!env_path.exists());
        assert!(matches!(
            vault.retrieve("COPIED_KEY"),
            Err(PhantomError::SecretNotFound(_))
        ));
    }
}
