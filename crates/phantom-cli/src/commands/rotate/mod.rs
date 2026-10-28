//! Local placeholder remapping and the rotation command surface.

mod provider;

pub use provider::{run_batch, run_shadow, run_validate_promote, run_with_provider};

use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::fs::{
    AnchoredEffect, AnchoredFilePermissions, AnchoredRead, AnchoredTarget, FileIdentity,
    TrustedAnchor,
};
use phantom_core::token::TokenMap;
use phantom_vault::VaultBackend;
use sha2::{Digest, Sha256};
use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

const MAX_TERMINAL_PATH_BYTES: usize = 4096;
const MAX_ROTATE_CHALLENGE_BYTES: usize = 12 * 1024;
const MAX_RENDERED_NAMES_BYTES: usize = 4096;
const ROTATE_DOTENV_NAMES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.development",
    ".env.development.local",
];

fn acquire_reviewed_project_lock(
    project_root: &Path,
    reviewed_project: &TrustedAnchor,
    before_project_lock: impl FnOnce(),
    operation: &str,
) -> Result<phantom_vault::ProjectTransactionLock> {
    before_project_lock();
    let transaction_lock = phantom_vault::acquire_project_transaction_lock(project_root)
        .with_context(|| format!("Failed to acquire project transaction lock for {operation}"))?;
    if transaction_lock.project_root_at_acquisition() != project_root {
        anyhow::bail!(
            "Project root changed while acquiring the {operation} lock; no project state was used."
        );
    }
    if transaction_lock.project_identity_at_acquisition() != reviewed_project.identity() {
        anyhow::bail!(
            "Project root was replaced while opening the {operation} vault; no project state was used."
        );
    }
    Ok(transaction_lock)
}

struct LocalTokenRemapPlan {
    project_dir: PathBuf,
    project_identity: FileIdentity,
    config_path: PathBuf,
    config_before: Vec<u8>,
    config_digest: String,
    local_project_id: String,
    env_path: PathBuf,
    env_identity: FileIdentity,
    env_permissions: AnchoredFilePermissions,
    env_before: Vec<u8>,
    env_digest: String,
    names: Vec<String>,
    names_digest: String,
}

impl LocalTokenRemapPlan {
    fn challenge(&self) -> Result<String> {
        let project = terminal_safe_path(&self.project_dir, "project")?;
        let dotenv = terminal_safe_path(&self.env_path, "managed dotenv")?;
        let challenge = format!(
            "REMAP {} PHANTOM TOKENS IN {} ID {} CONFIG {} DOTENV {} DIGEST {} NAMES {}",
            self.names.len(),
            project,
            self.local_project_id,
            self.config_digest,
            dotenv,
            self.env_digest,
            self.names_digest
        );
        if challenge.len() > MAX_ROTATE_CHALLENGE_BYTES {
            anyhow::bail!(
                "Cannot render a bounded token-remap challenge for these project paths; no state changed."
            );
        }
        Ok(challenge)
    }

    fn commit(&self) -> Result<()> {
        self.commit_with_before_project_lock(|| {})
    }

    fn commit_with_before_project_lock(&self, before_project_lock: impl FnOnce()) -> Result<()> {
        let current_project = std::env::current_dir()?
            .canonicalize()
            .context("Failed to re-resolve project directory before token remap")?;
        if current_project != self.project_dir {
            anyhow::bail!(
                "Cannot remap Phantom tokens: the current project changed after approval; no Phantom write was committed."
            );
        }
        let reviewed_project = TrustedAnchor::open(&current_project)
            .context("Failed to retain the approved project root before token remap")?;
        if reviewed_project.identity() != self.project_identity {
            anyhow::bail!(
                "Cannot remap Phantom tokens: the approved project root identity changed; no Phantom write was committed."
            );
        }
        let current_local_project_id = PhantomConfig::project_id_from_path(&current_project);
        if current_local_project_id != self.local_project_id {
            anyhow::bail!(
                "Cannot remap Phantom tokens: the local project identity changed after approval; no Phantom write was committed."
            );
        }

        let reviewed_config_target = reviewed_project
            .target(".phantom.toml")
            .context("Failed to retain the approved project config target")?;
        let reviewed_config = reviewed_config_target
            .read_regular()?
            .context("Project config disappeared after approval")?;
        if reviewed_config.bytes() != self.config_before {
            anyhow::bail!(
                "Cannot remap Phantom tokens: .phantom.toml changed after approval; no Phantom write was committed."
            );
        }
        let config = PhantomConfig::load_from_bytes(&self.config_path, reviewed_config.bytes())
            .context("Failed to reload exact .phantom.toml snapshot before token remap")?;
        if config.local_project_id() != self.local_project_id {
            anyhow::bail!(
                "Cannot remap Phantom tokens: the local project identity changed after approval; no Phantom write was committed."
            );
        }

        let env_relative = self
            .env_path
            .strip_prefix(&current_project)
            .context("Cannot revalidate a managed dotenv outside the approved project root")?;
        let reviewed_env_target = reviewed_project
            .target(env_relative)
            .context("Failed to retain the approved managed dotenv target")?;
        let reviewed_env = reviewed_env_target
            .read_regular()?
            .context("Managed dotenv disappeared after approval")?;
        if reviewed_env.identity() != self.env_identity
            || reviewed_env.bytes() != self.env_before
            || reviewed_env.permissions() != self.env_permissions
        {
            anyhow::bail!(
                "Cannot remap Phantom tokens: the managed dotenv identity changed after approval; no vault value was read and no Phantom write was committed."
            );
        }

        // Vault construction may take PROCESS_ENV_LOCK, so it must complete
        // before the project transaction lock is acquired.
        let vault = phantom_vault::try_create_vault(&current_local_project_id)
            .context("Failed to re-open vault before token remap")?;
        let transaction_lock = acquire_reviewed_project_lock(
            &current_project,
            &reviewed_project,
            before_project_lock,
            "token remap",
        )?;

        let config_target = transaction_lock
            .target(&self.config_path)
            .context("Failed to retain the approved project config target")?;
        let config_current = config_target
            .read_regular()?
            .context("Project config disappeared after approval")?;
        if config_current.identity() != reviewed_config.identity()
            || config_current.bytes() != reviewed_config.bytes()
            || config_current.permissions() != reviewed_config.permissions()
        {
            anyhow::bail!(
                "Cannot remap Phantom tokens: .phantom.toml changed after approval; no Phantom write was committed."
            );
        }

        self.commit_with_verified_config(&transaction_lock, &config, vault.as_ref())
    }

    fn commit_with_verified_config(
        &self,
        transaction_lock: &phantom_vault::ProjectTransactionLock,
        config: &PhantomConfig,
        vault: &dyn VaultBackend,
    ) -> Result<()> {
        let names = sorted_names(vault)?;
        if names != self.names || names_digest(&names) != self.names_digest {
            anyhow::bail!(
                "Cannot remap Phantom tokens: the protected-name set changed after approval; no Phantom write was committed."
            );
        }

        if let Some(configured) = config.phantom.dotenv_path.as_deref() {
            let configured = phantom_core::managed_dotenv::validate_dotenv_basename(configured)?;
            if self.project_dir.join(configured) != self.env_path {
                anyhow::bail!(
                    "Cannot remap Phantom tokens: the configured managed dotenv changed after approval; no Phantom write was committed."
                );
            }
        } else if !self
            .env_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| ROTATE_DOTENV_NAMES.contains(&name))
        {
            anyhow::bail!(
                "Cannot remap Phantom tokens: the approved legacy dotenv is no longer a supported project-local target; no Phantom write was committed."
            );
        }

        let env_target = transaction_lock
            .target(&self.env_path)
            .context("Failed to retain the approved managed dotenv target")?;
        let env_current = env_target
            .read_regular()?
            .context("Managed dotenv disappeared after approval")?;
        if env_current.identity() != self.env_identity
            || env_current.bytes() != self.env_before
            || env_current.permissions() != self.env_permissions
        {
            anyhow::bail!(
                "Cannot remap Phantom tokens: the managed dotenv changed after approval; no Phantom write was committed."
            );
        }

        remap_phantom_tokens_from_snapshot(
            &env_target,
            &self.env_path,
            &self.names,
            &env_current,
            || {},
        )
    }
}

fn terminal_safe_path(path: &Path, label: &str) -> Result<String> {
    let rendered = path.to_str().with_context(|| {
        format!("Cannot render non-UTF-8 {label} path in a trusted-terminal challenge")
    })?;
    if rendered.chars().any(char::is_control) {
        anyhow::bail!(
            "Cannot render control characters from the {label} path in a trusted-terminal challenge"
        );
    }
    let rendered = rendered
        .chars()
        .flat_map(char::escape_default)
        .collect::<String>();
    if rendered.len() > MAX_TERMINAL_PATH_BYTES {
        anyhow::bail!(
            "Cannot render {label} path longer than {MAX_TERMINAL_PATH_BYTES} bytes in a trusted-terminal challenge"
        );
    }
    Ok(rendered)
}

fn digest_bytes(domain: &[u8], bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    hex::encode(digest.finalize())
}

fn names_digest(names: &[String]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"phantom-local-token-remap-names-v1\0");
    for name in names {
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
    }
    hex::encode(digest.finalize())
}

fn sorted_names(vault: &dyn VaultBackend) -> Result<Vec<String>> {
    let mut names = vault.list().context("Failed to list protected names")?;
    names.sort();
    names.dedup();
    Ok(names)
}

fn require_attached_rotate_terminals() -> Result<()> {
    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || !std::io::stderr().is_terminal()
    {
        anyhow::bail!(
            "`phantom rotate` requires attached stdin, stdout, and stderr terminals and cannot run headlessly. No vault values were read and no project file was changed."
        );
    }
    Ok(())
}

fn prepare_local_token_remap(project_dir: &Path) -> Result<Option<LocalTokenRemapPlan>> {
    let project_dir = project_dir
        .canonicalize()
        .context("Failed to resolve project directory")?;
    let project_anchor = TrustedAnchor::open(&project_dir)
        .context("Failed to retain project directory for token-remap review")?;
    let project_identity = project_anchor.identity();
    let config_path = project_dir.join(".phantom.toml");
    let config_before = phantom_core::fs::read_regular_file(&config_path)?
        .context("No .phantom.toml found. Run `phantom init` first.")?;
    let config = PhantomConfig::load_from_bytes(&config_path, &config_before)
        .context("Failed to load exact .phantom.toml snapshot")?;
    crate::commands::add::validate_managed_dotenv_preflight(&project_dir, &config)?;
    let local_project_id = config.local_project_id().to_string();
    let vault = crate::util::open_vault(&local_project_id).context("Failed to initialize vault")?;
    let names = sorted_names(vault.as_ref())?;
    // The remap claims to invalidate every persistent phm_ mapping for the
    // project. Beside an encrypted-file vault this process cannot open, an
    // empty keychain listing is not "nothing to remap" and a keychain-only
    // listing would leave every file-vault entry's token unchanged.
    crate::util::require_complete_inventory(
        vault.as_ref(),
        &local_project_id,
        names.len(),
        "remap Phantom tokens",
    )?;
    if names.is_empty() {
        return Ok(None);
    }

    let resolved = phantom_core::managed_dotenv::resolve_dotenv(&project_dir, &config, &names)?;
    let env_relative = resolved
        .path
        .strip_prefix(&project_dir)
        .context("Managed dotenv resolved outside the retained project root")?;
    let env_target = project_anchor
        .target(env_relative)
        .context("Failed to retain managed dotenv for token-remap review")?;
    let env_review = env_target
        .read_regular()?
        .context("Managed dotenv does not exist")?;
    let env_path = project_dir.join(env_relative);
    validate_protected_placeholders(&env_path, &names, env_review.bytes())?;
    let env_identity = env_review.identity();
    let env_permissions = env_review.permissions();
    let env_before = env_review.into_bytes();

    Ok(Some(LocalTokenRemapPlan {
        project_dir,
        project_identity,
        config_path,
        config_digest: digest_bytes(b"phantom-local-token-remap-config-v1\0", &config_before),
        config_before,
        local_project_id,
        env_path,
        env_identity,
        env_permissions,
        env_digest: digest_bytes(b"phantom-local-token-remap-dotenv-v1\0", &env_before),
        env_before,
        names_digest: names_digest(&names),
        names,
    }))
}

fn require_trusted_terminal_rotate_with(
    plan: &LocalTokenRemapPlan,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<()> {
    let challenge = plan.challenge()?;
    let project = terminal_safe_path(&plan.project_dir, "project")?;
    let dotenv = terminal_safe_path(&plan.env_path, "managed dotenv")?;
    let escaped_names = plan
        .names
        .iter()
        .map(|name| {
            name.chars()
                .flat_map(char::escape_default)
                .collect::<String>()
        })
        .collect::<Vec<_>>();
    let rendered_names = serde_json::to_string(&escaped_names)?;
    let rendered_names = if rendered_names.len() <= MAX_RENDERED_NAMES_BYTES {
        rendered_names
    } else {
        format!(
            "<{} names; review sorted-name digest {} in the challenge>",
            plan.names.len(),
            plan.names_digest
        )
    };
    writeln!(
        output,
        "This invalidates every current persistent phm_ mapping for the project. Provider credentials are unchanged.\nProject: {}\nManaged dotenv: {}\nProtected names (sorted, JSON escaped): {}\nType this exact challenge to continue:\n{}",
        project,
        dotenv,
        rendered_names,
        challenge
    )?;
    write!(output, "> ")?;
    output.flush()?;
    let mut response = String::new();
    (&mut *input)
        .take((challenge.len() + 2) as u64)
        .read_line(&mut response)
        .context("Failed to read trusted-terminal token-remap confirmation")?;
    if response.trim_end_matches(['\r', '\n']) != challenge {
        anyhow::bail!(
            "Token-remap confirmation did not match exactly. No vault value was read and no project file was changed."
        );
    }
    Ok(())
}

/// Remap all local phantom tokens without changing provider credentials.
///
/// The legacy `--with-expiry` and `--sync` combinations are rejected because a
/// placeholder remap is not evidence of credential rotation and must not renew
/// provider lifecycle metadata or deploy an unchanged credential.
pub fn run_with_expiry(sync_after: bool, expiry_days: Option<u64>) -> Result<()> {
    if expiry_days.is_some() {
        anyhow::bail!(
            "--with-expiry is not valid for a Phantom token remap: the provider credential is unchanged, so its TTL cannot be renewed. Rotate at the provider, then store the replacement from a trusted terminal; automated live provider issuance is disabled."
        );
    }
    if sync_after {
        anyhow::bail!(
            "--sync is not valid for a Phantom token remap: there is no new provider credential to deploy. Rotate at the provider, store the replacement from a trusted terminal, then run an explicitly reviewed sync."
        );
    }

    // This check deliberately precedes config, dotenv, and vault access. An
    // agent-controlled headless process never gets far enough to exercise a
    // backend or alter token availability.
    require_attached_rotate_terminals()?;
    let project_dir = std::env::current_dir()?;
    let Some(plan) = prepare_local_token_remap(&project_dir)? else {
        println!("{} No Phantom tokens to remap.", "!".yellow().bold());
        return Ok(());
    };

    require_trusted_terminal_rotate_with(
        &plan,
        &mut std::io::stdin().lock(),
        &mut std::io::stderr().lock(),
    )?;
    plan.commit()?;
    for name in &plan.names {
        phantom_core::audit::log("secret.token_remapped", Some(name));
    }
    println!(
        "{} Remapped {} Phantom token(s) in .env. Provider credentials and expiry metadata are unchanged.",
        "ok".green().bold(),
        plan.names.len()
    );

    Ok(())
}

/// Reject the legacy local auto-rotation schedule.
///
/// Called by `phantom rotate --schedule-strategy <STRATEGY>`.
pub fn run_with_schedule_strategy(
    _strategy_str: &str,
    _sync_after: bool,
    _expiry_days: Option<u64>,
) -> Result<()> {
    anyhow::bail!(
        "--schedule-strategy is deprecated and disabled: the legacy watcher only remapped local phm_ placeholders and did not rotate provider credentials. Configure a rotation_provider and use an explicitly reviewed provider rotation workflow."
    )
}

/// Replace local `phm_` placeholders through Phantom's retained project root.
///
/// This deliberately has no access to vault metadata or deployment sync. Every
/// requested name must already be represented by a Phantom token, otherwise no
/// file is written. The target retains every project ancestor from snapshot
/// through publish; exact identity, bytes, and permissions are rechecked at
/// the commit edge.
pub(crate) fn remap_phantom_tokens(env_path: &std::path::Path, names: &[String]) -> Result<()> {
    remap_phantom_tokens_with(env_path, names, || {})
}

fn remap_phantom_tokens_with(
    env_path: &std::path::Path,
    names: &[String],
    before_commit: impl FnOnce(),
) -> Result<()> {
    let project_dir = env_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    let transaction_lock = phantom_vault::acquire_project_transaction_lock(project_dir)
        .with_context(|| {
            format!(
                "Failed to acquire transaction lock for {}",
                project_dir.display()
            )
        })?;
    remap_phantom_tokens_locked_with(&transaction_lock, env_path, names, before_commit)
}

fn remap_phantom_tokens_locked(
    transaction_lock: &phantom_vault::ProjectTransactionLock,
    env_path: &std::path::Path,
    names: &[String],
) -> Result<()> {
    remap_phantom_tokens_locked_with(transaction_lock, env_path, names, || {})
}

fn remap_phantom_tokens_locked_with(
    transaction_lock: &phantom_vault::ProjectTransactionLock,
    env_path: &std::path::Path,
    names: &[String],
    before_commit: impl FnOnce(),
) -> Result<()> {
    let target = transaction_lock
        .target(env_path)
        .with_context(|| format!("Refusing unmanaged dotenv target {}", env_path.display()))?;
    let before = target.read_regular()?.with_context(|| {
        format!(
            "Cannot remap Phantom tokens: {} does not exist.",
            env_path.display()
        )
    })?;
    remap_phantom_tokens_from_snapshot(&target, env_path, names, &before, before_commit)
}

fn validate_protected_placeholders(env_path: &Path, names: &[String], before: &[u8]) -> Result<()> {
    let content = std::str::from_utf8(before)
        .with_context(|| format!("Failed to parse {} as UTF-8", env_path.display()))?;
    let dotenv = DotenvFile::parse_str(content);
    dotenv
        .validate_for_mutation()
        .context("Managed dotenv is malformed; no token remap was prepared")?;
    for name in names {
        let entry = dotenv
            .entries()
            .into_iter()
            .find(|entry| entry.key == *name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Cannot remap '{name}': it is not present in {}.",
                    env_path.display()
                )
            })?;
        if !entry.is_phantom {
            anyhow::bail!(
                "Cannot remap '{name}': its value in {} is not a protected phm_ token.",
                env_path.display()
            );
        }
    }
    Ok(())
}

fn resolve_managed_dotenv_path(
    transaction_lock: &phantom_vault::ProjectTransactionLock,
    project_dir: &Path,
    config: &PhantomConfig,
    vault_names: &[String],
) -> Result<PathBuf> {
    let protected_state = !vault_names.is_empty() || !config.phantom.secrets.is_empty();
    if let Some(configured) = config.phantom.dotenv_path.as_deref() {
        let configured = phantom_core::managed_dotenv::validate_dotenv_basename(configured)?;
        let path = project_dir.join(configured);
        let target = transaction_lock.target(&path)?;
        let current = target.read_regular()?.with_context(|| {
            format!(
                "Configured protected dotenv does not exist: {}",
                path.display()
            )
        })?;
        let dotenv = DotenvFile::parse_str(
            std::str::from_utf8(current.bytes())
                .with_context(|| format!("Failed to parse {} as UTF-8", path.display()))?,
        );
        if protected_state && !dotenv.entries().iter().any(|entry| entry.is_phantom) {
            anyhow::bail!(
                "Protected vault/config state exists, but {} contains no phantom tokens; refusing rotation",
                path.display()
            );
        }
        return Ok(path);
    }

    let mut existing = Vec::new();
    let mut token_bearing = Vec::new();
    for name in ROTATE_DOTENV_NAMES {
        let path = project_dir.join(name);
        let target = transaction_lock.target(&path)?;
        let Some(current) = target.read_regular()? else {
            continue;
        };
        let dotenv = DotenvFile::parse_str(
            std::str::from_utf8(current.bytes())
                .with_context(|| format!("Failed to parse {} as UTF-8", path.display()))?,
        );
        if dotenv.entries().iter().any(|entry| entry.is_phantom) {
            token_bearing.push(path.clone());
        }
        existing.push(path);
    }
    match token_bearing.len() {
        1 => return Ok(token_bearing.pop().expect("length checked")),
        count if count > 1 => anyhow::bail!(
            "Legacy config has {count} token-bearing dotenv files; rerun `phantom init --from <file>` to persist one explicit filename"
        ),
        _ => {}
    }
    if protected_state {
        anyhow::bail!(
            "Protected vault/config state exists, but no token-bearing dotenv file could be resolved; refusing rotation"
        );
    }
    Ok(existing
        .into_iter()
        .next()
        .unwrap_or_else(|| project_dir.join(".env")))
}

fn validate_managed_dotenv_for_mutation(
    transaction_lock: &phantom_vault::ProjectTransactionLock,
    env_path: &Path,
) -> Result<()> {
    let target = transaction_lock
        .target(env_path)
        .with_context(|| format!("Refusing unmanaged dotenv target {}", env_path.display()))?;
    let before = target.read_regular()?.with_context(|| {
        format!(
            "Managed dotenv disappeared before mutation: {}",
            env_path.display()
        )
    })?;
    let content = std::str::from_utf8(before.bytes())
        .with_context(|| format!("Failed to parse {} as UTF-8", env_path.display()))?;
    DotenvFile::parse_str(content)
        .validate_for_mutation()
        .context("Managed dotenv cannot be mutated safely")
}

fn remap_phantom_tokens_from_snapshot(
    target: &AnchoredTarget,
    env_path: &Path,
    names: &[String],
    before: &AnchoredRead,
    before_commit: impl FnOnce(),
) -> Result<()> {
    validate_protected_placeholders(env_path, names, before.bytes())?;
    let content = std::str::from_utf8(before.bytes())
        .with_context(|| format!("Failed to parse {} as UTF-8", env_path.display()))?;
    let dotenv = DotenvFile::parse_str(content);

    let mut token_map = TokenMap::new();
    for name in names {
        token_map.insert(name.clone());
    }
    let (rewritten, mut originals) = dotenv
        .rewrite_with_phantoms(&token_map)
        .context("Managed dotenv cannot be rewritten safely")?;
    for value in originals.values_mut() {
        value.zeroize();
    }
    originals.clear();

    before_commit();
    match target.replace_if_exact_with_permissions(
        Some(before),
        rewritten.as_bytes(),
        before.permissions(),
    )? {
        AnchoredEffect::Durable(_) => Ok(()),
        AnchoredEffect::CommittedVerifiedButDurabilityUncertain { .. } => {
            eprintln!(
                "warning: Phantom token remap for {} committed and was verified, but directory crash durability is not provable on this platform",
                env_path.display()
            );
            Ok(())
        }
        AnchoredEffect::CommittedButUncertain { error, .. } => anyhow::bail!(
            "Phantom token remap was committed for {}, but durability could not be verified: {error}",
            env_path.display()
        ),
    }
}

#[cfg(test)]
use provider::{persist_provider_rotation_metadata, read_expiry_metadata};

#[cfg(test)]
mod token_remap_tests;
