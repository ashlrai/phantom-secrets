use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::fs::{AnchoredEffect, AnchoredRead, AnchoredTarget, FileIdentity, TrustedAnchor};
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
        if env_current.bytes() != self.env_before {
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
    let local_project_id = config.local_project_id().to_string();
    let vault =
        phantom_vault::try_create_vault(&local_project_id).context("Failed to initialize vault")?;
    let names = sorted_names(vault.as_ref())?;
    if names.is_empty() {
        return Ok(None);
    }

    let resolved = phantom_core::managed_dotenv::resolve_dotenv(&project_dir, &config, &names)?;
    let env_before = phantom_core::fs::read_regular_file(&resolved.path)?
        .context("Managed dotenv does not exist")?;
    let env_path = resolved
        .path
        .canonicalize()
        .context("Failed to resolve managed dotenv")?;
    validate_protected_placeholders(&env_path, &names, &env_before)?;

    Ok(Some(LocalTokenRemapPlan {
        project_dir,
        project_identity,
        config_path,
        config_digest: digest_bytes(b"phantom-local-token-remap-config-v1\0", &config_before),
        config_before,
        local_project_id,
        env_path,
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
    let (rewritten, mut originals) = dotenv.rewrite_with_phantoms(&token_map);
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
        AnchoredEffect::CommittedButUncertain { error, .. } => anyhow::bail!(
            "Phantom token remap was committed for {}, but durability could not be verified: {error}",
            env_path.display()
        ),
    }
}

#[derive(Debug, serde::Serialize)]
struct CliProviderStages {
    provider_issued: bool,
    vault_committed: &'static str,
    token_remapped: bool,
    metadata_committed: bool,
    old_cleanup_attempted: bool,
    old_cleanup_succeeded: bool,
    cleanup_semantics: phantom_core::rotation_provider::CleanupSemantics,
    cleanup_outcome: Option<phantom_core::rotation_provider::CleanupOutcome>,
}

impl Default for CliProviderStages {
    fn default() -> Self {
        Self {
            provider_issued: false,
            vault_committed: "false",
            token_remapped: false,
            metadata_committed: false,
            old_cleanup_attempted: false,
            old_cleanup_succeeded: false,
            cleanup_semantics: phantom_core::rotation_provider::CleanupSemantics::NotApplicable,
            cleanup_outcome: None,
        }
    }
}

fn cli_provider_partial_error(
    name: &str,
    stage: &str,
    error: impl std::fmt::Display,
    stages: &CliProviderStages,
) -> anyhow::Error {
    let receipt = serde_json::to_string(stages).unwrap_or_else(|_| "receipt_unavailable".into());
    anyhow::anyhow!(
        "Provider rotation for '{name}' partially succeeded: {stage} failed. stage_receipt: {receipt}. Local and provider state may now differ. Do not retry automatically; reconcile provider, vault, token, metadata, and cleanup state first. Cause: {error}"
    )
}

fn persist_cli_provider_value(
    vault: &dyn VaultBackend,
    name: &str,
    before: Option<&zeroize::Zeroizing<String>>,
    issued: &str,
    stages: &mut CliProviderStages,
) -> Result<()> {
    match vault.compare_and_swap(name, before.map(|value| value.as_str()), Some(issued)) {
        Ok(true) => {}
        Ok(false) => {
            return Err(cli_provider_partial_error(
                name,
                "vault exact-before persistence",
                "destination changed concurrently",
                stages,
            ))
        }
        Err(error) => {
            stages.vault_committed = "unknown";
            return Err(cli_provider_partial_error(
                name,
                "vault persistence",
                error,
                stages,
            ));
        }
    }
    verify_cli_provider_value(
        vault,
        name,
        issued,
        "vault persistence verification",
        stages,
    )?;
    stages.vault_committed = "true";
    Ok(())
}

fn verify_cli_provider_value(
    vault: &dyn VaultBackend,
    name: &str,
    issued: &str,
    stage: &str,
    stages: &mut CliProviderStages,
) -> Result<()> {
    match vault.retrieve(name) {
        Ok(value) if value.as_str() == issued => Ok(()),
        Ok(_) => {
            stages.vault_committed = "false";
            Err(cli_provider_partial_error(
                name,
                stage,
                "vault no longer contains the provider-issued credential",
                stages,
            ))
        }
        Err(error) => {
            stages.vault_committed = "unknown";
            Err(cli_provider_partial_error(name, stage, error, stages))
        }
    }
}

fn read_expiry_metadata(vault: &dyn VaultBackend, name: &str) -> Result<Option<u64>> {
    Ok(vault
        .get_metadata(name)
        .with_context(|| format!("Failed to read rotation metadata for '{name}'"))?
        .and_then(|metadata| metadata.expires_at))
}

fn persist_provider_rotation_metadata(
    vault: &dyn VaultBackend,
    name: &str,
    expires_override: Option<u64>,
) -> Result<Option<u64>> {
    vault
        .record_provider_rotation(name, expires_override)
        .with_context(|| {
            format!(
                "Provider issued and Phantom stored a new credential for '{name}', but rotation metadata could not be persisted; provider cleanup and deployment sync were not attempted"
            )
        })
}

/// Current Unix timestamp in seconds.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Format a Unix timestamp as an ISO-8601-like UTC string for display.
fn chrono_iso(secs: u64) -> String {
    // Manual calculation to avoid pulling in chrono — only for display.
    let s = secs;
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hour = (s / 3600) % 24;
    let days = s / 86_400;
    // Approximate date from days since epoch (good enough for display).
    let year = 1970 + days / 365;
    let rem_days = days % 365;
    let month = rem_days / 30 + 1;
    let day = rem_days % 30 + 1;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Reject the legacy shadow-candidate path.
///
/// It generated only a local `phm_cand_` placeholder, not a provider-issued
/// credential, so neither staging nor later promotion was a real rotation.
pub fn run_shadow(_name: &str) -> Result<String> {
    anyhow::bail!(
        "--shadow is deprecated and disabled: Phantom's legacy implementation generated a local phm_cand_ placeholder, not a provider credential. No candidate was created or stored. Automated live provider issuance is also disabled; rotate at the provider and store the replacement from a trusted terminal."
    )
}

/// Reject legacy candidate validation and promotion without reading or writing
/// the vault. `promote` is retained only for call-site compatibility.
pub fn run_validate_promote(_name: &str, _promote: bool) -> Result<()> {
    anyhow::bail!(
        "--promote is deprecated and disabled: legacy shadow candidates were local phm_cand_ placeholders, not provider-issued credentials. No credential or metadata was changed. Automated live provider issuance is also disabled; rotate at the provider and store the replacement from a trusted terminal."
    )
}

/// Rotate a single named secret using a vendor-specific rotation provider.
///
/// Called by `phantom rotate --name <KEY> [--provider <PROVIDER>]`. Shipped
/// builds hard-deny every automated live issuance mode before bootstrap access
/// or provider I/O. Exact unit-test mocks exercise the local transaction only.
///
/// When `provider` is `None` the provider is resolved from the secret's
/// `[phantom.secrets.<KEY>.rotation_provider]` block in `.phantom.toml`.
/// The bootstrap credential named by `api_key_env` is sourced from the
/// process environment first, then from the vault under the same name —
/// it is never echoed.
///
/// The locked CAS/remap/metadata/cleanup transaction remains as tested
/// scaffolding for future provider-specific recovery contracts; it is not a
/// claim of current production issuance capability.
pub fn run_with_provider(
    provider: Option<&str>,
    name: &str,
    sync_after: bool,
    json_output: bool,
) -> Result<()> {
    use phantom_core::rotation_provider::{
        auto_sync_rotation_with_bootstrap, default_rotation_providers,
    };

    let reviewed_project_root = std::env::current_dir()?
        .canonicalize()
        .context("Failed to resolve canonical project root for provider rotation")?;
    let reviewed_project = TrustedAnchor::open(&reviewed_project_root)
        .context("Failed to retain project root before provider rotation")?;
    let reviewed_local_project_id = PhantomConfig::project_id_from_path(&reviewed_project_root);
    let config_path = reviewed_project_root.join(".phantom.toml");
    let reviewed_config_target = reviewed_project
        .target(".phantom.toml")
        .context("Failed to retain .phantom.toml for provider rotation")?;
    let reviewed_config = reviewed_config_target.read_regular()?.ok_or_else(|| {
        anyhow::anyhow!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        )
    })?;
    let config = PhantomConfig::load_from_bytes(&config_path, reviewed_config.bytes())
        .context("Failed to load .phantom.toml")?;
    if config.local_project_id() != reviewed_local_project_id {
        anyhow::bail!(
            "Reviewed config did not bind to the canonical local project identity; no provider or project payload was used."
        );
    }
    // Vault construction may take PROCESS_ENV_LOCK, so it must complete before
    // the project transaction lock is acquired.
    let vault = phantom_vault::try_create_vault(&reviewed_local_project_id)
        .context("Failed to initialize vault")?;
    let transaction_lock = acquire_reviewed_project_lock(
        &reviewed_project_root,
        &reviewed_project,
        || {},
        "provider rotation",
    )?;
    let config_target = transaction_lock
        .target(&config_path)
        .context("Failed to retain .phantom.toml for provider rotation")?;
    let retained_config = config_target.read_regular()?.ok_or_else(|| {
        anyhow::anyhow!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        )
    })?;
    if retained_config.identity() != reviewed_config.identity()
        || retained_config.bytes() != reviewed_config.bytes()
        || retained_config.permissions() != reviewed_config.permissions()
    {
        anyhow::bail!(
            "Project config changed while opening the provider-rotation vault; no provider or project payload was used."
        );
    }
    let vault_names = vault.list().context("Failed to list secrets")?;
    let env_path = resolve_managed_dotenv_path(
        &transaction_lock,
        &reviewed_project_root,
        &config,
        &vault_names,
    )?;

    // Resolve provider config from .phantom.toml.
    let provider_config = config
        .phantom
        .secrets
        .get(name)
        .and_then(|ov| ov.rotation_provider.as_ref());

    // GitHub App installation tokens are minted fresh from the App PEM, so a
    // github-provider target that does not exist yet is legal — the mint
    // creates it. Every other provider still requires an existing value to
    // rotate.
    let is_github_grant = provider_config
        .map(|cfg| cfg.provider.eq_ignore_ascii_case("github"))
        .unwrap_or(false);
    if !vault
        .exists(name)
        .with_context(|| format!("Failed to check if '{name}' exists in vault"))?
        && !is_github_grant
    {
        anyhow::bail!("Secret '{}' not found in vault.", name);
    }

    // Determine the effective provider: explicit --provider flag, else the
    // provider named in the secret's rotation_provider config block.
    let effective_provider: String = match (provider, provider_config) {
        (Some(requested), Some(cfg)) => {
            if cfg.provider != requested {
                anyhow::bail!(
                    "Secret '{}' is configured for provider '{}' but '{}' was requested.\n\
                     Update [phantom.secrets.{}.rotation_provider] in .phantom.toml.",
                    name,
                    cfg.provider,
                    requested,
                    name
                );
            }
            requested.to_string()
        }
        (requested, None) => {
            // No config in .phantom.toml — inform the user how to add it.
            anyhow::bail!(
                "No rotation_provider configured for secret '{}'.\n\
                 Add the following to .phantom.toml:\n\n\
                 [phantom.secrets.{}.rotation_provider]\n\
                 provider = \"{}\"\n\
                 api_key_env = \"<ENV_VAR_OR_VAULT_NAME_HOLDING_ROTATION_CREDENTIAL>\"",
                name,
                name,
                requested.unwrap_or("stripe")
            );
        }
        (None, Some(cfg)) => {
            if !json_output {
                println!(
                    "{} Using provider {} from .phantom.toml",
                    "->".blue().bold(),
                    cfg.provider.cyan().bold()
                );
            }
            cfg.provider.clone()
        }
    };

    if effective_provider.eq_ignore_ascii_case("stripe")
        && provider_config
            .and_then(|cfg| cfg.api_key_env.as_deref())
            .map(|name| name.to_ascii_uppercase().ends_with("REFRESH_TOKEN"))
            .unwrap_or(false)
    {
        anyhow::bail!(
            "Stripe OAuth refresh rotation is disabled before credential access or provider issuance: Stripe invalidates the current refresh token during exchange, before Phantom can durably verify the successor. A durable verified recovery escrow channel is required. Do not retry automatically."
        );
    }
    if effective_provider.eq_ignore_ascii_case("supabase-management")
        && provider_config.is_some_and(|cfg| cfg.account_id.is_none())
    {
        anyhow::bail!(
            "Supabase management refresh-token rotation is disabled before credential access or provider issuance: the refresh exchange invalidates the current token before Phantom can durably verify its successor. A durable verified recovery escrow channel is required. Keep the vaulted enrollment material and obtain fresh operator consent when it expires. Do not retry automatically."
        );
    }
    if !phantom_core::rotation_provider::unit_test_mock_issuance_enabled() {
        anyhow::bail!(
            "Automated live provider issuance for '{}' is disabled before credential access or network I/O. Phantom requires a durable value-free provider recovery handle and verified abort path before it can safely persist a successor locally. Rotate at the provider, then store the replacement interactively. Unit-test mock providers are not production capability evidence. Do not retry automatically.",
            effective_provider
        );
    }

    // Source the bootstrap credential: environment variable first, then the
    // vault under the same name. The value is zeroized after the call and is
    // never printed.
    let mut bootstrap = if let Some(env_name) = provider_config
        .and_then(|cfg| cfg.api_key_env.as_deref())
        .filter(|env_name| std::env::var(env_name).is_err())
    {
        Some(vault.retrieve(env_name).with_context(|| {
            format!("Failed to retrieve rotation bootstrap credential '{env_name}'")
        })?)
    } else {
        None
    };

    // GitHub App grants vault the PEM (never a ready JWT) under api_key_env.
    // Mint the short-lived RS256 App JWT in-process from that PEM immediately
    // before rotation: it is never an env var, never on disk, and is zeroized
    // on drop; the PEM's only destination is GitHub. A non-PEM value (a mock
    // prefix, or a pre-minted JWT) passes through untouched.
    if effective_provider.eq_ignore_ascii_case("github") {
        if let Some(pem) = bootstrap.as_ref() {
            if pem.as_str().trim_start().starts_with("-----BEGIN") {
                let client_id = vault
                    .retrieve(phantom_core::issuance::github_app::GITHUB_APP_CLIENT_ID_NAME)
                    .context("Failed to retrieve GitHub App client ID")?;
                bootstrap = Some(
                    phantom_core::issuance::mint_app_jwt(pem, &client_id)
                        .context("Failed to mint GitHub App bootstrap JWT")?,
                );
            }
        }
    }

    let providers = default_rotation_providers();

    // Capture the outgoing value BEFORE overwriting it: providers that revoke
    // the old credential at the vendor (Vercel) do so only after the new value
    // is durably stored, authenticating with the old value itself.
    let old_value = match vault.retrieve(name) {
        Ok(value) => Some(value),
        Err(phantom_core::error::PhantomError::SecretNotFound(_)) if is_github_grant => None,
        Err(error) => {
            return Err(error).with_context(|| {
                format!("Failed to snapshot the outgoing credential for '{name}'")
            });
        }
    };

    let config_at_provider_edge = config_target.read_regular()?;
    if config_at_provider_edge.as_ref().is_none_or(|current| {
        current.identity() != reviewed_config.identity()
            || current.bytes() != reviewed_config.bytes()
            || current.permissions() != reviewed_config.permissions()
    }) {
        anyhow::bail!(
            ".phantom.toml changed after provider rotation was planned; no provider call was made"
        );
    }

    let new_value = auto_sync_rotation_with_bootstrap(name, provider_config, &providers, bootstrap)
        .map_err(|e| anyhow::anyhow!("Provider rotation failed for '{}': {}", name, e))?;

    match new_value {
        Some(secret) => {
            let mut stages = CliProviderStages {
                provider_issued: true,
                ..CliProviderStages::default()
            };
            persist_cli_provider_value(
                vault.as_ref(),
                name,
                old_value.as_ref(),
                secret.as_str(),
                &mut stages,
            )?;

            phantom_core::audit::log("vault.rotation.provider.stored", Some(name));

            // Refresh the phm_ token for this secret in .env so the old
            // token cannot resolve to the new credential.
            remap_phantom_tokens_locked(&transaction_lock, &env_path, &[name.to_string()])
                .map_err(|error| {
                    cli_provider_partial_error(name, "Phantom token remap", error, &stages)
                })?;
            let env_token_refreshed = true;
            stages.token_remapped = true;

            // Persist rotation metadata (rotated_at + recomputed expires_at).
            // GitHub App installation tokens expire after 1 hour, so stamp the
            // real short TTL instead of leaving a dead token looking fresh.
            let expires_override = if effective_provider.eq_ignore_ascii_case("github") {
                Some(
                    now_unix()
                        + phantom_core::rotation_provider::GITHUB_INSTALLATION_TOKEN_TTL_SECS,
                )
            } else {
                None
            };
            verify_cli_provider_value(
                vault.as_ref(),
                name,
                secret.as_str(),
                "pre-metadata vault verification",
                &mut stages,
            )?;
            let expires_at =
                persist_provider_rotation_metadata(vault.as_ref(), name, expires_override)
                    .map_err(|error| {
                        cli_provider_partial_error(name, "rotation metadata commit", error, &stages)
                    })?;
            stages.metadata_committed = true;

            // Only providers that declare a real cleanup effect are invoked.
            // Default no-op providers report not_applicable and are never
            // represented as an attempted or successful revocation.
            if let (Some(provider), Some(cfg)) = (
                providers
                    .iter()
                    .find(|p| p.name().eq_ignore_ascii_case(&effective_provider)),
                provider_config,
            ) {
                let semantics = provider.cleanup_semantics(cfg);
                stages.cleanup_semantics = semantics;
                if semantics
                    == phantom_core::rotation_provider::CleanupSemantics::RevokePriorCredential
                {
                    verify_cli_provider_value(
                        vault.as_ref(),
                        name,
                        secret.as_str(),
                        "pre-cleanup vault verification",
                        &mut stages,
                    )?;
                    stages.old_cleanup_attempted = true;
                    let outcome = provider
                        .post_store_cleanup(name, cfg, old_value.as_ref())
                        .map_err(|error| {
                            cli_provider_partial_error(
                                name,
                                "prior-credential cleanup",
                                error,
                                &stages,
                            )
                        })?;
                    stages.cleanup_outcome = Some(outcome);
                    stages.old_cleanup_succeeded =
                        outcome == phantom_core::rotation_provider::CleanupOutcome::Succeeded;
                    verify_cli_provider_value(
                        vault.as_ref(),
                        name,
                        secret.as_str(),
                        "post-cleanup vault verification",
                        &mut stages,
                    )?;
                } else {
                    stages.cleanup_outcome =
                        Some(phantom_core::rotation_provider::CleanupOutcome::NotApplicable);
                }
            }

            if json_output {
                let obj = serde_json::json!({
                    "secret": name,
                    "provider": effective_provider,
                    "status": "rotated",
                    "vendor_rotated": true,
                    "stored_in_vault": true,
                    "env_token_refreshed": env_token_refreshed,
                    "expires_at": expires_at,
                    "value_printed": false,
                    "stage_receipt": stages,
                });
                println!("{}", serde_json::to_string_pretty(&obj)?);
            } else {
                println!(
                    "{} Provider rotation succeeded for {} via {}.",
                    "ok".green().bold(),
                    name.bold(),
                    effective_provider.cyan()
                );
                println!("   The new credential has been stored in the vault.");
                if env_token_refreshed {
                    println!("   The phm_ token for {name} in .env was refreshed.");
                }
                if let Some(ts) = expires_at {
                    println!("   Expires at: {}", chrono_iso(ts));
                }
                match stages.cleanup_outcome {
                    Some(phantom_core::rotation_provider::CleanupOutcome::Succeeded) => {
                        println!("   The prior provider credential was revoked.");
                    }
                    Some(
                        phantom_core::rotation_provider::CleanupOutcome::SkippedNoPriorCredential,
                    ) => {
                        println!("   Prior-credential cleanup was skipped: no prior local value was available.");
                    }
                    Some(
                        phantom_core::rotation_provider::CleanupOutcome::SkippedMockCredential,
                    ) => {
                        println!(
                            "   Prior-credential cleanup was skipped for the unit-test mock value."
                        );
                    }
                    Some(
                        phantom_core::rotation_provider::CleanupOutcome::SkippedPriorCredentialNotFound,
                    ) => {
                        println!(
                            "   Prior-credential cleanup found no matching provider credential; revocation was not confirmed."
                        );
                    }
                    Some(phantom_core::rotation_provider::CleanupOutcome::NotApplicable) | None => {
                        println!(
                            "   This provider does not declare a prior-credential cleanup effect."
                        );
                    }
                }
                println!("   The secret value was not printed for security.");
            }
        }
        None => {
            // auto_sync returns Ok(None) only for provider = "manual" now;
            // disabled configs and unknown provider names are hard errors
            // surfaced above with their own messages.
            anyhow::bail!(
                "Secret '{}' is configured with provider = \"manual\" — there is no vendor \
                 API to call.\nRotate the credential manually, then store it with `phantom add {}`.",
                name,
                name
            );
        }
    }

    drop(transaction_lock);

    if sync_after {
        if !json_output {
            println!("\n{} Syncing to deployment platforms…", "->".blue().bold());
        }
        crate::commands::sync::run(None, None, vec![], false, false)?;
    }

    Ok(())
}

/// Execute expiry-driven batch rotation across all vault secrets whose TTL
/// falls within `rotation_window_days`.
///
/// Vendor batch issuance is disabled before any provider call. Issuing several
/// successors before each one is independently persisted and verified creates
/// unrecoverable ambiguity. Manual items remain report-only; provider
/// credentials must be rotated at the provider and stored from a trusted
/// terminal.
///
/// Emits a composite audit event with a shared `batch_id` covering the
/// discovery/manual-report outcomes.
/// Prints a summary table: secret name | old expiry | new expiry | provider.
pub fn run_batch(
    rotation_window_days: u64,
    sync_after: bool,
    json_output: bool,
) -> anyhow::Result<()> {
    use phantom_core::rotation_provider::{
        batch_discover_due, default_rotation_providers, execute_batch_rotation,
    };

    if sync_after {
        anyhow::bail!(
            "--sync is not valid for report-only batch rotation: no provider credential is issued or changed. Rotate and sync each configured secret individually."
        );
    }

    let project_dir = std::env::current_dir()?;
    let config_path = project_dir.join(".phantom.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "No .phantom.toml found. Run {} first.",
            "phantom init".cyan().bold()
        );
    }

    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
    let vault = phantom_vault::try_create_vault(config.local_project_id())
        .context("Failed to initialize vault")?;

    // Gather all secrets with their expiry metadata and provider config.
    let names = vault.list().context("Failed to list secrets")?;
    if names.is_empty() {
        println!("{} No secrets in vault.", "!".yellow().bold());
        return Ok(());
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Build the scan input: (name, expires_at, provider_config)
    let mut scan_input: Vec<(
        String,
        Option<u64>,
        Option<phantom_core::rotation_provider::RotationProviderConfig>,
    )> = Vec::new();
    for name in &names {
        let expires_at = read_expiry_metadata(vault.as_ref(), name)?;
        let provider_config = config
            .phantom
            .secrets
            .get(name)
            .and_then(|ov| ov.rotation_provider.clone());
        scan_input.push((name.clone(), expires_at, provider_config));
    }

    let rotation_window_secs = rotation_window_days * 86_400;
    let providers = default_rotation_providers();

    let due_items = batch_discover_due(&scan_input, rotation_window_secs, now, &providers);

    if due_items.is_empty() {
        println!(
            "{} No secrets are due for rotation within the next {} day(s).",
            "ok".green().bold(),
            rotation_window_days
        );
        return Ok(());
    }

    if due_items.iter().any(|item| item.provider_label != "manual") {
        anyhow::bail!(
            "Batch vendor rotation is disabled before issuance: Phantom cannot durably persist and verify each successor before issuing the next. Rotate each credential through the provider's trusted interface, then store each replacement from a trusted terminal. No provider call was made; do not retry this batch automatically."
        );
    }

    println!(
        "{} Found {} secret(s) due for rotation within {} day(s).",
        "->".blue().bold(),
        due_items.len(),
        rotation_window_days
    );
    println!();

    // Execute the batch.
    let (batch_id, outcomes) = execute_batch_rotation(&due_items, &providers, now);

    // Print summary table.
    if json_output {
        // Emit JSON array for scripting.
        let rows: Vec<serde_json::Value> = outcomes
            .iter()
            .map(|o| {
                serde_json::json!({
                    "secret": o.secret_name,
                    "old_expires_at": o.old_expires_at,
                    "new_expires_at": o.new_expires_at,
                    "provider": o.provider_label,
                    "vendor_rotated": o.vendor_rotated,
                    "ok": o.is_ok(),
                    "error": o.error,
                    "batch_id": batch_id,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else {
        println!("{}", "Batch Rotation Summary".bold());
        println!("{}", "-".repeat(80));
        println!(
            "{:<32} {:<20} {:<20} {:<12} {}",
            "Secret".bold(),
            "Old Expiry".bold(),
            "New Expiry".bold(),
            "Provider".bold(),
            "Status".bold()
        );
        println!("{}", "-".repeat(80));

        for outcome in &outcomes {
            let old_exp = outcome
                .old_expires_at
                .map(chrono_iso)
                .unwrap_or_else(|| "none".to_string());
            let new_exp = outcome
                .new_expires_at
                .map(chrono_iso)
                .unwrap_or_else(|| "none".to_string());
            let status = if let Some(ref err) = outcome.error {
                format!(
                    "{} {}",
                    "FAIL".red().bold(),
                    err.chars().take(30).collect::<String>()
                )
            } else if outcome.vendor_rotated {
                format!("{} via {}", "ok".green().bold(), outcome.provider_label)
            } else if outcome.new_value.is_none() && outcome.error.is_none() {
                format!("{} (manual rotation needed)", "!".yellow().bold())
            } else {
                "ok".green().bold().to_string()
            };

            println!(
                "{:<32} {:<20} {:<20} {:<12} {}",
                outcome.secret_name.chars().take(31).collect::<String>(),
                old_exp,
                new_exp,
                outcome.provider_label.chars().take(11).collect::<String>(),
                status
            );
        }

        println!("{}", "-".repeat(80));
        let succeeded = outcomes
            .iter()
            .filter(|o| o.is_ok() && o.vendor_rotated)
            .count();
        let manual = outcomes
            .iter()
            .filter(|o| o.is_ok() && !o.vendor_rotated)
            .count();
        let failed = outcomes.iter().filter(|o| !o.is_ok()).count();
        println!(
            "\n{} Batch {}: {} vendor-rotated, {} manual, {} failed",
            "ok".green().bold(),
            batch_id.cyan(),
            succeeded,
            manual,
            failed
        );
        println!(
            "   Audit events tagged with {}",
            format!("batch_id={batch_id}").cyan()
        );
    }

    Ok(())
}

#[cfg(test)]
mod token_remap_tests {
    use super::*;
    use phantom_core::error::{PhantomError, Result as PhantomResult};
    use phantom_core::validator::ValidationMetadata;
    use phantom_vault::SecretMetadata;
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    fn sample_plan() -> LocalTokenRemapPlan {
        let project_dir = PathBuf::from("/canonical/project");
        let config_before = b"[phantom]\nversion = \"1\"\n".to_vec();
        let env_before =
            format!("A=phm_{}\nB=phm_{}\n", "a".repeat(64), "b".repeat(64)).into_bytes();
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
        let env_before =
            format!("A=phm_{}\nB=phm_{}\n", "a".repeat(64), "b".repeat(64)).into_bytes();
        std::fs::write(&env_path, &env_before).unwrap();
        let env_path = env_path.canonicalize().unwrap();
        let names = vec!["A".to_string(), "B".to_string()];
        let plan = LocalTokenRemapPlan {
            project_identity: TrustedAnchor::open(&project_dir).unwrap().identity(),
            project_dir,
            config_path,
            config_digest: digest_bytes(b"phantom-local-token-remap-config-v1\0", &config_before),
            config_before,
            local_project_id: config.local_project_id().to_string(),
            env_path,
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
        let concurrent =
            format!("A=phm_{}\nB=phm_{}\n", "c".repeat(64), "d".repeat(64)).into_bytes();
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
    fn vault_resolution_precedes_project_lock_source_contract() {
        let source = include_str!("rotate.rs");
        let provider = source
            .split("pub fn run_with_provider")
            .nth(1)
            .unwrap()
            .split("pub fn")
            .next()
            .unwrap();
        let anchor = provider.find("TrustedAnchor::open").unwrap();
        let vault = provider.find("try_create_vault").unwrap();
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
        let vault = commit.find("try_create_vault").unwrap();
        let project_lock = commit.find("acquire_reviewed_project_lock").unwrap();
        assert!(approved_identity < vault && vault < project_lock);
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
        let transaction_lock =
            phantom_vault::acquire_project_transaction_lock(project.path()).unwrap();

        let error =
            remap_phantom_tokens_locked(&transaction_lock, &env_path, &["TARGET".to_string()])
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
}
