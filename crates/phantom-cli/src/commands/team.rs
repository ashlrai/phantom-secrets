use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::{auth, config::PhantomConfig, teams, teams_vault};
use std::collections::BTreeMap;
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

/// "Refusing to ..." wording for the rotation gate on a team vault pull,
/// shared with the MCP `phantom_team_vault_pull` tool.
const TEAM_PULL_ACTION: &str = "pull the team vault";

/// `phantom team list --json`: `{"teams":[{"id","name","role"}]}`. The
/// service does not report an active team, so no `active` field is invented.
fn team_list_json(team_list: &[teams::Team]) -> serde_json::Value {
    serde_json::json!({
        "teams": team_list
            .iter()
            .map(|team| serde_json::json!({
                "id": team.id,
                "name": team.name,
                "role": team.role,
            }))
            .collect::<Vec<_>>(),
    })
}

/// `json` prints [`team_list_json`] instead of the text list. Both pass the
/// same trusted-terminal consent gate and make the same single request.
pub fn run_list(json: bool) -> Result<()> {
    require_trusted_terminal_team(&team_consent_plan(
        "list",
        &[],
        "read the stored Phantom bearer and send an authenticated request for the caller's remote team list",
    )?)?;
    let token = Zeroizing::new(auth::require_token()?);
    let api_base = auth::api_base_url()?;

    let rt = crate::util::oneshot_runtime()?;
    let team_list = rt.block_on(teams::list_teams(&api_base, &token))?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&team_list_json(&team_list))?
        );
        return Ok(());
    }

    if team_list.is_empty() {
        println!(
            "{}  No teams yet. Create one with `phantom team create <name>`",
            "->".blue().bold()
        );
        return Ok(());
    }

    println!("{}  Your teams:\n", "ok".green().bold());
    for team in &team_list {
        println!(
            "   {} {} (role: {})",
            team.id.dimmed(),
            team.name.bold(),
            team.role
        );
    }

    Ok(())
}

pub fn run_create(name: &str) -> Result<()> {
    require_trusted_terminal_team(&team_consent_plan(
        "create",
        &[name],
        "create a persistent remote team and make the authenticated caller its owner",
    )?)?;
    let token = Zeroizing::new(auth::require_token()?);
    let api_base = auth::api_base_url()?;

    println!("{}  Creating team \"{}\"...", "->".blue().bold(), name);

    let rt = crate::util::oneshot_runtime()?;
    let team = rt
        .block_on(teams::create_team(&api_base, &token, name))
        .context(
            "Team creation did not return a success receipt; the remote outcome is unknown. Inspect the team list before any retry",
        )?;

    println!(
        "{}  Team \"{}\" created (id: {})",
        "ok".green().bold(),
        team.name,
        team.id
    );

    Ok(())
}

pub fn run_members(team_id: &str) -> Result<()> {
    require_trusted_terminal_team(&team_consent_plan(
        "members",
        &[team_id],
        "read the stored Phantom bearer and send an authenticated request for the selected team's member roster",
    )?)?;
    let token = Zeroizing::new(auth::require_token()?);
    let api_base = auth::api_base_url()?;

    let rt = crate::util::oneshot_runtime()?;
    let members = rt.block_on(teams::list_members(&api_base, &token, team_id))?;

    if members.is_empty() {
        println!(
            "{}  No members yet. Invite someone with `phantom team invite {} <github_login>`",
            "->".blue().bold(),
            team_id
        );
        return Ok(());
    }

    println!("{}  Team members:\n", "ok".green().bold());
    for member in &members {
        let email_str = member
            .email
            .as_deref()
            .map(|e| format!(" <{e}>"))
            .unwrap_or_default();
        println!(
            "   @{}{} ({})",
            member.github_login.bold(),
            email_str.dimmed(),
            member.role
        );
    }

    Ok(())
}

pub fn run_key_publish(team_id: &str) -> Result<()> {
    require_trusted_terminal_team(&team_consent_plan(
        "key-publish",
        &[team_id],
        "provision or load this device's private team key and register its public key remotely",
    )?)?;
    let token = Zeroizing::new(auth::require_token()?);
    let api_base = auth::api_base_url()?;
    let kp = auth::get_or_create_team_keypair()?;
    let pk = kp.public_b64();
    // Last 8 chars of the base64 pubkey as a stable, distinguishable
    // fingerprint for verification across rotations. Full key is on the
    // server and in the user's keychain — this is just a visual aid.
    let fp_len = 8.min(pk.len());
    let fingerprint = &pk[pk.len() - fp_len..];
    let rt = crate::util::oneshot_runtime()?;
    rt.block_on(teams::register_team_key(&api_base, &token, team_id, &pk))
        .context("Team key registration did not return a success receipt; a local device keypair may already exist and the remote outcome is unknown. Inspect registered keys before any retry")?;
    println!(
        "{}  Public key registered for team id {} — fingerprint …{}",
        "ok".green().bold(),
        team_id,
        fingerprint
    );
    Ok(())
}

pub fn run_vault_push(team_id: &str) -> Result<()> {
    let (project_dir, _config_path, _config_before, config) = load_team_project_exact()?;
    let project_id = config.portable_project_id().to_string();
    let project_path = project_dir.to_string_lossy().into_owned();
    // A locked or partial inventory and an overdue enforced, read-only or
    // unjudgeable entry are known from names and metadata alone: refuse
    // before asking for consent, so the user never confirms a push that
    // cannot run. All are judged again after consent, before any value read.
    {
        let vault = crate::util::open_vault(config.local_project_id())?;
        let names = vault.list()?;
        crate::util::require_complete_inventory(
            vault.as_ref(),
            config.local_project_id(),
            names.len(),
            "push to the team vault",
        )?;
        gate_team_push(
            &config,
            vault.as_ref(),
            &names,
            super::rotation_gate::now_secs(),
        )?;
    }
    require_trusted_terminal_team(&team_consent_plan(
        "vault-push",
        &[team_id, &project_id, &project_path],
        "retrieve every local vault value, encrypt it to registered team members, and overwrite the remote shared vault",
    )?)?;
    let token = Zeroizing::new(auth::require_token()?);
    let api_base = auth::api_base_url()?;
    let kp = auth::get_or_create_team_keypair()?;
    vault_push_after_consent(team_id, &project_id, &config, &token, &api_base, &kp)
}

/// "Refusing to ..." wording for the lifecycle gate on a team vault push.
const TEAM_PUSH_ACTION: &str = "push to the team vault";

/// Team members receive real values and inject them at runtime: refuse an
/// overdue enforced secret, as `phantom exec` would, and an entry the expiry
/// policy demoted to read-only (the demotion exists to stop that) or whose
/// lifecycle metadata cannot be read. Names and metadata only; the whole push
/// is refused, naming entries only.
fn gate_team_push(
    config: &phantom_core::config::PhantomConfig,
    vault: &dyn phantom_vault::VaultBackend,
    secret_names: &[String],
    now_secs: u64,
) -> Result<()> {
    super::rotation_gate::enforce_lifecycle_on_propagation(
        config,
        vault,
        secret_names.iter().map(String::as_str),
        TEAM_PUSH_ACTION,
        "Rotate or promote them before sharing with the team.",
        "No vault plaintext was read and no team request was sent.",
        now_secs,
    )
}

/// Read every value a team push sends, after [`gate_team_push`] judges the
/// inventory again immediately before any value is read.
fn read_team_push_values(
    config: &phantom_core::config::PhantomConfig,
    vault: &dyn phantom_vault::VaultBackend,
    secret_names: &[String],
    now_secs: u64,
) -> Result<BTreeMap<String, Zeroizing<String>>> {
    gate_team_push(config, vault, secret_names, now_secs)?;
    let mut secrets: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    for name in secret_names {
        // The injection read re-checks the mode atomically with the value
        // read, so an entry demoted after the preflight is never sent.
        let value = vault.retrieve_for_injection(name)?; // Zeroizing<String>
        secrets.insert(name.clone(), Zeroizing::new(String::from(value.as_str())));
    }
    Ok(secrets)
}

/// `team vault-push` once terminal consent is given and the bearer and team
/// keypair are read: list the local vault, judge that inventory, and only
/// then read values and send. Split out so a test can enter here without a
/// terminal; `run_vault_push` is the only production caller.
fn vault_push_after_consent(
    team_id: &str,
    project_id: &str,
    config: &phantom_core::config::PhantomConfig,
    token: &str,
    api_base: &str,
    kp: &phantom_core::team_crypto::MemberKeypair,
) -> Result<()> {
    let rt = crate::util::oneshot_runtime()?;

    // Read the local vault into a Zeroizing-valued map so the secret
    // bytes are scrubbed when the helper drops them.
    let vault = crate::util::open_vault(config.local_project_id())?;
    let secret_names = vault.list()?;
    // The push overwrites the remote shared vault: never from a keychain-only
    // view of a project whose encrypted-file vault this process cannot open.
    crate::util::require_complete_inventory(
        vault.as_ref(),
        config.local_project_id(),
        secret_names.len(),
        "push to the team vault",
    )?;
    if secret_names.is_empty() {
        println!("{}  No secrets to push", "warn".yellow().bold());
        return Ok(());
    }
    let secrets = read_team_push_values(
        config,
        vault.as_ref(),
        &secret_names,
        super::rotation_gate::now_secs(),
    )?;

    let outcome = rt
        .block_on(teams_vault::push_for_project(
            api_base, token, team_id, project_id, secrets, kp,
        ))
        .context(
            "Team vault push did not return a success receipt; the remote ciphertext outcome is unknown. Do not retry automatically until the remote vault version is inspected",
        )?;

    let suffix = if outcome.skipped > 0 {
        format!(
            ", {} member(s) skipped — no key registered yet",
            outcome.skipped
        )
    } else {
        String::new()
    };
    println!(
        "{}  {} secret(s) pushed to team id {} (v{}, encrypted for {} member(s){suffix})",
        "ok".green().bold(),
        outcome.secret_count,
        team_id,
        outcome.new_version,
        outcome.recipients,
    );
    Ok(())
}

pub fn run_vault_pull(team_id: &str) -> Result<()> {
    let (project_dir, config_path, config_before, config) = load_team_project_exact()?;
    // Judge the destination before consent, credentials, network or any value
    // read: every pulled entry is written into this vault.
    let vault = team_vault_pull_destination(&config)?;
    let project_id = config.portable_project_id().to_string();
    let project_path = project_dir.to_string_lossy().into_owned();
    require_trusted_terminal_team(&team_consent_plan(
        "vault-pull",
        &[team_id, &project_id, &project_path],
        "download and decrypt the remote shared vault, then transactionally overwrite matching local vault entries",
    )?)?;
    let token = Zeroizing::new(auth::require_token()?);
    let api_base = auth::api_base_url()?;
    let kp = auth::get_or_create_team_keypair()?;
    let rt = crate::util::oneshot_runtime()?;

    let (secrets, version) = rt.block_on(teams_vault::pull_for_project(
        &api_base,
        &token,
        team_id,
        &project_id,
        &kp,
    ))?;

    // Commit the complete remote snapshot under Phantom's project transaction
    // lock. Every target carries an exact local before-image; a later failure
    // rolls back only transaction-owned writes and never prints a value.
    let written = apply_team_vault_pull_transaction(
        &project_dir,
        &config,
        vault.as_ref(),
        &secrets,
        vec![phantom_vault::InitFile::replace_if_unchanged(
            config_path,
            Some(config_before.clone()),
            config_before,
        )],
    )?;

    println!(
        "{}  Pulled {} secret(s) from team id {} (v{}). Local vault updated.",
        "ok".green().bold(),
        written,
        team_id,
        version
    );
    Ok(())
}

/// Open the vault a `team vault-pull` writes into, listing names only. Beside
/// an encrypted-file vault this process cannot open, the OS keychain it
/// selects instead would take every pulled entry (splitting the project
/// across two vaults) with before-images from the keychain alone, so an empty
/// or keychain-only inventory is refused.
fn team_vault_pull_destination(
    config: &PhantomConfig,
) -> Result<Box<dyn phantom_vault::VaultBackend>> {
    let vault = crate::util::open_vault(config.local_project_id())?;
    let listed = vault.list()?.len();
    crate::util::require_complete_inventory(
        vault.as_ref(),
        config.local_project_id(),
        listed,
        "reconcile a team vault pull",
    )?;
    Ok(vault)
}

fn apply_team_vault_pull_transaction(
    project_dir: &std::path::Path,
    config: &PhantomConfig,
    vault: &dyn phantom_vault::VaultBackend,
    secrets: &BTreeMap<String, Zeroizing<String>>,
    files: Vec<phantom_vault::InitFile>,
) -> Result<usize> {
    let mut mutations = Vec::with_capacity(secrets.len());
    let mut changed = Vec::new();
    for (name, value) in secrets {
        let before = match vault.retrieve(name) {
            Ok(value) => Some(value),
            Err(phantom_core::error::PhantomError::SecretNotFound(_)) => None,
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "Team vault pull preflight failed for '{name}' before any local write: {error}"
                ));
            }
        };
        if before.as_ref().map(|local| local.as_str()) != Some(value.as_str()) {
            changed.push(name.as_str());
        }
        mutations.push(phantom_vault::InitSecret::replace_if_unchanged(
            name,
            before.as_ref().map(|value| value.as_str().to_string()),
            value.as_str(),
        ));
    }
    // The remote names are known only after the download, so this is the
    // earliest point the gate can run. A team-pulled value carries no
    // rotation anchor: a new entry would be stamped as stored now and an
    // overwrite would keep the local anchor, laundering an overdue value.
    // Refuse every enforced change before any vault or config write; an
    // identical value keeps its anchor and is not judged.
    super::rotation_gate::enforce_rotation_on_restore(
        config,
        vault,
        changed,
        TEAM_PULL_ACTION,
        super::rotation_gate::now_secs(),
    )?;
    let written = mutations.len();
    phantom_vault::commit_init(project_dir, vault, mutations, files).map_err(|error| {
        anyhow::anyhow!(
            "Team vault pull transaction failed; local state was rolled back where exact transaction ownership could be verified: {error}. No secret value is included. Inspect the local vault before retrying."
        )
    })?;
    Ok(written)
}

pub fn run_revoke(team_id: &str, github_login: &str, _yes: bool) -> Result<()> {
    anyhow::bail!(
        "Team member revocation is unavailable: Phantom Cloud does not yet expose the required atomic membership-removal and vault-key-rotation transaction (team {team_id}, member @{github_login})"
    )
}

pub fn run_rotate_vault(team_id: &str) -> Result<()> {
    let (project_dir, _config_path, _config_before, config) = load_team_project_exact()?;
    let project_id = config.portable_project_id().to_string();
    let project_path = project_dir.to_string_lossy().into_owned();
    require_trusted_terminal_team(&team_consent_plan(
        "vault-rotate",
        &[team_id, &project_id, &project_path],
        "download the shared vault, generate a new vault key, and overwrite remote ciphertext and member key shares",
    )?)?;
    let token = Zeroizing::new(auth::require_token()?);
    let api_base = auth::api_base_url()?;
    let kp = auth::get_or_create_team_keypair()?;

    println!(
        "{}  Rotating vault key for team {} (all members will be re-wrapped)...",
        "->".blue().bold(),
        team_id
    );

    let rt = crate::util::oneshot_runtime()?;
    let outcome = rt
        .block_on(teams_vault::rotate_vault(
            &api_base,
            &token,
            team_id,
            &project_id,
            &kp,
        ))
        .context(
            "Team vault rotation did not return a success receipt; the remote key/ciphertext outcome is unknown. Do not retry automatically until the remote vault version and member shares are inspected",
        )?;

    println!(
        "{}  Vault rotated to v{} ({} secret(s), re-encrypted for {} member(s){}).",
        "ok".green().bold(),
        outcome.new_version,
        outcome.secret_count,
        outcome.recipients,
        if outcome.skipped > 0 {
            format!(", {} skipped — no key registered", outcome.skipped)
        } else {
            String::new()
        }
    );
    println!(
        "{}  Audit events recorded: team.vault.key_rotated + team.vault.rotation_members",
        "   ".dimmed()
    );
    Ok(())
}

pub fn run_invite(team_id: &str, github_login: &str, role: &str) -> Result<()> {
    require_trusted_terminal_team(&team_consent_plan(
        "invite",
        &[team_id, github_login, role],
        "add the GitHub account to the remote team; current roles do not restrict shared-vault read/write access",
    )?)?;
    let token = Zeroizing::new(auth::require_token()?);
    let api_base = auth::api_base_url()?;

    println!(
        "{}  Inviting @{} as {} to team {}...",
        "->".blue().bold(),
        github_login,
        role,
        team_id
    );

    let rt = crate::util::oneshot_runtime()?;
    rt.block_on(teams::invite_member(
        &api_base,
        &token,
        team_id,
        github_login,
        role,
    ))
    .context(
        "Team invitation did not return a success receipt; the remote membership outcome is unknown. Inspect the team roster before any retry",
    )?;

    println!(
        "{}  @{} invited as {}",
        "ok".green().bold(),
        github_login,
        role
    );

    println!("\n{}", invitation_checklist(team_id));

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct TeamConsentPlan {
    effect: &'static str,
    challenge: String,
}

fn team_consent_plan(
    action: &str,
    components: &[&str],
    effect: &'static str,
) -> Result<TeamConsentPlan> {
    if action.is_empty()
        || !action
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
    {
        anyhow::bail!("Invalid internal team consent action");
    }
    let mut challenge = format!("team {action}");
    for component in components {
        if component.is_empty() || component.len() > 1024 || component.chars().any(char::is_control)
        {
            anyhow::bail!(
                "Team effect identifiers must be non-empty, bounded, and contain no control characters"
            );
        }
        challenge.push(' ');
        challenge.push_str(
            &serde_json::to_string(component)
                .context("Failed to encode the team consent challenge")?,
        );
    }
    Ok(TeamConsentPlan { effect, challenge })
}

fn require_trusted_terminal_team(plan: &TeamConsentPlan) -> Result<()> {
    let attached = std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal();
    let stdin = std::io::stdin();
    let stderr = std::io::stderr();
    confirm_team_effect(plan, attached, &mut stdin.lock(), &mut stderr.lock())
}

fn confirm_team_effect(
    plan: &TeamConsentPlan,
    attached: bool,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> Result<()> {
    if !attached {
        anyhow::bail!(
            "Team effects require stdin, stdout, and stderr attached to a trusted terminal before credential, keypair, vault-value, or network access"
        );
    }
    writeln!(writer, "Team effect: {}", plan.effect)?;
    writeln!(
        writer,
        "Approve only if this terminal is outside the requesting agent's authority; a same-user shell or agent-controlled PTY can automate this ceremony."
    )?;
    write!(writer, "Type `{}` to continue: ", plan.challenge)?;
    writer.flush()?;
    let mut response = String::new();
    reader.read_line(&mut response)?;
    if response.trim() != plan.challenge {
        anyhow::bail!("Team effect cancelled: typed confirmation did not match");
    }
    Ok(())
}

fn load_team_project_exact() -> Result<(PathBuf, PathBuf, Vec<u8>, PhantomConfig)> {
    let project_dir = crate::util::project_dir()?.canonicalize()?;
    let config_path = project_dir.join(".phantom.toml");
    let config_before = phantom_core::fs::read_regular_file(&config_path)
        .context("Failed to safely read .phantom.toml")?
        .ok_or_else(|| anyhow::anyhow!("No .phantom.toml found. Run `phantom init` first."))?;
    let config = PhantomConfig::load_from_bytes(&config_path, &config_before)
        .context("Failed to load .phantom.toml")?;
    if phantom_core::fs::read_regular_file(&config_path)
        .context("Failed to recheck .phantom.toml")?
        .as_deref()
        != Some(config_before.as_slice())
    {
        anyhow::bail!(".phantom.toml changed during team preflight; no team effect was attempted");
    }
    Ok((project_dir, config_path, config_before, config))
}

fn invitation_checklist(team_id: &str) -> String {
    format!(
        "Send your teammate this ordered checklist:\n\
         1. Install a checksum-verifiable release from https://github.com/ashlrai/phantom-secrets/releases/tag/v{}\n\
         2. Sign in: phantom login\n\
         3. Member publishes this device key: phantom team key-publish {team_id}\n\
         4. Owner/admin creates the member key share: phantom team vault-push {team_id}\n\
         5. Member pulls only after step 4 succeeds: phantom team vault-pull {team_id}\n\
         Access boundary: current team roles do not restrict shared-vault read/write access.\n\
         Offboarding boundary: removing a member does not revoke old ciphertext; rotate affected secrets after offboarding.",
        env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::{
        apply_team_vault_pull_transaction, confirm_team_effect, invitation_checklist,
        read_team_push_values, team_consent_plan, team_list_json,
    };
    use phantom_core::error::{PhantomError, Result as PhantomResult};
    use phantom_vault::{file::FileVault, VaultBackend};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;
    use zeroize::Zeroizing;

    /// `phantom team vault-push` sent an overdue enforced secret to every
    /// member. The push now refuses it before reading any value, as
    /// `phantom exec` would; an inventory inside its window is read.
    #[test]
    fn team_push_applies_rotation_enforcement() {
        use crate::commands::rotation_gate::fixtures::{aged_vault, enforced_config, NOW};
        let dir = tempfile::tempdir().unwrap();
        let vault = aged_vault(&dir, &[("STALE_KEY", 45), ("FRESH_KEY", 1)]);
        let config = enforced_config(&["STALE_KEY", "FRESH_KEY"]);
        let names = vault.list().unwrap();

        let refused = read_team_push_values(&config, &vault, &names, NOW);
        let message = refused
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(message.starts_with(
            "Refusing to push to the team vault: rotation enforcement blocked 1 secret(s)."
        ));

        let fresh = vec!["FRESH_KEY".to_string()];
        let read = read_team_push_values(&config, &vault, &fresh, NOW);
        assert!(read.is_ok_and(|values| values.len() == 1));
    }

    /// `phantom team vault-push` read every value with a plain retrieve, so a
    /// secret the expiry policy demoted to read-only was still handed to every
    /// team member. The whole push is now refused before any value is read,
    /// naming the entry only; a read-write inventory is still read.
    #[test]
    fn team_push_refuses_read_only_entries_before_any_value_read() {
        use phantom_vault::metadata::VaultMode;
        let dir = tempfile::tempdir().unwrap();
        let inner = phantom_vault::file::FileVault::new(
            &crate::test_support::canonical_tempdir_path(&dir),
            "team-read-only-fixture",
            format!("team-{}", std::process::id()),
        )
        .unwrap();
        for (entry, mode) in [
            ("DEMOTED_KEY", VaultMode::ReadOnly),
            ("ACTIVE_KEY", VaultMode::ReadWrite),
        ] {
            inner.store(entry, "fixture-value").unwrap();
            inner
                .set_metadata(
                    entry,
                    phantom_vault::SecretMetadata {
                        created_at: Some(1_800_000_000),
                        vault_mode: mode,
                        ..phantom_vault::SecretMetadata::default()
                    },
                )
                .unwrap();
        }
        let vault = CountingVault {
            inner,
            reads: AtomicUsize::new(0),
        };
        let config = unenforced();
        let names = vec!["ACTIVE_KEY".to_string(), "DEMOTED_KEY".to_string()];

        let refused = read_team_push_values(&config, &vault, &names, 1_800_000_000);
        assert!(refused.is_err());
        let message = refused
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(
            message.starts_with("Refusing to push to the team vault: 1 secret(s) are read-only")
        );
        assert!(message.contains("'DEMOTED_KEY'"));
        assert!(!message.contains("'ACTIVE_KEY'"));
        assert_eq!(vault.reads.load(Ordering::SeqCst), 0);

        let active = vec!["ACTIVE_KEY".to_string()];
        let read = read_team_push_values(&config, &vault, &active, 1_800_000_000);
        assert!(read.is_ok_and(|values| values.len() == 1));
    }

    /// Unreadable lifecycle metadata refuses the push too, before any value
    /// read.
    #[test]
    fn team_push_refuses_when_metadata_cannot_be_read() {
        let dir = tempfile::tempdir().unwrap();
        let inner = phantom_vault::file::FileVault::new(
            &crate::test_support::canonical_tempdir_path(&dir),
            "team-metadata-fixture",
            format!("team-meta-{}", std::process::id()),
        )
        .unwrap();
        inner.store("SOME_KEY", "fixture-value").unwrap();
        let vault = MetadataFailingVault {
            inner,
            reads: AtomicUsize::new(0),
        };
        let names = vec!["SOME_KEY".to_string()];
        let refused = read_team_push_values(&unenforced(), &vault, &names, 1_800_000_000);
        let message = refused
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default();
        assert!(message.starts_with(
            "Refusing to push to the team vault: could not read lifecycle metadata for 'SOME_KEY'"
        ));
        assert_eq!(vault.reads.load(Ordering::SeqCst), 0);
    }

    /// Counts value reads; everything else passes through.
    struct CountingVault {
        inner: phantom_vault::file::FileVault,
        reads: AtomicUsize,
    }

    impl VaultBackend for CountingVault {
        fn store(&self, name: &str, value: &str) -> PhantomResult<()> {
            self.inner.store(name, value)
        }
        fn retrieve(&self, name: &str) -> PhantomResult<Zeroizing<String>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.retrieve(name)
        }
        fn retrieve_for_injection(&self, name: &str) -> PhantomResult<Zeroizing<String>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.retrieve_for_injection(name)
        }
        fn delete(&self, name: &str) -> PhantomResult<()> {
            self.inner.delete(name)
        }
        fn list(&self) -> PhantomResult<Vec<String>> {
            self.inner.list()
        }
        fn backend_name(&self) -> &str {
            "counting"
        }
        fn get_metadata(&self, name: &str) -> PhantomResult<Option<phantom_vault::SecretMetadata>> {
            self.inner.get_metadata(name)
        }
    }

    /// Fails every metadata read and counts value reads.
    struct MetadataFailingVault {
        inner: phantom_vault::file::FileVault,
        reads: AtomicUsize,
    }

    impl VaultBackend for MetadataFailingVault {
        fn store(&self, name: &str, value: &str) -> PhantomResult<()> {
            self.inner.store(name, value)
        }
        fn retrieve(&self, name: &str) -> PhantomResult<Zeroizing<String>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.retrieve(name)
        }
        fn retrieve_for_injection(&self, name: &str) -> PhantomResult<Zeroizing<String>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.retrieve_for_injection(name)
        }
        fn delete(&self, name: &str) -> PhantomResult<()> {
            self.inner.delete(name)
        }
        fn list(&self) -> PhantomResult<Vec<String>> {
            self.inner.list()
        }
        fn backend_name(&self) -> &str {
            "metadata-failing"
        }
        fn get_metadata(&self, _: &str) -> PhantomResult<Option<phantom_vault::SecretMetadata>> {
            Err(phantom_core::error::PhantomError::VaultError(
                "metadata unavailable".to_string(),
            ))
        }
    }

    /// `phantom team vault-push` asked for trusted-terminal consent and only
    /// then refused a read-only entry or unreadable lifecycle metadata, so the
    /// user typed the confirmation for a push that could never run. The
    /// refusal now comes first, from names and metadata alone.
    #[test]
    fn team_push_refuses_read_only_entries_before_consent() {
        use crate::util::test_seam::{demoted_vault, SeamProject};
        let _project = SeamProject::new(demoted_vault);
        let refusal = super::run_vault_push("team-fixture")
            .map(|()| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(
            refusal.starts_with("Refusing to push to the team vault: 1 secret(s) are read-only")
        );
        assert!(refusal.contains("'DEMOTED_KEY'"));
    }

    #[test]
    fn team_push_refuses_unreadable_metadata_before_consent() {
        use crate::util::test_seam::{metadata_unreadable_vault, SeamProject};
        let _project = SeamProject::new(metadata_unreadable_vault);
        let refusal = super::run_vault_push("team-fixture")
            .map(|()| String::new())
            .unwrap_or_else(|error| error.to_string());
        assert!(refusal.starts_with("Refusing to push to the team vault:"));
        assert!(refusal.contains("'DEMOTED_KEY'"));
    }

    #[test]
    fn team_list_json_wraps_teams_with_name_and_role() {
        let teams = vec![phantom_core::teams::Team {
            id: "team-placeholder-id".to_string(),
            name: "placeholder-team".to_string(),
            role: "admin".to_string(),
        }];
        let report = team_list_json(&teams);
        assert_eq!(report["teams"][0]["name"], "placeholder-team");
        assert_eq!(report["teams"][0]["role"], "admin");
        assert_eq!(report["teams"][0]["id"], "team-placeholder-id");
        assert_eq!(team_list_json(&[])["teams"], serde_json::json!([]));
    }

    struct FaultVault {
        inner: FileVault,
        cas_calls: AtomicUsize,
        fail_cas: Option<usize>,
        fail_retrieve: Option<String>,
    }

    impl VaultBackend for FaultVault {
        fn store(&self, name: &str, value: &str) -> PhantomResult<()> {
            self.inner.store(name, value)
        }

        fn retrieve(&self, name: &str) -> PhantomResult<Zeroizing<String>> {
            if self.fail_retrieve.as_deref() == Some(name) {
                return Err(PhantomError::VaultError(
                    "injected team-pull preflight read failure".to_string(),
                ));
            }
            self.inner.retrieve(name)
        }

        fn delete(&self, name: &str) -> PhantomResult<()> {
            self.inner.delete(name)
        }

        fn compare_and_swap(
            &self,
            name: &str,
            expected: Option<&str>,
            replacement: Option<&str>,
        ) -> PhantomResult<bool> {
            let call = self.cas_calls.fetch_add(1, Ordering::SeqCst) + 1;
            if self.fail_cas == Some(call) {
                return Err(PhantomError::VaultError(
                    "injected team-pull CAS failure".to_string(),
                ));
            }
            self.inner.compare_and_swap(name, expected, replacement)
        }

        fn list(&self) -> PhantomResult<Vec<String>> {
            self.inner.list()
        }

        fn backend_name(&self) -> &str {
            "team-pull-fault"
        }
    }

    fn fault_vault(
        dir: &TempDir,
        fail_cas: Option<usize>,
        fail_retrieve: Option<&str>,
    ) -> FaultVault {
        FaultVault {
            inner: FileVault::new(
                &crate::test_support::canonical_tempdir_path(dir),
                "team-pull",
                "passphrase".to_string(),
            )
            .unwrap(),
            cas_calls: AtomicUsize::new(0),
            fail_cas,
            fail_retrieve: fail_retrieve.map(str::to_string),
        }
    }

    fn remote(values: &[(&str, &str)]) -> BTreeMap<String, Zeroizing<String>> {
        values
            .iter()
            .map(|(name, value)| ((*name).to_string(), Zeroizing::new((*value).to_string())))
            .collect()
    }

    fn unenforced() -> phantom_core::config::PhantomConfig {
        phantom_core::config::PhantomConfig::new_with_defaults("team-pull".to_string())
    }

    /// A team-pulled value carries no rotation anchor: a new entry was stamped
    /// as stored now and an overwrite kept the local anchor, so an overdue
    /// value pushed by a teammate came back looking fresh. Every enforced
    /// write is refused before any vault or config write.
    #[test]
    fn team_pull_refuses_to_write_an_enforced_secret_of_unknown_age() {
        use crate::commands::rotation_gate::fixtures::enforced_config;
        let project = TempDir::new().unwrap();
        let vault = fault_vault(&project, None, None);
        vault.store("EXISTING_KEY", "local-owner").unwrap();
        let config = enforced_config(&["NEW_KEY", "EXISTING_KEY"]);

        let refused = apply_team_vault_pull_transaction(
            project.path(),
            &config,
            &vault,
            &remote(&[
                ("EXISTING_KEY", "remote-existing"),
                ("NEW_KEY", "remote-new"),
            ]),
            Vec::new(),
        );
        let message = refused
            .err()
            .map(|error| format!("{error:#}"))
            .unwrap_or_default();
        assert!(message.starts_with(
            "Refusing to pull the team vault: rotation enforcement blocked 2 secret(s)."
        ));
        assert!(matches!(
            vault.retrieve("NEW_KEY"),
            Err(PhantomError::SecretNotFound(_))
        ));
        assert!(vault.retrieve("EXISTING_KEY").unwrap().as_str() == "local-owner");
        assert_eq!(vault.cas_calls.load(Ordering::SeqCst), 0);
    }

    /// Only changed values are gated: an identical enforced value keeps its
    /// anchor and an unenforced new value still lands.
    #[test]
    fn team_pull_lets_identical_and_unenforced_entries_through() {
        use crate::commands::rotation_gate::fixtures::enforced_config;
        let project = TempDir::new().unwrap();
        let vault = fault_vault(&project, None, None);
        let shared = ["same", "on", "both", "sides"].join("-");
        vault.store("EXISTING_KEY", &shared).unwrap();
        let config = enforced_config(&["EXISTING_KEY"]);

        let written = apply_team_vault_pull_transaction(
            project.path(),
            &config,
            &vault,
            &remote(&[
                ("EXISTING_KEY", shared.as_str()),
                ("PLAIN_KEY", "remote-plain"),
            ]),
            Vec::new(),
        );
        assert!(written.is_ok());
        assert_eq!(
            vault.retrieve("PLAIN_KEY").unwrap().as_str(),
            "remote-plain"
        );
    }

    #[test]
    fn team_revoke_fails_before_auth_or_network_access() {
        let error = super::run_revoke("team-test", "member-test", true).unwrap_err();
        assert!(error.to_string().contains("atomic membership-removal"));
    }

    #[test]
    fn team_pull_rolls_back_first_write_when_second_cas_fails() {
        let project = TempDir::new().unwrap();
        let vault = fault_vault(&project, Some(2), None);
        vault.store("A", "old-a").unwrap();
        vault.store("B", "old-b").unwrap();

        let error = apply_team_vault_pull_transaction(
            project.path(),
            &unenforced(),
            &vault,
            &remote(&[("A", "new-a"), ("B", "new-b")]),
            Vec::new(),
        )
        .expect_err("second CAS must fail the whole pull");

        assert!(error.to_string().contains("rolled back"));
        assert_eq!(vault.retrieve("A").unwrap().as_str(), "old-a");
        assert_eq!(vault.retrieve("B").unwrap().as_str(), "old-b");
    }

    #[test]
    fn team_pull_preflight_read_failure_writes_nothing() {
        let project = TempDir::new().unwrap();
        let vault = fault_vault(&project, None, Some("B"));
        vault.store("A", "old-a").unwrap();
        vault.store("B", "old-b").unwrap();

        let error = apply_team_vault_pull_transaction(
            project.path(),
            &unenforced(),
            &vault,
            &remote(&[("A", "new-a"), ("B", "new-b")]),
            Vec::new(),
        )
        .expect_err("preflight read failure must abort");

        assert!(error.to_string().contains("before any local write"));
        assert_eq!(vault.retrieve("A").unwrap().as_str(), "old-a");
        assert_eq!(vault.inner.retrieve("B").unwrap().as_str(), "old-b");
        assert_eq!(vault.cas_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn team_pull_config_drift_blocks_every_vault_write() {
        let project = TempDir::new().unwrap();
        let config_path = project.path().join(".phantom.toml");
        let before = b"project = 'reviewed'\n".to_vec();
        let concurrent = b"project = 'concurrent'\n".to_vec();
        std::fs::write(&config_path, &concurrent).unwrap();
        let vault = fault_vault(&project, None, None);

        let error = apply_team_vault_pull_transaction(
            project.path(),
            &unenforced(),
            &vault,
            &remote(&[("A", "new-a")]),
            vec![phantom_vault::InitFile::replace_if_unchanged(
                &config_path,
                Some(before),
                b"project = 'reviewed'\n".to_vec(),
            )],
        )
        .unwrap_err();

        assert!(error.to_string().contains("rolled back"));
        assert_eq!(std::fs::read(&config_path).unwrap(), concurrent);
        assert!(matches!(
            vault.retrieve("A"),
            Err(PhantomError::SecretNotFound(_))
        ));
        assert_eq!(vault.cas_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn invitation_guidance_is_reviewed_and_orders_key_share_before_pull() {
        let guide = invitation_checklist("team-test");
        let publish = guide.find("phantom team key-publish team-test").unwrap();
        let push = guide.find("phantom team vault-push team-test").unwrap();
        let pull = guide.find("phantom team vault-pull team-test").unwrap();
        assert!(publish < push && push < pull);
        assert!(guide.contains("releases/tag/v"));
        assert!(guide.contains("roles do not restrict shared-vault read/write access"));
        assert!(guide.contains("rotate affected secrets after offboarding"));
        assert!(!guide.contains("curl"));
        assert!(!guide.contains("cargo install"));
        assert!(!guide.contains("npm install"));
        assert!(!guide.contains("npx "));
    }

    #[test]
    fn team_consent_challenge_is_exact_and_control_safe() {
        let plan = team_consent_plan(
            "invite",
            &["team-id", "octocat", "member"],
            "add one member",
        )
        .unwrap();
        assert_eq!(
            plan.challenge,
            "team invite \"team-id\" \"octocat\" \"member\""
        );
        assert!(team_consent_plan("invite", &["team\nspoof"], "effect").is_err());
    }

    #[test]
    fn headless_team_consent_fails_before_reading_confirmation() {
        let plan = team_consent_plan("vault-push", &["team-id", "project-id"], "effect").unwrap();
        let mut reader = std::io::Cursor::new(plan.challenge.as_bytes());
        let mut output = Vec::new();

        let error = confirm_team_effect(&plan, false, &mut reader, &mut output).unwrap_err();
        assert!(error.to_string().contains("trusted terminal"));
        assert_eq!(reader.position(), 0);
        assert!(output.is_empty());
    }
}

#[cfg(all(test, unix))]
mod locked_vault_tests {
    use crate::util::test_seam::{empty_keychain, keychain_with_one, LockedProject};

    /// Entered after consent, the bearer and the team keypair, as
    /// `run_vault_push` does. The stub keychain panics on any value read, and
    /// the API base is unroutable, so a refusal here comes before any
    /// retrieve or network call.
    fn push(project: &LockedProject) -> String {
        let config =
            phantom_core::config::PhantomConfig::load(&project.dir.join(".phantom.toml")).unwrap();
        let kp = phantom_core::team_crypto::MemberKeypair::generate();
        super::vault_push_after_consent(
            "team-fixture",
            config.portable_project_id(),
            &config,
            "unused-bearer",
            "http://127.0.0.1:9",
            &kp,
        )
        .unwrap_err()
        .to_string()
    }

    /// A keychain-only view would overwrite the shared vault with a partial
    /// set.
    #[test]
    fn team_vault_push_refuses_a_partial_inventory_before_any_read_or_send() {
        let project = LockedProject::new(keychain_with_one);
        let error = push(&project);
        assert!(
            error.starts_with("Refusing to push to the team vault from a partial inventory"),
            "{error}"
        );
    }

    /// An empty keychain beside a locked file vault was "No secrets to push".
    #[test]
    fn team_vault_push_refuses_a_locked_file_vault() {
        let project = LockedProject::new(empty_keychain);
        let error = push(&project);
        assert!(error.starts_with("Vault locked:"), "{error}");
    }

    /// Entered as the CLI does, before consent. Tests run without a trusted
    /// terminal, so a run that reached the consent prompt fails there instead.
    fn run_push_refusal() -> String {
        super::run_vault_push("team-fixture")
            .unwrap_err()
            .to_string()
    }

    /// A locked file vault was refused only after typed consent was spent.
    #[test]
    fn team_vault_push_refuses_a_locked_file_vault_before_consent() {
        let _project = LockedProject::new(empty_keychain);
        let refusal = run_push_refusal();
        assert!(
            refusal.starts_with("Vault locked:"),
            "team vault-push reached consent before refusing the locked vault"
        );
    }

    /// A keychain-only view beside a locked file vault was refused only after
    /// typed consent was spent.
    #[test]
    fn team_vault_push_refuses_a_partial_inventory_before_consent() {
        let _project = LockedProject::new(keychain_with_one);
        let refusal = run_push_refusal();
        assert!(
            refusal.starts_with("Refusing to push to the team vault from a partial inventory"),
            "team vault-push reached consent before refusing the partial inventory"
        );
    }

    /// Entered as `run_vault_pull` does, before consent. The stub keychain
    /// panics on any value read.
    fn pull_destination(project: &LockedProject) -> Option<String> {
        let config =
            phantom_core::config::PhantomConfig::load(&project.dir.join(".phantom.toml")).unwrap();
        super::team_vault_pull_destination(&config)
            .err()
            .map(|error| error.to_string())
    }

    /// A keychain-only view would take every pulled entry beside the locked
    /// file vault, with before-images from the keychain alone.
    #[test]
    fn team_vault_pull_refuses_a_partial_destination_inventory() {
        let project = LockedProject::new(keychain_with_one);
        let refusal = pull_destination(&project).unwrap_or_default();
        assert!(
            refusal.starts_with("Refusing to reconcile a team vault pull from a partial inventory")
        );
    }

    /// An empty keychain beside a locked file vault would read as a fresh
    /// destination and receive the whole shared vault.
    #[test]
    fn team_vault_pull_refuses_a_locked_file_vault() {
        let project = LockedProject::new(empty_keychain);
        let refusal = pull_destination(&project).unwrap_or_default();
        assert!(refusal.starts_with("Vault locked:"));
    }

    #[test]
    fn team_vault_pull_judges_the_destination_before_consent() {
        let source = include_str!("team.rs");
        let destination = source
            .find("let vault = team_vault_pull_destination(&config)?;")
            .expect("vault-pull must judge its destination inventory");
        let consent = source
            .find("\"vault-pull\",")
            .expect("vault-pull must require terminal consent");
        let network = source
            .find("teams_vault::pull_for_project(")
            .expect("vault-pull must fetch the shared vault");
        assert!(destination < consent);
        assert!(consent < network);
    }
}
