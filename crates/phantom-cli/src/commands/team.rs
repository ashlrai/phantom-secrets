use anyhow::{Context, Result};
use colored::Colorize;
use phantom_core::{auth, config::PhantomConfig, teams, teams_vault};
use std::collections::BTreeMap;
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

pub fn run_list() -> Result<()> {
    require_trusted_terminal_team(&team_consent_plan(
        "list",
        &[],
        "read the stored Phantom bearer and send an authenticated request for the caller's remote team list",
    )?)?;
    let token = Zeroizing::new(auth::require_token()?);
    let api_base = auth::api_base_url()?;

    let rt = tokio::runtime::Runtime::new()?;
    let team_list = rt.block_on(teams::list_teams(&api_base, &token))?;

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

    let rt = tokio::runtime::Runtime::new()?;
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

    let rt = tokio::runtime::Runtime::new()?;
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
    let rt = tokio::runtime::Runtime::new()?;
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
    require_trusted_terminal_team(&team_consent_plan(
        "vault-push",
        &[team_id, &project_id, &project_path],
        "retrieve every local vault value, encrypt it to registered team members, and overwrite the remote shared vault",
    )?)?;
    let token = Zeroizing::new(auth::require_token()?);
    let api_base = auth::api_base_url()?;
    let kp = auth::get_or_create_team_keypair()?;
    let rt = tokio::runtime::Runtime::new()?;

    // Read the local vault into a Zeroizing-valued map so the secret
    // bytes are scrubbed when the helper drops them.
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let secret_names = vault.list()?;
    if secret_names.is_empty() {
        println!("{}  No secrets to push", "warn".yellow().bold());
        return Ok(());
    }
    let mut secrets: BTreeMap<String, Zeroizing<String>> = BTreeMap::new();
    for name in &secret_names {
        let value = vault.retrieve(name)?; // Zeroizing<String>
        secrets.insert(name.clone(), Zeroizing::new(String::from(value.as_str())));
    }

    let outcome = rt
        .block_on(teams_vault::push_for_project(
            &api_base,
            &token,
            team_id,
            &project_id,
            secrets,
            &kp,
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
    let rt = tokio::runtime::Runtime::new()?;

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
    let vault = phantom_vault::try_create_vault(config.local_project_id())?;
    let written = apply_team_vault_pull_transaction(
        &project_dir,
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

fn apply_team_vault_pull_transaction(
    project_dir: &std::path::Path,
    vault: &dyn phantom_vault::VaultBackend,
    secrets: &BTreeMap<String, Zeroizing<String>>,
    files: Vec<phantom_vault::InitFile>,
) -> Result<usize> {
    let mut mutations = Vec::with_capacity(secrets.len());
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
        mutations.push(phantom_vault::InitSecret::replace_if_unchanged(
            name,
            before.as_ref().map(|value| value.as_str().to_string()),
            value.as_str(),
        ));
    }
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

    let rt = tokio::runtime::Runtime::new()?;
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

    let rt = tokio::runtime::Runtime::new()?;
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
    let project_dir = std::env::current_dir()?.canonicalize()?;
    let config_path = project_dir.join(".phantom.toml");
    let config_before = phantom_core::fs::read_regular_file(&config_path)
        .context("Failed to safely read .phantom.toml")?
        .ok_or_else(|| anyhow::anyhow!("No .phantom.toml found. Run `phantom init` first."))?;
    let config = PhantomConfig::load(&config_path).context("Failed to load .phantom.toml")?;
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
        team_consent_plan,
    };
    use phantom_core::error::{PhantomError, Result as PhantomResult};
    use phantom_vault::{file::FileVault, VaultBackend};
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;
    use zeroize::Zeroizing;

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
            inner: FileVault::new(dir.path(), "team-pull", "passphrase".to_string()).unwrap(),
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
