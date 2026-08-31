use anyhow::{bail, Context, Result};
use colored::Colorize;
use phantom_core::config::PhantomConfig;
use phantom_core::dotenv::DotenvFile;
use phantom_core::token::TokenMap;
use phantom_core::workspace_request::{
    self, SanitizedActionSummary, WorkspaceActionKind, WorkspaceApplyReceipt, WorkspaceRequestState,
};
use phantom_vault::{SecretMetadata, VaultBackend};
use phantom_workspace::{
    apply_setup_plan_durable, build_sealed_setup_plan, clear_setup_plan_journal,
    recover_setup_plan_journal, DurableJournalConfig, JournalRecovery, ParticipantError,
    ParticipantFileMutation, ParticipantPreparation, PlanSealKey, SealedSetupPlan, SetupAction,
    SetupActionKind, SetupPlan, SetupTransactionParticipant,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize)]
struct PlanOutput<'a> {
    request_id: &'a str,
    plan_id: &'a str,
    pre_state_id: &'a str,
    actions: Vec<ActionOutput<'a>>,
    blockers: &'a [String],
}

#[derive(Serialize)]
struct ActionOutput<'a> {
    id: &'a str,
    kind: SetupActionKind,
    target: &'a str,
    key_names: &'a [String],
}

pub fn run_plan(json: bool) -> Result<()> {
    let workspace = std::env::current_dir().context("Could not resolve the current workspace")?;
    let key_bytes = workspace_request::load_or_create_workspace_plan_key()
        .context("Could not load the local workspace plan key")?;
    let seal_key = PlanSealKey::from_bytes(*key_bytes);
    let sealed = build_sealed_setup_plan(&workspace, &seal_key)
        .context("Could not build the exact workspace setup plan")?;
    let request_id = workspace_request::create_request(
        &workspace,
        &sealed.plan.plan_id,
        &sealed.pre_state_id,
        action_summary(&sealed.plan),
    )
    .context("Could not create the pending workspace request")?;
    print_plan(&request_id, &sealed, json)
}

pub fn run_status(request_id: &str, json: bool) -> Result<()> {
    let status = workspace_request::get_status(request_id)
        .context("Could not read the workspace request")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        println!("Workspace request {}", status.request_id.bold());
        println!("  State:       {:?}", status.state);
        println!("  Plan:        {}", status.plan_id);
        println!("  Pre-state:   {}", status.pre_state_id);
        println!("  Actions:     {}", status.action_summary.action_count);
        println!("  Kinds:       {:?}", status.action_summary.kinds);
        println!("  Expires at:  {}", status.expires_at);
        if let Some(deadline) = status.execution_deadline {
            println!("  Execution deadline: {deadline}");
        }
        if let Some(outcome) = status.execution_outcome {
            println!("  Execution outcome:  {outcome:?}");
        }
        if status
            .action_summary
            .kinds
            .contains(&WorkspaceActionKind::ReviewPlaceBinding)
        {
            println!(
                "  Note:        Applied does not imply an active Locus place; authority review remains separate."
            );
        }
    }
    Ok(())
}

pub fn run_apply(request_id: &str) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        bail!(
            "workspace apply requires both stdin and stderr to be attached to a trusted terminal"
        );
    }

    let workspace = std::env::current_dir().context("Could not resolve the current workspace")?;
    let status = workspace_request::get_status(request_id)
        .context("Could not read the workspace request")?;
    if status.workspace_scope_hash != workspace_request::workspace_scope_hash(&workspace)? {
        bail!("workspace request belongs to a different workspace");
    }
    if status.state == WorkspaceRequestState::Applied {
        println!(
            "{} Workspace request {} is already applied",
            "ok".green().bold(),
            request_id
        );
        return Ok(());
    }
    if !matches!(
        status.state,
        WorkspaceRequestState::Pending | WorkspaceRequestState::Claimed
    ) {
        bail!(
            "workspace request is already terminal in state {:?}",
            status.state
        );
    }

    let (journal_path, journal_key) =
        workspace_request::load_or_create_workspace_journal(request_id)
            .context("Could not load the local workspace recovery journal key")?;
    let journal = DurableJournalConfig::new(request_id, journal_path, *journal_key);
    let mut participant = VaultSetupParticipant::new(&workspace)?;
    match recover_setup_plan_journal(
        &workspace,
        &status.plan_id,
        &status.pre_state_id,
        &mut participant,
        &journal,
    )
    .context("Could not recover the prior workspace transaction")?
    {
        JournalRecovery::Applied(receipt) => {
            persist_applied_request(request_id, &workspace, &status, &receipt)?;
            clear_setup_plan_journal(&journal).context(
                "Applied receipt persisted, but encrypted recovery journal cleanup failed",
            )?;
            println!(
                "{} Recovered applied workspace request {}",
                "ok".green().bold(),
                request_id
            );
            return Ok(());
        }
        JournalRecovery::RolledBack => {
            if status.state == WorkspaceRequestState::Claimed {
                workspace_request::rollback_request(
                    request_id,
                    &workspace,
                    &status.plan_id,
                    &status.pre_state_id,
                )?;
            }
            clear_setup_plan_journal(&journal)?;
            bail!("recovered and rolled back an interrupted workspace transaction; create a fresh plan before applying again");
        }
        JournalRecovery::Absent => {}
    }

    let key_bytes = workspace_request::load_or_create_workspace_plan_key()
        .context("Could not load the local workspace plan key")?;
    let seal_key = PlanSealKey::from_bytes(*key_bytes);
    let sealed = build_sealed_setup_plan(&workspace, &seal_key)
        .context("Could not rebuild the exact workspace setup plan")?;
    if sealed.plan.plan_id != status.plan_id || sealed.pre_state_id != status.pre_state_id {
        bail!("workspace changed after this request was created; create a fresh plan");
    }
    print_confirmation(&sealed.plan, request_id)?;

    let mut input = std::io::BufReader::new(std::io::stdin().lock());
    let mut confirmation = String::new();
    input
        .read_line(&mut confirmation)
        .context("Could not read typed workspace confirmation")?;
    if confirmation.trim() != format!("apply {request_id}") {
        bail!("workspace apply cancelled: typed confirmation did not match");
    }

    if status.state == WorkspaceRequestState::Pending {
        workspace_request::claim_exact(
            request_id,
            &workspace,
            &sealed.plan.plan_id,
            &sealed.pre_state_id,
        )
        .context("Workspace request did not match this exact plan and pre-state")?;
    }

    match apply_setup_plan_durable(&sealed, &seal_key, &mut participant, &journal) {
        Ok(transaction) => {
            persist_applied_request(request_id, &workspace, &status, &transaction.receipt)
                .context("Workspace was applied and journaled, but request completion failed; rerun apply to recover")?;
            clear_setup_plan_journal(&journal).context(
                "Request completion persisted, but encrypted recovery journal cleanup failed",
            )?;
            let deferred = transaction
                .receipt
                .actions
                .iter()
                .filter(|outcome| outcome.state == phantom_workspace::ActionOutcomeState::Deferred)
                .count();
            if transaction.receipt.fully_applied {
                println!(
                    "{} Applied workspace request {} ({} file change(s))",
                    "ok".green().bold(),
                    request_id,
                    transaction.receipt.file_changes.len()
                );
            } else {
                println!(
                    "{} Applied the local workspace portion of request {} ({} file change(s)); {} authority-dependent action(s) remain deferred",
                    "ok".green().bold(),
                    request_id,
                    transaction.receipt.file_changes.len(),
                    deferred
                );
            }
            Ok(())
        }
        Err(error) => {
            match recover_setup_plan_journal(
                &workspace,
                &status.plan_id,
                &status.pre_state_id,
                &mut participant,
                &journal,
            ) {
                Ok(JournalRecovery::RolledBack) => {
                    workspace_request::rollback_request(
                        request_id,
                        &workspace,
                        &status.plan_id,
                        &status.pre_state_id,
                    )?;
                    clear_setup_plan_journal(&journal)?;
                    Err(error).context("Workspace setup failed and was durably rolled back")
                }
                Ok(JournalRecovery::Applied(receipt)) => {
                    persist_applied_request(request_id, &workspace, &status, &receipt)?;
                    clear_setup_plan_journal(&journal)?;
                    Ok(())
                }
                Ok(JournalRecovery::Absent) => {
                    workspace_request::rollback_request(
                        request_id,
                        &workspace,
                        &status.plan_id,
                        &status.pre_state_id,
                    )?;
                    Err(error).context("Workspace setup failed before any journaled mutation")
                }
                Err(recovery_error) => Err(recovery_error).context(
                    "Workspace setup was interrupted and requires recovery; request remains claimed",
                ),
            }
        }
    }
}

fn persist_applied_request(
    request_id: &str,
    workspace: &Path,
    status: &workspace_request::WorkspaceRequestStatus,
    receipt: &phantom_workspace::SetupTransactionReceipt,
) -> Result<()> {
    let recorded_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    workspace_request::complete_request_with_receipt(
        request_id,
        workspace,
        &status.plan_id,
        &status.pre_state_id,
        WorkspaceApplyReceipt {
            receipt_digest: receipt.digest_hex()?,
            file_change_count: u32::try_from(receipt.file_changes.len()).unwrap_or(u32::MAX),
            fully_applied: receipt.fully_applied,
            recorded_at,
        },
    )?;
    Ok(())
}

fn print_plan(request_id: &str, sealed: &SealedSetupPlan, json: bool) -> Result<()> {
    let actions = sealed
        .plan
        .actions
        .iter()
        .map(|action| ActionOutput {
            id: &action.id,
            kind: action.kind,
            target: &action.target,
            key_names: &action.key_names,
        })
        .collect();
    let output = PlanOutput {
        request_id,
        plan_id: &sealed.plan.plan_id,
        pre_state_id: &sealed.pre_state_id,
        actions,
        blockers: &sealed.plan.blockers,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    println!("Workspace setup request {}", request_id.bold());
    println!("  Plan:      {}", sealed.plan.plan_id);
    println!("  Pre-state: {}", sealed.pre_state_id);
    print_actions_to(&sealed.plan, &mut std::io::stdout().lock())?;
    println!("\nApply from a trusted terminal:");
    println!("  phantom workspace apply --request {request_id}");
    Ok(())
}

fn print_confirmation(plan: &SetupPlan, request_id: &str) -> Result<()> {
    let mut stderr = std::io::stderr().lock();
    writeln!(stderr, "Exact workspace setup plan:")?;
    print_actions_to(plan, &mut stderr)?;
    writeln!(stderr)?;
    writeln!(
        stderr,
        "Type apply {request_id} to claim and apply this exact request:"
    )?;
    write!(stderr, "> ")?;
    stderr.flush()?;
    Ok(())
}

fn print_actions_to(plan: &SetupPlan, output: &mut impl Write) -> Result<()> {
    for action in &plan.actions {
        let names = if action.key_names.is_empty() {
            String::new()
        } else {
            format!(" [{}]", action.key_names.join(", "))
        };
        writeln!(output, "  - {:?}: {}{names}", action.kind, action.target)?;
    }
    if !plan.blockers.is_empty() {
        writeln!(output, "  Blockers:")?;
        for blocker in &plan.blockers {
            writeln!(output, "    - {blocker}")?;
        }
    }
    Ok(())
}

fn action_summary(plan: &SetupPlan) -> SanitizedActionSummary {
    SanitizedActionSummary::new(plan.actions.iter().map(|action| match action.kind {
        SetupActionKind::InitializeWorkspace => WorkspaceActionKind::InitializeWorkspace,
        SetupActionKind::ProtectEnvFile => WorkspaceActionKind::ProtectEnvironment,
        SetupActionKind::EnsureEnvIgnoreRules => WorkspaceActionKind::UpdateIgnoreRules,
        SetupActionKind::GenerateEnvExample => WorkspaceActionKind::GenerateEnvironmentExample,
        SetupActionKind::InstallPreCommitCheck => WorkspaceActionKind::InstallPreCommitCheck,
        SetupActionKind::ReviewPlaceBinding => WorkspaceActionKind::ReviewPlaceBinding,
    }))
}

struct VaultSnapshot {
    name: String,
    value: Option<Zeroizing<String>>,
    metadata: Option<SecretMetadata>,
}

#[derive(Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultRecoverySnapshot {
    name: String,
    value: Option<String>,
    metadata: Option<SecretMetadata>,
}

struct VaultSetupParticipant {
    workspace_root: PathBuf,
    vault: Box<dyn VaultBackend>,
    snapshots: Vec<VaultSnapshot>,
    staged_values: BTreeMap<String, Zeroizing<String>>,
    commit_started: bool,
    #[cfg(test)]
    fail_commit: bool,
}

impl VaultSetupParticipant {
    fn new(workspace_root: &Path) -> Result<Self> {
        let config_path = workspace_root.join(".phantom.toml");
        let project_id = if config_path.exists() {
            let metadata = std::fs::symlink_metadata(&config_path)
                .context("Existing .phantom.toml could not be inspected safely")?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("existing .phantom.toml is not a regular file");
            }
            PhantomConfig::load(&config_path)
                .context("Existing .phantom.toml could not be loaded safely")?
                .phantom
                .project_id
        } else {
            PhantomConfig::project_id_from_path(workspace_root)
        };
        Ok(Self {
            workspace_root: workspace_root.to_path_buf(),
            vault: phantom_vault::create_vault(&project_id),
            snapshots: Vec::new(),
            staged_values: BTreeMap::new(),
            commit_started: false,
            #[cfg(test)]
            fail_commit: false,
        })
    }

    #[cfg(test)]
    fn with_vault(workspace_root: &Path, vault: Box<dyn VaultBackend>, fail_commit: bool) -> Self {
        Self {
            workspace_root: workspace_root.to_path_buf(),
            vault,
            snapshots: Vec::new(),
            staged_values: BTreeMap::new(),
            commit_started: false,
            fail_commit,
        }
    }

    fn approved_path(&self, target: &str) -> std::result::Result<PathBuf, ParticipantError> {
        let relative = Path::new(target);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(ParticipantError::new("invalid_approved_env_path"));
        }
        Ok(self.workspace_root.join(relative))
    }

    fn restore_snapshots(&mut self) -> std::result::Result<(), ParticipantError> {
        if !self.commit_started {
            self.snapshots.clear();
            self.staged_values.clear();
            return Ok(());
        }
        let mut failed = false;
        for snapshot in self.snapshots.drain(..).rev() {
            let result = match snapshot.value {
                Some(value) => {
                    let stored = self.vault.store(&snapshot.name, value.as_str());
                    if stored.is_ok() {
                        match snapshot.metadata {
                            Some(metadata) => self.vault.set_metadata(&snapshot.name, metadata),
                            None => Ok(()),
                        }
                    } else {
                        stored
                    }
                }
                None => match self.vault.exists(&snapshot.name) {
                    Ok(true) => self.vault.delete(&snapshot.name),
                    Ok(false) => Ok(()),
                    Err(error) => Err(error),
                },
            };
            if result.is_err() {
                failed = true;
            }
        }
        if failed {
            Err(ParticipantError::new("vault_rollback_failed"))
        } else {
            self.commit_started = false;
            self.staged_values.clear();
            Ok(())
        }
    }
}

impl SetupTransactionParticipant for VaultSetupParticipant {
    fn prepare(
        &mut self,
        _plan: &SetupPlan,
        external_actions: &[SetupAction],
    ) -> std::result::Result<ParticipantPreparation, ParticipantError> {
        if !self.snapshots.is_empty() {
            return Err(ParticipantError::new("vault_participant_reused"));
        }

        let protect_actions = external_actions
            .iter()
            .filter(|action| action.kind == SetupActionKind::ProtectEnvFile)
            .collect::<Vec<_>>();
        let mut parsed = Vec::with_capacity(protect_actions.len());
        let mut values = BTreeMap::<String, Zeroizing<String>>::new();
        for action in &protect_actions {
            let path = self.approved_path(&action.target)?;
            let dotenv = DotenvFile::parse_file(&path)
                .map_err(|_| ParticipantError::new("approved_env_parse_failed"))?;
            let approved_names = action.key_names.iter().collect::<BTreeSet<_>>();
            let mut found = BTreeSet::new();
            for entry in dotenv.entries() {
                if !approved_names.contains(&entry.key) {
                    continue;
                }
                if entry.is_phantom {
                    return Err(ParticipantError::new("approved_env_already_tokenized"));
                }
                found.insert(entry.key.clone());
                match values.get(&entry.key) {
                    Some(existing) if existing.as_str() != entry.value => {
                        return Err(ParticipantError::new("divergent_secret_values"));
                    }
                    Some(_) => {}
                    None => {
                        values.insert(entry.key.clone(), Zeroizing::new(entry.value.clone()));
                    }
                }
            }
            if found.len() != approved_names.len() {
                return Err(ParticipantError::new("approved_secret_missing"));
            }
            parsed.push((action, dotenv));
        }

        let mut snapshots = Vec::with_capacity(values.len());
        for name in values.keys() {
            let existed = self
                .vault
                .exists(name)
                .map_err(|_| ParticipantError::new("vault_snapshot_failed"))?;
            snapshots.push(VaultSnapshot {
                name: name.clone(),
                value: if existed {
                    Some(
                        self.vault
                            .retrieve(name)
                            .map_err(|_| ParticipantError::new("vault_snapshot_failed"))?,
                    )
                } else {
                    None
                },
                metadata: self
                    .vault
                    .get_metadata(name)
                    .map_err(|_| ParticipantError::new("vault_snapshot_failed"))?,
            });
        }
        let mut token_map = TokenMap::new();
        for name in values.keys() {
            token_map.insert(name.clone());
        }
        let mut mutations = Vec::with_capacity(parsed.len());
        for (action, dotenv) in parsed {
            let (content, mut originals) = dotenv.rewrite_with_phantoms(&token_map);
            for value in originals.values_mut() {
                value.zeroize();
            }
            originals.clear();
            mutations.push(ParticipantFileMutation::replace(
                action.target.clone(),
                content.into_bytes(),
            ));
        }
        self.snapshots = snapshots;
        self.staged_values = values;

        Ok(ParticipantPreparation::new(
            protect_actions.iter().map(|action| action.id.clone()),
            mutations,
        ))
    }

    fn commit(&mut self) -> std::result::Result<(), ParticipantError> {
        self.commit_started = true;
        for (name, value) in &self.staged_values {
            self.vault
                .store(name, value.as_str())
                .map_err(|_| ParticipantError::new("vault_store_failed"))?;
        }
        #[cfg(test)]
        if self.fail_commit {
            return Err(ParticipantError::new("injected_vault_commit_failure"));
        }
        self.snapshots.clear();
        self.staged_values.clear();
        self.commit_started = false;
        Ok(())
    }

    fn rollback(&mut self) -> std::result::Result<(), ParticipantError> {
        self.restore_snapshots()
    }

    fn recovery_payload(&self) -> std::result::Result<Vec<u8>, ParticipantError> {
        let snapshots = self
            .snapshots
            .iter()
            .map(|snapshot| VaultRecoverySnapshot {
                name: snapshot.name.clone(),
                value: snapshot
                    .value
                    .as_ref()
                    .map(|value| value.as_str().to_string()),
                metadata: snapshot.metadata.clone(),
            })
            .collect::<Vec<_>>();
        serde_json::to_vec(&snapshots)
            .map_err(|_| ParticipantError::new("vault_recovery_serialize_failed"))
    }

    fn restore_recovery_payload(
        &mut self,
        payload: &[u8],
    ) -> std::result::Result<(), ParticipantError> {
        let snapshots: Vec<VaultRecoverySnapshot> = serde_json::from_slice(payload)
            .map_err(|_| ParticipantError::new("vault_recovery_parse_failed"))?;
        self.snapshots = snapshots
            .into_iter()
            .map(|snapshot| VaultSnapshot {
                name: snapshot.name,
                value: snapshot.value.map(Zeroizing::new),
                metadata: snapshot.metadata,
            })
            .collect();
        self.commit_started = true;
        Ok(())
    }
}

// These exercise the CLI participant inside descriptor-relative workspace
// transactions. The transaction engine intentionally fails closed before
// participant preparation on platforms without the required Unix filesystem
// primitives; that cross-platform contract is covered in phantom-workspace.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use phantom_core::error::{PhantomError, Result as PhantomResult};
    use phantom_vault::file::FileVault;
    use phantom_workspace::{apply_setup_plan, WorkspaceError};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    #[derive(Clone)]
    struct FailingStoreVault {
        values: Arc<Mutex<BTreeMap<String, String>>>,
        fail_name: String,
    }

    impl VaultBackend for FailingStoreVault {
        fn store(&self, name: &str, value: &str) -> PhantomResult<()> {
            if name == self.fail_name {
                return Err(PhantomError::VaultError(
                    "injected store failure".to_string(),
                ));
            }
            self.values
                .lock()
                .unwrap()
                .insert(name.to_string(), value.to_string());
            Ok(())
        }

        fn retrieve(&self, name: &str) -> PhantomResult<Zeroizing<String>> {
            self.values
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .map(Zeroizing::new)
                .ok_or_else(|| PhantomError::SecretNotFound(name.to_string()))
        }

        fn delete(&self, name: &str) -> PhantomResult<()> {
            self.values.lock().unwrap().remove(name);
            Ok(())
        }

        fn list(&self) -> PhantomResult<Vec<String>> {
            Ok(self.values.lock().unwrap().keys().cloned().collect())
        }

        fn backend_name(&self) -> &str {
            "injected-test-vault"
        }
    }

    fn write(path: impl AsRef<Path>, content: &str) {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn test_vault(directory: &Path, project_id: &str) -> Box<dyn VaultBackend> {
        Box::new(
            FileVault::new(
                directory,
                project_id,
                "workspace-test-passphrase".to_string(),
            )
            .unwrap(),
        )
    }

    fn seal_key() -> PlanSealKey {
        PlanSealKey::from_bytes([0x71; 32])
    }

    #[test]
    fn multi_env_same_value_uses_one_token_and_one_vault_entry() {
        let workspace = TempDir::new().unwrap();
        let vault_dir = TempDir::new().unwrap();
        let sentinel = "sk-shared-multi-env-sentinel";
        write(
            workspace.path().join(".env"),
            &format!("OPENAI_API_KEY={sentinel}\n"),
        );
        write(
            workspace.path().join("apps/web/.env.local"),
            &format!("OPENAI_API_KEY={sentinel}\n"),
        );
        let key = seal_key();
        let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();
        let mut participant = VaultSetupParticipant::with_vault(
            workspace.path(),
            test_vault(vault_dir.path(), "same-value"),
            false,
        );

        apply_setup_plan(&sealed, &key, &mut participant).unwrap();
        let root_env = std::fs::read_to_string(workspace.path().join(".env")).unwrap();
        let web_env =
            std::fs::read_to_string(workspace.path().join("apps/web/.env.local")).unwrap();
        let root_token = root_env.trim().split_once('=').unwrap().1;
        let web_token = web_env.trim().split_once('=').unwrap().1;
        assert_eq!(root_token, web_token);
        assert!(root_token.starts_with("phm_"));
        let verify = FileVault::new(
            vault_dir.path(),
            "same-value",
            "workspace-test-passphrase".to_string(),
        )
        .unwrap();
        assert_eq!(
            verify.retrieve("OPENAI_API_KEY").unwrap().as_str(),
            sentinel
        );
        assert_eq!(verify.list().unwrap(), vec!["OPENAI_API_KEY"]);
    }

    #[test]
    fn divergent_multi_env_values_fail_without_vault_or_file_changes() {
        let workspace = TempDir::new().unwrap();
        let vault_dir = TempDir::new().unwrap();
        let root_content = "OPENAI_API_KEY=sk-first-divergent-sentinel\n";
        let web_content = "OPENAI_API_KEY=sk-second-divergent-sentinel\n";
        write(workspace.path().join(".env"), root_content);
        write(workspace.path().join("apps/web/.env.local"), web_content);
        let key = seal_key();
        let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();
        let mut participant = VaultSetupParticipant::with_vault(
            workspace.path(),
            test_vault(vault_dir.path(), "divergent"),
            false,
        );

        let error = apply_setup_plan(&sealed, &key, &mut participant).unwrap_err();
        assert!(matches!(error, WorkspaceError::Participant { .. }));
        assert_eq!(
            std::fs::read_to_string(workspace.path().join(".env")).unwrap(),
            root_content
        );
        assert_eq!(
            std::fs::read_to_string(workspace.path().join("apps/web/.env.local")).unwrap(),
            web_content
        );
        let verify = FileVault::new(
            vault_dir.path(),
            "divergent",
            "workspace-test-passphrase".to_string(),
        )
        .unwrap();
        assert!(verify.list().unwrap().is_empty());
    }

    #[test]
    fn vault_and_metadata_are_restored_when_transaction_commit_fails() {
        let workspace = TempDir::new().unwrap();
        let vault_dir = TempDir::new().unwrap();
        let original_env = "OPENAI_API_KEY=sk-new-workspace-value\nNEW_SECRET=sk-new-entry\n";
        write(workspace.path().join(".env"), original_env);
        let vault = FileVault::new(
            vault_dir.path(),
            "rollback",
            "workspace-test-passphrase".to_string(),
        )
        .unwrap();
        vault.store("OPENAI_API_KEY", "sk-old-vault-value").unwrap();
        vault.set_rotation_policy("OPENAI_API_KEY", 17).unwrap();
        let metadata_before = vault.get_metadata("OPENAI_API_KEY").unwrap().unwrap();
        let key = seal_key();
        let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();
        let mut participant =
            VaultSetupParticipant::with_vault(workspace.path(), Box::new(vault), true);

        let error = apply_setup_plan(&sealed, &key, &mut participant).unwrap_err();
        assert!(matches!(error, WorkspaceError::Participant { .. }));
        assert_eq!(
            std::fs::read_to_string(workspace.path().join(".env")).unwrap(),
            original_env
        );
        let verify = FileVault::new(
            vault_dir.path(),
            "rollback",
            "workspace-test-passphrase".to_string(),
        )
        .unwrap();
        assert_eq!(
            verify.retrieve("OPENAI_API_KEY").unwrap().as_str(),
            "sk-old-vault-value"
        );
        assert_eq!(
            serde_json::to_value(verify.get_metadata("OPENAI_API_KEY").unwrap().unwrap()).unwrap(),
            serde_json::to_value(metadata_before).unwrap()
        );
        assert!(!verify.exists("NEW_SECRET").unwrap());
    }

    #[test]
    fn mid_store_failure_deletes_only_entries_that_were_actually_staged() {
        let workspace = TempDir::new().unwrap();
        let original_env = "A_SECRET=sk-first-store\nB_SECRET=sk-second-store\n";
        write(workspace.path().join(".env"), original_env);
        let shared = Arc::new(Mutex::new(BTreeMap::new()));
        let vault = FailingStoreVault {
            values: Arc::clone(&shared),
            fail_name: "B_SECRET".to_string(),
        };
        let key = seal_key();
        let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();
        let mut participant =
            VaultSetupParticipant::with_vault(workspace.path(), Box::new(vault), false);

        let error = apply_setup_plan(&sealed, &key, &mut participant).unwrap_err();
        assert!(matches!(error, WorkspaceError::Participant { .. }));
        assert!(shared.lock().unwrap().is_empty());
        assert_eq!(
            std::fs::read_to_string(workspace.path().join(".env")).unwrap(),
            original_env
        );
        assert!(!workspace.path().join(".phantom.toml").exists());
    }

    #[test]
    fn durable_journal_is_encrypted_and_replays_applied_receipt() {
        let workspace = TempDir::new().unwrap();
        let vault_dir = TempDir::new().unwrap();
        let journal_dir = TempDir::new().unwrap();
        let sentinel = "sk-journal-plaintext-must-not-appear";
        write(
            workspace.path().join(".env"),
            &format!("OPENAI_API_KEY={sentinel}\n"),
        );
        let key = seal_key();
        let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();
        let path = journal_dir.path().join("request.journal");
        let journal = DurableJournalConfig::new("a".repeat(64), path.clone(), [0x42; 32]);
        let mut participant = VaultSetupParticipant::with_vault(
            workspace.path(),
            test_vault(vault_dir.path(), "journal-success"),
            false,
        );

        let transaction =
            apply_setup_plan_durable(&sealed, &key, &mut participant, &journal).unwrap();
        let encoded = std::fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains(sentinel));

        let mut recovery = VaultSetupParticipant::with_vault(
            workspace.path(),
            test_vault(vault_dir.path(), "journal-success"),
            false,
        );
        assert_eq!(
            recover_setup_plan_journal(
                workspace.path(),
                &sealed.plan.plan_id,
                &sealed.pre_state_id,
                &mut recovery,
                &journal,
            )
            .unwrap(),
            JournalRecovery::Applied(transaction.receipt)
        );
        clear_setup_plan_journal(&journal).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn interrupted_commit_journal_recovers_to_before_images() {
        let workspace = TempDir::new().unwrap();
        let vault_dir = TempDir::new().unwrap();
        let journal_dir = TempDir::new().unwrap();
        let original_env = "OPENAI_API_KEY=sk-new-interrupted-value\n";
        write(workspace.path().join(".env"), original_env);
        let original_vault = FileVault::new(
            vault_dir.path(),
            "journal-rollback",
            "workspace-test-passphrase".to_string(),
        )
        .unwrap();
        original_vault
            .store("OPENAI_API_KEY", "sk-old-interrupted-value")
            .unwrap();
        let key = seal_key();
        let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();
        let journal = DurableJournalConfig::new(
            "b".repeat(64),
            journal_dir.path().join("request.journal"),
            [0x43; 32],
        );
        let mut participant =
            VaultSetupParticipant::with_vault(workspace.path(), Box::new(original_vault), true);

        assert!(apply_setup_plan_durable(&sealed, &key, &mut participant, &journal).is_err());
        let mut recovery = VaultSetupParticipant::with_vault(
            workspace.path(),
            test_vault(vault_dir.path(), "journal-rollback"),
            false,
        );
        assert_eq!(
            recover_setup_plan_journal(
                workspace.path(),
                &sealed.plan.plan_id,
                &sealed.pre_state_id,
                &mut recovery,
                &journal,
            )
            .unwrap(),
            JournalRecovery::RolledBack
        );
        assert_eq!(
            std::fs::read_to_string(workspace.path().join(".env")).unwrap(),
            original_env
        );
        let verify = FileVault::new(
            vault_dir.path(),
            "journal-rollback",
            "workspace-test-passphrase".to_string(),
        )
        .unwrap();
        assert_eq!(
            verify.retrieve("OPENAI_API_KEY").unwrap().as_str(),
            "sk-old-interrupted-value"
        );
    }
}
