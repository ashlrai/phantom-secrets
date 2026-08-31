use phantom_workspace::{
    apply_setup_plan, build_capability_card, build_sealed_setup_plan, build_setup_plan,
    inspect_workspace, rollback_workspace, AuthorityState, CapabilityScope, NoopSetupParticipant,
    ParticipantError, ParticipantFileMutation, ParticipantPreparation, PlanSealKey, SetupAction,
    SetupActionKind, SetupPlan, SetupTransactionParticipant, WorkspaceError,
};
use std::path::Path;
use tempfile::TempDir;

fn write(path: impl AsRef<Path>, content: &str) {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

#[test]
fn discovers_multiple_env_files_without_crossing_nested_repositories() {
    let workspace = TempDir::new().unwrap();
    write(
        workspace.path().join(".env"),
        "OPENAI_API_KEY=sk-root-secret\nNODE_ENV=development\n",
    );
    write(
        workspace.path().join("apps/web/.env.local"),
        "STRIPE_SECRET_KEY=sk_test_web_secret\n",
    );
    write(
        workspace.path().join("apps/api/.env.production"),
        "DATABASE_URL=postgres://user:pass@example.test/db\n",
    );
    write(
        workspace.path().join("vendor/ignored/.env"),
        "IGNORED_SECRET=sk-ignored\n",
    );
    std::fs::create_dir_all(workspace.path().join("nested/.git")).unwrap();
    write(
        workspace.path().join("nested/.env"),
        "NESTED_SECRET=sk-nested\n",
    );

    let inspection = inspect_workspace(workspace.path()).unwrap();
    let paths = inspection
        .env_files
        .iter()
        .map(|env| env.path.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        paths,
        vec![".env", "apps/api/.env.production", "apps/web/.env.local"]
    );
    assert_eq!(
        inspection.env_files[0].unprotected_secret_names,
        vec!["OPENAI_API_KEY"]
    );
    assert_eq!(inspection.env_files[0].config_names, vec!["NODE_ENV"]);
}

#[test]
fn serialized_inspection_and_plan_never_contain_environment_values() {
    let workspace = TempDir::new().unwrap();
    let sentinels = [
        "sk-super-sensitive-sentinel",
        "postgres://secret-user:secret-pass@db.example.test/prod",
        "ordinary-but-private-config-value",
    ];
    write(
        workspace.path().join(".env"),
        &format!(
            "OPENAI_API_KEY={}\nDATABASE_URL={}\nINTERNAL_LABEL={}\n",
            sentinels[0], sentinels[1], sentinels[2]
        ),
    );

    let inspection = inspect_workspace(workspace.path()).unwrap();
    let plan = build_setup_plan(&inspection).unwrap();
    let serialized = format!(
        "{}\n{}",
        serde_json::to_string(&inspection).unwrap(),
        serde_json::to_string(&plan).unwrap()
    );

    for sentinel in sentinels {
        assert!(
            !serialized.contains(sentinel),
            "serialized value-blind state leaked {sentinel}"
        );
    }
    assert!(serialized.contains("OPENAI_API_KEY"));
    assert!(serialized.contains("DATABASE_URL"));
    assert!(serialized.contains("INTERNAL_LABEL"));
}

#[test]
fn infers_place_hint_from_strict_normalized_git_remote() {
    let workspace = TempDir::new().unwrap();
    write(
        workspace.path().join(".git/config"),
        r#"[core]
    repositoryformatversion = 0
[remote "origin"]
    url = https://github.com/acme-corp/payments.git
[remote "upstream"]
    url = git@gitlab.com:platform-group/payments.git
"#,
    );

    let inspection = inspect_workspace(workspace.path()).unwrap();
    let git = inspection.git.as_ref().unwrap();
    assert_eq!(git.remotes[0].host, "github.com");
    assert_eq!(git.remotes[0].owner, "acme-corp");
    assert_eq!(git.remotes[0].repository, "payments");
    assert_eq!(inspection.place_hints[0].label, "acme-corp");
    assert_eq!(inspection.place_hints[0].source, "git.remote.origin");
}

#[test]
fn rejects_remote_credentials_queries_fragments_and_non_allowlisted_components() {
    let cases = [
        "https://oauth2:embedded-token@github.com/acme-corp/payments.git",
        "https://github.com/acme-corp/payments.git?access_token=embedded-token",
        "https://github.com/acme-corp/payments.git#embedded-token",
        "token-user@github.com:acme-corp/payments.git",
        "https://github.com/acme-corp/payments/extra.git",
        "https://github.com/acme%2fadmin/payments.git",
    ];

    for remote in cases {
        let workspace = TempDir::new().unwrap();
        write(
            workspace.path().join(".git/config"),
            &format!("[remote \"origin\"]\nurl = {remote}\n"),
        );
        let inspection = inspect_workspace(workspace.path()).unwrap();
        assert!(inspection.git.is_none(), "remote was accepted: {remote}");
        let serialized = serde_json::to_string(&inspection).unwrap();
        assert!(!serialized.contains("embedded-token"));
    }
}

#[test]
fn rejects_arbitrary_out_of_workspace_gitdir_indirection() {
    let workspace = TempDir::new().unwrap();
    let attacker = TempDir::new().unwrap();
    write(
        attacker.path().join("config"),
        "[remote \"origin\"]\nurl = https://github.com/attacker/repository.git\n",
    );
    write(
        workspace.path().join(".git"),
        &format!("gitdir: {}\n", attacker.path().display()),
    );

    let inspection = inspect_workspace(workspace.path()).unwrap();
    assert!(inspection.git.is_none());
    assert!(inspection.place_hints.is_empty());
}

#[test]
fn accepts_contained_gitdir_indirection() {
    let workspace = TempDir::new().unwrap();
    write(
        workspace.path().join(".git-data/config"),
        "[remote \"origin\"]\nurl = https://github.com/acme/project.git\n",
    );
    write(workspace.path().join(".git"), "gitdir: .git-data\n");

    let inspection = inspect_workspace(workspace.path()).unwrap();
    let remote = &inspection.git.unwrap().remotes[0];
    assert_eq!(remote.host, "github.com");
    assert_eq!(remote.owner, "acme");
    assert_eq!(remote.repository, "project");
}

#[test]
fn accepts_external_linked_worktree_gitdir_with_exact_backlink() {
    let workspace = TempDir::new().unwrap();
    let common = TempDir::new().unwrap();
    let worktree_git_dir = common.path().join("worktrees/slot");
    write(
        common.path().join("config"),
        "[remote \"origin\"]\nurl = https://github.com/acme/linked-project.git\n",
    );
    write(worktree_git_dir.join("commondir"), "../..\n");
    write(
        worktree_git_dir.join("gitdir"),
        &format!("{}\n", workspace.path().join(".git").display()),
    );
    write(
        workspace.path().join(".git"),
        &format!("gitdir: {}\n", worktree_git_dir.display()),
    );

    let inspection = inspect_workspace(workspace.path()).unwrap();
    let plan = build_setup_plan(&inspection).unwrap();
    let remote = &inspection.git.as_ref().unwrap().remotes[0];
    assert_eq!(remote.owner, "acme");
    assert_eq!(remote.repository, "linked-project");
    assert!(plan
        .actions
        .iter()
        .all(|action| action.kind != SetupActionKind::InstallPreCommitCheck));
}

#[test]
fn setup_plan_id_is_deterministic_and_changes_with_observed_state() {
    let workspace = TempDir::new().unwrap();
    write(
        workspace.path().join(".env"),
        "B_SECRET=sk-b-value\nA_SECRET=sk-a-value\n",
    );

    let first = build_setup_plan(&inspect_workspace(workspace.path()).unwrap()).unwrap();
    let second = build_setup_plan(&inspect_workspace(workspace.path()).unwrap()).unwrap();
    assert_eq!(first.plan_id, second.plan_id);
    assert_eq!(first.actions, second.actions);

    let protect = first
        .actions
        .iter()
        .find(|action| action.kind == SetupActionKind::ProtectEnvFile)
        .unwrap();
    assert_eq!(protect.key_names, vec!["A_SECRET", "B_SECRET"]);

    write(
        workspace.path().join(".env.local"),
        "STRIPE_SECRET_KEY=sk_test_changed-state\n",
    );
    let changed = build_setup_plan(&inspect_workspace(workspace.path()).unwrap()).unwrap();
    assert_ne!(first.plan_id, changed.plan_id);
}

#[test]
fn capability_card_has_explicit_hard_nos_without_locus_seal() {
    let workspace = TempDir::new().unwrap();
    let inspection = inspect_workspace(workspace.path()).unwrap();
    let card = build_capability_card(&inspection);

    assert_eq!(card.authority, AuthorityState::NoLocusSeal);
    assert_eq!(card.scope, CapabilityScope::ConversationFacadeV1);
    assert!(!card.compatibility_catalog.governed_by_this_card);
    assert!(!card.compatibility_catalog.locus_sealed);
    assert!(card.place.is_none());
    assert!(card.seal_id.is_none());
    assert!(card.expires_at.is_none());
    assert_eq!(card.requestable_verbs, vec!["setup_workspace"]);
    assert_eq!(
        card.allowed_verbs,
        vec![
            "capability",
            "inspect_workspace",
            "propose_engineering_action"
        ]
    );

    let hard_nos = card
        .hard_nos
        .iter()
        .map(|hard_no| hard_no.verb.as_str())
        .collect::<Vec<_>>();
    for required in [
        "assume_place",
        "cross_workspace",
        "delete",
        "execute_engineering_action",
        "external_mutation",
        "fix_auth",
        "need_secret",
        "production",
        "secret_reveal",
        "share",
        "spend",
    ] {
        assert!(hard_nos.contains(&required), "missing hard no: {required}");
    }
    assert!(card
        .summary
        .contains("No verified Locus authority is active"));
}

fn seal_key() -> PlanSealKey {
    PlanSealKey::from_bytes([0xa7; 32])
}

#[test]
fn sealed_plan_rejects_same_key_value_drift_without_exposing_values_or_seal_key() {
    let workspace = TempDir::new().unwrap();
    let first_value = "sk-first-exact-pre-state-sentinel";
    let second_value = "sk-second-exact-pre-state-sentinel";
    write(
        workspace.path().join(".env"),
        &format!("OPENAI_API_KEY={first_value}\n"),
    );
    let key = seal_key();
    let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();
    let serialized = serde_json::to_string(&sealed).unwrap();
    assert!(!serialized.contains(first_value));
    assert!(!serialized.contains(&hex::encode([0xa7; 32])));

    write(
        workspace.path().join(".env"),
        &format!("OPENAI_API_KEY={second_value}\n"),
    );
    let error = apply_setup_plan(&sealed, &key, &mut NoopSetupParticipant).unwrap_err();
    assert!(matches!(error, WorkspaceError::PlanDrift { .. }));
    assert!(!error.to_string().contains(first_value));
    assert!(!error.to_string().contains(second_value));
}

#[test]
fn sealed_plan_rejects_existing_config_namespace_drift() {
    let workspace = TempDir::new().unwrap();
    write(
        workspace.path().join(".phantom.toml"),
        "[phantom]\nproject_id = \"first-namespace\"\n",
    );
    let key = seal_key();
    let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();

    write(
        workspace.path().join(".phantom.toml"),
        "[phantom]\nproject_id = \"second-namespace\"\n",
    );

    let error = apply_setup_plan(&sealed, &key, &mut NoopSetupParticipant).unwrap_err();
    assert!(matches!(error, WorkspaceError::PlanDrift { .. }));
}

#[test]
fn filesystem_apply_is_atomic_idempotent_and_recoverable() {
    let workspace = TempDir::new().unwrap();
    let secret = "sk-transaction-secret-sentinel";
    write(
        workspace.path().join(".env"),
        &format!("OPENAI_API_KEY={secret}\nPORT=3000\n"),
    );
    write(
        workspace.path().join(".git/config"),
        "[remote \"origin\"]\nurl = git@github.com:acme/project.git\n",
    );
    let original_ignore = "# keep this deny policy\n.env.production\n";
    let original_hook = "#!/bin/sh\necho existing-check\n";
    write(workspace.path().join(".gitignore"), original_ignore);
    write(
        workspace.path().join(".git/hooks/pre-commit"),
        original_hook,
    );
    let client_config = r#"{"permissions":{"deny":["Read(.env*)"]},"custom":true}"#;
    write(
        workspace.path().join(".claude/settings.local.json"),
        client_config,
    );

    let key = seal_key();
    let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();
    let first = apply_setup_plan(&sealed, &key, &mut NoopSetupParticipant).unwrap();
    assert!(!first.receipt.fully_applied);
    assert!(workspace.path().join(".phantom.toml").is_file());
    let example = std::fs::read_to_string(workspace.path().join(".env.example")).unwrap();
    assert!(example.contains("OPENAI_API_KEY=\n"));
    assert!(example.contains("PORT=\n"));
    assert!(!example.contains(secret));
    assert_eq!(
        std::fs::read_to_string(workspace.path().join(".env")).unwrap(),
        format!("OPENAI_API_KEY={secret}\nPORT=3000\n")
    );
    let ignore = std::fs::read_to_string(workspace.path().join(".gitignore")).unwrap();
    assert!(ignore.starts_with(original_ignore));
    let hook = std::fs::read_to_string(workspace.path().join(".git/hooks/pre-commit")).unwrap();
    assert!(hook.starts_with(original_hook));
    assert!(hook.contains("phantom-secrets check --staged"));
    assert_eq!(
        std::fs::read_to_string(workspace.path().join(".claude/settings.local.json")).unwrap(),
        client_config
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(workspace.path().join(".git/hooks/pre-commit"))
            .unwrap()
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0);
    }
    let serialized_receipt = serde_json::to_string(&first.receipt).unwrap();
    assert!(!serialized_receipt.contains(secret));
    assert!(!format!("{:?}", first.snapshot).contains(secret));

    // Idempotency uses a fresh exact pre-state seal; desired merge operations
    // produce no duplicate lines and no filesystem changes.
    let current = build_sealed_setup_plan(workspace.path(), &key).unwrap();
    let second = apply_setup_plan(&current, &key, &mut NoopSetupParticipant).unwrap();
    assert!(second.receipt.file_changes.is_empty());
    let ignore_after = std::fs::read_to_string(workspace.path().join(".gitignore")).unwrap();
    assert_eq!(ignore_after.matches(".env.local").count(), 1);
    let hook_after =
        std::fs::read_to_string(workspace.path().join(".git/hooks/pre-commit")).unwrap();
    assert_eq!(
        hook_after.matches("phantom-secrets check --staged").count(),
        1
    );

    rollback_workspace(first.snapshot).unwrap();
    assert!(!workspace.path().join(".phantom.toml").exists());
    assert!(!workspace.path().join(".env.example").exists());
    assert_eq!(
        std::fs::read_to_string(workspace.path().join(".gitignore")).unwrap(),
        original_ignore
    );
    assert_eq!(
        std::fs::read_to_string(workspace.path().join(".git/hooks/pre-commit")).unwrap(),
        original_hook
    );
}

#[derive(Default)]
struct CommitFailureParticipant {
    rollback_called: bool,
}

impl SetupTransactionParticipant for CommitFailureParticipant {
    fn prepare(
        &mut self,
        _plan: &SetupPlan,
        _external_actions: &[SetupAction],
    ) -> Result<ParticipantPreparation, ParticipantError> {
        Ok(ParticipantPreparation::default())
    }

    fn commit(&mut self) -> Result<(), ParticipantError> {
        Err(ParticipantError::new("injected_commit_failure"))
    }

    fn rollback(&mut self) -> Result<(), ParticipantError> {
        self.rollback_called = true;
        Ok(())
    }
}

#[test]
fn participant_commit_failure_restores_every_filesystem_change() {
    let workspace = TempDir::new().unwrap();
    write(
        workspace.path().join(".env"),
        "OPENAI_API_KEY=sk-rollback-sentinel\n",
    );
    write(workspace.path().join(".gitignore"), "# original\n");
    let env_before = std::fs::read(workspace.path().join(".env")).unwrap();
    let ignore_before = std::fs::read(workspace.path().join(".gitignore")).unwrap();
    let key = seal_key();
    let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();
    let mut participant = CommitFailureParticipant::default();

    let error = apply_setup_plan(&sealed, &key, &mut participant).unwrap_err();
    assert!(matches!(error, WorkspaceError::Participant { .. }));
    assert!(participant.rollback_called);
    assert_eq!(
        std::fs::read(workspace.path().join(".env")).unwrap(),
        env_before
    );
    assert_eq!(
        std::fs::read(workspace.path().join(".gitignore")).unwrap(),
        ignore_before
    );
    assert!(!workspace.path().join(".phantom.toml").exists());
    assert!(!workspace.path().join(".env.example").exists());
}

#[cfg(unix)]
#[test]
fn sealed_plan_refuses_symlinked_mutation_targets() {
    use std::os::unix::fs::symlink;

    let workspace = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    write(
        workspace.path().join(".env"),
        "OPENAI_API_KEY=sk-symlink-sentinel\n",
    );
    write(outside.path().join("ignore"), "outside\n");
    symlink(
        outside.path().join("ignore"),
        workspace.path().join(".gitignore"),
    )
    .unwrap();

    let error = build_sealed_setup_plan(workspace.path(), &seal_key()).unwrap_err();
    assert!(matches!(error, WorkspaceError::UnsafeTarget(_)));
    assert_eq!(
        std::fs::read_to_string(outside.path().join("ignore")).unwrap(),
        "outside\n"
    );
}

#[cfg(unix)]
#[test]
fn sealed_plan_refuses_existing_hardlinked_targets() {
    let workspace = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    write(
        workspace.path().join(".env"),
        "OPENAI_API_KEY=sk-hardlink-sentinel\n",
    );
    write(outside.path().join("shared-ignore"), "outside-policy\n");
    std::fs::hard_link(
        outside.path().join("shared-ignore"),
        workspace.path().join(".gitignore"),
    )
    .unwrap();

    let error = build_sealed_setup_plan(workspace.path(), &seal_key()).unwrap_err();
    assert!(matches!(error, WorkspaceError::UnsafeTarget(_)));
    assert_eq!(
        std::fs::read_to_string(outside.path().join("shared-ignore")).unwrap(),
        "outside-policy\n"
    );
}

#[test]
fn apply_rejects_env_path_that_becomes_a_nested_repository() {
    let workspace = TempDir::new().unwrap();
    write(
        workspace.path().join("apps/web/.env"),
        "OPENAI_API_KEY=sk-nested-swap-sentinel\n",
    );
    let key = seal_key();
    let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();
    std::fs::create_dir_all(workspace.path().join("apps/.git")).unwrap();

    let error = apply_setup_plan(&sealed, &key, &mut NoopSetupParticipant).unwrap_err();
    assert!(matches!(
        error,
        WorkspaceError::PlanDrift { .. } | WorkspaceError::UnsafeTarget(_)
    ));
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("apps/web/.env")).unwrap(),
        "OPENAI_API_KEY=sk-nested-swap-sentinel\n"
    );
}

#[derive(Default)]
struct PrepareFailureParticipant {
    rollback_called: bool,
}

impl SetupTransactionParticipant for PrepareFailureParticipant {
    fn prepare(
        &mut self,
        _plan: &SetupPlan,
        _external_actions: &[SetupAction],
    ) -> Result<ParticipantPreparation, ParticipantError> {
        Err(ParticipantError::new("injected_prepare_failure"))
    }

    fn commit(&mut self) -> Result<(), ParticipantError> {
        panic!("commit must not run after prepare failure")
    }

    fn rollback(&mut self) -> Result<(), ParticipantError> {
        self.rollback_called = true;
        Ok(())
    }
}

#[test]
fn participant_prepare_failure_runs_compensation_without_changing_files() {
    let workspace = TempDir::new().unwrap();
    write(
        workspace.path().join(".env"),
        "OPENAI_API_KEY=sk-prepare-failure-sentinel\n",
    );
    write(
        workspace.path().join(".gitignore"),
        "# byte-exact-original\n",
    );
    let env_before = std::fs::read(workspace.path().join(".env")).unwrap();
    let ignore_before = std::fs::read(workspace.path().join(".gitignore")).unwrap();
    let key = seal_key();
    let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();
    let mut participant = PrepareFailureParticipant::default();

    let error = apply_setup_plan(&sealed, &key, &mut participant).unwrap_err();
    assert!(matches!(error, WorkspaceError::Participant { .. }));
    assert!(participant.rollback_called);
    assert_eq!(
        std::fs::read(workspace.path().join(".env")).unwrap(),
        env_before
    );
    assert_eq!(
        std::fs::read(workspace.path().join(".gitignore")).unwrap(),
        ignore_before
    );
    assert!(!workspace.path().join(".phantom.toml").exists());
    assert!(!workspace.path().join(".env.example").exists());
}

enum InvalidMutationMode {
    Duplicate,
    Unauthorized,
}

struct InvalidMutationParticipant {
    mode: InvalidMutationMode,
    rollback_called: bool,
}

impl SetupTransactionParticipant for InvalidMutationParticipant {
    fn prepare(
        &mut self,
        _plan: &SetupPlan,
        external_actions: &[SetupAction],
    ) -> Result<ParticipantPreparation, ParticipantError> {
        let protect = external_actions
            .iter()
            .find(|action| action.kind == SetupActionKind::ProtectEnvFile)
            .unwrap();
        let mutations = match self.mode {
            InvalidMutationMode::Duplicate => vec![
                ParticipantFileMutation::replace(&protect.target, b"TOKEN=phm_one\n".to_vec()),
                ParticipantFileMutation::replace(&protect.target, b"TOKEN=phm_two\n".to_vec()),
            ],
            InvalidMutationMode::Unauthorized => vec![ParticipantFileMutation::replace(
                ".claude/settings.local.json",
                b"{}".to_vec(),
            )],
        };
        Ok(ParticipantPreparation::new([protect.id.clone()], mutations))
    }

    fn commit(&mut self) -> Result<(), ParticipantError> {
        panic!("invalid preparation must not commit")
    }

    fn rollback(&mut self) -> Result<(), ParticipantError> {
        self.rollback_called = true;
        Ok(())
    }
}

#[test]
fn duplicate_and_unauthorized_participant_mutations_are_rejected_and_compensated() {
    for mode in [
        InvalidMutationMode::Duplicate,
        InvalidMutationMode::Unauthorized,
    ] {
        let workspace = TempDir::new().unwrap();
        let original = "OPENAI_API_KEY=sk-invalid-mutation-sentinel\n";
        write(workspace.path().join(".env"), original);
        let key = seal_key();
        let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();
        let mut participant = InvalidMutationParticipant {
            mode,
            rollback_called: false,
        };

        let error = apply_setup_plan(&sealed, &key, &mut participant).unwrap_err();
        assert!(matches!(
            error,
            WorkspaceError::InvalidPlan | WorkspaceError::UnsafeTarget(_)
        ));
        assert!(participant.rollback_called);
        assert_eq!(
            std::fs::read_to_string(workspace.path().join(".env")).unwrap(),
            original
        );
        assert!(!workspace.path().join(".phantom.toml").exists());
        assert!(!workspace
            .path()
            .join(".claude/settings.local.json")
            .exists());
    }
}

#[test]
fn explicit_rollback_refuses_to_overwrite_later_file_changes() {
    let workspace = TempDir::new().unwrap();
    write(
        workspace.path().join(".env"),
        "OPENAI_API_KEY=sk-rollback-drift-sentinel\n",
    );
    write(workspace.path().join(".gitignore"), "# original\n");
    let key = seal_key();
    let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();
    let transaction = apply_setup_plan(&sealed, &key, &mut NoopSetupParticipant).unwrap();
    write(
        workspace.path().join(".gitignore"),
        "# user changed this after setup\n",
    );

    let error = rollback_workspace(transaction.snapshot).unwrap_err();
    assert!(matches!(error, WorkspaceError::RollbackDrift(_)));
    assert_eq!(
        std::fs::read_to_string(workspace.path().join(".gitignore")).unwrap(),
        "# user changed this after setup\n"
    );
}

#[test]
fn concurrent_applies_allow_only_one_exact_plan_to_mutate() {
    use std::sync::{Arc, Barrier};

    let workspace = TempDir::new().unwrap();
    write(
        workspace.path().join(".env"),
        "OPENAI_API_KEY=sk-concurrent-apply-sentinel\n",
    );
    let key = seal_key();
    let sealed = build_sealed_setup_plan(workspace.path(), &key).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let sealed = sealed.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            let key = seal_key();
            barrier.wait();
            match apply_setup_plan(&sealed, &key, &mut NoopSetupParticipant) {
                Ok(transaction) => {
                    assert!(!transaction.receipt.file_changes.is_empty());
                    "applied"
                }
                Err(WorkspaceError::PlanDrift { .. }) => "drift",
                Err(error) => panic!("unexpected concurrent result: {error}"),
            }
        }));
    }
    barrier.wait();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();

    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == "applied")
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == "drift")
            .count(),
        1
    );
    assert!(workspace.path().join(".phantom.toml").is_file());
}
