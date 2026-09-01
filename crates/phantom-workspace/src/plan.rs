use crate::discovery::{digest_hex, PlaceHint, WorkspaceInspection};
use crate::Result;
use serde::{Deserialize, Serialize};

const PLAN_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupActionKind {
    InitializeWorkspace,
    ProtectEnvFile,
    EnsureEnvIgnoreRules,
    GenerateEnvExample,
    InstallPreCommitCheck,
    ReviewPlaceBinding,
}

/// One deterministic, value-blind setup action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupAction {
    pub id: String,
    pub kind: SetupActionKind,
    pub target: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_names: Vec<String>,
    pub requires_out_of_band_approval: bool,
    pub reason: String,
}

/// An inspect/setup plan whose identifier can be bound to approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupPlan {
    pub schema_version: u8,
    pub plan_id: String,
    pub workspace_fingerprint: String,
    pub workspace_root: String,
    pub candidate_places: Vec<PlaceHint>,
    pub actions: Vec<SetupAction>,
    pub blockers: Vec<String>,
}

#[derive(Serialize)]
struct PlanBasis<'a> {
    schema_version: u8,
    workspace_fingerprint: &'a str,
    workspace_root: &'a str,
    candidate_places: &'a [PlaceHint],
    actions: &'a [SetupAction],
    blockers: &'a [String],
}

/// Build a stable setup plan from an immutable inspection snapshot.
pub fn build_setup_plan(inspection: &WorkspaceInspection) -> Result<SetupPlan> {
    let mut actions = Vec::new();
    let mut blockers = inspection.warnings.clone();

    if !inspection.phantom_initialized {
        actions.push(action(
            SetupActionKind::InitializeWorkspace,
            ".phantom.toml",
            Vec::new(),
            "Create the project-scoped Phantom configuration and vault namespace.",
        ));
    }

    for env in &inspection.env_files {
        if env.unprotected_secret_names.is_empty() {
            continue;
        }
        actions.push(action(
            SetupActionKind::ProtectEnvFile,
            &env.path,
            env.unprotected_secret_names.clone(),
            "Move detected secret values into the vault and replace them with phantom tokens.",
        ));
    }

    if !inspection.env_files.is_empty() {
        actions.push(action(
            SetupActionKind::EnsureEnvIgnoreRules,
            ".gitignore",
            Vec::new(),
            "Keep local dotenv material out of version control.",
        ));
        if !inspection.env_example_exists {
            actions.push(action(
                SetupActionKind::GenerateEnvExample,
                ".env.example",
                Vec::new(),
                "Generate a value-free environment contract for collaborators.",
            ));
        }
    }

    // Git owns hook-path resolution. Keep the transaction root-contained: an
    // effective path outside the workspace (common for linked worktrees or an
    // absolute core.hooksPath) is surfaced as an explicit trusted-terminal
    // blocker instead of being silently skipped or rewritten.
    if inspection.git.is_some() {
        let root = std::path::Path::new(&inspection.workspace_root);
        match phantom_core::precommit_hook::resolve_path(root) {
            Ok(Some(hook_path)) => match hook_path.strip_prefix(root) {
                Ok(relative) if relative.file_name().is_some() => actions.push(action(
                    SetupActionKind::InstallPreCommitCheck,
                    &relative.to_string_lossy().replace('\\', "/"),
                    Vec::new(),
                    "Reject newly staged plaintext credentials before they enter Git history.",
                )),
                _ => blockers.push(format!(
                    "Git's effective pre-commit hook path is outside the workspace transaction boundary ({}); run `phantom doctor --fix` in a trusted terminal.",
                    hook_path.display()
                )),
            },
            Ok(None) => blockers.push(
                "Git metadata was discovered, but Git no longer recognizes this workspace as a repository."
                    .to_string(),
            ),
            Err(error) => blockers.push(format!(
                "Git's effective pre-commit hook path could not be resolved: {error}"
            )),
        }
    }

    let place_target = inspection
        .place_hints
        .first()
        .map(|hint| hint.label.as_str())
        .unwrap_or("unresolved");
    actions.push(action(
        SetupActionKind::ReviewPlaceBinding,
        place_target,
        Vec::new(),
        "A human-attested Locus place is required before external or privileged actions.",
    ));

    if inspection.place_hints.is_empty() {
        blockers.push("No place binding could be inferred from repository metadata.".to_string());
    } else {
        let distinct_labels = inspection
            .place_hints
            .iter()
            .map(|hint| hint.label.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if distinct_labels.len() > 1 {
            blockers.push(
                "Repository metadata suggests multiple places; a human must choose one."
                    .to_string(),
            );
        }
    }

    actions.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.target.cmp(&right.target))
            .then_with(|| left.key_names.cmp(&right.key_names))
    });
    blockers.sort();
    blockers.dedup();

    let plan_id = calculate_plan_id(
        &inspection.workspace_fingerprint,
        &inspection.workspace_root,
        &inspection.place_hints,
        &actions,
        &blockers,
    )?;

    Ok(SetupPlan {
        schema_version: PLAN_SCHEMA_VERSION,
        plan_id,
        workspace_fingerprint: inspection.workspace_fingerprint.clone(),
        workspace_root: inspection.workspace_root.clone(),
        candidate_places: inspection.place_hints.clone(),
        actions,
        blockers,
    })
}

pub(crate) fn plan_has_valid_id(plan: &SetupPlan) -> Result<bool> {
    Ok(plan.schema_version == PLAN_SCHEMA_VERSION
        && plan.plan_id
            == calculate_plan_id(
                &plan.workspace_fingerprint,
                &plan.workspace_root,
                &plan.candidate_places,
                &plan.actions,
                &plan.blockers,
            )?)
}

fn calculate_plan_id(
    workspace_fingerprint: &str,
    workspace_root: &str,
    candidate_places: &[PlaceHint],
    actions: &[SetupAction],
    blockers: &[String],
) -> Result<String> {
    let basis = PlanBasis {
        schema_version: PLAN_SCHEMA_VERSION,
        workspace_fingerprint,
        workspace_root,
        candidate_places,
        actions,
        blockers,
    };
    Ok(digest_hex(&serde_json::to_vec(&basis)?))
}

fn action(
    kind: SetupActionKind,
    target: &str,
    mut key_names: Vec<String>,
    reason: &str,
) -> SetupAction {
    key_names.sort();
    key_names.dedup();
    let id_basis = serde_json::json!({
        "kind": kind,
        "target": target,
        "key_names": key_names,
    });
    let id = format!(
        "action_{}",
        &digest_hex(&serde_json::to_vec(&id_basis).expect("action basis is serializable"))[..16]
    );
    SetupAction {
        id,
        kind,
        target: target.to_string(),
        key_names,
        requires_out_of_band_approval: true,
        reason: reason.to_string(),
    }
}
