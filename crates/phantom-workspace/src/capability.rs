use crate::WorkspaceInspection;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const CAPABILITY_SCHEMA_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityState {
    NoLocusSeal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityScope {
    ConversationFacadeV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityCatalogNotice {
    pub governed_by_this_card: bool,
    pub locus_sealed: bool,
    pub mutation_gate: String,
    pub warning: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HardNo {
    pub verb: String,
    pub reason: String,
}

/// A sentence-ready, value-free summary of what the current session can do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityCard {
    pub schema_version: u8,
    /// This card governs only the small conversation-native facade, not every
    /// advanced compatibility tool exposed by the MCP server.
    pub scope: CapabilityScope,
    pub compatibility_catalog: CompatibilityCatalogNotice,
    /// Local drift-detection fingerprint, not a Locus workspace identity.
    pub workspace_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub place: Option<String>,
    pub authority: AuthorityState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    pub allowed_verbs: Vec<String>,
    pub requestable_verbs: Vec<String>,
    pub hard_nos: Vec<HardNo>,
    pub summary: String,
}

/// Build a truthful capability card with no externally verified authority.
///
/// Only local read-only inspection is allowed. This API intentionally has no
/// parameter that can describe an "active" seal: authority must eventually
/// enter through Phantom's non-deserializable verified-grant witness after the
/// private Locus broker exists.
/// Only workspace setup currently has a real governed request object. Future
/// verbs remain hard denied until their corresponding workflows exist.
pub fn build_capability_card(inspection: &WorkspaceInspection) -> CapabilityCard {
    CapabilityCard {
        schema_version: CAPABILITY_SCHEMA_VERSION,
        scope: CapabilityScope::ConversationFacadeV1,
        compatibility_catalog: CompatibilityCatalogNotice {
            governed_by_this_card: false,
            locus_sealed: false,
            mutation_gate: "legacy_confirm_plus_out_of_band_local_approval".to_string(),
            warning: "Advanced compatibility tools have separate legacy approval gates and are not governed by this facade capability card.".to_string(),
        },
        workspace_fingerprint: inspection.workspace_fingerprint.clone(),
        place: None,
        authority: AuthorityState::NoLocusSeal,
        seal_id: None,
        expires_at: None,
        allowed_verbs: vec![
            "capability".to_string(),
            "inspect_workspace".to_string(),
            "propose_engineering_action".to_string(),
        ],
        requestable_verbs: vec!["setup_workspace".to_string()],
        hard_nos: unsealed_hard_nos().into_iter().collect(),
        summary: "No verified Locus authority is active for the conversation facade. The facade can inspect and propose local changes but cannot perform external or privileged actions; advanced compatibility tools use separate legacy approval gates."
            .to_string(),
    }
}

fn unsealed_hard_nos() -> BTreeSet<HardNo> {
    [
        (
            "assume_place",
            "Place assumption is unavailable until a verified Locus seal and exact place binding exist.",
        ),
        (
            "cross_workspace",
            "No authority exists for a different workspace or account.",
        ),
        (
            "delete",
            "Destructive actions require a scoped human-attested grant.",
        ),
        (
            "execute_engineering_action",
            "Engineering execution requires a verified permit, trusted handles, OS confinement, and correlated evidence.",
        ),
        (
            "external_mutation",
            "External systems are unavailable without an active Locus seal.",
        ),
        (
            "fix_auth",
            "Governed authentication repair requests are not implemented.",
        ),
        (
            "need_secret",
            "The high-level secret request workflow is inactive; secret entry remains trusted-terminal only.",
        ),
        (
            "production",
            "Production effects require an explicit elevated grant.",
        ),
        (
            "secret_reveal",
            "Real secret values are never an agent capability.",
        ),
        (
            "share",
            "Membership and secret sharing require a scoped human-attested grant.",
        ),
        (
            "spend",
            "Financial effects require an explicit capped grant.",
        ),
    ]
    .into_iter()
    .map(|(verb, reason)| HardNo {
        verb: verb.to_string(),
        reason: reason.to_string(),
    })
    .collect()
}
