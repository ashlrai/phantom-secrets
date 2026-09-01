pub mod agent;
pub mod analytics;
pub mod audit;
pub mod audit_export;
pub mod auth;
pub mod cloud;
pub mod config;
pub mod dotenv;
pub mod env_scope;
pub mod error;
pub mod fs;
pub mod importers;
pub mod issuance;
pub mod leak_correlation;
pub mod managed_dotenv;
pub mod mcp_approval;
pub mod precommit_hook;
pub mod rotation_provider;
pub mod rotation_strategy;
pub mod sync;
pub mod team_crypto;
pub mod teams;
pub mod teams_vault;
pub mod token;
pub mod validation_scheduler;
pub mod validator;
pub mod workspace_request;

/// Crate-wide test helpers: a single `ENV_LOCK` shared by all modules whose
/// tests mutate process-wide env vars (`HOME`, `PHANTOM_AUDIT`, etc.).
/// Using separate per-module statics causes data-races when cargo runs tests
/// from different modules in parallel within the same test binary.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Mutex;
    pub(crate) static ENV_LOCK: Mutex<()> = Mutex::new(());
}
