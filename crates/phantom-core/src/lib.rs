pub mod agent;
pub mod analytics;
pub mod audit;
pub mod audit_export;
pub mod auth;
pub mod cloud;
mod cloud_http;
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
mod provider_http;
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

/// Process-wide serialization for code that reads or mutates environment
/// variables which influence Phantom's filesystem roots.
///
/// This is public only so Phantom workspace crates and their test suites share
/// one lock instead of accidentally coordinating on crate-local mutexes.
#[doc(hidden)]
pub static PROCESS_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Crate-wide test helpers: a single `ENV_LOCK` shared by all modules whose
/// tests mutate process-wide env vars (`HOME`, `PHANTOM_AUDIT`, etc.).
/// Using separate per-module statics causes data-races when cargo runs tests
/// from different modules in parallel within the same test binary.
#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) use crate::PROCESS_ENV_LOCK as ENV_LOCK;
}
