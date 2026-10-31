//! Command-family argument definitions. Add flags in the owning fragment.
//! Keep parser regressions in `cli_tests/<family>.rs` so independent command
//! changes do not append to one shared source or test module. Top-level command
//! registration stays in main.rs; dispatch and JSON routing have separate modules.

mod agent;
mod cloud;
mod crypto;
mod expiry;
mod grant;
mod leaks;
mod mcp;
mod team;
mod validate;
mod vault;
mod workspace;

pub(crate) use agent::AgentAction;
pub(crate) use cloud::CloudAction;
pub(crate) use crypto::CryptoAction;
pub(crate) use expiry::ExpiryAction;
pub(crate) use grant::GrantAction;
pub(crate) use leaks::LeaksAction;
pub(crate) use mcp::McpAction;
pub(crate) use team::TeamAction;
pub(crate) use validate::ValidateAction;
pub(crate) use vault::VaultAction;
pub(crate) use workspace::WorkspaceCliAction;
