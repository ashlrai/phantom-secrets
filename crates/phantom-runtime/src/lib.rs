//! Fail-closed supervised execution contracts for engineering actions.
//!
//! Production execution is deliberately unavailable until Phantom ships sealed
//! workspace/toolchain handles and an OS confinement backend that owns the full
//! child lifecycle. The test-only direct runner returns only bounded byte counts
//! and a value-free outcome. Authority is never accepted through MCP, argv, or
//! environment variables.

mod action;
mod cancellation;
mod runtime;

pub use action::{ActionError, EngineeringAction, PackageName, RelativeCwd, TestFilter};
pub use cancellation::{CancellationToken, RevocationHandle};
pub use runtime::{
    ConfinementBackend, DenyAllConfinement, ExecutionError, ExecutionOutcome, ExecutionPolicy,
    OutcomeKind, RuntimeBuilder, SupervisedRuntime, Toolchain, WorkspaceHandle,
};
