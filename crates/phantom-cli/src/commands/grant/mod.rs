//! `phantom grant` compatibility surface.
//!
//! This release hard-denies enrollment before project, vault, environment,
//! browser, loopback, or network access. Protocol engines and request builders
//! remain test foundations for a future compensated enrollment transaction.
//! List/status are value-blind and read-only; revoke remains a hard denial.

pub mod add;
pub mod list;
pub mod revoke;
pub mod status;
