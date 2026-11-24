//! Durability warnings are for operators. Versioned JSON success must leave
//! stderr empty, including on Windows where a verified write cannot prove
//! directory crash durability.

use std::sync::atomic::{AtomicBool, Ordering};

static SUPPRESSED: AtomicBool = AtomicBool::new(false);

/// Latch for one process. The CLI sets this before a versioned JSON command
/// so a successful receipt does not share stderr with a human warning.
pub fn suppress_for_process() {
    SUPPRESSED.store(true, Ordering::Relaxed);
}

pub fn emit(message: &str) {
    if emit_allowed(SUPPRESSED.load(Ordering::Relaxed)) {
        eprintln!("{message}");
    }
}

fn emit_allowed(suppressed: bool) -> bool {
    !suppressed
}

#[cfg(test)]
mod tests {
    use super::emit_allowed;

    #[test]
    fn a_suppressed_process_does_not_emit_durability_warnings() {
        assert!(!emit_allowed(true));
        assert!(emit_allowed(false));
    }
}
