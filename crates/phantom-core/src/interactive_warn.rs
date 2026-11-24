//! Durability warnings for operators.
//!
//! A JSON command that copies the warning into its receipt holds a
//! [`SuppressGuard`] so the same text is not also printed on stderr. The guard
//! is thread-local and resets when dropped. Commands whose JSON has no
//! durability field, such as `phantom audit path --json`, must not arm it.

use std::cell::Cell;
use std::marker::PhantomData;

thread_local! {
    static SUPPRESS_DEPTH: Cell<usize> = const { Cell::new(0) };
}

/// Suppresses [`emit`] on this thread until dropped.
pub struct SuppressGuard {
    armed: bool,
    _thread: PhantomData<*const ()>,
}

impl SuppressGuard {
    pub fn arm() -> Self {
        SUPPRESS_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self {
            armed: true,
            _thread: PhantomData,
        }
    }
}

impl Drop for SuppressGuard {
    fn drop(&mut self) {
        if self.armed {
            SUPPRESS_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
        }
    }
}

pub fn emit(message: &str) {
    if !suppressed() {
        eprintln!("{message}");
    }
}

pub fn suppressed() -> bool {
    SUPPRESS_DEPTH.with(|depth| depth.get() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suppress_guard_resets_when_dropped() {
        assert!(!suppressed());
        {
            let outer = SuppressGuard::arm();
            assert!(suppressed());
            {
                let _inner = SuppressGuard::arm();
                assert!(suppressed());
                drop(outer);
                assert!(suppressed());
            }
            assert!(!suppressed());
        }
        assert!(!suppressed());
    }
}
