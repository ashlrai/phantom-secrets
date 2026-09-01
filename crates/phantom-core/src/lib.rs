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

thread_local! {
    static PROCESS_ENV_LOCK_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PROCESS_ENV_LOCK_GUARD: std::cell::RefCell<Option<std::sync::MutexGuard<'static, ()>>> =
        const { std::cell::RefCell::new(None) };
}

/// A process-wide environment mutex that is re-entrant on one thread.
///
/// Tests hold this guard while temporarily overriding `HOME`, and production
/// filesystem-root discovery takes the same guard while reading environment
/// state. Root discovery can therefore be nested inside a test's guarded call;
/// a plain `Mutex` deadlocks in that case, while crate-local mutexes race.
#[doc(hidden)]
pub struct ProcessEnvMutex(std::sync::Mutex<()>);

#[doc(hidden)]
pub struct ProcessEnvGuard {
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl ProcessEnvMutex {
    const fn new() -> Self {
        Self(std::sync::Mutex::new(()))
    }

    pub fn lock(&'static self) -> std::sync::LockResult<ProcessEnvGuard> {
        let nested = PROCESS_ENV_LOCK_DEPTH.with(|depth| {
            let current = depth.get();
            if current > 0 {
                depth.set(current + 1);
                true
            } else {
                false
            }
        });
        if nested {
            return Ok(ProcessEnvGuard {
                _not_send: std::marker::PhantomData,
            });
        }

        match self.0.lock() {
            Ok(guard) => {
                PROCESS_ENV_LOCK_GUARD.with(|slot| {
                    debug_assert!(slot.borrow().is_none());
                    *slot.borrow_mut() = Some(guard);
                });
                PROCESS_ENV_LOCK_DEPTH.with(|depth| depth.set(1));
                Ok(ProcessEnvGuard {
                    _not_send: std::marker::PhantomData,
                })
            }
            Err(poisoned) => {
                PROCESS_ENV_LOCK_GUARD.with(|slot| {
                    debug_assert!(slot.borrow().is_none());
                    *slot.borrow_mut() = Some(poisoned.into_inner());
                });
                PROCESS_ENV_LOCK_DEPTH.with(|depth| depth.set(1));
                Err(std::sync::PoisonError::new(ProcessEnvGuard {
                    _not_send: std::marker::PhantomData,
                }))
            }
        }
    }
}

impl Drop for ProcessEnvGuard {
    fn drop(&mut self) {
        PROCESS_ENV_LOCK_DEPTH.with(|depth| {
            let current = depth.get();
            debug_assert!(current > 0, "process environment guard depth underflow");
            let remaining = current.saturating_sub(1);
            depth.set(remaining);
            if remaining == 0 {
                PROCESS_ENV_LOCK_GUARD.with(|slot| {
                    let guard = slot.borrow_mut().take();
                    debug_assert!(guard.is_some());
                    drop(guard);
                });
            }
        });
    }
}

/// Process-wide serialization for code that reads or mutates environment
/// variables which influence Phantom's filesystem roots.
///
/// This is public only so Phantom workspace crates and their test suites share
/// one lock instead of accidentally coordinating on crate-local mutexes.
#[doc(hidden)]
pub static PROCESS_ENV_LOCK: ProcessEnvMutex = ProcessEnvMutex::new();

/// Crate-wide test helpers: a single `ENV_LOCK` shared by all modules whose
/// tests mutate process-wide env vars (`HOME`, `PHANTOM_AUDIT`, etc.).
/// Using separate per-module statics causes data-races when cargo runs tests
/// from different modules in parallel within the same test binary.
#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) use crate::PROCESS_ENV_LOCK as ENV_LOCK;
}

#[cfg(test)]
mod process_env_lock_tests {
    use super::PROCESS_ENV_LOCK;

    #[test]
    fn process_environment_lock_is_same_thread_reentrant() {
        let outer = PROCESS_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let inner = PROCESS_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        drop(inner);
        drop(outer);

        PROCESS_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
    }

    #[test]
    fn process_environment_lock_still_serializes_threads() {
        let outer = PROCESS_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _guard = PROCESS_ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            tx.send(()).unwrap();
        });

        assert!(rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err());
        drop(outer);
        rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap();
        worker.join().unwrap();
    }
}
