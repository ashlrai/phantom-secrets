//! Test-only atomic lease ledger.
//!
//! Production must use a crash-safe transactional replay store. Keeping this
//! implementation behind `cfg(test)` prevents an in-memory ledger from being
//! mistaken for durable production authority.

use crate::lease::{LeaseBinding, LeaseBindingError};
use phantom_authority::{canonical_json_v1, CanonicalJsonError, LeaseId, UseCapacity};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

pub(crate) struct InMemoryLeaseLedger {
    state: Mutex<LedgerState>,
}

struct LedgerState {
    broker_generation: u64,
    seen_nonces: HashSet<String>,
    idempotency: HashMap<String, IdempotencyRecord>,
    leases: HashMap<LeaseId, LeaseRecord>,
}

struct IdempotencyRecord {
    request_fingerprint: Vec<u8>,
    lease_id: LeaseId,
}

struct LeaseRecord {
    binding: LeaseBinding,
    remaining_uses: u32,
    active_uses: u16,
    revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reservation {
    New(LeaseId),
    Existing(LeaseId),
}

impl InMemoryLeaseLedger {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(LedgerState {
                broker_generation: 1,
                seen_nonces: HashSet::new(),
                idempotency: HashMap::new(),
                leases: HashMap::new(),
            }),
        }
    }

    /// Atomically consume a private grant nonce, reserve its idempotency key,
    /// and create exactly one value-free lease record.
    pub(crate) fn reserve(
        &self,
        grant_nonce: &str,
        idempotency_key: &str,
        binding: LeaseBinding,
    ) -> Result<Reservation, LedgerError> {
        binding.validate()?;
        if grant_nonce.len() != 64
            || !grant_nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || idempotency_key.is_empty()
            || idempotency_key.len() > 128
        {
            return Err(LedgerError::InvalidReservationKey);
        }
        let request_fingerprint = canonical_json_v1(&binding)?;
        let mut state = self.state.lock().map_err(|_| LedgerError::Poisoned)?;

        if let Some(existing) = state.idempotency.get(idempotency_key) {
            return if existing.request_fingerprint == request_fingerprint {
                Ok(Reservation::Existing(existing.lease_id.clone()))
            } else {
                Err(LedgerError::IdempotencyCollision)
            };
        }
        if state.seen_nonces.contains(grant_nonce) {
            return Err(LedgerError::Replay);
        }
        if binding.broker_generation() != state.broker_generation {
            return Err(LedgerError::StaleBrokerGeneration);
        }
        if state.leases.contains_key(&binding.lease_id) {
            return Err(LedgerError::LeaseIdCollision);
        }

        state.seen_nonces.insert(grant_nonce.to_owned());
        state.idempotency.insert(
            idempotency_key.to_owned(),
            IdempotencyRecord {
                request_fingerprint,
                lease_id: binding.lease_id.clone(),
            },
        );
        let lease_id = binding.lease_id.clone();
        state.leases.insert(
            lease_id.clone(),
            LeaseRecord {
                remaining_uses: binding
                    .constraints()
                    .uses
                    .capacity
                    .limits()
                    .ok_or(LedgerError::InvalidBinding(
                        LeaseBindingError::NoUsableCapacity,
                    ))?
                    .0,
                binding,
                active_uses: 0,
                revoked: false,
            },
        );
        Ok(Reservation::New(lease_id))
    }

    pub(crate) fn begin_use(&self, lease_id: &LeaseId, now: u64) -> Result<(), LedgerError> {
        let mut state = self.state.lock().map_err(|_| LedgerError::Poisoned)?;
        let generation = state.broker_generation;
        let record = state
            .leases
            .get_mut(lease_id)
            .ok_or(LedgerError::UnknownLease)?;
        if record.revoked || record.binding.broker_generation() != generation {
            return Err(LedgerError::Revoked);
        }
        if !record.binding.active_at(now) {
            return Err(LedgerError::Expired);
        }
        let max_concurrent_uses = match record.binding.constraints().uses.capacity {
            UseCapacity::Bounded {
                max_concurrent_uses,
                ..
            } => max_concurrent_uses,
            UseCapacity::Denied => return Err(LedgerError::CapacityExhausted),
        };
        if record.remaining_uses == 0 || record.active_uses >= max_concurrent_uses {
            return Err(LedgerError::CapacityExhausted);
        }
        record.remaining_uses -= 1;
        record.active_uses += 1;
        Ok(())
    }

    pub(crate) fn finish_use(&self, lease_id: &LeaseId) -> Result<(), LedgerError> {
        let mut state = self.state.lock().map_err(|_| LedgerError::Poisoned)?;
        let record = state
            .leases
            .get_mut(lease_id)
            .ok_or(LedgerError::UnknownLease)?;
        if record.active_uses == 0 {
            return Err(LedgerError::NoActiveUse);
        }
        record.active_uses -= 1;
        Ok(())
    }

    pub(crate) fn simulate_restart(&self) -> Result<u64, LedgerError> {
        let mut state = self.state.lock().map_err(|_| LedgerError::Poisoned)?;
        state.broker_generation = state
            .broker_generation
            .checked_add(1)
            .ok_or(LedgerError::GenerationExhausted)?;
        for record in state.leases.values_mut() {
            record.revoked = true;
        }
        Ok(state.broker_generation)
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum LedgerError {
    #[error("invalid reservation key")]
    InvalidReservationKey,
    #[error("grant nonce replayed")]
    Replay,
    #[error("idempotency key reused for different request")]
    IdempotencyCollision,
    #[error("lease id collision")]
    LeaseIdCollision,
    #[error("stale broker generation")]
    StaleBrokerGeneration,
    #[error("unknown lease")]
    UnknownLease,
    #[error("lease revoked")]
    Revoked,
    #[error("lease expired")]
    Expired,
    #[error("lease use or concurrency capacity exhausted")]
    CapacityExhausted,
    #[error("lease has no active use")]
    NoActiveUse,
    #[error("broker generation exhausted")]
    GenerationExhausted,
    #[error("test ledger lock poisoned")]
    Poisoned,
    #[error(transparent)]
    InvalidBinding(#[from] LeaseBindingError),
    #[error(transparent)]
    Canonical(#[from] CanonicalJsonError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lease::test_support::binding;
    use std::sync::Arc;
    use std::thread;

    const NONCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn exact_idempotent_retry_returns_same_lease() {
        let ledger = InMemoryLeaseLedger::new();
        let binding = binding();
        let lease_id = binding.lease_id.clone();
        assert_eq!(
            ledger.reserve(NONCE, "request-1", binding.clone()).unwrap(),
            Reservation::New(lease_id.clone())
        );
        assert_eq!(
            ledger.reserve(NONCE, "request-1", binding).unwrap(),
            Reservation::Existing(lease_id)
        );
    }

    #[test]
    fn idempotency_collision_and_nonce_replay_fail_closed() {
        let ledger = InMemoryLeaseLedger::new();
        let binding = binding();
        ledger.reserve(NONCE, "request-1", binding.clone()).unwrap();

        let mut changed = binding.clone();
        changed.canonical_args_sha256 = "11".repeat(32).parse().unwrap();
        assert!(matches!(
            ledger.reserve(NONCE, "request-1", changed),
            Err(LedgerError::IdempotencyCollision)
        ));
        assert!(matches!(
            ledger.reserve(NONCE, "request-2", binding),
            Err(LedgerError::Replay)
        ));
    }

    #[test]
    fn concurrent_nonce_consumption_creates_exactly_one_lease() {
        let ledger = Arc::new(InMemoryLeaseLedger::new());
        let mut handles = Vec::new();
        for index in 0..32 {
            let ledger = Arc::clone(&ledger);
            let mut candidate = binding();
            candidate.lease_id = format!("lea_{index:032x}").parse().unwrap();
            handles.push(thread::spawn(move || {
                ledger.reserve(NONCE, &format!("request-{index}"), candidate)
            }));
        }

        let results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok(Reservation::New(_))))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(LedgerError::Replay)))
                .count(),
            31
        );
    }

    #[test]
    fn use_and_concurrency_limits_are_atomic() {
        let ledger = InMemoryLeaseLedger::new();
        let lease = binding();
        let lease_id = lease.lease_id.clone();
        ledger.reserve(NONCE, "request-1", lease).unwrap();
        ledger.begin_use(&lease_id, 10).unwrap();
        assert!(matches!(
            ledger.begin_use(&lease_id, 10),
            Err(LedgerError::CapacityExhausted)
        ));
        ledger.finish_use(&lease_id).unwrap();
        assert!(matches!(
            ledger.begin_use(&lease_id, 10),
            Err(LedgerError::CapacityExhausted)
        ));
    }

    #[test]
    fn restart_revokes_all_existing_leases() {
        let ledger = InMemoryLeaseLedger::new();
        let lease = binding();
        let lease_id = lease.lease_id.clone();
        ledger.reserve(NONCE, "request-1", lease).unwrap();
        assert_eq!(ledger.simulate_restart().unwrap(), 2);
        assert!(matches!(
            ledger.begin_use(&lease_id, 10),
            Err(LedgerError::Revoked)
        ));
    }
}
