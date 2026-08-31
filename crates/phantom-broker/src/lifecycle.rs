//! Closed request-lifecycle transition validator.
//!
//! This production type validates local state transitions, but is not durable
//! storage. Active broker integration must persist the resulting generation in
//! the replay store before treating a transition as committed.

use phantom_authority::ActionId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestState {
    Draft,
    AwaitingAuthority,
    Denied,
    Expired,
    Cancelled,
    GrantReserved,
    LeaseActive,
    Executing,
    Completed,
    Failed,
    Revoked,
}

impl RequestState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Denied
                | Self::Expired
                | Self::Cancelled
                | Self::Completed
                | Self::Failed
                | Self::Revoked
        )
    }

    fn can_transition_to(self, next: Self) -> bool {
        match self {
            Self::Draft => matches!(next, Self::AwaitingAuthority | Self::Cancelled),
            Self::AwaitingAuthority => matches!(
                next,
                Self::Denied | Self::Expired | Self::Cancelled | Self::GrantReserved
            ),
            Self::GrantReserved => matches!(
                next,
                Self::LeaseActive
                    | Self::Denied
                    | Self::Expired
                    | Self::Cancelled
                    | Self::Failed
                    | Self::Revoked
            ),
            Self::LeaseActive => matches!(
                next,
                Self::Executing | Self::Expired | Self::Cancelled | Self::Failed | Self::Revoked
            ),
            Self::Executing => matches!(next, Self::Completed | Self::Failed | Self::Revoked),
            Self::Denied
            | Self::Expired
            | Self::Cancelled
            | Self::Completed
            | Self::Failed
            | Self::Revoked => false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct RequestLifecycle {
    action_id: ActionId,
    state: RequestState,
    generation: u64,
}

impl RequestLifecycle {
    pub fn new(action_id: ActionId) -> Self {
        Self {
            action_id,
            state: RequestState::Draft,
            generation: 0,
        }
    }

    pub fn state(&self) -> RequestState {
        self.state
    }
    pub fn action_id(&self) -> &ActionId {
        &self.action_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Compare-and-swap one legal lifecycle transition.
    pub fn compare_and_swap(
        &mut self,
        expected_state: RequestState,
        expected_generation: u64,
        next: RequestState,
    ) -> Result<(), LifecycleError> {
        if self.state != expected_state || self.generation != expected_generation {
            return Err(LifecycleError::StaleGeneration {
                actual_state: self.state,
                actual_generation: self.generation,
            });
        }
        if !self.state.can_transition_to(next) {
            return Err(LifecycleError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(LifecycleError::GenerationExhausted)?;
        self.state = next;
        self.generation = next_generation;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LifecycleError {
    #[error("stale lifecycle generation {actual_generation} in state {actual_state:?}")]
    StaleGeneration {
        actual_state: RequestState,
        actual_generation: u64,
    },
    #[error("invalid lifecycle transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: RequestState,
        to: RequestState,
    },
    #[error("lifecycle generation exhausted")]
    GenerationExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lifecycle() -> RequestLifecycle {
        RequestLifecycle::new(format!("act_{}", "01".repeat(16)).parse().unwrap())
    }

    #[test]
    fn legal_lifecycle_reaches_completion() {
        let mut lifecycle = lifecycle();
        for next in [
            RequestState::AwaitingAuthority,
            RequestState::GrantReserved,
            RequestState::LeaseActive,
            RequestState::Executing,
            RequestState::Completed,
        ] {
            let prior_state = lifecycle.state;
            let prior_generation = lifecycle.generation;
            lifecycle
                .compare_and_swap(prior_state, prior_generation, next)
                .unwrap();
        }
        assert!(lifecycle.state.is_terminal());
        assert_eq!(lifecycle.generation, 5);
    }

    #[test]
    fn exhausted_generation_does_not_mutate_state() {
        let mut lifecycle = RequestLifecycle {
            action_id: format!("act_{}", "01".repeat(16)).parse().unwrap(),
            state: RequestState::Draft,
            generation: u64::MAX,
        };
        let before = (lifecycle.state(), lifecycle.generation());

        assert!(matches!(
            lifecycle.compare_and_swap(
                RequestState::Draft,
                u64::MAX,
                RequestState::AwaitingAuthority
            ),
            Err(LifecycleError::GenerationExhausted)
        ));
        assert_eq!((lifecycle.state(), lifecycle.generation()), before);
    }

    #[test]
    fn stale_and_illegal_transitions_fail_closed() {
        let mut lifecycle = lifecycle();
        assert!(matches!(
            lifecycle.compare_and_swap(RequestState::Draft, 1, RequestState::AwaitingAuthority),
            Err(LifecycleError::StaleGeneration { .. })
        ));
        assert!(matches!(
            lifecycle.compare_and_swap(RequestState::Draft, 0, RequestState::Completed),
            Err(LifecycleError::InvalidTransition { .. })
        ));
        assert_eq!(lifecycle.state, RequestState::Draft);
        assert_eq!(lifecycle.generation, 0);
    }

    #[test]
    fn terminal_states_cannot_be_resurrected() {
        let mut lifecycle = lifecycle();
        lifecycle
            .compare_and_swap(RequestState::Draft, 0, RequestState::Cancelled)
            .unwrap();
        assert!(lifecycle
            .compare_and_swap(RequestState::Cancelled, 1, RequestState::Draft)
            .is_err());
    }
}
