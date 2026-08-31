use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    inner: Arc<CancellationState>,
}

#[derive(Debug, Default)]
struct CancellationState {
    cancelled: AtomicBool,
    notify: Notify,
}

impl CancellationToken {
    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            self.inner.notify.notify_waiters();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RevocationHandle {
    revoked: CancellationToken,
}

impl RevocationHandle {
    pub fn revoke(&self) {
        self.revoked.cancel();
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.is_cancelled()
    }

    #[cfg(test)]
    pub(crate) async fn revoked(&self) {
        self.revoked.cancelled().await;
    }
}
