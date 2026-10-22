use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Mutex, PoisonError},
};
use ulid::Ulid;

use crate::{PbcpError, common::unix_now};

/// Error returned by an external [ReplayStore] backend.
pub type BackendError = Box<dyn std::error::Error + Send + Sync>;

/// Storage recording used challenges to prevent replay.
pub struct ReplayStore {
    storage: Storage,
    margin: u64,
}

impl ReplayStore {
    /// Create an in-memory store, local to this process.
    pub fn new() -> Self {
        Self {
            storage: Storage::Memory(Mutex::default()),
            margin: 0,
        }
    }

    /// Create a store backed by an external check-and-insert function.
    ///
    /// The function receives a challenge identifier and a retention deadline
    /// (Unix seconds), which is the challenge expiration plus any configured
    /// margin. It must atomically record the identifier if it is absent, and
    /// keep it at least until the deadline. It returns `Ok(true)` only if
    /// this call recorded it, `Ok(false)` if the identifier was already
    /// present, and `Err` if the result could not be determined.
    pub fn from_fn(
        check_and_insert: impl Fn(
            Ulid,
            u64,
        ) -> Result<
            bool,
            Box<dyn std::error::Error + Send + Sync>,
        > + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            storage: Storage::External(Box::new(check_and_insert)),
            margin: 0,
        }
    }

    /// Retain entries for `seconds` beyond expiry to cover clock differences
    /// between verifiers or between a verifier and its backend.
    pub fn with_margin(mut self, seconds: u64) -> Self {
        self.margin = seconds;
        self
    }

    /// Atomically check whether a challenge identifier has been seen and
    /// record it if not.
    ///
    /// Returns `Ok(true)` the first time an identifier is presented and
    /// `Ok(false)` on every later attempt. Returns an error if an external
    /// store fails.
    pub fn check_and_insert(
        &self,
        id: Ulid,
        expires_at: u64,
    ) -> Result<bool, PbcpError> {
        let retain_until = expires_at.saturating_add(self.margin);

        match &self.storage {
            Storage::Memory(memory) => {
                let mut memory =
                    memory.lock().unwrap_or_else(PoisonError::into_inner);
                Ok(memory.check_and_insert(id, retain_until, unix_now()))
            }
            Storage::External(check_and_insert) => {
                Ok(check_and_insert(id, retain_until)?)
            }
        }
    }
}

impl Default for ReplayStore {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for ReplayStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayStore")
            .field("margin", &self.margin)
            .finish_non_exhaustive()
    }
}

enum Storage {
    Memory(Mutex<Memory>),
    External(
        Box<dyn Fn(Ulid, u64) -> Result<bool, BackendError> + Send + Sync>,
    ),
}

#[derive(Default)]
struct Memory {
    by_id: BTreeMap<Ulid, u64>,
    by_expiry: BTreeSet<(u64, Ulid)>,
}

impl Memory {
    fn check_and_insert(
        &mut self,
        id: Ulid,
        retain_until: u64,
        time: u64,
    ) -> bool {
        self.evict(time);

        if self.by_id.contains_key(&id) {
            return false;
        }
        self.by_id.insert(id, retain_until);
        self.by_expiry.insert((retain_until, id));
        true
    }

    fn evict(&mut self, time: u64) {
        while let Some(&(expiry, id)) = self.by_expiry.first() {
            if expiry >= time {
                break;
            }
            self.by_expiry.pop_first();
            self.by_id.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };

    use super::*;

    const TTL: u64 = 300;
    const MARGIN: u64 = 5;

    #[test]
    fn from_fn_returns_backend_result() {
        let id = Ulid::generate();

        let inserted = ReplayStore::from_fn(|_, _| Ok(true));
        let result = inserted.check_and_insert(id, unix_now() + TTL);
        assert!(result.is_ok());
        assert!(result.expect("result is Ok"));

        let present = ReplayStore::from_fn(|_, _| Ok(false));
        let result = present.check_and_insert(id, unix_now() + TTL);
        assert!(result.is_ok());
        assert!(!result.expect("result is Ok"));
    }

    #[test]
    fn margin_extends_retention_deadline() {
        let deadline = Arc::new(AtomicU64::new(0));
        let seen = Arc::clone(&deadline);
        let store = ReplayStore::from_fn(move |_, retain_until| {
            seen.store(retain_until, Ordering::SeqCst);
            Ok(true)
        })
        .with_margin(MARGIN);
        let id = Ulid::generate();

        let expires_at = unix_now() + TTL;

        store
            .check_and_insert(id, expires_at)
            .expect("backend always succeeds");
        assert_eq!(deadline.load(Ordering::SeqCst), expires_at + MARGIN);

        // Saturates instead of overflowing
        store
            .check_and_insert(id, u64::MAX)
            .expect("backend accepts saturated deadline");
        assert_eq!(deadline.load(Ordering::SeqCst), u64::MAX);
    }

    #[test]
    fn check_and_insert_detects_replay() {
        let store = ReplayStore::new();
        let expires_at = unix_now() + TTL;
        let id = Ulid::generate();

        let original = store.check_and_insert(id, expires_at);
        assert!(original.is_ok());
        assert!(original.expect("result is Ok"));

        let replayed = store.check_and_insert(id, expires_at);
        assert!(replayed.is_ok());
        assert!(!replayed.expect("result is Ok"));
    }

    #[test]
    fn default_memory_without_margin() {
        let store = ReplayStore::default();
        assert!(matches!(store.storage, Storage::Memory(_)));
        assert_eq!(store.margin, 0);
    }

    #[test]
    fn debug_shows_margin() {
        let store = ReplayStore::new().with_margin(MARGIN);
        assert_eq!(
            format!("{store:?}"),
            format!("ReplayStore {{ margin: {MARGIN}, .. }}")
        );
    }

    #[test]
    fn memory_evicts_after_deadline() {
        let mut memory = Memory::default();
        let id = Ulid::generate();

        assert!(memory.check_and_insert(id, 100, 0));
        // Still retained at the deadline itself
        assert!(!memory.check_and_insert(id, 100, 100));
        // Evicted once the deadline has passed
        assert!(memory.check_and_insert(id, 100, 101));
    }
}
