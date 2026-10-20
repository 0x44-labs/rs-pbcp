use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, PoisonError},
};
use ulid::Ulid;

use crate::common::unix_now;

/// Registry of challenges by identifier that have already been used.
#[derive(Clone)]
pub struct ReplayStore {
    storage: Storage,
    margin: u64,
}

impl ReplayStore {
    /// Create an in-memory store, local to this process and its clones.
    pub fn new() -> Self {
        Self {
            storage: Storage::Memory(Arc::default()),
            margin: 0,
        }
    }

    /// Create a store backed by an external check-and-insert function.
    ///
    /// The function receives a challenge identifier and expiration (Unix
    /// seconds). It must atomically record the identifier if it is absent,
    /// keep it at least until the deadline, and return `true` only if this
    /// call recorded it.
    pub fn from_fn(
        check_and_insert: impl Fn(Ulid, u64) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            storage: Storage::External(Arc::new(check_and_insert)),
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
    /// Returns `true` the first time an identifier is presented and `false` on
    /// every later attempt.
    pub fn check_and_insert(&self, id: Ulid, expires_at: u64) -> bool {
        let retain_until = expires_at.saturating_add(self.margin);

        match &self.storage {
            Storage::Memory(memory) => {
                let mut memory =
                    memory.lock().unwrap_or_else(PoisonError::into_inner);
                memory.check_and_insert(id, retain_until, unix_now())
            }
            Storage::External(check_and_insert) => {
                check_and_insert(id, retain_until)
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

#[derive(Clone)]
enum Storage {
    Memory(Arc<Mutex<Memory>>),
    External(Arc<dyn Fn(Ulid, u64) -> bool + Send + Sync>),
}

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

impl Default for Memory {
    fn default() -> Self {
        Self {
            by_id: BTreeMap::new(),
            by_expiry: BTreeSet::new(),
        }
    }
}
