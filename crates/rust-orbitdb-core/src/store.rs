//! Entry storage seam (GLP-0003 P03b). The log depends on this trait, not a
//! concrete store, so an in-memory store, a crash-injecting store (P03h), or a
//! persistence adapter can be swapped without touching log semantics. I/O-free
//! at this layer: concrete OS/file stores live in host/adapter crates.

use crate::Entry;
use std::collections::HashMap;

/// Content-addressed entry storage, keyed by entry CID.
pub trait EntryStore {
    /// Fetch an entry by CID, if present.
    fn get(&self, cid: &str) -> Option<Entry>;
    /// Store an entry under its CID.
    fn put(&mut self, cid: &str, entry: Entry);
    /// Whether an entry with this CID is present.
    fn has(&self, cid: &str) -> bool {
        self.get(cid).is_some()
    }
}

/// Simple in-memory entry store.
#[derive(Debug, Default)]
pub struct MemoryStore {
    entries: HashMap<String, Entry>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the store holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl EntryStore for MemoryStore {
    fn get(&self, cid: &str) -> Option<Entry> {
        self.entries.get(cid).cloned()
    }

    fn put(&mut self, cid: &str, entry: Entry) {
        self.entries.insert(cid.to_string(), entry);
    }
}
