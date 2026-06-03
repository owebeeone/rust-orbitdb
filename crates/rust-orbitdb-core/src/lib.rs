#![forbid(unsafe_code)]

//! OrbitDB-compatible oplog entry: canonical dag-cbor encoding, CID, and
//! secp256k1 signature verification. Matches `@orbitdb/core@4.0.0` semantics
//! (see GLP-0003 fixtures). I/O-free; no libp2p, no async runtime.

use cid::multibase::Base;
use cid::Cid;
use ipld_core::ipld::Ipld;
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use multihash::Multihash;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

mod store;
pub use store::{EntryStore, MemoryStore};

/// dag-cbor codec code.
const DAG_CBOR: u64 = 0x71;
/// sha2-256 multihash code.
const SHA2_256: u64 = 0x12;

/// Lamport clock as stored in an entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Clock {
    pub id: String,
    pub time: u64,
}

/// A v2 OrbitDB oplog entry.
///
/// Field order is the canonical dag-cbor order (length-first, then bytewise):
/// `v, id, key, sig, next, refs, clock, payload, identity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    pub v: u8,
    pub id: String,
    pub key: String,
    pub sig: String,
    pub next: Vec<String>,
    pub refs: Vec<String>,
    pub clock: Clock,
    pub payload: Ipld,
    pub identity: String,
}

/// The signed projection of an entry: everything except `key`, `sig`, and
/// `identity` (this is the byte string `@orbitdb/core` signs). Canonical order:
/// `v, id, next, refs, clock, payload`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SignedEntry<'a> {
    v: u8,
    id: &'a str,
    next: &'a [String],
    refs: &'a [String],
    clock: &'a Clock,
    payload: &'a Ipld,
}

#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    #[error("dag-cbor encode failed: {0}")]
    Encode(#[from] serde_ipld_dagcbor::EncodeError<std::collections::TryReserveError>),
    #[error("malformed hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid public key")]
    PublicKey,
    #[error("invalid signature")]
    Signature,
    #[error("multihash wrap failed")]
    Multihash,
}

impl Entry {
    /// Canonical dag-cbor bytes of the full entry.
    pub fn encode(&self) -> Result<Vec<u8>, EntryError> {
        Ok(serde_ipld_dagcbor::to_vec(self)?)
    }

    /// dag-cbor bytes of the signed projection (the bytes that were signed).
    pub fn signed_bytes(&self) -> Result<Vec<u8>, EntryError> {
        let signed = SignedEntry {
            v: self.v,
            id: &self.id,
            next: &self.next,
            refs: &self.refs,
            clock: &self.clock,
            payload: &self.payload,
        };
        Ok(serde_ipld_dagcbor::to_vec(&signed)?)
    }

    /// CIDv1 (dag-cbor / sha2-256) of the full entry, base58btc-encoded — the
    /// OrbitDB entry hash string (e.g. `zdpu...`).
    pub fn cid(&self) -> Result<String, EntryError> {
        let bytes = self.encode()?;
        cid_of(&bytes)
    }

    /// Verifies the entry signature over its signed projection, against the
    /// entry's own `key`.
    pub fn verify_signature(&self) -> Result<bool, EntryError> {
        let signed = self.signed_bytes()?;
        verify_secp256k1(&self.key, &signed, &self.sig)
    }
}

/// CIDv1 (dag-cbor / sha2-256), base58btc-encoded.
pub fn cid_of(bytes: &[u8]) -> Result<String, EntryError> {
    let digest = Sha256::digest(bytes);
    let mh = Multihash::<64>::wrap(SHA2_256, &digest).map_err(|_| EntryError::Multihash)?;
    let cid = Cid::new_v1(DAG_CBOR, mh);
    cid.to_string_of_base(Base::Base58Btc)
        .map_err(|_| EntryError::Multihash)
}

/// Signs `message` with a 32-byte secp256k1 private scalar, producing a
/// DER-encoded ECDSA signature (hex), hashing with sha256 and using RFC6979
/// deterministic nonces — matching `@libp2p/crypto` / `@noble/secp256k1`.
pub fn sign_secp256k1(private_key: &[u8], message: &[u8]) -> Result<String, EntryError> {
    let sk = SigningKey::from_slice(private_key).map_err(|_| EntryError::PublicKey)?;
    let sig: Signature = sk.sign(message);
    Ok(hex::encode(sig.to_der()))
}

/// Verifies a secp256k1 ECDSA signature (DER hex) over `message`, hashing with
/// sha256, against a compressed-SEC1 public key (hex). Matches
/// `@libp2p/crypto` secp256k1 signing.
pub fn verify_secp256k1(
    public_key_hex: &str,
    message: &[u8],
    der_sig_hex: &str,
) -> Result<bool, EntryError> {
    let pk_bytes = hex::decode(public_key_hex)?;
    let sig_bytes = hex::decode(der_sig_hex)?;
    let vk = VerifyingKey::from_sec1_bytes(&pk_bytes).map_err(|_| EntryError::PublicKey)?;
    let sig = Signature::from_der(&sig_bytes).map_err(|_| EntryError::Signature)?;
    Ok(vk.verify(message, &sig).is_ok())
}

/// Compares two clocks the way `@orbitdb/core` `compareClocks` does: primary by
/// `time`, secondary by `id` (bytewise). Returns [`Ordering::Equal`] only when
/// both clocks are identical. Ids are ASCII hex in OrbitDB, so bytewise order
/// matches JS string order.
pub fn compare_clocks(a: &Clock, b: &Clock) -> Ordering {
    a.time.cmp(&b.time).then_with(|| a.id.cmp(&b.id))
}

/// Returned when a conflict comparator yields [`Ordering::Equal`] for two
/// distinct entries — OrbitDB's `NoZeroes` guard throws in this case, because
/// the log requires a strict total order over distinct entries.
#[derive(Debug, thiserror::Error)]
#[error("conflict tiebreaker returned zero for distinct entries")]
pub struct NoZeroError;

/// Last-Write-Wins entry ordering, matching `@orbitdb/core`: order by clock
/// (time then id); if the clocks are identical, the ultimate tiebreak takes the
/// first (left) entry, so `a` is treated as the winner. Never returns
/// [`Ordering::Equal`].
pub fn last_write_wins(a: &Entry, b: &Entry) -> Ordering {
    match compare_clocks(&a.clock, &b.clock) {
        Ordering::Equal => Ordering::Greater,
        ord => ord,
    }
}

/// Wraps a conflict comparator with OrbitDB's `NoZeroes` invariant: a zero
/// (Equal) result for distinct entries is an error, not a silent tie.
pub fn no_zeroes<F>(cmp: F, a: &Entry, b: &Entry) -> Result<Ordering, NoZeroError>
where
    F: Fn(&Entry, &Entry) -> Ordering,
{
    match cmp(a, b) {
        Ordering::Equal => Err(NoZeroError),
        ord => Ok(ord),
    }
}

/// An append-only oplog: holds all known entries and the current heads, and
/// appends signed entries matching `@orbitdb/core` `Log.append`. sans-io: the
/// signing key is supplied by the caller; identity hashing is treated as a
/// constant for a fixed identity.
pub struct Log {
    pub id: String,
    public_key: String,
    identity_hash: String,
    signing_key: Vec<u8>,
    heads: Vec<Entry>,
    store: Box<dyn EntryStore>,
}

impl Log {
    /// Creates an empty log for a fixed identity.
    pub fn new(
        id: impl Into<String>,
        public_key: impl Into<String>,
        identity_hash: impl Into<String>,
        signing_key: Vec<u8>,
    ) -> Self {
        Self {
            id: id.into(),
            public_key: public_key.into(),
            identity_hash: identity_hash.into(),
            signing_key,
            heads: Vec::new(),
            store: Box::new(MemoryStore::new()),
        }
    }

    /// Creates an empty log backed by a caller-supplied entry store (e.g. a
    /// crash-injecting store for fault tests).
    pub fn with_store(
        id: impl Into<String>,
        public_key: impl Into<String>,
        identity_hash: impl Into<String>,
        signing_key: Vec<u8>,
        store: Box<dyn EntryStore>,
    ) -> Self {
        Self {
            id: id.into(),
            public_key: public_key.into(),
            identity_hash: identity_hash.into(),
            signing_key,
            heads: Vec::new(),
            store,
        }
    }

    /// Current heads as CIDs, sorted descending by LWW (latest first) — the
    /// order `@orbitdb/core` `heads()` returns and uses for `next` pointers.
    pub fn head_cids(&self) -> Result<Vec<String>, EntryError> {
        let mut hs = self.heads.clone();
        hs.sort_by(last_write_wins);
        hs.reverse();
        hs.iter().map(Entry::cid).collect()
    }

    /// Appends a new entry with `referencesCount` 0 (no skip-refs).
    pub fn append(&mut self, payload: Ipld) -> Result<Entry, EntryError> {
        self.append_with_refs(payload, 0)
    }

    /// Appends a new entry: `next` = current heads, clock = max head time + 1,
    /// `refs` = skip-pointers from `getReferences`, signs, and replaces covered
    /// heads. Returns the entry.
    pub fn append_with_refs(
        &mut self,
        payload: Ipld,
        references_count: usize,
    ) -> Result<Entry, EntryError> {
        let mut heads_desc = self.heads.clone();
        heads_desc.sort_by(last_write_wins);
        heads_desc.reverse();
        let next: Vec<String> = heads_desc
            .iter()
            .map(Entry::cid)
            .collect::<Result<_, _>>()?;
        let refs = self.get_references(&heads_desc, references_count + heads_desc.len())?;
        let max_time = self.heads.iter().map(|e| e.clock.time).max().unwrap_or(0);
        let mut entry = Entry {
            v: 2,
            id: self.id.clone(),
            key: self.public_key.clone(),
            sig: String::new(),
            next,
            refs,
            clock: Clock {
                id: self.public_key.clone(),
                time: max_time + 1,
            },
            payload,
            identity: self.identity_hash.clone(),
        };
        let signed = entry.signed_bytes()?;
        entry.sig = sign_secp256k1(&self.signing_key, &signed)?;
        self.add_head(entry.clone())?;
        Ok(entry)
    }

    /// Joins a single entry produced elsewhere (a concurrent writer): verifies
    /// its signature, then merges it into the heads. Concurrent entries that do
    /// not cover each other both remain heads. Assumes the entry's causal
    /// dependencies are already present (shallow join).
    pub fn join_entry(&mut self, entry: Entry) -> Result<(), EntryError> {
        if !entry.verify_signature()? {
            return Err(EntryError::Signature);
        }
        self.add_head(entry)
    }

    /// All entries oldest-first (ascending) — `@orbitdb/core` `values()`.
    pub fn values(&self) -> Result<Vec<Entry>, EntryError> {
        let mut v = self.traverse(&self.heads, None)?;
        v.reverse();
        Ok(v)
    }

    /// Traverse the DAG from `roots` following `next`, yielding entries in
    /// descending conflict order. Faithful port of `@orbitdb/core` `traverse`;
    /// `stop_after` mirrors a count-based `shouldStopFn` (stop once that many
    /// entries have been yielded).
    pub fn traverse(
        &self,
        roots: &[Entry],
        stop_after: Option<usize>,
    ) -> Result<Vec<Entry>, EntryError> {
        use std::collections::HashSet;
        let mut stack = roots.to_vec();
        let mut traversed: HashSet<String> = HashSet::new();
        let mut fetched: HashSet<String> = HashSet::new();
        let mut to_fetch: Vec<String> = Vec::new();
        let mut yielded: Vec<Entry> = Vec::new();
        while !stack.is_empty() {
            stack.sort_by(last_write_wins);
            let entry = stack.pop().unwrap();
            let hash = entry.cid()?;
            if traversed.contains(&hash) {
                continue;
            }
            yielded.push(entry.clone());
            if let Some(n) = stop_after {
                if yielded.len() >= n {
                    break;
                }
            }
            traversed.insert(hash.clone());
            fetched.insert(hash.clone());
            for n in &entry.next {
                to_fetch.push(n.clone());
            }
            to_fetch.retain(|h| !traversed.contains(h) && !fetched.contains(h));
            let mut nexts: Vec<Entry> = Vec::new();
            for h in &to_fetch {
                if !traversed.contains(h) && !fetched.contains(h) {
                    fetched.insert(h.clone());
                    if let Some(e) = self.store.get(h) {
                        nexts.push(e);
                    }
                }
            }
            let mut next_to_fetch: Vec<String> = Vec::new();
            let mut seen: HashSet<String> = HashSet::new();
            for e in &nexts {
                for n in &e.next {
                    if seen.insert(n.clone()) {
                        next_to_fetch.push(n.clone());
                    }
                }
            }
            next_to_fetch.retain(|h| !traversed.contains(h) && !fetched.contains(h));
            to_fetch = next_to_fetch;
            let mut new_stack = nexts;
            new_stack.append(&mut stack);
            stack = new_stack;
        }
        Ok(yielded)
    }

    /// Skip-references for a new entry — port of `@orbitdb/core` `getReferences`.
    fn get_references(&self, heads: &[Entry], amount: usize) -> Result<Vec<String>, EntryError> {
        let yielded = self.traverse(heads, Some(amount))?;
        let refs: Vec<String> = yielded.iter().map(Entry::cid).collect::<Result<_, _>>()?;
        let start = heads.len();
        let end = amount.min(refs.len());
        Ok(if start < end {
            refs[start..end].to_vec()
        } else {
            Vec::new()
        })
    }

    /// Head-set update shared by append and join: store the entry, drop heads
    /// covered by its `next`, then add it if not already a head.
    fn add_head(&mut self, entry: Entry) -> Result<(), EntryError> {
        let entry_cid = entry.cid()?;
        self.store.put(&entry_cid, entry.clone());
        let covered: std::collections::HashSet<&String> = entry.next.iter().collect();
        let mut kept = Vec::new();
        for h in &self.heads {
            if !covered.contains(&h.cid()?) {
                kept.push(h.clone());
            }
        }
        let already_head = kept
            .iter()
            .any(|h| h.cid().map(|c| c == entry_cid).unwrap_or(false));
        if !already_head {
            kept.push(entry);
        }
        self.heads = kept;
        Ok(())
    }
}
