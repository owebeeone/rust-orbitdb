#![forbid(unsafe_code)]

//! OrbitDB-compatible oplog entry: canonical dag-cbor encoding, CID, and
//! secp256k1 signature verification. Matches `@orbitdb/core@4.0.0` semantics
//! (see GLP-0003 fixtures). I/O-free; no libp2p, no async runtime.

use cid::multibase::Base;
use cid::Cid;
use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, VerifyingKey};
use multihash::Multihash;
use serde::Serialize;
use sha2::{Digest, Sha256};

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
    pub payload: String,
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
    payload: &'a str,
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
