//! JS OrbitDB conformance: the Rust entry encoding, CID, and signature must
//! match the `@orbitdb/core@4.0.0` fixture oracle generated under
//! `node/orbitdb-fixtures` (GLP-0003 P01/P02).

use rust_orbitdb_core::{Clock, Entry};
use serde_json::Value;

const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../node/orbitdb-fixtures/corpus/entry-create-hello.json"
));

fn load() -> (Entry, Value) {
    let v: Value = serde_json::from_str(FIXTURE).expect("fixture is valid JSON");
    let e = &v["expected"];
    let strs = |k: &str| -> Vec<String> {
        e[k].as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect()
    };
    let entry = Entry {
        v: e["v"].as_u64().unwrap() as u8,
        id: v["input"]["logId"].as_str().unwrap().to_string(),
        key: e["key"].as_str().unwrap().to_string(),
        sig: e["sig"].as_str().unwrap().to_string(),
        next: strs("next"),
        refs: strs("refs"),
        clock: Clock {
            id: e["clock"]["id"].as_str().unwrap().to_string(),
            time: e["clock"]["time"].as_u64().unwrap(),
        },
        payload: e["payload"].as_str().unwrap().to_string(),
        identity: e["identity"].as_str().unwrap().to_string(),
    };
    (entry, v)
}

#[test]
fn full_entry_encodes_to_canonical_bytes() {
    let (entry, v) = load();
    let got = hex::encode(entry.encode().unwrap());
    assert_eq!(got, v["expected"]["bytesHex"].as_str().unwrap());
}

#[test]
fn signed_projection_matches() {
    let (entry, v) = load();
    let got = hex::encode(entry.signed_bytes().unwrap());
    assert_eq!(got, v["expected"]["signedBytesHex"].as_str().unwrap());
}

#[test]
fn cid_matches_orbitdb_hash() {
    let (entry, v) = load();
    assert_eq!(entry.cid().unwrap(), v["expected"]["cid"].as_str().unwrap());
}

#[test]
fn signature_verifies() {
    let (entry, _) = load();
    assert!(entry.verify_signature().unwrap());
}

#[test]
fn tampered_payload_is_rejected() {
    let (mut entry, _) = load();
    entry.payload = "HELLO".to_string();
    assert!(!entry.verify_signature().unwrap());
}

#[test]
fn tampered_signature_is_rejected() {
    let (mut entry, _) = load();
    // flip the last hex nibble of the DER signature
    let mut s = entry.sig.clone();
    let last = s.pop().unwrap();
    let flipped = if last == '0' { '1' } else { '0' };
    s.push(flipped);
    entry.sig = s;
    // Either it fails to parse as a valid signature, or it verifies false.
    let ok = entry.verify_signature().unwrap_or(false);
    assert!(!ok);
}
