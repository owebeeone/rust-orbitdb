//! JS OrbitDB conformance: the Rust entry encoding, CID, and signature must
//! match the `@orbitdb/core@4.0.0` fixture oracle generated under
//! `node/orbitdb-fixtures` (GLP-0003 P01/P02). Iterates the whole corpus.

use ipld_core::ipld::Ipld;
use rust_orbitdb_core::{Clock, Entry};
use serde_json::Value;

const CORPUS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../node/orbitdb-fixtures/corpus/entries.json"
));

/// Convert a JSON payload value into the IPLD data model (the payloads used in
/// the corpus are strings, integers, and nested string/int maps).
fn json_to_ipld(v: &Value) -> Ipld {
    match v {
        Value::Null => Ipld::Null,
        Value::Bool(b) => Ipld::Bool(*b),
        Value::Number(n) => Ipld::Integer(n.as_i64().expect("corpus uses integers") as i128),
        Value::String(s) => Ipld::String(s.clone()),
        Value::Array(a) => Ipld::List(a.iter().map(json_to_ipld).collect()),
        Value::Object(o) => Ipld::Map(
            o.iter()
                .map(|(k, v)| (k.clone(), json_to_ipld(v)))
                .collect(),
        ),
    }
}

fn strs(e: &Value, k: &str) -> Vec<String> {
    e[k].as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

fn entry_of(case: &Value) -> Entry {
    let e = &case["expected"];
    Entry {
        v: e["v"].as_u64().unwrap() as u8,
        id: case["input"]["logId"].as_str().unwrap().to_string(),
        key: e["key"].as_str().unwrap().to_string(),
        sig: e["sig"].as_str().unwrap().to_string(),
        next: strs(e, "next"),
        refs: strs(e, "refs"),
        clock: Clock {
            id: e["clock"]["id"].as_str().unwrap().to_string(),
            time: e["clock"]["time"].as_u64().unwrap(),
        },
        payload: json_to_ipld(&e["payload"]),
        identity: e["identity"].as_str().unwrap().to_string(),
    }
}

fn corpus() -> Vec<Value> {
    serde_json::from_str::<Vec<Value>>(CORPUS).expect("corpus is valid JSON")
}

#[test]
fn full_entry_encodes_to_canonical_bytes() {
    for case in corpus() {
        let desc = case["description"].as_str().unwrap();
        let got = hex::encode(entry_of(&case).encode().unwrap());
        assert_eq!(
            got,
            case["expected"]["bytesHex"].as_str().unwrap(),
            "bytes mismatch: {desc}"
        );
    }
}

#[test]
fn signed_projection_matches() {
    for case in corpus() {
        let desc = case["description"].as_str().unwrap();
        let got = hex::encode(entry_of(&case).signed_bytes().unwrap());
        assert_eq!(
            got,
            case["expected"]["signedBytesHex"].as_str().unwrap(),
            "signed bytes mismatch: {desc}"
        );
    }
}

#[test]
fn cid_matches_orbitdb_hash() {
    for case in corpus() {
        let desc = case["description"].as_str().unwrap();
        assert_eq!(
            entry_of(&case).cid().unwrap(),
            case["expected"]["cid"].as_str().unwrap(),
            "cid mismatch: {desc}"
        );
    }
}

#[test]
fn signatures_verify() {
    for case in corpus() {
        let desc = case["description"].as_str().unwrap();
        assert!(
            entry_of(&case).verify_signature().unwrap(),
            "sig failed: {desc}"
        );
    }
}

#[test]
fn tampered_payload_is_rejected() {
    let case = &corpus()[0];
    let mut entry = entry_of(case);
    entry.payload = Ipld::String("HELLO".to_string());
    assert!(!entry.verify_signature().unwrap());
}

#[test]
fn tampered_signature_is_rejected() {
    let case = &corpus()[0];
    let mut entry = entry_of(case);
    let mut s = entry.sig.clone();
    let last = s.pop().unwrap();
    s.push(if last == '0' { '1' } else { '0' });
    entry.sig = s;
    assert!(!entry.verify_signature().unwrap_or(false));
}
