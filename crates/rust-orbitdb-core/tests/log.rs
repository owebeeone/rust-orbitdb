//! Log append conformance (GLP-0003 P03): replaying a linear append sequence in
//! Rust must reproduce @orbitdb/core's next/refs/clock/CID and head progression
//! byte-for-byte, including signing.

use ipld_core::ipld::Ipld;
use rust_orbitdb_core::Log;
use serde_json::Value;

const LOGS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../node/orbitdb-fixtures/corpus/logs.json"
));

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn linear_append_matches_orbitdb() {
    let logs: Vec<Value> = serde_json::from_str(LOGS).unwrap();
    for spec in logs {
        let signing_key = hex::decode(spec["innerPrivateKeyHex"].as_str().unwrap()).unwrap();
        let mut log = Log::new(
            spec["logId"].as_str().unwrap(),
            spec["key"].as_str().unwrap(),
            spec["identityHash"].as_str().unwrap(),
            signing_key,
        );

        for step in spec["steps"].as_array().unwrap() {
            let payload = Ipld::String(step["payload"].as_str().unwrap().to_string());
            let entry = log.append(payload).unwrap();

            assert_eq!(entry.cid().unwrap(), step["cid"].as_str().unwrap(), "cid");
            assert_eq!(entry.next, strs(&step["next"]), "next");
            assert_eq!(entry.refs, strs(&step["refs"]), "refs");
            assert_eq!(
                entry.clock.time,
                step["clock"]["time"].as_u64().unwrap(),
                "clock time"
            );
            assert_eq!(
                entry.clock.id,
                step["clock"]["id"].as_str().unwrap(),
                "clock id"
            );
            assert!(
                entry.verify_signature().unwrap(),
                "self-signed entry verifies"
            );
            assert_eq!(
                log.head_cids().unwrap(),
                strs(&step["headsAfter"]),
                "heads after"
            );
        }
    }
}
