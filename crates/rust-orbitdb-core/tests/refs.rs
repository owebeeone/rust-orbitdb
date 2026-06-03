//! Refs / traverse conformance (GLP-0003 P03g): appending with referencesCount
//! must reproduce @orbitdb/core's skip-refs, and traverse/values order.

use ipld_core::ipld::Ipld;
use rust_orbitdb_core::Log;
use serde_json::Value;

const REFS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../node/orbitdb-fixtures/corpus/refs.json"
));

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn refs_and_traverse_match_orbitdb() {
    let specs: Vec<Value> = serde_json::from_str(REFS).unwrap();
    for spec in specs {
        let desc = spec["description"].as_str().unwrap();
        let rc = spec["referencesCount"].as_u64().unwrap() as usize;
        let mut log = Log::new(
            spec["logId"].as_str().unwrap(),
            spec["key"].as_str().unwrap(),
            spec["identityHash"].as_str().unwrap(),
            hex::decode(spec["innerPrivateKeyHex"].as_str().unwrap()).unwrap(),
        );
        for step in spec["steps"].as_array().unwrap() {
            let payload = Ipld::String(step["payload"].as_str().unwrap().to_string());
            let entry = log.append_with_refs(payload, rc).unwrap();
            assert_eq!(
                entry.cid().unwrap(),
                step["cid"].as_str().unwrap(),
                "{desc}: cid"
            );
            assert_eq!(entry.next, strs(&step["next"]), "{desc}: next");
            assert_eq!(
                entry.refs,
                strs(&step["refs"]),
                "{desc}: refs for '{}'",
                step["payload"]
            );
        }

        // values() = ascending (oldest first)
        let values: Vec<String> = log
            .values()
            .unwrap()
            .iter()
            .map(|e| e.cid().unwrap())
            .collect();
        assert_eq!(values, strs(&spec["values"]), "{desc}: values order");
    }
}
