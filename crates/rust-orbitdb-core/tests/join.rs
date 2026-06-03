//! Multi-writer join conformance (GLP-0003 P03f): two writers append
//! concurrently to the same log, one joins the other (concurrent heads), then a
//! converging append covers both. Both writers' entries are Rust-signed; CIDs
//! and head progression must match @orbitdb/core.

use ipld_core::ipld::Ipld;
use rust_orbitdb_core::Log;
use serde_json::Value;

const JOINS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../node/orbitdb-fixtures/corpus/joins.json"
));

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

fn writer(spec: &Value, who: &str, log_id: &str) -> Log {
    Log::new(
        log_id,
        spec[who]["key"].as_str().unwrap(),
        spec[who]["identityHash"].as_str().unwrap(),
        hex::decode(spec[who]["innerPrivateKeyHex"].as_str().unwrap()).unwrap(),
    )
}

#[test]
fn concurrent_join_then_converge_matches_orbitdb() {
    let specs: Vec<Value> = serde_json::from_str(JOINS).unwrap();
    for spec in specs {
        let log_id = spec["logId"].as_str().unwrap();
        let mut log_a = writer(&spec, "writerA", log_id);
        let mut log_b = writer(&spec, "writerB", log_id);

        let ea = log_a.append(Ipld::String("from-A".into())).unwrap();
        let eb = log_b.append(Ipld::String("from-B".into())).unwrap();
        assert_eq!(
            ea.cid().unwrap(),
            spec["ea"]["cid"].as_str().unwrap(),
            "ea cid"
        );
        assert_eq!(
            eb.cid().unwrap(),
            spec["eb"]["cid"].as_str().unwrap(),
            "eb cid"
        );

        // A joins B's concurrent entry -> two heads.
        log_a.join_entry(eb).unwrap();
        assert_eq!(
            log_a.head_cids().unwrap(),
            strs(&spec["headsAfterJoin"]),
            "heads after join"
        );

        // Converging append covers both heads.
        let ec = log_a.append(Ipld::String("converge".into())).unwrap();
        assert_eq!(
            ec.cid().unwrap(),
            spec["ec"]["cid"].as_str().unwrap(),
            "ec cid"
        );
        assert_eq!(
            ec.next,
            strs(&spec["ec"]["next"]),
            "ec next covers both heads"
        );
        assert_eq!(
            ec.clock.time,
            spec["ec"]["clock"]["time"].as_u64().unwrap(),
            "ec clock"
        );
        assert_eq!(
            log_a.head_cids().unwrap(),
            strs(&spec["headsAfterConverge"]),
            "heads after converge"
        );
    }
}
