//! Clock comparison + conflict ordering (GLP-0003 P02f).
//! JS conformance against the `compareClocks` oracle, plus property tests for
//! the total-order axioms and the NoZeroes invariant.

use ipld_core::ipld::Ipld;
use proptest::prelude::*;
use rust_orbitdb_core::{compare_clocks, last_write_wins, no_zeroes, Clock, Entry};
use serde_json::Value;
use std::cmp::Ordering;

const CLOCKS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../node/orbitdb-fixtures/corpus/clocks.json"
));

fn ord_sign(o: Ordering) -> i64 {
    match o {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

fn clock_of(v: &Value) -> Clock {
    Clock {
        id: v["id"].as_str().unwrap().to_string(),
        time: v["time"].as_u64().unwrap(),
    }
}

#[test]
fn clock_comparison_matches_orbitdb() {
    let cases: Vec<Value> = serde_json::from_str(CLOCKS).unwrap();
    for case in cases {
        let a = clock_of(&case["a"]);
        let b = clock_of(&case["b"]);
        let want = case["cmp"].as_i64().unwrap();
        assert_eq!(
            ord_sign(compare_clocks(&a, &b)),
            want,
            "clock cmp mismatch: {}",
            case["description"].as_str().unwrap()
        );
    }
}

fn entry_with_clock(id: &str, time: u64) -> Entry {
    Entry {
        v: 2,
        id: "log-1".to_string(),
        key: String::new(),
        sig: String::new(),
        next: vec![],
        refs: vec![],
        clock: Clock {
            id: id.to_string(),
            time,
        },
        payload: Ipld::Null,
        identity: String::new(),
    }
}

#[test]
fn no_zeroes_rejects_equal_for_distinct_entries() {
    let a = entry_with_clock("x", 1);
    let b = entry_with_clock("y", 2);
    // A deliberately-bad comparator that ties must be rejected (mirrors OrbitDB).
    assert!(no_zeroes(|_, _| Ordering::Equal, &a, &b).is_err());
    // last_write_wins never ties, so the guarded call always succeeds.
    assert!(no_zeroes(last_write_wins, &a, &b).is_ok());
}

proptest! {
    #[test]
    fn clock_compare_is_antisymmetric(t1 in 0u64..1000, id1 in "[a-z]{1,5}", t2 in 0u64..1000, id2 in "[a-z]{1,5}") {
        let a = Clock { id: id1, time: t1 };
        let b = Clock { id: id2, time: t2 };
        prop_assert_eq!(compare_clocks(&a, &b), compare_clocks(&b, &a).reverse());
    }

    #[test]
    fn clock_equal_iff_identical(t1 in 0u64..1000, id1 in "[a-z]{1,5}", t2 in 0u64..1000, id2 in "[a-z]{1,5}") {
        let a = Clock { id: id1.clone(), time: t1 };
        let b = Clock { id: id2.clone(), time: t2 };
        let is_equal = compare_clocks(&a, &b) == Ordering::Equal;
        prop_assert_eq!(is_equal, t1 == t2 && id1 == id2);
    }

    #[test]
    fn lww_never_ties(t1 in 0u64..50, id1 in "[a-z]{1,3}", t2 in 0u64..50, id2 in "[a-z]{1,3}") {
        let a = entry_with_clock(&id1, t1);
        let b = entry_with_clock(&id2, t2);
        prop_assert_ne!(last_write_wins(&a, &b), Ordering::Equal);
        prop_assert!(no_zeroes(last_write_wins, &a, &b).is_ok());
    }
}
