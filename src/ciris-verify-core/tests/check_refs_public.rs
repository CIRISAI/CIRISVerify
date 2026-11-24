//! `edition2::check_refs` as a producer calls it: the same shape check the
//! statement reader applies (23.5.1, CIRISPersist's request).
#![cfg(feature = "pqc")]

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::{check_refs, Invalid};

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn row_ref(n: u8) -> Value {
    Value::Array(vec![
        Value::int(2),
        Value::Array(vec![Value::int(-16), Value::Bytes(vec![n; 32])]),
    ])
}

fn map(members: Vec<(&str, Value)>) -> Value {
    Value::Map(members.into_iter().map(|(k, v)| (t(k), v)).collect())
}

#[test]
fn the_reader_and_a_producer_share_one_check() {
    // head beside target, as an authored withdraws carries them.
    assert_eq!(
        check_refs(&map(vec![("head", row_ref(1)), ("target", row_ref(2))])),
        Ok(())
    );
    // `under` is a set of exactly one row-ref.
    let under = |refs: Vec<Value>| map(vec![("also", map(vec![("under", Value::Array(refs))]))]);
    assert_eq!(check_refs(&under(vec![row_ref(1)])), Ok(()));
    assert_eq!(
        check_refs(&under(vec![row_ref(1), row_ref(2)])),
        Err(Invalid::Malformed { member: "under" })
    );
    // A bare row-ref where a set is wanted, an unknown role, an unknown member.
    assert_eq!(
        check_refs(&map(vec![("also", map(vec![("under", row_ref(1))]))])),
        Err(Invalid::Malformed { member: "also" })
    );
    assert_eq!(
        check_refs(&map(vec![(
            "also",
            map(vec![("other", Value::Array(vec![row_ref(1)]))])
        )])),
        Err(Invalid::UnexpectedMember { within: "also" })
    );
    assert_eq!(
        check_refs(&map(vec![("heads", row_ref(1))])),
        Err(Invalid::UnexpectedMember { within: "refs" })
    );
    // An edition-1 row-ref, and an empty refs map.
    let ed1 = Value::Array(vec![
        Value::int(1),
        Value::Array(vec![Value::int(-16), Value::Bytes(vec![1; 32])]),
    ]);
    assert_eq!(
        check_refs(&map(vec![("target", ed1)])),
        Err(Invalid::Malformed { member: "target" })
    );
    assert_eq!(
        check_refs(&Value::Map(vec![])),
        Err(Invalid::Malformed { member: "refs" })
    );
}
