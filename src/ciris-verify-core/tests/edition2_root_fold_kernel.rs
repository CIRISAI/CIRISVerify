//! CIRISKernel's reference cases for what a reader acts on at the tips of a
//! trust root's lineage, replayed through `edition2::root_fold`.
//!
//! `tests/vectors/edition2/genesis/kernel_root_reader.json` is CIRISKernel's
//! `crates/ciris-kernel/tests/fixtures/root_reader.json` (branch `root-fold`
//! 272fcd6), byte for byte, written by its model `models/trust_root/root.py`.
//! The model names keys and bundles by short names; here each name is its
//! SHA-256. Each bundle's own count (the model's `counted`) is restated in
//! this test, since `root_fold` reads bundles whose count another reader has
//! concluded; its `meets` is the module's.

use std::collections::{BTreeMap, BTreeSet};

use ciris_verify_core::edition2::root_fold::{Lineage, Reader, ReaderAnchor, RootBundle};
use ciris_verify_core::edition2::Digest32;
use serde_json::Value as J;
use sha2::Digest as _;

const FILE: &str = include_str!("vectors/edition2/genesis/kernel_root_reader.json");
const FILE_SHA256: &str = "196afcde24e602a37dcbbcaaf7463ff0407eb093d1d092330b49aa9e600f96d0";

fn id(name: &str) -> Digest32 {
    sha2::Sha256::digest(name.as_bytes()).into()
}

fn names(v: &J) -> Vec<&str> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect()
}

fn ids(v: &J) -> BTreeSet<Digest32> {
    names(v).into_iter().map(id).collect()
}

/// The model's bundle, by name.
struct Named<'a> {
    name: &'a str,
    prev: Vec<&'a str>,
    version: u64,
    family: &'a str,
    holders: BTreeSet<&'a str>,
    seats: BTreeSet<&'a str>,
    charter: &'a str,
    recovers: Option<(&'a str, &'a str)>,
    /// The keys whose statement carries the bundle's `iat`.
    stmts: BTreeSet<String>,
}

fn named(b: &J) -> Named<'_> {
    let iat = &b["iat"];
    Named {
        name: b["id"].as_str().unwrap(),
        prev: names(&b["prev"]),
        version: b["version"].as_u64().unwrap(),
        family: b["family"].as_str().unwrap(),
        holders: names(&b["holders"]).into_iter().collect(),
        seats: names(&b["seats"]).into_iter().collect(),
        charter: b["charter"].as_str().unwrap(),
        recovers: b["recovers"]
            .as_array()
            .map(|r| (r[0].as_str().unwrap(), r[1].as_str().unwrap())),
        stmts: b["stmts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| s[1] == *iat)
            .map(|s| s[0].as_str().unwrap().to_owned())
            .collect(),
    }
}

fn root_bundle(n: &Named<'_>, concluded: bool) -> RootBundle {
    RootBundle {
        id: id(n.name),
        prev: n.prev.iter().map(|p| id(p)).collect(),
        version: u32::try_from(n.version).unwrap(),
        holders: n.holders.iter().map(|k| id(k)).collect(),
        seats: n.seats.iter().map(|k| id(k)).collect(),
        regime: n.charter.as_bytes().to_vec(),
        voices: n.stmts.iter().map(|k| id(k)).collect(),
        recovers: n.recovers.map(|(a, b)| (id(a), id(b))),
        concluded,
    }
}

/// The model's `past`, by name.
fn past<'a>(by: &BTreeMap<&'a str, &Named<'a>>, i: &str, out: &mut BTreeSet<&'a str>) {
    for p in &by[i].prev {
        if by.contains_key(p) && out.insert(p) {
            past(by, p, out);
        }
    }
}

/// The model's `consistent` and `recovery_ok`, and its count through the
/// module's `meets`: each bundle's own conclusion, predecessors first.
fn conclude<'a>(ns: &[Named<'a>], owners: &BTreeMap<Digest32, Digest32>) -> BTreeSet<&'a str> {
    let by: BTreeMap<&str, &Named<'_>> = ns.iter().map(|n| (n.name, n)).collect();
    let raw: Vec<RootBundle> = ns.iter().map(|n| root_bundle(n, false)).collect();
    let lineage = Lineage::new(&raw, &[], owners);
    let mut done: BTreeMap<&str, bool> = BTreeMap::new();
    while done.len() < ns.len() {
        let before = done.len();
        for (n, rb) in ns.iter().zip(&raw) {
            if done.contains_key(n.name) {
                continue;
            }
            if n.prev.iter().any(|p| !by.contains_key(p)) {
                done.insert(n.name, false);
                continue;
            }
            if n.prev.iter().any(|p| !done.contains_key(p)) {
                continue;
            }
            let ps: Vec<&Named<'_>> = n.prev.iter().map(|p| by[p]).collect();
            let mut pasts = BTreeSet::new();
            past(&by, n.name, &mut pasts);
            let consistent = ps.is_empty()
                || (n.version == ps.iter().map(|p| p.version).max().unwrap() + 1
                    && ps.iter().all(|p| p.family == n.family)
                    && (ps.len() < 2 || {
                        let first = ps
                            .iter()
                            .min_by_key(|p| (std::cmp::Reverse(p.version), p.name))
                            .unwrap()
                            .name;
                        let in_anothers_past = n.prev.iter().any(|a| {
                            n.prev.iter().any(|c| {
                                let mut pc = BTreeSet::new();
                                past(&by, c, &mut pc);
                                pc.contains(a)
                            })
                        });
                        n.prev[0] == first && !in_anothers_past
                    }));
            let ok = if !consistent || n.prev.iter().any(|p| !done[p]) {
                false
            } else if ps.is_empty() {
                !n.holders.is_empty() && n.holders.iter().all(|h| n.stmts.contains(*h))
            } else if let Some((h, new)) = n.recovers {
                // A holder's own recovery: under its recovery key, changing
                // only its own seat, its commitment not spent in its past.
                let p = ps[0];
                let want: BTreeSet<&str> = p
                    .holders
                    .iter()
                    .map(|k| if *k == h { new } else { *k })
                    .collect();
                ps.len() == 1
                    && n.stmts.contains(&format!("r:{h}"))
                    && n.holders == want
                    && n.seats == p.seats
                    && n.charter == p.charter
                    && !pasts
                        .iter()
                        .any(|x| by[x].recovers.is_some_and(|r| r.0 == h))
            } else {
                lineage.meets(rb, &lineage.voices(rb), None)
            };
            done.insert(n.name, ok);
        }
        assert!(done.len() > before, "a cycle in the fixture");
    }
    done.into_iter()
        .filter(|(_, v)| *v)
        .map(|(k, _)| k)
        .collect()
}

#[test]
fn kernel_root_reader_cases() {
    assert_eq!(
        hex::encode(sha2::Sha256::digest(FILE.as_bytes())),
        FILE_SHA256
    );
    let f: J = serde_json::from_str(FILE).unwrap();
    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 22);
    let mut bad = Vec::new();
    for c in cases {
        let name = c["name"].as_str().unwrap();
        assert!(c["revokes"].as_array().unwrap().is_empty(), "{name}");
        let ns: Vec<Named<'_>> = c["bundles"].as_array().unwrap().iter().map(named).collect();
        // A holder is one voice whatever key it signs with: its key, its
        // recovery key, and the key a recovery seats.
        let mut owners: BTreeMap<Digest32, Digest32> = BTreeMap::new();
        for n in &ns {
            if let Some((h, new)) = n.recovers {
                owners.insert(id(new), id(h));
                owners.insert(id(&format!("r:{h}")), id(h));
            }
        }
        let concluded = conclude(&ns, &owners);
        let bundles: Vec<RootBundle> = ns
            .iter()
            .map(|n| root_bundle(n, concluded.contains(n.name)))
            .collect();
        let lineage = Lineage::new(&bundles, &[], &owners);
        let reader = Reader {
            anchor: c["reader"]["anchor"]
                .as_str()
                .map(|a| ReaderAnchor::Bundle(id(a))),
            acks: names(&c["reader"]["acks"]).into_iter().map(id).collect(),
        };
        let Some(got) = lineage.in_force(&reader) else {
            bad.push(format!("{name}: rooted on nothing"));
            continue;
        };
        let heads: BTreeSet<Digest32> = got.heads.iter().copied().collect();
        if heads != ids(&c["tips"]) {
            bad.push(format!("{name}: tips"));
        }
        if got.holders != ids(&c["holders"]) {
            let back: Vec<&str> = ns
                .iter()
                .flat_map(|n| n.holders.iter().copied())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .filter(|k| got.holders.contains(&id(k)))
                .collect();
            bad.push(format!("{name}: holders, got {back:?}"));
        }
        if got.seats != ids(&c["seats"]) {
            bad.push(format!("{name}: seats"));
        }
    }
    assert!(bad.is_empty(), "\n{}", bad.join("\n"));
}
