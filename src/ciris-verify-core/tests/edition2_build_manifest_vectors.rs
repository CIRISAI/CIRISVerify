//! Replays `tests/vectors/edition2/build_manifest/build_manifest_blob_v1.json`
//! (`gen_build_manifest_blob_v1.py`, independent of verify): the
//! `ciris-binary-manifest/1` blob of FSD-008 §6, its function-table Merkle
//! root per leaf count, and its refusals by token.
#![cfg(feature = "pqc")]

use ciris_verify_core::edition2::build_manifest::{
    self, check_functions_root, decode, encode, functions_root, leaf_bytes, leaf_hash,
    BinaryManifest, FunctionLeaf, FORMAT, MAX_BLOB_LEN,
};
use serde_json::Value as J;

const FILE: &str = include_str!("vectors/edition2/build_manifest/build_manifest_blob_v1.json");
/// SHA-256 of the file, pinned so a regeneration is a visible change.
const FILE_SHA256: &str = "792c168b21a5f970ae79327344e9cbbdecc249049d6db5bb59923f8a1ed64e65";

fn file() -> J {
    serde_json::from_str(FILE).unwrap()
}

fn hx(v: &J) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn h32(v: &J) -> [u8; 32] {
    hx(v).try_into().unwrap()
}

fn leaf(f: &J) -> FunctionLeaf {
    FunctionLeaf {
        name: f["name"].as_str().unwrap().to_owned(),
        offset: f["offset"].as_u64().unwrap(),
        size: f["size"].as_u64().unwrap(),
        hash: h32(&f["hash"]),
    }
}

fn bytes_of(c: &J) -> Vec<u8> {
    if let Some(h) = c.get("blob_hex") {
        return hx(h);
    }
    let b = &c["blob"];
    let mut out = hx(&b["head_hex"]);
    let byte = hx(&b["run_byte_hex"])[0];
    out.resize(
        out.len() + usize::try_from(b["run_len"].as_u64().unwrap()).unwrap(),
        byte,
    );
    out.extend(hx(&b["tail_hex"]));
    out
}

#[test]
fn file_is_pinned() {
    use sha2::Digest as _;
    assert_eq!(
        hex::encode(sha2::Sha256::digest(FILE.as_bytes())),
        FILE_SHA256
    );
    let f = file();
    assert_eq!(f["format"], FORMAT);
    assert_eq!(f["max_blob_len"].as_u64().unwrap(), MAX_BLOB_LEN as u64);
}

#[test]
fn merkle_known_answers() {
    let f = file();
    let cases = f["merkle"].as_array().unwrap();
    let counts: Vec<u64> = cases
        .iter()
        .map(|c| c["leaf_count"].as_u64().unwrap())
        .collect();
    assert_eq!(counts, [1, 2, 3, 5, 96]);
    for c in cases {
        let leaves: Vec<FunctionLeaf> = c["functions"]
            .as_array()
            .unwrap()
            .iter()
            .map(leaf)
            .collect();
        for (i, l) in leaves.iter().enumerate() {
            assert_eq!(
                leaf_bytes(l),
                hx(&c["leaf_bytes_hex"][i]),
                "{} leaf {i}",
                c["id"]
            );
            assert_eq!(
                leaf_hash(l).to_vec(),
                hx(&c["leaf_hashes_hex"][i]),
                "{} hash {i}",
                c["id"]
            );
        }
        let root = h32(&c["root_hex"]);
        assert_eq!(functions_root(&leaves), root, "{}", c["id"]);
        // The root does not depend on the order the leaves are given in.
        let mut rev = leaves.clone();
        rev.reverse();
        assert_eq!(functions_root(&rev), root, "{} reversed", c["id"]);
        assert_eq!(check_functions_root(&leaves, &root), Ok(()));
    }
}

#[test]
fn valid_blobs_decode_and_re_encode() {
    let f = file();
    let cases = f["valid"].as_array().unwrap();
    assert_eq!(cases.len(), 10);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let bytes = bytes_of(c);
        let m = decode(&bytes).unwrap_or_else(|e| panic!("{id}: {e}"));
        let e = &c["expect"];
        assert_eq!(m.project, e["project"].as_str().unwrap(), "{id}");
        assert_eq!(m.version, e["version"].as_str().unwrap(), "{id}");
        assert_eq!(m.target, e["target"].as_str().unwrap(), "{id}");
        assert_eq!(m.binary_hash, h32(&e["binary_hash"]), "{id}");
        assert_eq!(m.functions_root, h32(&e["functions_root_hex"]), "{id}");
        assert_eq!(m.generated_at, e["generated_at"].as_str().unwrap(), "{id}");
        assert_eq!(m.tool, e["tool"].as_str().unwrap(), "{id}");
        let want: Option<Vec<FunctionLeaf>> = e["functions"]
            .as_array()
            .map(|a| a.iter().map(leaf).collect());
        assert_eq!(m.functions, want, "{id}");
        assert_eq!(encode(&m).unwrap(), bytes, "{id}: re-encode");
        // The producer path gives the same bytes.
        let fs = want.clone().unwrap_or_else(|| {
            let twin = id.replace("root_only", "inline");
            let t = cases.iter().find(|c| c["id"] == twin.as_str()).unwrap();
            t["expect"]["functions"]
                .as_array()
                .unwrap()
                .iter()
                .map(leaf)
                .collect()
        });
        let built = BinaryManifest::new(
            &m.project,
            &m.version,
            &m.target,
            m.binary_hash,
            fs,
            want.is_some(),
            &m.generated_at,
            &m.tool,
        )
        .unwrap();
        assert_eq!(encode(&built).unwrap(), bytes, "{id}: producer");
    }
}

#[test]
fn refusals_by_token() {
    let f = file();
    let cases = f["refusals"].as_array().unwrap();
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let err = decode(&bytes_of(c)).expect_err(id);
        assert_eq!(err.token(), c["expect"].as_str().unwrap(), "{id}: {err:?}");
        assert_eq!(
            err.detail(),
            c.get("detail").and_then(J::as_str),
            "{id}: {err:?}"
        );
    }
    let mut tokens: Vec<&str> = cases
        .iter()
        .map(|c| c["expect"].as_str().unwrap())
        .collect();
    tokens.sort_unstable();
    tokens.dedup();
    assert_eq!(
        tokens,
        [
            "build_manifest_empty_functions",
            "build_manifest_float",
            "build_manifest_functions_root_mismatch",
            "build_manifest_malformed",
            "build_manifest_missing_member",
            "build_manifest_not_a_map",
            "build_manifest_not_deterministic",
            "build_manifest_oversize",
            "build_manifest_unknown_member",
            "build_manifest_wrong_format",
        ]
    );
}

#[test]
fn error_display_carries_token() {
    let e = build_manifest::BlobError::MissingMember { member: "tool" };
    assert_eq!(e.to_string(), "build_manifest_missing_member: tool");
}
