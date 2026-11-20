//! Replays `tests/vectors/fedcode/fedcode_e2_v1.json` (`gen_fedcode_e2.py`,
//! independent of verify) against `edition2::fedcode`: every valid code
//! decodes to its fields and re-encodes to the same text, every refusal gives
//! its token, and the transport-key check at resolution answers as stated.
#![cfg(feature = "pqc")]

use ciris_crypto::composite::CompositePublicKey;
use ciris_verify_core::edition2::fedcode::{AutoScope, FedCodeE2, Hint, Kind};
use ciris_verify_core::edition2::thumbprint;
use serde_json::Value as J;

const FILE: &str = include_str!("vectors/fedcode/fedcode_e2_v1.json");
/// SHA-256 of the file, pinned so a regeneration is a visible change.
const FILE_SHA256: &str = "6ba1623267b9ef442354e8c3d8aa22b3a7567ddc4121a525d66ef8b73cc18717";

fn file() -> J {
    serde_json::from_str(FILE).unwrap()
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::User => "user",
        Kind::Agent => "agent",
        Kind::Node => "node",
        Kind::Family => "family",
        Kind::Community => "community",
    }
}

fn hint_json(h: &Hint) -> J {
    use serde_json::json;
    match h {
        Hint::Tcp { host, port } => json!({"type": "tcp", "host": host, "port": port}),
        Hint::Udp { host, port } => json!({"type": "udp", "host": host, "port": port}),
        Hint::Auto { scope, group_id } => {
            let s = match scope {
                AutoScope::Link => "link",
                AutoScope::Admin => "admin",
                AutoScope::Site => "site",
                AutoScope::Organisation => "organisation",
                AutoScope::Global => "global",
            };
            json!({"type": "auto", "scope": s, "group_id": group_id})
        },
        Hint::RNode {
            frequency_hz,
            bandwidth_hz,
            spreading_factor,
            coding_rate,
        } => json!({
            "type": "rnode", "frequency_hz": frequency_hz, "bandwidth_hz": bandwidth_hz,
            "spreading_factor": spreading_factor, "coding_rate": coding_rate}),
        Hint::Http { url } => json!({"type": "http", "url": url}),
        Hint::Unknown { tag, body } => {
            json!({"type": "unknown", "tag": tag, "body_hex": hex::encode(body)})
        },
        _ => panic!("a hint this replay does not know"),
    }
}

fn endpoint_json(e: &ciris_verify_core::edition2::fedcode::Endpoint) -> serde_json::Map<String, J> {
    let mut m = serde_json::Map::new();
    m.insert(
        "transport_identity_hex".into(),
        hex::encode(e.transport_identity).into(),
    );
    m.insert(
        "rns_identity_hash_hex".into(),
        hex::encode(e.rns_identity_hash()).into(),
    );
    m.insert(
        "hints".into(),
        J::Array(e.hints.iter().map(hint_json).collect()),
    );
    m
}

fn decoded_json(c: &FedCodeE2) -> J {
    let mut m = serde_json::Map::new();
    m.insert("kind".into(), kind_name(c.kind).into());
    m.insert("kid_hex".into(), hex::encode(c.kid).into());
    match c.kind {
        Kind::User => {
            let nodes = c.nodes.iter().map(|n| {
                let mut e = endpoint_json(&n.endpoint);
                e.insert("kid_hex".into(), hex::encode(n.kid).into());
                J::Object(e)
            });
            m.insert("nodes".into(), J::Array(nodes.collect()));
        },
        Kind::Node => {
            m.insert(
                "endpoint".into(),
                J::Object(endpoint_json(c.endpoint.as_ref().unwrap())),
            );
        },
        _ => {},
    }
    J::Object(m)
}

#[test]
fn file_is_pinned() {
    use sha2::Digest as _;
    assert_eq!(
        hex::encode(sha2::Sha256::digest(FILE.as_bytes())),
        FILE_SHA256
    );
}

#[test]
fn valid_codes_decode_and_reencode() {
    let f = file();
    let valid = f["valid"].as_array().unwrap();
    assert_eq!(valid.len(), 12);
    for v in valid {
        let id = v["id"].as_str().unwrap();
        let code = v["code"].as_str().unwrap();
        let c = FedCodeE2::decode(code).unwrap_or_else(|e| panic!("{id}: {e}"));
        assert_eq!(decoded_json(&c), v["decoded"], "{id}");
        assert_eq!(
            FedCodeE2::decode(v["qr"].as_str().unwrap()).unwrap(),
            c,
            "{id}: qr form"
        );
        let payload = hex::decode(v["payload_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            FedCodeE2::from_payload(&payload).unwrap(),
            c,
            "{id}: payload"
        );
        // A minter emits only assigned hint types; every other code round-trips.
        if id == "unknown_hint_skipped" {
            assert!(c.encode().is_err(), "{id}: an unknown hint is not minted");
            continue;
        }
        assert_eq!(c.payload().unwrap(), payload, "{id}: re-encoded payload");
        assert_eq!(c.encode().unwrap(), code, "{id}: display form");
        assert_eq!(
            c.encode_qr().unwrap(),
            v["qr"].as_str().unwrap(),
            "{id}: qr form"
        );
    }
}

#[test]
fn refusals_give_their_tokens() {
    let f = file();
    let refusals = f["refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), 23);
    for r in refusals {
        let id = r["id"].as_str().unwrap();
        let err = FedCodeE2::decode(r["code"].as_str().unwrap()).expect_err(id);
        assert_eq!(err.token(), r["error"].as_str().unwrap(), "{id}");
    }
}

#[test]
fn transport_key_check_at_resolution() {
    let f = file();
    for k in f["key_checks"].as_array().unwrap() {
        let id = k["id"].as_str().unwrap();
        let key = |h: &J| {
            CompositePublicKey::from_bytes(&hex::decode(h.as_str().unwrap()).unwrap()).unwrap()
        };
        let owner = key(&k["owner_composite_hex"]);
        let nodes: Vec<(String, CompositePublicKey)> = k["node_composites_hex"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(kid, h)| (kid.clone(), key(h)))
            .collect();
        for (kid, pk) in &nodes {
            assert_eq!(
                &hex::encode(thumbprint(pk)),
                kid,
                "{id}: the kid is the key's thumbprint"
            );
        }
        let c = FedCodeE2::decode(k["code"].as_str().unwrap()).unwrap();
        assert_eq!(
            c.kid,
            thumbprint(&owner),
            "{id}: the code's kid is the owner's thumbprint"
        );
        let got = c.check_transport_keys(&owner, |kid| {
            nodes
                .iter()
                .find(|(k, _)| *k == hex::encode(kid))
                .map(|(_, pk)| pk)
        });
        let want = k["expect"].as_str().unwrap();
        match got {
            Ok(()) => assert_eq!(want, "ok", "{id}"),
            Err(e) => assert_eq!(e.token(), want, "{id}"),
        }
    }
}

/// The QR size of every valid code (alphanumeric mode: base32 and the prefix
/// are all in the QR alphanumeric set). Printed for the layout proposal; the
/// largest code must still render.
#[cfg(feature = "host")]
#[test]
fn qr_sizes() {
    let f = file();
    for v in f["valid"].as_array().unwrap() {
        let qr = v["qr"].as_str().unwrap();
        for ec in [qrcode::EcLevel::L, qrcode::EcLevel::M] {
            let q = qrcode::QrCode::with_error_correction_level(qr, ec)
                .unwrap_or_else(|e| panic!("{}: {e}", v["id"]));
            let qrcode::Version::Normal(n) = q.version() else {
                panic!("micro")
            };
            println!(
                "{} payload {} chars {} ec {:?}: version {n} ({}x{})",
                v["id"],
                v["payload_len"],
                qr.len(),
                ec,
                17 + 4 * n,
                17 + 4 * n
            );
        }
    }
}
