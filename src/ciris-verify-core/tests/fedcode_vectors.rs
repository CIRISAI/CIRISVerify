//! Golden FedCode vectors — **authored by CIRISVerify** (CC 2.6.8, FSD-003).
//!
//! CC 2.6.8 names `ciris_verify_core::fedcode` the reference implementation:
//! every other component (the client's Kotlin port, the agent's Python codec,
//! the server's `nodecode.rs`) is judged byte-for-byte against it. This harness
//! produces `tests/vectors/fedcode/fedcode_vectors.json` from the codec with
//! fixed inputs and then replays the committed file as a consumer would.
//!
//! **Emit-or-verify.** A missing vector file is written; an existing one must
//! equal what the codec produces now, byte for byte, so drift fails here first.
//! To regenerate deliberately (the diff is the review):
//!
//! ```text
//! CIRIS_FEDCODE_VECTORS_REGENERATE=1 cargo test -p ciris-verify-core --test fedcode_vectors
//! ```
//!
//! The CRC-16-CCITT and base32 used to construct the hand-built codes (v1, the
//! pre-commitment v3 tail, every corrupted payload) are reimplemented in this
//! file rather than borrowed from the crate, so the payload bytes the file
//! carries are an independent reading of the codec's output.

use std::path::PathBuf;

use ciris_verify_core::fedcode::{
    decode, derive_key_id, encode, encode_qr, AdmittedHybridKey, FedCode, FedCodeError, FedKind,
    OwnedNode,
};
use ed25519_dalek::SigningKey;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const VECTOR_FILE: &str = "fedcode_vectors.json";
const REGENERATE_ENV: &str = "CIRIS_FEDCODE_VECTORS_REGENERATE";

const PREFIX_V1: &str = "CIRIS-V1-";
const PREFIX_V2: &str = "CIRIS-V2-";
const PREFIX_V3: &str = "CIRIS-V3-";

/// Deterministic stand-in for a raw ML-DSA-65 public key (1952 bytes):
/// byte `i` is `i mod 251`. Its sha256 is the commitment the vectors carry.
const ML_DSA_65_PUBKEY_LEN: usize = 1952;

fn vectors_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests/vectors/fedcode");
    p
}

// ---- independent primitives (the test's own reading of the wire) ------------

fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn b32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buf >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buf << (5 - bits)) & 0x1F) as usize] as char);
    }
    out
}

fn b32_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for ch in text.bytes() {
        let v = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'2'..=b'7' => ch - b'2' + 26,
            other => panic!("not base32: {other:?}"),
        };
        buf = (buf << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    out
}

fn group4(text: &str) -> String {
    text.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

/// Render a payload under a prefix the way the codec does: CRC appended
/// big-endian, base32 without padding, dashed display form and QR form.
fn render(prefix: &str, payload: &[u8]) -> (String, String, u16) {
    let crc = crc16_ccitt(payload);
    let mut full = payload.to_vec();
    full.extend_from_slice(&crc.to_be_bytes());
    let body = b32_encode(&full);
    (
        format!("{prefix}{}", group4(&body)),
        format!("{prefix}{body}"),
        crc,
    )
}

/// Split a QR-form code the codec produced into (prefix, payload, declared crc).
fn unrender(code_qr: &str) -> (&'static str, Vec<u8>, u16) {
    for p in [PREFIX_V3, PREFIX_V2, PREFIX_V1] {
        if let Some(body) = code_qr.strip_prefix(p) {
            let raw = b32_decode(body);
            let (payload, crc) = raw.split_at(raw.len() - 2);
            return (p, payload.to_vec(), u16::from_be_bytes([crc[0], crc[1]]));
        }
    }
    panic!("no fedcode prefix on {code_qr}");
}

// ---- deterministic material ---------------------------------------------------

fn ed25519_pubkey(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn ml_dsa_65_pubkey_stand_in() -> Vec<u8> {
    (0..ML_DSA_65_PUBKEY_LEN).map(|i| (i % 251) as u8).collect()
}

fn commitment_hex() -> String {
    hex::encode(Sha256::digest(ml_dsa_65_pubkey_stand_in()))
}

struct Owner {
    seed: u8,
    label: &'static str,
    pubkey: [u8; 32],
    key_id: String,
}

fn owner(seed: u8, label: &'static str) -> Owner {
    let pubkey = ed25519_pubkey(seed);
    Owner {
        seed,
        label,
        pubkey,
        key_id: derive_key_id(label, &pubkey),
    }
}

fn owner_code(o: &Owner, kind: FedKind) -> FedCode {
    FedCode::new(kind, o.key_id.clone(), b64(&o.pubkey))
}

/// Node `i`: federation key seed `0x40 + i` (names the node's `key_id`),
/// transport key seed `0x80 + i` (what the code embeds).
fn node(i: u8) -> (OwnedNode, Value) {
    let fed = ed25519_pubkey(0x40 + i);
    let transport = ed25519_pubkey(0x80 + i);
    let key_id = derive_key_id(&format!("node{i:02}"), &fed);
    let input = json!({
        "key_id": key_id,
        "key_id_derivation": {
            "label": format!("node{i:02}"),
            "federation_ed25519_seed_hex": hex::encode([0x40 + i; 32]),
            "federation_ed25519_pubkey_hex": hex::encode(fed),
        },
        "transport_ed25519_seed_hex": hex::encode([0x80 + i; 32]),
        "transport_pubkey_ed25519_hex": hex::encode(transport),
        "transport_pubkey_ed25519_base64": b64(&transport),
    });
    (OwnedNode::new(key_id, b64(&transport)), input)
}

fn nodes(n: u8) -> (Vec<OwnedNode>, Vec<Value>) {
    (1..=n).map(node).unzip()
}

// ---- JSON shapes ------------------------------------------------------------------

fn error_kind(e: &FedCodeError) -> Value {
    match e {
        FedCodeError::InvalidVersion(_) => json!("InvalidVersion"),
        FedCodeError::Malformed(_) => json!("Malformed"),
        FedCodeError::ChecksumMismatch { declared, computed } => json!({
            "ChecksumMismatch": {
                "declared_hex": format!("{declared:04x}"),
                "computed_hex": format!("{computed:04x}"),
            }
        }),
        _ => json!("Other"),
    }
}

fn fedcode_json(fc: &FedCode) -> Value {
    json!({
        "kind": fc.kind.as_str(),
        "key_id": fc.key_id,
        "pubkey_ed25519_base64": fc.pubkey_ed25519_base64,
        "transport_hint": fc.transport_hint,
        "alias_hint": fc.alias_hint,
        "group_key_id": fc.group_key_id,
        "owned_nodes": fc.owned_nodes.iter().map(|n| json!({
            "key_id": n.key_id,
            "transport_pubkey_ed25519_base64": n.transport_pubkey_ed25519_base64,
        })).collect::<Vec<_>>(),
        "ml_dsa_65_pubkey_sha256": fc.ml_dsa_65_pubkey_sha256,
    })
}

fn owner_json(o: &Owner) -> Value {
    json!({
        "label": o.label,
        "ed25519_seed_hex": hex::encode([o.seed; 32]),
        "ed25519_pubkey_hex": hex::encode(o.pubkey),
        "ed25519_pubkey_base64": b64(&o.pubkey),
        "key_id": o.key_id,
        "key_id_hash_sha256_hex": hex::encode(Sha256::digest(o.key_id.as_bytes())),
    })
}

/// A vector the encoder produced: input, payload, CRC, both renders, and the
/// value `decode` returns for them.
fn valid_from_encoder(id: &str, description: &str, o: &Owner, fc: &FedCode) -> Value {
    let display = encode(fc).unwrap_or_else(|e| panic!("{id}: encode failed: {e}"));
    let qr = encode_qr(fc).unwrap();
    let (prefix, payload, crc) = unrender(&qr);
    assert_eq!(
        crc,
        crc16_ccitt(&payload),
        "{id}: codec CRC vs the test's CRC"
    );
    let (display2, qr2, _) = render(prefix, &payload);
    assert_eq!(display, display2, "{id}: codec render vs the test's render");
    assert_eq!(qr, qr2);
    let decoded = decode(&display).unwrap_or_else(|e| panic!("{id}: decode failed: {e}"));
    assert_eq!(decode(&qr).unwrap(), decoded);
    json!({
        "id": id,
        "description": description,
        "owner": owner_json(o),
        "encoder_input": fedcode_json(fc),
        "prefix": prefix,
        "version_byte_hex": format!("{:02x}", payload[0]),
        "payload_hex": hex::encode(&payload),
        "payload_len": payload.len(),
        "crc16_ccitt_hex": format!("{crc:04x}"),
        "code": display,
        "code_qr": qr,
        "decoded": fedcode_json(&decoded),
    })
}

/// A vector built by hand from a payload (no encoder path exists for it).
fn valid_by_hand(
    id: &str,
    description: &str,
    construction: &str,
    o: &Owner,
    prefix: &str,
    payload: &[u8],
) -> Value {
    let (display, qr, crc) = render(prefix, payload);
    let decoded = decode(&display).unwrap_or_else(|e| panic!("{id}: decode failed: {e}"));
    assert_eq!(decode(&qr).unwrap(), decoded);
    json!({
        "id": id,
        "description": description,
        "construction": construction,
        "owner": owner_json(o),
        "encoder_input": Value::Null,
        "prefix": prefix,
        "version_byte_hex": format!("{:02x}", payload[0]),
        "payload_hex": hex::encode(payload),
        "payload_len": payload.len(),
        "crc16_ccitt_hex": format!("{crc:04x}"),
        "code": display,
        "code_qr": qr,
        "decoded": fedcode_json(&decoded),
    })
}

fn refused_at_encode(id: &str, description: &str, constraint: &str, fc: &FedCode) -> Value {
    let err = match encode(fc) {
        Err(e) => e,
        Ok(code) => panic!("{id}: encoder accepted what it must refuse: {code}"),
    };
    assert!(encode_qr(fc).is_err());
    json!({
        "id": id,
        "description": description,
        "constraint": constraint,
        "stage": "encode",
        "encoder_input": fedcode_json(fc),
        "error": error_kind(&err),
    })
}

fn refused_at_decode(id: &str, description: &str, constraint: &str, code: &str) -> Value {
    let err = match decode(code) {
        Err(e) => e,
        Ok(fc) => panic!("{id}: decoder accepted what it must refuse: {fc:?}"),
    };
    json!({
        "id": id,
        "description": description,
        "constraint": constraint,
        "stage": "decode",
        "code": code,
        "error": error_kind(&err),
    })
}

/// A hand-built payload rendered and refused on decode; the payload is carried
/// so a port can see exactly which bytes it must refuse.
fn refused_payload(
    id: &str,
    description: &str,
    constraint: &str,
    prefix: &str,
    payload: &[u8],
) -> Value {
    let (display, _, crc) = render(prefix, payload);
    let mut v = refused_at_decode(id, description, constraint, &display);
    let m = v.as_object_mut().unwrap();
    m.insert("payload_hex".into(), json!(hex::encode(payload)));
    m.insert("payload_len".into(), json!(payload.len()));
    m.insert("crc16_ccitt_hex".into(), json!(format!("{crc:04x}")));
    v
}

// ---- the vector set ------------------------------------------------------------------

fn build_vectors() -> Value {
    let alice = owner(0x01, "alice");
    let agent = owner(0x02, "helper-agent");
    let node_o = owner(0x03, "lab-node");
    let family = owner(0x04, "moore-family");
    let community = owner(0x05, "roselle-salon");
    let family_group = owner(0x14, "family-group-key");
    let community_group = owner(0x15, "community-group-key");
    let commitment = commitment_hex();

    let mut valid = Vec::new();
    let mut refusals = Vec::new();

    // -- v2, five kinds, with and without hints ------------------------------------
    for (o, kind, group) in [
        (&alice, FedKind::User, None),
        (&agent, FedKind::Agent, None),
        (&node_o, FedKind::Node, None),
        (&family, FedKind::Family, Some(&family_group)),
        (&community, FedKind::Community, Some(&community_group)),
    ] {
        let k = kind.as_str();
        valid.push(valid_from_encoder(
            &format!("v2_{k}_bare"),
            &format!("v2 `{k}` code: no hints, no group_key_id, no v3 tail."),
            o,
            &owner_code(o, kind),
        ));
        let mut fc = owner_code(o, kind)
            .with_transport_hint("https://example.invalid/ciris")
            .with_alias_hint(format!("{} (display)", o.label));
        let mut desc = format!("v2 `{k}` code with transport and alias hints");
        if let Some(g) = group {
            fc = fc.with_group_key_id(g.key_id.clone());
            desc.push_str(" and the group's key_id");
        }
        desc.push('.');
        valid.push(valid_from_encoder(&format!("v2_{k}_hints"), &desc, o, &fc));
    }

    // -- v3: nodes; commitment only; both; the 16-node bound; the 1,024-byte edge --
    let (one, _) = nodes(1);
    valid.push(valid_from_encoder(
        "v3_user_nodes_1",
        "v3 `user` code embedding one owned node; commitment absent (tag 0x00).",
        &alice,
        &owner_code(&alice, FedKind::User).with_owned_nodes(one.clone()),
    ));
    let (three, _) = nodes(3);
    valid.push(valid_from_encoder(
        "v3_user_nodes_3_hints",
        "v3 `user` code with transport and alias hints and three owned nodes; commitment absent.",
        &alice,
        &owner_code(&alice, FedKind::User)
            .with_transport_hint("https://example.invalid/ciris")
            .with_alias_hint("alice (display)")
            .with_owned_nodes(three.clone()),
    ));
    valid.push(valid_from_encoder(
        "v3_user_commitment_only",
        "v3 `user` code carrying the PQC commitment and no nodes (node_count = 0): CC 2.6.8 PQC rule (b).",
        &alice,
        &owner_code(&alice, FedKind::User).with_ml_dsa_65_pubkey_sha256(commitment.clone()),
    ));
    for (o, kind, group) in [
        (&agent, FedKind::Agent, None),
        (&node_o, FedKind::Node, None),
        (&family, FedKind::Family, Some(&family_group)),
        (&community, FedKind::Community, Some(&community_group)),
    ] {
        let k = kind.as_str();
        let mut fc = owner_code(o, kind).with_ml_dsa_65_pubkey_sha256(commitment.clone());
        let mut desc = format!(
            "v3 `{k}` code carrying the PQC commitment and no nodes (node_count = 0): the commitment applies to any kind (CC 2.6.8 PQC rule (b)); constraint 2 restricts only embedded nodes"
        );
        if let Some(g) = group {
            fc = fc.with_group_key_id(g.key_id.clone());
            desc.push_str("; carries the group's key_id");
        }
        desc.push('.');
        valid.push(valid_from_encoder(
            &format!("v3_{k}_commitment_only"),
            &desc,
            o,
            &fc,
        ));
    }
    valid.push(valid_from_encoder(
        "v3_user_nodes_and_commitment",
        "v3 `user` code with hints, three owned nodes and the PQC commitment (tag 0x01 + 32 raw bytes, last).",
        &alice,
        &owner_code(&alice, FedKind::User)
            .with_transport_hint("https://example.invalid/ciris")
            .with_alias_hint("alice (display)")
            .with_owned_nodes(three.clone())
            .with_ml_dsa_65_pubkey_sha256(commitment.clone()),
    ));
    let (sixteen, _) = nodes(16);
    valid.push(valid_from_encoder(
        "v3_user_nodes_16",
        "v3 `user` code at the node bound: 16 owned nodes admitted (CC 2.6.8 constraint 3).",
        &alice,
        &owner_code(&alice, FedKind::User).with_owned_nodes(sixteen.clone()),
    ));

    // Exactly 1,024 payload bytes: 16 nodes + commitment, the transport hint
    // padded to land on the budget; one more byte is refused by the encoder.
    let at_budget = |pad: usize| {
        owner_code(&alice, FedKind::User)
            .with_transport_hint("x".repeat(pad))
            .with_alias_hint("alice (display)")
            .with_owned_nodes(sixteen.clone())
            .with_ml_dsa_65_pubkey_sha256(commitment.clone())
    };
    let probe = unrender(&encode_qr(&at_budget(1)).unwrap()).1.len();
    let pad = 1024 - probe + 1;
    assert!(
        pad <= 255,
        "transport hint pad {pad} must fit one length byte"
    );
    let budget_fc = at_budget(pad);
    let budget_vec = valid_from_encoder(
        "v3_user_payload_1024",
        "v3 `user` code whose payload is exactly 1,024 bytes before base32: admitted at the edge (CC 2.6.8 constraint 3).",
        &alice,
        &budget_fc,
    );
    assert_eq!(budget_vec["payload_len"], 1024);
    valid.push(budget_vec);
    refusals.push(refused_at_encode(
        "enc_payload_1025",
        "The same code with one more transport-hint byte: payload 1,025 bytes, refused by the encoder.",
        "CC 2.6.8 constraint 3 (payload <= 1024 bytes before base32)",
        &at_budget(pad + 1),
    ));

    // -- constraint 4: the empty tail is v2 byte for byte ------------------------------
    let empty_tail = owner_code(&alice, FedKind::User)
        .with_owned_nodes(Vec::new())
        .with_ml_dsa_65_pubkey_sha256(commitment.clone());
    let mut empty_tail = empty_tail;
    empty_tail.ml_dsa_65_pubkey_sha256 = None;
    let bare = &valid[0];
    assert_eq!(bare["id"], "v2_user_bare");
    let empty_tail_code = encode(&empty_tail).unwrap();
    assert_eq!(empty_tail_code, bare["code"].as_str().unwrap());
    valid.push(json!({
        "id": "v2_user_empty_tail_is_v2",
        "description": "A v3-capable encoder given an empty node list and no commitment emits the v2 code byte for byte (CC 2.6.8 constraint 4). Identical to `v2_user_bare`.",
        "identical_to": "v2_user_bare",
        "owner": owner_json(&alice),
        "encoder_input": fedcode_json(&empty_tail),
        "prefix": bare["prefix"],
        "version_byte_hex": bare["version_byte_hex"],
        "payload_hex": bare["payload_hex"],
        "payload_len": bare["payload_len"],
        "crc16_ccitt_hex": bare["crc16_ccitt_hex"],
        "code": bare["code"],
        "code_qr": bare["code_qr"],
        "decoded": bare["decoded"],
    }));

    // -- hand-built: v1 NodeCode, and the pre-commitment v3 tail -------------------------
    let v1_payload = |hints: Option<(&str, &str)>| {
        let mut p = vec![0x01u8];
        p.extend_from_slice(&Sha256::digest(node_o.key_id.as_bytes()));
        p.extend_from_slice(&node_o.pubkey);
        p.push(node_o.key_id.len() as u8);
        p.extend_from_slice(node_o.key_id.as_bytes());
        match hints {
            None => p.extend_from_slice(&[0x00, 0x00]),
            Some((t, a)) => {
                p.push(t.len() as u8);
                p.extend_from_slice(t.as_bytes());
                p.push(a.len() as u8);
                p.extend_from_slice(a.as_bytes());
            },
        }
        p
    };
    valid.push(valid_by_hand(
        "v1_node_bare",
        "Legacy v1 NodeCode (`CIRIS-V1-`), no hints: decodes as kind `node` (CC 2.6.8 constraint 5).",
        "version=0x01 | sha256(key_id)(32) | pubkey(32) | LP(key_id) | 0x00 | 0x00; no kind byte, no group_key_id hint.",
        &node_o,
        PREFIX_V1,
        &v1_payload(None),
    ));
    valid.push(valid_by_hand(
        "v1_node_hints",
        "Legacy v1 NodeCode with transport and alias hints: decodes as kind `node`.",
        "version=0x01 | sha256(key_id)(32) | pubkey(32) | LP(key_id) | LP(transport) | LP(alias).",
        &node_o,
        PREFIX_V1,
        &v1_payload(Some((
            "https://example.invalid/ciris",
            "lab-node (display)",
        ))),
    ));

    let v3_one_node_payload = {
        let qr =
            encode_qr(&owner_code(&alice, FedKind::User).with_owned_nodes(one.clone())).unwrap();
        unrender(&qr).1
    };
    assert_eq!(
        *v3_one_node_payload.last().unwrap(),
        0x00,
        "tag 0x00 closes the tail"
    );
    let pre_commitment = &v3_one_node_payload[..v3_one_node_payload.len() - 1];
    valid.push(valid_by_hand(
        "v3_user_nodes_1_no_commitment_tag",
        "A v3 code minted before the PQC commitment existed ends after the node list; it decodes with the commitment absent (CC 2.6.8 PQC rule (c)).",
        "The `v3_user_nodes_1` payload with its trailing 0x00 commitment tag removed, CRC recomputed.",
        &alice,
        PREFIX_V3,
        pre_commitment,
    ));

    // -- refusals at the encoder --------------------------------------------------------------
    let with_commitment =
        |c: &str| owner_code(&alice, FedKind::User).with_ml_dsa_65_pubkey_sha256(c.to_string());
    refusals.push(refused_at_encode(
        "enc_commitment_uppercase_hex",
        "The commitment in uppercase hex is refused, not lowercased (CC 2.6.8 PQC rule (d)).",
        "CC 2.6.8 PQC rule (d)",
        &with_commitment(&commitment.to_ascii_uppercase()),
    ));
    refusals.push(refused_at_encode(
        "enc_commitment_short_hex",
        "A 62-character commitment (31 bytes) is refused.",
        "CC 2.6.8 PQC rule (d)",
        &with_commitment(&commitment[..62]),
    ));
    refusals.push(refused_at_encode(
        "enc_commitment_long_hex",
        "A 66-character commitment (33 bytes) is refused.",
        "CC 2.6.8 PQC rule (d)",
        &with_commitment(&format!("{commitment}00")),
    ));
    refusals.push(refused_at_encode(
        "enc_commitment_non_hex",
        "A 64-character commitment with a non-hex character is refused.",
        "CC 2.6.8 PQC rule (d)",
        &with_commitment(&format!("{}g", &commitment[..63])),
    ));
    refusals.push(refused_at_encode(
        "enc_commitment_empty",
        "An empty commitment string is refused (absence is `None`, not the empty string).",
        "CC 2.6.8 PQC rule (d)",
        &with_commitment(""),
    ));
    let (seventeen, _) = nodes(17);
    refusals.push(refused_at_encode(
        "enc_nodes_17",
        "17 owned nodes are refused by the encoder.",
        "CC 2.6.8 constraint 3 (node_count <= 16)",
        &owner_code(&alice, FedKind::User).with_owned_nodes(seventeen),
    ));
    refusals.push(refused_at_encode(
        "enc_node_transport_equals_owner_pubkey",
        "An embedded node whose transport key is the owner's own Ed25519 pubkey is refused.",
        "CC 2.6.8 constraint 1",
        &owner_code(&alice, FedKind::User)
            .with_owned_nodes(vec![OwnedNode::new(node(1).0.key_id, b64(&alice.pubkey))]),
    ));
    for (o, kind) in [
        (&agent, FedKind::Agent),
        (&node_o, FedKind::Node),
        (&family, FedKind::Family),
        (&community, FedKind::Community),
    ] {
        refusals.push(refused_at_encode(
            &format!("enc_{}_with_nodes", kind.as_str()),
            &format!(
                "A `{}` code embedding a node is refused; only `user` may embed nodes.",
                kind.as_str()
            ),
            "CC 2.6.8 constraint 2",
            &owner_code(o, kind).with_owned_nodes(one.clone()),
        ));
    }
    refusals.push(refused_at_encode(
        "enc_node_key_id_empty",
        "An owned node with an empty key_id is refused (LP fields in the tail are 1..=255 bytes).",
        "CC 2.6.8 wire format (LP)",
        &owner_code(&alice, FedKind::User)
            .with_owned_nodes(vec![OwnedNode::new("", b64(&ed25519_pubkey(0x81)))]),
    ));
    refusals.push(refused_at_encode(
        "enc_node_transport_wrong_length",
        "An owned node whose transport key is not 32 raw bytes is refused.",
        "CC 2.6.8 wire format (transport_ed25519(32))",
        &owner_code(&alice, FedKind::User)
            .with_owned_nodes(vec![OwnedNode::new(node(1).0.key_id, b64(&[0x81u8; 31]))]),
    ));
    refusals.push(refused_at_encode(
        "enc_key_id_over_255",
        "A key_id of 256 bytes is refused (1-byte length prefix).",
        "CC 2.6.8 wire format (fields <= 255 UTF-8 bytes)",
        &FedCode::new(FedKind::User, "k".repeat(256), b64(&alice.pubkey)),
    ));
    refusals.push(refused_at_encode(
        "enc_hint_over_255",
        "A transport hint of 256 bytes is refused.",
        "CC 2.6.8 wire format (fields <= 255 UTF-8 bytes)",
        &owner_code(&alice, FedKind::User).with_transport_hint("h".repeat(256)),
    ));
    refusals.push(refused_at_encode(
        "enc_pubkey_wrong_length",
        "An owner pubkey of 31 raw bytes is refused.",
        "CC 2.6.8 wire format (ed25519_pubkey(32))",
        &FedCode::new(FedKind::User, alice.key_id.clone(), b64(&[0x01u8; 31])),
    ));
    refusals.push(refused_at_encode(
        "enc_pubkey_not_base64",
        "An owner pubkey that is not base64 is refused.",
        "API: pubkey_ed25519_base64 is standard base64 of 32 raw bytes",
        &FedCode::new(FedKind::User, alice.key_id.clone(), "not*base64!"),
    ));

    // -- refusals at the decoder -------------------------------------------------------------------
    let reference_qr = valid
        .iter()
        .find(|v| v["id"] == "v3_user_nodes_and_commitment")
        .unwrap()["code_qr"]
        .as_str()
        .unwrap()
        .to_string();
    let reference_display = valid
        .iter()
        .find(|v| v["id"] == "v3_user_nodes_and_commitment")
        .unwrap()["code"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, reference_payload, _) = unrender(&reference_qr);
    let v2_hints_qr = valid.iter().find(|v| v["id"] == "v2_user_hints").unwrap()["code_qr"]
        .as_str()
        .unwrap()
        .to_string();
    let (_, v2_hints_payload, _) = unrender(&v2_hints_qr);

    // CRC mismatch: one payload byte flipped, the carried CRC left as it was.
    {
        let mut raw = b32_decode(reference_qr.strip_prefix(PREFIX_V3).unwrap());
        let idx = 2 + 32 + 32 + 1; // first byte of the key_id
        raw[idx] ^= 0x01;
        let code = format!("{PREFIX_V3}{}", group4(&b32_encode(&raw)));
        refusals.push(refused_at_decode(
            "dec_crc_mismatch",
            "The `v3_user_nodes_and_commitment` code with the first key_id byte flipped and the original CRC kept: checksum mismatch.",
            "CC 2.6.8 wire format (CRC-16-CCITT)",
            &code,
        ));
    }
    refusals.push(refused_at_decode(
        "dec_unknown_prefix",
        "A `CIRIS-V9-` prefix is not a fedcode.",
        "CC 2.6.8 constraint 5 (prefix read before any payload byte)",
        &reference_display.replacen("CIRIS-V3-", "CIRIS-V9-", 1),
    ));
    refusals.push(refused_at_decode(
        "dec_not_a_fedcode",
        "Text with no CIRIS prefix at all.",
        "CC 2.6.8 wire format (prefix)",
        "HELLO-WORLD-ABCD-EFGH",
    ));
    refusals.push(refused_at_decode(
        "dec_empty_body",
        "A bare prefix with no payload.",
        "CC 2.6.8 wire format",
        "CIRIS-V2-",
    ));
    refusals.push(refused_at_decode(
        "dec_garbage_body_not_base32",
        "A body containing characters outside the RFC 4648 alphabet (0, 1, 8, 9).",
        "CC 2.6.8 wire format (base32 alphabet A-Z2-7)",
        "CIRIS-V2-0189-0189-0189-0189-0189-0189-0189-0189-0189-0189-0189-0189-0189-0189-0189-0189",
    ));
    {
        // Valid base32 of deterministic bytes that are not a payload.
        let garbage: Vec<u8> = Sha256::digest(b"fedcode garbage body").to_vec();
        let mut bytes = garbage.clone();
        bytes.extend_from_slice(&Sha256::digest(&garbage));
        bytes.extend_from_slice(&Sha256::digest(bytes.clone()));
        let code = format!("{PREFIX_V2}{}", group4(&b32_encode(&bytes)));
        refusals.push(refused_at_decode(
            "dec_garbage_body_valid_base32",
            "96 bytes of sha256 output rendered as a v2 body: well-formed base32, not a payload.",
            "CC 2.6.8 wire format (CRC-16-CCITT)",
            &code,
        ));
    }
    refusals.push(refused_at_decode(
        "dec_truncated_string_short",
        "The reference display code cut after its first group: too short to hold a payload.",
        "CC 2.6.8 wire format",
        &reference_display[..PREFIX_V3.len() + 4],
    ));
    refusals.push(refused_at_decode(
        "dec_truncated_string_long",
        "The reference display code with its last two groups dropped: the bytes no longer end in their CRC.",
        "CC 2.6.8 wire format (CRC-16-CCITT)",
        &reference_display[..reference_display.len() - 10],
    ));
    // Hand-built payloads, CRC recomputed, so the structural check is what refuses.
    refusals.push(refused_payload(
        "dec_truncated_payload_recrc",
        "The reference payload cut in the middle of the key_id with the CRC recomputed: the declared field length exceeds the buffer.",
        "CC 2.6.8 wire format (LP)",
        PREFIX_V3,
        &reference_payload[..2 + 32 + 32 + 1 + 4],
    ));
    {
        let mut p = v2_hints_payload.clone();
        p[0] = 0x04;
        refusals.push(refused_payload(
            "dec_unknown_version_byte",
            "A v2 payload whose version byte is 0x04 under the v2 prefix, CRC recomputed.",
            "CC 2.6.8 wire format (version)",
            PREFIX_V2,
            &p,
        ));
    }
    {
        let mut p = v2_hints_payload.clone();
        p[1] = 0x06;
        refusals.push(refused_payload(
            "dec_unknown_kind_byte",
            "A v2 payload whose kind byte is 6, CRC recomputed.",
            "CC 2.6.8 kind(1): 1..=5",
            PREFIX_V2,
            &p,
        ));
    }
    {
        let mut p = v2_hints_payload.clone();
        p[1] = 0x00;
        refusals.push(refused_payload(
            "dec_kind_byte_zero",
            "A v2 payload whose kind byte is 0, CRC recomputed.",
            "CC 2.6.8 kind(1): 1..=5",
            PREFIX_V2,
            &p,
        ));
    }
    {
        // 17 nodes, hand-built: the encoder refuses it, so the bytes come from here.
        let (seventeen, _) = nodes(17);
        let mut p = v2_hints_payload.clone();
        p[0] = 0x03;
        p.push(17);
        for n in &seventeen {
            p.push(n.key_id.len() as u8);
            p.extend_from_slice(n.key_id.as_bytes());
            p.extend_from_slice(
                &hex::decode(hex_of_b64(&n.transport_pubkey_ed25519_base64)).unwrap(),
            );
        }
        p.push(0x00);
        refusals.push(refused_payload(
            "dec_nodes_17",
            "A v3 payload declaring 17 nodes, CRC recomputed: refused by the decoder.",
            "CC 2.6.8 constraint 3 (node_count <= 16)",
            PREFIX_V3,
            &p,
        ));
    }
    {
        let mut p = v2_hints_payload.clone();
        p[0] = 0x03;
        p.push(1);
        let id = node(1).0.key_id;
        p.push(id.len() as u8);
        p.extend_from_slice(id.as_bytes());
        p.extend_from_slice(&alice.pubkey);
        p.push(0x00);
        refusals.push(refused_payload(
            "dec_node_transport_equals_owner_pubkey",
            "A v3 payload (minted elsewhere) whose embedded node transport key equals the owner's pubkey, CRC recomputed: refused by the decoder.",
            "CC 2.6.8 constraint 1",
            PREFIX_V3,
            &p,
        ));
    }
    {
        let mut p = v2_hints_payload.clone();
        p[0] = 0x03;
        p[1] = 0x02; // agent
        p.push(1);
        let id = node(1).0.key_id;
        p.push(id.len() as u8);
        p.extend_from_slice(id.as_bytes());
        p.extend_from_slice(&ed25519_pubkey(0x81));
        p.push(0x00);
        refusals.push(refused_payload(
            "dec_agent_with_nodes",
            "A v3 payload with kind `agent` and one embedded node, CRC recomputed: refused by the decoder.",
            "CC 2.6.8 constraint 2",
            PREFIX_V3,
            &p,
        ));
    }
    {
        let mut p = reference_payload.clone();
        let tag_at = p.len() - 33;
        assert_eq!(p[tag_at], 0x01);
        p[tag_at] = 0x02;
        refusals.push(refused_payload(
            "dec_pqc_tag_0x02",
            "The reference payload with the commitment presence tag set to 0x02, CRC recomputed.",
            "CC 2.6.8 PQC commitment: 0x00 absent | 0x01 + 32 bytes",
            PREFIX_V3,
            &p,
        ));
    }
    refusals.push(refused_payload(
        "dec_pqc_commitment_truncated",
        "The reference payload with the commitment cut to 16 bytes after its 0x01 tag, CRC recomputed.",
        "CC 2.6.8 PQC commitment: 0x01 + 32 raw bytes",
        PREFIX_V3,
        &reference_payload[..reference_payload.len() - 16],
    ));
    {
        let mut p = v2_hints_payload.clone();
        let lp = 2 + 32 + 32;
        p[lp + 1] = 0xFF; // first key_id byte: not UTF-8
        refusals.push(refused_payload(
            "dec_field_not_utf8",
            "A v2 payload whose key_id carries a 0xFF byte, CRC recomputed: LP fields are UTF-8.",
            "CC 2.6.8 wire format (LP = UTF-8)",
            PREFIX_V2,
            &p,
        ));
    }
    {
        let mut p = v2_hints_payload.clone();
        let lp = 2 + 32 + 32;
        p[lp] = 0xFF; // declared key_id length far past the end
        refusals.push(refused_payload(
            "dec_field_length_exceeds_buffer",
            "A v2 payload whose key_id length prefix declares 255 bytes the buffer does not hold, CRC recomputed.",
            "CC 2.6.8 wire format (LP)",
            PREFIX_V2,
            &p,
        ));
    }

    {
        let mut p = v2_hints_payload.clone();
        for b in &mut p[2..34] {
            *b = 0;
        }
        refusals.push(refused_payload(
            "dec_key_id_hash_zeroed",
            "The `v2_user_hints` payload with its sha256(key_id) zeroed, CRC recomputed: the hash does not match the display key_id.",
            "CC 2.6.8 wire format (a decoder MUST verify sha256(key_id) against key_id)",
            PREFIX_V2,
            &p,
        ));
    }
    {
        // The display key_id swapped after minting (same length), the hash left
        // as minted and the CRC recomputed: only the hash check catches it.
        let mut p = v2_hints_payload.clone();
        let id_at = 2 + 32 + 32 + 1;
        assert_eq!(p[id_at], b'a');
        p[id_at] = b'm';
        refusals.push(refused_payload(
            "dec_key_id_swapped",
            "The `v2_user_hints` payload with the display key_id's first byte changed (`alice-…` to `mlice-…`), the minted sha256(key_id) kept and the CRC recomputed: refused.",
            "CC 2.6.8 wire format (a decoder MUST verify sha256(key_id) against key_id)",
            PREFIX_V2,
            &p,
        ));
    }
    {
        // 1,025 bytes: the budget payload with one hint byte more, hand-built.
        let (_, budget_payload, _) = unrender(&encode_qr(&budget_fc).unwrap());
        let hint_len_at = 2 + 32 + 32 + 1 + alice.key_id.len();
        let mut p = budget_payload.clone();
        p[hint_len_at] += 1;
        p.insert(hint_len_at + 1, b'x');
        assert_eq!(p.len(), 1025);
        refusals.push(refused_payload(
            "dec_payload_1025",
            "The `v3_user_payload_1024` payload with one more transport-hint byte (1,025 bytes), CRC recomputed: refused by the decoder as `enc_payload_1025` is by the encoder.",
            "CC 2.6.8 constraint 3 (payload <= 1024 bytes before base32, enforced at encoder AND decoder)",
            PREFIX_V3,
            &p,
        ));
    }
    {
        // v2 payload with the group_key_id hint byte missing.
        assert_eq!(*v2_hints_payload.last().unwrap(), 0x00);
        refusals.push(refused_payload(
            "dec_v2_missing_group_hint",
            "The `v2_user_hints` payload ending after hint(alias), its 0x00 group_key_id hint byte removed, CRC recomputed: truncated.",
            "CC 2.6.8 wire format (hint(group_key_id) is 0x00 when absent, never omitted)",
            PREFIX_V2,
            &v2_hints_payload[..v2_hints_payload.len() - 1],
        ));
    }

    // -- display normalisation ----------------------------------------------------------------------
    let mut normalisation = Vec::new();
    for (target_id, display, qr) in [
        (
            "v3_user_nodes_and_commitment",
            reference_display.clone(),
            reference_qr.clone(),
        ),
        (
            "v2_user_hints",
            valid.iter().find(|v| v["id"] == "v2_user_hints").unwrap()["code"]
                .as_str()
                .unwrap()
                .to_string(),
            v2_hints_qr.clone(),
        ),
    ] {
        let target = decode(&display).unwrap();
        let body = qr.strip_prefix("CIRIS-V").unwrap();
        let (ver, rest) = body.split_at(1);
        let spaced: String = display.split('-').collect::<Vec<_>>().join(" - ");
        let newlines: String = display.replace('-', "\n");
        let forms: Vec<(&str, String)> = vec![
            ("dashed_display", display.clone()),
            ("undashed_qr", qr.clone()),
            ("lowercase_dashed", display.to_ascii_lowercase()),
            ("lowercase_undashed", qr.to_ascii_lowercase()),
            (
                "undashed_prefix_dashed_body",
                format!("CIRISV{ver}{}", group4(rest)),
            ),
            ("spaces_around_dashes", spaced),
            ("newlines_for_dashes", newlines),
            ("leading_trailing_whitespace", format!("  \t{display}\n")),
            ("mixed_case_and_whitespace", {
                let mut s = String::new();
                for (i, c) in qr.chars().enumerate() {
                    if i % 7 == 3 {
                        s.push(' ');
                    }
                    s.push(if i % 2 == 0 {
                        c.to_ascii_lowercase()
                    } else {
                        c
                    });
                }
                s
            }),
        ];
        for (form, input) in forms {
            let got = decode(&input).unwrap_or_else(|e| panic!("{target_id}/{form}: {e}"));
            assert_eq!(got, target, "{target_id}/{form}");
            normalisation.push(json!({
                "id": format!("norm_{target_id}_{form}"),
                "form": form,
                "input": input,
                "decodes_as": target_id,
            }));
        }
    }

    // -- the consumer's case: a v2-only decoder ------------------------------------------------------
    let consumer_cases = vec![json!({
        "id": "v2_only_decoder_refuses_v3_prefix",
        "description": "A v2-only decoder MUST refuse `CIRIS-V3-` (and `CIRISV3`) before reading a payload byte (CC 2.6.8 constraint 5). ciris_verify_core exposes no v2-only decode path, so this is the consumer's test: feed each input to a v2-only decoder and require a prefix refusal, not a parse attempt.",
        "constraint": "CC 2.6.8 constraint 5",
        "inputs": [reference_display, reference_qr, format!("CIRISV3{}", reference_qr.strip_prefix(PREFIX_V3).unwrap())],
        "expected": "refused on the prefix",
    })];

    // -- PQC admission (the commitment at the API) -----------------------------------------------------
    let pulled = ml_dsa_65_pubkey_stand_in();
    let committed =
        owner_code(&alice, FedKind::User).with_ml_dsa_65_pubkey_sha256(commitment.clone());
    let admitted = AdmittedHybridKey::admit(&committed, &pulled).unwrap();
    let mut substituted = pulled.clone();
    substituted[0] ^= 0x01;
    let substituted_err = AdmittedHybridKey::admit(&committed, &substituted).unwrap_err();
    let no_commitment_err =
        AdmittedHybridKey::admit(&owner_code(&alice, FedKind::User), &pulled).unwrap_err();
    let admission = json!({
        "ml_dsa_65_pubkey_stand_in": {
            "description": "A deterministic 1952-byte stand-in for a raw ML-DSA-65 public key: byte i = i mod 251. The vectors commit to its sha256; a port that cannot produce ML-DSA keys can still reproduce the commitment.",
            "len": ML_DSA_65_PUBKEY_LEN,
            "sha256_hex": commitment,
            "first_16_bytes_hex": hex::encode(&pulled[..16]),
        },
        "cases": [
            {
                "id": "admit_matching_pull",
                "description": "The pulled key hashes to the code's commitment: admitted, both halves returned.",
                "code": valid.iter().find(|v| v["id"] == "v3_user_commitment_only").unwrap()["code"],
                "pulled": "ml_dsa_65_pubkey_stand_in",
                "result": {
                    "key_id": admitted.key_id(),
                    "pubkey_ed25519_base64": admitted.pubkey_ed25519_base64(),
                    "ml_dsa_65_pubkey_base64_sha256_hex": hex::encode(Sha256::digest(admitted.ml_dsa_65_pubkey_base64().as_bytes())),
                }
            },
            {
                "id": "admit_substituted_pull",
                "description": "The pulled key differs from the commitment in one bit: refused (CC 2.6.8 PQC rule (a)).",
                "code": valid.iter().find(|v| v["id"] == "v3_user_commitment_only").unwrap()["code"],
                "pulled": "ml_dsa_65_pubkey_stand_in with byte 0 xor 0x01",
                "error": error_kind(&substituted_err),
            },
            {
                "id": "admit_without_commitment",
                "description": "A code with no commitment admits nothing: fails closed (CC 2.6.8: nothing to bind the pulled key to).",
                "code": valid.iter().find(|v| v["id"] == "v2_user_bare").unwrap()["code"],
                "pulled": "ml_dsa_65_pubkey_stand_in",
                "error": error_kind(&no_commitment_err),
            }
        ]
    });

    json!({
        "$schema_note": "Golden FedCode vectors generated by ciris-verify-core/tests/fedcode_vectors.rs from ciris_verify_core::fedcode (the CC 2.6.8 reference). Keys are sorted; regenerate with CIRIS_FEDCODE_VECTORS_REGENERATE=1. See README.md beside this file.",
        "spec": {
            "constitution": "CC 2.6.8 (key_id — FedCode)",
            "fsd": "FSD-003 §3, §3A, §4",
            "reference_implementation": "ciris_verify_core::fedcode",
        },
        "wire": {
            "crc": "CRC-16-CCITT, polynomial 0x1021, init 0xFFFF, no final xor, appended big-endian",
            "base32": "RFC 4648 alphabet A-Z2-7, no padding; display groups of 4 joined by '-', QR form ungrouped",
            "prefixes": [PREFIX_V1, PREFIX_V2, PREFIX_V3],
            "kind_bytes": {"user": 1, "agent": 2, "node": 3, "family": 4, "community": 5},
            "hint": "0x00 absent, else 1-byte length + UTF-8 (<= 255 bytes); order transport, alias, group_key_id",
            "v3_tail": "node_count(1) 0..=16, node_count x [LP(node_key_id) | transport_ed25519(32)], then 0x00 | 0x01 + sha256(raw ML-DSA-65 pubkey)(32)",
            "limits": {"max_owned_nodes": 16, "max_payload_bytes": 1024, "max_field_bytes": 255},
            "key_id": "<label>-<first 10 lowercase base32 chars of sha256(ed25519_pubkey)>",
        },
        "material": {
            "ed25519": "Every pubkey is ed25519-dalek's verifying key for the 32-byte seed shown (seed byte repeated 32 times).",
            "ml_dsa_65_pubkey_stand_in": "1952 bytes, byte i = i mod 251; its sha256 is the commitment carried by every vector.",
        },
        "valid": valid,
        "refusals": refusals,
        "normalisation": normalisation,
        "consumer_cases": consumer_cases,
        "admission": admission,
        "known_disagreements": {
            "note": "Where ciris_verify_core::fedcode departs from CC 2.6.8. Empty: the four departures recorded in v22.1.0 (unverified sha256(key_id), encoder-only payload bound, unreadable non-user commitment-only v3, tolerated missing group_key_id hint) were fixed in CIRISVerify#331 and their inputs now sit in `refusals` and `valid`.",
            "cases": Vec::<Value>::new(),
        },
    })
}

fn hex_of_b64(b64_text: &str) -> String {
    use base64::Engine as _;
    hex::encode(
        base64::engine::general_purpose::STANDARD
            .decode(b64_text)
            .unwrap(),
    )
}

fn render_json(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap() + "\n"
}

/// Read the committed file with LF line endings whatever the checkout did to
/// them (a Windows checkout with `core.autocrlf` rewrites text files to CRLF).
fn read_lf(path: &std::path::Path) -> std::io::Result<String> {
    std::fs::read_to_string(path).map(|t| t.replace("\r\n", "\n"))
}

// ---- tests ----------------------------------------------------------------------------------------------

/// Emit-or-verify: the committed file must equal what the codec produces now.
#[test]
fn vectors_match_the_codec() {
    let produced = render_json(&build_vectors());
    let path = vectors_dir().join(VECTOR_FILE);
    let regenerate = std::env::var_os(REGENERATE_ENV).is_some();
    if path.exists() && !regenerate {
        let on_disk = read_lf(&path).unwrap();
        assert!(
            on_disk == produced,
            "{} drifted from ciris_verify_core::fedcode. If the codec changed on purpose, \
             regenerate with {REGENERATE_ENV}=1 and review the diff.",
            path.display()
        );
    } else {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, produced).unwrap();
    }
}

fn load() -> Value {
    let path = vectors_dir().join(VECTOR_FILE);
    if !path.exists() {
        vectors_match_the_codec();
    }
    serde_json::from_str(&read_lf(&path).unwrap()).unwrap()
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v[k].as_str()
        .unwrap_or_else(|| panic!("{k} missing on {}", v["id"]))
}

fn opt(v: &Value) -> Option<String> {
    v.as_str().map(str::to_string)
}

fn fedcode_from_json(v: &Value) -> FedCode {
    let kind = match s(v, "kind") {
        "user" => FedKind::User,
        "agent" => FedKind::Agent,
        "node" => FedKind::Node,
        "family" => FedKind::Family,
        "community" => FedKind::Community,
        other => panic!("unknown kind {other}"),
    };
    let mut fc = FedCode::new(kind, s(v, "key_id"), s(v, "pubkey_ed25519_base64"));
    if let Some(t) = opt(&v["transport_hint"]) {
        fc = fc.with_transport_hint(t);
    }
    if let Some(a) = opt(&v["alias_hint"]) {
        fc = fc.with_alias_hint(a);
    }
    if let Some(g) = opt(&v["group_key_id"]) {
        fc = fc.with_group_key_id(g);
    }
    let nodes: Vec<OwnedNode> = v["owned_nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| OwnedNode::new(s(n, "key_id"), s(n, "transport_pubkey_ed25519_base64")))
        .collect();
    if !nodes.is_empty() {
        fc = fc.with_owned_nodes(nodes);
    }
    if let Some(c) = opt(&v["ml_dsa_65_pubkey_sha256"]) {
        fc = fc.with_ml_dsa_65_pubkey_sha256(c);
    }
    fc
}

/// Replay the committed file as a consumer would: every valid vector decodes
/// from both renders to the recorded value, re-encodes to the recorded code,
/// and its payload and CRC are what the file says; every refusal is refused
/// with the recorded error kind; every normalisation form decodes to its
/// target; any recorded disagreement still holds (none are recorded since
/// CIRISVerify#331).
#[test]
fn committed_vectors_replay() {
    let file = load();
    let valid = file["valid"].as_array().unwrap();
    assert!(
        valid.len() >= 20,
        "expected the full valid set, got {}",
        valid.len()
    );
    let by_id = |id: &str| valid.iter().find(|v| v["id"] == id).unwrap();

    for v in valid {
        let id = s(v, "id");
        let code = s(v, "code");
        let qr = s(v, "code_qr");
        let expected = fedcode_from_json(&v["decoded"]);
        assert_eq!(decode(code).unwrap(), expected, "{id}: display decode");
        assert_eq!(decode(qr).unwrap(), expected, "{id}: qr decode");
        let payload = hex::decode(s(v, "payload_hex")).unwrap();
        assert_eq!(
            payload.len(),
            v["payload_len"].as_u64().unwrap() as usize,
            "{id}"
        );
        assert_eq!(
            format!("{:04x}", crc16_ccitt(&payload)),
            s(v, "crc16_ccitt_hex"),
            "{id}: CRC"
        );
        let (display2, qr2, _) = render(s(v, "prefix"), &payload);
        assert_eq!(display2, code, "{id}: payload renders to the recorded code");
        assert_eq!(qr2, qr);
        assert!(code.starts_with(s(v, "prefix")));
        assert_eq!(format!("{:02x}", payload[0]), s(v, "version_byte_hex"));
        if !v["encoder_input"].is_null() {
            let input = fedcode_from_json(&v["encoder_input"]);
            assert_eq!(encode(&input).unwrap(), code, "{id}: re-encode");
            assert_eq!(encode_qr(&input).unwrap(), qr, "{id}: re-encode qr");
        }
        if let Some(twin) = v["identical_to"].as_str() {
            assert_eq!(by_id(twin)["code"], v["code"], "{id}: constraint 4");
        }
    }

    let refusals = file["refusals"].as_array().unwrap();
    assert!(
        refusals.len() >= 30,
        "expected the full refusal set, got {}",
        refusals.len()
    );
    for r in refusals {
        let id = s(r, "id");
        let err = match s(r, "stage") {
            "encode" => encode(&fedcode_from_json(&r["encoder_input"]))
                .expect_err(&format!("{id}: encoder must refuse")),
            "decode" => decode(s(r, "code")).expect_err(&format!("{id}: decoder must refuse")),
            other => panic!("{id}: stage {other}"),
        };
        assert_eq!(error_kind(&err), r["error"], "{id}: error kind");
    }

    for n in file["normalisation"].as_array().unwrap() {
        let target = fedcode_from_json(&by_id(s(n, "decodes_as"))["decoded"]);
        assert_eq!(decode(s(n, "input")).unwrap(), target, "{}", s(n, "id"));
    }

    for d in file["known_disagreements"]["cases"].as_array().unwrap() {
        let id = s(d, "id");
        let outcome = &d["shipped_outcome"];
        match decode(s(d, "code")) {
            Ok(fc) => assert_eq!(
                fedcode_json(&fc),
                outcome["decoded"],
                "{id}: the shipped decoder's acceptance changed; if the codec now follows CC 2.6.8, regenerate and move the case to refusals"
            ),
            Err(e) => assert_eq!(
                error_kind(&e),
                outcome["error"],
                "{id}: the shipped decoder's refusal changed; if the codec now follows CC 2.6.8, regenerate and move the case to valid"
            ),
        }
    }

    let stand_in = ml_dsa_65_pubkey_stand_in();
    assert_eq!(
        hex::encode(Sha256::digest(&stand_in)),
        s(
            &file["admission"]["ml_dsa_65_pubkey_stand_in"],
            "sha256_hex"
        )
    );
    for c in file["admission"]["cases"].as_array().unwrap() {
        let id = s(c, "id");
        let fc = decode(s(c, "code")).unwrap();
        let pulled = if s(c, "pulled").contains("xor") {
            let mut p = stand_in.clone();
            p[0] ^= 0x01;
            p
        } else {
            stand_in.clone()
        };
        match AdmittedHybridKey::admit(&fc, &pulled) {
            Ok(a) => {
                assert_eq!(a.key_id(), s(&c["result"], "key_id"), "{id}");
                assert_eq!(
                    a.pubkey_ed25519_base64(),
                    s(&c["result"], "pubkey_ed25519_base64")
                );
                assert_eq!(a.ml_dsa_65_pubkey_base64(), b64(&stand_in));
            },
            Err(e) => assert_eq!(error_kind(&e), c["error"], "{id}"),
        }
    }
}

/// The file is sorted-key, two-space JSON with one trailing newline, so a diff
/// is readable and a port's own serializer reproduces it.
#[test]
fn committed_file_is_canonical_json() {
    let path = vectors_dir().join(VECTOR_FILE);
    let text = read_lf(&path).unwrap_or_else(|_| {
        vectors_match_the_codec();
        read_lf(&path).unwrap()
    });
    let parsed: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(render_json(&parsed), text);
    fn sorted(v: &Value) -> bool {
        match v {
            Value::Object(m) => {
                let keys: Vec<&String> = m.keys().collect();
                let mut k2 = keys.clone();
                k2.sort();
                keys == k2 && m.values().all(sorted)
            },
            Value::Array(a) => a.iter().all(sorted),
            _ => true,
        }
    }
    assert!(sorted(&parsed));
    let _: Map<String, Value> = parsed.as_object().unwrap().clone();
}
