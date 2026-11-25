//! Replays `tests/vectors/edition2/room/private_room_v1.json` and
//! `private_room_rows_v1.json` (`gen_private_room_v1.py`, independent of
//! verify): the seat commitment, the binding of a voice to its person, the
//! sealed plaintexts of a room, a room's MLS group ids, `refs.also.voice`,
//! the leaf vouch and its door, the window rows, the room-key members of a
//! key record and an occurrence's binding key (CC 2.6.1.11, CC 3.3.6.1,
//! CC 3.3.6.4, CC 5.1; CIRISConstitution v1.0-rc22).
#![cfg(all(feature = "pqc", feature = "std"))]

use std::collections::BTreeMap;

use ciris_crypto::composite::{CompositePublicKey, CompositeSigningKey};
use ciris_crypto::xwing::XWingSecretKey;
use ciris_verify_core::cde;
use ciris_verify_core::edition2::keys::check_key_record;
use ciris_verify_core::edition2::leaf_vouch::{check_leaf_at_door, LeafDoor};
use ciris_verify_core::edition2::room::{
    binding_challenge_secret, binding_challenge_with_rng, binding_confirm_with_rng,
    binding_key_name, binding_open, mls_call_group_id, mls_group_id, open_invitation,
    open_room_wrap, seal_invitation_with_rng, seal_room_wrap_with_rng, seat_commitment,
    seat_commitment_input, seat_commitment_opens, BindingClaim, BindingConfirmation,
    BindingContext, BindingOpening, ConfirmInput, RoomSealed,
};
use ciris_verify_core::edition2::{
    check_identity_occurrence, thumbprint, verify_row_statement, Digest32, Invalid, Verdict,
};
use serde_json::Value as J;

const VALUES: &str = include_str!("vectors/edition2/room/private_room_v1.json");
const ROWS: &str = include_str!("vectors/edition2/room/private_room_rows_v1.json");
/// SHA-256 of each file, pinned so a regeneration is a visible change.
const PINS: [(&str, &str); 2] = [
    (
        VALUES,
        "553fb40a62136f1e5627351d5ecdbd1982af5f65e290809922aaa7c38cb0e4ba",
    ),
    (
        ROWS,
        "3fff0eef52a86a75a2e950e59e1297318fca5431a5643e4eeff7824459fc7cdc",
    ),
];

/// An RNG that returns the bytes it was given, for known answers only.
struct Fixed(Vec<u8>);

impl rand_core::RngCore for Fixed {
    fn next_u32(&mut self) -> u32 {
        unimplemented!()
    }
    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let rest = self.0.split_off(dest.len());
        dest.copy_from_slice(&self.0);
        self.0 = rest;
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl rand_core::CryptoRng for Fixed {}

fn h(v: &J) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn d32(v: &J) -> Digest32 {
    h(v).try_into().unwrap()
}

fn s(v: &J) -> &str {
    v.as_str().unwrap()
}

fn secret(v: &J) -> XWingSecretKey {
    XWingSecretKey::from_seed(d32(v))
}

fn values() -> J {
    serde_json::from_str(VALUES).unwrap()
}

fn rows() -> J {
    serde_json::from_str(ROWS).unwrap()
}

fn list<'a>(f: &'a J, k: &str, n: usize) -> &'a Vec<J> {
    let a = f[k].as_array().unwrap();
    assert_eq!(a.len(), n, "{k}");
    a
}

#[test]
fn files_are_pinned() {
    use sha2::Digest as _;
    for (file, pin) in PINS {
        assert_eq!(hex::encode(sha2::Sha256::digest(file.as_bytes())), pin);
    }
}

#[test]
fn derived_values() {
    let f = values();
    for c in list(&f, "seat_commitment", 5) {
        let (room, rk, person, nonce) = (
            s(&c["room"]),
            d32(&c["room_key_hex"]),
            s(&c["person"]),
            d32(&c["nonce_hex"]),
        );
        assert_eq!(
            seat_commitment_input(room, &rk, person, &nonce).unwrap(),
            h(&c["input_hex"]),
            "{}",
            c["id"]
        );
        let want = d32(&c["commitment_hex"]);
        assert_eq!(seat_commitment(room, &rk, person, &nonce).unwrap(), want);
        assert!(seat_commitment_opens(&want, room, &rk, person, &nonce));
    }
    // Each case's commitment opens only its own four.
    let all = list(&f, "seat_commitment", 5);
    let base = &all[0];
    for other in &all[1..] {
        assert!(!seat_commitment_opens(
            &d32(&other["commitment_hex"]),
            s(&base["room"]),
            &d32(&base["room_key_hex"]),
            s(&base["person"]),
            &d32(&base["nonce_hex"]),
        ));
    }
    for c in list(&f, "binding_key_name", 2) {
        assert_eq!(
            binding_key_name(&h(&c["key_hex"])).unwrap().to_vec(),
            h(&c["name_hex"])
        );
    }
    for c in list(&f, "mls_group_id", 2) {
        assert_eq!(
            mls_group_id(s(&c["room"])).unwrap().to_vec(),
            h(&c["id_hex"])
        );
    }
    for c in list(&f, "mls_call_group_id", 3) {
        assert_eq!(
            mls_call_group_id(s(&c["room"]), &h(&c["call_hex"]))
                .unwrap()
                .to_vec(),
            h(&c["id_hex"])
        );
    }
}

#[test]
fn binding_exchanges() {
    let f = values();
    for c in list(&f, "binding", 2) {
        let id = &c["id"];
        let binding_key = h(&c["binding_key_hex"]);
        // The challenge, by the addressee.
        let (ct_c, ss) =
            binding_challenge_with_rng(&binding_key, &mut Fixed(h(&c["challenge_eseed_hex"])))
                .unwrap();
        assert_eq!(ct_c, h(&c["challenge_hex"]), "{id}: challenge");
        assert_eq!(ss.to_vec(), h(&c["challenge_secret_hex"]), "{id}: secret");
        // The room key's holder decapsulates it under the binding key.
        let m_ss = binding_challenge_secret(&secret(&c["binding_secret_seed_hex"]), &ct_c).unwrap();
        assert_eq!(*m_ss, *ss, "{id}");
        let context = BindingContext {
            room: s(&c["room"]),
            room_key: d32(&c["room_key_hex"]),
            addressee_key: d32(&c["addressee_key_hex"]),
            seat_commitment: d32(&c["seat_commitment_hex"]),
            binding_key: &binding_key,
        };
        assert_eq!(context.info().unwrap(), h(&c["info_hex"]), "{id}: info");
        let opening = BindingOpening {
            person: s(&c["person"]).to_owned(),
            nonce: d32(&c["nonce_hex"]),
        };
        assert_eq!(opening.encode(), h(&c["opening_hex"]), "{id}: opening");
        // The confirmation.
        let kem_key = h(&c["addressee_kem_key_hex"]);
        let confirmation = binding_confirm_with_rng(
            &ConfirmInput {
                context: &context,
                challenge: &ct_c,
                challenge_secret: &m_ss,
                addressee_kem_key: &kem_key,
                opening: &opening,
            },
            &mut Fixed(h(&c["confirmation_eseed_hex"])),
        )
        .unwrap();
        assert_eq!(confirmation.enc, h(&c["confirmation"]["enc_hex"]), "{id}");
        assert_eq!(confirmation.ct, h(&c["confirmation"]["ct_hex"]), "{id}");
        // The addressee opens it.
        let opened = binding_open(
            &context,
            &confirmation,
            &ct_c,
            &ss,
            &secret(&c["addressee_kem_seed_hex"]),
            s(&c["person"]),
        )
        .unwrap();
        assert_eq!(opened, opening, "{id}");
    }
}

#[test]
fn binding_open_cases() {
    let f = values();
    for c in list(&f, "binding_open", 20) {
        let binding_key = h(&c["binding_key_hex"]);
        let context = BindingContext {
            room: s(&c["room"]),
            room_key: d32(&c["room_key_hex"]),
            addressee_key: d32(&c["addressee_key_hex"]),
            seat_commitment: d32(&c["seat_commitment_hex"]),
            binding_key: &binding_key,
        };
        let confirmation = BindingConfirmation {
            enc: h(&c["confirmation"]["enc_hex"]),
            ct: h(&c["confirmation"]["ct_hex"]),
        };
        let got = binding_open(
            &context,
            &confirmation,
            &h(&c["challenge_hex"]),
            &d32(&c["challenge_secret_hex"]),
            &secret(&c["addressee_kem_seed_hex"]),
            s(&c["person_challenged"]),
        );
        let got = match got {
            Ok(_) => "ok",
            Err(e) => e.token(),
        };
        assert_eq!(got, s(&c["expect"]), "{}", c["id"]);
    }
}

fn sealed_of(c: &J) -> RoomSealed {
    RoomSealed {
        dek: c.get("dek_hex").map(d32),
        claim: c.get("claim").map(|cl| BindingClaim {
            person: s(&cl["person"]).to_owned(),
            occurrence: cl["occurrence_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(h)
                .collect(),
        }),
        challenge: c.get("challenge_hex").map(h),
        confirmation: c.get("confirmation").map(|cf| BindingConfirmation {
            enc: h(&cf["enc_hex"]),
            ct: h(&cf["ct_hex"]),
        }),
    }
}

#[test]
fn sealed_plaintexts() {
    let f = values();
    for c in list(&f, "room_sealed", 9) {
        let sealed = sealed_of(c);
        let bytes = h(&c["plaintext_hex"]);
        assert_eq!(sealed.encode().unwrap(), bytes, "{}", c["id"]);
        assert_eq!(RoomSealed::decode(&bytes).unwrap(), sealed, "{}", c["id"]);
    }
    for c in list(&f, "room_sealed_refused", 13) {
        assert!(
            RoomSealed::decode(&h(&c["plaintext_hex"])).is_err(),
            "{}",
            c["id"]
        );
    }
    for c in list(&f, "room_wrap", 8) {
        let sealed = sealed_of(c);
        let wrapped = seal_room_wrap_with_rng(
            &h(&c["kem_key_hex"]),
            &sealed,
            &mut Fixed(h(&c["eseed_hex"])),
        )
        .unwrap();
        assert_eq!(wrapped, h(&c["sealed_hex"]), "{}", c["id"]);
        let sk = secret(&c["kem_seed_hex"]);
        assert_eq!(open_room_wrap(&sk, &wrapped).unwrap(), sealed);
        // A wrap is no invitation: the info differs.
        assert!(open_invitation(&sk, &wrapped).is_err());
    }
    for c in list(&f, "invitation", 2) {
        let pt = h(&c["plaintext_hex"]);
        let sealed =
            seal_invitation_with_rng(&h(&c["kem_key_hex"]), &pt, &mut Fixed(h(&c["eseed_hex"])))
                .unwrap();
        assert_eq!(sealed, h(&c["sealed_hex"]), "{}", c["id"]);
        let sk = secret(&c["kem_seed_hex"]);
        assert_eq!(*open_invitation(&sk, &sealed).unwrap(), pt);
        assert!(open_room_wrap(&sk, &sealed).is_err());
    }
}

fn held(c: &J) -> BTreeMap<Digest32, CompositePublicKey> {
    c["held_key_seeds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            let n = u8::try_from(n.as_u64().unwrap()).unwrap();
            let k = CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(100); 32]);
            (thumbprint(k.public_key()), k.public_key().clone())
        })
        .collect()
}

fn invalid(i: &Invalid) -> String {
    match i {
        Invalid::Malformed { member } => format!("invalid:malformed:{member}"),
        Invalid::UnexpectedMember { within } => format!("invalid:unexpected_member:{within}"),
        i => match i.token() {
            Some(t) => format!("invalid:{t}"),
            None => format!("invalid:{i:?}"),
        },
    }
}

#[test]
fn row_statements() {
    let f = rows();
    for c in list(&f, "row_statements", 44) {
        let got = match verify_row_statement(&h(&c["statement_hex"]), &held(c)) {
            Verdict::Valid(_) => "valid".to_owned(),
            Verdict::Invalid(i) => invalid(&i),
            Verdict::Waiting { .. } => "waiting".to_owned(),
        };
        assert_eq!(got, s(&c["expect"]), "{}", c["id"]);
    }
}

#[test]
fn leaf_door() {
    let f = rows();
    for c in list(&f, "leaf_door", 19) {
        let id = &c["id"];
        let row = c["statement_hex"].as_str().map(|st| {
            match verify_row_statement(&hex::decode(st).unwrap(), &held(c)) {
                Verdict::Valid(r) => *r,
                other => panic!("{id}: the presented row reads {other:?}"),
            }
        });
        let leaf_key = d32(&c["leaf_key_hex"]);
        let door = LeafDoor {
            room: s(&c["room"]),
            leaf_key: &leaf_key,
            member: s(&c["member"]),
            now_ms: c["now_ms"].as_u64().unwrap(),
            withdrawn: c["withdrawn"].as_bool().unwrap(),
        };
        let got = match check_leaf_at_door(row.as_ref(), &door) {
            Ok(entry) => {
                assert_eq!((entry.room.as_str(), entry.leaf_key), (door.room, leaf_key));
                "ok"
            },
            Err(r) => r.token(),
        };
        assert_eq!(got, s(&c["expect"]), "{id}");
    }
}

#[test]
fn key_records_and_occurrences() {
    let f = rows();
    let decode = |c: &J| cde::decode(&h(&c["payload_hex"])).unwrap();
    for c in list(&f, "key_records", 17) {
        let got = match check_key_record(&decode(c)) {
            Ok(r) => {
                // A record that carries `room` is a room key's.
                assert_eq!(r.room_key.is_some(), decode(c).get_text("room").is_some());
                "valid"
            },
            Err(e) => e.token(),
        };
        assert_eq!(got, s(&c["expect"]), "{}", c["id"]);
    }
    for c in list(&f, "occurrences", 13) {
        let got = match check_identity_occurrence(&decode(c)) {
            Ok(()) => "valid".to_owned(),
            Err(i) => invalid(&i),
        };
        assert_eq!(got, s(&c["expect"]), "{}", c["id"]);
    }
}
