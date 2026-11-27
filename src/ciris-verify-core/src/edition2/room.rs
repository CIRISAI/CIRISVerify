//! The wire of a private room (CC 2.6.1.11, CC 3.1.3.2, CC 5.1;
//! CIRISConstitution v1.0-rc22 f467193).
//!
//! **Derived values** (pure: no clock, no randomness, no I/O):
//!
//! ```text
//! seat commitment   = SHA-256( CDE( ["CEG-seat/2", room, room_key, person, nonce] ) )
//! binding key name  = SHA-256( CDE( ["CEG-binding-key/2", room_binding_xwing_pubkey] ) )
//! binding info      = CDE( ["CEG-binding/2", room, room_key, addressee_key,
//!                           [-16, seat_commitment], binding key name] )
//! binding opening   = CDE( [person, nonce] )
//! chat group id     = SHA-256( CDE( ["CEG-mls-group/2", room] ) )
//! call group id     = SHA-256( CDE( ["CEG-mls-call-group/2", room, call] ) )
//! ```
//!
//! `room` is the room's derived id (a group reference, text); `room_key` and
//! `addressee_key` are RFC 9679 thumbprints (32 bytes, as `kid` carries
//! them); `person` is an identity reference (text); `nonce` is 32 bytes.
//! The binding key's name is the verifier's encoding (CC 2.6.1.12, open
//! encodings): the labelled digest above over the 1216 bytes of the person's
//! `room_binding_xwing_pubkey`.
//!
//! **The binding of a voice to its person** (feature `std`): three flows
//! between M, who holds the room key R and the person's binding key, and A,
//! the addressee, who holds a room key of its own in the room.
//!
//! 1. *claim*, M to A: the person's identity reference.
//! 2. *challenge*, A to M ([`binding_challenge`]): `ct_c`, an X-Wing
//!    encapsulation to the person's binding key (1120 bytes). A keeps the
//!    shared secret.
//! 3. *confirmation*, M to A ([`binding_confirm`]): an RFC 9180 HPKE seal in
//!    `mode_psk` (KEM X-Wing 0x647a, HKDF-SHA256, AES-256-GCM) to the
//!    `kem_xwing_pubkey` of A's room key, with `psk` the challenge's shared
//!    secret, `psk_id = SHA-256(ct_c)`, `info` the binding info, empty `aad`
//!    and plaintext the binding opening.
//!
//! A opens it ([`binding_open`]), checks that `person` is the one it
//! challenged, and checks that the seat commitment recomputed from the
//! opening equals the commitment on R's record. There is no MAC and no
//! derived seed: the AEAD authenticates the opening under both shared
//! secrets. One exchange is made for each room key, each with a fresh
//! challenge. Whether the binding key stands on a live occurrence of the
//! person is A's own check and is not made here.
//!
//! **Sealed plaintexts** (feature `std`): a wrap to a room key and a sealed
//! envelope are HPKE `mode_base` seals under the same identifiers to the
//! recipient room key's `kem_xwing_pubkey`, `info` the text
//! `CEG-room-wrap/2`, empty `aad`, plaintext the deterministic encoding of
//! [`RoomSealed`]; on the wire `enc ‖ ct`. An invitation is sealed the same
//! way under `CEG-invitation/2`; its contents are the transport's.

use super::{cde, group::is_group_ref, hash_digest_value, is_identity_ref, Digest32, Value};
use crate::prelude::*;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The domain label of the seat commitment.
pub const SEAT_LABEL: &str = "CEG-seat/2";
/// The domain label of a binding's HPKE `info`.
pub const BINDING_LABEL: &str = "CEG-binding/2";
/// The domain label of a binding key's name.
pub const BINDING_KEY_LABEL: &str = "CEG-binding-key/2";
/// The HPKE `info` of an invitation, as text.
pub const INVITATION_INFO: &str = "CEG-invitation/2";
/// The HPKE `info` of a wrap to a room key and of a sealed envelope, as text.
pub const ROOM_WRAP_INFO: &str = "CEG-room-wrap/2";
/// The domain label of a room's chat MLS group id.
pub const MLS_GROUP_LABEL: &str = "CEG-mls-group/2";
/// The domain label of a room's call MLS group id.
pub const MLS_CALL_GROUP_LABEL: &str = "CEG-mls-call-group/2";
/// The `wrap_algorithm` of a `key_grant` row that wraps to a room key.
pub const ROOM_WRAP_ALGORITHM: &str = "xwing_hpke_aes256_gcm_hkdf_sha256";
/// The length of a seat commitment's nonce.
pub const SEAT_NONCE_LEN: usize = 32;
/// The length of an X-Wing encapsulation: a challenge, and the `enc` of a
/// confirmation or a wrap.
pub const XWING_ENCAPSULATION_LEN: usize = 1120;

/// Why a room value is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RoomError {
    /// `room` is not a group reference.
    Room,
    /// `person` is not an identity reference.
    Person,
    /// A key is not an X-Wing public key of 1216 bytes.
    Key,
    /// A challenge or an encapsulation is not 1120 bytes.
    Encapsulation,
    /// A sealed plaintext is not the deterministic encoding of its form.
    Encoding,
    /// The confirmation does not open: a wrong key, a wrong challenge, a
    /// different `info`, a tampered ciphertext. Opaque by design.
    Open,
    /// The opening names another person than the one challenged.
    OtherPerson,
    /// The seat commitment recomputed from the opening is not the one on the
    /// room key's record.
    SeatCommitment,
    /// The seal failed (the RNG health latch, or an AEAD fault).
    Seal,
}

impl RoomError {
    /// A stable token for logs and vectors.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Room => "room_not_group_ref",
            Self::Person => "person_not_identity_ref",
            Self::Key => "xwing_key_malformed",
            Self::Encapsulation => "encapsulation_malformed",
            Self::Encoding => "room_sealed_malformed",
            Self::Open => "binding_open_failed",
            Self::OtherPerson => "binding_other_person",
            Self::SeatCommitment => "binding_seat_commitment_mismatch",
            Self::Seal => "seal_failed",
        }
    }
}

impl core::fmt::Display for RoomError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.token())
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RoomError {}

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

fn b(x: &[u8]) -> Value {
    Value::Bytes(x.to_vec())
}

/// The deterministic encoding of
/// `["CEG-seat/2", room, room_key, person, nonce]`.
///
/// # Errors
/// [`RoomError::Room`] or [`RoomError::Person`] for a member off its form.
pub fn seat_commitment_input(
    room: &str,
    room_key: &Digest32,
    person: &str,
    nonce: &[u8; SEAT_NONCE_LEN],
) -> Result<Vec<u8>, RoomError> {
    if !is_group_ref(room) {
        return Err(RoomError::Room);
    }
    if !is_identity_ref(person) {
        return Err(RoomError::Person);
    }
    Ok(cde::encode(&Value::Array(vec![
        t(SEAT_LABEL),
        t(room),
        b(room_key),
        t(person),
        b(nonce),
    ])))
}

/// The seat commitment of a room key (CC 2.6.1.11): the 32 bytes of the
/// `[-16, digest]` its key record carries as `seat_commitment`.
///
/// # Errors
/// As [`seat_commitment_input`].
pub fn seat_commitment(
    room: &str,
    room_key: &Digest32,
    person: &str,
    nonce: &[u8; SEAT_NONCE_LEN],
) -> Result<Digest32, RoomError> {
    Ok(Sha256::digest(seat_commitment_input(room, room_key, person, nonce)?).into())
}

/// Whether `commitment` is the seat commitment of these four, compared in
/// constant time. Members off their form answer `false`.
#[must_use]
pub fn seat_commitment_opens(
    commitment: &Digest32,
    room: &str,
    room_key: &Digest32,
    person: &str,
    nonce: &[u8; SEAT_NONCE_LEN],
) -> bool {
    seat_commitment(room, room_key, person, nonce).is_ok_and(|c| bool::from(c.ct_eq(commitment)))
}

/// The name of a binding key as a binding's `info` carries it:
/// `SHA-256(CDE(["CEG-binding-key/2", key]))` over the 1216 bytes of the
/// person's `room_binding_xwing_pubkey`.
///
/// # Errors
/// [`RoomError::Key`] where `key` is not 1216 bytes.
pub fn binding_key_name(key: &[u8]) -> Result<Digest32, RoomError> {
    if key.len() != super::XWING_PUBLIC_KEY_LEN {
        return Err(RoomError::Key);
    }
    Ok(Sha256::digest(cde::encode(&Value::Array(vec![
        t(BINDING_KEY_LABEL),
        b(key),
    ])))
    .into())
}

/// What a binding is of: the room, the room key R it binds, the addressee's
/// room key, the commitment on R's record, and the person's binding key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingContext<'a> {
    /// The room's derived id.
    pub room: &'a str,
    /// The thumbprint of R, the room key the binding is of.
    pub room_key: Digest32,
    /// The thumbprint of the addressee's room key, never a node key.
    pub addressee_key: Digest32,
    /// The commitment on R's key record.
    pub seat_commitment: Digest32,
    /// The person's `room_binding_xwing_pubkey`, 1216 bytes.
    pub binding_key: &'a [u8],
}

impl BindingContext<'_> {
    /// The HPKE `info` of the confirmation: the deterministic encoding of
    /// `["CEG-binding/2", room, room_key, addressee_key, seat_commitment,
    /// binding_key]`.
    ///
    /// # Errors
    /// [`RoomError::Room`] or [`RoomError::Key`] for a member off its form.
    pub fn info(&self) -> Result<Vec<u8>, RoomError> {
        if !is_group_ref(self.room) {
            return Err(RoomError::Room);
        }
        let name = binding_key_name(self.binding_key)?;
        Ok(cde::encode(&Value::Array(vec![
            t(BINDING_LABEL),
            t(self.room),
            b(&self.room_key),
            b(&self.addressee_key),
            hash_digest_value(&self.seat_commitment),
            b(&name),
        ])))
    }
}

/// What a confirmation seals: the person and the nonce under the seat
/// commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingOpening {
    /// The person the room key's holder names.
    pub person: String,
    /// The nonce under the seat commitment.
    pub nonce: [u8; SEAT_NONCE_LEN],
}

impl BindingOpening {
    /// The deterministic encoding of `[person, nonce]`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        cde::encode(&Value::Array(vec![t(&self.person), b(&self.nonce)]))
    }

    /// Read `[person, nonce]`; the bytes must be their own deterministic
    /// encoding.
    ///
    /// # Errors
    /// [`RoomError::Encoding`].
    pub fn decode(bytes: &[u8]) -> Result<Self, RoomError> {
        let v = cde::decode(bytes).map_err(|_| RoomError::Encoding)?;
        match v.as_array() {
            Some([p, n]) => {
                let person = p
                    .as_text()
                    .filter(|p| is_identity_ref(p))
                    .ok_or(RoomError::Encoding)?;
                let nonce = n
                    .as_bytes()
                    .and_then(|n| <[u8; SEAT_NONCE_LEN]>::try_from(n).ok())
                    .ok_or(RoomError::Encoding)?;
                Ok(Self {
                    person: person.to_owned(),
                    nonce,
                })
            },
            _ => Err(RoomError::Encoding),
        }
    }
}

/// The id of a room's chat MLS group (CC 5.1):
/// `SHA-256(CDE(["CEG-mls-group/2", room]))`.
///
/// # Errors
/// [`RoomError::Room`].
pub fn mls_group_id(room: &str) -> Result<Digest32, RoomError> {
    if !is_group_ref(room) {
        return Err(RoomError::Room);
    }
    Ok(Sha256::digest(cde::encode(&Value::Array(vec![
        t(MLS_GROUP_LABEL),
        t(room),
    ])))
    .into())
}

/// The id of a room's call MLS group (CC 5.1):
/// `SHA-256(CDE(["CEG-mls-call-group/2", room, call]))`, `call` the call's
/// id as bytes.
///
/// # Errors
/// [`RoomError::Room`].
pub fn mls_call_group_id(room: &str, call: &[u8]) -> Result<Digest32, RoomError> {
    if !is_group_ref(room) {
        return Err(RoomError::Room);
    }
    Ok(Sha256::digest(cde::encode(&Value::Array(vec![
        t(MLS_CALL_GROUP_LABEL),
        t(room),
        b(call),
    ])))
    .into())
}

/// The first flow of a binding: the person the room key's holder names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingClaim {
    /// The person claimed, an identity reference.
    pub person: String,
    /// The statements of the person's `identity:occurrence` row that carries
    /// the binding key, where the addressee may hold none; empty where not
    /// carried.
    pub occurrence: Vec<Vec<u8>>,
}

/// The third flow of a binding: the seal the addressee opens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingConfirmation {
    /// The confirmation's own X-Wing encapsulation, 1120 bytes.
    pub enc: Vec<u8>,
    /// The AEAD ciphertext over the opening.
    pub ct: Vec<u8>,
}

/// What a wrap to a room key seals, and what a sealed envelope carries
/// (`room-sealed`, a closed map): a wrap carries `dek`, an envelope none;
/// either carries whichever flows of a binding ride it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoomSealed {
    /// The wrapped key, on a wrap.
    pub dek: Option<[u8; 32]>,
    /// The first flow.
    pub claim: Option<BindingClaim>,
    /// The second flow: the encapsulation to the person's binding key.
    pub challenge: Option<Vec<u8>>,
    /// The third flow.
    pub confirmation: Option<BindingConfirmation>,
}

impl RoomSealed {
    /// The deterministic encoding of the map.
    ///
    /// # Errors
    /// [`RoomError::Person`] for a claim whose person is no identity
    /// reference; [`RoomError::Encapsulation`] for a challenge or an `enc`
    /// that is not 1120 bytes.
    pub fn encode(&self) -> Result<Vec<u8>, RoomError> {
        let mut m: Vec<(Value, Value)> = Vec::new();
        if let Some(d) = &self.dek {
            m.push((t("dek"), b(d)));
        }
        if let Some(c) = &self.claim {
            if !is_identity_ref(&c.person) {
                return Err(RoomError::Person);
            }
            let mut cm = vec![(t("person"), t(&c.person))];
            if !c.occurrence.is_empty() {
                cm.push((
                    t("occurrence"),
                    Value::Array(c.occurrence.iter().map(|s| b(s)).collect()),
                ));
            }
            m.push((t("claim"), Value::Map(cm)));
        }
        if let Some(c) = &self.challenge {
            if c.len() != XWING_ENCAPSULATION_LEN {
                return Err(RoomError::Encapsulation);
            }
            m.push((t("challenge"), b(c)));
        }
        if let Some(c) = &self.confirmation {
            if c.enc.len() != XWING_ENCAPSULATION_LEN {
                return Err(RoomError::Encapsulation);
            }
            m.push((
                t("confirmation"),
                Value::Map(vec![(t("enc"), b(&c.enc)), (t("ct"), b(&c.ct))]),
            ));
        }
        Ok(cde::encode(&Value::Map(m)))
    }

    /// Read the map; the bytes must be their own deterministic encoding and
    /// carry no member the form does not name.
    ///
    /// # Errors
    /// [`RoomError::Encoding`].
    pub fn decode(bytes: &[u8]) -> Result<Self, RoomError> {
        let bad = RoomError::Encoding;
        let v = cde::decode(bytes).map_err(|_| bad)?;
        let m = v.as_map().ok_or(bad)?;
        let mut out = Self::default();
        for (k, x) in m {
            match k.as_text() {
                Some("dek") => {
                    out.dek = Some(
                        x.as_bytes()
                            .and_then(|d| <[u8; 32]>::try_from(d).ok())
                            .ok_or(bad)?,
                    );
                },
                Some("claim") => {
                    let cm = x.as_map().ok_or(bad)?;
                    let mut person = None;
                    let mut occurrence = Vec::new();
                    for (ck, cx) in cm {
                        match ck.as_text() {
                            Some("person") => {
                                person = cx.as_text().filter(|p| is_identity_ref(p));
                                if person.is_none() {
                                    return Err(bad);
                                }
                            },
                            Some("occurrence") => {
                                occurrence = cx
                                    .as_array()
                                    .filter(|a| !a.is_empty())
                                    .ok_or(bad)?
                                    .iter()
                                    .map(|s| s.as_bytes().map(<[u8]>::to_vec).ok_or(bad))
                                    .collect::<Result<_, _>>()?;
                            },
                            _ => return Err(bad),
                        }
                    }
                    out.claim = Some(BindingClaim {
                        person: person.ok_or(bad)?.to_owned(),
                        occurrence,
                    });
                },
                Some("challenge") => {
                    out.challenge = Some(
                        x.as_bytes()
                            .filter(|c| c.len() == XWING_ENCAPSULATION_LEN)
                            .ok_or(bad)?
                            .to_vec(),
                    );
                },
                Some("confirmation") => {
                    let cm = x.as_map().filter(|m| m.len() == 2).ok_or(bad)?;
                    let _ = cm;
                    let enc = x
                        .get_text("enc")
                        .and_then(Value::as_bytes)
                        .filter(|e| e.len() == XWING_ENCAPSULATION_LEN)
                        .ok_or(bad)?;
                    let ct = x.get_text("ct").and_then(Value::as_bytes).ok_or(bad)?;
                    out.confirmation = Some(BindingConfirmation {
                        enc: enc.to_vec(),
                        ct: ct.to_vec(),
                    });
                },
                _ => return Err(bad),
            }
        }
        Ok(out)
    }
}

// ------------------------------------------------------------ the room's door

/// The room a row is of, by its placement (CC 3.1.3.2): `cohort_scope` is
/// `community` and `community_id` is that room's id. `None` for a row placed
/// anywhere else. Whether that room is private is the room's own record, which
/// the caller holds.
#[must_use]
pub fn row_room(payload: &Value) -> Option<&str> {
    if payload.get_text("cohort_scope").and_then(Value::as_text) != Some("community") {
        return None;
    }
    payload
        .get_text("community_id")
        .and_then(Value::as_text)
        .filter(|r| is_group_ref(r))
}

/// The head of the signer's voice roster a row names: the one row under
/// `refs.also.voice` (CC 2.6.1.11). `None` where the row names none.
#[must_use]
pub fn row_voice_head(payload: &Value) -> Option<Digest32> {
    let set = payload
        .get_text("refs")?
        .get_text("also")?
        .get_text("voice")?
        .as_array()?;
    match set {
        [one] => match one.as_array()? {
            [_, d] => match d.as_array()? {
                [_, bytes] => bytes.as_bytes()?.try_into().ok(),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

/// The caller's view of one voice's key roster at one head: the fold is the
/// caller's (the self-roster fold with the voice in place of the identity,
/// CC 3.1.3.2), not made here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoiceRoster<'a> {
    /// The head this view is of: the row id a room row names under
    /// `refs.also.voice`. For a voice of one key, that key's own record.
    pub head: Digest32,
    /// The voice's name: the identity reference of its first room key.
    pub voice: &'a str,
    /// The thumbprints of the room keys live in the voice at that head.
    pub live_keys: &'a [Digest32],
}

/// Why a row of a private room is refused at the room's door: a fault of
/// the row and its signer's record alone (CC 3.1.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RoomRowRefusal {
    /// The row is placed in no room (`cohort_scope` is not `community` with a
    /// `community_id`): the caller asked about a row that is not a room's.
    /// Not CC's token; a caller's error.
    NotARoomRow,
    /// `room_row_signer_not_room_key`: the key that signed is no room key
    /// (its record carries no `room`): an identity key or a node key.
    SignerNotRoomKey,
    /// `room_key_other_room`: the signing key's record names another room
    /// than the one the row is placed in.
    KeyOtherRoom,
    /// `room_row_voice_head_malformed`: `refs.also.voice` is missing or
    /// names more than one row.
    VoiceHeadMalformed,
}

impl RoomRowRefusal {
    /// The refusal token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::NotARoomRow => "not_a_room_row",
            Self::SignerNotRoomKey => "room_row_signer_not_room_key",
            Self::KeyOtherRoom => "room_key_other_room",
            Self::VoiceHeadMalformed => "room_row_voice_head_malformed",
        }
    }
}

/// Why a well-formed row of a private room concludes nothing: it reads other
/// rows (the voice's roster), so it is no fault of the row alone and has no
/// refusal name (CC 3.1.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotOfTheVoice {
    /// The row's `iss` is not the voice whose roster head it names.
    IssNotTheVoice,
    /// The room key that signed is not a live key of the voice at that head.
    KeyNotLive,
}

/// What the door answers for one row of a private room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum RoomRowReading {
    /// The row is its voice's: signed by a room key of this room that is live
    /// in the voice at the head the row names.
    Valid,
    /// The caller holds no view of the voice roster at the head the row
    /// names: the row waits on that row (never refused, never passed).
    Waiting {
        /// The head named under `refs.also.voice`.
        head: Digest32,
    },
    /// The row concludes nothing.
    ConcludesNothing(NotOfTheVoice),
    /// Refused.
    Refused(RoomRowRefusal),
}

/// The door of a private room for one row (CC 3.1.3.2, CC 2.6.1.11), over a
/// statement the reader already verified. The caller has established that
/// the room the row is placed in is private.
///
/// - `iss`, `kid`, `payload`: the verified row's issuer, signing key and
///   payload.
/// - `signer_record`: the key record of `kid`, as [`super::keys::check_key_record`]
///   read it.
/// - `roster`: the caller's view of the voice roster at the head the row
///   names ([`row_voice_head`]); `None` where it holds none.
///
/// In order: the row is placed in a room; the signing key is a room key
/// (`room_row_signer_not_room_key`); it is this room's
/// (`room_key_other_room`); the row names exactly one head of its voice's
/// roster (`room_row_voice_head_malformed`); with no view at that head the
/// row waits; then, concluding nothing otherwise, `iss` is the voice and the
/// key is live in the voice at that head. A node's room key is no voice (it is owned in the
/// room by a member's room key): rows under one are not read here.
pub fn check_room_row(
    iss: &str,
    kid: &Digest32,
    payload: &Value,
    signer_record: &super::keys::KeyRecord,
    roster: Option<&VoiceRoster<'_>>,
) -> RoomRowReading {
    use RoomRowReading::Refused;
    let Some(room) = row_room(payload) else {
        return Refused(RoomRowRefusal::NotARoomRow);
    };
    let Some(members) = &signer_record.room_key else {
        return Refused(RoomRowRefusal::SignerNotRoomKey);
    };
    if members.room != room {
        return Refused(RoomRowRefusal::KeyOtherRoom);
    }
    let Some(head) = row_voice_head(payload) else {
        return Refused(RoomRowRefusal::VoiceHeadMalformed);
    };
    let Some(roster) = roster.filter(|r| bool::from(r.head.ct_eq(&head))) else {
        return RoomRowReading::Waiting { head };
    };
    if iss != roster.voice {
        return RoomRowReading::ConcludesNothing(NotOfTheVoice::IssNotTheVoice);
    }
    if !roster.live_keys.iter().any(|k| bool::from(k.ct_eq(kid))) {
        return RoomRowReading::ConcludesNothing(NotOfTheVoice::KeyNotLive);
    }
    RoomRowReading::Valid
}

/// The two rows that would tie a room key to an identity in public
/// (CC 3.1.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomKeyRow {
    /// An `identity:occurrence` naming the room key.
    Occurrence,
    /// An owner-binding naming the room key, as the owned or the owning key.
    OwnerBinding,
}

impl RoomKeyRow {
    /// CC's refusal token for such a row placed outside the key's room.
    #[must_use]
    pub const fn outside_room_token(self) -> &'static str {
        match self {
            Self::Occurrence => "room_key_occurrence_outside_room",
            Self::OwnerBinding => "room_key_binding_outside_room",
        }
    }
}

/// An `identity:occurrence` or an owner-binding that names a room key is
/// placed in that key's own room and nowhere else (CC 3.1.3.2): `payload` is
/// the row's, `key_room` the `room` of the room key's record.
///
/// # Errors
/// The row's kind, whose [`RoomKeyRow::outside_room_token`] is the refusal,
/// where the row is placed anywhere but at community scope with that room's
/// `community_id`.
pub fn check_room_key_row_placement(
    kind: RoomKeyRow,
    payload: &Value,
    key_room: &str,
) -> Result<(), RoomKeyRow> {
    if row_room(payload) == Some(key_room) {
        Ok(())
    } else {
        Err(kind)
    }
}

#[cfg(test)]
mod door_tests {
    use super::*;
    use crate::edition2::keys::{KeyRecord, RoomKeyMembers};
    use ciris_crypto::composite::CompositeSigningKey;

    const ROOM: &str = "group-ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs";
    const ROOM2: &str = "group-PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0";
    const VOICE: &str =
        "urn:ietf:params:oauth:ckt:sha-256:1vCVtzih4Y-2L6kkeANhicuJQgOUbUxxpS2bJ7QRdGM";

    fn record(room: Option<&str>) -> KeyRecord {
        let k = CompositeSigningKey::from_seeds(&[1; 32], &[101; 32]);
        KeyRecord {
            kid: crate::edition2::thumbprint(k.public_key()),
            key: k.public_key().clone(),
            identity_type: vec!["user".into()],
            asserted_at: 1,
            valid_until: None,
            pq_custody: None,
            hardware_class: None,
            chain: Vec::new(),
            room_key: room.map(|r| RoomKeyMembers {
                room: r.into(),
                kem_xwing_pubkey: vec![0; 1216],
                seat_commitment: [0; 32],
            }),
        }
    }

    fn row(room: Option<&str>, voice_heads: &[u8]) -> Value {
        let mut m = vec![(t("asserted_at"), Value::Uint(5))];
        if let Some(r) = room {
            m.push((t("cohort_scope"), t("community")));
            m.push((t("community_id"), t(r)));
        }
        if !voice_heads.is_empty() {
            let refs = voice_heads
                .iter()
                .map(|n| Value::Array(vec![Value::Uint(2), hash_digest_value(&[*n; 32])]))
                .collect();
            m.push((
                t("refs"),
                Value::Map(vec![(
                    t("also"),
                    Value::Map(vec![(t("voice"), Value::Array(refs))]),
                )]),
            ));
        }
        Value::Map(m)
    }

    #[test]
    fn the_door_in_order() {
        use RoomRowReading::{ConcludesNothing, Refused, Valid, Waiting};
        let rec = record(Some(ROOM));
        let kid = rec.kid;
        let live = [kid];
        let roster = VoiceRoster {
            head: [7; 32],
            voice: VOICE,
            live_keys: &live,
        };
        let check = |p: &Value, r: &KeyRecord, v: Option<&VoiceRoster<'_>>| {
            check_room_row(VOICE, &kid, p, r, v)
        };
        let good = row(Some(ROOM), &[7]);
        assert_eq!(check(&good, &rec, Some(&roster)), Valid);
        // Not placed in a room.
        assert_eq!(
            check(&row(None, &[7]), &rec, Some(&roster)),
            Refused(RoomRowRefusal::NotARoomRow)
        );
        // An identity or node key: its record carries no room.
        assert_eq!(
            check(&good, &record(None), Some(&roster)),
            Refused(RoomRowRefusal::SignerNotRoomKey)
        );
        // A room key of another room, named before any roster is read.
        assert_eq!(
            check(&good, &record(Some(ROOM2)), None),
            Refused(RoomRowRefusal::KeyOtherRoom)
        );
        // No head named, or two.
        for heads in [&[][..], &[7, 8][..]] {
            assert_eq!(
                check(&row(Some(ROOM), heads), &rec, Some(&roster)),
                Refused(RoomRowRefusal::VoiceHeadMalformed)
            );
        }
        // No view, or a view of another head: the row waits on the head it names.
        assert_eq!(check(&good, &rec, None), Waiting { head: [7; 32] });
        assert_eq!(
            check(&row(Some(ROOM), &[9]), &rec, Some(&roster)),
            Waiting { head: [9; 32] }
        );
        // iss is not the voice.
        assert_eq!(
            check_room_row("urn:other", &kid, &good, &rec, Some(&roster)),
            ConcludesNothing(NotOfTheVoice::IssNotTheVoice)
        );
        // The key is not live in the voice at that head.
        let none_live = VoiceRoster {
            live_keys: &[[1; 32]],
            ..roster.clone()
        };
        assert_eq!(
            check(&good, &rec, Some(&none_live)),
            ConcludesNothing(NotOfTheVoice::KeyNotLive)
        );
    }

    #[test]
    fn a_room_key_row_is_placed_in_its_room() {
        let inside = row(Some(ROOM), &[]);
        for kind in [RoomKeyRow::Occurrence, RoomKeyRow::OwnerBinding] {
            assert_eq!(check_room_key_row_placement(kind, &inside, ROOM), Ok(()));
            assert_eq!(
                check_room_key_row_placement(kind, &inside, ROOM2),
                Err(kind)
            );
            assert_eq!(
                check_room_key_row_placement(kind, &row(None, &[]), ROOM),
                Err(kind)
            );
        }
        assert_eq!(
            RoomKeyRow::Occurrence.outside_room_token(),
            "room_key_occurrence_outside_room"
        );
        assert_eq!(
            RoomKeyRow::OwnerBinding.outside_room_token(),
            "room_key_binding_outside_room"
        );
    }
}

#[cfg(feature = "std")]
pub use sealed::*;

#[cfg(feature = "std")]
mod sealed {
    use super::{
        seat_commitment_opens, BindingConfirmation, BindingContext, BindingOpening, Digest32,
        RoomError, RoomSealed, INVITATION_INFO, ROOM_WRAP_INFO, SEAT_NONCE_LEN,
        XWING_ENCAPSULATION_LEN,
    };
    use crate::edition2::is_identity_ref;
    use crate::prelude::*;
    use ciris_crypto::hpke::{self, HpkeSealed};
    use ciris_crypto::xwing::{XWingPublicKey, XWingSecretKey};
    use rand_core::CryptoRngCore;
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    /// The shared secret of a challenge: the `psk` of the confirmation.
    pub type ChallengeSecret = Zeroizing<[u8; 32]>;

    fn pk(bytes: &[u8]) -> Result<XWingPublicKey, RoomError> {
        XWingPublicKey::from_bytes(bytes).map_err(|_| RoomError::Key)
    }

    /// The second flow, made by the addressee: an X-Wing encapsulation to
    /// the person's binding key. Returns `ct_c` (1120 bytes), which travels,
    /// and the shared secret, which the addressee keeps to open the
    /// confirmation. A fresh challenge is made for each room key.
    ///
    /// # Errors
    /// [`RoomError::Key`] where `binding_key` is no X-Wing public key.
    pub fn binding_challenge_with_rng(
        binding_key: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, ChallengeSecret), RoomError> {
        let (ct, ss) = pk(binding_key)?.encapsulate_with_rng(rng);
        Ok((ct.to_vec(), ss))
    }

    /// [`binding_challenge_with_rng`] with randomness from the health-latched
    /// RNG.
    ///
    /// # Errors
    /// [`RoomError::Key`]; [`RoomError::Seal`] if the RNG latch has failed.
    pub fn binding_challenge(binding_key: &[u8]) -> Result<(Vec<u8>, ChallengeSecret), RoomError> {
        let (ct, ss) = pk(binding_key)?
            .encapsulate()
            .map_err(|_| RoomError::Seal)?;
        Ok((ct.to_vec(), ss))
    }

    /// What the room key's holder gives to make a confirmation.
    pub struct ConfirmInput<'a> {
        /// What the binding is of.
        pub context: &'a BindingContext<'a>,
        /// The challenge received, `ct_c`.
        pub challenge: &'a [u8],
        /// The challenge's shared secret: `ct_c` decapsulated under the
        /// person's binding key, wherever that key is kept.
        pub challenge_secret: &'a [u8; 32],
        /// The `kem_xwing_pubkey` of the addressee's room key.
        pub addressee_kem_key: &'a [u8],
        /// The person and the nonce under R's seat commitment.
        pub opening: &'a BindingOpening,
    }

    fn psk_id(challenge: &[u8]) -> Result<[u8; 32], RoomError> {
        if challenge.len() != XWING_ENCAPSULATION_LEN {
            return Err(RoomError::Encapsulation);
        }
        Ok(Sha256::digest(challenge).into())
    }

    /// The third flow, made by the room key's holder: the HPKE `mode_psk`
    /// seal of the opening to the addressee's room key. The opening must
    /// open the context's seat commitment, so no confirmation is made that
    /// its addressee would refuse.
    ///
    /// # Errors
    /// [`RoomError::Person`], [`RoomError::Room`], [`RoomError::Key`],
    /// [`RoomError::Encapsulation`]; [`RoomError::SeatCommitment`] where the
    /// opening does not open the commitment; [`RoomError::Seal`].
    pub fn binding_confirm_with_rng(
        input: &ConfirmInput<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<BindingConfirmation, RoomError> {
        let (info, id, to) = confirm_parts(input)?;
        let s = hpke::seal_psk_with_rng(
            &to,
            &info,
            &[],
            &input.opening.encode(),
            input.challenge_secret,
            &id,
            rng,
        )
        .map_err(|_| RoomError::Seal)?;
        Ok(BindingConfirmation {
            enc: s.encapsulation,
            ct: s.ciphertext,
        })
    }

    /// [`binding_confirm_with_rng`] with randomness from the health-latched
    /// RNG.
    ///
    /// # Errors
    /// As [`binding_confirm_with_rng`].
    pub fn binding_confirm(input: &ConfirmInput<'_>) -> Result<BindingConfirmation, RoomError> {
        let (info, id, to) = confirm_parts(input)?;
        let s = hpke::seal_psk(
            &to,
            &info,
            &[],
            &input.opening.encode(),
            input.challenge_secret,
            &id,
        )
        .map_err(|_| RoomError::Seal)?;
        Ok(BindingConfirmation {
            enc: s.encapsulation,
            ct: s.ciphertext,
        })
    }

    fn confirm_parts(
        input: &ConfirmInput<'_>,
    ) -> Result<(Vec<u8>, [u8; 32], XWingPublicKey), RoomError> {
        let c = input.context;
        if !is_identity_ref(&input.opening.person) {
            return Err(RoomError::Person);
        }
        let info = c.info()?;
        let id = psk_id(input.challenge)?;
        let to = pk(input.addressee_kem_key)?;
        if !seat_commitment_opens(
            &c.seat_commitment,
            c.room,
            &c.room_key,
            &input.opening.person,
            &input.opening.nonce,
        ) {
            return Err(RoomError::SeatCommitment);
        }
        Ok((info, id, to))
    }

    /// The challenge's shared secret, for a holder whose binding key is held
    /// as an [`XWingSecretKey`]: `ct_c` decapsulated.
    ///
    /// # Errors
    /// [`RoomError::Encapsulation`] where `challenge` is not 1120 bytes.
    pub fn binding_challenge_secret(
        binding_secret_key: &XWingSecretKey,
        challenge: &[u8],
    ) -> Result<ChallengeSecret, RoomError> {
        binding_secret_key
            .decapsulate(challenge)
            .map_err(|_| RoomError::Encapsulation)
    }

    /// The addressee opens a confirmation: the HPKE open under its room
    /// key's KEM secret, the challenge it made and the secret it kept; then
    /// the two checks CC 2.6.1.11 puts on it: `person` is the one challenged,
    /// and the seat commitment recomputed from the opening is the one on the
    /// room key's record (constant time). Whether the binding key stands on
    /// a live occurrence of the person is the addressee's own further check.
    ///
    /// # Errors
    /// [`RoomError::Open`], opaque, where the seal does not open or its
    /// plaintext is no opening; [`RoomError::OtherPerson`];
    /// [`RoomError::SeatCommitment`]; [`RoomError::Room`] or
    /// [`RoomError::Key`] for a context off its form.
    pub fn binding_open(
        context: &BindingContext<'_>,
        confirmation: &BindingConfirmation,
        challenge: &[u8],
        challenge_secret: &[u8; 32],
        addressee_kem_secret: &XWingSecretKey,
        person_challenged: &str,
    ) -> Result<BindingOpening, RoomError> {
        let info = context.info()?;
        let id = psk_id(challenge).map_err(|_| RoomError::Open)?;
        let sealed = HpkeSealed {
            encapsulation: confirmation.enc.clone(),
            ciphertext: confirmation.ct.clone(),
        };
        let pt = Zeroizing::new(
            hpke::open_psk(
                addressee_kem_secret,
                &sealed,
                &info,
                &[],
                challenge_secret,
                &id,
            )
            .map_err(|_| RoomError::Open)?,
        );
        let opening = BindingOpening::decode(&pt).map_err(|_| RoomError::Open)?;
        if opening.person != person_challenged {
            return Err(RoomError::OtherPerson);
        }
        if !seat_commitment_opens(
            &context.seat_commitment,
            context.room,
            &context.room_key,
            &opening.person,
            &opening.nonce,
        ) {
            return Err(RoomError::SeatCommitment);
        }
        Ok(opening)
    }

    fn wire(s: HpkeSealed) -> Vec<u8> {
        let mut out = s.encapsulation;
        out.extend_from_slice(&s.ciphertext);
        out
    }

    fn unwire(bytes: &[u8]) -> Result<HpkeSealed, RoomError> {
        if bytes.len() < XWING_ENCAPSULATION_LEN {
            return Err(RoomError::Open);
        }
        let (enc, ct) = bytes.split_at(XWING_ENCAPSULATION_LEN);
        Ok(HpkeSealed {
            encapsulation: enc.to_vec(),
            ciphertext: ct.to_vec(),
        })
    }

    /// Seal `plaintext` to a room key's `kem_xwing_pubkey` in HPKE
    /// `mode_base` under `info`, empty `aad`: `enc ‖ ct`.
    fn seal_to(
        kem_key: &[u8],
        info: &str,
        plaintext: &[u8],
        rng: Option<&mut dyn rand_core::CryptoRngCore>,
    ) -> Result<Vec<u8>, RoomError> {
        let to = pk(kem_key)?;
        let s = match rng {
            Some(mut r) => hpke::seal_base_with_rng(&to, info.as_bytes(), &[], plaintext, &mut r),
            None => hpke::seal_base(&to, info.as_bytes(), &[], plaintext),
        }
        .map_err(|_| RoomError::Seal)?;
        Ok(wire(s))
    }

    /// A wrap to a room key, or a sealed envelope to one: `sealed` under
    /// `CEG-room-wrap/2`, as the `wrapped_dek` of a `key_grant` row carries
    /// it (`enc`, 1120 bytes, then the AEAD ciphertext).
    ///
    /// # Errors
    /// [`RoomError::Key`], a [`RoomSealed::encode`] error, or
    /// [`RoomError::Seal`].
    pub fn seal_room_wrap(kem_key: &[u8], sealed: &RoomSealed) -> Result<Vec<u8>, RoomError> {
        seal_to(
            kem_key,
            ROOM_WRAP_INFO,
            &Zeroizing::new(sealed.encode()?),
            None,
        )
    }

    /// [`seal_room_wrap`] with the encapsulation's randomness from `rng`.
    ///
    /// # Errors
    /// As [`seal_room_wrap`].
    pub fn seal_room_wrap_with_rng(
        kem_key: &[u8],
        sealed: &RoomSealed,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, RoomError> {
        seal_to(
            kem_key,
            ROOM_WRAP_INFO,
            &Zeroizing::new(sealed.encode()?),
            Some(rng),
        )
    }

    /// Open a wrap or a sealed envelope under the room key's KEM secret.
    ///
    /// # Errors
    /// [`RoomError::Open`], opaque; [`RoomError::Encoding`] where the
    /// plaintext is not a `room-sealed` map.
    pub fn open_room_wrap(
        kem_secret: &XWingSecretKey,
        wrapped: &[u8],
    ) -> Result<RoomSealed, RoomError> {
        let pt = Zeroizing::new(
            hpke::open_base(
                kem_secret,
                &unwire(wrapped)?,
                ROOM_WRAP_INFO.as_bytes(),
                &[],
            )
            .map_err(|_| RoomError::Open)?,
        );
        RoomSealed::decode(&pt)
    }

    /// Seal an invitation's bytes under `CEG-invitation/2`: `enc ‖ ct`. What
    /// the plaintext holds beyond a binding's flows, and the key a first
    /// invitation is sealed to, are the transport's (CC 2.6.1.12).
    ///
    /// # Errors
    /// [`RoomError::Key`] or [`RoomError::Seal`].
    pub fn seal_invitation(kem_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, RoomError> {
        seal_to(kem_key, INVITATION_INFO, plaintext, None)
    }

    /// [`seal_invitation`] with the encapsulation's randomness from `rng`.
    ///
    /// # Errors
    /// As [`seal_invitation`].
    pub fn seal_invitation_with_rng(
        kem_key: &[u8],
        plaintext: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, RoomError> {
        seal_to(kem_key, INVITATION_INFO, plaintext, Some(rng))
    }

    /// Open an invitation under the invitee's KEM secret.
    ///
    /// # Errors
    /// [`RoomError::Open`], opaque.
    pub fn open_invitation(
        kem_secret: &XWingSecretKey,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, RoomError> {
        hpke::open_base(
            kem_secret,
            &unwire(sealed)?,
            INVITATION_INFO.as_bytes(),
            &[],
        )
        .map(Zeroizing::new)
        .map_err(|_| RoomError::Open)
    }

    /// A seat commitment's nonce and the commitment, made fresh for a new
    /// room key.
    ///
    /// # Errors
    /// [`RoomError::Seal`] if the RNG latch has failed; otherwise as
    /// [`super::seat_commitment`].
    pub fn new_seat_commitment(
        room: &str,
        room_key: &Digest32,
        person: &str,
    ) -> Result<([u8; SEAT_NONCE_LEN], Digest32), RoomError> {
        let mut nonce = [0u8; SEAT_NONCE_LEN];
        ciris_crypto::random::fill(&mut nonce).map_err(|_| RoomError::Seal)?;
        Ok((
            nonce,
            super::seat_commitment(room, room_key, person, &nonce)?,
        ))
    }
}
