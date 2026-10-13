//! CC 5.3.3.5 E1 — the A/V **per-hop transit key**: the key that seals the
//! outer layer of `double_sealed_ciphertext` on one hop (CIRISVerify#309,
//! CIRISEdge#805, CIRISConstitution#171).
//!
//! The outer nonce is already pinned in `ciris-verify-core`'s `av_chunk`
//! (`SHA-256("CIRIS-AV-OUTER-V1" ‖ link_id ‖ link_seq_be8)[0..12]`); this
//! module pins the key it is used under.
//!
//! ## Pattern (CC 3.3.6.2, steward ruling 2026-10-13)
//!
//! The relay publishes a static `transit_kex_pubkeys {x25519, ml_kem_768}` on
//! its signed `transport_destination` binding. The initiator (always the
//! dialler) runs a hybrid KEX against that static pair with a fresh one-time
//! X25519 key and a fresh ML-KEM-768 encapsulation, inside the RNS link's
//! first exchange. There is **no classical fallback**: E1 forbids it.
//!
//! ```text
//! shared_x     = X25519(eph_sk, relay_x25519_pub)          (all-zero → refused)
//! (ct, ss_kem) = ML-KEM-768.Encaps(relay_mlkem768_pub)
//! ikm          = shared_x ‖ ss_kem
//! salt         = link_id[16] ‖ eph_pub[32] ‖ relay_x25519_pub[32] ‖ ct[1088] ‖ relay_mlkem768_pub[1184]
//! ids          = u16_be(len(i)) ‖ i ‖ u16_be(len(r)) ‖ r
//!                  i = initiator occurrence_key_id, r = relay (responder) occurrence_key_id
//! k_i2r        = HKDF-SHA256(salt, ikm, b"ciris-transit-key/v1/initiator-to-responder" ‖ ids, 32)
//! k_r2i        = HKDF-SHA256(salt, ikm, b"ciris-transit-key/v1/responder-to-initiator" ‖ ids, 32)
//! ```
//!
//! ## Why two keys
//!
//! The pinned outer nonce carries **no direction**: it is a function of
//! `(link_id, link_seq)` only. Both ends of a link expose both directions, so
//! one shared key would let each side produce the same nonces from its own
//! `link_seq` — AES-GCM nonce reuse. Each direction therefore gets its own key,
//! named by **role**, not by who sends media: on a subscriber leg the relay is
//! the sender and seals with `responder_to_initiator`. [`TransitKeys::seal_key`]
//! / [`TransitKeys::open_key`] pick the right one from a [`TransitRole`].
//!
//! ## Rotation: one handshake, one key pair
//!
//! Keys are per **handshake**, not per link. A `link_seq` restart is permitted
//! **only** under a new handshake: re-admitting a peer on a still-live link
//! means a new handshake, which draws a fresh one-time key and therefore fresh
//! keys even though `link_id` is unchanged.
//!
//! ## What this proves, and what it does not
//!
//! The ML-KEM ciphertext and the X25519 share can only be opened with the
//! relay's published transit private keys, so a successful hop proves the far
//! end holds the relay's transit pair. It does **not** authenticate the
//! initiator: the initiator's `occurrence_key_id` rides in the handshake and
//! the KDF so both ends agree on what was **claimed**, and a relay must check
//! that claim itself (rooted key, transport identity equal to the link's
//! proven identity, attribution) before admitting. Binding the 16-byte RNS
//! `link_id` ties the keys to one link: it commits to the initiator's link
//! ephemeral and the destination, so a handshake replayed onto another link
//! derives different keys.
//!
//! ## Identifier vs labels (CC 5.1 class rule)
//!
//! [`TRANSIT_KEX_IDENTIFIER`] is a wire-vocabulary identifier (lowercase
//! `snake_case`, exact byte match) and is **not** the at-rest `wrap_algorithm`
//! `x25519_mlkem768_aes256_gcm_hkdf_sha256`; neither may be accepted in the
//! other's place. The two direction labels are domain-separation byte literals
//! and are used exactly as written.

use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::ml_kem::{
    ML_KEM_768_CIPHERTEXT_LEN, ML_KEM_768_PUBKEY_LEN, ML_KEM_768_SHARED_SECRET_LEN,
};
use crate::{kdf, ml_kem, x25519};

/// Wire-vocabulary identifier of the in-transit KEX (CC 5.3.3.5 E1). Distinct
/// from the at-rest `wrap_algorithm`; matched by exact byte comparison.
pub const TRANSIT_KEX_IDENTIFIER: &str = "transit_x25519_mlkem768_hkdf_sha256";

/// HKDF info label for the initiator → responder key.
pub const TRANSIT_LABEL_INITIATOR_TO_RESPONDER: &[u8] =
    b"ciris-transit-key/v1/initiator-to-responder";

/// HKDF info label for the responder → initiator key.
pub const TRANSIT_LABEL_RESPONDER_TO_INITIATOR: &[u8] =
    b"ciris-transit-key/v1/responder-to-initiator";

/// RNS `LinkId` length: the hash of the LINKREQUEST, held by both ends.
pub const LINK_ID_LEN: usize = 16;

/// Transit key length (AES-256-GCM).
pub const TRANSIT_KEY_LEN: usize = 32;

/// Longest `occurrence_key_id` accepted in a handshake. Real key ids are far
/// shorter; the cap bounds what a parser will allocate from a peer's bytes.
pub const MAX_KEY_ID_LEN: usize = 1024;

/// Errors from the transit KEX.
#[derive(Debug)]
#[non_exhaustive]
pub enum TransitKexError {
    /// An underlying primitive failed (RNG latch, bad key length, …).
    Crypto(CryptoError),
    /// The handshake names a different construction.
    WrongIdentifier,
    /// The handshake bytes do not parse under the pinned layout.
    Malformed(&'static str),
    /// A key id is empty or longer than [`MAX_KEY_ID_LEN`].
    InvalidKeyId,
    /// The handshake was addressed to a different responder key than the one
    /// this node is answering as.
    ResponderMismatch,
    /// The X25519 share is all-zero: a low-order public key was supplied.
    LowOrderPoint,
}

impl From<CryptoError> for TransitKexError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl std::fmt::Display for TransitKexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "transit_kex crypto: {e}"),
            Self::WrongIdentifier => write!(f, "transit_kex: handshake names another construction"),
            Self::Malformed(why) => write!(f, "transit_kex: malformed handshake: {why}"),
            Self::InvalidKeyId => write!(f, "transit_kex: key id empty or too long"),
            Self::ResponderMismatch => {
                write!(
                    f,
                    "transit_kex: handshake is addressed to another responder key"
                )
            },
            Self::LowOrderPoint => write!(f, "transit_kex: X25519 share is all-zero"),
        }
    }
}

impl std::error::Error for TransitKexError {}

/// Which end of the hop this node is. The initiator is always the dialler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitRole {
    /// The dialler.
    Initiator,
    /// The relay that was dialled.
    Responder,
}

/// The initiator's first message, carried over the link's Channel ahead of
/// media. Serialize with [`TransitHandshake::to_bytes`]; the transport splits
/// and rejoins those bytes but never parses them.
///
/// ```text
/// u8(len(identifier)) ‖ identifier
/// ‖ u16_be(len(initiator_key_id)) ‖ initiator_key_id
/// ‖ u16_be(len(responder_key_id)) ‖ responder_key_id
/// ‖ x25519_ephemeral_pub[32] ‖ mlkem768_ciphertext[1088]
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitHandshake {
    initiator_key_id: String,
    responder_key_id: String,
    x25519_ephemeral_pub: [u8; 32],
    mlkem768_ciphertext: Vec<u8>,
}

impl TransitHandshake {
    /// The initiator's **claimed** `occurrence_key_id`. Unauthenticated by
    /// this module: the relay must verify it before admitting the peer.
    #[must_use]
    pub fn initiator_key_id(&self) -> &str {
        &self.initiator_key_id
    }

    /// The relay `occurrence_key_id` the initiator dialled.
    #[must_use]
    pub fn responder_key_id(&self) -> &str {
        &self.responder_key_id
    }

    /// Serialize under the pinned layout.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let id = TRANSIT_KEX_IDENTIFIER.as_bytes();
        let mut out = Vec::with_capacity(
            1 + id.len()
                + 4
                + self.initiator_key_id.len()
                + self.responder_key_id.len()
                + 32
                + self.mlkem768_ciphertext.len(),
        );
        // The identifier is a compile-time constant well under 256 bytes.
        out.push(id.len() as u8);
        out.extend_from_slice(id);
        push_key_id(&mut out, &self.initiator_key_id);
        push_key_id(&mut out, &self.responder_key_id);
        out.extend_from_slice(&self.x25519_ephemeral_pub);
        out.extend_from_slice(&self.mlkem768_ciphertext);
        out
    }

    /// Parse under the pinned layout. Refuses another construction, an empty
    /// or oversized key id, non-UTF-8 key ids, a short or long ciphertext, and
    /// trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TransitKexError> {
        let mut r = Reader(bytes);
        let id_len = usize::from(r.take(1)?[0]);
        if r.take(id_len)? != TRANSIT_KEX_IDENTIFIER.as_bytes() {
            return Err(TransitKexError::WrongIdentifier);
        }
        let initiator_key_id = r.key_id()?;
        let responder_key_id = r.key_id()?;
        let mut x25519_ephemeral_pub = [0u8; 32];
        x25519_ephemeral_pub.copy_from_slice(r.take(32)?);
        let mlkem768_ciphertext = r.take(ML_KEM_768_CIPHERTEXT_LEN)?.to_vec();
        if !r.0.is_empty() {
            return Err(TransitKexError::Malformed("trailing bytes"));
        }
        Ok(Self {
            initiator_key_id,
            responder_key_id,
            x25519_ephemeral_pub,
            mlkem768_ciphertext,
        })
    }
}

/// The two per-direction keys for one handshake. Zeroized on drop.
pub struct TransitKeys {
    initiator_to_responder: Zeroizing<[u8; TRANSIT_KEY_LEN]>,
    responder_to_initiator: Zeroizing<[u8; TRANSIT_KEY_LEN]>,
}

impl std::fmt::Debug for TransitKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransitKeys { .. }")
    }
}

impl TransitKeys {
    /// Key for the initiator → responder direction.
    #[must_use]
    pub fn initiator_to_responder(&self) -> &[u8; TRANSIT_KEY_LEN] {
        &self.initiator_to_responder
    }

    /// Key for the responder → initiator direction.
    #[must_use]
    pub fn responder_to_initiator(&self) -> &[u8; TRANSIT_KEY_LEN] {
        &self.responder_to_initiator
    }

    /// The key this end seals outbound frames with.
    #[must_use]
    pub fn seal_key(&self, role: TransitRole) -> &[u8; TRANSIT_KEY_LEN] {
        match role {
            TransitRole::Initiator => self.initiator_to_responder(),
            TransitRole::Responder => self.responder_to_initiator(),
        }
    }

    /// The key this end opens inbound frames with.
    #[must_use]
    pub fn open_key(&self, role: TransitRole) -> &[u8; TRANSIT_KEY_LEN] {
        match role {
            TransitRole::Initiator => self.responder_to_initiator(),
            TransitRole::Responder => self.initiator_to_responder(),
        }
    }
}

/// Initiator side: run the hop KEX against the relay's published transit pair
/// (resolved from its signed `transport_destination` binding, never from a
/// bare announce). Returns the handshake to send and this hop's keys.
///
/// `responder_key_id` is the relay `occurrence_key_id` that was dialled.
pub fn initiate(
    link_id: &[u8; LINK_ID_LEN],
    initiator_key_id: &str,
    responder_key_id: &str,
    relay_x25519_pub: &[u8; 32],
    relay_mlkem768_pub: &[u8],
) -> Result<(TransitHandshake, TransitKeys), TransitKexError> {
    check_key_id(initiator_key_id)?;
    check_key_id(responder_key_id)?;
    let (eph_sk, eph_pk) = x25519::generate_ephemeral_keypair()?;
    let eph_sk = Zeroizing::new(eph_sk);
    let (ct, ss_kem) = ml_kem::encapsulate(relay_mlkem768_pub)?;
    finish_initiate(
        link_id,
        initiator_key_id,
        responder_key_id,
        relay_x25519_pub,
        relay_mlkem768_pub,
        &eph_sk,
        eph_pk,
        ct,
        Zeroizing::new(ss_kem),
    )
}

/// Responder (relay) side. `local_key_id` is the `occurrence_key_id` this
/// node is answering as; a handshake addressed to any other key is refused, so
/// a node carrying two rooted keys on one transport identity never answers
/// under the wrong one. The returned keys say nothing about who the initiator
/// is: check [`TransitHandshake::initiator_key_id`] before admitting.
pub fn respond(
    link_id: &[u8; LINK_ID_LEN],
    local_key_id: &str,
    relay_x25519_priv: &[u8; 32],
    relay_mlkem768_priv: &[u8],
    relay_mlkem768_pub: &[u8],
    handshake: &TransitHandshake,
) -> Result<TransitKeys, TransitKexError> {
    check_key_id(&handshake.initiator_key_id)?;
    check_key_id(&handshake.responder_key_id)?;
    if handshake.responder_key_id != local_key_id {
        return Err(TransitKexError::ResponderMismatch);
    }
    let relay_x25519_pub = x25519::public_from_secret(relay_x25519_priv);
    let shared_x = Zeroizing::new(x25519::dh(
        relay_x25519_priv,
        &handshake.x25519_ephemeral_pub,
    )?);
    let ss_kem = Zeroizing::new(ml_kem::decapsulate(
        relay_mlkem768_priv,
        &handshake.mlkem768_ciphertext,
    )?);
    derive_transit_keys(
        link_id,
        &handshake.initiator_key_id,
        &handshake.responder_key_id,
        &shared_x,
        &ss_kem,
        &handshake.x25519_ephemeral_pub,
        &relay_x25519_pub,
        &handshake.mlkem768_ciphertext,
        relay_mlkem768_pub,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_initiate(
    link_id: &[u8; LINK_ID_LEN],
    initiator_key_id: &str,
    responder_key_id: &str,
    relay_x25519_pub: &[u8; 32],
    relay_mlkem768_pub: &[u8],
    eph_sk: &[u8; 32],
    eph_pk: [u8; 32],
    ct: Vec<u8>,
    ss_kem: Zeroizing<[u8; ML_KEM_768_SHARED_SECRET_LEN]>,
) -> Result<(TransitHandshake, TransitKeys), TransitKexError> {
    let shared_x = Zeroizing::new(x25519::dh(eph_sk, relay_x25519_pub)?);
    let keys = derive_transit_keys(
        link_id,
        initiator_key_id,
        responder_key_id,
        &shared_x,
        &ss_kem,
        &eph_pk,
        relay_x25519_pub,
        &ct,
        relay_mlkem768_pub,
    )?;
    Ok((
        TransitHandshake {
            initiator_key_id: initiator_key_id.to_owned(),
            responder_key_id: responder_key_id.to_owned(),
            x25519_ephemeral_pub: eph_pk,
            mlkem768_ciphertext: ct,
        },
        keys,
    ))
}

/// The KDF step on its own, so a second implementation can reproduce the
/// pinned vectors from fixed shared secrets. Callers use [`initiate`] /
/// [`respond`].
#[allow(clippy::too_many_arguments)]
pub fn derive_transit_keys(
    link_id: &[u8; LINK_ID_LEN],
    initiator_key_id: &str,
    responder_key_id: &str,
    shared_x25519: &[u8; 32],
    shared_mlkem768: &[u8; ML_KEM_768_SHARED_SECRET_LEN],
    x25519_ephemeral_pub: &[u8; 32],
    relay_x25519_pub: &[u8; 32],
    mlkem768_ciphertext: &[u8],
    relay_mlkem768_pub: &[u8],
) -> Result<TransitKeys, TransitKexError> {
    check_key_id(initiator_key_id)?;
    check_key_id(responder_key_id)?;
    if bool::from(subtle::ConstantTimeEq::ct_eq(
        &shared_x25519[..],
        &[0u8; 32][..],
    )) {
        return Err(TransitKexError::LowOrderPoint);
    }
    if mlkem768_ciphertext.len() != ML_KEM_768_CIPHERTEXT_LEN {
        return Err(TransitKexError::Malformed("ML-KEM-768 ciphertext length"));
    }
    if relay_mlkem768_pub.len() != ML_KEM_768_PUBKEY_LEN {
        return Err(TransitKexError::Malformed("ML-KEM-768 public key length"));
    }

    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(shared_x25519);
    ikm.extend_from_slice(shared_mlkem768);

    let mut salt = Vec::with_capacity(
        LINK_ID_LEN + 32 + 32 + ML_KEM_768_CIPHERTEXT_LEN + ML_KEM_768_PUBKEY_LEN,
    );
    salt.extend_from_slice(link_id);
    salt.extend_from_slice(x25519_ephemeral_pub);
    salt.extend_from_slice(relay_x25519_pub);
    salt.extend_from_slice(mlkem768_ciphertext);
    salt.extend_from_slice(relay_mlkem768_pub);

    let mut ids = Vec::new();
    push_key_id(&mut ids, initiator_key_id);
    push_key_id(&mut ids, responder_key_id);

    Ok(TransitKeys {
        initiator_to_responder: expand(&ikm, &salt, TRANSIT_LABEL_INITIATOR_TO_RESPONDER, &ids)?,
        responder_to_initiator: expand(&ikm, &salt, TRANSIT_LABEL_RESPONDER_TO_INITIATOR, &ids)?,
    })
}

fn expand(
    ikm: &[u8],
    salt: &[u8],
    label: &[u8],
    ids: &[u8],
) -> Result<Zeroizing<[u8; TRANSIT_KEY_LEN]>, TransitKexError> {
    let mut info = Vec::with_capacity(label.len() + ids.len());
    info.extend_from_slice(label);
    info.extend_from_slice(ids);
    let derived = Zeroizing::new(kdf::hkdf_sha256(ikm, salt, &info, TRANSIT_KEY_LEN)?);
    let mut out = Zeroizing::new([0u8; TRANSIT_KEY_LEN]);
    out.copy_from_slice(&derived);
    Ok(out)
}

fn check_key_id(id: &str) -> Result<(), TransitKexError> {
    if id.is_empty() || id.len() > MAX_KEY_ID_LEN {
        return Err(TransitKexError::InvalidKeyId);
    }
    Ok(())
}

fn push_key_id(out: &mut Vec<u8>, id: &str) {
    // `check_key_id` caps every id at MAX_KEY_ID_LEN (< u16::MAX) before it is
    // ever serialized.
    out.extend_from_slice(&(id.len() as u16).to_be_bytes());
    out.extend_from_slice(id.as_bytes());
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TransitKexError> {
        if self.0.len() < n {
            return Err(TransitKexError::Malformed("truncated"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn key_id(&mut self) -> Result<String, TransitKexError> {
        let len_bytes = self.take(2)?;
        let len = usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]]));
        if len == 0 || len > MAX_KEY_ID_LEN {
            return Err(TransitKexError::InvalidKeyId);
        }
        let raw = self.take(len)?;
        String::from_utf8(raw.to_vec()).map_err(|_| TransitKexError::Malformed("key id not UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK: [u8; LINK_ID_LEN] = [0x11; LINK_ID_LEN];
    const INIT: &str = "occ-initiator";
    const RELAY: &str = "occ-relay";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn relay() -> ([u8; 32], [u8; 32], Vec<u8>, Vec<u8>) {
        let x_sk = [0x22; 32];
        let x_pk = x25519::public_from_secret(&x_sk);
        let (kem_sk, kem_pk) = ml_kem::generate_keypair_deterministic(&[0x33; 64]).unwrap();
        (x_sk, x_pk, kem_sk, kem_pk)
    }

    /// Deterministic initiate for the KAT: fixed one-time X25519 secret and
    /// fixed ML-KEM encapsulation randomness.
    fn initiate_fixed(
        link: &[u8; LINK_ID_LEN],
        x_pk: &[u8; 32],
        kem_pk: &[u8],
    ) -> (TransitHandshake, TransitKeys) {
        let eph_sk = [0x44; 32];
        let eph_pk = x25519::public_from_secret(&eph_sk);
        let (ct, ss) = ml_kem::encapsulate_deterministic(kem_pk, &[0x55; 32]).unwrap();
        finish_initiate(
            link,
            INIT,
            RELAY,
            x_pk,
            kem_pk,
            &eph_sk,
            eph_pk,
            ct,
            Zeroizing::new(ss),
        )
        .unwrap()
    }

    #[test]
    fn both_ends_derive_the_same_two_keys() {
        let (x_sk, x_pk, kem_sk, kem_pk) = relay();
        let (hs, ki) = initiate(&LINK, INIT, RELAY, &x_pk, &kem_pk).unwrap();
        let wire = TransitHandshake::from_bytes(&hs.to_bytes()).unwrap();
        assert_eq!(wire, hs);
        let kr = respond(&LINK, RELAY, &x_sk, &kem_sk, &kem_pk, &wire).unwrap();
        assert_eq!(ki.initiator_to_responder(), kr.initiator_to_responder());
        assert_eq!(ki.responder_to_initiator(), kr.responder_to_initiator());
        // What one end seals, the other opens.
        assert_eq!(
            ki.seal_key(TransitRole::Initiator),
            kr.open_key(TransitRole::Responder)
        );
        assert_eq!(
            kr.seal_key(TransitRole::Responder),
            ki.open_key(TransitRole::Initiator)
        );
    }

    /// The pinned outer nonce has no direction, so the two directions must
    /// never share a key.
    #[test]
    fn the_two_directions_never_share_a_key() {
        let (_, x_pk, _, kem_pk) = relay();
        let (_, k) = initiate(&LINK, INIT, RELAY, &x_pk, &kem_pk).unwrap();
        assert_ne!(k.initiator_to_responder(), k.responder_to_initiator());
        assert_ne!(
            k.seal_key(TransitRole::Initiator),
            k.seal_key(TransitRole::Responder)
        );
    }

    /// Re-admission on a live link restarts `link_seq` under the same
    /// `link_id`; it must come with a new handshake, which gives new keys.
    #[test]
    fn a_new_handshake_on_the_same_link_gives_new_keys() {
        let (_, x_pk, _, kem_pk) = relay();
        let (_, a) = initiate(&LINK, INIT, RELAY, &x_pk, &kem_pk).unwrap();
        let (_, b) = initiate(&LINK, INIT, RELAY, &x_pk, &kem_pk).unwrap();
        assert_ne!(a.initiator_to_responder(), b.initiator_to_responder());
        assert_ne!(a.responder_to_initiator(), b.responder_to_initiator());
    }

    #[test]
    fn a_handshake_replayed_onto_another_link_derives_other_keys() {
        let (x_sk, x_pk, kem_sk, kem_pk) = relay();
        let (hs, ki) = initiate(&LINK, INIT, RELAY, &x_pk, &kem_pk).unwrap();
        let other = [0x12; LINK_ID_LEN];
        let kr = respond(&other, RELAY, &x_sk, &kem_sk, &kem_pk, &hs).unwrap();
        assert_ne!(ki.initiator_to_responder(), kr.initiator_to_responder());
    }

    #[test]
    fn a_handshake_for_another_responder_key_is_refused() {
        let (x_sk, x_pk, kem_sk, kem_pk) = relay();
        let (hs, _) = initiate(&LINK, INIT, RELAY, &x_pk, &kem_pk).unwrap();
        assert!(matches!(
            respond(&LINK, "occ-other", &x_sk, &kem_sk, &kem_pk, &hs),
            Err(TransitKexError::ResponderMismatch)
        ));
    }

    /// Substituting the claimed initiator id in transit changes both keys.
    #[test]
    fn a_substituted_initiator_id_diverges_the_keys() {
        let (x_sk, x_pk, kem_sk, kem_pk) = relay();
        let (mut hs, ki) = initiate(&LINK, INIT, RELAY, &x_pk, &kem_pk).unwrap();
        hs.initiator_key_id = "occ-mallory".into();
        let kr = respond(&LINK, RELAY, &x_sk, &kem_sk, &kem_pk, &hs).unwrap();
        assert_ne!(ki.initiator_to_responder(), kr.initiator_to_responder());
        assert_ne!(ki.responder_to_initiator(), kr.responder_to_initiator());
    }

    #[test]
    fn a_low_order_ephemeral_is_refused() {
        let (x_sk, x_pk, kem_sk, kem_pk) = relay();
        let (mut hs, _) = initiate(&LINK, INIT, RELAY, &x_pk, &kem_pk).unwrap();
        hs.x25519_ephemeral_pub = [0u8; 32];
        assert!(matches!(
            respond(&LINK, RELAY, &x_sk, &kem_sk, &kem_pk, &hs),
            Err(TransitKexError::LowOrderPoint)
        ));
    }

    #[test]
    fn the_wire_parser_refuses_what_it_should() {
        let (_, x_pk, _, kem_pk) = relay();
        let (hs, _) = initiate(&LINK, INIT, RELAY, &x_pk, &kem_pk).unwrap();
        let good = hs.to_bytes();

        let mut trailing = good.clone();
        trailing.push(0);
        assert!(matches!(
            TransitHandshake::from_bytes(&trailing),
            Err(TransitKexError::Malformed(_))
        ));
        assert!(matches!(
            TransitHandshake::from_bytes(&good[..good.len() - 1]),
            Err(TransitKexError::Malformed(_))
        ));

        // The at-rest wrap_algorithm is not accepted in this field (CC 5.1).
        let at_rest = b"x25519_mlkem768_aes256_gcm_hkdf_sha256";
        let mut other = vec![at_rest.len() as u8];
        other.extend_from_slice(at_rest);
        other.extend_from_slice(&good[1 + TRANSIT_KEX_IDENTIFIER.len()..]);
        assert!(matches!(
            TransitHandshake::from_bytes(&other),
            Err(TransitKexError::WrongIdentifier)
        ));

        // An empty initiator key id.
        let mut empty = good[..1 + TRANSIT_KEX_IDENTIFIER.len()].to_vec();
        empty.extend_from_slice(&[0, 0]);
        empty.extend_from_slice(&good[1 + TRANSIT_KEX_IDENTIFIER.len() + 2 + INIT.len()..]);
        assert!(matches!(
            TransitHandshake::from_bytes(&empty),
            Err(TransitKexError::InvalidKeyId)
        ));

        assert!(matches!(
            initiate(&LINK, "", RELAY, &x_pk, &kem_pk),
            Err(TransitKexError::InvalidKeyId)
        ));
    }

    /// The KDF step alone, against vectors computed independently with a
    /// from-scratch RFC 5869 HKDF in Python from these fixed inputs. A red
    /// here means the derivation no longer matches the layout in the module
    /// docs, not merely its own earlier output.
    #[test]
    fn kdf_matches_the_independently_derived_vectors() {
        let kem_pk: Vec<u8> = (0..ML_KEM_768_PUBKEY_LEN)
            .map(|i| (i % 251) as u8)
            .collect();
        let ct: Vec<u8> = (0..ML_KEM_768_CIPHERTEXT_LEN)
            .map(|i| (i % 241) as u8)
            .collect();
        let k = derive_transit_keys(
            &LINK,
            INIT,
            RELAY,
            &[0x01; 32],
            &[0x02; 32],
            &[0x03; 32],
            &[0x04; 32],
            &ct,
            &kem_pk,
        )
        .unwrap();
        assert_eq!(hex(k.initiator_to_responder()), KDF_I2R);
        assert_eq!(hex(k.responder_to_initiator()), KDF_R2I);
    }

    const KDF_I2R: &str = "30ea7dfe1f6ff994997bc33b9a6cab01191ca7dc4746a61ba87ef4422c9cff59";
    const KDF_R2I: &str = "2b0792102adb8f58f8d84958e2ce43033c80988d80c38c6be64618d4b8d64a79";

    /// End to end with fixed randomness: the handshake bytes and both keys.
    /// X25519 and the KDF were reproduced independently in Python
    /// (`cryptography` + from-scratch HKDF); the ML-KEM ciphertext and shared
    /// secret come from the FIPS 203 deterministic path this crate already
    /// pins by KAT (`ml_kem` tests).
    #[test]
    fn end_to_end_matches_the_pinned_vectors() {
        let (x_sk, x_pk, kem_sk, kem_pk) = relay();
        let (hs, ki) = initiate_fixed(&LINK, &x_pk, &kem_pk);
        let bytes = hs.to_bytes();
        assert_eq!(bytes.len(), 1 + 35 + 2 + 13 + 2 + 9 + 32 + 1088);
        assert_eq!(hex(&sha2_256(&bytes)), E2E_HANDSHAKE_SHA256);
        assert_eq!(hex(ki.initiator_to_responder()), E2E_I2R);
        assert_eq!(hex(ki.responder_to_initiator()), E2E_R2I);
        let kr = respond(&LINK, RELAY, &x_sk, &kem_sk, &kem_pk, &hs).unwrap();
        assert_eq!(hex(kr.initiator_to_responder()), E2E_I2R);
    }

    fn sha2_256(b: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(b).into()
    }

    const E2E_HANDSHAKE_SHA256: &str =
        "41af915dd3568609d2afe644be486f4be5b90b4cc847fb8d0f68c20d0e84de8e";
    const E2E_I2R: &str = "4cdd7ac798adcffbf729f6f402e5e746f5fc3635e7cc22fe44dabeda44129b37";
    const E2E_R2I: &str = "6abd0e4417f36141c8f913595da2f9bfba57160c952201a20bd8442d8bfccd76";
}
