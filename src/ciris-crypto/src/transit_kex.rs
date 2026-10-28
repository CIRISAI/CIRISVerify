//! CC 5.3.3.5 E1 — the A/V **per-hop transit key**: the key that seals the
//! outer layer of `double_sealed_ciphertext` on one hop.
//!
//! The outer nonce is already pinned in `ciris-verify-core`'s `av_chunk`
//! (`SHA-256("CIRIS-AV-OUTER-V1" ‖ link_id ‖ link_seq_be8)[0..12]`); this
//! module pins the key it is used under.
//!
//! ## Pattern (CC 3.3.6.2)
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
//! bound        = u8(len(suite)) ‖ suite ‖ u16_be(len(i)) ‖ i ‖ u16_be(len(r)) ‖ r
//!                  suite = b"transit_x25519_mlkem768_hkdf_sha256"
//!                  i = initiator occurrence_key_id, r = relay (responder) occurrence_key_id
//! k_i2r        = HKDF-SHA256(salt, ikm, b"ciris-transit-key/v1/initiator-to-responder" ‖ bound, 32)
//! k_r2i        = HKDF-SHA256(salt, ikm, b"ciris-transit-key/v1/responder-to-initiator" ‖ bound, 32)
//! ```
//!
//! ## Agility: a new scheme is a new suite, not a new format
//!
//! The hybrid will grow (a different ML-KEM level, a third component). Three
//! things keep that an addition rather than a break:
//!
//! - The handshake **opens** with the length-prefixed suite identifier and the
//!   parser dispatches on it, so everything after the two key ids is defined
//!   per suite: a larger ciphertext or an extra component is a new
//!   [`TransitSuite`] variant with its own body, and this envelope never moves.
//! - The suite identifier is **bound into the KDF info**, so two suites can
//!   never derive the same key from the same secrets, whatever their labels.
//! - Every component's shared secret goes into **one** KDF call (`ikm` is
//!   their concatenation in suite order); dropping or swapping a component
//!   changes the key, and breaking one primitive alone does not reveal it.
//!
//! No size is fixed outside a suite's own body, so the transport must carry
//! the handshake as opaque bytes of any length (ML-KEM-1024's ciphertext alone
//! is 1568 B), never as a fixed number of fragments.
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

/// The transit KEX suite a handshake runs under. Closed and exhaustive on
/// purpose: a new suite is a wire change every consumer must notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransitSuite {
    /// X25519 + ML-KEM-768, HKDF-SHA256 ([`TRANSIT_KEX_IDENTIFIER`]).
    X25519MlKem768HkdfSha256,
}

impl TransitSuite {
    /// The suite's wire identifier.
    #[must_use]
    pub const fn identifier(self) -> &'static str {
        match self {
            Self::X25519MlKem768HkdfSha256 => TRANSIT_KEX_IDENTIFIER,
        }
    }

    /// Resolve a wire identifier by exact byte match; `None` for anything
    /// else, including the at-rest `wrap_algorithm` (CC 5.1).
    #[must_use]
    pub fn from_identifier(id: &[u8]) -> Option<Self> {
        (id == TRANSIT_KEX_IDENTIFIER.as_bytes()).then_some(Self::X25519MlKem768HkdfSha256)
    }
}

/// HKDF info label for the initiator → responder key.
pub const TRANSIT_LABEL_INITIATOR_TO_RESPONDER: &[u8] =
    b"ciris-transit-key/v1/initiator-to-responder";

/// HKDF info label for the responder → initiator key.
pub const TRANSIT_LABEL_RESPONDER_TO_INITIATOR: &[u8] =
    b"ciris-transit-key/v1/responder-to-initiator";

/// RNS `LinkId` length: the hash of the LINKREQUEST, held by both ends.
///
/// Callers MUST pass the **wire** link id, the hash of the LINKREQUEST that
/// actually established the link. An establishment retry regenerates the
/// initiator's link keys and so the wire id, and an API that keeps reporting
/// the first attempt's id would make the two ends bind different ids: every
/// frame then fails its tag. The same id feeds the outer nonce, which has the
/// same requirement.
///
/// The outer nonce's `link_seq` is each direction's own `u64` counter under
/// that direction's key, never a value derived from the link's Channel
/// sequence (a `u16` that wraps).
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
/// u8(len(identifier)) ‖ identifier          (stable envelope, all suites)
/// ‖ u16_be(len(initiator_key_id)) ‖ initiator_key_id
/// ‖ u16_be(len(responder_key_id)) ‖ responder_key_id
/// ‖ x25519_ephemeral_pub[32] ‖ mlkem768_ciphertext[1088]   (suite body)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitHandshake {
    suite: TransitSuite,
    initiator_key_id: String,
    responder_key_id: String,
    x25519_ephemeral_pub: [u8; 32],
    mlkem768_ciphertext: Vec<u8>,
}

impl TransitHandshake {
    /// The suite this handshake runs under.
    #[must_use]
    pub fn suite(&self) -> TransitSuite {
        self.suite
    }

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
        let id = self.suite.identifier().as_bytes();
        let mut out = Vec::with_capacity(
            1 + id.len()
                + 4
                + self.initiator_key_id.len()
                + self.responder_key_id.len()
                + 32
                + self.mlkem768_ciphertext.len(),
        );
        push_suite(&mut out, self.suite);
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
        let suite = TransitSuite::from_identifier(r.take(id_len)?)
            .ok_or(TransitKexError::WrongIdentifier)?;
        let initiator_key_id = r.key_id()?;
        let responder_key_id = r.key_id()?;
        // The suite body: a new suite adds an arm here, the envelope above
        // never changes.
        let (x25519_ephemeral_pub, mlkem768_ciphertext) = match suite {
            TransitSuite::X25519MlKem768HkdfSha256 => {
                let mut eph = [0u8; 32];
                eph.copy_from_slice(r.take(32)?);
                (eph, r.take(ML_KEM_768_CIPHERTEXT_LEN)?.to_vec())
            },
        };
        if !r.0.is_empty() {
            return Err(TransitKexError::Malformed("trailing bytes"));
        }
        Ok(Self {
            suite,
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
            suite: TransitSuite::X25519MlKem768HkdfSha256,
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

    let mut bound = Vec::new();
    push_suite(&mut bound, TransitSuite::X25519MlKem768HkdfSha256);
    push_key_id(&mut bound, initiator_key_id);
    push_key_id(&mut bound, responder_key_id);

    Ok(TransitKeys {
        initiator_to_responder: expand(&ikm, &salt, TRANSIT_LABEL_INITIATOR_TO_RESPONDER, &bound)?,
        responder_to_initiator: expand(&ikm, &salt, TRANSIT_LABEL_RESPONDER_TO_INITIATOR, &bound)?,
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

fn push_suite(out: &mut Vec<u8>, suite: TransitSuite) {
    // Suite identifiers are compile-time constants well under 256 bytes.
    let id = suite.identifier().as_bytes();
    out.push(id.len() as u8);
    out.extend_from_slice(id);
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

    #[test]
    fn the_suite_round_trips_and_is_bound() {
        let (_, x_pk, _, kem_pk) = relay();
        let (hs, _) = initiate(&LINK, INIT, RELAY, &x_pk, &kem_pk).unwrap();
        assert_eq!(hs.suite(), TransitSuite::X25519MlKem768HkdfSha256);
        assert_eq!(
            TransitHandshake::from_bytes(&hs.to_bytes())
                .unwrap()
                .suite(),
            hs.suite()
        );
        assert_eq!(
            TransitSuite::from_identifier(TRANSIT_KEX_IDENTIFIER.as_bytes()),
            Some(TransitSuite::X25519MlKem768HkdfSha256)
        );
        assert_eq!(
            TransitSuite::from_identifier(b"transit_x25519_mlkem1024_hkdf_sha256"),
            None
        );
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

    const KDF_I2R: &str = "141c0595eeb264ccad2d1b7c500b6def12b8a1c10a9f57cd5145291c2f105af5";
    const KDF_R2I: &str = "bba06dbf629ea03211a4f3a079fc43e508f0de0d493a06926ab570d5d6cc9772";

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
    const E2E_I2R: &str = "4626d0360796cce6027afcede2a06f9c0bfb2d0b45d8406049d5df8725156ca3";
    const E2E_R2I: &str = "c7b2192779a1ab092d7196e64c1de20e21aa51b9b967117192eae4a2c4210683";
}
