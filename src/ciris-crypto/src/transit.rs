//! CC 5.3.3.10: the mutual X-Wing **link handshake**, `CTKX` v2, suite
//! `transit_xwing_hkdf_sha256` (CIRISEdge#1007). The wire is
//! `docs/TRANSIT_HANDSHAKE_V2.md`, which is normative for this module; it
//! replaces the responder-only `transit_kex` (`CTKX` v1) as a hard cut.
//!
//! ```text
//! h0 = H("ciris-transit/v2" ‖ link_id[16] ‖ pk(S_r))
//! (ct1, ss1) = XW.Encaps(pk(S_r))
//! h1 = H(h0 ‖ pk(E_i) ‖ ct1)
//! k_id = HKDF(salt = h1, ikm = ss1, info = "ciris-transit/v2/identity", 32)
//! id_block = u16 len ‖ initiator_key_id ‖ u8 has_static ‖ [H(pk(S_i))]
//! id_ct = AES-256-GCM(k_id, nonce = 0^12, aad = h1, id_block)
//! msg1 = 0x01 ‖ u8 len ‖ suite ‖ u16 len ‖ responder_key_id ‖ pk(E_i) ‖ ct1 ‖ u16 len ‖ id_ct
//! h2 = H(h1 ‖ id_ct)
//! (ct2, ss2) = XW.Encaps(pk(E_i));  (ct3, ss3) = XW.Encaps(pk(S_i)) iff mutual
//! h3 = H(h2 ‖ flags ‖ ct2 ‖ [ct3])
//! prk = HKDF-Extract(salt = h3, ikm = ss1 ‖ ss2 ‖ [ss3])
//! k_i2r / k_r2i / k_conf = HKDF-Expand(prk, label ‖ bound, 32)
//! msg2 = 0x02 ‖ flags ‖ ct2 ‖ [ct3] ‖ HMAC(k_conf, "responder" ‖ h3)
//! CTKC = "CTKC" ‖ HMAC(k_conf, "initiator" ‖ h3)        (the initiator's first sealed frame)
//! msg3 = 0x03 ‖ ct3'                                     (promotion)
//! h3' = H(h3 ‖ "promote" ‖ ct3');  prk' = HKDF-Extract(h3', k_i2r ‖ k_r2i ‖ ss3')
//! CTKC' = "CTKC" ‖ HMAC(k_conf', "initiator" ‖ h3')
//! ```
//!
//! `bound = u8 len ‖ suite ‖ u16 len ‖ initiator_key_id ‖ u16 len ‖
//! responder_key_id`, as in v1. Every length and integer is big-endian.
//!
//! ## What this module does and does not hold
//!
//! - **Static secrets never enter it.** The decapsulations to the two statics
//!   (the responder's of `ct1`, the initiator's of `ct3` and `ct3'`) are
//!   closures, because in the WASM node the vault performs them
//!   (`seal.xwing-decap`).
//! - **The ephemeral `E_i` lives in [`InitiatorState`]** and is zeroized when
//!   the state is consumed by [`InitiatorState::finish`] or dropped.
//! - **No OS randomness in the core.** Every function takes the ephemeral seed
//!   and the 64-byte X-Wing encapsulation randomness (`EncapsulateDerand`'s
//!   `eseed`) from the caller, so the WASM node can feed `random.fill` and the
//!   known answers are deterministic. `*_with_rng` wrappers draw from an
//!   injected RNG; with the `random` feature `*_random` wrappers draw from the
//!   health-latched facade. A caller MUST NOT reuse encapsulation randomness.
//! - **The per-frame link seal** is edge's (`link_seal.rs`); this module gives
//!   the direction keys ([`SessionKeys`]), the `CTKC` payload to seal as the
//!   first frame, the promotion rekey ([`promotion_rekey`]) with a key phase
//!   counter, and a reference implementation of the seal frame v0x02 with key
//!   phases ([`seal_frame`], [`FrameOpener`]):
//!
//!   ```text
//!   frame = 0x02 ‖ phase u8 ‖ counter u64_be ‖ AES-256-GCM(k, nonce, aad, pt) ‖ tag[16]
//!   k     = HKDF-SHA256(ikm = k_dir(phase), salt = link_id, info = "CIRIS-E1-LINK-SEAL-V2")
//!   nonce = lane u8 ‖ 0x000000 ‖ counter u64_be
//!   aad   = 0x02 ‖ lane u8 ‖ phase u8 ‖ link_id
//!   ```
//! - **The part framing** (`"CTKX" ‖ 0x02 ‖ kind ‖ …`) is here:
//!   [`encode_parts`] and [`Reassembler`]. `CTKX` 0x01 is refused by name.
//!
//! ## Responder lifecycle
//!
//! [`Responder::accept`] answers `msg1` and returns the [`Mode`]. Sending `msg2`
//! attributes nothing: until [`ResponderState::confirm`] verifies `CTKC` the
//! link serves only the first-contact plane (this is what defeats a replayed
//! `msg1`). In mutual mode a verified `CTKC` attributes the initiator. In
//! first-contact mode it confirms only possession of `E_i`; once the
//! initiator's binding is held and hashes to the `msg1` commitment,
//! [`ResponderState::promote`] sends `msg3`, and
//! [`ResponderState::confirm_promotion`] attributes the initiator on `CTKC'`.
//! Any refusal from `confirm` or `confirm_promotion` means the caller closes
//! the link.
//!
//! ## Primitives
//!
//! X-Wing draft-11 ([`crate::xwing`]), SHA-256, HKDF-SHA256 (`hkdf`),
//! HMAC-SHA256 (`hmac`), AES-256-GCM. The AEAD here is **RustCrypto
//! `aes-gcm` 0.10**, not the `ring`-backed `ciris_crypto::aes_gcm` module: `ring`
//! needs `std`, and this module must build `no_std` for the WASM node. So the
//! crate carries two AES-GCM implementations; this one seals the identity
//! block and the reference seal frames. RustCrypto's `aes` 0.8 uses AES-NI (detected at run time
//! via `cpufeatures`) on x86/x86_64 and otherwise the constant-time fixsliced
//! software AES; on aarch64 the ARMv8 instructions need `--cfg aes_armv8`,
//! without which it is the fixsliced software path. GHASH (`polyval`) likewise
//! uses CLMUL when detected and a constant-time software multiply otherwise.
//! MAC and commitment comparisons are constant-time (`subtle`).

#[allow(unused_imports)]
use crate::prelude::*;

use aes_gcm_soft::aead::{Aead, KeyInit, Payload};
use aes_gcm_soft::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::xwing::{
    XWingPublicKey, XWingSecretKey, XWING_CIPHERTEXT_LEN, XWING_ENCAPSULATION_RANDOMNESS_LEN,
    XWING_PUBLIC_KEY_LEN, XWING_SEED_LEN, XWING_SHARED_SECRET_LEN,
};

/// The v2 suite identifier (CC 3.3.2 snake_case), matched by exact bytes.
pub const TRANSIT_SUITE: &str = "transit_xwing_hkdf_sha256";
/// The v1 suite identifier, refused by name ([`TransitError::SuiteV1Refused`]).
pub const TRANSIT_SUITE_V1: &str = "transit_x25519_mlkem768_hkdf_sha256";

/// Transcript prefix of `h0`.
pub const LABEL_TRANSCRIPT: &[u8] = b"ciris-transit/v2";
/// HKDF info of the identity key `k_id`.
pub const LABEL_IDENTITY: &[u8] = b"ciris-transit/v2/identity";
/// HKDF info label (followed by `bound`) of `k_i2r`.
pub const LABEL_INITIATOR_TO_RESPONDER: &[u8] = b"ciris-transit/v2/initiator-to-responder";
/// HKDF info label (followed by `bound`) of `k_r2i`.
pub const LABEL_RESPONDER_TO_INITIATOR: &[u8] = b"ciris-transit/v2/responder-to-initiator";
/// HKDF info label (followed by `bound`) of `k_conf`.
pub const LABEL_CONFIRM: &[u8] = b"ciris-transit/v2/confirm";
/// The promotion transcript label in `h3' = H(h3 ‖ "promote" ‖ ct3')`.
pub const LABEL_PROMOTE: &[u8] = b"promote";
/// MAC prefix of `confirm_r`.
pub const MAC_RESPONDER: &[u8] = b"responder";
/// MAC prefix of `CTKC` and `CTKC'`.
pub const MAC_INITIATOR: &[u8] = b"initiator";
/// The tag that opens the initiator's key-confirmation frame.
pub const CTKC_TAG: &[u8; 4] = b"CTKC";
/// Length of a `CTKC` payload: tag plus HMAC-SHA256.
pub const CTKC_LEN: usize = 4 + 32;

/// Message type of `msg1`.
pub const MSG1_TYPE: u8 = 0x01;
/// Message type of `msg2`.
pub const MSG2_TYPE: u8 = 0x02;
/// Message type of `msg3` (promotion).
pub const MSG3_TYPE: u8 = 0x03;
/// `flags` bit 0: mutual, `ct3` present. Every other bit is refused.
pub const FLAG_MUTUAL: u8 = 0x01;

/// `msg2` length in first-contact mode: `1 + 1 + 1120 + 32`.
pub const MSG2_FIRST_CONTACT_LEN: usize = 2 + XWING_CIPHERTEXT_LEN + 32;
/// `msg2` length in mutual mode: `1 + 1 + 1120 + 1120 + 32`.
pub const MSG2_MUTUAL_LEN: usize = MSG2_FIRST_CONTACT_LEN + XWING_CIPHERTEXT_LEN;
/// `msg3` length: `1 + 1120`.
pub const MSG3_LEN: usize = 1 + XWING_CIPHERTEXT_LEN;

/// RNS `LinkId` length. Callers pass the wire link id (the hash of the
/// LINKREQUEST that established the link), as in v1.
pub const LINK_ID_LEN: usize = 16;
/// Direction-key and confirmation-key length.
pub const SESSION_KEY_LEN: usize = 32;
/// Longest key id accepted (carried over from v1); ids are non-empty UTF-8.
pub const MAX_KEY_ID_LEN: usize = 1024;

/// Part framing magic.
pub const FRAMING_MAGIC: &[u8; 4] = b"CTKX";
/// Part framing version of this handshake.
pub const FRAMING_VERSION: u8 = 0x02;
/// Part kind: start (`u32 total_len` follows).
pub const PART_START: u8 = 0x00;
/// Part kind: continuation.
pub const PART_CONTINUATION: u8 = 0x01;
/// Header length of a start part: magic, version, kind, `u32 total_len`.
pub const START_HEADER_LEN: usize = 10;
/// Header length of a continuation part: magic, version, kind.
pub const CONTINUATION_HEADER_LEN: usize = 6;
/// Largest handshake message (8 KiB).
pub const MAX_MESSAGE_LEN: usize = 8192;

const AEAD_TAG_LEN: usize = 16;

type HmacSha256 = Hmac<Sha256>;

/// A 32-byte X-Wing shared secret, zeroized on drop.
pub type SharedSecret = Zeroizing<[u8; XWING_SHARED_SECRET_LEN]>;

/// The decapsulation closure's type when there is none to pass:
/// `None::<NoDecap>` for a first-contact [`InitiatorState::finish`].
pub type NoDecap = fn(&[u8; XWING_CIPHERTEXT_LEN]) -> Result<SharedSecret, CryptoError>;

/// Every refusal of the handshake. Each has a stable [`code`](Self::code), the
/// name the known-answer file uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransitError {
    /// Input ended before a field was complete.
    #[error("transit: truncated")]
    Truncated,
    /// Bytes remain after the last field.
    #[error("transit: trailing bytes")]
    TrailingBytes,
    /// A field has an impossible length (an `id_ct` shorter than its tag, an
    /// empty message, a part size too small for its header).
    #[error("transit: bad length")]
    BadLength,
    /// A key id is empty, longer than [`MAX_KEY_ID_LEN`] or not UTF-8.
    #[error("transit: key id empty, too long or not UTF-8")]
    KeyIdInvalid,
    /// `msg1` names a responder key other than the one answering.
    #[error("transit: msg1 is addressed to another responder key")]
    ResponderKeyIdMismatch,
    /// The suite is not `transit_xwing_hkdf_sha256`.
    #[error("transit: unknown suite")]
    SuiteUnknown,
    /// The suite is v1's `transit_x25519_mlkem768_hkdf_sha256`, deleted.
    #[error("transit: the v1 suite is refused")]
    SuiteV1Refused,
    /// The message type byte is not the one expected here.
    #[error("transit: unexpected message type")]
    MessageType,
    /// `pk(E_i)` fails the X-Wing public-key check.
    #[error("transit: ephemeral public key invalid")]
    PublicKeyInvalid,
    /// `id_ct` does not open under `k_id`: the link closes.
    #[error("transit: id_ct does not open")]
    IdentityOpenFailed,
    /// `id_block` opened but does not parse.
    #[error("transit: id_block malformed")]
    IdentityBlockMalformed,
    /// A `flags` bit other than bit 0 is set.
    #[error("transit: unknown flags")]
    FlagsUnknown,
    /// `msg2` claims mutual to an initiator with no static, or no `ct3`
    /// decapsulation was supplied.
    #[error("transit: mutual msg2 without an initiator static")]
    ModeMismatch,
    /// A decapsulation closure failed.
    #[error("transit: decapsulation failed")]
    DecapsulationFailed,
    /// `confirm_r` does not verify: the link closes.
    #[error("transit: confirm_r mismatch")]
    ConfirmMismatch,
    /// The initiator's first sealed frame is not a `CTKC`: the link closes.
    #[error("transit: first frame is not CTKC")]
    NotCtkc,
    /// The `CTKC` MAC does not verify: the link closes.
    #[error("transit: CTKC mismatch")]
    CtkcMismatch,
    /// The binding offered for promotion does not hash to msg1's commitment.
    #[error("transit: promotion static does not match the msg1 commitment")]
    PromotionCommitmentMismatch,
    /// The link cannot be promoted (mutual already, no static committed, or
    /// first `CTKC` not yet verified).
    #[error("transit: link not promotable")]
    NotPromotable,
    /// A state method was called out of order.
    #[error("transit: out of order")]
    OutOfOrder,
    /// The health-latched RNG refused to draw (`*_random` wrappers only).
    #[error("transit: RNG unavailable")]
    RngUnavailable,
    /// A part's framing version is 0x01: v1 is deleted.
    #[error("transit: CTKX v1 framing refused")]
    FramingV1Refused,
    /// A part's framing version is neither 0x01 nor 0x02.
    #[error("transit: CTKX framing version unsupported")]
    FramingVersionUnsupported,
    /// A part does not start with `CTKX` or is shorter than its header.
    #[error("transit: CTKX part malformed")]
    FramingMalformed,
    /// A part kind other than start or continuation.
    #[error("transit: CTKX part kind unknown")]
    FramingPartKind,
    /// A message is empty or larger than [`MAX_MESSAGE_LEN`].
    #[error("transit: CTKX message too large")]
    FramingTooLarge,
    /// A continuation without a start, a second start, or a part after the
    /// message completed.
    #[error("transit: CTKX part out of order")]
    FramingOutOfOrder,
}

impl TransitError {
    /// The stable refusal name.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::TrailingBytes => "trailing_bytes",
            Self::BadLength => "bad_length",
            Self::KeyIdInvalid => "key_id_invalid",
            Self::ResponderKeyIdMismatch => "responder_key_id_mismatch",
            Self::SuiteUnknown => "suite_unknown",
            Self::SuiteV1Refused => "suite_v1_refused",
            Self::MessageType => "message_type",
            Self::PublicKeyInvalid => "public_key_invalid",
            Self::IdentityOpenFailed => "identity_open_failed",
            Self::IdentityBlockMalformed => "identity_block_malformed",
            Self::FlagsUnknown => "flags_unknown",
            Self::ModeMismatch => "mode_mismatch",
            Self::DecapsulationFailed => "decapsulation_failed",
            Self::ConfirmMismatch => "confirm_mismatch",
            Self::NotCtkc => "not_ctkc",
            Self::CtkcMismatch => "ctkc_mismatch",
            Self::PromotionCommitmentMismatch => "promotion_commitment_mismatch",
            Self::NotPromotable => "not_promotable",
            Self::OutOfOrder => "out_of_order",
            Self::RngUnavailable => "rng_unavailable",
            Self::FramingV1Refused => "framing_v1_refused",
            Self::FramingVersionUnsupported => "framing_version_unsupported",
            Self::FramingMalformed => "framing_malformed",
            Self::FramingPartKind => "framing_part_kind",
            Self::FramingTooLarge => "framing_too_large",
            Self::FramingOutOfOrder => "framing_out_of_order",
        }
    }
}

/// Which end of the link this node is. The initiator is the dialler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The dialler.
    Initiator,
    /// The dialled node.
    Responder,
}

/// The handshake's mode, from `msg2`'s `flags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `ct3` present: both statics used.
    Mutual,
    /// `ct3` omitted: sealed and forward-secret, the initiator unattributed.
    FirstContact,
}

/// What a verified `CTKC` establishes at the responder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation {
    /// Mutual: the initiator is attributed to the key id sealed in `id_ct`.
    Attributed,
    /// First contact: the initiator holds `E_i`; it is not attributed.
    FirstContactConfirmed,
}

/// The two direction keys. Zeroized on drop.
#[derive(Clone)]
pub struct SessionKeys {
    k_i2r: Zeroizing<[u8; SESSION_KEY_LEN]>,
    k_r2i: Zeroizing<[u8; SESSION_KEY_LEN]>,
}

impl core::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SessionKeys { .. }")
    }
}

impl SessionKeys {
    /// The initiator-to-responder key.
    #[must_use]
    pub fn k_i2r(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.k_i2r
    }

    /// The responder-to-initiator key.
    #[must_use]
    pub fn k_r2i(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.k_r2i
    }

    /// The key `role` seals with.
    #[must_use]
    pub fn seal_key(&self, role: Role) -> &[u8; SESSION_KEY_LEN] {
        match role {
            Role::Initiator => self.k_i2r(),
            Role::Responder => self.k_r2i(),
        }
    }

    /// The key `role` opens with.
    #[must_use]
    pub fn open_key(&self, role: Role) -> &[u8; SESSION_KEY_LEN] {
        match role {
            Role::Initiator => self.k_r2i(),
            Role::Responder => self.k_i2r(),
        }
    }
}

/// `k_conf`, the key-confirmation MAC key. Zeroized on drop.
#[derive(Clone)]
pub struct ConfirmKey(Zeroizing<[u8; SESSION_KEY_LEN]>);

impl core::fmt::Debug for ConfirmKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ConfirmKey(..)")
    }
}

impl ConfirmKey {
    /// The key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.0
    }

    /// `HMAC(k_conf, prefix ‖ transcript)`.
    #[must_use]
    pub fn mac(&self, prefix: &[u8], transcript: &[u8; 32]) -> [u8; 32] {
        let mut m = <HmacSha256 as Mac>::new_from_slice(self.0.as_ref())
            .expect("HMAC takes any key length");
        m.update(prefix);
        m.update(transcript);
        m.finalize().into_bytes().into()
    }

    /// The `CTKC` payload over `transcript` (`h3`, or `h3'` after promotion).
    #[must_use]
    pub fn ctkc(&self, transcript: &[u8; 32]) -> [u8; CTKC_LEN] {
        let mut out = [0u8; CTKC_LEN];
        out[..4].copy_from_slice(CTKC_TAG);
        out[4..].copy_from_slice(&self.mac(MAC_INITIATOR, transcript));
        out
    }

    /// Check a `CTKC` payload over `transcript`: a frame not opening with
    /// `CTKC` is [`TransitError::NotCtkc`]; a bad MAC is
    /// [`TransitError::CtkcMismatch`] (constant-time).
    ///
    /// # Errors
    /// As above, plus [`TransitError::Truncated`] / [`TransitError::TrailingBytes`]
    /// for a `CTKC` of the wrong length.
    pub fn verify_ctkc(&self, payload: &[u8], transcript: &[u8; 32]) -> Result<(), TransitError> {
        if payload.len() < 4 || &payload[..4] != CTKC_TAG {
            return Err(TransitError::NotCtkc);
        }
        if payload.len() < CTKC_LEN {
            return Err(TransitError::Truncated);
        }
        if payload.len() > CTKC_LEN {
            return Err(TransitError::TrailingBytes);
        }
        let expected = self.mac(MAC_INITIATOR, transcript);
        if bool::from(expected.ct_eq(&payload[4..])) {
            Ok(())
        } else {
            Err(TransitError::CtkcMismatch)
        }
    }
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// `H(pk)`, the commitment `id_block` carries for the initiator's static.
#[must_use]
pub fn static_commitment(pk: &XWingPublicKey) -> [u8; 32] {
    sha256(&[pk.as_bytes()])
}

fn check_key_id(id: &str) -> Result<(), TransitError> {
    if id.is_empty() || id.len() > MAX_KEY_ID_LEN {
        return Err(TransitError::KeyIdInvalid);
    }
    Ok(())
}

fn push_key_id(out: &mut Vec<u8>, id: &str) {
    // `check_key_id` caps every id at MAX_KEY_ID_LEN (< u16::MAX) first.
    #[allow(clippy::cast_possible_truncation)]
    out.extend_from_slice(&(id.len() as u16).to_be_bytes());
    out.extend_from_slice(id.as_bytes());
}

fn push_suite(out: &mut Vec<u8>) {
    #[allow(clippy::cast_possible_truncation)]
    out.push(TRANSIT_SUITE.len() as u8);
    out.extend_from_slice(TRANSIT_SUITE.as_bytes());
}

/// `bound = u8 len ‖ suite ‖ u16 len ‖ initiator_key_id ‖ u16 len ‖ responder_key_id`.
///
/// # Errors
/// [`TransitError::KeyIdInvalid`] for an empty or over-long id.
pub fn bound(initiator_key_id: &str, responder_key_id: &str) -> Result<Vec<u8>, TransitError> {
    check_key_id(initiator_key_id)?;
    check_key_id(responder_key_id)?;
    let mut out = Vec::with_capacity(
        1 + TRANSIT_SUITE.len() + 4 + initiator_key_id.len() + responder_key_id.len(),
    );
    push_suite(&mut out);
    push_key_id(&mut out, initiator_key_id);
    push_key_id(&mut out, responder_key_id);
    Ok(out)
}

fn expand32(hk: &Hkdf<Sha256>, label: &[u8], bound: &[u8]) -> Zeroizing<[u8; SESSION_KEY_LEN]> {
    let mut out = Zeroizing::new([0u8; SESSION_KEY_LEN]);
    hk.expand_multi_info(&[label, bound], out.as_mut())
        .expect("32 bytes is within HKDF-SHA256's output bound");
    out
}

/// The key schedule: `prk = HKDF-Extract(salt, ikm)`, then `k_i2r`, `k_r2i`
/// and `k_conf` as `HKDF-Expand(prk, label ‖ bound, 32)`. `salt` is `h3` at
/// the handshake and `h3'` at promotion.
#[must_use]
pub fn derive_session_keys(salt: &[u8; 32], ikm: &[u8], bound: &[u8]) -> (SessionKeys, ConfirmKey) {
    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), ikm);
    let keys = SessionKeys {
        k_i2r: expand32(&hk, LABEL_INITIATOR_TO_RESPONDER, bound),
        k_r2i: expand32(&hk, LABEL_RESPONDER_TO_INITIATOR, bound),
    };
    let conf = ConfirmKey(expand32(&hk, LABEL_CONFIRM, bound));
    (keys, conf)
}

/// The promotion rekey (the key-phase derivation): `h3' = H(h3 ‖ "promote" ‖
/// ct3')`, `prk' = HKDF-Extract(salt = h3', ikm = k_i2r ‖ k_r2i ‖ ss3')`, and
/// the new keys under the same labels followed by `bound`. Returns `h3'`, the
/// new keys and `k_conf'`.
#[must_use]
pub fn promotion_rekey(
    h3: &[u8; 32],
    ct3_prime: &[u8; XWING_CIPHERTEXT_LEN],
    old: &SessionKeys,
    ss3_prime: &[u8; XWING_SHARED_SECRET_LEN],
    bound: &[u8],
) -> ([u8; 32], SessionKeys, ConfirmKey) {
    let h3p = sha256(&[h3, LABEL_PROMOTE, ct3_prime]);
    let mut ikm = Zeroizing::new([0u8; 3 * 32]);
    ikm[..32].copy_from_slice(old.k_i2r());
    ikm[32..64].copy_from_slice(old.k_r2i());
    ikm[64..].copy_from_slice(ss3_prime);
    let (keys, conf) = derive_session_keys(&h3p, ikm.as_ref(), bound);
    (h3p, keys, conf)
}

fn k_id(h1: &[u8; 32], ss1: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(&h1[..]), &ss1[..]);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(LABEL_IDENTITY, out.as_mut())
        .expect("32 bytes is within HKDF-SHA256's output bound");
    out
}

fn aead(k: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(k).expect("32-byte key")
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], TransitError> {
        if self.0.len() < n {
            return Err(TransitError::Truncated);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TransitError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, TransitError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<usize, TransitError> {
        let b = self.take(2)?;
        Ok(usize::from(u16::from_be_bytes([b[0], b[1]])))
    }

    fn key_id(&mut self) -> Result<String, TransitError> {
        let len = self.u16()?;
        let raw = self.take(len)?;
        let s = core::str::from_utf8(raw).map_err(|_| TransitError::KeyIdInvalid)?;
        check_key_id(s)?;
        Ok(s.to_owned())
    }

    fn end(&self) -> Result<(), TransitError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(TransitError::TrailingBytes)
        }
    }
}

fn h0(link_id: &[u8; LINK_ID_LEN], responder_static_pk: &XWingPublicKey) -> [u8; 32] {
    sha256(&[LABEL_TRANSCRIPT, link_id, responder_static_pk.as_bytes()])
}

fn draw<const N: usize>(rng: &mut impl CryptoRngCore) -> Zeroizing<[u8; N]> {
    let mut out = Zeroizing::new([0u8; N]);
    rng.fill_bytes(out.as_mut());
    out
}

#[cfg(feature = "random")]
fn draw_random<const N: usize>() -> Result<Zeroizing<[u8; N]>, TransitError> {
    let mut out = Zeroizing::new([0u8; N]);
    crate::random::fill(out.as_mut()).map_err(|_| TransitError::RngUnavailable)?;
    Ok(out)
}

/// The initiator's entry point.
pub struct Initiator;

impl Initiator {
    /// Build `msg1`. `e_seed` is `E_i`'s 32-byte X-Wing seed and `encaps_rand`
    /// the 64 bytes for `ct1`; both must be fresh. `initiator_static_pk` is the
    /// initiator's published transit key, `None` for a node with none
    /// (`has_static = 0`).
    ///
    /// # Errors
    /// [`TransitError::KeyIdInvalid`] for an empty or over-long key id.
    pub fn start(
        link_id: &[u8; LINK_ID_LEN],
        responder_static_pk: &XWingPublicKey,
        responder_key_id: &str,
        initiator_key_id: &str,
        initiator_static_pk: Option<&XWingPublicKey>,
        e_seed: &[u8; XWING_SEED_LEN],
        encaps_rand: &[u8; XWING_ENCAPSULATION_RANDOMNESS_LEN],
    ) -> Result<(InitiatorState, Vec<u8>), TransitError> {
        check_key_id(initiator_key_id)?;
        check_key_id(responder_key_id)?;
        let e_i = XWingSecretKey::from_seed(*e_seed);
        let pk_e = e_i.public_key();
        let h0 = h0(link_id, responder_static_pk);
        let (ct1, ss1) = responder_static_pk.encapsulate_derand(encaps_rand);
        let h1 = sha256(&[&h0, pk_e.as_bytes(), &ct1]);
        let k_id = k_id(&h1, &ss1);

        let mut id_block = Zeroizing::new(Vec::with_capacity(2 + initiator_key_id.len() + 33));
        push_key_id(&mut id_block, initiator_key_id);
        match initiator_static_pk {
            None => id_block.push(0),
            Some(pk) => {
                id_block.push(1);
                id_block.extend_from_slice(&static_commitment(pk));
            },
        }
        let id_ct = aead(&k_id)
            .encrypt(
                Nonce::from_slice(&[0u8; 12]),
                Payload {
                    msg: &id_block,
                    aad: &h1,
                },
            )
            .expect("AES-GCM seals any short message");
        let h2 = sha256(&[&h1, &id_ct]);

        let mut msg1 = Vec::with_capacity(
            1 + 1
                + TRANSIT_SUITE.len()
                + 2
                + responder_key_id.len()
                + XWING_PUBLIC_KEY_LEN
                + XWING_CIPHERTEXT_LEN
                + 2
                + id_ct.len(),
        );
        msg1.push(MSG1_TYPE);
        push_suite(&mut msg1);
        push_key_id(&mut msg1, responder_key_id);
        msg1.extend_from_slice(pk_e.as_bytes());
        msg1.extend_from_slice(&ct1);
        #[allow(clippy::cast_possible_truncation)]
        msg1.extend_from_slice(&(id_ct.len() as u16).to_be_bytes());
        msg1.extend_from_slice(&id_ct);

        Ok((
            InitiatorState {
                e_i,
                ss1,
                h2,
                initiator_key_id: initiator_key_id.to_owned(),
                responder_key_id: responder_key_id.to_owned(),
                has_static: initiator_static_pk.is_some(),
            },
            msg1,
        ))
    }

    /// [`Self::start`] with `E_i`'s seed then `ct1`'s randomness drawn from `rng`.
    ///
    /// # Errors
    /// As [`Self::start`].
    pub fn start_with_rng(
        link_id: &[u8; LINK_ID_LEN],
        responder_static_pk: &XWingPublicKey,
        responder_key_id: &str,
        initiator_key_id: &str,
        initiator_static_pk: Option<&XWingPublicKey>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(InitiatorState, Vec<u8>), TransitError> {
        let e_seed = draw::<XWING_SEED_LEN>(rng);
        let rand = draw::<XWING_ENCAPSULATION_RANDOMNESS_LEN>(rng);
        Self::start(
            link_id,
            responder_static_pk,
            responder_key_id,
            initiator_key_id,
            initiator_static_pk,
            &e_seed,
            &rand,
        )
    }

    /// [`Self::start`] with randomness from the health-latched RNG facade.
    ///
    /// # Errors
    /// As [`Self::start`]; [`TransitError::RngUnavailable`] if the RNG latch
    /// has failed.
    #[cfg(feature = "random")]
    pub fn start_random(
        link_id: &[u8; LINK_ID_LEN],
        responder_static_pk: &XWingPublicKey,
        responder_key_id: &str,
        initiator_key_id: &str,
        initiator_static_pk: Option<&XWingPublicKey>,
    ) -> Result<(InitiatorState, Vec<u8>), TransitError> {
        let e_seed = draw_random::<XWING_SEED_LEN>()?;
        let rand = draw_random::<XWING_ENCAPSULATION_RANDOMNESS_LEN>()?;
        Self::start(
            link_id,
            responder_static_pk,
            responder_key_id,
            initiator_key_id,
            initiator_static_pk,
            &e_seed,
            &rand,
        )
    }
}

/// The initiator between `msg1` and `msg2`. Holds `E_i` and `ss1`, both
/// zeroized when the state is consumed or dropped.
pub struct InitiatorState {
    e_i: XWingSecretKey,
    ss1: SharedSecret,
    h2: [u8; 32],
    initiator_key_id: String,
    responder_key_id: String,
    has_static: bool,
}

impl core::fmt::Debug for InitiatorState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InitiatorState")
            .field("initiator_key_id", &self.initiator_key_id)
            .field("responder_key_id", &self.responder_key_id)
            .field("has_static", &self.has_static)
            .finish_non_exhaustive()
    }
}

impl InitiatorState {
    /// Process `msg2`. `decap3` decapsulates `ct3` with the initiator's
    /// static (in the vault); pass `None::<NoDecap>` when the initiator has
    /// none. On success the link's keys are derived, `confirm_r` has verified
    /// (constant-time) and [`InitiatorLink::ctkc`] is the first frame to seal
    /// under `k_i2r`. `E_i` and the shared secrets are zeroized.
    ///
    /// # Errors
    /// [`TransitError::MessageType`], [`TransitError::FlagsUnknown`],
    /// [`TransitError::Truncated`], [`TransitError::TrailingBytes`],
    /// [`TransitError::ModeMismatch`], [`TransitError::DecapsulationFailed`],
    /// [`TransitError::ConfirmMismatch`]. Any refusal closes the link.
    pub fn finish<D>(self, msg2: &[u8], decap3: Option<D>) -> Result<InitiatorLink, TransitError>
    where
        D: FnOnce(&[u8; XWING_CIPHERTEXT_LEN]) -> Result<SharedSecret, CryptoError>,
    {
        let mut r = Reader(msg2);
        if r.u8()? != MSG2_TYPE {
            return Err(TransitError::MessageType);
        }
        let flags = r.u8()?;
        if flags & !FLAG_MUTUAL != 0 {
            return Err(TransitError::FlagsUnknown);
        }
        let mutual = flags & FLAG_MUTUAL != 0;
        let ct2: [u8; XWING_CIPHERTEXT_LEN] = r.array()?;
        let ct3: Option<[u8; XWING_CIPHERTEXT_LEN]> = if mutual { Some(r.array()?) } else { None };
        let confirm_r: [u8; 32] = r.array()?;
        r.end()?;

        let decap3 = match (mutual, decap3) {
            (true, Some(d)) if self.has_static => Some(d),
            (true, _) => return Err(TransitError::ModeMismatch),
            (false, _) => None,
        };

        let ss2 = self
            .e_i
            .decapsulate(&ct2)
            .map_err(|_| TransitError::DecapsulationFailed)?;
        let mut ikm = Zeroizing::new(Vec::with_capacity(96));
        ikm.extend_from_slice(self.ss1.as_ref());
        ikm.extend_from_slice(ss2.as_ref());
        let h3 = match (&ct3, decap3) {
            (Some(ct3), Some(d)) => {
                let ss3 = d(ct3).map_err(|_| TransitError::DecapsulationFailed)?;
                ikm.extend_from_slice(ss3.as_ref());
                sha256(&[&self.h2, &[flags], &ct2, ct3])
            },
            _ => sha256(&[&self.h2, &[flags], &ct2]),
        };
        let bound = bound(&self.initiator_key_id, &self.responder_key_id)?;
        let (keys, k_conf) = derive_session_keys(&h3, &ikm, &bound);
        let expected = k_conf.mac(MAC_RESPONDER, &h3);
        if !bool::from(expected.ct_eq(&confirm_r)) {
            return Err(TransitError::ConfirmMismatch);
        }
        let ctkc = k_conf.ctkc(&h3);
        Ok(InitiatorLink {
            keys,
            k_conf,
            h3,
            mode: if mutual {
                Mode::Mutual
            } else {
                Mode::FirstContact
            },
            has_static: self.has_static,
            bound,
            ctkc,
            key_phase: 0,
            previous: None,
        })
        // `self` (E_i, ss1) drops here and is zeroized.
    }

    /// Whether `msg1` committed to an initiator static.
    #[must_use]
    pub fn has_static(&self) -> bool {
        self.has_static
    }
}

/// The initiator's side of a keyed link.
pub struct InitiatorLink {
    keys: SessionKeys,
    k_conf: ConfirmKey,
    h3: [u8; 32],
    mode: Mode,
    has_static: bool,
    bound: Vec<u8>,
    ctkc: [u8; CTKC_LEN],
    key_phase: u8,
    previous: Option<SessionKeys>,
}

impl core::fmt::Debug for InitiatorLink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InitiatorLink")
            .field("mode", &self.mode)
            .field("key_phase", &self.key_phase)
            .finish_non_exhaustive()
    }
}

impl InitiatorLink {
    /// The current phase's keys.
    #[must_use]
    pub fn keys(&self) -> &SessionKeys {
        &self.keys
    }

    /// The previous phase's keys, kept after promotion until
    /// [`Self::retire_previous_keys`].
    #[must_use]
    pub fn previous_keys(&self) -> Option<&SessionKeys> {
        self.previous.as_ref()
    }

    /// Zeroize the previous phase's keys.
    pub fn retire_previous_keys(&mut self) {
        self.previous = None;
    }

    /// The current phase's `k_conf`.
    #[must_use]
    pub fn confirm_key(&self) -> &ConfirmKey {
        &self.k_conf
    }

    /// The handshake's mode (mutual after promotion).
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The key phase: 0 at the handshake, 1 after promotion.
    #[must_use]
    pub fn key_phase(&self) -> u8 {
        self.key_phase
    }

    /// The current transcript hash (`h3`, then `h3'`).
    #[must_use]
    pub fn transcript_hash(&self) -> &[u8; 32] {
        &self.h3
    }

    /// The `CTKC` payload of the current phase, to seal as the first frame of
    /// that phase under `k_i2r`.
    #[must_use]
    pub fn ctkc(&self) -> &[u8; CTKC_LEN] {
        &self.ctkc
    }

    /// Process `msg3`: decapsulate `ct3'` with the initiator's static (`decap`,
    /// in the vault), rekey, and return `CTKC'` to seal under the new `k_i2r`.
    /// The old keys stay in [`Self::previous_keys`].
    ///
    /// # Errors
    /// [`TransitError::NotPromotable`] if the link is mutual or has no static;
    /// [`TransitError::MessageType`], [`TransitError::Truncated`],
    /// [`TransitError::TrailingBytes`], [`TransitError::DecapsulationFailed`].
    pub fn on_promote<D>(&mut self, msg3: &[u8], decap: D) -> Result<[u8; CTKC_LEN], TransitError>
    where
        D: FnOnce(&[u8; XWING_CIPHERTEXT_LEN]) -> Result<SharedSecret, CryptoError>,
    {
        if self.mode != Mode::FirstContact || !self.has_static {
            return Err(TransitError::NotPromotable);
        }
        let mut r = Reader(msg3);
        if r.u8()? != MSG3_TYPE {
            return Err(TransitError::MessageType);
        }
        let ct3p: [u8; XWING_CIPHERTEXT_LEN] = r.array()?;
        r.end()?;
        let ss3p = decap(&ct3p).map_err(|_| TransitError::DecapsulationFailed)?;
        let (h3p, keys, conf) = promotion_rekey(&self.h3, &ct3p, &self.keys, &ss3p, &self.bound);
        self.previous = Some(core::mem::replace(&mut self.keys, keys));
        self.k_conf = conf;
        self.h3 = h3p;
        self.ctkc = self.k_conf.ctkc(&self.h3);
        self.mode = Mode::Mutual;
        self.key_phase = self.key_phase.wrapping_add(1);
        Ok(self.ctkc)
    }
}

/// The responder's entry point.
pub struct Responder;

impl Responder {
    /// Answer `msg1`. `responder_static_pk` is this node's transit key and
    /// `responder_key_id` the id it answers as; `decap1` decapsulates `ct1`
    /// with the static (in the vault). `lookup(initiator_key_id, commitment)`
    /// returns the initiator's bound transit key if this node holds its
    /// binding; it is called only after `id_ct` opens and only when the
    /// initiator committed to a static, and the mode is mutual only when the
    /// key hashes to the commitment. `ct2_rand` and `ct3_rand` are fresh
    /// encapsulation randomness (`ct3_rand` is unused at first contact).
    ///
    /// Sending `msg2` attributes nothing: the link serves the first-contact
    /// plane until [`ResponderState::confirm`] verifies `CTKC`.
    ///
    /// # Errors
    /// [`TransitError::MessageType`], [`TransitError::SuiteV1Refused`],
    /// [`TransitError::SuiteUnknown`], [`TransitError::KeyIdInvalid`],
    /// [`TransitError::ResponderKeyIdMismatch`], [`TransitError::Truncated`],
    /// [`TransitError::TrailingBytes`], [`TransitError::BadLength`],
    /// [`TransitError::PublicKeyInvalid`], [`TransitError::DecapsulationFailed`],
    /// [`TransitError::IdentityOpenFailed`],
    /// [`TransitError::IdentityBlockMalformed`]. Any refusal closes the link.
    #[allow(clippy::too_many_arguments)]
    pub fn accept<D, L>(
        link_id: &[u8; LINK_ID_LEN],
        responder_static_pk: &XWingPublicKey,
        responder_key_id: &str,
        msg1: &[u8],
        decap1: D,
        lookup: L,
        ct2_rand: &[u8; XWING_ENCAPSULATION_RANDOMNESS_LEN],
        ct3_rand: &[u8; XWING_ENCAPSULATION_RANDOMNESS_LEN],
    ) -> Result<(ResponderState, Vec<u8>, Mode), TransitError>
    where
        D: FnOnce(&[u8; XWING_CIPHERTEXT_LEN]) -> Result<SharedSecret, CryptoError>,
        L: FnOnce(&str, &[u8; 32]) -> Option<XWingPublicKey>,
    {
        let mut r = Reader(msg1);
        if r.u8()? != MSG1_TYPE {
            return Err(TransitError::MessageType);
        }
        let suite_len = usize::from(r.u8()?);
        let suite = r.take(suite_len)?;
        if suite == TRANSIT_SUITE_V1.as_bytes() {
            return Err(TransitError::SuiteV1Refused);
        }
        if suite != TRANSIT_SUITE.as_bytes() {
            return Err(TransitError::SuiteUnknown);
        }
        let rid = r.key_id()?;
        if rid != responder_key_id {
            return Err(TransitError::ResponderKeyIdMismatch);
        }
        let pk_e_raw = r.take(XWING_PUBLIC_KEY_LEN)?;
        let ct1: [u8; XWING_CIPHERTEXT_LEN] = r.array()?;
        let id_ct_len = r.u16()?;
        let id_ct = r.take(id_ct_len)?;
        r.end()?;
        if id_ct.len() < AEAD_TAG_LEN {
            return Err(TransitError::BadLength);
        }
        let pk_e =
            XWingPublicKey::from_bytes(pk_e_raw).map_err(|_| TransitError::PublicKeyInvalid)?;

        let h0 = h0(link_id, responder_static_pk);
        let ss1 = decap1(&ct1).map_err(|_| TransitError::DecapsulationFailed)?;
        let h1 = sha256(&[&h0, pk_e.as_bytes(), &ct1]);
        let k_id = k_id(&h1, &ss1);
        let id_block = Zeroizing::new(
            aead(&k_id)
                .decrypt(
                    Nonce::from_slice(&[0u8; 12]),
                    Payload {
                        msg: id_ct,
                        aad: &h1,
                    },
                )
                .map_err(|_| TransitError::IdentityOpenFailed)?,
        );
        let (iid, commitment) = parse_id_block(&id_block)?;
        let h2 = sha256(&[&h1, id_ct]);

        // Only now, with id_ct open, may the store be consulted.
        let pk_s = commitment.and_then(|c| {
            lookup(&iid, &c).filter(|pk| bool::from(static_commitment(pk).ct_eq(&c)))
        });

        let (ct2, ss2) = pk_e.encapsulate_derand(ct2_rand);
        let mut ikm = Zeroizing::new(Vec::with_capacity(96));
        ikm.extend_from_slice(ss1.as_ref());
        ikm.extend_from_slice(ss2.as_ref());
        let mut msg2 = Vec::with_capacity(MSG2_MUTUAL_LEN);
        msg2.push(MSG2_TYPE);
        let (mode, h3) = if let Some(pk_s) = &pk_s {
            let (ct3, ss3) = pk_s.encapsulate_derand(ct3_rand);
            ikm.extend_from_slice(ss3.as_ref());
            msg2.push(FLAG_MUTUAL);
            msg2.extend_from_slice(&ct2);
            msg2.extend_from_slice(&ct3);
            (Mode::Mutual, sha256(&[&h2, &[FLAG_MUTUAL], &ct2, &ct3]))
        } else {
            msg2.push(0);
            msg2.extend_from_slice(&ct2);
            (Mode::FirstContact, sha256(&[&h2, &[0], &ct2]))
        };
        let bound = bound(&iid, &rid)?;
        let (keys, k_conf) = derive_session_keys(&h3, &ikm, &bound);
        msg2.extend_from_slice(&k_conf.mac(MAC_RESPONDER, &h3));

        Ok((
            ResponderState {
                keys,
                k_conf,
                h3,
                mode,
                initiator_key_id: iid,
                commitment,
                bound,
                phase: ResponderPhase::AwaitingCtkc,
                key_phase: 0,
                previous: None,
            },
            msg2,
            mode,
        ))
    }

    /// [`Self::accept`] with `ct2`'s then `ct3`'s randomness drawn from `rng`
    /// (both are drawn whatever the mode).
    ///
    /// # Errors
    /// As [`Self::accept`].
    #[allow(clippy::too_many_arguments)]
    pub fn accept_with_rng<D, L>(
        link_id: &[u8; LINK_ID_LEN],
        responder_static_pk: &XWingPublicKey,
        responder_key_id: &str,
        msg1: &[u8],
        decap1: D,
        lookup: L,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(ResponderState, Vec<u8>, Mode), TransitError>
    where
        D: FnOnce(&[u8; XWING_CIPHERTEXT_LEN]) -> Result<SharedSecret, CryptoError>,
        L: FnOnce(&str, &[u8; 32]) -> Option<XWingPublicKey>,
    {
        let r2 = draw::<XWING_ENCAPSULATION_RANDOMNESS_LEN>(rng);
        let r3 = draw::<XWING_ENCAPSULATION_RANDOMNESS_LEN>(rng);
        Self::accept(
            link_id,
            responder_static_pk,
            responder_key_id,
            msg1,
            decap1,
            lookup,
            &r2,
            &r3,
        )
    }

    /// [`Self::accept`] with randomness from the health-latched RNG facade.
    ///
    /// # Errors
    /// As [`Self::accept`]; [`TransitError::RngUnavailable`] if the RNG latch
    /// has failed.
    #[cfg(feature = "random")]
    pub fn accept_random<D, L>(
        link_id: &[u8; LINK_ID_LEN],
        responder_static_pk: &XWingPublicKey,
        responder_key_id: &str,
        msg1: &[u8],
        decap1: D,
        lookup: L,
    ) -> Result<(ResponderState, Vec<u8>, Mode), TransitError>
    where
        D: FnOnce(&[u8; XWING_CIPHERTEXT_LEN]) -> Result<SharedSecret, CryptoError>,
        L: FnOnce(&str, &[u8; 32]) -> Option<XWingPublicKey>,
    {
        let r2 = draw_random::<XWING_ENCAPSULATION_RANDOMNESS_LEN>()?;
        let r3 = draw_random::<XWING_ENCAPSULATION_RANDOMNESS_LEN>()?;
        Self::accept(
            link_id,
            responder_static_pk,
            responder_key_id,
            msg1,
            decap1,
            lookup,
            &r2,
            &r3,
        )
    }
}

fn parse_id_block(block: &[u8]) -> Result<(String, Option<[u8; 32]>), TransitError> {
    let malformed = |_| TransitError::IdentityBlockMalformed;
    let mut r = Reader(block);
    let len = r.u16().map_err(malformed)?;
    let raw = r.take(len).map_err(malformed)?;
    let commitment = match r.u8().map_err(malformed)? {
        0 => None,
        1 => Some(r.array::<32>().map_err(malformed)?),
        _ => return Err(TransitError::IdentityBlockMalformed),
    };
    r.end().map_err(malformed)?;
    let iid = core::str::from_utf8(raw).map_err(|_| TransitError::KeyIdInvalid)?;
    check_key_id(iid)?;
    Ok((iid.to_owned(), commitment))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponderPhase {
    AwaitingCtkc,
    Confirmed,
    AwaitingPromotionCtkc,
}

/// The responder's side of a keyed link.
pub struct ResponderState {
    keys: SessionKeys,
    k_conf: ConfirmKey,
    h3: [u8; 32],
    mode: Mode,
    initiator_key_id: String,
    commitment: Option<[u8; 32]>,
    bound: Vec<u8>,
    phase: ResponderPhase,
    key_phase: u8,
    previous: Option<SessionKeys>,
}

impl core::fmt::Debug for ResponderState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ResponderState")
            .field("mode", &self.mode)
            .field("initiator_key_id", &self.initiator_key_id)
            .field("phase", &self.phase)
            .field("key_phase", &self.key_phase)
            .finish_non_exhaustive()
    }
}

impl ResponderState {
    /// Check the initiator's first sealed frame, which MUST be `CTKC`. Mutual
    /// → [`Confirmation::Attributed`]; first contact →
    /// [`Confirmation::FirstContactConfirmed`].
    ///
    /// # Errors
    /// [`TransitError::NotCtkc`], [`TransitError::CtkcMismatch`],
    /// [`TransitError::Truncated`], [`TransitError::TrailingBytes`] (the link
    /// closes); [`TransitError::OutOfOrder`] if already confirmed.
    pub fn confirm(&mut self, ctkc: &[u8]) -> Result<Confirmation, TransitError> {
        if self.phase != ResponderPhase::AwaitingCtkc {
            return Err(TransitError::OutOfOrder);
        }
        self.k_conf.verify_ctkc(ctkc, &self.h3)?;
        self.phase = ResponderPhase::Confirmed;
        Ok(match self.mode {
            Mode::Mutual => Confirmation::Attributed,
            Mode::FirstContact => Confirmation::FirstContactConfirmed,
        })
    }

    /// Promote a confirmed first-contact link: `initiator_static_pk` is the
    /// transit key of the binding now held, which MUST hash to msg1's
    /// commitment. Returns `msg3`, to send on the sealed link. The responder
    /// switches its keys to the new phase (frames it sends after `msg3` use
    /// them) and keeps the old keys in [`Self::previous_keys`].
    ///
    /// # Errors
    /// [`TransitError::NotPromotable`], [`TransitError::PromotionCommitmentMismatch`]
    /// (the link stays at first contact).
    pub fn promote(
        &mut self,
        initiator_static_pk: &XWingPublicKey,
        encaps_rand: &[u8; XWING_ENCAPSULATION_RANDOMNESS_LEN],
    ) -> Result<Vec<u8>, TransitError> {
        let commitment = match (self.mode, self.phase, self.commitment) {
            (Mode::FirstContact, ResponderPhase::Confirmed, Some(c)) => c,
            _ => return Err(TransitError::NotPromotable),
        };
        if !bool::from(static_commitment(initiator_static_pk).ct_eq(&commitment)) {
            return Err(TransitError::PromotionCommitmentMismatch);
        }
        let (ct3p, ss3p) = initiator_static_pk.encapsulate_derand(encaps_rand);
        let (h3p, keys, conf) = promotion_rekey(&self.h3, &ct3p, &self.keys, &ss3p, &self.bound);
        self.previous = Some(core::mem::replace(&mut self.keys, keys));
        self.k_conf = conf;
        self.h3 = h3p;
        self.key_phase = self.key_phase.wrapping_add(1);
        self.phase = ResponderPhase::AwaitingPromotionCtkc;
        let mut msg3 = Vec::with_capacity(MSG3_LEN);
        msg3.push(MSG3_TYPE);
        msg3.extend_from_slice(&ct3p);
        Ok(msg3)
    }

    /// [`Self::promote`] with randomness from `rng`.
    ///
    /// # Errors
    /// As [`Self::promote`].
    pub fn promote_with_rng(
        &mut self,
        initiator_static_pk: &XWingPublicKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, TransitError> {
        let r = draw::<XWING_ENCAPSULATION_RANDOMNESS_LEN>(rng);
        self.promote(initiator_static_pk, &r)
    }

    /// Check `CTKC'`, the initiator's first frame of the new phase. On success
    /// the link is mutual and the initiator attributed.
    ///
    /// # Errors
    /// As [`Self::confirm`]; [`TransitError::OutOfOrder`] without a pending
    /// promotion.
    pub fn confirm_promotion(&mut self, ctkc: &[u8]) -> Result<Confirmation, TransitError> {
        if self.phase != ResponderPhase::AwaitingPromotionCtkc {
            return Err(TransitError::OutOfOrder);
        }
        self.k_conf.verify_ctkc(ctkc, &self.h3)?;
        self.phase = ResponderPhase::Confirmed;
        self.mode = Mode::Mutual;
        Ok(Confirmation::Attributed)
    }

    /// The handshake's mode (mutual after a confirmed promotion).
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Whether the initiator is attributed: mutual and `CTKC` (or `CTKC'`)
    /// verified.
    #[must_use]
    pub fn is_attributed(&self) -> bool {
        self.mode == Mode::Mutual && self.phase == ResponderPhase::Confirmed
    }

    /// The initiator key id sealed in `id_ct` (claimed until attributed).
    #[must_use]
    pub fn initiator_key_id(&self) -> &str {
        &self.initiator_key_id
    }

    /// msg1's commitment `H(pk(S_i))`, `None` for `has_static = 0`.
    #[must_use]
    pub fn commitment(&self) -> Option<&[u8; 32]> {
        self.commitment.as_ref()
    }

    /// The current phase's keys.
    #[must_use]
    pub fn keys(&self) -> &SessionKeys {
        &self.keys
    }

    /// The previous phase's keys, kept after promotion until
    /// [`Self::retire_previous_keys`].
    #[must_use]
    pub fn previous_keys(&self) -> Option<&SessionKeys> {
        self.previous.as_ref()
    }

    /// Zeroize the previous phase's keys.
    pub fn retire_previous_keys(&mut self) {
        self.previous = None;
    }

    /// The current phase's `k_conf`.
    #[must_use]
    pub fn confirm_key(&self) -> &ConfirmKey {
        &self.k_conf
    }

    /// The key phase: 0 at the handshake, 1 after promotion.
    #[must_use]
    pub fn key_phase(&self) -> u8 {
        self.key_phase
    }

    /// The current transcript hash (`h3`, then `h3'`).
    #[must_use]
    pub fn transcript_hash(&self) -> &[u8; 32] {
        &self.h3
    }
}

/// Split a handshake message into `CTKX` v2 parts of at most `max_part_len`
/// bytes each, headers included: a start part `"CTKX" ‖ 0x02 ‖ 0x00 ‖
/// u32 total_len ‖ bytes`, then continuations `"CTKX" ‖ 0x02 ‖ 0x01 ‖ bytes`.
///
/// # Errors
/// [`TransitError::FramingTooLarge`] for an empty or over-8-KiB message;
/// [`TransitError::BadLength`] if `max_part_len` leaves no room for bytes.
pub fn encode_parts(msg: &[u8], max_part_len: usize) -> Result<Vec<Vec<u8>>, TransitError> {
    if msg.is_empty() || msg.len() > MAX_MESSAGE_LEN {
        return Err(TransitError::FramingTooLarge);
    }
    if max_part_len <= START_HEADER_LEN {
        return Err(TransitError::BadLength);
    }
    let first = (max_part_len - START_HEADER_LEN).min(msg.len());
    let mut start = Vec::with_capacity(START_HEADER_LEN + first);
    start.extend_from_slice(FRAMING_MAGIC);
    start.push(FRAMING_VERSION);
    start.push(PART_START);
    #[allow(clippy::cast_possible_truncation)]
    start.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    start.extend_from_slice(&msg[..first]);
    let mut parts = vec![start];
    for chunk in msg[first..].chunks(max_part_len - CONTINUATION_HEADER_LEN) {
        let mut p = Vec::with_capacity(CONTINUATION_HEADER_LEN + chunk.len());
        p.extend_from_slice(FRAMING_MAGIC);
        p.push(FRAMING_VERSION);
        p.push(PART_CONTINUATION);
        p.extend_from_slice(chunk);
        parts.push(p);
    }
    Ok(parts)
}

/// Reassembles one handshake message from `CTKX` v2 parts.
#[derive(Debug, Default)]
pub struct Reassembler {
    total: Option<usize>,
    buf: Vec<u8>,
    done: bool,
}

impl Reassembler {
    /// An empty reassembler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one part. Returns the message when it completes.
    ///
    /// # Errors
    /// [`TransitError::FramingV1Refused`] for version 0x01,
    /// [`TransitError::FramingVersionUnsupported`], [`TransitError::FramingMalformed`],
    /// [`TransitError::FramingPartKind`], [`TransitError::FramingTooLarge`],
    /// [`TransitError::FramingOutOfOrder`], [`TransitError::TrailingBytes`]
    /// (a part overruns `total_len`).
    pub fn push(&mut self, part: &[u8]) -> Result<Option<Vec<u8>>, TransitError> {
        if part.len() < CONTINUATION_HEADER_LEN || &part[..4] != FRAMING_MAGIC {
            return Err(TransitError::FramingMalformed);
        }
        match part[4] {
            0x01 => return Err(TransitError::FramingV1Refused),
            FRAMING_VERSION => {},
            _ => return Err(TransitError::FramingVersionUnsupported),
        }
        if self.done {
            return Err(TransitError::FramingOutOfOrder);
        }
        let body = match part[5] {
            PART_START => {
                if self.total.is_some() {
                    return Err(TransitError::FramingOutOfOrder);
                }
                if part.len() < START_HEADER_LEN {
                    return Err(TransitError::FramingMalformed);
                }
                let total = u32::from_be_bytes([part[6], part[7], part[8], part[9]]) as usize;
                if total == 0 || total > MAX_MESSAGE_LEN {
                    return Err(TransitError::FramingTooLarge);
                }
                self.total = Some(total);
                &part[START_HEADER_LEN..]
            },
            PART_CONTINUATION => {
                if self.total.is_none() {
                    return Err(TransitError::FramingOutOfOrder);
                }
                &part[CONTINUATION_HEADER_LEN..]
            },
            _ => return Err(TransitError::FramingPartKind),
        };
        let total = self.total.unwrap_or_default();
        if self.buf.len() + body.len() > total {
            return Err(TransitError::TrailingBytes);
        }
        self.buf.extend_from_slice(body);
        if self.buf.len() == total {
            self.done = true;
            return Ok(Some(core::mem::take(&mut self.buf)));
        }
        Ok(None)
    }
}

// --------------------------------------------------------------------------
// The per-frame link seal, frame version 0x02 with key phases
// --------------------------------------------------------------------------

/// Seal frame version of this module (key phases). The leading byte of every
/// sealed frame.
pub const SEAL_FRAME_VERSION: u8 = 0x02;
/// v1's seal frame version (`0x01 ‖ counter ‖ …`), refused by name
/// ([`FrameError::V1Refused`]).
pub const SEAL_FRAME_VERSION_V1: u8 = 0x01;
/// HKDF info of the per-direction seal key `k`.
pub const LABEL_LINK_SEAL: &[u8] = b"CIRIS-E1-LINK-SEAL-V2";
/// Header length: version, phase, `u64_be` counter.
pub const SEAL_HEADER_LEN: usize = 1 + 1 + 8;
/// The AES-256-GCM tag length.
pub const SEAL_TAG_LEN: usize = AEAD_TAG_LEN;
/// The shortest frame: a header and a tag (an empty plaintext).
pub const SEAL_OVERHEAD: usize = SEAL_HEADER_LEN + SEAL_TAG_LEN;
/// Each lane's replay window, in frames.
pub const REPLAY_WINDOW: u64 = 128;
/// Key phase 0: the keys from `msg2`.
pub const PHASE_HANDSHAKE: u8 = 0;
/// Key phase 1: the keys from a promotion (`k_i2r'`, `k_r2i'`).
pub const PHASE_PROMOTED: u8 = 1;

const LANE_COUNT: usize = 5;

/// A link carrier. Each has its own counter and replay window, because lanes
/// are not ordered with one another; the lane is in the nonce and the AAD but
/// not on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Lane {
    /// A Channel message.
    Channel = 1,
    /// A Resource transfer.
    Resource = 2,
    /// A link request's data.
    Request = 3,
    /// A link response's data.
    Response = 4,
    /// A link datagram.
    Datagram = 5,
}

impl Lane {
    /// Every lane, in wire order.
    pub const ALL: [Self; LANE_COUNT] = [
        Self::Channel,
        Self::Resource,
        Self::Request,
        Self::Response,
        Self::Datagram,
    ];

    /// The lane byte in the nonce and the AAD.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The lane with this byte, if any.
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Channel),
            2 => Some(Self::Resource),
            3 => Some(Self::Request),
            4 => Some(Self::Response),
            5 => Some(Self::Datagram),
            _ => None,
        }
    }

    const fn index(self) -> usize {
        self as usize - 1
    }
}

/// `k = HKDF-SHA256(ikm = k_dir, salt = link_id, info = "CIRIS-E1-LINK-SEAL-V2")`,
/// the AES-256-GCM key of one direction in one key phase. `k_dir` is `k_i2r` or
/// `k_r2i` (phase 0) or their promoted successors (phase 1).
#[must_use]
pub fn link_seal_key(
    k_dir: &[u8; SESSION_KEY_LEN],
    link_id: &[u8; LINK_ID_LEN],
) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(&link_id[..]), &k_dir[..]);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(LABEL_LINK_SEAL, out.as_mut())
        .expect("32 bytes is within HKDF-SHA256's output bound");
    out
}

/// `nonce = lane ‖ 0x000000 ‖ counter u64_be`.
fn seal_nonce(lane: Lane, counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = lane.as_u8();
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

/// `aad = 0x02 ‖ lane ‖ phase ‖ link_id`.
fn seal_aad(lane: Lane, phase: u8, link_id: &[u8; LINK_ID_LEN]) -> [u8; 3 + LINK_ID_LEN] {
    let mut a = [0u8; 3 + LINK_ID_LEN];
    a[0] = SEAL_FRAME_VERSION;
    a[1] = lane.as_u8();
    a[2] = phase;
    a[3..].copy_from_slice(link_id);
    a
}

/// Seal one frame: `0x02 ‖ phase ‖ counter u64_be ‖ AES-256-GCM(k, nonce, aad,
/// pt) ‖ tag[16]`, with `k` from [`link_seal_key`].
///
/// The caller owns the counter: one per lane, strictly increasing, and
/// continuing across the phase change. A counter MUST NOT repeat on a lane
/// within a phase. `phase` is written as given and not checked, so the
/// known answers can build the frames a receiver refuses; a sender uses only
/// [`PHASE_HANDSHAKE`] and [`PHASE_PROMOTED`], switching every lane to phase 1
/// once it has sent or received `CTKC'`.
#[must_use]
pub fn seal_frame(
    k_dir: &[u8; SESSION_KEY_LEN],
    link_id: &[u8; LINK_ID_LEN],
    lane: Lane,
    phase: u8,
    counter: u64,
    pt: &[u8],
) -> Vec<u8> {
    let k = link_seal_key(k_dir, link_id);
    let nonce = seal_nonce(lane, counter);
    let aad = seal_aad(lane, phase, link_id);
    let ct = aead(&k)
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad: &aad })
        .expect("AES-256-GCM seals any input under a 32-byte key");
    let mut out = Vec::with_capacity(SEAL_HEADER_LEN + ct.len());
    out.push(SEAL_FRAME_VERSION);
    out.push(phase);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(&ct);
    out
}

/// A refused sealed frame. **Every variant means the caller closes the
/// link**; a frame the link survives is an [`OpenOutcome`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// Shorter than [`SEAL_OVERHEAD`] (or empty).
    #[error("link seal: frame truncated")]
    Truncated,
    /// Seal frame version 0x01: v1 is refused after the cut.
    #[error("link seal: v1 frame refused")]
    V1Refused,
    /// A seal frame version other than 0x01 or 0x02.
    #[error("link seal: frame version unsupported")]
    VersionUnsupported,
    /// A phase byte of 2 or more: a link is promoted at most once.
    #[error("link seal: unknown key phase")]
    UnknownPhase,
    /// A phase-1 frame on a link this receiver has not promoted.
    #[error("link seal: phase 1 before promotion")]
    PhaseBeforePromotion,
    /// A frame of a known, held phase fails AEAD.
    #[error("link seal: frame does not open")]
    OpenFailed,
    /// [`FrameOpener::promote`] called on a link already promoted.
    #[error("link seal: link already promoted")]
    AlreadyPromoted,
}

impl FrameError {
    /// The stable refusal name, as the seal-frame known answers record it.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Truncated => "seal_truncated",
            Self::V1Refused => "seal_v1_refused",
            Self::VersionUnsupported => "seal_version_unsupported",
            Self::UnknownPhase => "seal_unknown_phase",
            Self::PhaseBeforePromotion => "seal_phase_before_promotion",
            Self::OpenFailed => "seal_open_failed",
            Self::AlreadyPromoted => "seal_already_promoted",
        }
    }
}

/// What [`FrameOpener::open`] did with a frame the link survives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenOutcome {
    /// The frame opened and its counter is fresh: deliver the plaintext.
    Plaintext(Vec<u8>),
    /// A phase-0 frame on a lane whose phase-0 keys are retired: late, not
    /// forged. Dropped unopened and counted ([`FrameOpener::seal_stale_phase`]).
    DroppedStale,
    /// The frame opened, but its counter repeats inside the lane's window or
    /// is older than it. Dropped and counted
    /// ([`FrameOpener::seal_dropped_replay`]), as in v1: the tag is valid, so
    /// the peer holds the keys.
    DroppedReplay,
}

/// Highest counter accepted plus a bitmap of the [`REPLAY_WINDOW`] below it.
#[derive(Debug, Default, Clone, Copy)]
struct ReplayWindow {
    highest: Option<u64>,
    /// Bit `i` set iff `highest - i` was accepted.
    seen: u128,
}

impl ReplayWindow {
    /// Accept `c` once, or refuse it.
    fn accept(&mut self, c: u64) -> bool {
        let Some(h) = self.highest else {
            self.highest = Some(c);
            self.seen = 1;
            return true;
        };
        if c > h {
            let shift = c - h;
            self.seen = if shift >= REPLAY_WINDOW {
                0
            } else {
                self.seen << shift
            };
            self.seen |= 1;
            self.highest = Some(c);
            return true;
        }
        let back = h - c;
        if back >= REPLAY_WINDOW {
            return false;
        }
        let bit = 1u128 << back;
        if self.seen & bit != 0 {
            return false;
        }
        self.seen |= bit;
        true
    }
}

/// The receiving half of one link's seal: the open keys of each phase held,
/// and per lane whether phase 0 is retired and the replay window.
///
/// [`open`](Self::open) classifies a frame by its clear phase byte before
/// opening it:
///
/// - phase 0 on a lane whose phase-0 keys are retired (phase 1 seen on that
///   lane, or [`retire_phase0`](Self::retire_phase0) at the end of the
///   handshake budget): [`OpenOutcome::DroppedStale`], the link stays open;
/// - phase 2 or more, or phase 1 before [`promote`](Self::promote):
///   [`FrameError::UnknownPhase`] / [`FrameError::PhaseBeforePromotion`];
/// - a held phase that fails AEAD: [`FrameError::OpenFailed`];
/// - a frame that opened with a repeated or too-old counter:
///   [`OpenOutcome::DroppedReplay`]. The window moves only for a frame that
///   opened, so forged counters cannot push real frames out of it. It is
///   shared by both phases, because counters continue across the change.
///
/// Every [`FrameError`] means close the link; the opener is then not reused.
pub struct FrameOpener {
    role: Role,
    link_id: [u8; LINK_ID_LEN],
    phase0: Option<Zeroizing<[u8; 32]>>,
    phase1: Option<Zeroizing<[u8; 32]>>,
    phase0_retired: [bool; LANE_COUNT],
    windows: [ReplayWindow; LANE_COUNT],
    stale: u64,
    replays: u64,
}

impl core::fmt::Debug for FrameOpener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FrameOpener")
            .field("role", &self.role)
            .field("promoted", &self.is_promoted())
            .field("phase0_retired", &self.phase0_retired)
            .field("seal_stale_phase", &self.stale)
            .field("seal_dropped_replay", &self.replays)
            .finish_non_exhaustive()
    }
}

impl FrameOpener {
    /// The receiver of `role` on `link_id`, holding phase 0 from the `msg2`
    /// keys. It opens the peer's direction: `k_i2r` at the responder, `k_r2i`
    /// at the initiator.
    #[must_use]
    pub fn new(
        role: Role,
        k_i2r: &[u8; SESSION_KEY_LEN],
        k_r2i: &[u8; SESSION_KEY_LEN],
        link_id: &[u8; LINK_ID_LEN],
    ) -> Self {
        Self {
            role,
            link_id: *link_id,
            phase0: Some(link_seal_key(Self::pick(role, k_i2r, k_r2i), link_id)),
            phase1: None,
            phase0_retired: [false; LANE_COUNT],
            windows: [ReplayWindow::default(); LANE_COUNT],
            stale: 0,
            replays: 0,
        }
    }

    /// [`new`](Self::new) from the handshake's [`SessionKeys`].
    #[must_use]
    pub fn from_session_keys(role: Role, keys: &SessionKeys, link_id: &[u8; LINK_ID_LEN]) -> Self {
        Self::new(role, keys.k_i2r(), keys.k_r2i(), link_id)
    }

    fn pick<'k>(
        role: Role,
        k_i2r: &'k [u8; SESSION_KEY_LEN],
        k_r2i: &'k [u8; SESSION_KEY_LEN],
    ) -> &'k [u8; SESSION_KEY_LEN] {
        match role {
            Role::Initiator => k_r2i,
            Role::Responder => k_i2r,
        }
    }

    /// Install phase 1 from the promotion keys `k_i2r'` / `k_r2i'`. Phase 0's
    /// keys stay held on each lane until phase 1 is seen there, or until
    /// [`retire_phase0`](Self::retire_phase0).
    ///
    /// # Errors
    /// [`FrameError::AlreadyPromoted`]: a link is promoted at most once.
    pub fn promote(
        &mut self,
        k_i2r_prime: &[u8; SESSION_KEY_LEN],
        k_r2i_prime: &[u8; SESSION_KEY_LEN],
    ) -> Result<(), FrameError> {
        if self.phase1.is_some() {
            return Err(FrameError::AlreadyPromoted);
        }
        self.phase1 = Some(link_seal_key(
            Self::pick(self.role, k_i2r_prime, k_r2i_prime),
            &self.link_id,
        ));
        Ok(())
    }

    /// [`promote`](Self::promote) from the promotion's [`SessionKeys`].
    ///
    /// # Errors
    /// As [`promote`](Self::promote).
    pub fn promote_session_keys(&mut self, keys: &SessionKeys) -> Result<(), FrameError> {
        self.promote(keys.k_i2r(), keys.k_r2i())
    }

    /// Retire phase 0 on every lane and zeroize its key: the handshake budget
    /// after the promotion has run out. Before a promotion it does nothing,
    /// because phase 0 is then the link's only phase.
    pub fn retire_phase0(&mut self) {
        if self.is_promoted() {
            self.phase0_retired = [true; LANE_COUNT];
            self.phase0 = None;
        }
    }

    /// Whether phase 1 is installed.
    #[must_use]
    pub fn is_promoted(&self) -> bool {
        self.phase1.is_some()
    }

    /// Whether phase-0 frames still open on `lane`.
    #[must_use]
    pub fn holds_phase0(&self, lane: Lane) -> bool {
        self.phase0.is_some() && !self.phase0_retired[lane.index()]
    }

    /// Frames dropped as a stale phase (the `seal_stale_phase` counter).
    #[must_use]
    pub fn seal_stale_phase(&self) -> u64 {
        self.stale
    }

    /// Frames that opened but were dropped by the replay window.
    #[must_use]
    pub fn seal_dropped_replay(&self) -> u64 {
        self.replays
    }

    /// Open one frame received on `lane`.
    ///
    /// # Errors
    /// Every [`FrameError`] closes the link: [`FrameError::Truncated`],
    /// [`FrameError::V1Refused`], [`FrameError::VersionUnsupported`],
    /// [`FrameError::UnknownPhase`], [`FrameError::PhaseBeforePromotion`],
    /// [`FrameError::OpenFailed`].
    pub fn open(&mut self, lane: Lane, frame: &[u8]) -> Result<OpenOutcome, FrameError> {
        match frame.first() {
            None => return Err(FrameError::Truncated),
            Some(&SEAL_FRAME_VERSION) => {},
            Some(&SEAL_FRAME_VERSION_V1) => return Err(FrameError::V1Refused),
            Some(_) => return Err(FrameError::VersionUnsupported),
        }
        if frame.len() < SEAL_OVERHEAD {
            return Err(FrameError::Truncated);
        }
        let phase = frame[1];
        let mut be = [0u8; 8];
        be.copy_from_slice(&frame[2..SEAL_HEADER_LEN]);
        let counter = u64::from_be_bytes(be);
        let i = lane.index();
        let key = match phase {
            PHASE_HANDSHAKE => match &self.phase0 {
                Some(k) if !self.phase0_retired[i] => k,
                _ => {
                    self.stale += 1;
                    return Ok(OpenOutcome::DroppedStale);
                },
            },
            PHASE_PROMOTED => match &self.phase1 {
                Some(k) => k,
                None => return Err(FrameError::PhaseBeforePromotion),
            },
            _ => return Err(FrameError::UnknownPhase),
        };
        let nonce = seal_nonce(lane, counter);
        let aad = seal_aad(lane, phase, &self.link_id);
        let pt = aead(key)
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &frame[SEAL_HEADER_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| FrameError::OpenFailed)?;
        if phase == PHASE_PROMOTED && !self.phase0_retired[i] {
            self.phase0_retired[i] = true;
            if self.phase0_retired.iter().all(|r| *r) {
                self.phase0 = None;
            }
        }
        if self.windows[i].accept(counter) {
            Ok(OpenOutcome::Plaintext(pt))
        } else {
            self.replays += 1;
            Ok(OpenOutcome::DroppedReplay)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decap(
        sk: &XWingSecretKey,
    ) -> impl FnOnce(&[u8; XWING_CIPHERTEXT_LEN]) -> Result<SharedSecret, CryptoError> + '_ {
        move |ct| sk.decapsulate(ct)
    }

    #[test]
    fn mutual_round_trip_and_sizes() {
        let sr = XWingSecretKey::from_seed([1; 32]);
        let si = XWingSecretKey::from_seed([2; 32]);
        let (pr, pi) = (sr.public_key(), si.public_key());
        let link = [9u8; 16];
        let (st, m1) =
            Initiator::start(&link, &pr, "r", "i", Some(&pi), &[3; 32], &[4; 64]).unwrap();
        let pi2 = pi.clone();
        let (mut rs, m2, mode) = Responder::accept(
            &link,
            &pr,
            "r",
            &m1,
            decap(&sr),
            |_, _| Some(pi2),
            &[5; 64],
            &[6; 64],
        )
        .unwrap();
        assert_eq!(mode, Mode::Mutual);
        assert_eq!(m2.len(), MSG2_MUTUAL_LEN);
        let il = st.finish(&m2, Some(decap(&si))).unwrap();
        assert_eq!(il.keys().k_i2r(), rs.keys().k_i2r());
        assert_eq!(il.keys().k_r2i(), rs.keys().k_r2i());
        assert_ne!(il.keys().k_i2r(), il.keys().k_r2i());
        assert!(!rs.is_attributed());
        assert_eq!(rs.confirm(il.ctkc()).unwrap(), Confirmation::Attributed);
        assert!(rs.is_attributed());
        assert_eq!(rs.confirm(il.ctkc()), Err(TransitError::OutOfOrder));
    }

    #[test]
    fn first_contact_then_promotion() {
        let sr = XWingSecretKey::from_seed([1; 32]);
        let si = XWingSecretKey::from_seed([2; 32]);
        let (pr, pi) = (sr.public_key(), si.public_key());
        let link = [9u8; 16];
        let (st, m1) =
            Initiator::start(&link, &pr, "r", "i", Some(&pi), &[3; 32], &[4; 64]).unwrap();
        let (mut rs, m2, mode) = Responder::accept(
            &link,
            &pr,
            "r",
            &m1,
            decap(&sr),
            |_, _| None,
            &[5; 64],
            &[6; 64],
        )
        .unwrap();
        assert_eq!(mode, Mode::FirstContact);
        assert_eq!(m2.len(), MSG2_FIRST_CONTACT_LEN);
        let mut il = st.finish(&m2, Some(decap(&si))).unwrap();
        // Promotion before CTKC is refused.
        assert_eq!(rs.promote(&pi, &[7; 64]), Err(TransitError::NotPromotable));
        assert_eq!(
            rs.confirm(il.ctkc()).unwrap(),
            Confirmation::FirstContactConfirmed
        );
        let m3 = rs.promote(&pi, &[7; 64]).unwrap();
        assert_eq!(m3.len(), MSG3_LEN);
        let ctkc2 = il.on_promote(&m3, decap(&si)).unwrap();
        assert_eq!(il.keys().k_i2r(), rs.keys().k_i2r());
        assert_eq!(il.key_phase(), 1);
        assert_eq!(
            rs.previous_keys().unwrap().k_i2r(),
            il.previous_keys().unwrap().k_i2r()
        );
        assert_eq!(
            rs.confirm_promotion(&ctkc2).unwrap(),
            Confirmation::Attributed
        );
        assert!(rs.is_attributed());
    }

    #[test]
    fn framing_round_trip() {
        let msg: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let parts = encode_parts(&msg, 400).unwrap();
        let mut r = Reassembler::new();
        let mut out = None;
        for p in &parts {
            assert!(p.len() <= 400);
            out = r.push(p).unwrap();
        }
        assert_eq!(out.unwrap(), msg);
    }
}
