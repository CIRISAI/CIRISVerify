//! §10.5.8.3–.5 realtime A/V chunk wire — `SealedAvChunk` header + the
//! double-seal deterministic nonce derivation (CEG 1.0-RC10, absorbed byte-exact
//! from CIRISEdge v4.0.0 `SealedAvChunk::to_bytes`).
//!
//! A `SealedAvChunk` rides each RNS Link payload. Its content is
//! `outer-AEAD( inner-AEAD( plaintext ) )` — two independent AES-256-GCM layers:
//! the **inner** is the end-to-end epoch-DEK content seal, the **outer** the
//! per-RNS-Link transit wrap (a relay sees only the outer layer, never
//! plaintext — the §10.5.5 E1 two-layer posture). **No nonce is transmitted** —
//! every holder recomputes both deterministically, so a BE/LE disagreement on
//! `epoch`/`seq` yields a different nonce → GCM auth-tag failure. This module
//! pins both derivations and the header layout so a cross-impl verifier
//! recomputes byte-identically (the §19.6 / #57 vector target for A/V).
//!
//! ## Header layout (normative §10.5.8.3)
//!
//! ```text
//! 0..32   stream_id        32 bytes (caller-derived: sha256(stream_meta))
//! 32..40  epoch            u64 big-endian
//! 40..48  chunk_seq        u64 big-endian
//! 48..52  codec_id(1) ‖ ChunkLayer{spatial:u8, temporal:u8, quality:u8}
//! 52..    double_sealed_ciphertext
//! ```
//! A v3.7.0 chunk round-trips as `codec_id = 0xFF` + `ChunkLayer{0,0,0}`.

use sha2::{Digest, Sha256};

/// The fixed `stream_id`+`epoch`+`chunk_seq` header length (stable since v3.7.0).
pub const CHUNK_HEADER_LEN: usize = 48;
/// The `codec_id`+`ChunkLayer` additive block length.
pub const CHUNK_CODEC_LAYER_LEN: usize = 4;
/// Offset of the codec/layer block.
pub const CHUNK_CODEC_LAYER_OFFSET: usize = 48;
/// `stream_id` width.
pub const STREAM_ID_LEN: usize = 32;
/// AES-GCM nonce width (96-bit / 12 bytes).
pub const AV_NONCE_LEN: usize = 12;

/// Inner-seal nonce domain separator of the **retired** A/V inner nonce.
///
/// Kept so a historical artifact is recognisable; nothing seals with it. The
/// inner seal is the CC 5.3.3.1 STREAM nonce ([`av_inner_nonce`]).
#[deprecated(
    since = "19.1.0",
    note = "the A/V inner seal is the CC 5.3.3.1 STREAM nonce (CIRISConstitution#140); use av_inner_nonce"
)]
pub const AV_INNER_DOMAIN: &[u8] = b"CIRIS-AV-INNER-V1";
/// Outer-seal (per-RNS-Link transit) nonce domain separator.
pub const AV_OUTER_DOMAIN: &[u8] = b"CIRIS-AV-OUTER-V1";

/// The §10.5.8.3 scalable-codec layer block (clear metadata, NOT inside the
/// AEAD — a relay drops by `codec_id`/`ChunkLayer` without touching the seal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkLayer {
    /// Spatial enhancement layer.
    pub spatial: u8,
    /// Temporal enhancement layer.
    pub temporal: u8,
    /// Quality enhancement layer.
    pub quality: u8,
}

/// The parsed clear header of a `SealedAvChunk` (everything before the
/// double-sealed ciphertext).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedAvChunkHeader {
    /// 32-byte stream id.
    pub stream_id: [u8; STREAM_ID_LEN],
    /// Epoch (u64).
    pub epoch: u64,
    /// Per-stream chunk sequence (u64).
    pub chunk_seq: u64,
    /// Codec discriminant (`0xFF` = the v3.7.0 round-trip).
    pub codec_id: u8,
    /// Scalable-codec layer selectors.
    pub layer: ChunkLayer,
}

/// Parse the clear header of a `SealedAvChunk` (§10.5.8.3). Returns the header
/// plus the offset at which the double-sealed ciphertext begins.
///
/// # Errors
///
/// `Err(())` if `bytes` is shorter than the 52-byte clear header.
#[allow(clippy::result_unit_err)]
pub fn parse_header(bytes: &[u8]) -> Result<(SealedAvChunkHeader, usize), ()> {
    let clear = CHUNK_HEADER_LEN + CHUNK_CODEC_LAYER_LEN;
    if bytes.len() < clear {
        return Err(());
    }
    let mut stream_id = [0u8; STREAM_ID_LEN];
    stream_id.copy_from_slice(&bytes[0..STREAM_ID_LEN]);
    let epoch = u64::from_be_bytes(bytes[32..40].try_into().unwrap());
    let chunk_seq = u64::from_be_bytes(bytes[40..48].try_into().unwrap());
    let codec_id = bytes[CHUNK_CODEC_LAYER_OFFSET];
    let layer = ChunkLayer {
        spatial: bytes[49],
        temporal: bytes[50],
        quality: bytes[51],
    };
    Ok((
        SealedAvChunkHeader {
            stream_id,
            epoch,
            chunk_seq,
            codec_id,
            layer,
        },
        clear,
    ))
}

fn sha256_12(parts: &[&[u8]]) -> [u8; AV_NONCE_LEN] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    let full = h.finalize();
    let mut out = [0u8; AV_NONCE_LEN];
    out.copy_from_slice(&full[..AV_NONCE_LEN]);
    out
}

/// The **retired** A/V inner nonce:
/// `SHA-256( b"CIRIS-AV-INNER-V1" ‖ stream_id[32] ‖ epoch_be8 ‖ chunk_seq_be8 )[0..12]`.
///
/// It was a second normative seal for what CC calls one wire. The steward ruled
/// the realtime inner seal is the CC 5.3.3.1 STREAM nonce (CIRISConstitution#140,
/// CC rc7 `7561d07`); use [`av_inner_nonce`]. Retained only so an existing
/// artifact can be identified, never to seal.
#[deprecated(
    since = "19.1.0",
    note = "the A/V inner seal is the CC 5.3.3.1 STREAM nonce (CIRISConstitution#140); use av_inner_nonce"
)]
#[must_use]
#[allow(deprecated)]
pub fn inner_nonce(
    stream_id: &[u8; STREAM_ID_LEN],
    epoch: u64,
    chunk_seq: u64,
) -> [u8; AV_NONCE_LEN] {
    sha256_12(&[
        AV_INNER_DOMAIN,
        stream_id,
        &epoch.to_be_bytes(),
        &chunk_seq.to_be_bytes(),
    ])
}

/// The STREAM `stream_id` of an A/V stream: the lowercase hex of the header's
/// 32 bytes (64 ASCII chars). CIRISEdge names a kept call's persist recording by
/// this same string, so a live stream and its stored segments share one
/// `stream_id` and one seal (CIRISVerify#303).
#[must_use]
pub fn av_stream_id(stream_id: &[u8; STREAM_ID_LEN]) -> String {
    hex::encode(stream_id)
}

/// The **inner** (end-to-end, epoch-DEK) AES-GCM nonce for an A/V chunk: the
/// CC 5.3.3.1 STREAM nonce over [`av_stream_id`], with `counter = chunk_seq`
/// and `last` set on the epoch's final chunk (CIRISConstitution#140).
///
/// **`chunk_seq` must be the chunk's index WITHIN its epoch**, restarting at 0
/// on every epoch roll. That is what the STREAM counter is, and it is how
/// CIRISPersist seals a stored chunk (`rec.chunk_count`, reset at every roll).
/// A stream-global sequence number coincides with it only in epoch 0 of a
/// stream that never rolled; past that, a live chunk sealed with the global
/// number and its stored copy sealed with the epoch-local one carry different
/// nonces, and the recording no longer opens. A stream-global position belongs
/// in the AAD (persist binds it there), never in the nonce counter.
///
/// `None` when `chunk_seq` exceeds `u32::MAX`: the STREAM counter is 32 bits
/// and CC requires the epoch to roll before it wraps, so such a chunk cannot be
/// sealed under this epoch. Truncating instead would reuse a `(DEK, nonce)`
/// pair. (A persist epoch terminator is not affected: its nonce counter is the
/// epoch's next chunk index, not its storage position.)
#[must_use]
pub fn av_inner_nonce(
    epoch_dek: &[u8; ciris_crypto::stream_seal::EPOCH_DEK_LEN],
    stream_id: &[u8; STREAM_ID_LEN],
    epoch: u64,
    chunk_seq: u64,
    last: bool,
) -> Option<[u8; AV_NONCE_LEN]> {
    let counter = ciris_crypto::stream_seal::counter_from_seq(chunk_seq)?;
    Some(ciris_crypto::stream_seal::stream_nonce(
        epoch_dek,
        &av_stream_id(stream_id),
        epoch,
        counter,
        last,
    ))
}

/// Derive the **outer** (per-RNS-Link transit) AES-GCM nonce (§10.5.8.3):
/// `SHA-256( b"CIRIS-AV-OUTER-V1" ‖ link_id ‖ link_seq_be8 )[0..12]`.
///
/// `link_id` is the transit link identifier (variable bytes, appended raw — the
/// fixed 8-byte `link_seq` suffix keeps the parse unambiguous for a fixed link).
#[must_use]
pub fn outer_nonce(link_id: &[u8], link_seq: u64) -> [u8; AV_NONCE_LEN] {
    sha256_12(&[AV_OUTER_DOMAIN, link_id, &link_seq.to_be_bytes()])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- KATs: the nonce derivations are byte-pinned (RC10 / §19.6 vectors).

    /// The inner seal is the STREAM nonce over the header's hex `stream_id`,
    /// byte-for-byte (CIRISConstitution#140). Golden derived independently in
    /// Python: DEK `[0x42;32]`, `stream_id` `[0x11;32]`, epoch 1, seq 0.
    #[test]
    fn av_inner_nonce_is_the_cc_5_3_3_1_stream_nonce() {
        let dek = [0x42u8; 32];
        let sid = [0x11u8; 32];
        assert_eq!(av_stream_id(&sid), "11".repeat(32));
        let n = av_inner_nonce(&dek, &sid, 1, 0, false).unwrap();
        assert_eq!(hex::encode(n), "03d118a1cbe0350000000000");
        assert_eq!(
            n,
            ciris_crypto::stream_seal::stream_nonce(&dek, &"11".repeat(32), 1, 0, false)
        );
        assert_eq!(av_inner_nonce(&dek, &sid, 1, 0, true).unwrap()[11], 0x01);
    }

    /// The KAT inverted: the retired construction must not be what seals.
    #[test]
    #[allow(deprecated)]
    fn the_retired_inner_nonce_is_not_the_seal() {
        let sid = [0x11u8; 32];
        let retired = inner_nonce(&sid, 1, 0);
        let mut h = Sha256::new();
        h.update(b"CIRIS-AV-INNER-V1");
        h.update(sid);
        h.update(1u64.to_be_bytes());
        h.update(0u64.to_be_bytes());
        assert_eq!(&retired[..], &h.finalize()[..12], "still identifiable");
        for dek in [[0x42u8; 32], [0u8; 32]] {
            assert_ne!(av_inner_nonce(&dek, &sid, 1, 0, false).unwrap(), retired);
        }
    }

    #[test]
    fn a_chunk_seq_past_the_stream_counter_is_refused() {
        let dek = [0x42u8; 32];
        let sid = [0u8; 32];
        assert!(av_inner_nonce(&dek, &sid, 1, u64::from(u32::MAX), true).is_some());
        assert!(av_inner_nonce(&dek, &sid, 1, u64::from(u32::MAX) + 1, false).is_none());
    }

    #[test]
    fn outer_nonce_kat() {
        let n = outer_nonce(b"link-7", 42);
        let mut h = Sha256::new();
        h.update(b"CIRIS-AV-OUTER-V1");
        h.update(b"link-7");
        h.update(42u64.to_be_bytes());
        assert_eq!(&n[..], &h.finalize()[..12]);
    }

    #[test]
    fn av_inner_nonce_unique_per_seq_epoch_and_stream() {
        let d = [0x42u8; 32];
        let s = [0u8; 32];
        let n = |sid: &[u8; 32], e, q| av_inner_nonce(&d, sid, e, q, false).unwrap();
        assert_ne!(n(&s, 1, 0), n(&s, 1, 1));
        assert_ne!(n(&s, 1, 0), n(&s, 2, 0));
        assert_ne!(n(&s, 1, 0), n(&s, 0, 1));
        assert_ne!(n(&s, 1, 0), n(&[1u8; 32], 1, 0));
    }

    #[test]
    fn header_parses_with_codec_block() {
        let mut buf = vec![0u8; 52 + 10];
        buf[0..32].copy_from_slice(&[0xAB; 32]);
        buf[32..40].copy_from_slice(&7u64.to_be_bytes());
        buf[40..48].copy_from_slice(&99u64.to_be_bytes());
        buf[48] = 0x02; // codec_id
        buf[49] = 1; // spatial
        buf[50] = 2; // temporal
        buf[51] = 3; // quality
        let (h, off) = parse_header(&buf).unwrap();
        assert_eq!(h.stream_id, [0xAB; 32]);
        assert_eq!(h.epoch, 7);
        assert_eq!(h.chunk_seq, 99);
        assert_eq!(h.codec_id, 0x02);
        assert_eq!(
            h.layer,
            ChunkLayer {
                spatial: 1,
                temporal: 2,
                quality: 3
            }
        );
        assert_eq!(off, 52);
    }

    #[test]
    fn v370_chunk_round_trips_as_codec_ff() {
        let mut buf = vec![0u8; 52];
        buf[48] = 0xFF;
        let (h, _) = parse_header(&buf).unwrap();
        assert_eq!(h.codec_id, 0xFF);
        assert_eq!(
            h.layer,
            ChunkLayer {
                spatial: 0,
                temporal: 0,
                quality: 0
            }
        );
    }

    #[test]
    fn short_header_rejected() {
        assert!(parse_header(&[0u8; 51]).is_err());
    }
}
