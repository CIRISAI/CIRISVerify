//! CC 5.3.3.1 — the STREAM chunk nonce: the **one** per-chunk AES-256-GCM
//! nonce for sealed streams, live and stored.
//!
//! ```text
//! nonce[12] = prefix[7] ‖ counter_be[4] ‖ last_flag[1]
//! prefix    = HKDF-SHA256(ikm = epoch_dek, salt = ∅,
//!                         info = b"ciris-stream-nonce/v1" ‖ utf8(stream_id) ‖ u64_be(epoch))[0..7]
//! last_flag = 0x01 on the epoch's final chunk, else 0x00
//! ```
//!
//! STREAM layout (Hoang–Reyhanitabar–Rogaway–Vizár, CRYPTO 2015), CEG's binding
//! profile of SFrame's per-sender nonce. **Nothing is transmitted**: every
//! holder of the epoch DEK recomputes the nonce to open a chunk, so the
//! encoding must be byte-identical across producer, substrate and consumer —
//! a BE/LE or tag disagreement is a GCM tag failure on every chunk, silently.
//!
//! ## Why this lives here
//!
//! The derivation is [`crate::kdf::hkdf_sha256`] with an empty salt. Pinning it
//! in the crate that owns that KDF gives persist, edge and verify **one**
//! implementation to call instead of three to keep identical. The golden vectors below were
//! derived independently (a from-scratch RFC 5869 HKDF in Python), not by
//! running this code.
//!
//! ## Not to be confused with
//!
//! [`crate::epoch_key::derive_epoch_stream_nonce`] — a **different** wire
//! fact: the CC 5.1 `CLM-epoch-keying` 24-byte XChaCha nonce, salted and with
//! a length-prefixed `stream_id`. The two are not interchangeable and neither
//! is a variant of the other.
//!
//! ## The call stream id
//!
//! [`call_stream_id`](crate::stream_seal::call_stream_id) is the CC 5.3.3.5 v3 derivation of the 32-byte stream id
//! from room, publisher and join nonce (length-prefixed since rc21). Known
//! answers: `tests/vectors/composite/stream_key_binding_v2_composite_v2.json`.
//!
//! ## The A/V inner seal
//!
//! The realtime A/V inner seal is this STREAM nonce, so live and stored streams
//! share one seal. The retired `SHA-256(b"CIRIS-AV-INNER-V1" ‖ stream_id ‖
//! epoch ‖ seq)[0..12]` construction is deprecated in `ciris-verify-core`'s
//! `av_chunk` and seals nothing.

#[allow(unused_imports)]
use crate::prelude::*;
use hkdf::Hkdf;
use sha2::Sha256;

/// HKDF `info` domain tag (CC 5.3.3.1).
pub const STREAM_NONCE_INFO_TAG: &[u8] = b"ciris-stream-nonce/v1";
/// Derived prefix length.
pub const STREAM_NONCE_PREFIX_LEN: usize = 7;
/// AES-GCM nonce length: `prefix[7] ‖ counter_be[4] ‖ last_flag[1]`.
pub const STREAM_NONCE_LEN: usize = 12;
/// Epoch-DEK length (AES-256 key).
pub const EPOCH_DEK_LEN: usize = 32;
/// `last_flag` on the final chunk of an epoch.
pub const LAST_CHUNK_FLAG: u8 = 0x01;
/// `last_flag` on every other chunk.
pub const NOT_LAST_CHUNK_FLAG: u8 = 0x00;

/// Derive the 12-byte STREAM nonce for one chunk (CC 5.3.3.1).
///
/// `counter` is the chunk's index within the epoch. It is a `u32` by
/// construction: CC caps it at 2³²−1 per epoch and requires an epoch roll
/// before wrap, so a caller holding a wider sequence number must refuse values
/// above `u32::MAX`, never truncate them — see [`counter_from_seq`].
///
/// Infallible: the HKDF expand length (7) is far below RFC 5869's cap.
#[must_use]
pub fn stream_nonce(
    epoch_dek: &[u8; EPOCH_DEK_LEN],
    stream_id: &str,
    epoch: u64,
    counter: u32,
    last: bool,
) -> [u8; STREAM_NONCE_LEN] {
    let sid = stream_id.as_bytes();
    let mut info = Vec::with_capacity(STREAM_NONCE_INFO_TAG.len() + sid.len() + 8);
    info.extend_from_slice(STREAM_NONCE_INFO_TAG);
    info.extend_from_slice(sid);
    info.extend_from_slice(&epoch.to_be_bytes());

    // Empty salt → RFC 5869's HashLen-zeros default, exactly as
    // `kdf::hkdf_sha256(dek, &[], …)` does; the DEK is the IKM.
    let mut prefix = [0u8; STREAM_NONCE_PREFIX_LEN];
    Hkdf::<Sha256>::new(None, epoch_dek)
        .expand(&info, &mut prefix)
        .expect("HKDF-SHA256 expand of 7 bytes cannot exceed the RFC 5869 limit");

    let mut nonce = [0u8; STREAM_NONCE_LEN];
    nonce[..STREAM_NONCE_PREFIX_LEN].copy_from_slice(&prefix);
    nonce[STREAM_NONCE_PREFIX_LEN..STREAM_NONCE_LEN - 1].copy_from_slice(&counter.to_be_bytes());
    nonce[STREAM_NONCE_LEN - 1] = if last {
        LAST_CHUNK_FLAG
    } else {
        NOT_LAST_CHUNK_FLAG
    };
    nonce
}

/// Narrow a wider chunk sequence number to the STREAM counter, **refusing**
/// rather than truncating. `None` above `u32::MAX`: CC 5.3.3.1 requires the
/// epoch to roll before the counter would wrap, so such a chunk cannot be
/// sealed under this epoch at all. Truncating would reuse a `(DEK, nonce)`
/// pair — the GCM-catastrophic case.
#[must_use]
pub fn counter_from_seq(seq: u64) -> Option<u32> {
    u32::try_from(seq).ok()
}

/// Read `(counter, last)` back out of a STREAM nonce; `None` if the flag byte
/// is neither value (a nonce this derivation never produces).
#[must_use]
pub fn parse_stream_nonce(nonce: &[u8; STREAM_NONCE_LEN]) -> Option<(u32, bool)> {
    let mut c = [0u8; 4];
    c.copy_from_slice(&nonce[STREAM_NONCE_PREFIX_LEN..STREAM_NONCE_LEN - 1]);
    let last = match nonce[STREAM_NONCE_LEN - 1] {
        LAST_CHUNK_FLAG => true,
        NOT_LAST_CHUNK_FLAG => false,
        _ => return None,
    };
    Some((u32::from_be_bytes(c), last))
}

/// Why a call stream id was not derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StreamIdError {
    /// `room` or `publisher` is not 1 to 1024 bytes of UTF-8 (CC 5.3.3.5).
    #[error("{0} is not 1 to 1024 bytes")]
    FieldLength(&'static str),
}

/// The domain label of the 32-byte call stream id (CC 5.3.3.5, rc21 815050d).
pub const CALL_STREAM_ID_LABEL: &[u8] = b"ciris-edge:call-stream:v3";
/// The largest `room` or `publisher` a StreamKeyBinding carries, in bytes.
pub const CALL_STREAM_FIELD_MAX: usize = 1024;

/// The 32-byte stream id of a call stream (CC 5.3.3.5), the `stream_id` a
/// StreamKeyBinding carries and `crate::stream_dek::av_stream_id` spells:
///
/// ```text
/// SHA-256("ciris-edge:call-stream:v3" ‖ u16_be(len room) ‖ room
///         ‖ u16_be(len publisher) ‖ publisher ‖ join_nonce[32])
/// ```
///
/// `room` is the community key id and `publisher` the publishing member's
/// federation key id (the member's key on the producing device, never a node
/// key). The length prefixes keep `("ab", "c")` and `("a", "bc")` apart, which
/// the v2 concatenation did not.
///
/// # Errors
///
/// [`StreamIdError::FieldLength`] when `room` or `publisher` is empty or over
/// [`CALL_STREAM_FIELD_MAX`] bytes.
pub fn call_stream_id(
    room: &str,
    publisher: &str,
    join_nonce: &[u8; 32],
) -> Result<[u8; 32], StreamIdError> {
    use sha2::Digest;
    let len = |f: &str, name: &'static str| match u16::try_from(f.len()) {
        Ok(n) if (1..=CALL_STREAM_FIELD_MAX).contains(&f.len()) => Ok(n.to_be_bytes()),
        _ => Err(StreamIdError::FieldLength(name)),
    };
    let (rl, pl) = (len(room, "room")?, len(publisher, "publisher")?);
    let mut h = Sha256::new();
    h.update(CALL_STREAM_ID_LABEL);
    h.update(rl);
    h.update(room.as_bytes());
    h.update(pl);
    h.update(publisher.as_bytes());
    h.update(join_nonce);
    Ok(h.finalize().into())
}

/// The domain label of a file delivery stream's id (CC 5.3.3.8, rc22 0774639).
pub const FILE_STREAM_ID_LABEL: &[u8] = b"ciris:file-stream:v1";
/// The text prefix of a file stream id.
pub const FILE_STREAM_ID_PREFIX: &str = "file-";

/// The id of a file delivery stream (CC 5.3.3.8), which commits to its
/// producer:
///
/// ```text
/// "file-" ‖ lower-hex(SHA-256("ciris:file-stream:v1" ‖ u16_be(len producer) ‖ producer ‖ nonce[32]))
/// ```
///
/// `producer` is the UTF-8 text of the opening member's identity reference.
/// The `(producer, nonce)` pair travels beside a stream head as submission
/// material, so a service holding no part of the stream can recompute the
/// id and check the head's author.
///
/// # Errors
///
/// [`StreamIdError::FieldLength`] when `producer` is empty or over
/// [`CALL_STREAM_FIELD_MAX`] bytes.
pub fn file_stream_id(producer: &str, nonce: &[u8; 32]) -> Result<String, StreamIdError> {
    use sha2::Digest;
    let n = match u16::try_from(producer.len()) {
        Ok(n) if (1..=CALL_STREAM_FIELD_MAX).contains(&producer.len()) => n,
        _ => return Err(StreamIdError::FieldLength("producer")),
    };
    let mut h = Sha256::new();
    h.update(FILE_STREAM_ID_LABEL);
    h.update(n.to_be_bytes());
    h.update(producer.as_bytes());
    h.update(nonce);
    let d: [u8; 32] = h.finalize().into();
    let mut out = String::with_capacity(FILE_STREAM_ID_PREFIX.len() + 64);
    out.push_str(FILE_STREAM_ID_PREFIX);
    for b in d {
        out.push(char::from(b"0123456789abcdef"[usize::from(b >> 4)]));
        out.push(char::from(b"0123456789abcdef"[usize::from(b & 15)]));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEK: [u8; 32] = [0x42; 32];

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Golden vectors derived independently: a from-scratch RFC 5869 HKDF in
    /// Python over the CC 5.3.3.1 info encoding, DEK = `[0x42; 32]`. If this
    /// fails, the Rust derivation no longer matches the spec as written —
    /// not merely its own earlier output.
    #[test]
    fn matches_the_independently_derived_cc_5_3_3_1_vectors() {
        let cases: [(&str, u64, u32, bool, &str); 5] = [
            ("cam-1", 7, 0x102, false, "334c5b834c1ddd0000010200"),
            ("cam-1", 7, 0x102, true, "334c5b834c1ddd0000010201"),
            ("cam-1", 8, 0x102, false, "58b01d9376176b0000010200"),
            ("", 0, 0, false, "4dee044e7c7b010000000000"),
            (
                "stream-\u{e9}",
                u64::MAX,
                u32::MAX,
                true,
                "1b86de86e1bfc4ffffffff01",
            ),
        ];
        for (sid, epoch, ctr, last, want) in cases {
            assert_eq!(
                hex(&stream_nonce(&DEK, sid, epoch, ctr, last)),
                want,
                "{sid:?} epoch={epoch} ctr={ctr} last={last}"
            );
        }
    }

    /// Same KDF call persist v53 makes (`kdf::hkdf_sha256(dek, &[], info, 7)`),
    /// so a divergence between the two crates' HKDF framing is a red here.
    #[cfg(feature = "kdf")]
    #[test]
    fn prefix_is_kdf_hkdf_sha256_with_empty_salt() {
        let mut info = STREAM_NONCE_INFO_TAG.to_vec();
        info.extend_from_slice(b"cam-1");
        info.extend_from_slice(&7u64.to_be_bytes());
        let p = crate::kdf::hkdf_sha256(&DEK, &[], &info, 7).unwrap();
        assert_eq!(&stream_nonce(&DEK, "cam-1", 7, 0, false)[..7], p.as_slice());
    }

    #[test]
    fn layout_counter_be_then_flag() {
        let n = stream_nonce(&DEK, "s", 3, 0x0102_0304, true);
        assert_eq!(&n[7..11], &[1, 2, 3, 4]);
        assert_eq!(n[11], LAST_CHUNK_FLAG);
        assert_eq!(parse_stream_nonce(&n), Some((0x0102_0304, true)));
        let mut bad = n;
        bad[11] = 0x02;
        assert_eq!(parse_stream_nonce(&bad), None);
    }

    /// Each input moves the nonce; the last flag alone does (truncation and
    /// append resistance), and epoch is not confusable with counter.
    #[test]
    fn every_input_is_bound() {
        let base = stream_nonce(&DEK, "s", 1, 0, false);
        assert_ne!(base, stream_nonce(&DEK, "s", 1, 0, true));
        assert_ne!(base, stream_nonce(&DEK, "s", 1, 1, false));
        assert_ne!(base, stream_nonce(&DEK, "s", 2, 0, false));
        assert_ne!(base, stream_nonce(&DEK, "t", 1, 0, false));
        assert_ne!(base, stream_nonce(&[0x43; 32], "s", 1, 0, false));
        assert_ne!(
            stream_nonce(&DEK, "s", 1, 0, false)[..7],
            stream_nonce(&DEK, "s", 0, 1, false)[..7]
        );
    }

    #[test]
    fn a_wide_sequence_number_is_refused_not_truncated() {
        assert_eq!(counter_from_seq(0), Some(0));
        assert_eq!(counter_from_seq(u64::from(u32::MAX)), Some(u32::MAX));
        assert_eq!(counter_from_seq(u64::from(u32::MAX) + 1), None);
        assert_eq!(counter_from_seq(u64::MAX), None);
    }
}
