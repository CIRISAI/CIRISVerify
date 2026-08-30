//! **Redactable commitments** — telling "redacted by authority" apart from
//! "tampered", cryptographically (CIRISVerify#241, CC 2.6 redaction clause).
//!
//! ## The problem
//!
//! A redaction rewrites bytes inside a signed envelope. Every verifying reader
//! then computes `sha256(canonical) != original_content_hash` and rejects the
//! row as tampered. There is no way to distinguish a lawful erasure from an
//! attack, and — as CIRISPersist established — the gate that bites is
//! **receiver-side**, so a storage-plane fix is inert: the redacting node
//! tolerates its own redaction and the first peer it replicates to refuses it.
//!
//! ## What CC ruled out, and why it matters
//!
//! The shape every drafter reaches for first — a signed *"I redacted this"*
//! marker — is a **normative dead end** (CC 2.6):
//!
//! > a signed redaction marker proves an authorized party changed the bytes —
//! > it does not prove that *only* the redacted parts changed.
//!
//! A compromised or coerced authority key becomes a licence to rewrite
//! arbitrary content while every reader reports the row as legitimately
//! redacted. **Integrity replaced by authority** — the AV-50 conflation
//! arriving quietly.
//!
//! ## Why salted digests, and not a plain Merkle tree over fields
//!
//! The obvious fix is to commit to per-member hashes and redact by replacing a
//! value with its hash. **For erasure that is broken**: an unsalted digest of a
//! low-entropy member — a boolean, a small enum, a status, a date — is
//! recoverable by dictionary search. The digest *is* the value, for anything
//! with a small domain, and erased content is exactly what an adversary wants.
//!
//! CC names the alternative directly: *"committing to the encoded disclosure
//! bytes directly (the SD-JWT/mDoc salted-digest shape, which needs no
//! canonicalization)"*. Each member gets a **fresh random salt**; the
//! commitment is `sha256(salt ‖ index ‖ member_bytes)`. Disclosure reveals
//! `(salt, bytes)`; redaction simply withholds it. The digest then reveals
//! nothing about the value regardless of its entropy.
//!
//! It also drops the canonicalization dependency: the commitment is over the
//! **encoded disclosure bytes**, so a JCS change cannot silently invalidate
//! previously-signed commitments.
//!
//! ## The two things committed, per CC's uniform-scheme exemption
//!
//! CC exempts *uniformly*-redactable schemes from declaring which members are
//! redactable (all of them are), **provided the signed object commits to member
//! count and index ordering**. Both are bound here:
//!
//! - **count** — a redaction may blank a member, never *drop* one. Without this
//!   a scheme still admits "redact by omission", where removing a member
//!   entirely is indistinguishable from it never having existed.
//! - **index** — each digest binds its own position, so members cannot be
//!   reordered or swapped between slots.
//!
//! ## What this module does NOT decide
//!
//! **Whether a redacted object keeps its kind or becomes a distinct one.** CC
//! left that open (constraint (d): *"the third option stays open"*). This is
//! the primitive; where it is applied is a policy decision that belongs to
//! whoever owns the objects being erased. Building the primitive
//! kind-agnostically is deliberate — it keeps the wire-break scope a separate
//! decision from the cryptography.
//!
//! It also does **not** replace the signature: a producer signs
//! [`crate::redactable::RedactableCommitment::root`], and the existing hybrid machinery is
//! unchanged.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain prefix for a member digest. Pinned; a change is a wire break.
pub const MEMBER_DOMAIN: &[u8] = b"ciris.redactable.member.v1\n";
/// Domain prefix for the root commitment.
pub const ROOT_DOMAIN: &[u8] = b"ciris.redactable.root.v1\n";
/// Salt length in bytes. 128 bits — the digest must not be brute-forceable for
/// a low-entropy member, which is the entire reason salts are here.
pub const SALT_LEN: usize = 16;

/// One member's disclosure: the salt and the bytes it commits to.
///
/// **Withholding a disclosure is what redaction is.** The commitment stays; the
/// value goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disclosure {
    /// 0-based position. Bound into the digest, so a member cannot be moved.
    pub index: u32,
    /// Per-member random salt.
    pub salt: Vec<u8>,
    /// The member's encoded bytes.
    pub bytes: Vec<u8>,
}

impl Disclosure {
    /// `sha256(MEMBER_DOMAIN ‖ u32_be(index) ‖ u32_be(salt.len) ‖ salt ‖ bytes)`.
    ///
    /// Lengths are prefixed so `(salt="ab", bytes="c")` and `(salt="a",
    /// bytes="bc")` cannot collide — the same length-prefix discipline the
    /// epoch-key and §19.0 preimages use.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(MEMBER_DOMAIN);
        h.update(self.index.to_be_bytes());
        h.update(
            u32::try_from(self.salt.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        h.update(&self.salt);
        h.update(&self.bytes);
        h.finalize().into()
    }
}

/// The commitment a producer signs, plus whichever disclosures survive.
///
/// `digests` is complete and fixed at signing time; `disclosures` shrinks as
/// members are redacted. A verifier recomputes each present disclosure's digest
/// and checks it against its slot — so a redaction is *visible* (a slot with no
/// disclosure) and a tamper is *detectable* (a slot whose disclosure does not
/// reproduce its digest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactableCommitment {
    /// Per-member digests, in index order. Length **is** the committed count.
    pub digests: Vec<[u8; 32]>,
    /// Surviving disclosures. Absent index = redacted.
    pub disclosures: Vec<Disclosure>,
}

/// Why a redactable commitment did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RedactionError {
    /// A disclosure names a slot outside the committed member set — including
    /// the "redact by omission" attempt of appending a member after signing.
    IndexOutOfRange {
        /// The offending index.
        index: u32,
        /// The committed member count.
        count: usize,
    },
    /// Two disclosures claim the same slot.
    DuplicateIndex {
        /// The duplicated index.
        index: u32,
    },
    /// A disclosure does not reproduce the digest committed for its slot —
    /// **tampering**, as distinct from redaction.
    DigestMismatch {
        /// Which slot.
        index: u32,
    },
    /// The recomputed root does not match the signed one — the member set's
    /// count or ordering changed.
    RootMismatch,
}

impl std::fmt::Display for RedactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IndexOutOfRange { index, count } => write!(
                f,
                "disclosure index {index} outside the committed member count {count}"
            ),
            Self::DuplicateIndex { index } => write!(f, "duplicate disclosure for index {index}"),
            Self::DigestMismatch { index } => write!(
                f,
                "member {index} does not reproduce its commitment — TAMPERED (a redaction \
                 withholds a disclosure; it does not alter one)"
            ),
            Self::RootMismatch => write!(f, "root mismatch — member count or ordering changed"),
        }
    }
}

impl std::error::Error for RedactionError {}

/// What a verifier learned about one member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberState {
    /// Disclosed and reproduces its commitment.
    Disclosed,
    /// **Redacted by authority** — the slot is committed, no disclosure is
    /// present, and the root still verifies. Distinct from tampering, and now
    /// distinguishable without trusting anyone's assertion.
    Redacted,
}

impl RedactableCommitment {
    /// The signed root: `sha256(ROOT_DOMAIN ‖ u32_be(count) ‖ digests…)`.
    ///
    /// The **count is inside the root**, which is what forecloses redaction by
    /// omission: dropping a member changes the root, so it is a detectable
    /// tamper rather than an invisible erasure.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(ROOT_DOMAIN);
        h.update(
            u32::try_from(self.digests.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        for d in &self.digests {
            h.update(d);
        }
        h.finalize().into()
    }

    /// Build a commitment over `members`, one fresh salt each.
    ///
    /// # Errors
    /// [`crate::error::VerifyError`] if the RNG refuses (SP 800-90B fail-secure
    /// latch — a predictable salt would defeat the point).
    pub fn commit(members: &[Vec<u8>]) -> Result<Self, crate::error::VerifyError> {
        let mut disclosures = Vec::with_capacity(members.len());
        for (i, m) in members.iter().enumerate() {
            let mut salt = vec![0u8; SALT_LEN];
            ciris_crypto::random::fill(&mut salt).map_err(|e| {
                crate::error::VerifyError::IntegrityError {
                    message: format!("salt draw refused: {e}"),
                }
            })?;
            disclosures.push(Disclosure {
                index: u32::try_from(i).unwrap_or(u32::MAX),
                salt,
                bytes: m.clone(),
            });
        }
        let digests = disclosures.iter().map(Disclosure::digest).collect();
        Ok(Self {
            digests,
            disclosures,
        })
    }

    /// Redact member `index` — withhold its disclosure, keep its commitment.
    ///
    /// Idempotent, and a no-op for an unknown index. The root is **unchanged**,
    /// which is the whole property: the producer's original signature still
    /// verifies over a redacted object.
    pub fn redact(&mut self, index: u32) {
        self.disclosures.retain(|d| d.index != index);
    }

    /// Verify against the **signed** root and report each member's state.
    ///
    /// Distinguishes the two cases that previously looked identical:
    /// a slot with no disclosure is [`MemberState::Redacted`]; a slot whose
    /// disclosure does not reproduce its digest is
    /// [`RedactionError::DigestMismatch`] — tampering.
    ///
    /// # Errors
    /// A [`RedactionError`] naming the first failure.
    pub fn verify(&self, signed_root: &[u8; 32]) -> Result<Vec<MemberState>, RedactionError> {
        if &self.root() != signed_root {
            return Err(RedactionError::RootMismatch);
        }
        let count = self.digests.len();
        let mut state = vec![MemberState::Redacted; count];
        let mut seen = vec![false; count];

        for d in &self.disclosures {
            let i = d.index as usize;
            if i >= count {
                return Err(RedactionError::IndexOutOfRange {
                    index: d.index,
                    count,
                });
            }
            if seen[i] {
                return Err(RedactionError::DuplicateIndex { index: d.index });
            }
            seen[i] = true;
            if d.digest() != self.digests[i] {
                return Err(RedactionError::DigestMismatch { index: d.index });
            }
            state[i] = MemberState::Disclosed;
        }
        Ok(state)
    }

    /// Indices with no surviving disclosure — what an operator needs to see
    /// *which* members were erased, not merely that some were.
    #[must_use]
    pub fn redacted_indices(&self) -> Vec<u32> {
        (0..self.digests.len() as u32)
            .filter(|i| !self.disclosures.iter().any(|d| d.index == *i))
            .collect()
    }
}

impl crate::classification::Classification for MemberState {
    /// **MEASUREMENT.** States what happened to a member. Whether a redacted
    /// member is acceptable is consumer policy — a reader may reasonably accept
    /// a redacted audit row and refuse a redacted key record.
    fn gating() -> crate::classification::Gating {
        crate::classification::Gating::Measurement
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members() -> Vec<Vec<u8>> {
        vec![
            b"alice@example.org".to_vec(),
            b"true".to_vec(), // low entropy — the case unsalted digests leak
            b"2026-08-03".to_vec(),
        ]
    }

    #[test]
    fn full_disclosure_verifies_and_reports_all_disclosed() {
        let c = RedactableCommitment::commit(&members()).unwrap();
        let root = c.root();
        assert_eq!(c.verify(&root).unwrap(), vec![MemberState::Disclosed; 3]);
        assert!(c.redacted_indices().is_empty());
    }

    /// **The property this module exists for.** After redaction the producer's
    /// ORIGINAL signed root still verifies, and the redacted member is reported
    /// as redacted rather than as tampering.
    #[test]
    fn redaction_preserves_the_signed_root() {
        let mut c = RedactableCommitment::commit(&members()).unwrap();
        let signed_root = c.root(); // what the producer signed
        c.redact(1);

        assert_eq!(c.root(), signed_root, "redaction must not move the root");
        let state = c.verify(&signed_root).unwrap();
        assert_eq!(state[0], MemberState::Disclosed);
        assert_eq!(state[1], MemberState::Redacted);
        assert_eq!(state[2], MemberState::Disclosed);
        assert_eq!(c.redacted_indices(), vec![1]);
    }

    /// Redaction and tampering are now DIFFERENT observables — the whole point.
    #[test]
    fn tampering_is_distinguishable_from_redaction() {
        let mut c = RedactableCommitment::commit(&members()).unwrap();
        let signed_root = c.root();
        c.disclosures[0].bytes = b"mallory@example.org".to_vec();

        assert_eq!(
            c.verify(&signed_root).unwrap_err(),
            RedactionError::DigestMismatch { index: 0 },
            "an altered disclosure is TAMPERING, not redaction"
        );
    }

    /// **Why salts.** A low-entropy member must not be recoverable from its
    /// commitment by dictionary search — the flaw in a plain unsalted
    /// Merkle-over-fields design.
    #[test]
    fn low_entropy_members_are_not_dictionary_recoverable() {
        let c = RedactableCommitment::commit(&[b"true".to_vec()]).unwrap();
        let committed = c.digests[0];

        // An attacker knowing the domain and the tiny value space still cannot
        // reproduce the digest without the salt.
        for guess in [&b"true"[..], b"false", b"1", b"0", b"yes", b"no"] {
            let unsalted = {
                let mut h = Sha256::new();
                h.update(MEMBER_DOMAIN);
                h.update(0u32.to_be_bytes());
                h.update(0u32.to_be_bytes());
                h.update(guess);
                let d: [u8; 32] = h.finalize().into();
                d
            };
            assert_ne!(unsalted, committed, "salt must defeat dictionary search");
        }
    }

    /// Two commitments over identical members differ — salts are fresh, so a
    /// digest cannot be correlated across objects.
    #[test]
    fn identical_members_commit_differently() {
        let a = RedactableCommitment::commit(&members()).unwrap();
        let b = RedactableCommitment::commit(&members()).unwrap();
        assert_ne!(a.digests, b.digests);
        assert_ne!(a.root(), b.root());
    }

    /// CC's count commitment: **redact by omission is foreclosed.** Dropping a
    /// member changes the root, so it is a detectable tamper.
    #[test]
    fn dropping_a_member_breaks_the_root() {
        let mut c = RedactableCommitment::commit(&members()).unwrap();
        let signed_root = c.root();
        c.digests.pop();
        c.disclosures.retain(|d| d.index != 2);
        assert_eq!(
            c.verify(&signed_root).unwrap_err(),
            RedactionError::RootMismatch
        );
    }

    /// CC's index commitment: members cannot be swapped between slots.
    #[test]
    fn reordering_members_is_detected() {
        let mut c = RedactableCommitment::commit(&members()).unwrap();
        let signed_root = c.root();
        c.digests.swap(0, 2);
        assert_eq!(
            c.verify(&signed_root).unwrap_err(),
            RedactionError::RootMismatch
        );
    }

    /// A disclosure moved to another slot fails, because the index is inside
    /// the digest.
    #[test]
    fn a_disclosure_cannot_be_moved_to_another_slot() {
        let mut c = RedactableCommitment::commit(&members()).unwrap();
        let signed_root = c.root();
        c.disclosures[0].index = 2;
        assert!(matches!(
            c.verify(&signed_root).unwrap_err(),
            RedactionError::DigestMismatch { .. } | RedactionError::DuplicateIndex { .. }
        ));
    }

    #[test]
    fn appended_disclosure_is_out_of_range() {
        let mut c = RedactableCommitment::commit(&members()).unwrap();
        let signed_root = c.root();
        c.disclosures.push(Disclosure {
            index: 9,
            salt: vec![0; SALT_LEN],
            bytes: b"injected".to_vec(),
        });
        assert_eq!(
            c.verify(&signed_root).unwrap_err(),
            RedactionError::IndexOutOfRange { index: 9, count: 3 }
        );
    }

    #[test]
    fn redaction_is_idempotent_and_tolerates_unknown_indices() {
        let mut c = RedactableCommitment::commit(&members()).unwrap();
        let signed_root = c.root();
        c.redact(1);
        c.redact(1);
        c.redact(99);
        assert_eq!(c.root(), signed_root);
        assert_eq!(c.redacted_indices(), vec![1]);
    }

    /// Length-prefixing: `(salt="ab", bytes="c")` must not collide with
    /// `(salt="a", bytes="bc")`.
    #[test]
    fn salt_and_bytes_boundaries_cannot_be_confused() {
        let a = Disclosure {
            index: 0,
            salt: b"ab".to_vec(),
            bytes: b"c".to_vec(),
        };
        let b = Disclosure {
            index: 0,
            salt: b"a".to_vec(),
            bytes: b"bc".to_vec(),
        };
        assert_ne!(a.digest(), b.digest());
    }

    /// Erasing everything still verifies — the object becomes a proof that N
    /// members existed and are gone, which is exactly what an erasure receipt
    /// should be.
    #[test]
    fn fully_redacted_object_still_verifies() {
        let mut c = RedactableCommitment::commit(&members()).unwrap();
        let signed_root = c.root();
        for i in 0..3 {
            c.redact(i);
        }
        assert_eq!(
            c.verify(&signed_root).unwrap(),
            vec![MemberState::Redacted; 3]
        );
        assert_eq!(c.redacted_indices(), vec![0, 1, 2]);
    }
}
