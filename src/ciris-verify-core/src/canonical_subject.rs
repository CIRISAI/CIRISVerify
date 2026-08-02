//! Canonical-hash **subject** codec (CC 2.3.2.1 `CLM-registry-canonical`).
//!
//! An attestation subject is either a **key** (a `key_id`) or a **content
//! hash**. Both are hex-ish strings, so an untagged 64-hex subject is
//! *format-indistinguishable* from a `key_id` — accepting one silently
//! conflates a content-hash subject with a key subject. CC 2.3.2.1 therefore
//! REQUIRES the tagged form and mandates that **bare hex be rejected**:
//!
//! ```text
//! canonical:sha256:<64 lowercase hex>
//! ```
//!
//! This module is the one blessed encoder/decoder for that tag, so producers
//! and admission gates cannot drift (CIRISVerify#201). CIRISPersist gates
//! `subject_key_ids` on [`classify_subject`]; CIRISConformance drives CC 2.3.2.1
//! against these functions.
//!
//! ## Pinned construction (⚠ verify-authored — cross-impl contract)
//!
//! ```text
//! preimage = utf8("{platform}:{entity_kind}:{id}")
//! subject  = "canonical:sha256:" ‖ lowercase_hex(sha256(preimage))
//! ```
//!
//! The preimage is the triple joined by `:` **exactly as given** — no
//! normalization, no case-folding, no trimming. `id` MAY itself contain colons;
//! `platform` and `entity_kind` MUST NOT (see [`canonical_subject_from_triple`],
//! which splits on the first two colons only). A change to this layout is a
//! cross-repo wire break.
//!
//! ## Strictness of the parser
//!
//! [`parse_canonical_subject`] accepts **only** the exact tagged form. It
//! rejects: bare hex, an uppercase or non-`sha256` algorithm, uppercase hex,
//! wrong digest length, extra/missing segments, and surrounding whitespace.
//! Fail-closed: anything not provably the pinned form is refused.

use sha2::{Digest, Sha256};

/// The subject tag prefix, including the algorithm and its trailing colon.
pub const CANONICAL_SUBJECT_PREFIX: &str = "canonical:sha256:";

/// The only hash algorithm CC 2.3.2.1 admits for a canonical subject.
pub const CANONICAL_SUBJECT_ALG: &str = "sha256";

/// Hex length of a SHA-256 digest.
const SHA256_HEX_LEN: usize = 64;

/// What a subject string is, once classified.
///
/// The whole point of the tag is that these are distinguishable; a gate should
/// admit only [`SubjectKind::CanonicalHash`] where a content-hash subject is
/// expected, and must never silently treat [`SubjectKind::BareHex`] as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectKind {
    /// A well-formed `canonical:sha256:<64 lower hex>` subject.
    CanonicalHash {
        /// The decoded 32-byte digest.
        digest: [u8; 32],
    },
    /// A bare hex string of SHA-256 length and no tag — **MUST be rejected**
    /// where a canonical subject is expected (CC 2.3.2.1): it is
    /// indistinguishable from a `key_id`.
    BareHex,
    /// Anything else — treated as an opaque `key_id`-shaped subject. This
    /// module does not validate `key_id`s; it only reports that the string is
    /// not a canonical-hash subject and not the ambiguous bare-hex case.
    Other,
}

/// Why a subject failed to parse as a canonical-hash subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectError {
    /// No `canonical:sha256:` prefix. Carries the classification so a caller
    /// can distinguish the security-relevant bare-hex case from a plain
    /// `key_id`.
    NotTagged {
        /// What the string looked like instead.
        kind: SubjectKind,
    },
    /// Tagged `canonical:` but with an algorithm other than `sha256`.
    UnsupportedAlgorithm {
        /// The algorithm segment as given.
        algorithm: String,
    },
    /// The digest segment is not exactly 64 characters.
    BadDigestLength {
        /// The length seen.
        len: usize,
    },
    /// The digest segment contains a non-`[0-9a-f]` character (uppercase hex is
    /// rejected — the encoding is lowercase-pinned so the subject string is
    /// canonical).
    NonLowercaseHex,
    /// A `platform` or `entity_kind` component contained a `:`, which would
    /// make the triple ambiguous to split.
    MalformedTriple {
        /// Human-readable detail.
        detail: String,
    },
}

impl std::fmt::Display for SubjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotTagged { kind } => match kind {
                SubjectKind::BareHex => write!(
                    f,
                    "bare hex subject is not admissible (CC 2.3.2.1): it is \
                     indistinguishable from a key_id — use canonical:sha256:<hex>"
                ),
                _ => write!(f, "subject is not tagged canonical:sha256:<hex>"),
            },
            Self::UnsupportedAlgorithm { algorithm } => write!(
                f,
                "canonical subject algorithm {algorithm:?} is not supported (only {CANONICAL_SUBJECT_ALG})"
            ),
            Self::BadDigestLength { len } => write!(
                f,
                "canonical subject digest must be {SHA256_HEX_LEN} hex chars, got {len}"
            ),
            Self::NonLowercaseHex => {
                write!(f, "canonical subject digest must be lowercase hex")
            },
            Self::MalformedTriple { detail } => write!(f, "malformed subject triple: {detail}"),
        }
    }
}

impl std::error::Error for SubjectError {}

/// Is `s` exactly 64 lowercase-hex characters (the ambiguous bare-hex shape)?
fn is_bare_sha256_hex(s: &str) -> bool {
    s.len() == SHA256_HEX_LEN && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// CC 2.3.2.1 production for `{platform}` / `{entity_kind}`:
/// `[a-z0-9][a-z0-9._-]*`. Reject-not-repair — no case folding, no trimming.
fn check_component(name: &'static str, v: &str) -> Result<(), SubjectError> {
    let mut chars = v.chars();
    let Some(first) = chars.next() else {
        return Err(SubjectError::MalformedTriple {
            detail: format!("{name} must be non-empty"),
        });
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return Err(SubjectError::MalformedTriple {
            detail: format!("{name} must start with [a-z0-9] (CC 2.3.2.1)"),
        });
    }
    for c in v.chars() {
        let ok = c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-');
        if !ok {
            return Err(SubjectError::MalformedTriple {
                detail: format!("{name} must match [a-z0-9][a-z0-9._-]* (CC 2.3.2.1)"),
            });
        }
    }
    Ok(())
}

/// CC 2.3.2.1 production for `{id}`: non-empty, no C0/C1 controls, no U+FEFF,
/// no leading/trailing `White_Space`. `id` MAY contain `:`.
fn check_id(id: &str) -> Result<(), SubjectError> {
    if id.is_empty() {
        return Err(SubjectError::MalformedTriple {
            detail: "id must be non-empty (CC 2.3.2.1)".to_string(),
        });
    }
    if id.starts_with(char::is_whitespace) || id.ends_with(char::is_whitespace) {
        return Err(SubjectError::MalformedTriple {
            detail: "id must not have leading/trailing whitespace — reject, never trim \
                     (CC 2.3.2.1)"
                .to_string(),
        });
    }
    for c in id.chars() {
        // C0 (U+0000..U+001F, U+007F) and C1 (U+0080..U+009F).
        if c.is_control() {
            return Err(SubjectError::MalformedTriple {
                detail: "id must not contain C0/C1 control characters (CC 2.3.2.1)".to_string(),
            });
        }
        if c == '\u{FEFF}' {
            return Err(SubjectError::MalformedTriple {
                detail: "id must not contain U+FEFF (CC 2.3.2.1)".to_string(),
            });
        }
    }
    Ok(())
}

/// Build the canonical-hash subject for `{platform}:{entity_kind}:{id}`.
///
/// See the module docs for the pinned preimage.
///
/// # CC 2.3.2.1 productions — **reject, never repair** (CIRISVerify#235)
///
/// - `platform` / `entity_kind` MUST match `[a-z0-9][a-z0-9._-]*` (which also
///   excludes `:`, keeping the triple splittable).
/// - `id` MUST be non-empty, contain **no C0/C1 control characters**, no
///   `U+FEFF`, and **no leading or trailing `White_Space`**.
///
/// Normalizing instead of rejecting would fork the digest between producers —
/// `("Discord", "user", "1234 ")` and `("discord", "user", "1234")` must not
/// silently become the same subject, so both are refused rather than repaired.
///
/// Rust `&str` is already guaranteed to hold Unicode scalar values, so the CC
/// "no surrogates" clause is enforced by the type system here. It is a real
/// clause for other implementations — a Python producer using `surrogatepass`
/// would fork the digest — so it is checked at the parse boundary where bytes
/// enter.
///
/// # Errors
/// [`SubjectError::MalformedTriple`] naming the first production violated.
pub fn canonical_subject(
    platform: &str,
    entity_kind: &str,
    id: &str,
) -> Result<String, SubjectError> {
    check_component("platform", platform)?;
    check_component("entity_kind", entity_kind)?;
    check_id(id)?;
    let preimage = format!("{platform}:{entity_kind}:{id}");
    Ok(format!(
        "{CANONICAL_SUBJECT_PREFIX}{}",
        hex::encode(Sha256::digest(preimage.as_bytes()))
    ))
}

/// Build the canonical-hash subject from an already-joined
/// `{platform}:{entity_kind}:{id}` triple, splitting on the **first two**
/// colons so `id` may itself contain colons.
///
/// # Errors
/// [`SubjectError::MalformedTriple`] if fewer than two colons are present.
pub fn canonical_subject_from_triple(triple: &str) -> Result<String, SubjectError> {
    let mut parts = triple.splitn(3, ':');
    let (Some(platform), Some(entity_kind), Some(id)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(SubjectError::MalformedTriple {
            detail: "expected {platform}:{entity_kind}:{id} (at least two ':')".to_string(),
        });
    };
    canonical_subject(platform, entity_kind, id)
}

/// Classify a subject string without erroring — the shape an admission gate
/// wants when it must distinguish "canonical hash" from the ambiguous bare hex
/// from an ordinary `key_id`.
#[must_use]
pub fn classify_subject(subject: &str) -> SubjectKind {
    match parse_canonical_subject(subject) {
        Ok(digest) => SubjectKind::CanonicalHash { digest },
        Err(SubjectError::NotTagged { kind }) => kind,
        // Tagged but malformed: not a valid canonical hash, and definitely not
        // a bare-hex/key_id shape either.
        Err(_) => SubjectKind::Other,
    }
}

/// Parse and validate a canonical-hash subject, returning the 32-byte digest.
///
/// Accepts **only** `canonical:sha256:<64 lowercase hex>` — see the module docs
/// for the full strictness list. This is the gate CC 2.3.2.1 requires.
///
/// # Errors
/// [`SubjectError`] naming why it was refused; [`SubjectError::NotTagged`]
/// carries a [`SubjectKind`] so a caller can single out the bare-hex case.
pub fn parse_canonical_subject(subject: &str) -> Result<[u8; 32], SubjectError> {
    let Some(rest) = subject.strip_prefix("canonical:") else {
        return Err(SubjectError::NotTagged {
            kind: if is_bare_sha256_hex(subject) {
                SubjectKind::BareHex
            } else {
                SubjectKind::Other
            },
        });
    };
    // Algorithm segment, up to the next colon.
    let Some((algorithm, digest_hex)) = rest.split_once(':') else {
        return Err(SubjectError::MalformedTriple {
            detail: "expected canonical:{alg}:{hex}".to_string(),
        });
    };
    if algorithm != CANONICAL_SUBJECT_ALG {
        return Err(SubjectError::UnsupportedAlgorithm {
            algorithm: algorithm.to_string(),
        });
    }
    if digest_hex.len() != SHA256_HEX_LEN {
        return Err(SubjectError::BadDigestLength {
            len: digest_hex.len(),
        });
    }
    // Lowercase-pinned: uppercase hex would give two spellings of one subject.
    if !digest_hex
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SubjectError::NonLowercaseHex);
    }
    let bytes = hex::decode(digest_hex).map_err(|_| SubjectError::NonLowercaseHex)?;
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes);
    Ok(digest)
}

/// Convenience gate: `Ok(())` iff `subject` is an admissible canonical-hash
/// subject. Wraps [`parse_canonical_subject`] for call sites that only need the
/// verdict.
///
/// # Errors
/// [`SubjectError`] — see [`parse_canonical_subject`].
pub fn require_canonical_subject(subject: &str) -> Result<(), SubjectError> {
    parse_canonical_subject(subject).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_pins_the_construction() {
        let s = canonical_subject("discord", "user", "12345").unwrap();
        assert!(s.starts_with(CANONICAL_SUBJECT_PREFIX));
        // Pinned golden: sha256("discord:user:12345"). Cross-impl contract —
        // persist/conformance reproduce this exact value.
        let expected = hex::encode(Sha256::digest(b"discord:user:12345"));
        assert_eq!(s, format!("canonical:sha256:{expected}"));
        let digest = parse_canonical_subject(&s).unwrap();
        assert_eq!(
            digest.to_vec(),
            Sha256::digest(b"discord:user:12345").to_vec()
        );
    }

    #[test]
    fn triple_splits_on_first_two_colons_only() {
        // `id` may contain colons; platform/entity_kind may not.
        let a = canonical_subject_from_triple("matrix:room:!abc:server.tld").unwrap();
        let b = canonical_subject("matrix", "room", "!abc:server.tld").unwrap();
        assert_eq!(a, b);
        assert!(matches!(
            canonical_subject_from_triple("onlyonecolon:x"),
            Err(SubjectError::MalformedTriple { .. })
        ));
    }

    /// THE CC 2.3.2.1 gate: a bare 64-hex subject is indistinguishable from a
    /// key_id and MUST be rejected — and reported as such, not as generic junk.
    #[test]
    fn bare_hex_is_rejected_and_identified() {
        let bare = hex::encode(Sha256::digest(b"anything"));
        assert_eq!(bare.len(), 64);
        let err = parse_canonical_subject(&bare).unwrap_err();
        assert_eq!(
            err,
            SubjectError::NotTagged {
                kind: SubjectKind::BareHex
            }
        );
        assert_eq!(classify_subject(&bare), SubjectKind::BareHex);
        assert!(require_canonical_subject(&bare).is_err());
        // And the message says why, so a gate can log something actionable.
        assert!(err.to_string().contains("indistinguishable from a key_id"));
    }

    #[test]
    fn non_sha256_algorithm_is_rejected() {
        let s = format!("canonical:md5:{}", "a".repeat(32));
        assert!(matches!(
            parse_canonical_subject(&s),
            Err(SubjectError::UnsupportedAlgorithm { .. })
        ));
        // Uppercase alg is not sha256 either — the tag is case-pinned.
        let s = format!("canonical:SHA256:{}", "a".repeat(64));
        assert!(matches!(
            parse_canonical_subject(&s),
            Err(SubjectError::UnsupportedAlgorithm { .. })
        ));
    }

    #[test]
    fn malformed_digests_are_rejected() {
        // Too short / too long.
        assert!(matches!(
            parse_canonical_subject("canonical:sha256:abcd"),
            Err(SubjectError::BadDigestLength { .. })
        ));
        assert!(matches!(
            parse_canonical_subject(&format!("canonical:sha256:{}", "a".repeat(65))),
            Err(SubjectError::BadDigestLength { .. })
        ));
        // Uppercase hex rejected — one canonical spelling per subject.
        assert!(matches!(
            parse_canonical_subject(&format!("canonical:sha256:{}", "A".repeat(64))),
            Err(SubjectError::NonLowercaseHex)
        ));
        // Non-hex.
        assert!(matches!(
            parse_canonical_subject(&format!("canonical:sha256:{}", "z".repeat(64))),
            Err(SubjectError::NonLowercaseHex)
        ));
        // Missing the algorithm segment entirely.
        assert!(matches!(
            parse_canonical_subject("canonical:deadbeef"),
            Err(SubjectError::MalformedTriple { .. })
        ));
        // Surrounding whitespace is not trimmed away into validity.
        let ok = canonical_subject("p", "k", "i").unwrap();
        assert!(parse_canonical_subject(&format!(" {ok}")).is_err());
        assert!(parse_canonical_subject(&format!("{ok} ")).is_err());
    }

    #[test]
    fn a_key_id_shaped_subject_classifies_as_other_not_bare_hex() {
        // Ordinary key_ids must not be mistaken for the ambiguous bare-hex case.
        assert_eq!(classify_subject("A1"), SubjectKind::Other);
        assert_eq!(classify_subject("ciris-canonical-1"), SubjectKind::Other);
        // 64 chars but not hex → Other, not BareHex.
        assert_eq!(classify_subject(&"g".repeat(64)), SubjectKind::Other);
    }

    #[test]
    fn distinct_triples_give_distinct_subjects() {
        // The colon join must not let two different triples collide.
        let a = canonical_subject("p", "k", "ab").unwrap();
        let b = canonical_subject("p", "k:a", "b");
        // entity_kind with ':' is refused outright, so the collision is
        // structurally impossible rather than merely unlikely.
        assert!(b.is_err());
        let c = canonical_subject("p", "k", "a:b").unwrap();
        assert_ne!(a, c);
    }
}

#[cfg(test)]
mod cc_2_3_2_1_reject_vectors {
    use super::*;

    /// CC 2.3.2.1 reject vectors (CIRISVerify#235). Before this, only the colon
    /// ban was enforced — `canonical_subject("Discord", "user", "1234 ")`
    /// succeeded, against two published reject vectors.
    ///
    /// **Reject, never repair.** Normalizing would fork the digest between
    /// implementations: a producer that trims or case-folds and one that does
    /// not would emit different subjects for the same logical entity.
    #[test]
    fn cc_reject_vectors_are_refused() {
        let cases: &[(&str, &str, &str, &str)] = &[
            // (platform, entity_kind, id, why)
            ("Discord", "user", "1234", "uppercase platform"),
            ("discord", "User", "1234", "uppercase entity_kind"),
            ("discord", "user", "1234 ", "trailing whitespace in id"),
            ("discord", "user", " 1234", "leading whitespace in id"),
            ("discord", "user", "", "empty id"),
            ("", "user", "1234", "empty platform"),
            ("discord", "", "1234", "empty entity_kind"),
            ("_discord", "user", "1234", "platform must start [a-z0-9]"),
            ("-discord", "user", "1234", "platform must start [a-z0-9]"),
            ("dis:cord", "user", "1234", "colon in platform"),
            ("dis cord", "user", "1234", "space in platform"),
            ("discord", "user", "12\u{0}34", "C0 control in id"),
            ("discord", "user", "12\u{9}34", "C0 tab in id"),
            ("discord", "user", "12\u{85}34", "C1 control in id"),
            ("discord", "user", "\u{FEFF}1234", "U+FEFF in id"),
        ];
        for (p, e, i, why) in cases {
            assert!(
                canonical_subject(p, e, i).is_err(),
                "must reject ({p:?}, {e:?}, {i:?}) — {why}"
            );
        }
    }

    /// The productions must not reject legitimate subjects — the accept side of
    /// the same rule.
    #[test]
    fn cc_accept_vectors_still_admit() {
        let cases: &[(&str, &str, &str)] = &[
            ("discord", "user", "1234"),
            ("ciris.ai", "agent", "datum"),
            ("matrix-org", "room", "!abc:example.org"), // `id` MAY contain colons
            ("x", "y", "z"),
            ("p0", "e_1", "id.with-dots_and-dashes"),
            ("discord", "user", "naïve-ünïcode-id"), // non-ASCII id is fine
        ];
        for (p, e, i) in cases {
            let s = canonical_subject(p, e, i)
                .unwrap_or_else(|err| panic!("must admit ({p:?}, {e:?}, {i:?}): {err}"));
            assert!(s.starts_with(CANONICAL_SUBJECT_PREFIX));
        }
    }

    /// The productions are a *gate*, not a transform: an admitted subject's
    /// digest is unchanged by this work (all pre-#235 golden vectors reproduce).
    #[test]
    fn admitted_digests_are_unchanged_by_the_productions() {
        // The pinned example from the module docs.
        let s = canonical_subject("discord", "user", "1234").unwrap();
        let expected = {
            use sha2::{Digest, Sha256};
            format!(
                "{CANONICAL_SUBJECT_PREFIX}{}",
                hex::encode(Sha256::digest(b"discord:user:1234"))
            )
        };
        assert_eq!(s, expected, "productions must not alter the preimage");
    }
}
