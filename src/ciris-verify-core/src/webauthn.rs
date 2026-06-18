//! WebAuthn / FIDO2 passkey **assertion** verification — the presence factor for
//! a user identity (CIRISVerify#80, the "authenticator app" path).
//!
//! A YubiKey PIV slot or a TPM/SE-sealed key *signs the federation owner-binding
//! directly*. A **passkey** (Google Authenticator, Microsoft Authenticator,
//! Apple/Android passkeys, a platform authenticator) is different: it signs
//! **WebAuthn's assertion format over a server challenge**, not the federation
//! preimage. So a passkey is a [`crate::webauthn`]-verified **presence / unlock
//! factor** ([`ciris_keyring::user_identity::FactorKind::Presence`]) — it proves
//! "the human with this credential is here, now" and gates access to the signing
//! key; it never produces the owner-binding signature itself.
//!
//! This module verifies a `navigator.credentials.get()` assertion per the
//! [WebAuthn Level 2 §7.2] verification steps that are checkable without
//! relying-party session state:
//!
//! 1. `clientDataJSON.type == "webauthn.get"`;
//! 2. `clientDataJSON.challenge` equals the (base64url-no-pad) challenge the
//!    relying party issued — constant-time compared;
//! 3. `authenticatorData[0..32]` (rpIdHash) equals `SHA-256(rp_id)`;
//! 4. the **User Present** flag is set (and **User Verified** if required);
//! 5. the signature verifies over `authenticatorData ‖ SHA-256(clientDataJSON)`
//!    with the credential public key — `ES256` (P-256, DER) or `EdDSA`
//!    (Ed25519), the two algorithms passkeys actually use.
//!
//! [WebAuthn Level 2 §7.2]: https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion

use base64::Engine;
use ciris_crypto::{ClassicalVerifier, Ed25519Verifier, P256Verifier};
use sha2::{Digest, Sha256};

/// The COSE signature algorithm a passkey assertion uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebauthnAlg {
    /// COSE alg -7: ECDSA P-256 + SHA-256, DER-encoded signature. The credential
    /// public key is **SEC1** uncompressed (`0x04 ‖ x ‖ y`, 65 bytes).
    Es256,
    /// COSE alg -8: Ed25519. The credential public key is the raw 32-byte key.
    EdDsa,
}

/// Why a passkey assertion failed verification. Coarse by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebauthnError {
    /// `clientDataJSON` was not valid JSON / missing fields.
    ClientDataParse,
    /// `type` was not `"webauthn.get"`.
    WrongType,
    /// `challenge` did not match the issued challenge.
    ChallengeMismatch,
    /// `clientDataJSON.origin` was not one of the expected origins — the
    /// anti-phishing check (distinct from `rpIdHash`; an attacker page on a
    /// different origin produces a valid-rpId assertion but the wrong origin).
    OriginMismatch,
    /// `authenticatorData` was shorter than the 37-byte minimum.
    MalformedAuthData,
    /// rpIdHash did not equal `SHA-256(rp_id)`.
    RpIdMismatch,
    /// The User-Present flag was not set.
    UserNotPresent,
    /// User verification was required but the User-Verified flag was not set.
    UserNotVerified,
    /// The assertion signature did not verify.
    SignatureInvalid,
}

/// A successful assertion's relying-party-relevant outputs. The caller MUST do
/// the **stateful** clone-detection check itself: compare [`Self::sign_count`]
/// against the value it last stored for this credential, and reject (possible
/// cloned authenticator) when the new count is **not greater** — unless both are
/// `0` (the authenticator does not implement a counter). `verify_assertion`
/// cannot do this — it has no stored state — so it returns the count instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssertionOutcome {
    /// The authenticator's signature counter (`authenticatorData[33..37]`, u32
    /// big-endian). Compare against the stored value for clone detection.
    pub sign_count: u32,
    /// Whether the User-Verified flag was set (biometric/PIN, not just a tap).
    pub user_verified: bool,
}

/// A passkey assertion to verify (a `navigator.credentials.get()` result).
pub struct Assertion<'a> {
    /// The COSE algorithm the credential signs with.
    pub alg: WebauthnAlg,
    /// The credential public key — SEC1 (65 bytes) for `Es256`, raw 32 bytes for
    /// `EdDsa`. (Pinned per credential when the passkey was registered.)
    pub credential_public_key: &'a [u8],
    /// The raw `authenticatorData` bytes.
    pub authenticator_data: &'a [u8],
    /// The raw `clientDataJSON` bytes.
    pub client_data_json: &'a [u8],
    /// The assertion signature — DER for `Es256`, 64 bytes for `EdDsa`.
    pub signature: &'a [u8],
}

// authenticatorData flag bits (WebAuthn §6.1).
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;

/// Verify a passkey assertion. `expected_challenge` is the **raw** challenge the
/// relying party issued (this function base64url-encodes it for the compare).
/// `require_user_verified` gates on the UV flag (set it for high-assurance
/// presence — e.g. the authenticator did a biometric/PIN, not just a tap).
///
/// Returns `Ok(())` only if every checkable step passes — the single admit
/// signal. The caller treats this as a *presence* proof, never as the
/// owner-binding signature.
///
/// # Errors
///
/// One of [`WebauthnError`].
pub fn verify_assertion(
    assertion: &Assertion<'_>,
    expected_challenge: &[u8],
    expected_rp_id: &str,
    expected_origins: &[&str],
    require_user_verified: bool,
) -> Result<AssertionOutcome, WebauthnError> {
    // 1. clientDataJSON type.
    let client: serde_json::Value = serde_json::from_slice(assertion.client_data_json)
        .map_err(|_| WebauthnError::ClientDataParse)?;
    if client.get("type").and_then(|t| t.as_str()) != Some("webauthn.get") {
        return Err(WebauthnError::WrongType);
    }
    // 2. challenge (constant-time — it gates auth).
    let got_challenge = client
        .get("challenge")
        .and_then(|c| c.as_str())
        .ok_or(WebauthnError::ClientDataParse)?;
    let want_challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expected_challenge);
    if !ciris_crypto::constant_time_eq(got_challenge.as_bytes(), want_challenge.as_bytes()) {
        return Err(WebauthnError::ChallengeMismatch);
    }
    // 3. origin (anti-phishing, exact match against the allowed set — the check
    //    rpIdHash alone does NOT cover; `webauthn-rs` does the same exact match).
    let got_origin = client
        .get("origin")
        .and_then(|o| o.as_str())
        .ok_or(WebauthnError::ClientDataParse)?;
    if !expected_origins.contains(&got_origin) {
        return Err(WebauthnError::OriginMismatch);
    }

    // 4+5. authenticatorData: rpIdHash + flags.
    let auth = assertion.authenticator_data;
    if auth.len() < 37 {
        return Err(WebauthnError::MalformedAuthData);
    }
    let rp_id_hash: [u8; 32] = Sha256::digest(expected_rp_id.as_bytes()).into();
    if !ciris_crypto::constant_time_eq(&auth[0..32], &rp_id_hash) {
        return Err(WebauthnError::RpIdMismatch);
    }
    let flags = auth[32];
    if flags & FLAG_USER_PRESENT == 0 {
        return Err(WebauthnError::UserNotPresent);
    }
    let user_verified = flags & FLAG_USER_VERIFIED != 0;
    if require_user_verified && !user_verified {
        return Err(WebauthnError::UserNotVerified);
    }
    // signCount (authenticatorData[33..37], u32 BE) — returned for the caller's
    // stateful clone-detection (this function holds no stored counter).
    let sign_count = u32::from_be_bytes(auth[33..37].try_into().unwrap());

    // 6. signature over authenticatorData ‖ SHA-256(clientDataJSON).
    let client_hash: [u8; 32] = Sha256::digest(assertion.client_data_json).into();
    let mut signed = Vec::with_capacity(auth.len() + 32);
    signed.extend_from_slice(auth);
    signed.extend_from_slice(&client_hash);

    let ok = match assertion.alg {
        WebauthnAlg::Es256 => P256Verifier::verify_webauthn_es256(
            assertion.credential_public_key,
            &signed,
            assertion.signature,
        )
        .unwrap_or(false),
        WebauthnAlg::EdDsa => {
            let v = Ed25519Verifier::new();
            matches!(
                v.verify(
                    assertion.credential_public_key,
                    &signed,
                    assertion.signature
                ),
                Ok(true)
            )
        },
    };
    if ok {
        Ok(AssertionOutcome {
            sign_count,
            user_verified,
        })
    } else {
        Err(WebauthnError::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::{ClassicalSigner, Ed25519Signer};

    const RP: &str = "ciris.ai";
    const ORIGIN: &str = "https://ciris.ai";
    fn origins() -> [&'static str; 1] {
        [ORIGIN]
    }

    /// Build a valid EdDSA passkey assertion for `challenge` / `rp_id`, with the
    /// given `origin`, UV flag, and signCount.
    fn make_eddsa_assertion(
        signer: &Ed25519Signer,
        challenge: &[u8],
        rp_id: &str,
        origin: &str,
        uv: bool,
        sign_count: u32,
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let client = serde_json::json!({
            "type": "webauthn.get",
            "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
            "origin": origin,
        });
        let client_data_json = serde_json::to_vec(&client).unwrap();
        let mut auth = Vec::new();
        auth.extend_from_slice(&<[u8; 32]>::from(Sha256::digest(rp_id.as_bytes())));
        auth.push(FLAG_USER_PRESENT | if uv { FLAG_USER_VERIFIED } else { 0 });
        auth.extend_from_slice(&sign_count.to_be_bytes());
        let client_hash: [u8; 32] = Sha256::digest(&client_data_json).into();
        let mut signed = auth.clone();
        signed.extend_from_slice(&client_hash);
        let sig = signer.sign(&signed).unwrap();
        (client_data_json, auth, sig)
    }

    fn assertion<'a>(pk: &'a [u8], cdj: &'a [u8], auth: &'a [u8], sig: &'a [u8]) -> Assertion<'a> {
        Assertion {
            alg: WebauthnAlg::EdDsa,
            credential_public_key: pk,
            authenticator_data: auth,
            client_data_json: cdj,
            signature: sig,
        }
    }

    #[test]
    fn valid_eddsa_passkey_assertion_verifies_and_returns_sign_count() {
        let signer = Ed25519Signer::random().unwrap();
        let pk = signer.public_key().unwrap();
        let challenge = b"server-issued-challenge-bytes";
        let (cdj, auth, sig) = make_eddsa_assertion(&signer, challenge, RP, ORIGIN, true, 7);
        let a = assertion(&pk, &cdj, &auth, &sig);
        let out = verify_assertion(&a, challenge, RP, &origins(), true).unwrap();
        assert_eq!(out.sign_count, 7, "signCount returned for clone detection");
        assert!(out.user_verified);
    }

    #[test]
    fn wrong_origin_rejected_anti_phishing() {
        // The attacker's page is on a different origin but presents a valid-rpId
        // assertion. rpIdHash passes; origin does not — the phishing catch.
        let signer = Ed25519Signer::random().unwrap();
        let pk = signer.public_key().unwrap();
        let (cdj, auth, sig) =
            make_eddsa_assertion(&signer, b"c", RP, "https://ciris.ai.evil.example", true, 1);
        let a = assertion(&pk, &cdj, &auth, &sig);
        assert_eq!(
            verify_assertion(&a, b"c", RP, &origins(), false),
            Err(WebauthnError::OriginMismatch)
        );
    }

    #[test]
    fn wrong_challenge_rejected() {
        let signer = Ed25519Signer::random().unwrap();
        let pk = signer.public_key().unwrap();
        let (cdj, auth, sig) = make_eddsa_assertion(&signer, b"real", RP, ORIGIN, false, 1);
        let a = assertion(&pk, &cdj, &auth, &sig);
        assert_eq!(
            verify_assertion(&a, b"attacker-challenge", RP, &origins(), false),
            Err(WebauthnError::ChallengeMismatch)
        );
    }

    #[test]
    fn wrong_rp_id_rejected() {
        let signer = Ed25519Signer::random().unwrap();
        let pk = signer.public_key().unwrap();
        let (cdj, auth, sig) = make_eddsa_assertion(&signer, b"c", RP, ORIGIN, false, 1);
        let a = assertion(&pk, &cdj, &auth, &sig);
        // origin allowed, but the expected rp_id differs → rpIdHash mismatch.
        assert_eq!(
            verify_assertion(&a, b"c", "evil.example", &origins(), false),
            Err(WebauthnError::RpIdMismatch)
        );
    }

    #[test]
    fn require_user_verified_rejects_tap_only() {
        let signer = Ed25519Signer::random().unwrap();
        let pk = signer.public_key().unwrap();
        // uv=false: user-present (tap) but not user-verified (no biometric/PIN).
        let (cdj, auth, sig) = make_eddsa_assertion(&signer, b"c", RP, ORIGIN, false, 1);
        let a = assertion(&pk, &cdj, &auth, &sig);
        assert_eq!(
            verify_assertion(&a, b"c", RP, &origins(), true),
            Err(WebauthnError::UserNotVerified)
        );
        // …but accepted when UV is not required.
        assert!(verify_assertion(&a, b"c", RP, &origins(), false).is_ok());
    }

    #[test]
    fn tampered_signature_rejected() {
        let signer = Ed25519Signer::random().unwrap();
        let pk = signer.public_key().unwrap();
        let (cdj, auth, mut sig) = make_eddsa_assertion(&signer, b"c", RP, ORIGIN, true, 1);
        sig[0] ^= 1;
        let a = assertion(&pk, &cdj, &auth, &sig);
        assert_eq!(
            verify_assertion(&a, b"c", RP, &origins(), true),
            Err(WebauthnError::SignatureInvalid)
        );
    }
}
