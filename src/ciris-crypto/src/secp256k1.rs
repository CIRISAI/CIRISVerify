//! secp256k1 wallet signing support for EVM transactions.
//!
//! This module provides secp256k1 key derivation and signing for EVM-compatible
//! wallets. The wallet key is derived deterministically from the agent's Ed25519
//! root identity using HKDF.
//!
//! # Key Hierarchy
//!
//! ```text
//! Ed25519 Seed (32 bytes)
//!     │
//!     └── HKDF-SHA256(salt="CIRIS-wallet-v1", info="secp256k1-evm-signing-key")
//!             │
//!             └── secp256k1 Private Key (32 bytes)
//!                     │
//!                     └── secp256k1 Public Key (65 bytes uncompressed)
//!                             │
//!                             └── EVM Address (20 bytes via keccak256)
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use ciris_crypto::secp256k1::{derive_wallet_keypair, get_evm_address, sign_message};
//!
//! let ed25519_seed = [0u8; 32];
//! let (secret_key, public_key) = derive_wallet_keypair(&ed25519_seed);
//! let address = get_evm_address(&public_key);
//!
//! let message_hash = [0u8; 32];
//! let signature = sign_message(&secret_key, &message_hash);
//! ```

use hkdf::Hkdf;
use sha2::Sha256;
use sha3::{Digest, Keccak256};

#[cfg(feature = "secp256k1")]
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey};

/// HKDF salt for wallet key derivation.
const WALLET_HKDF_SALT: &[u8] = b"CIRIS-wallet-v1";

/// HKDF info for secp256k1 key derivation.
const SECP256K1_HKDF_INFO: &[u8] = b"secp256k1-evm-signing-key";

/// Derive a secp256k1 keypair from an Ed25519 seed.
///
/// The derivation is deterministic: the same Ed25519 seed will always produce
/// the same secp256k1 keypair.
///
/// # Arguments
///
/// * `ed25519_seed` - 32-byte Ed25519 seed (the root identity)
///
/// # Returns
///
/// A tuple of (SigningKey, VerifyingKey) for the derived wallet.
///
/// # Panics
///
/// Panics if the derived bytes are not a valid secp256k1 scalar (extremely rare).
#[cfg(feature = "secp256k1")]
pub fn derive_wallet_keypair(ed25519_seed: &[u8; 32]) -> (SigningKey, VerifyingKey) {
    let hkdf = Hkdf::<Sha256>::new(Some(WALLET_HKDF_SALT), ed25519_seed);
    let mut secp_seed = [0u8; 32];
    hkdf.expand(SECP256K1_HKDF_INFO, &mut secp_seed)
        .expect("HKDF expansion should not fail for 32 bytes");

    // Create signing key from derived seed
    // Note: k256 will reject invalid scalars, but HKDF output is essentially random
    // so the probability of hitting an invalid scalar is negligible (~2^-128)
    let signing_key =
        SigningKey::from_bytes((&secp_seed).into()).expect("HKDF output should be valid scalar");

    let verifying_key = *signing_key.verifying_key();

    // Zero out the seed
    secp_seed.iter_mut().for_each(|b| *b = 0);

    (signing_key, verifying_key)
}

/// Derive only the secp256k1 public key from an Ed25519 seed.
///
/// This is useful when you only need the public key (e.g., for address derivation)
/// without exposing the private key.
///
/// # Returns
///
/// 65-byte uncompressed public key (04 || x || y)
#[cfg(feature = "secp256k1")]
pub fn derive_secp256k1_public_key(ed25519_seed: &[u8; 32]) -> [u8; 65] {
    let (_, verifying_key) = derive_wallet_keypair(ed25519_seed);
    let encoded = verifying_key.to_encoded_point(false);
    let bytes = encoded.as_bytes();

    let mut result = [0u8; 65];
    result.copy_from_slice(bytes);
    result
}

/// Get the EVM address from a secp256k1 public key.
///
/// The address is derived by taking keccak256 of the public key (without the 04 prefix)
/// and taking the last 20 bytes.
///
/// # Arguments
///
/// * `public_key` - 65-byte uncompressed public key (04 || x || y)
///
/// # Returns
///
/// 20-byte EVM address
#[cfg(feature = "secp256k1")]
pub fn get_evm_address(public_key: &[u8; 65]) -> [u8; 20] {
    // Skip the 04 prefix and hash the 64-byte x||y coordinates
    let hash = Keccak256::digest(&public_key[1..]);

    // Take the last 20 bytes
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    address
}

/// Get the checksummed EVM address string.
///
/// Implements EIP-55 checksum encoding.
#[cfg(feature = "secp256k1")]
pub fn get_evm_address_checksummed(public_key: &[u8; 65]) -> String {
    let address = get_evm_address(public_key);
    let hex_addr = hex::encode(address);

    // Hash the lowercase hex address
    let hash = Keccak256::digest(hex_addr.as_bytes());

    // Apply checksum
    let mut result = String::with_capacity(42);
    result.push_str("0x");

    for (i, c) in hex_addr.chars().enumerate() {
        let hash_nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };

        if hash_nibble >= 8 {
            result.push(c.to_ascii_uppercase());
        } else {
            result.push(c);
        }
    }

    result
}

/// Sign a 32-byte message hash with the derived secp256k1 key.
///
/// # Arguments
///
/// * `signing_key` - The secp256k1 signing key
/// * `message_hash` - 32-byte hash to sign (typically keccak256)
///
/// # Returns
///
/// 65-byte signature in Ethereum format (r || s || v)
/// where v is the recovery id (0 or 1, not adjusted for EIP-155)
#[cfg(feature = "secp256k1")]
pub fn sign_message(signing_key: &SigningKey, message_hash: &[u8; 32]) -> [u8; 65] {
    use k256::ecdsa::signature::hazmat::PrehashSigner;

    // Sign with recovery - explicit type annotation for the trait
    let (signature, recovery_id) =
        PrehashSigner::<(K256Signature, RecoveryId)>::sign_prehash(signing_key, message_hash)
            .expect("signing should not fail");

    // Encode as r || s || v
    let mut result = [0u8; 65];
    let sig_bytes = signature.to_bytes();
    result[..64].copy_from_slice(&sig_bytes);
    result[64] = recovery_id.to_byte();

    result
}

// ===========================================================================
// CIRISVerify#207 item 2 — RLP + keccak INSIDE the boundary.
//
// Before this, `sign_evm_transaction` took only a pre-computed 32-byte hash,
// so CIRISAgent rebuilt RLP + keccak256 in Python **with a three-way
// third-party fallback** (pysha3 → pycryptodome → eth_hash) for real-money
// transactions: the bytes a signature commits to were produced by whichever
// hash library happened to import. These functions move that inside the
// crate that owns the key, so the preimage and the signature come from one
// implementation.
// ===========================================================================

/// keccak256 — the EVM's hash, exposed so a caller never has to source it
/// (CIRISVerify#207 item 2).
///
/// NB this is **Keccak-256, not SHA3-256**: they differ in padding, and a
/// caller who reaches for "sha3" in most languages gets the FIPS-202 variant
/// and a wrong address. Same primitive [`get_evm_address`] already uses.
#[cfg(feature = "secp256k1")]
#[must_use]
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(bytes));
    out
}

/// EIP-55 checksum an **arbitrary** 20-byte address.
///
/// [`get_evm_address_checksummed`] only accepts a public key, so a caller
/// could not checksum an address it does not hold the key for — which is
/// precisely the address that matters: the **recipient** of a transfer.
/// EIP-55 is the only cheap guard against a mistyped destination, and it was
/// unreachable for exactly the funds-moving case.
#[cfg(feature = "secp256k1")]
#[must_use]
pub fn checksum_address(address: &[u8; 20]) -> String {
    let hex_addr = hex::encode(address);
    let hash = Keccak256::digest(hex_addr.as_bytes());
    let mut result = String::with_capacity(42);
    result.push_str("0x");
    for (i, c) in hex_addr.chars().enumerate() {
        let nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };
        if nibble >= 8 {
            result.extend(c.to_uppercase());
        } else {
            result.push(c);
        }
    }
    result
}

/// RLP-encode a byte string (Ethereum Yellow Paper Appendix B).
#[cfg(feature = "secp256k1")]
fn rlp_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else if bytes.len() <= 55 {
        out.push(0x80 + bytes.len() as u8);
        out.extend_from_slice(bytes);
    } else {
        let len = bytes.len().to_be_bytes();
        let len = &len[len.iter().position(|b| *b != 0).unwrap_or(len.len() - 1)..];
        out.push(0xb7 + len.len() as u8);
        out.extend_from_slice(len);
        out.extend_from_slice(bytes);
    }
}

/// RLP-encode an integer as a **minimal** big-endian byte string.
///
/// Leading zeros are forbidden and zero is the *empty* string (`0x80`), not
/// `0x00` — a non-minimal encoding changes the preimage and therefore the
/// hash, so this is load-bearing rather than cosmetic.
#[cfg(feature = "secp256k1")]
fn rlp_uint(out: &mut Vec<u8>, n: u128) {
    let be = n.to_be_bytes();
    let first = be.iter().position(|b| *b != 0).unwrap_or(be.len());
    rlp_bytes(out, &be[first..]);
}

/// Wrap an already-encoded payload as an RLP list.
#[cfg(feature = "secp256k1")]
fn rlp_list(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 9);
    if payload.len() <= 55 {
        out.push(0xc0 + payload.len() as u8);
    } else {
        let len = payload.len().to_be_bytes();
        let len = &len[len.iter().position(|b| *b != 0).unwrap_or(len.len() - 1)..];
        out.push(0xf7 + len.len() as u8);
        out.extend_from_slice(len);
    }
    out.extend_from_slice(payload);
    out
}

/// The fields of a legacy (type-0) EVM transaction.
///
/// `to == None` is a contract **creation** — RLP-encoded as the empty string,
/// which is a different preimage from any address, so the distinction cannot
/// be flattened.
#[cfg(feature = "secp256k1")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LegacyTxFields<'a> {
    /// Sender nonce.
    pub nonce: u128,
    /// Gas price, wei.
    pub gas_price: u128,
    /// Gas limit.
    pub gas_limit: u128,
    /// Recipient; `None` for contract creation.
    pub to: Option<[u8; 20]>,
    /// Value, wei.
    pub value: u128,
    /// Call data.
    pub data: &'a [u8],
}

#[cfg(feature = "secp256k1")]
impl<'a> LegacyTxFields<'a> {
    /// Every field explicitly. `to: None` is contract creation.
    ///
    /// A constructor rather than a struct literal because the type is
    /// `#[non_exhaustive]` (CIRISVerify#274): a field added later must be an
    /// added argument here, never a compile break for every caller.
    #[must_use]
    pub fn new(
        nonce: u128,
        gas_price: u128,
        gas_limit: u128,
        to: Option<[u8; 20]>,
        value: u128,
        data: &'a [u8],
    ) -> Self {
        Self {
            nonce,
            gas_price,
            gas_limit,
            to,
            value,
            data,
        }
    }

    /// A transfer with no call data — the common case.
    #[must_use]
    pub fn transfer(
        nonce: u128,
        gas_price: u128,
        gas_limit: u128,
        to: [u8; 20],
        value: u128,
    ) -> Self {
        Self {
            nonce,
            gas_price,
            gas_limit,
            to: Some(to),
            value,
            data: &[],
        }
    }
}

/// The EIP-155 signing preimage: `rlp([nonce, gasPrice, gasLimit, to, value,
/// data, chainId, 0, 0])`.
///
/// Exposed (not just the hash) so a caller can diff bytes against another
/// implementation when they disagree — the thing that makes a preimage bug
/// findable instead of mysterious.
#[cfg(feature = "secp256k1")]
#[must_use]
pub fn legacy_tx_signing_bytes(tx: &LegacyTxFields<'_>, chain_id: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(128);
    rlp_uint(&mut p, tx.nonce);
    rlp_uint(&mut p, tx.gas_price);
    rlp_uint(&mut p, tx.gas_limit);
    match tx.to {
        Some(addr) => rlp_bytes(&mut p, &addr),
        None => rlp_bytes(&mut p, &[]), // contract creation
    }
    rlp_uint(&mut p, tx.value);
    rlp_bytes(&mut p, tx.data);
    rlp_uint(&mut p, u128::from(chain_id));
    rlp_uint(&mut p, 0);
    rlp_uint(&mut p, 0);
    rlp_list(&p)
}

/// `keccak256` of [`legacy_tx_signing_bytes`] — what the key actually signs.
#[cfg(feature = "secp256k1")]
#[must_use]
pub fn legacy_tx_signing_hash(tx: &LegacyTxFields<'_>, chain_id: u64) -> [u8; 32] {
    keccak256(&legacy_tx_signing_bytes(tx, chain_id))
}

/// A signed legacy transaction's signature, with the **real** EIP-155 `v`.
#[cfg(feature = "secp256k1")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LegacySignature {
    /// `r`, 32 bytes big-endian.
    pub r: [u8; 32],
    /// `s`, 32 bytes big-endian.
    pub s: [u8; 32],
    /// EIP-155 `v = recovery_id + chain_id * 2 + 35`.
    pub v: u64,
}

/// Sign a legacy transaction **from its fields** — RLP and keccak inside the
/// boundary, and a genuinely EIP-155-adjusted `v` (CIRISVerify#207 item 2).
///
/// Contrast [`sign_evm_transaction`], which takes a pre-computed hash and,
/// despite its name and its `chain_id` parameter, returns a *legacy*
/// `v = 27 + recovery_id`. Use this one for anything replay-protected.
#[cfg(feature = "secp256k1")]
#[must_use]
pub fn sign_legacy_transaction(
    signing_key: &SigningKey,
    tx: &LegacyTxFields<'_>,
    chain_id: u64,
) -> LegacySignature {
    let hash = legacy_tx_signing_hash(tx, chain_id);
    let raw = sign_message(signing_key, &hash);
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&raw[..32]);
    s.copy_from_slice(&raw[32..64]);
    LegacySignature {
        r,
        s,
        v: u64::from(raw[64]) + chain_id * 2 + 35,
    }
}

impl LegacySignature {
    /// The recovery id `v` encodes, or `None` if `v` is not an EIP-155 `v` for
    /// `chain_id`.
    ///
    /// Fail-closed on purpose: returning a guessed parity would recover a
    /// *different, valid-looking* sender address, which on a funds-moving path
    /// is worse than refusing.
    #[must_use]
    pub fn recovery_id(&self, chain_id: u64) -> Option<u8> {
        let base = chain_id.checked_mul(2)?.checked_add(35)?;
        match self.v.checked_sub(base)? {
            id @ 0..=1 => Some(id as u8),
            _ => None,
        }
    }
}

/// RLP-encode the **signed** transaction — the bytes you broadcast
/// (CIRISVerify#207 item 2).
///
/// `rlp([nonce, gas_price, gas_limit, to, value, data, v, r, s])`, where `v` is
/// the EIP-155 value. Without this a caller still needs its own RLP
/// implementation to send the transaction, which leaves the preimage in this
/// crate and the wire bytes somewhere else — half the reason the split was a
/// problem.
///
/// `r` and `s` are encoded as RLP integers, so their leading zero bytes are
/// stripped: a fixed 32-byte encoding produces a non-canonical transaction that
/// some nodes reject.
#[cfg(feature = "secp256k1")]
#[must_use]
pub fn encode_signed_legacy_tx(tx: &LegacyTxFields<'_>, sig: &LegacySignature) -> Vec<u8> {
    let mut payload = Vec::new();
    rlp_uint(&mut payload, tx.nonce);
    rlp_uint(&mut payload, tx.gas_price);
    rlp_uint(&mut payload, tx.gas_limit);
    match tx.to {
        Some(ref addr) => rlp_bytes(&mut payload, addr),
        None => rlp_bytes(&mut payload, &[]),
    }
    rlp_uint(&mut payload, tx.value);
    rlp_bytes(&mut payload, tx.data);
    rlp_uint_bytes(&mut payload, &sig.v.to_be_bytes());
    rlp_uint_bytes(&mut payload, &sig.r);
    rlp_uint_bytes(&mut payload, &sig.s);
    rlp_list(&payload)
}

/// The transaction hash (txid) of a signed transaction: `keccak256` of the
/// broadcast bytes.
#[cfg(feature = "secp256k1")]
#[must_use]
pub fn signed_legacy_tx_hash(tx: &LegacyTxFields<'_>, sig: &LegacySignature) -> [u8; 32] {
    keccak256(&encode_signed_legacy_tx(tx, sig))
}

/// RLP-encode a big-endian integer already in byte form, stripping leading
/// zeros so the encoding is canonical.
#[cfg(feature = "secp256k1")]
fn rlp_uint_bytes(out: &mut Vec<u8>, be: &[u8]) {
    let first = be.iter().position(|b| *b != 0).unwrap_or(be.len());
    rlp_bytes(out, &be[first..]);
}

/// Sign a pre-computed EVM transaction hash, returning a **legacy** `v`.
///
/// # This does NOT apply EIP-155 replay protection (CIRISVerify#207 item 2)
///
/// The doc here previously claimed "EIP-155 adjusted v value" and the
/// `chain_id` parameter suggests it, but the body ignores `chain_id` and
/// returns `v = 27 + recovery_id`. For funds-moving code that mismatch is how
/// a caller broadcasts a **replayable** transaction believing otherwise, so
/// it is now stated rather than buried in a body comment.
///
/// Use [`sign_legacy_transaction`] for replay protection: it takes the tx
/// *fields*, builds the EIP-155 preimage inside the boundary, and returns a
/// real `v = recovery_id + chain_id * 2 + 35`.
///
/// `chain_id` is retained (and ignored) only so existing callers still
/// compile; it is deliberately not removed in a patch release.
///
/// # Arguments
///
/// * `signing_key` - The secp256k1 signing key
/// * `tx_hash` - 32-byte hash the caller computed
/// * `_chain_id` - IGNORED; see above
///
/// # Returns
///
/// 65-byte signature, `v = 27 + recovery_id` (legacy, NOT EIP-155)
#[cfg(feature = "secp256k1")]
pub fn sign_evm_transaction(
    signing_key: &SigningKey,
    tx_hash: &[u8; 32],
    _chain_id: u64,
) -> [u8; 65] {
    let mut sig = sign_message(signing_key, tx_hash);

    // Adjust v for EIP-155: v = recovery_id + chain_id * 2 + 35
    // But we store only the low byte since chain_id adjustment is done at higher level
    // For compatibility, we use the standard Ethereum format:
    // v = 27 + recovery_id (legacy) or v = recovery_id (for EIP-1559)
    // The caller (wallet adapter) handles the full EIP-155 encoding

    // For now, use legacy format (v = 27 + recovery_id)
    sig[64] += 27;

    sig
}

/// Sign EIP-712 typed data.
///
/// # Arguments
///
/// * `signing_key` - The secp256k1 signing key
/// * `domain_hash` - 32-byte domain separator hash
/// * `message_hash` - 32-byte struct hash
///
/// # Returns
///
/// 65-byte signature over keccak256(0x1901 || domain_hash || message_hash)
#[cfg(feature = "secp256k1")]
pub fn sign_typed_data(
    signing_key: &SigningKey,
    domain_hash: &[u8; 32],
    message_hash: &[u8; 32],
) -> [u8; 65] {
    // EIP-712: hash = keccak256("\x19\x01" || domainSeparator || structHash)
    let mut data = Vec::with_capacity(66);
    data.push(0x19);
    data.push(0x01);
    data.extend_from_slice(domain_hash);
    data.extend_from_slice(message_hash);

    let hash = Keccak256::digest(&data);
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&hash);

    sign_message(signing_key, &hash_array)
}

/// Verify a signature and recover the signer's address.
///
/// # Arguments
///
/// * `message_hash` - 32-byte hash that was signed
/// * `signature` - 65-byte signature (r || s || v)
///
/// # Returns
///
/// The recovered 20-byte EVM address, or None if recovery fails
#[cfg(feature = "secp256k1")]
pub fn recover_address(message_hash: &[u8; 32], signature: &[u8; 65]) -> Option<[u8; 20]> {
    // Parse v value
    let v = signature[64];
    let recovery_id = if v >= 27 {
        v - 27 // Legacy format
    } else {
        v // Raw recovery id
    };

    let recovery_id = RecoveryId::from_byte(recovery_id)?;

    // Parse r || s
    let sig = K256Signature::from_slice(&signature[..64]).ok()?;

    // Recover public key
    let verifying_key = VerifyingKey::recover_from_prehash(message_hash, &sig, recovery_id).ok()?;

    // Get address
    let encoded = verifying_key.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    let mut pubkey = [0u8; 65];
    pubkey.copy_from_slice(bytes);

    Some(get_evm_address(&pubkey))
}

#[cfg(all(test, feature = "secp256k1"))]
mod tests {
    use super::*;

    #[test]
    fn test_derivation_is_deterministic() {
        let seed = [42u8; 32];

        let (sk1, pk1) = derive_wallet_keypair(&seed);
        let (sk2, pk2) = derive_wallet_keypair(&seed);

        assert_eq!(
            sk1.to_bytes().as_ref() as &[u8],
            sk2.to_bytes().as_ref() as &[u8],
            "Private keys should match"
        );
        assert_eq!(
            pk1.to_encoded_point(false).as_bytes(),
            pk2.to_encoded_point(false).as_bytes(),
            "Public keys should match"
        );
    }

    #[test]
    fn test_different_seeds_produce_different_keys() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let (_, pk1) = derive_wallet_keypair(&seed1);
        let (_, pk2) = derive_wallet_keypair(&seed2);

        assert_ne!(
            pk1.to_encoded_point(false).as_bytes(),
            pk2.to_encoded_point(false).as_bytes(),
            "Different seeds should produce different keys"
        );
    }

    #[test]
    fn test_public_key_format() {
        let seed = [0u8; 32];
        let pubkey = derive_secp256k1_public_key(&seed);

        // Uncompressed public key starts with 0x04
        assert_eq!(
            pubkey[0], 0x04,
            "Public key should be uncompressed (04 prefix)"
        );
        assert_eq!(
            pubkey.len(),
            65,
            "Uncompressed public key should be 65 bytes"
        );
    }

    #[test]
    fn test_evm_address_length() {
        let seed = [0u8; 32];
        let pubkey = derive_secp256k1_public_key(&seed);
        let address = get_evm_address(&pubkey);

        assert_eq!(address.len(), 20, "EVM address should be 20 bytes");
    }

    #[test]
    fn test_checksummed_address_format() {
        let seed = [0u8; 32];
        let pubkey = derive_secp256k1_public_key(&seed);
        let address = get_evm_address_checksummed(&pubkey);

        assert!(address.starts_with("0x"), "Address should start with 0x");
        assert_eq!(address.len(), 42, "Checksummed address should be 42 chars");
    }

    #[test]
    fn test_signature_format() {
        let seed = [0u8; 32];
        let (sk, _) = derive_wallet_keypair(&seed);

        let message_hash = [0u8; 32];
        let signature = sign_message(&sk, &message_hash);

        assert_eq!(
            signature.len(),
            65,
            "Signature should be 65 bytes (r || s || v)"
        );
        assert!(
            signature[64] <= 1,
            "Recovery id should be 0 or 1, got {}",
            signature[64]
        );
    }

    #[test]
    fn test_signature_recovery() {
        let seed = [0u8; 32];
        let (sk, _) = derive_wallet_keypair(&seed);
        let pubkey = derive_secp256k1_public_key(&seed);
        let expected_address = get_evm_address(&pubkey);

        let message_hash = [1u8; 32];
        let signature = sign_message(&sk, &message_hash);

        let recovered = recover_address(&message_hash, &signature);
        assert!(recovered.is_some(), "Recovery should succeed");
        assert_eq!(
            recovered.unwrap(),
            expected_address,
            "Recovered address should match"
        );
    }

    #[test]
    fn test_evm_transaction_signature() {
        let seed = [0u8; 32];
        let (sk, _) = derive_wallet_keypair(&seed);

        let tx_hash = [0u8; 32];
        let chain_id = 8453; // Base mainnet

        let signature = sign_evm_transaction(&sk, &tx_hash, chain_id);

        assert_eq!(signature.len(), 65);
        // v should be 27 or 28 in legacy format
        assert!(
            signature[64] == 27 || signature[64] == 28,
            "v should be 27 or 28, got {}",
            signature[64]
        );
    }

    #[test]
    fn test_eip712_typed_data_signature() {
        let seed = [0u8; 32];
        let (sk, _) = derive_wallet_keypair(&seed);
        let pubkey = derive_secp256k1_public_key(&seed);
        let expected_address = get_evm_address(&pubkey);

        let domain_hash = [1u8; 32];
        let message_hash = [2u8; 32];

        let signature = sign_typed_data(&sk, &domain_hash, &message_hash);

        // Recompute the hash that was signed
        let mut data = Vec::with_capacity(66);
        data.push(0x19);
        data.push(0x01);
        data.extend_from_slice(&domain_hash);
        data.extend_from_slice(&message_hash);
        let hash = Keccak256::digest(&data);
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&hash);

        // Recover and verify
        let recovered = recover_address(&hash_array, &signature);
        assert!(recovered.is_some(), "Recovery should succeed");
        assert_eq!(
            recovered.unwrap(),
            expected_address,
            "Recovered address should match"
        );
    }
}

/// CIRISVerify#207 item 2 — RLP + keccak inside the boundary, KAT-locked.
#[cfg(all(test, feature = "secp256k1"))]
mod tx_fields_tests {
    use super::*;

    /// The EIP-155 specification's own worked example.
    ///
    /// Transcribed from <https://eips.ethereum.org/EIPS/eip-155> and
    /// **independently re-derived in Python (pycryptodome keccak) from the
    /// Yellow Paper RLP rules** before this test was written — so the vector is
    /// the spec's, agreed by a second implementation, not an echo of this code.
    /// That matters more than usual here: these bytes are what a key commits to
    /// when it moves real money.
    const SPEC_SIGNING_BYTES: &str = "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080";
    const SPEC_SIGNING_HASH: &str =
        "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53";
    const SPEC_R: &str = "28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276";
    const SPEC_S: &str = "67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
    const SPEC_V: u64 = 37;

    /// The spec example's private key.
    fn spec_key() -> SigningKey {
        SigningKey::from_slice(
            &hex::decode("4646464646464646464646464646464646464646464646464646464646464646")
                .unwrap(),
        )
        .unwrap()
    }

    fn hex_to_20(h: &str) -> [u8; 20] {
        let mut a = [0u8; 20];
        a.copy_from_slice(&hex::decode(h).unwrap());
        a
    }

    fn spec_tx() -> LegacyTxFields<'static> {
        let mut to = [0u8; 20];
        to.copy_from_slice(&hex::decode("3535353535353535353535353535353535353535").unwrap());
        LegacyTxFields::transfer(9, 20_000_000_000, 21_000, to, 1_000_000_000_000_000_000)
    }

    #[test]
    fn eip155_spec_vector_preimage_and_hash() {
        let tx = spec_tx();
        assert_eq!(
            hex::encode(legacy_tx_signing_bytes(&tx, 1)),
            SPEC_SIGNING_BYTES,
            "RLP preimage"
        );
        assert_eq!(
            hex::encode(legacy_tx_signing_hash(&tx, 1)),
            SPEC_SIGNING_HASH,
            "signing hash"
        );
    }

    /// The full signature, including the **real** EIP-155 `v = 37` — the value
    /// `sign_evm_transaction` never produced despite its name.
    #[test]
    fn eip155_spec_vector_signature() {
        let sig = sign_legacy_transaction(&spec_key(), &spec_tx(), 1);
        assert_eq!(hex::encode(sig.r), SPEC_R, "r");
        assert_eq!(hex::encode(sig.s), SPEC_S, "s");
        assert_eq!(sig.v, SPEC_V, "EIP-155 v");
    }

    /// Chain id reaches the preimage AND the `v`: signing the same fields for a
    /// different chain must differ in both, or replay protection is theatre.
    #[test]
    fn chain_id_changes_both_the_hash_and_v() {
        let tx = spec_tx();
        assert_ne!(
            legacy_tx_signing_hash(&tx, 1),
            legacy_tx_signing_hash(&tx, 137)
        );
        let sk = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
        // Read the chain ids from bindings so the assertion states the EIP-155
        // formula rather than two folded constants.
        let (mainnet, polygon) = (1u64, 137u64);
        let a = sign_legacy_transaction(&sk, &tx, mainnet);
        let b = sign_legacy_transaction(&sk, &tx, polygon);
        assert_ne!(a.v, b.v);
        for (chain, sig) in [(mainnet, &a), (polygon, &b)] {
            let base = chain * 2 + 35;
            assert!(
                sig.v == base || sig.v == base + 1,
                "v must be chain-bound: chain {chain} gave {}",
                sig.v
            );
        }
    }

    /// RLP integer minimality: zero is the empty string `0x80`, never `0x00`,
    /// and no value carries leading zeros. A non-minimal encoding changes the
    /// preimage, so this is the encoder's correctness, not style.
    #[test]
    fn rlp_integers_are_minimal() {
        let mut out = Vec::new();
        rlp_uint(&mut out, 0);
        assert_eq!(out, vec![0x80], "zero must be the empty string");
        out.clear();
        rlp_uint(&mut out, 1);
        assert_eq!(out, vec![0x01], "small ints are themselves");
        out.clear();
        rlp_uint(&mut out, 0x7f);
        assert_eq!(out, vec![0x7f]);
        out.clear();
        rlp_uint(&mut out, 0x80);
        assert_eq!(out, vec![0x81, 0x80], "0x80 needs a length prefix");
        out.clear();
        rlp_uint(&mut out, 1_000_000_000_000_000_000);
        assert_eq!(
            out,
            vec![0x88, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]
        );
    }

    /// Contract creation (`to: None`) is the EMPTY string, a different preimage
    /// from any address — the distinction must not flatten.
    #[test]
    fn contract_creation_differs_from_any_recipient() {
        let create = LegacyTxFields::new(1, 1, 21_000, None, 0, &[]);
        let to_zero = LegacyTxFields::new(1, 1, 21_000, Some([0u8; 20]), 0, &[]);
        assert_ne!(
            legacy_tx_signing_hash(&create, 1),
            legacy_tx_signing_hash(&to_zero, 1),
            "creation must not equal a send to 0x00..00"
        );
    }

    /// keccak256 is Keccak-256, not FIPS-202 SHA3-256 — the mistake a caller
    /// sourcing "sha3" elsewhere makes, and it yields a wrong address.
    #[test]
    fn keccak256_is_keccak_not_sha3() {
        // Published: keccak256("") = c5d2460186f7...
        assert_eq!(
            hex::encode(keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        // FIPS-202 SHA3-256("") is a6ea... — must NOT be what we return.
        assert_ne!(
            hex::encode(keccak256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    /// EIP-55 over an arbitrary address — the recipient case the pubkey-only
    /// helper could not reach. Published vector from the EIP itself.
    #[test]
    fn eip55_checksums_an_arbitrary_address() {
        let mut a = [0u8; 20];
        a.copy_from_slice(&hex::decode("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap());
        assert_eq!(
            checksum_address(&a),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
    }

    /// The spec example's **broadcastable** bytes and its txid.
    ///
    /// Derived independently in Python (a separate RLP implementation) from the
    /// spec's published `r`/`s`/`v`, and matching the widely-published raw
    /// transaction and transaction hash for this example — so three sources
    /// agree before the fixture was pinned, rather than the fixture echoing
    /// this code's own output.
    const SPEC_SIGNED_TX: &str = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
    const SPEC_TXID: &str = "33469b22e9f636356c4160a87eb19df52b7412e8eac32a4a55ffe88ea8350788";

    #[test]
    fn eip155_spec_vector_signed_tx_and_txid() {
        let tx = spec_tx();
        let sig = sign_legacy_transaction(&spec_key(), &tx, 1);

        assert_eq!(
            hex::encode(encode_signed_legacy_tx(&tx, &sig)),
            SPEC_SIGNED_TX,
            "broadcast bytes diverge from the EIP-155 example"
        );
        assert_eq!(
            hex::encode(signed_legacy_tx_hash(&tx, &sig)),
            SPEC_TXID,
            "txid diverges from the EIP-155 example"
        );
    }

    #[test]
    fn signed_tx_strips_leading_zeros_from_r_and_s() {
        // A fixed 32-byte encoding of r/s yields a non-canonical transaction
        // that some nodes reject, so this is a wire property, not a nicety.
        let to = hex_to_20("3535353535353535353535353535353535353535");
        let tx = LegacyTxFields::transfer(1, 1, 21_000, to, 1);
        let sig = LegacySignature {
            r: {
                let mut r = [0u8; 32];
                r[31] = 7;
                r
            },
            s: {
                let mut s = [0u8; 32];
                s[31] = 9;
                s
            },
            v: 37,
        };
        let encoded = hex::encode(encode_signed_legacy_tx(&tx, &sig));
        assert!(
            encoded.ends_with("250709"),
            "r and s must encode as single bytes 0x07/0x09, got {encoded}"
        );
    }

    #[test]
    fn v_recovers_the_signer_for_both_parities() {
        // The KAT only exercises recovery_id 0 (the spec example happens to be
        // even). Walk nonces until each parity has been seen, so a flipped
        // parity cannot pass: r/s would still match a KAT while every node
        // recovered a different — and entirely plausible — sender.
        let key = spec_key();
        let expected = {
            let encoded = key.verifying_key().to_encoded_point(false);
            let mut pk = [0u8; 65];
            pk.copy_from_slice(encoded.as_bytes());
            get_evm_address(&pk)
        };
        let to = hex_to_20("3535353535353535353535353535353535353535");
        let mut seen = [false; 2];
        for nonce in 0..64u128 {
            let tx = LegacyTxFields::transfer(nonce, 1, 21_000, to, 1);
            let sig = sign_legacy_transaction(&key, &tx, 1);
            let id = sig
                .recovery_id(1)
                .expect("a signature we just produced must carry a valid recovery id");
            let mut raw = [0u8; 65];
            raw[..32].copy_from_slice(&sig.r);
            raw[32..64].copy_from_slice(&sig.s);
            raw[64] = id;
            assert_eq!(
                recover_address(&legacy_tx_signing_hash(&tx, 1), &raw),
                Some(expected),
                "nonce {nonce} recovers the wrong sender"
            );
            seen[id as usize] = true;
            if seen[0] && seen[1] {
                return;
            }
        }
        panic!("only saw recovery ids {seen:?} in 64 transactions — parity untested");
    }

    #[test]
    fn recovery_id_is_fail_closed_on_the_wrong_chain() {
        let key = spec_key();
        let to = hex_to_20("3535353535353535353535353535353535353535");
        let tx = LegacyTxFields::transfer(9, 1, 21_000, to, 1);
        let sig = sign_legacy_transaction(&key, &tx, 1);
        assert!(sig.recovery_id(1).is_some());
        // Asked about the wrong chain it must refuse, not guess: a guessed
        // parity recovers a different, valid-looking address.
        assert_eq!(sig.recovery_id(8453), None);
        assert_eq!(
            LegacySignature {
                r: [0; 32],
                s: [0; 32],
                v: 27
            }
            .recovery_id(1),
            None
        );
        assert_eq!(
            LegacySignature {
                r: [0; 32],
                s: [0; 32],
                v: 0
            }
            .recovery_id(u64::MAX),
            None,
            "chain_id * 2 + 35 must not overflow into a valid-looking answer"
        );
    }
}
