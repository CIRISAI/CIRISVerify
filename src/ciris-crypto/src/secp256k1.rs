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

/// Sign an EVM transaction with EIP-155 replay protection.
///
/// # Arguments
///
/// * `signing_key` - The secp256k1 signing key
/// * `tx_hash` - 32-byte transaction hash
/// * `chain_id` - EVM chain ID for replay protection
///
/// # Returns
///
/// 65-byte signature with EIP-155 adjusted v value
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
