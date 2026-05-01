//
//  CIRISVerify-Bridging-Header.h
//
//  C FFI declarations for CIRISVerify hardware-rooted license verification.
//  Import this header in your Swift project to access the native library.
//
//  Generated from: src/ciris-verify-ffi/src/lib.rs (v1.6.4)
//  License: AGPL-3.0-or-later
//

#ifndef CIRIS_VERIFY_BRIDGING_HEADER_H
#define CIRIS_VERIFY_BRIDGING_HEADER_H

#include <stdint.h>
#include <stddef.h>

// Opaque handle to the CIRISVerify instance.
// Created by ciris_verify_init(), freed by ciris_verify_destroy().
typedef void *CirisVerifyHandle;

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Initialize CIRISVerify. Returns an opaque handle, or NULL on failure.
CirisVerifyHandle ciris_verify_init(void);

/// Destroy the handle and release all resources.
void ciris_verify_destroy(CirisVerifyHandle handle);

/// Free memory allocated by any CIRISVerify function. Safe to call with NULL.
void ciris_verify_free(void *data);

// ---------------------------------------------------------------------------
// License Status
// ---------------------------------------------------------------------------

/// Get license status. Request/response are JSON byte arrays.
/// Returns 0 on success, negative error code on failure.
int32_t ciris_verify_get_status(
    CirisVerifyHandle handle,
    const uint8_t *request_data, size_t request_len,
    uint8_t **response_data, size_t *response_len);

// ---------------------------------------------------------------------------
// Hardware Signing (Secure Enclave ECDSA P-256)
// ---------------------------------------------------------------------------

/// Sign data with the hardware-bound key.
int32_t ciris_verify_sign(
    CirisVerifyHandle handle,
    const uint8_t *data, size_t data_len,
    uint8_t **signature_data, size_t *signature_len);

/// Get the hardware-bound public key (SEC1 uncompressed, 65 bytes).
int32_t ciris_verify_get_public_key(
    CirisVerifyHandle handle,
    uint8_t **key_data, size_t *key_len,
    uint8_t **algorithm, size_t *algorithm_len);

/// Get the storage descriptor of the signer's identity material as JSON.
///
/// Output JSON has a "kind" discriminator and variant-specific fields:
///   {"kind":"hardware","hardware_type":"TpmFirmware","blob_path":"/path/to/key.tpm"}
///   {"kind":"software_file","path":"/var/lib/ciris/key.bin"}
///   {"kind":"software_os_keyring","backend":"keychain","scope":"unknown"}
///   {"kind":"in_memory"}
///
/// blob_path on "hardware" is informational — the wrapped envelope is
/// useless without the HSM, so its presence does NOT imply ephemerality
/// risk. software_file.path IS the path to apply ephemeral-storage
/// heuristics to (PoB §2.4 stability contract). Caller must free the
/// returned data with ciris_verify_free.
int32_t ciris_verify_signer_storage_descriptor(
    CirisVerifyHandle handle,
    uint8_t **descriptor_data, size_t *descriptor_len);

// ---------------------------------------------------------------------------
// Attestation
// ---------------------------------------------------------------------------

/// Export attestation proof (Ed25519 signature over challenge + metadata).
int32_t ciris_verify_export_attestation(
    CirisVerifyHandle handle,
    const uint8_t *challenge, size_t challenge_len,
    uint8_t **proof_data, size_t *proof_len);

/// Run unified attestation (Level 1-5). Request/result are JSON.
int32_t ciris_verify_run_attestation(
    CirisVerifyHandle handle,
    const uint8_t *request_json, size_t request_len,
    uint8_t **result_json, size_t *result_len);

/// Report device attestation failure (Play Integrity / App Attest token acquisition failed).
/// Call this when token acquisition fails before reaching the verify endpoint.
/// Caches the failure so run_attestation returns level_pending=false.
int32_t ciris_verify_device_attestation_failed(
    CirisVerifyHandle handle,
    const char *platform,
    int32_t error_code,
    const char *error_message);

// ---------------------------------------------------------------------------
// Ed25519 Key Management (Portal-issued keys)
// ---------------------------------------------------------------------------

/// Import a 32-byte Ed25519 private key (from Portal).
int32_t ciris_verify_import_key(
    CirisVerifyHandle handle,
    const uint8_t *key_data, size_t key_len);

/// Check if an Ed25519 key is loaded. Returns 1 if loaded, 0 if not.
int32_t ciris_verify_has_key(CirisVerifyHandle handle);

/// Delete the loaded Ed25519 key (from memory and persistent storage).
int32_t ciris_verify_delete_key(CirisVerifyHandle handle);

/// Sign data with the loaded Ed25519 key.
int32_t ciris_verify_sign_ed25519(
    CirisVerifyHandle handle,
    const uint8_t *data, size_t data_len,
    uint8_t **signature_data, size_t *signature_len);

/// Get the Ed25519 public key (32 bytes).
int32_t ciris_verify_get_ed25519_public_key(
    CirisVerifyHandle handle,
    uint8_t **key_data, size_t *key_len);

// ---------------------------------------------------------------------------
// Named Key Storage (v1.5.0)
// ---------------------------------------------------------------------------

/// Store a named Ed25519 key (32-byte seed).
int32_t ciris_verify_store_named_key(
    CirisVerifyHandle handle,
    const char *key_id,
    const uint8_t *seed, size_t seed_len);

/// Sign data with a named key.
int32_t ciris_verify_sign_with_named_key(
    CirisVerifyHandle handle,
    const char *key_id,
    const uint8_t *data, size_t data_len,
    uint8_t **signature_data, size_t *signature_len);

/// Check if a named key exists. Returns 1 if exists, 0 if not.
int32_t ciris_verify_has_named_key(
    CirisVerifyHandle handle,
    const char *key_id);

/// Delete a named key.
int32_t ciris_verify_delete_named_key(
    CirisVerifyHandle handle,
    const char *key_id);

/// Get the public key for a named key (32 bytes).
int32_t ciris_verify_get_named_key_public(
    CirisVerifyHandle handle,
    const char *key_id,
    uint8_t **pubkey_data, size_t *pubkey_len);

/// List all named keys. Returns JSON array of key IDs.
int32_t ciris_verify_list_named_keys(
    CirisVerifyHandle handle,
    char **json_out);

/// Free a string returned by ciris_verify_list_named_keys.
void ciris_verify_free_string(char *str);

// ---------------------------------------------------------------------------
// Named Key Encryption (v1.6.0)
// ---------------------------------------------------------------------------

/// Encrypt data with a named key using AES-256-GCM.
/// Key is derived via HKDF-SHA256 from the Ed25519 seed + context.
/// Output format: nonce (12 bytes) || ciphertext || auth_tag (16 bytes).
/// Returns 0 on success, negative error code on failure.
int32_t ciris_verify_encrypt_with_named_key(
    CirisVerifyHandle handle,
    const char *key_id,
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t **ciphertext_out, size_t *ciphertext_len_out);

/// Decrypt data that was encrypted with ciris_verify_encrypt_with_named_key.
/// Input format: nonce (12 bytes) || ciphertext || auth_tag (16 bytes).
/// Returns 0 on success, -11 (DecryptionFailed) on auth failure.
int32_t ciris_verify_decrypt_with_named_key(
    CirisVerifyHandle handle,
    const char *key_id,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t **plaintext_out, size_t *plaintext_len_out);

/// Derive a symmetric key from a named key using HKDF-SHA256.
/// The context string provides domain separation.
/// Returns a 32-byte key suitable for AES-256 or other symmetric algorithms.
int32_t ciris_verify_derive_symmetric_key(
    CirisVerifyHandle handle,
    const char *key_id,
    const char *context,
    uint8_t **key_out, size_t *key_len_out);

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/// Get the library version string (static, do not free).
const char *ciris_verify_version(void);

// ---------------------------------------------------------------------------
// Capability & Integrity Checks
// ---------------------------------------------------------------------------

/// Check if a capability is allowed at the given tier.
int32_t ciris_verify_check_capability(
    CirisVerifyHandle handle,
    const char *capability, const char *action,
    int32_t required_tier, int32_t *allowed);

/// Check agent file integrity against a JSON manifest.
int32_t ciris_verify_check_agent_integrity(
    CirisVerifyHandle handle,
    const uint8_t *manifest_data, size_t manifest_len,
    const char *agent_root, uint32_t spot_check_count,
    uint8_t **response_data, size_t *response_len);

/// Verify audit trail from SQLite DB and/or JSONL file.
int32_t ciris_verify_audit_trail(
    CirisVerifyHandle handle,
    const char *db_path, const char *jsonl_path,
    const char *portal_key_id,
    uint8_t **result_json, size_t *result_len);

/// Get Ed25519 signer diagnostics (JSON string).
int32_t ciris_verify_get_diagnostics(
    CirisVerifyHandle handle,
    uint8_t **diag_data, size_t *diag_len);

// ---------------------------------------------------------------------------
// Platform Conformance Testing (v1.6.2)
// ---------------------------------------------------------------------------

/// Run all platform conformance tests.
/// Results are logged to platform logging (logcat, oslog, stdout).
/// Returns the number of failed tests (0 = all passed).
int32_t ciris_verify_run_conformance_tests(CirisVerifyHandle handle);

#endif /* CIRIS_VERIFY_BRIDGING_HEADER_H */
