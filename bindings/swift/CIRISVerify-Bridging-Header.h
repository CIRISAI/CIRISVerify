//
//  CIRISVerify-Bridging-Header.h
//
//  C FFI declarations for CIRISVerify hardware-rooted license verification.
//  Import this header in your Swift project to access the native library.
//
//  Generated from: src/ciris-verify-ffi/src/lib.rs (v0.6.16)
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

#endif /* CIRIS_VERIFY_BRIDGING_HEADER_H */
