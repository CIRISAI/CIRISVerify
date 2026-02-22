//
//  CIRISVerify.swift
//
//  Swift wrapper for CIRISVerify hardware-rooted license verification.
//  Mirrors the 13 Android JNI methods for cross-platform consistency,
//  plus extended methods for capability checks, file integrity, and audit trail.
//
//  Usage:
//    let verify = try CIRISVerify()
//    let status = try verify.getStatus(deploymentId: "my-app", challengeNonce: nonce)
//    print(CIRISVerify.version())
//
//  Requirements:
//    - CIRISVerify.xcframework linked in Xcode project
//    - Security.framework (for Secure Enclave)
//    - Keychain access entitlement
//
//  License: AGPL-3.0-or-later
//

import Foundation

// MARK: - Error Types

/// Error codes from CIRISVerify FFI (matches CirisVerifyError in lib.rs).
public enum CIRISVerifyError: Error, CustomStringConvertible {
    case initializationFailed
    case invalidArgument
    case requestFailed
    case serializationError
    case internalError(code: Int32)
    case noKeyLoaded

    public var description: String {
        switch self {
        case .initializationFailed:
            return "CIRISVerify initialization failed"
        case .invalidArgument:
            return "Invalid argument"
        case .requestFailed:
            return "Request failed"
        case .serializationError:
            return "Serialization error"
        case .internalError(let code):
            return "Internal error (code: \(code))"
        case .noKeyLoaded:
            return "No Ed25519 key loaded"
        }
    }

    /// Map FFI error code to Swift error.
    static func from(code: Int32) -> CIRISVerifyError {
        switch code {
        case -1: return .invalidArgument
        case -2: return .initializationFailed
        case -3: return .requestFailed
        case -4: return .serializationError
        default: return .internalError(code: code)
        }
    }
}

// MARK: - CIRISVerify

/// Hardware-rooted license verification for the CIRIS ecosystem.
///
/// Provides cryptographic proof of license status to prevent capability spoofing.
/// Uses the Secure Enclave for hardware-bound ECDSA P-256 signing and supports
/// Ed25519 Portal-issued keys for attestation.
///
/// Thread Safety: This class is NOT thread-safe. If you need concurrent access,
/// serialize calls through a `DispatchQueue`.
public final class CIRISVerify {

    /// Opaque handle to the native CIRISVerify instance.
    private var handle: OpaquePointer?

    // MARK: - Lifecycle (mirrors nativeInit / nativeDestroy)

    /// Initialize CIRISVerify.
    ///
    /// Creates the license engine, initializes hardware signing (Secure Enclave),
    /// sets up logging via Apple Unified Logging (oslog), and attempts to load
    /// any persisted Ed25519 Portal key.
    ///
    /// - Throws: `CIRISVerifyError.initializationFailed` if native initialization fails.
    public init() throws {
        let rawHandle = ciris_verify_init()
        guard let h = rawHandle else {
            throw CIRISVerifyError.initializationFailed
        }
        self.handle = OpaquePointer(h)
    }

    deinit {
        if let handle = handle {
            ciris_verify_destroy(UnsafeMutableRawPointer(handle))
        }
        handle = nil
    }

    // MARK: - 1. getStatus (mirrors nativeGetStatus)

    /// Get license verification status.
    ///
    /// Performs multi-source validation (DNS US, DNS EU, HTTPS), checks license
    /// validity, and returns a comprehensive status response including mandatory
    /// disclosure text.
    ///
    /// - Parameters:
    ///   - deploymentId: Unique deployment identifier for this agent instance.
    ///   - challengeNonce: Random nonce (>= 32 bytes) for replay protection.
    /// - Returns: JSON-encoded `LicenseStatusResponse`.
    /// - Throws: `CIRISVerifyError` on failure.
    public func getStatus(deploymentId: String, challengeNonce: Data) throws -> Data {
        let request: [String: Any] = [
            "deployment_id": deploymentId,
            "challenge_nonce": Array(challengeNonce),
        ]
        let requestData = try JSONSerialization.data(withJSONObject: request)
        return try callFFIWithDataResult(requestData) { handle, inPtr, inLen, outPtr, outLen in
            ciris_verify_get_status(handle, inPtr, inLen, outPtr, outLen)
        }
    }

    // MARK: - 2. sign (mirrors nativeSign)

    /// Sign data with the hardware-bound key (Secure Enclave ECDSA P-256).
    ///
    /// - Parameter data: Data to sign.
    /// - Returns: DER-encoded ECDSA signature.
    /// - Throws: `CIRISVerifyError` on failure.
    public func sign(data: Data) throws -> Data {
        return try callFFIWithDataResult(data) { handle, inPtr, inLen, outPtr, outLen in
            ciris_verify_sign(handle, inPtr, inLen, outPtr, outLen)
        }
    }

    // MARK: - 3. getPublicKey (mirrors nativeGetPublicKey)

    /// Get the hardware-bound public key.
    ///
    /// - Returns: SEC1 uncompressed point (65 bytes: 0x04 || X || Y).
    /// - Throws: `CIRISVerifyError` on failure.
    public func getPublicKey() throws -> Data {
        guard let handle = handle else { throw CIRISVerifyError.initializationFailed }
        let rawHandle = UnsafeMutableRawPointer(handle)

        var keyPtr: UnsafeMutablePointer<UInt8>?
        var keyLen: Int = 0
        var algoPtr: UnsafeMutablePointer<UInt8>?
        var algoLen: Int = 0

        let result = ciris_verify_get_public_key(
            rawHandle, &keyPtr, &keyLen, &algoPtr, &algoLen)

        // Free algorithm string regardless of outcome
        defer {
            if let p = algoPtr { ciris_verify_free(p) }
        }

        guard result == 0 else { throw CIRISVerifyError.from(code: result) }
        guard let ptr = keyPtr else { throw CIRISVerifyError.internalError(code: -99) }
        defer { ciris_verify_free(ptr) }

        return Data(bytes: ptr, count: keyLen)
    }

    // MARK: - 4. exportAttestation (mirrors nativeExportAttestation)

    /// Export attestation proof.
    ///
    /// Signs the challenge with the Ed25519 key (Portal-issued or ephemeral)
    /// and includes platform attestation metadata.
    ///
    /// - Parameter challenge: Server-provided challenge (>= 32 bytes).
    /// - Returns: JSON-encoded attestation proof.
    /// - Throws: `CIRISVerifyError` on failure.
    public func exportAttestation(challenge: Data) throws -> Data {
        return try callFFIWithDataResult(challenge) { handle, inPtr, inLen, outPtr, outLen in
            ciris_verify_export_attestation(handle, inPtr, inLen, outPtr, outLen)
        }
    }

    // MARK: - 5. runAttestation (mirrors nativeRunAttestation)

    /// Run unified attestation (Levels 1-5).
    ///
    /// Performs comprehensive verification: source validation (DNS+HTTPS),
    /// file integrity (manifest + spot check), and audit trail verification.
    ///
    /// - Parameter requestJSON: JSON-encoded `FullAttestationRequest`.
    /// - Returns: JSON-encoded `FullAttestationResult` with level (0-5).
    /// - Throws: `CIRISVerifyError` on failure.
    public func runAttestation(requestJSON: Data) throws -> Data {
        return try callFFIWithDataResult(requestJSON) { handle, inPtr, inLen, outPtr, outLen in
            ciris_verify_run_attestation(handle, inPtr, inLen, outPtr, outLen)
        }
    }

    // MARK: - 6. importKey (mirrors nativeImportKey)

    /// Import a 32-byte Ed25519 private key from Portal.
    ///
    /// The key is persisted to disk for future sessions.
    ///
    /// - Parameter keyBytes: 32-byte Ed25519 seed.
    /// - Throws: `CIRISVerifyError` on failure.
    public func importKey(keyBytes: Data) throws {
        guard let handle = handle else { throw CIRISVerifyError.initializationFailed }
        let rawHandle = UnsafeMutableRawPointer(handle)

        let result = keyBytes.withUnsafeBytes { buffer -> Int32 in
            guard let baseAddr = buffer.baseAddress else { return -1 }
            return ciris_verify_import_key(
                rawHandle,
                baseAddr.assumingMemoryBound(to: UInt8.self),
                buffer.count)
        }

        guard result == 0 else { throw CIRISVerifyError.from(code: result) }
    }

    // MARK: - 7. hasKey (mirrors nativeHasKey)

    /// Check if an Ed25519 key is loaded.
    ///
    /// - Returns: `true` if a Portal key is loaded, `false` otherwise.
    public func hasKey() -> Bool {
        guard let handle = handle else { return false }
        return ciris_verify_has_key(UnsafeMutableRawPointer(handle)) == 1
    }

    // MARK: - 8. deleteKey (mirrors nativeDeleteKey)

    /// Delete the loaded Ed25519 key from memory and persistent storage.
    ///
    /// - Throws: `CIRISVerifyError` on failure.
    public func deleteKey() throws {
        guard let handle = handle else { throw CIRISVerifyError.initializationFailed }
        let result = ciris_verify_delete_key(UnsafeMutableRawPointer(handle))
        guard result == 0 else { throw CIRISVerifyError.from(code: result) }
    }

    // MARK: - 9. signEd25519 (mirrors nativeSignEd25519)

    /// Sign data with the loaded Ed25519 key.
    ///
    /// - Parameter data: Data to sign.
    /// - Returns: 64-byte Ed25519 signature.
    /// - Throws: `CIRISVerifyError` on failure.
    public func signEd25519(data: Data) throws -> Data {
        return try callFFIWithDataResult(data) { handle, inPtr, inLen, outPtr, outLen in
            ciris_verify_sign_ed25519(handle, inPtr, inLen, outPtr, outLen)
        }
    }

    // MARK: - 10. getEd25519PublicKey (mirrors nativeGetEd25519PublicKey)

    /// Get the Ed25519 public key (32 bytes).
    ///
    /// - Returns: 32-byte Ed25519 public key.
    /// - Throws: `CIRISVerifyError` on failure.
    public func getEd25519PublicKey() throws -> Data {
        guard let handle = handle else { throw CIRISVerifyError.initializationFailed }
        let rawHandle = UnsafeMutableRawPointer(handle)

        var keyPtr: UnsafeMutablePointer<UInt8>?
        var keyLen: Int = 0

        let result = ciris_verify_get_ed25519_public_key(rawHandle, &keyPtr, &keyLen)
        guard result == 0 else { throw CIRISVerifyError.from(code: result) }
        guard let ptr = keyPtr else { throw CIRISVerifyError.internalError(code: -99) }
        defer { ciris_verify_free(ptr) }

        return Data(bytes: ptr, count: keyLen)
    }

    // MARK: - 11. version (mirrors nativeVersion, static)

    /// Get the library version string.
    ///
    /// - Returns: Version string (e.g. "0.6.16").
    public static func version() -> String {
        guard let cStr = ciris_verify_version() else { return "unknown" }
        return String(cString: cStr)
    }

    // MARK: - Extended Methods (not in Android JNI)

    /// Check if a capability is allowed at the given tier.
    ///
    /// - Parameters:
    ///   - capability: Capability name (e.g. "medical_advice").
    ///   - action: Action name (e.g. "provide").
    ///   - requiredTier: Minimum tier required (0=community, 1=standard, 2=professional).
    /// - Returns: `true` if the capability is allowed.
    /// - Throws: `CIRISVerifyError` on failure.
    public func checkCapability(_ capability: String, action: String, requiredTier: Int32) throws -> Bool {
        guard let handle = handle else { throw CIRISVerifyError.initializationFailed }
        let rawHandle = UnsafeMutableRawPointer(handle)

        var allowed: Int32 = 0
        let result = capability.withCString { capPtr in
            action.withCString { actPtr in
                ciris_verify_check_capability(rawHandle, capPtr, actPtr, requiredTier, &allowed)
            }
        }

        guard result == 0 else { throw CIRISVerifyError.from(code: result) }
        return allowed == 1
    }

    /// Check agent file integrity against a JSON manifest.
    ///
    /// - Parameters:
    ///   - manifest: JSON-encoded file manifest.
    ///   - agentRoot: Path to the agent's root directory.
    ///   - spotCheckCount: Number of files to spot-check (0 for full check).
    /// - Returns: JSON-encoded integrity check result.
    /// - Throws: `CIRISVerifyError` on failure.
    public func checkAgentIntegrity(manifest: Data, agentRoot: String, spotCheckCount: UInt32) throws -> Data {
        guard let handle = handle else { throw CIRISVerifyError.initializationFailed }
        let rawHandle = UnsafeMutableRawPointer(handle)

        var responsePtr: UnsafeMutablePointer<UInt8>?
        var responseLen: Int = 0

        let result = manifest.withUnsafeBytes { manifestBuffer -> Int32 in
            guard let manifestBase = manifestBuffer.baseAddress else { return -1 }
            return agentRoot.withCString { rootPtr in
                ciris_verify_check_agent_integrity(
                    rawHandle,
                    manifestBase.assumingMemoryBound(to: UInt8.self),
                    manifestBuffer.count,
                    rootPtr,
                    spotCheckCount,
                    &responsePtr,
                    &responseLen)
            }
        }

        guard result == 0 else { throw CIRISVerifyError.from(code: result) }
        guard let ptr = responsePtr else { throw CIRISVerifyError.internalError(code: -99) }
        defer { ciris_verify_free(ptr) }

        return Data(bytes: ptr, count: responseLen)
    }

    /// Verify audit trail from SQLite database and/or JSONL file.
    ///
    /// - Parameters:
    ///   - dbPath: Path to ciris_audit.db SQLite database.
    ///   - jsonlPath: Path to audit_logs.jsonl (optional).
    ///   - portalKeyId: Expected Portal key ID for signature verification (optional).
    /// - Returns: JSON-encoded `AuditVerificationResult`.
    /// - Throws: `CIRISVerifyError` on failure.
    public func verifyAuditTrail(dbPath: String, jsonlPath: String? = nil, portalKeyId: String? = nil) throws -> Data {
        guard let handle = handle else { throw CIRISVerifyError.initializationFailed }
        let rawHandle = UnsafeMutableRawPointer(handle)

        var resultPtr: UnsafeMutablePointer<UInt8>?
        var resultLen: Int = 0

        let result = dbPath.withCString { dbPtr -> Int32 in
            let jsonlPtr = jsonlPath.flatMap { $0.withCString { UnsafePointer($0) } }
            let portalPtr = portalKeyId.flatMap { $0.withCString { UnsafePointer($0) } }
            return ciris_verify_audit_trail(
                rawHandle, dbPtr, jsonlPtr, portalPtr,
                &resultPtr, &resultLen)
        }

        guard result == 0 else { throw CIRISVerifyError.from(code: result) }
        guard let ptr = resultPtr else { throw CIRISVerifyError.internalError(code: -99) }
        defer { ciris_verify_free(ptr) }

        return Data(bytes: ptr, count: resultLen)
    }

    /// Get Ed25519 signer diagnostics.
    ///
    /// - Returns: Diagnostics string with key persistence status and storage paths.
    /// - Throws: `CIRISVerifyError` on failure.
    public func getDiagnostics() throws -> String {
        guard let handle = handle else { throw CIRISVerifyError.initializationFailed }
        let rawHandle = UnsafeMutableRawPointer(handle)

        var diagPtr: UnsafeMutablePointer<UInt8>?
        var diagLen: Int = 0

        let result = ciris_verify_get_diagnostics(rawHandle, &diagPtr, &diagLen)
        guard result == 0 else { throw CIRISVerifyError.from(code: result) }
        guard let ptr = diagPtr else { throw CIRISVerifyError.internalError(code: -99) }
        defer { ciris_verify_free(ptr) }

        return String(bytes: Data(bytes: ptr, count: diagLen), encoding: .utf8) ?? ""
    }

    // MARK: - Private Helpers

    /// Common pattern for FFI calls that take input data and return output data.
    ///
    /// Handles:
    /// - Null handle check
    /// - Input data pointer extraction via `withUnsafeBytes`
    /// - Output pointer management with `defer { ciris_verify_free() }`
    /// - Error code mapping
    private func callFFIWithDataResult(
        _ input: Data,
        _ ffiCall: (
            UnsafeMutableRawPointer,
            UnsafePointer<UInt8>?, Int,
            UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
            UnsafeMutablePointer<Int>?
        ) -> Int32
    ) throws -> Data {
        guard let handle = handle else { throw CIRISVerifyError.initializationFailed }
        let rawHandle = UnsafeMutableRawPointer(handle)

        var outPtr: UnsafeMutablePointer<UInt8>?
        var outLen: Int = 0

        let result = input.withUnsafeBytes { buffer -> Int32 in
            guard let baseAddr = buffer.baseAddress else { return -1 }
            return ffiCall(
                rawHandle,
                baseAddr.assumingMemoryBound(to: UInt8.self),
                buffer.count,
                &outPtr,
                &outLen)
        }

        guard result == 0 else { throw CIRISVerifyError.from(code: result) }
        guard let ptr = outPtr else { throw CIRISVerifyError.internalError(code: -99) }
        defer { ciris_verify_free(ptr) }

        return Data(bytes: ptr, count: outLen)
    }
}
