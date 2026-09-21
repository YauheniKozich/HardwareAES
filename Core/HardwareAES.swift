import Foundation
import HardwareAESCore
import HardwareAESCTR

/// Unified AES encryption engine facade.
///
/// This class provides a unified API for AES encryption using CTR mode.
/// CTR mode is a cryptographically secure streaming mode that provides:
/// - Confidentiality (encryption/decryption)
/// - Parallel processing capability
/// - No padding required
/// - Random access to encrypted blocks
///
/// ## Thread Safety
/// This class is thread-safe. All operations are serialized through the
/// underlying CTR engine.
///
/// ## Example
/// ```swift
/// let key = try SecureKey(keyData)
/// let engine = try HardwareAES(key: key)
///
/// // Encrypt
/// let iv = try AESIV.random()
/// let ciphertext = try engine.encrypt(plaintext, mode: .ctr(iv: iv))
///
/// // Decrypt
/// let decrypted = try engine.decrypt(ciphertext, mode: .ctr(iv: iv))
/// ```
///
/// - Important: CTR mode provides confidentiality but NOT authentication.
///              For authenticated encryption, consider using GCM mode (future).
public final class HardwareAES: HardwareAESEngineProtocol, @unchecked Sendable {
    private let ctrEngine: HardwareAESCTR
    private let queue: DispatchQueue

    /// Initializes a new AES engine with CTR mode support.
    ///
    /// - Parameter key: A `SecureKey` instance containing a 16, 24, or 32-byte AES key.
    /// - Throws: `AESError.invalidKeyLength` if the key length is not valid.
    ///           `AESError.memoryAllocationFailed` if context allocation fails.
    public init(key: SecureKey) throws {
        self.ctrEngine = try HardwareAESCTR(key: key)
        self.queue = DispatchQueue(label: "com.hardwareaes.facade", qos: .userInitiated)
    }

    /// Encrypts plaintext data using CTR mode.
    ///
    /// CTR mode supports arbitrary length input - no padding required.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt (any length).
    ///   - mode: AES mode (must be .ctr for this implementation).
    /// - Returns: The encrypted ciphertext data (same length as input).
    /// - Throws: `AESError.unsupportedMode` if mode is not CTR,
    ///           `AESError` if encryption fails.
    public func encrypt(_ plaintext: Data, mode: AESMode) throws -> Data {
        try queue.sync {
            try encryptOnQueue(plaintext, mode: mode)
        }
    }

    /// Decrypts ciphertext data using CTR mode.
    ///
    /// CTR mode supports arbitrary length input - no padding required.
    ///
    /// - Parameters:
    ///   - ciphertext: The data to decrypt (any length).
    ///   - mode: AES mode (must be .ctr for this implementation).
    /// - Returns: The decrypted plaintext data (same length as input).
    /// - Throws: `AESError.unsupportedMode` if mode is not CTR,
    ///           `AESError` if decryption fails.
    public func decrypt(_ ciphertext: Data, mode: AESMode) throws -> Data {
        try queue.sync {
            try decryptOnQueue(ciphertext, mode: mode)
        }
    }
    
    /// Encrypts plaintext data using CTR mode asynchronously.
    public func encrypt(_ plaintext: Data, mode: AESMode) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [weak self] in
                do {
                    guard let self else {
                        continuation.resume(throwing: AESError.internalError)
                        return
                    }
                    let result = try self.encryptOnQueue(plaintext, mode: mode)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
    
    /// Decrypts ciphertext data using CTR mode asynchronously.
    public func decrypt(_ ciphertext: Data, mode: AESMode) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [weak self] in
                do {
                    guard let self else {
                        continuation.resume(throwing: AESError.internalError)
                        return
                    }
                    let result = try self.decryptOnQueue(ciphertext, mode: mode)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Runs NIST SP 800-38A F.5.1 CTR validation test for AES-128.
    ///
    /// - Returns: `true` if the test passes, `false` otherwise.
    ///
    /// - Note: This test validates the implementation against the official
    ///         NIST test vector for AES-128-CTR.
    public static func runNISTSelfTest() -> Bool {
        HardwareAESCTR.runNISTSelfTest()
    }

    private func encryptOnQueue(_ plaintext: Data, mode: AESMode) throws -> Data {
        guard case .ctr(let iv) = mode else {
            throw AESError.unsupportedMode
        }
        return try ctrEngine.encrypt(plaintext, mode: CTRMode(iv: iv))
    }

    private func decryptOnQueue(_ ciphertext: Data, mode: AESMode) throws -> Data {
        guard case .ctr(let iv) = mode else {
            throw AESError.unsupportedMode
        }
        return try ctrEngine.decrypt(ciphertext, mode: CTRMode(iv: iv))
    }

    // MARK: - Alloc-Free API (bypasses queue.sync)

    /// In-place CTR. Low-level; caller manages thread safety.
    public func encryptInPlace(
        _ buffer: inout Data,
        mode: AESMode
    ) throws {
        guard case .ctr(let iv) = mode else {
            throw AESError.unsupportedMode
        }
        try buffer.withUnsafeMutableBytes { raw in
            try ctrEngine.encryptInPlace(buffer: raw, iv: iv.data)
        }
    }

    /// Out-of-place CTR without allocation. Low-level; caller manages thread safety.
    public func encrypt(
        input: UnsafeRawBufferPointer,
        output: UnsafeMutableRawBufferPointer,
        mode: AESMode
    ) throws {
        guard case .ctr(let iv) = mode else {
            throw AESError.unsupportedMode
        }
        try ctrEngine.encrypt(input: input, output: output, iv: iv.data)
    }
}

// MARK: - Thread Safety Documentation

/// ## Concurrency
///
/// This class uses `@unchecked Sendable` because:
/// 1. `ctrEngine` is immutable after initialization and internally thread-safe
/// 2. All cryptographic operations are serialized by the underlying engine
/// 3. No shared mutable state between instances
///
/// - Warning: Do not modify the engine after initialization.
