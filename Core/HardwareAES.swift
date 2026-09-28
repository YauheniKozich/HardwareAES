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
/// This class is thread-safe for independent calls. The immutable AES key
/// context permits concurrent operations; callers must not access the same
/// mutable input/output buffer concurrently.
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
///              Use `SecureFileVault` for authenticated containers.
public final class HardwareAES: HardwareAESEngineProtocol, Sendable {
    private let ctrEngine: HardwareAESCTR

    /// Initializes a new AES engine with CTR mode support.
    ///
    /// - Parameter key: A `SecureKey` instance containing exactly 16 bytes.
    /// - Throws: `AESError.invalidKeyLength` if the key length is not valid.
    ///           `AESError.memoryAllocationFailed` if context allocation fails.
    public init(key: SecureKey) throws {
        self.ctrEngine = try HardwareAESCTR(key: key)
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
        try encryptWithCTR(plaintext, mode: mode)
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
        try decryptWithCTR(ciphertext, mode: mode)
    }
    
    /// Encrypts plaintext data using CTR mode asynchronously.
    public func encrypt(_ plaintext: Data, mode: AESMode) async throws -> Data {
        guard case .ctr(let iv) = mode else { throw AESError.unsupportedMode }
        return try await ctrEngine.encrypt(plaintext, mode: CTRMode(iv: iv))
    }
    
    /// Decrypts ciphertext data using CTR mode asynchronously.
    public func decrypt(_ ciphertext: Data, mode: AESMode) async throws -> Data {
        guard case .ctr(let iv) = mode else { throw AESError.unsupportedMode }
        return try await ctrEngine.decrypt(ciphertext, mode: CTRMode(iv: iv))
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

    private func encryptWithCTR(_ plaintext: Data, mode: AESMode) throws -> Data {
        guard case .ctr(let iv) = mode else {
            throw AESError.unsupportedMode
        }
        return try ctrEngine.encrypt(plaintext, mode: CTRMode(iv: iv))
    }

    private func decryptWithCTR(_ ciphertext: Data, mode: AESMode) throws -> Data {
        guard case .ctr(let iv) = mode else {
            throw AESError.unsupportedMode
        }
        return try ctrEngine.decrypt(ciphertext, mode: CTRMode(iv: iv))
    }

    // MARK: - Alloc-Free API

    /// In-place CTR. The caller owns exclusive access to `buffer` for this call.
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

    /// Out-of-place CTR without allocation. The caller owns exclusive access to
    /// both buffers and ensures they do not overlap for this call.
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
