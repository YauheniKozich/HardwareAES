import Foundation
import HardwareAESCore
import HardwareAESASM

/// Hardware-accelerated AES encryption engine with ECB mode support.
///
/// **WARNING: ECB mode is cryptographically insecure for most applications.**
/// Identical plaintext blocks produce identical ciphertext blocks, leaking patterns.
///
/// ## Thread Safety
/// This class is thread-safe. All operations are serialized via a private dispatch queue.
///
/// ## Example
/// ```swift
/// let key = try SecureKey(keyData)
/// let engine = try HardwareAESECB(key: key)
/// let ciphertext = try engine.encrypt(plaintext)
/// ```
public final class HardwareAESECB: HardwareAESEngineProtocol, @unchecked Sendable {
    private let ctxData: Data
    private let queue: DispatchQueue

    /// Initializes a new AES engine with ECB mode support.
    ///
    /// - Parameter key: A `SecureKey` instance containing a 16-byte AES-128 key.
    /// - Throws: `AESError.invalidKeyLength` if key is not 16 bytes,
    ///           `AESError.internalError` if hardware initialization fails.
    public init(key: SecureKey) throws {
        var ctxData = Data(count: Int(HAES_AES128_CTX_BYTES_FULL))
        self.queue = DispatchQueue(label: "com.hardwareaes.ecb", qos: .userInitiated)
        try Self.setupKey(key: key, ctxData: &ctxData)
        self.ctxData = ctxData
    }

    /// Encrypts plaintext data using ECB mode.
    ///
    /// Input length must be a multiple of 16 bytes.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt (must be multiple of 16 bytes).
    ///   - mode: ECB mode configuration (unused, kept for protocol conformance).
    /// - Returns: The encrypted ciphertext data.
    /// - Throws: `AESError` if encryption fails.
    public func encrypt(_ plaintext: Data, mode: AESMode) throws -> Data {
        try queue.sync {
            guard case .ecb = mode else { throw AESError.unsupportedMode }
            return try process(input: plaintext, encrypt: true)
        }
    }

    /// Decrypts ciphertext data using ECB mode.
    ///
    /// Input length must be a multiple of 16 bytes.
    ///
    /// - Parameters:
    ///   - ciphertext: The data to decrypt (must be multiple of 16 bytes).
    ///   - mode: ECB mode configuration (unused, kept for protocol conformance).
    /// - Returns: The decrypted plaintext data.
    /// - Throws: `AESError` if decryption fails.
    public func decrypt(_ ciphertext: Data, mode: AESMode) throws -> Data {
        try queue.sync {
            guard case .ecb = mode else { throw AESError.unsupportedMode }
            return try process(input: ciphertext, encrypt: false)
        }
    }

    /// Encrypts plaintext data using ECB mode asynchronously.
    public func encrypt(_ plaintext: Data, mode: AESMode) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [weak self] in
                do {
                    guard let self else {
                        continuation.resume(throwing: AESError.internalError)
                        return
                    }
                    guard case .ecb = mode else {
                        continuation.resume(throwing: AESError.unsupportedMode)
                        return
                    }
                    let result = try self.process(input: plaintext, encrypt: true)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Decrypts ciphertext data using ECB mode asynchronously.
    public func decrypt(_ ciphertext: Data, mode: AESMode) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { [weak self] in
                do {
                    guard let self else {
                        continuation.resume(throwing: AESError.internalError)
                        return
                    }
                    guard case .ecb = mode else {
                        continuation.resume(throwing: AESError.unsupportedMode)
                        return
                    }
                    let result = try self.process(input: ciphertext, encrypt: false)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private func process(input: Data, encrypt: Bool) throws -> Data {
        guard input.count > 0, input.count % 16 == 0 else {
            throw AESError.internalError
        }

        var output = Data(count: input.count)

        let status = ctxData.withUnsafeBytes { ctxBuf in
            input.withUnsafeBytes { inBuf in
                output.withUnsafeMutableBytes { outBuf in
                    let ctxPtr = ctxBuf.bindMemory(to: UInt8.self).baseAddress!
                    let inPtr = inBuf.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    let outPtr = outBuf.baseAddress!.assumingMemoryBound(to: UInt8.self)

                    if encrypt {
                        return Int(haes_aes128_ecb_encrypt(inPtr, outPtr, input.count, ctxPtr))
                    } else {
                        return Int(haes_aes128_ecb_decrypt(inPtr, outPtr, input.count, ctxPtr))
                    }
                }
            }
        }

        guard status == 0 else { throw AESError.internalError }
        return output
    }

    private static func setupKey(key: SecureKey, ctxData: inout Data) throws {
        let keyBytes = key.keyData
        guard keyBytes.count == 16 else { throw AESError.invalidKeyLength }

        let status = ctxData.withUnsafeMutableBytes { ctxBuf in
            keyBytes.withUnsafeBytes { keyBuf in
                let ctxPtr = ctxBuf.bindMemory(to: UInt8.self).baseAddress
                let keyPtr = keyBuf.bindMemory(to: UInt8.self).baseAddress
                guard let ctxPtr, let keyPtr else { return -1 }
                return Int(haes_aes128_init(ctxPtr, keyPtr))
            }
        }

        guard status == 0 else { throw AESError.internalError }
    }
}
