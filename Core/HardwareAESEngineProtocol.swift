import Dispatch
import Foundation

/// Protocol defining the interface for AES encryption/decryption engines.
///
/// Conforming types provide hardware-accelerated AES operations.
/// This protocol enables dependency injection and mock testing.
///
/// ## Example
/// ```swift
/// // Production use
/// let engine = try HardwareAES(key: key)
/// try await vault.encrypt(data: plaintext)
///
/// // Testing with mock
/// let mockEngine = MockHardwareAESEngine()
/// mockEngine.encryptHandler = { data, mode in data }  // Return unchanged
/// ```
public protocol HardwareAESEngineProtocol {
    /// Encrypts plaintext data using the specified AES mode.
    ///
    /// - Parameters:
    ///   - plaintext: The data to encrypt. Must be a multiple of 16 bytes for block modes.
    ///   - mode: The AES encryption mode.
    /// - Returns: The encrypted ciphertext data.
    /// - Throws: `AESError` if encryption fails.
    func encrypt(_ plaintext: Data, mode: AESMode) throws -> Data
    
    /// Decrypts ciphertext data using the specified AES mode.
    ///
    /// - Parameters:
    ///   - ciphertext: The data to decrypt. Must be a multiple of 16 bytes.
    ///   - mode: The AES decryption mode.
    /// - Returns: The decrypted plaintext data.
    /// - Throws: `AESError` if decryption fails.
    func decrypt(_ ciphertext: Data, mode: AESMode) throws -> Data
    
    /// Encrypts plaintext data asynchronously.
    func encrypt(_ plaintext: Data, mode: AESMode) async throws -> Data
    
    /// Decrypts ciphertext data asynchronously.
    func decrypt(_ ciphertext: Data, mode: AESMode) async throws -> Data
}

// MARK: - Mock Implementation

/// Mock AES engine for unit testing.
///
/// Use this class to test code that depends on `HardwareAESEngineProtocol`
/// without performing actual cryptographic operations.
///
/// ## Example
/// ```swift
/// let mock = MockHardwareAESEngine()
/// mock.encryptHandler = { data, mode in
///     // Return predictable ciphertext for testing
///     return Data(repeating: 0x42, count: data.count)
/// }
/// ```
public final class MockHardwareAESEngine: HardwareAESEngineProtocol, @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.hardwareaes.mock", qos: .userInitiated)

    /// Closure called when `encrypt(_:mode:)` is invoked.
    public var encryptHandler: ((Data, AESMode) throws -> Data)?
    
    /// Closure called when `decrypt(_:mode:)` is invoked.
    public var decryptHandler: ((Data, AESMode) throws -> Data)?
    
    /// Counter for encrypt calls (for testing verification).
    public private(set) var encryptCallCount = 0
    
    /// Counter for decrypt calls (for testing verification).
    public private(set) var decryptCallCount = 0
    
    public init() {}
    
    public func encrypt(_ plaintext: Data, mode: AESMode) throws -> Data {
        try queue.sync {
            encryptCallCount += 1
            return try encryptHandler?(plaintext, mode) ?? plaintext
        }
    }
    
    public func decrypt(_ ciphertext: Data, mode: AESMode) throws -> Data {
        try queue.sync {
            decryptCallCount += 1
            return try decryptHandler?(ciphertext, mode) ?? ciphertext
        }
    }
    
    public func encrypt(_ plaintext: Data, mode: AESMode) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    self.encryptCallCount += 1
                    let result = try self.encryptHandler?(plaintext, mode) ?? plaintext
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
    
    public func decrypt(_ ciphertext: Data, mode: AESMode) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    self.decryptCallCount += 1
                    let result = try self.decryptHandler?(ciphertext, mode) ?? ciphertext
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
