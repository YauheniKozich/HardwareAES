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
public protocol HardwareAESEngineProtocol: Sendable {
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

public extension HardwareAESEngineProtocol {
    /// Default asynchronous adapter for synchronous engines. Synchronous
    /// work runs off the caller's executor; cancellation cannot interrupt work
    /// once the synchronous operation has started.
    func encrypt(_ plaintext: Data, mode: AESMode) async throws -> Data {
        try Task.checkCancellation()
        return try await Task.detached(priority: .userInitiated) {
            try invokeSynchronousEncrypt(self, plaintext: plaintext, mode: mode)
        }.value
    }

    /// Default asynchronous adapter for synchronous engines. Synchronous
    /// work runs off the caller's executor; cancellation cannot interrupt work
    /// once the synchronous operation has started.
    func decrypt(_ ciphertext: Data, mode: AESMode) async throws -> Data {
        try Task.checkCancellation()
        return try await Task.detached(priority: .userInitiated) {
            try invokeSynchronousDecrypt(self, ciphertext: ciphertext, mode: mode)
        }.value
    }
}

private func invokeSynchronousEncrypt(
    _ engine: any HardwareAESEngineProtocol,
    plaintext: Data,
    mode: AESMode
) throws -> Data {
    try engine.encrypt(plaintext, mode: mode)
}

private func invokeSynchronousDecrypt(
    _ engine: any HardwareAESEngineProtocol,
    ciphertext: Data,
    mode: AESMode
) throws -> Data {
    try engine.decrypt(ciphertext, mode: mode)
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
    private let stateLock = NSLock()
    private var storedEncryptHandler: ((Data, AESMode) throws -> Data)?
    private var storedDecryptHandler: ((Data, AESMode) throws -> Data)?
    private var storedEncryptCallCount = 0
    private var storedDecryptCallCount = 0

    /// Closure called when `encrypt(_:mode:)` is invoked.
    public var encryptHandler: ((Data, AESMode) throws -> Data)? {
        get { stateLock.withLock { storedEncryptHandler } }
        set { stateLock.withLock { storedEncryptHandler = newValue } }
    }
    
    /// Closure called when `decrypt(_:mode:)` is invoked.
    public var decryptHandler: ((Data, AESMode) throws -> Data)? {
        get { stateLock.withLock { storedDecryptHandler } }
        set { stateLock.withLock { storedDecryptHandler = newValue } }
    }
    
    /// Counter for encrypt calls (for testing verification).
    public var encryptCallCount: Int { stateLock.withLock { storedEncryptCallCount } }
    
    /// Counter for decrypt calls (for testing verification).
    public var decryptCallCount: Int { stateLock.withLock { storedDecryptCallCount } }
    
    public init() {}
    
    public func encrypt(_ plaintext: Data, mode: AESMode) throws -> Data {
        try queue.sync {
            let handler = stateLock.withLock {
                storedEncryptCallCount += 1
                return storedEncryptHandler
            }
            return try handler?(plaintext, mode) ?? plaintext
        }
    }
    
    public func decrypt(_ ciphertext: Data, mode: AESMode) throws -> Data {
        try queue.sync {
            let handler = stateLock.withLock {
                storedDecryptCallCount += 1
                return storedDecryptHandler
            }
            return try handler?(ciphertext, mode) ?? ciphertext
        }
    }
    
    public func encrypt(_ plaintext: Data, mode: AESMode) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    let handler = self.stateLock.withLock {
                        self.storedEncryptCallCount += 1
                        return self.storedEncryptHandler
                    }
                    let result = try handler?(plaintext, mode) ?? plaintext
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
                    let handler = self.stateLock.withLock {
                        self.storedDecryptCallCount += 1
                        return self.storedDecryptHandler
                    }
                    let result = try handler?(ciphertext, mode) ?? ciphertext
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
}
