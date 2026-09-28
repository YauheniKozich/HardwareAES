import Foundation
import Security

/// AES encryption mode with type-safe IV/tweak parameters.
public enum AESMode: Equatable, Sendable {
    /// CTR mode with initialization vector
    case ctr(iv: AESIV)
}

/// Type-safe AES Initialization Vector (16 bytes for standard modes).
public struct AESIV: Equatable, Sendable {
    private let _data: Data
    
    /// Creates a standard 16-byte IV for the supported CTR mode.
    /// - Parameter data: Exactly 16 bytes of IV data.
    /// - Throws: `AESError.invalidIVLength` if data is not 16 bytes.
    public init(_ data: Data) throws {
        guard data.count == 16 else {
            throw AESError.invalidIVLength
        }
        self._data = data
    }
    
    /// Raw IV data (16 bytes).
    public var data: Data { _data }
    
    /// Generates a cryptographically secure random IV.
    /// - Returns: A new 16-byte random IV.
    /// - Throws: `AESError.internalError` if random generation fails.
    public static func random() throws -> AESIV {
        var bytes = [UInt8](repeating: 0, count: 16)
        let status = SecRandomCopyBytes(kSecRandomDefault, 16, &bytes)
        guard status == errSecSuccess else {
            throw AESError.internalError
        }
        return try AESIV(Data(bytes))
    }

}

/// AES key size supported by this implementation.
public enum AESKeySize: Int, Sendable {
    case bits128 = 16
}

/// AES encryption/decryption errors.
public enum AESError: Error, CustomNSError, Sendable {
    case invalidKeyLength
    case invalidIVLength
    case invalidTagLength
    case invalidCiphertextSize
    case unsupportedMode
    case internalError
    case memoryAllocationFailed
    case bufferSizeMismatch
    case counterExhausted
    case authenticationFailed
    case nonceUsageLimitReached
    
    public static var errorDomain: String {
        "com.hardwareaes.engine.error"
    }
    
    public var errorCode: Int {
        switch self {
        case .invalidKeyLength: return 1
        case .invalidIVLength: return 2
        case .invalidTagLength: return 3
        case .unsupportedMode: return 4
        case .internalError: return 5
        case .memoryAllocationFailed: return 6
        case .invalidCiphertextSize: return 7
        case .bufferSizeMismatch: return 8
        case .counterExhausted: return 9
        case .authenticationFailed: return 10
        case .nonceUsageLimitReached: return 11
        }
    }
    
    public var errorUserInfo: [String: Any] {
        [
            NSLocalizedDescriptionKey: localizedDescription,
            NSLocalizedFailureReasonErrorKey: failureReason
        ]
    }
    
    private var localizedDescription: String {
        switch self {
        case .invalidKeyLength: return "Invalid AES key length"
        case .invalidIVLength: return "Invalid initialization vector length"
        case .invalidTagLength: return "Invalid authentication tag length"
        case .unsupportedMode: return "Unsupported AES mode"
        case .internalError: return "Internal cryptographic error"
        case .memoryAllocationFailed: return "Failed to allocate secure memory"
        case .invalidCiphertextSize: return "Invalid ciphertext size"
        case .bufferSizeMismatch: return "Input and output buffer sizes differ"
        case .counterExhausted: return "CTR counter space has been exhausted"
        case .authenticationFailed: return "Authenticated ciphertext verification failed"
        case .nonceUsageLimitReached: return "Nonce sequence usage limit reached"
        }
    }
    
    private var failureReason: String {
        switch self {
        case .invalidKeyLength: return "Key must be exactly 16 bytes for AES-128"
        case .invalidIVLength: return "IV length does not match mode requirements"
        case .invalidTagLength: return "Tag length must be 4-16 bytes (even number)"
        case .unsupportedMode: return "This AES mode is not yet implemented"
        case .internalError: return "Low-level cryptographic operation failed"
        case .memoryAllocationFailed: return "Unable to allocate secure memory buffer"
        case .invalidCiphertextSize: return "The encrypted data package is missing header components or has an invalid block size"
        case .bufferSizeMismatch: return "CTR mode requires input.count == output.count"
        case .counterExhausted: return "The input exceeds the supported CTR counter space"
        case .authenticationFailed: return "The container tag is invalid or the container is malformed"
        case .nonceUsageLimitReached: return "Rotate the encryption key before generating more nonces"
        }
    }
}
