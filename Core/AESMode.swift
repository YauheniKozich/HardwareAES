import Foundation
import Security

/// AES encryption mode with type-safe IV/tweak parameters.
public enum AESMode: Equatable, Sendable {
    /// CTR mode with initialization vector
    case ctr(iv: AESIV)
    
    /// ECB mode (no IV needed, not recommended for production)
    case ecb
    
    /// CBC mode with initialization vector (not yet implemented)
    case cbc(iv: AESIV)
    
    /// GCM mode with nonce and additional authenticated data (not yet implemented)
    /// Храним чистый nonce как Data, чтобы не ломать математику GCM префиксами
    case gcm(nonce: Data, aad: Data)
    
    /// CCM mode with nonce, AAD, and tag length (not yet implemented)
    case ccm(nonce: Data, aad: Data, tagLength: CCMTagsLength)
    
    /// XTS mode with tweak for disk encryption (not yet implemented)
    case xts(tweak: AESIV)
}

/// Type-safe AES Initialization Vector (16 bytes for standard modes).
public struct AESIV: Equatable, Sendable {
    private let _data: Data
    
    /// Creates a standard 16-byte IV for CBC/CTR/XTS modes.
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

    /// Compatibility helper for nonce-based modes that normalize to 16 bytes.
    ///
    /// The engine currently operates on 16-byte IV-sized values internally, so
    /// shorter nonces are padded with trailing zero bytes for compatibility.
    public static func gcmNonce(_ nonce: Data) throws -> AESIV {
        try normalizedNonce(nonce)
    }

    /// Compatibility helper for nonce-based modes that normalize to 16 bytes.
    public static func ccmNonce(_ nonce: Data) throws -> AESIV {
        try normalizedNonce(nonce)
    }

    private static func normalizedNonce(_ nonce: Data) throws -> AESIV {
        guard nonce.count <= 16 else {
            throw AESError.invalidIVLength
        }

        if nonce.count == 16 {
            return try AESIV(nonce)
        }

        var bytes = Data(nonce)
        bytes.append(contentsOf: Array(repeating: UInt8(0), count: 16 - nonce.count))
        return try AESIV(bytes)
    }
}

/// CCM authentication tag length (must be even, 4-16 bytes).
public enum CCMTagsLength: Int, Sendable {
    case bits64 = 8
    case bits96 = 12
    case bits128 = 16
    
    public init?(_ value: Int) {
        guard (4...16).contains(value), value % 2 == 0 else {
            return nil
        }
        self.init(rawValue: value)
    }
}

/// AES key size in bits.
public enum AESKeySize: Int, Sendable {
    case bits128 = 16
    case bits192 = 24
    case bits256 = 32
}

/// AES operation type (encrypt or decrypt).
public enum AESOperation {
    case encrypt
    case decrypt
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
        }
    }
    
    private var failureReason: String {
        switch self {
        case .invalidKeyLength: return "Key must be 16, 24, or 32 bytes for AES-128/192/256"
        case .invalidIVLength: return "IV length does not match mode requirements"
        case .invalidTagLength: return "Tag length must be 4-16 bytes (even number)"
        case .unsupportedMode: return "This AES mode is not yet implemented"
        case .internalError: return "Low-level cryptographic operation failed"
        case .memoryAllocationFailed: return "Unable to allocate secure memory buffer"
        case .invalidCiphertextSize: return "The encrypted data package is missing header components or has an invalid block size"
        case .bufferSizeMismatch: return "CTR mode requires input.count == output.count"
        case .counterExhausted: return "The CTR counter cannot be reused after its 32-bit space is exhausted"
        }
    }
}
