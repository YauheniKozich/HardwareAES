import Foundation
import HardwareAESCore

/// CTR (Counter) mode configuration for AES encryption.
///
/// CTR mode turns a block cipher into a stream cipher by encrypting successive
/// counter values and XORing them with the plaintext. It provides:
/// - Parallel encryption and decryption
/// - No padding required
/// - Random access to encrypted blocks
///
/// - Important: CTR mode provides confidentiality but NOT authentication.
///              Consider using GCM mode if you need authentication.
public struct CTRMode: Equatable, Sendable {
    /// Initialization vector (nonce) - must be unique for each encryption
    public let iv: AESIV
    
    /// Creates a new CTR mode configuration.
    /// - Parameter iv: 16-byte initialization vector (nonce)
    /// - Throws: `AESError.invalidIVLength` if IV is not 16 bytes
    public init(iv: Data) throws {
        self.iv = try AESIV(iv)
    }
    
    /// Creates a new CTR mode configuration with a validated IV.
    /// - Parameter iv: AESIV instance
    public init(iv: AESIV) {
        self.iv = iv
    }
}

// MARK: - CTR Mode Extension for AESMode

public extension AESMode {
    /// Вспомогательный инициализатор для создания режима CTR напрямую из сырых Data.
    /// Переименован в `ctrMode`, чтобы исключить конфликт имен с `case ctr(iv: AESIV)`.
    ///
    /// ## Пример использования:
    /// ```swift
    /// let mode = try AESMode.ctrMode(iv: myRawDataBytes)
    /// ```
    static func ctrMode(iv: Data) throws -> AESMode {
        .ctr(iv: try AESIV(iv))
    }
}
