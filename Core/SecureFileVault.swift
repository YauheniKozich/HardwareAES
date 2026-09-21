import CryptoKit
import Foundation

/// Authenticated file container built on top of the low-level CTR primitive.
///
/// Format:
/// [1 byte version][16 byte IV][ciphertext][32 byte HMAC-SHA256 tag]
public final actor SecureFileVault {
    private static let formatVersion: UInt8 = 1
    private static let ivLength = 16
    private static let tagLength = 32

    private let engine: any HardwareAESEngineProtocol
    private let authenticationKey: SymmetricKey

    /// Creates a vault. The key is used only to authenticate the container;
    /// encryption and decryption are performed by the supplied engine.
    public init(engine: any HardwareAESEngineProtocol, key: SecureKey) {
        self.engine = engine
        self.authenticationKey = SymmetricKey(data: key.keyData)
    }

    /// Encrypts data using AES-CTR and authenticates the complete container.
    public func encryptCTR(data plaintext: Data) throws -> Data {
        let iv = try AESIV.random()
        let ciphertext = try engine.encrypt(plaintext, mode: .ctr(iv: iv))

        var authenticatedContent = Data([Self.formatVersion])
        authenticatedContent.append(iv.data)
        authenticatedContent.append(ciphertext)

        let tag = HMAC<SHA256>.authenticationCode(
            for: authenticatedContent,
            using: authenticationKey
        )
        authenticatedContent.append(contentsOf: tag)
        return authenticatedContent
    }

    /// Authenticates and decrypts a container produced by encryptCTR(data:).
    public func decryptCTR(data packagedData: Data) throws -> Data {
        let minimumSize = 1 + Self.ivLength + Self.tagLength
        guard packagedData.count >= minimumSize else {
            throw AESError.invalidCiphertextSize
        }

        guard packagedData[0] == Self.formatVersion else {
            throw AESError.invalidCiphertextSize
        }

        let authenticatedEnd = packagedData.count - Self.tagLength
        let authenticatedContent = packagedData.prefix(authenticatedEnd)
        let suppliedTag = packagedData.suffix(Self.tagLength)
        let expectedTag = HMAC<SHA256>.authenticationCode(
            for: authenticatedContent,
            using: authenticationKey
        )

        guard suppliedTag.elementsEqual(expectedTag) else {
            throw AESError.invalidCiphertextSize
        }

        let ivData = authenticatedContent.dropFirst().prefix(Self.ivLength)
        let iv = try AESIV(Data(ivData))
        let ciphertext = authenticatedContent.dropFirst(1 + Self.ivLength)
        return try engine.decrypt(Data(ciphertext), mode: .ctr(iv: iv))
    }
}
