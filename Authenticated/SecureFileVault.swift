import Foundation
import HardwareAESCore
import HardwareAESCTR
import HardwareAESBlockCipher
import HardwareAESASM

private enum SecureFileContainerFormat {
    static let version: UInt8 = 1
    static let nonceLength = 16
    static let tagLength = 16
}

/// Supplies nonces for CTR containers. Each implementation documents its
/// uniqueness scope; callers must share the required sequence or durable store
/// between all vaults that use the same key.
public protocol AESNonceSequence: Sendable {
    func nextNonce() async throws -> AESIV
}

/// Random 128-bit nonce provider with a per-instance usage ceiling.
///
/// This provider offers probabilistic uniqueness, not a persistence-backed
/// guarantee. Reuse one instance for all vaults using the same key. For keys
/// that survive process restarts, inject a durable `AESNonceSequence` instead.
public actor RandomAESNonceSequence: AESNonceSequence {
    private static let maximumUsage: UInt64 = 1 << 16
    private var usageCount: UInt64 = 0

    public init() {}

    public func nextNonce() throws -> AESIV {
        guard usageCount < Self.maximumUsage else {
            throw AESError.nonceUsageLimitReached
        }
        let nonce = try AESIV.random()
        usageCount += 1
        return nonce
    }
}

/// Authenticated AES-CTR container using AES-CMAC.
///
/// Format: version (1 byte), nonce (16 bytes), ciphertext, tag (16 bytes).
public actor SecureFileVault {
    private let encryption: HardwareAESCTR
    private let mac: AESCMAC
    private let nonceSequence: any AESNonceSequence

    public init(key: SecureKey, nonceSequence: any AESNonceSequence) throws {
        self.encryption = try HardwareAESCTR(key: key)
        self.mac = try AESCMAC(key: SecureFileVault.deriveMACKey(from: key))
        self.nonceSequence = nonceSequence
    }

    public func encrypt(_ plaintext: Data) async throws -> Data {
        let nonce = try await nonceSequence.nextNonce()
        let ciphertext = try await encryption.encrypt(plaintext, mode: CTRMode(iv: nonce))
        var authenticated = Data([SecureFileContainerFormat.version])
        authenticated.append(nonce.data)
        authenticated.append(ciphertext)
        let tag = try mac.tag(for: authenticated)
        authenticated.append(tag)
        return authenticated
    }

    /// Verifies and decrypts away from the actor executor. Cancellation is
    /// checked before work is dispatched; an in-flight C operation is not
    /// interruptible.
    public func decrypt(_ package: Data) async throws -> Data {
        try Task.checkCancellation()
        let encryption = self.encryption
        let mac = self.mac
        return try await Task.detached {
            try decryptPackage(package, encryption: encryption, mac: mac)
        }.value
    }

    private static func deriveMACKey(from key: SecureKey) throws -> SecureKey {
        let base = try AESCMAC(key: key)
        var derived = try base.tag(for: Data("HardwareAES-CMAC-MAC-v1".utf8))
        defer { derived.resetBytes(in: 0..<derived.count) }
        return try SecureKey(derived)
    }
}

private func decryptPackage(
    _ package: Data,
    encryption: HardwareAESCTR,
    mac: AESCMAC
) throws -> Data {
    let minimum = 1 + SecureFileContainerFormat.nonceLength + SecureFileContainerFormat.tagLength
    guard package.count >= minimum, package[0] == SecureFileContainerFormat.version else {
        throw AESError.authenticationFailed
    }
    let contentEnd = package.count - SecureFileContainerFormat.tagLength
    let content = Data(package.prefix(contentEnd))
    let supplied = Data(package.suffix(SecureFileContainerFormat.tagLength))
    guard constantTimeEqual(supplied, try mac.tag(for: content)) else {
        throw AESError.authenticationFailed
    }
    let nonceStart = 1
    let ciphertextStart = nonceStart + SecureFileContainerFormat.nonceLength
    let nonce = try AESIV(Data(content[nonceStart..<ciphertextStart]))
    return try encryption.decrypt(Data(content.dropFirst(ciphertextStart)), mode: CTRMode(iv: nonce))
}

private func constantTimeEqual(_ lhs: Data, _ rhs: Data) -> Bool {
    guard lhs.count == rhs.count else { return false }
    return lhs.withUnsafeBytes { lhsBuffer in
        rhs.withUnsafeBytes { rhsBuffer in
            guard let lhsPointer = lhsBuffer.bindMemory(to: UInt8.self).baseAddress,
                  let rhsPointer = rhsBuffer.bindMemory(to: UInt8.self).baseAddress
            else { return false }
            return haes_constant_time_equal(lhsPointer, rhsPointer, lhs.count) == 1
        }
    }
}
