import Foundation
import HardwareAESCore

/// ECB (Electronic Codebook) mode configuration.
///
/// ECB mode encrypts each 16-byte block independently with the same key.
/// **WARNING: ECB is cryptographically insecure for most applications**
/// because identical plaintext blocks produce identical ciphertext blocks.
///
/// Use only for:
/// - Testing against known test vectors
/// - Interoperability with legacy systems
/// - Educational purposes
public struct ECBMode: Equatable, Sendable {
    public init() {}
}
