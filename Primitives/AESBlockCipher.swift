import Foundation
import HardwareAESCore
import HardwareAESASM

// These symbols are intentionally not declared in the public C umbrella
// header. They are only called inside this package to implement AES-CMAC.
@_silgen_name("haes_aes128_ecb_encrypt")
private func haesInternalAESBlockEncrypt(
    _ input: UnsafePointer<UInt8>,
    _ output: UnsafeMutablePointer<UInt8>,
    _ length: Int,
    _ context: UnsafePointer<UInt8>
) -> Int32

@_silgen_name("haes_aes128_ecb_decrypt")
private func haesInternalAESBlockDecrypt(
    _ input: UnsafePointer<UInt8>,
    _ output: UnsafeMutablePointer<UInt8>,
    _ length: Int,
    _ context: UnsafePointer<UInt8>
) -> Int32

private final class ECBContextStorage: @unchecked Sendable {
    private let allocation: UnsafeMutableRawPointer
    var pointer: UnsafeMutablePointer<UInt8> {
        allocation.assumingMemoryBound(to: UInt8.self)
    }
    let count = Int(HAES_AES128_CTX_BYTES_FULL)

    init() {
        allocation = .allocate(byteCount: count, alignment: 16)
    }

    deinit {
        haes_secure_zero(pointer, count)
        allocation.deallocate()
    }
}

/// Package-only AES block primitive used by AES-CMAC. It is not an exported
/// encryption mode or package product.
package final class AESBlockCipher: Sendable {
    private let context: ECBContextStorage

    package init(key: SecureKey) throws {
        let context = ECBContextStorage()
        try Self.setupKey(key: key, context: context)
        self.context = context
    }

    package func encrypt(_ plaintext: Data) throws -> Data {
        try process(input: plaintext, encrypt: true)
    }

    package func decrypt(_ ciphertext: Data) throws -> Data {
        try process(input: ciphertext, encrypt: false)
    }

    private func process(input: Data, encrypt: Bool) throws -> Data {
        guard input.count > 0, input.count % 16 == 0 else {
            throw AESError.internalError
        }

        var output = Data(count: input.count)

        let status = withUnsafeBytes(of: context.pointer, count: context.count) { ctxBuf in
            input.withUnsafeBytes { inBuf in
                output.withUnsafeMutableBytes { outBuf in
                    guard let ctxPtr = ctxBuf.bindMemory(to: UInt8.self).baseAddress,
                          let inPtr = inBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                          let outPtr = outBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    else { return -1 }

                    if encrypt {
                        return Int(haesInternalAESBlockEncrypt(inPtr, outPtr, input.count, ctxPtr))
                    } else {
                        return Int(haesInternalAESBlockDecrypt(inPtr, outPtr, input.count, ctxPtr))
                    }
                }
            }
        }

        guard status == 0 else { throw AESError.internalError }
        return output
    }

    private static func setupKey(key: SecureKey, context: ECBContextStorage) throws {
        let status = key.withUnsafeBytes { keyBuf in
            guard let keyPtr = keyBuf.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return Int(haes_aes128_init(context.pointer, keyPtr))
        }

        guard status == 0 else { throw AESError.internalError }
    }

    private func withUnsafeBytes<T>(of pointer: UnsafeMutablePointer<UInt8>, count: Int,
                                    _ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        try body(UnsafeRawBufferPointer(start: pointer, count: count))
    }
}
