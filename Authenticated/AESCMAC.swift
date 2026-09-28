import Foundation
import HardwareAESCore
import HardwareAESBlockCipher

/// Package-internal AES-CMAC primitive used by the authenticated container.
final class AESCMAC: Sendable {
    private let engine: AESBlockCipher

    init(key: SecureKey) throws {
        self.engine = try AESBlockCipher(key: key)
    }

    func tag(for message: Data) throws -> Data {
        let zero = Data(repeating: 0, count: 16)
        let l = try encryptBlock(zero)
        let k1 = doubleBlock(l)
        let k2 = doubleBlock(k1)
        let complete = !message.isEmpty && message.count % 16 == 0
        // Divide first so a near-Int.max message length cannot overflow at
        // `count + 15` while computing the ceiling.
        let blockCount = max(1, message.count / 16 + (message.count % 16 == 0 ? 0 : 1))
        let lastLength = complete ? 16 : message.count % 16
        var last = Data(message.suffix(lastLength))
        if complete {
            last = xor(last, k1)
        } else {
            last.append(0x80)
            while last.count < 16 { last.append(0) }
            guard last.count == 16 else { throw AESError.internalError }
            last = xor(last, k2)
        }

        var state = zero
        if blockCount > 1 {
            for index in 0..<(blockCount - 1) {
                let start = index * 16
                let block = Data(message[start..<(start + 16)])
                state = try encryptBlock(xor(state, block))
            }
        }
        return try encryptBlock(xor(state, last))
    }

    private func encryptBlock(_ block: Data) throws -> Data {
        try engine.encrypt(block)
    }

    private func doubleBlock(_ block: Data) -> Data {
        var result = Data(repeating: 0, count: 16)
        var carry: UInt8 = 0
        for index in stride(from: 15, through: 0, by: -1) {
            let byte = block[index]
            result[index] = (byte << 1) | carry
            carry = (byte & 0x80) == 0 ? 0 : 1
        }
        let reductionMask = UInt8(0) &- carry
        result[15] ^= 0x87 & reductionMask
        return result
    }

    private func xor(_ lhs: Data, _ rhs: Data) -> Data {
        Data(zip(lhs, rhs).map { $0 ^ $1 })
    }
}
