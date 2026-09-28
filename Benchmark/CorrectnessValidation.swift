import Foundation
import CommonCrypto
import HardwareAESCore
import HardwareAESCTR
import HardwareAESASM

public struct CorrectnessReport {
    public let checks: Int
    public let randomCases: Int
    public let passed: Bool
    public let failure: String?

    public var summary: String {
        if passed {
            return "✅ Correctness: PASS (\(checks) checks, \(randomCases) randomized cases)"
        }
        return "❌ Correctness: FAIL — \(failure ?? "unknown failure")"
    }
}

extension CryptoBenchmark {
    /// Runs correctness gates before performance measurements.
    ///
    /// This intentionally uses a deterministic PRNG so a failure can be
    /// reproduced from the reported case number without making the benchmark
    /// depend on system entropy.
    public func validateCorrectness() -> CorrectnessReport {
        var checks = 0
        var randomCases = 0

        do {
            guard haes_aes128_ctr_kat() == 1 else { throw ValidationError("NIST CTR KAT") }
            checks += 1
            let keyData = Data(repeating: 0x42, count: 16)
            let ivData = Data((0..<16).map(UInt8.init))
            let engine = try HardwareAESCTR(key: SecureKey(keyData))

            for size in [0, 1, 2, 15, 16, 17, 31, 32, 33, 127, 128, 129, 4095, 4096] {
                let plaintext = Data((0..<size).map { UInt8(truncatingIfNeeded: $0 * 31) })
                let ciphertext = try engine.encrypt(plaintext, mode: CTRMode(iv: AESIV(ivData)))
                let expected = try encryptWithCommonCrypto(plaintext: plaintext, key: keyData, iv: ivData)
                guard ciphertext == expected else { throw ValidationError("tail/boundary size \(size)") }
                let roundTrip = try engine.decrypt(ciphertext, mode: CTRMode(iv: AESIV(ivData)))
                guard roundTrip == plaintext else { throw ValidationError("round trip size \(size)") }
                checks += 2
            }

            var rng = SplitMix64(seed: 0x484145532D46555A)
            for caseNumber in 0..<256 {
                let size = Int(rng.next() % 4097)
                let key = Data((0..<16).map { _ in UInt8(truncatingIfNeeded: rng.next()) })
                let iv = Data((0..<16).map { _ in UInt8(truncatingIfNeeded: rng.next()) })
                let plaintext = Data((0..<size).map { _ in UInt8(truncatingIfNeeded: rng.next()) })
                let testEngine = try HardwareAESCTR(key: SecureKey(key))
                let ours = try testEngine.encrypt(plaintext, mode: CTRMode(iv: AESIV(iv)))
                let reference = try encryptWithCommonCrypto(plaintext: plaintext, key: key, iv: iv)
                guard ours == reference else { throw ValidationError("random case \(caseNumber), size \(size)") }
                randomCases += 1
                checks += 1

                let stream = HardwareAESCTRStream(engine: testEngine, iv: try AESIV(iv))
                var streamed = Data()
                var offset = 0
                while offset < size {
                    let remaining = size - offset
                    let chunk = min(remaining, Int(rng.next() % 193))
                    let actualChunk = max(1, chunk)
                    streamed.append(try stream.update(Data(plaintext[offset..<(offset + actualChunk)])))
                    offset += actualChunk
                }
                guard streamed == ours else { throw ValidationError("stream case \(caseNumber)") }
                checks += 1
            }

            try validateUnalignedAndInPlace(engine: engine, iv: ivData, checks: &checks)
            try validateInc32Overflow(key: keyData, checks: &checks)

            return CorrectnessReport(checks: checks, randomCases: randomCases, passed: true, failure: nil)
        } catch {
            return CorrectnessReport(
                checks: checks,
                randomCases: randomCases,
                passed: false,
                failure: String(describing: error)
            )
        }
    }

    private func validateUnalignedAndInPlace(
        engine: HardwareAESCTR,
        iv: Data,
        checks: inout Int
    ) throws {
        let size = 4097
        let inputStorage = UnsafeMutableRawPointer.allocate(byteCount: size + 2, alignment: 1)
        let outputStorage = UnsafeMutableRawPointer.allocate(byteCount: size + 2, alignment: 1)
        let inPlaceStorage = UnsafeMutableRawPointer.allocate(byteCount: size + 2, alignment: 1)
        defer {
            inputStorage.deallocate()
            outputStorage.deallocate()
            inPlaceStorage.deallocate()
        }

        let input = inputStorage.advanced(by: 1)
        let output = outputStorage.advanced(by: 1)
        let inPlace = inPlaceStorage.advanced(by: 1)
        for index in 0..<size {
            input.storeBytes(of: UInt8(truncatingIfNeeded: index * 17), toByteOffset: index, as: UInt8.self)
        }
        memcpy(inPlace, input, size)

        try engine.encrypt(
            input: UnsafeRawBufferPointer(start: input, count: size),
            output: UnsafeMutableRawBufferPointer(start: output, count: size),
            iv: iv
        )
        try engine.encryptInPlace(
            buffer: UnsafeMutableRawBufferPointer(start: inPlace, count: size),
            iv: iv
        )

        let plaintext = Data(bytes: input, count: size)
        let expected = try encryptWithCommonCrypto(plaintext: plaintext, key: Data(repeating: 0x42, count: 16), iv: iv)
        guard Data(bytes: output, count: size) == expected,
              Data(bytes: inPlace, count: size) == expected else {
            throw ValidationError("unaligned or in-place buffers")
        }
        checks += 2
    }

    private func validateInc32Overflow(key: Data, checks: inout Int) throws {
        let boundaryPlaintext = Data(repeating: 0, count: 16 * 4)
        let overflowPlaintext = Data(repeating: 0, count: 16 * 4 + 7)
        let overflowEngine = try HardwareAESCTR(key: SecureKey(key))
        let prefixes: [[UInt8]] = [
            Array(repeating: 0, count: 12),
            Array(repeating: 0xff, count: 12),
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98]
        ]

        for prefix in prefixes {
            let ivAtBoundary = Data(prefix + [0xff, 0xff, 0xff, 0xfc])
            let run = try overflowEngine.encrypt(
                boundaryPlaintext,
                mode: CTRMode(iv: AESIV(ivAtBoundary))
            )
            let expected = try encryptWithCommonCrypto(
                plaintext: boundaryPlaintext,
                key: key,
                iv: ivAtBoundary
            )
            guard run == expected else {
                throw ValidationError("inc32 boundary prefix")
            }

            let wrapped = try overflowEngine.encrypt(
                overflowPlaintext,
                mode: CTRMode(iv: AESIV(ivAtBoundary))
            )
            let wrappedReference = try encryptCounterBlocksIndividually(
                engine: overflowEngine,
                plaintext: overflowPlaintext,
                iv: ivAtBoundary
            )
            guard wrapped == wrappedReference else {
                throw ValidationError("inc32 wrap")
            }
            checks += 2
        }

        let streamIV = Data([UInt8](repeating: 0, count: 12) + [0xff, 0xff, 0xff, 0xfc])
        let stream = HardwareAESCTRStream(engine: overflowEngine, iv: try AESIV(streamIV))
        let streamPrefix = try stream.update(Data(boundaryPlaintext.prefix(35)))
        let streamRemainder = Data(boundaryPlaintext.dropFirst(35)) + Data(repeating: 0, count: 7)
        let streamOutput = try stream.update(streamRemainder)
        let streamReference = try overflowEngine.encrypt(
            Data(boundaryPlaintext.prefix(35)) + streamRemainder,
            mode: CTRMode(iv: AESIV(streamIV))
        )
        guard streamPrefix + streamOutput == streamReference else {
            throw ValidationError("stream inc32 wrap")
        }
        checks += 1
    }

    private func encryptCounterBlocksIndividually(
        engine: HardwareAESCTR,
        plaintext: Data,
        iv: Data
    ) throws -> Data {
        var result = Data()
        let blockCount = (plaintext.count + 15) / 16
        for block in 0..<blockCount {
            let start = block * 16
            let length = min(16, plaintext.count - start)
            let blockIV = incrementInc32(iv, by: UInt32(block))
            let input = Data(plaintext[start..<(start + length)])
            result.append(try engine.encrypt(input, mode: CTRMode(iv: AESIV(blockIV))))
        }
        return result
    }

    private func incrementInc32(_ iv: Data, by blocks: UInt32) -> Data {
        var result = iv
        let lowWord = UInt32(result[12]) << 24
            | UInt32(result[13]) << 16
            | UInt32(result[14]) << 8
            | UInt32(result[15])
        let next = lowWord &+ blocks
        result[12] = UInt8(truncatingIfNeeded: next >> 24)
        result[13] = UInt8(truncatingIfNeeded: next >> 16)
        result[14] = UInt8(truncatingIfNeeded: next >> 8)
        result[15] = UInt8(truncatingIfNeeded: next)
        return result
    }

    private func encryptWithCommonCrypto(plaintext: Data, key: Data, iv: Data) throws -> Data {
        guard !plaintext.isEmpty else { return Data() }
        var cryptor: CCCryptorRef?
        let status = key.withUnsafeBytes { keyBuffer in
            iv.withUnsafeBytes { ivBuffer in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt), CCMode(kCCModeCTR), CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding), ivBuffer.baseAddress, keyBuffer.baseAddress, key.count,
                    nil, 0, 0, CCModeOptions(kCCModeOptionCTR_BE), &cryptor
                )
            }
        }
        guard status == CCCryptorStatus(kCCSuccess), let cryptor else {
            throw ValidationError("CommonCrypto create")
        }
        defer { CCCryptorRelease(cryptor) }

        var output = Data(count: plaintext.count)
        var moved = 0
        let updateStatus = output.withUnsafeMutableBytes { outputBuffer in
            plaintext.withUnsafeBytes { inputBuffer in
                CCCryptorUpdate(cryptor, inputBuffer.baseAddress, plaintext.count,
                                outputBuffer.baseAddress, plaintext.count, &moved)
            }
        }
        guard updateStatus == CCCryptorStatus(kCCSuccess), moved == plaintext.count else {
            throw ValidationError("CommonCrypto update")
        }
        return output
    }
}

private struct ValidationError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

private struct SplitMix64 {
    private var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state &+= 0x9E3779B97F4A7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9
        z = (z ^ (z >> 27)) &* 0x94D049BB133111EB
        return z ^ (z >> 31)
    }
}
