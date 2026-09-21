import Foundation
import XCTest
import Darwin
import CommonCrypto
import HardwareAESASM
@testable import HardwareAESCore
@testable import HardwareAESCTR

final class HardwareAESCTRTests: XCTestCase {
    
    // MARK: - CTR Mode Tests
    
    func testCTRMode_Init() throws {
        let iv = Data(repeating: 0x01, count: 16)
        let mode = try CTRMode(iv: iv)
        XCTAssertEqual(mode.iv.data.count, 16)
    }
    
    func testCTRMode_InvalidIV() {
        XCTAssertThrowsError(try CTRMode(iv: Data(repeating: 0x01, count: 12))) { error in
            XCTAssertEqual(error as? AESError, .invalidIVLength)
        }
    }
    
    // MARK: - HardwareAESCTR Tests
    
    func testHardwareAESCTR_Init() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESCTR(key: key)
        XCTAssertNotNil(engine)
    }
    
    func testHardwareAESCTR_EncryptDecrypt() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESCTR(key: key)
        let mode = try CTRMode(iv: Data(repeating: 0x01, count: 16))
        
        let plaintext = Data(repeating: 0x41, count: 32)
        
        let ciphertext = try engine.encrypt(plaintext, mode: mode)
        XCTAssertNotEqual(ciphertext, plaintext)
        
        let decrypted = try engine.decrypt(ciphertext, mode: mode)
        XCTAssertEqual(decrypted, plaintext)
    }
    
    func testHardwareAESCTR_NISTSelfTest() {
        // NIST F.5.1 AES-128 CTR test vector
        let keyData = Data([0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c])
        let pt = Data([0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a])
        let iv = Data([0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff])
        let expected = Data([0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce])
        
        do {
            let engine = try HardwareAESCTR(key: SecureKey(keyData))
            let mode = try CTRMode(iv: iv)
            let ct = try engine.encrypt(pt, mode: mode)

            XCTAssertTrue(ct == expected, "NIST CTR test should pass")
        } catch {
            XCTFail("NIST CTR test failed with error: \(error)")
        }
    }

    func testHardwareAESCTR_RunNISTSelfTest() {
        XCTAssertTrue(HardwareAESCTR.runNISTSelfTest())
    }
    
    // MARK: - Protocol Conformance Tests
    
    func testHardwareAESCTR_ProtocolConformance() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine: any HardwareAESEngineProtocol = try HardwareAESCTR(key: key)
        let mode = try AESMode.ctrMode(iv: Data(repeating: 0x01, count: 16))
        
        let plaintext = Data(repeating: 0x41, count: 16)
        let ciphertext = try engine.encrypt(plaintext, mode: mode)
        let decrypted = try engine.decrypt(ciphertext, mode: mode)
        
        XCTAssertEqual(decrypted, plaintext)
    }
    
    // MARK: - Async/Await Tests
    
    func testHardwareAESCTR_AsyncEncryptDecrypt() async throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESCTR(key: key)
        let mode = try CTRMode(iv: Data(repeating: 0x01, count: 16))
        
        let plaintext = Data(repeating: 0x41, count: 32)
        
        let ciphertext = try await engine.encrypt(plaintext, mode: mode)
        XCTAssertNotEqual(ciphertext, plaintext)
        
        let decrypted = try await engine.decrypt(ciphertext, mode: mode)
        XCTAssertEqual(decrypted, plaintext)
    }
    
    func testHardwareAESCTR_AsyncProtocolConformance() async throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine: any HardwareAESEngineProtocol = try HardwareAESCTR(key: key)
        let mode = try AESMode.ctrMode(iv: Data(repeating: 0x01, count: 16))

        let plaintext = Data(repeating: 0x41, count: 16)
        
        // Use Task to ensure async execution
        let ciphertext = try await Task.detached { @Sendable in
            try await engine.encrypt(plaintext, mode: mode)
        }.value
        
        let decrypted = try await Task.detached { @Sendable in
            try await engine.decrypt(ciphertext, mode: mode)
        }.value

        XCTAssertEqual(decrypted, plaintext)
    }
    
    // MARK: - Arbitrary Length Tests (No Padding Required)
    
    func testHardwareAESCTR_ArbitraryLength() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESCTR(key: key)
        let mode = try CTRMode(iv: Data(repeating: 0x01, count: 16))
        
        // Test various lengths (not multiples of 16)
        let testLengths = [1, 7, 15, 17, 31, 100, 1000]
        
        for length in testLengths {
            let plaintext = Data(repeating: 0x41, count: length)
            
            let ciphertext = try engine.encrypt(plaintext, mode: mode)
            XCTAssertEqual(ciphertext.count, length, "Ciphertext length should match plaintext for length \(length)")
            
            let decrypted = try engine.decrypt(ciphertext, mode: mode)
            XCTAssertEqual(decrypted, plaintext, "Round-trip should work for length \(length)")
        }
    }
    
    func testHardwareAESCTR_SingleByte() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESCTR(key: key)
        let mode = try CTRMode(iv: Data(repeating: 0x01, count: 16))
        
        let plaintext = Data([0x42])  // Single byte
        
        let ciphertext = try engine.encrypt(plaintext, mode: mode)
        XCTAssertEqual(ciphertext.count, 1)
        
        let decrypted = try engine.decrypt(ciphertext, mode: mode)
        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - 4-Way Interleaving Tests

    func testFourWayInterleaving_MultipleOf4Blocks() throws {
        // Test exactly 4 blocks (64 bytes) - uses 4-way interleaving
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESCTR(key: key)
        let mode = try CTRMode(iv: Data(repeating: 0x01, count: 16))

        let plaintext = Data(repeating: 0x41, count: 64)
        let ciphertext = try engine.encrypt(plaintext, mode: mode)
        let decrypted = try engine.decrypt(ciphertext, mode: mode)

        XCTAssertEqual(decrypted, plaintext, "4-block (64 bytes) round-trip failed")
    }

    func testFourWayInterleaving_RemainderCases() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESCTR(key: key)
        let mode = try CTRMode(iv: Data(repeating: 0x01, count: 16))

        // Test 65 bytes (4 blocks + 1 byte remainder)
        let plaintext65 = Data(repeating: 0x41, count: 65)
        let ciphertext65 = try engine.encrypt(plaintext65, mode: mode)
        let decrypted65 = try engine.decrypt(ciphertext65, mode: mode)
        XCTAssertEqual(decrypted65, plaintext65, "65 bytes round-trip failed")

        // Test 127 bytes (7 blocks + 15 bytes remainder)
        let plaintext127 = Data(repeating: 0x42, count: 127)
        let ciphertext127 = try engine.encrypt(plaintext127, mode: mode)
        let decrypted127 = try engine.decrypt(ciphertext127, mode: mode)
        XCTAssertEqual(decrypted127, plaintext127, "127 bytes round-trip failed")

        // Test 129 bytes (8 blocks + 1 byte remainder)
        let plaintext129 = Data(repeating: 0x43, count: 129)
        let ciphertext129 = try engine.encrypt(plaintext129, mode: mode)
        let decrypted129 = try engine.decrypt(ciphertext129, mode: mode)
        XCTAssertEqual(decrypted129, plaintext129, "129 bytes round-trip failed")
    }

    func testFourWayInterleaving_AllSizes() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESCTR(key: key)
        let mode = try CTRMode(iv: Data(repeating: 0x01, count: 16))

        // Test sizes that exercise different code paths:
        // - < 16 bytes: partial block only
        // - 16-63 bytes: 1-3 blocks + remainder
        // - 64 bytes: exactly 4 blocks (pure 4-way)
        // - 65+ bytes: 4-way + remainder
        let testSizes = [1, 7, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65, 127, 128, 129, 255, 256, 1024]

        for size in testSizes {
            let plaintext = Data(repeating: UInt8(size % 256), count: size)
            let ciphertext = try engine.encrypt(plaintext, mode: mode)
            let decrypted = try engine.decrypt(ciphertext, mode: mode)

            XCTAssertEqual(decrypted, plaintext, "Round-trip failed for size \(size) bytes")
        }
    }

    // MARK: - Performance Tests

    func testPerformance_CTREncryption() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESCTR(key: key)
        let mode = try CTRMode(iv: Data(repeating: 0x01, count: 16))
        let plaintext = Data(repeating: 0x41, count: 1024 * 1024)  // 1MB

        measure {
            _ = try? engine.encrypt(plaintext, mode: mode)
        }
    }
    
    // MARK: - Hardening and Differential Tests
    
    func testAllTailSizesRoundTrip() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESCTR(key: key)
        let iv = try AESIV(Data(repeating: 0x01, count: 16))
        let mode = CTRMode(iv: iv)

        for size in 0...64 {
            let plaintext = Data((0..<size).map { UInt8($0 & 0xff) })
            let ciphertext = try engine.encrypt(plaintext, mode: mode)
            XCTAssertEqual(ciphertext.count, size, "size=\(size)")
            XCTAssertEqual(try engine.decrypt(ciphertext, mode: mode), plaintext, "size=\(size)")
        }
    }

    func testInPlaceMatchesOutOfPlace() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESCTR(key: key)
        let iv = try AESIV(Data(repeating: 0x01, count: 16))
        let mode = CTRMode(iv: iv)

        for size in [0, 1, 15, 16, 17, 31, 32, 33, 64, 100, 128, 129, 1000, 4096, 65536] {
            let plaintext = Data((0..<size).map { UInt8($0 & 0xff) })
            let outOfPlace = try engine.encrypt(plaintext, mode: mode)
            var inPlace = plaintext
            try inPlace.withUnsafeMutableBytes { buffer in
                try engine.encryptInPlace(buffer: buffer, iv: iv.data)
            }
            XCTAssertEqual(inPlace, outOfPlace, "size=\(size)")
        }
    }

    func testCounterOverflow() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESCTR(key: key)

        var ivMaxMinusOne = Data(repeating: 0, count: 16)
        ivMaxMinusOne[12] = 0xff
        ivMaxMinusOne[13] = 0xff
        ivMaxMinusOne[14] = 0xff
        ivMaxMinusOne[15] = 0xfe
        var ivMax = Data(repeating: 0, count: 16)
        ivMax[12] = 0xff
        ivMax[13] = 0xff
        ivMax[14] = 0xff
        ivMax[15] = 0xff
        let ivZero = try AESIV(Data(repeating: 0, count: 16))
        let twoBlocks = Data(repeating: 0, count: 32)

        let ctMaxMinusOne = try engine.encrypt(twoBlocks, mode: CTRMode(iv: try AESIV(ivMaxMinusOne)))
        let ctFromMax = try engine.encrypt(twoBlocks, mode: CTRMode(iv: try AESIV(ivMax)))
        let ctZero = try engine.encrypt(Data(repeating: 0, count: 16), mode: CTRMode(iv: ivZero))

        XCTAssertNotEqual(ctMaxMinusOne.suffix(16), ctZero, "Counter wrapped too early")
        XCTAssertEqual(ctFromMax.suffix(16), ctZero, "Counter did not wrap at 2^32")
    }

    func testCounterWrapAtEveryPositionInsideWideBatches() throws {
        let keyData = Data(repeating: 0x42, count: 16)
        let engine = try HardwareAESCTR(key: SecureKey(keyData))
        let prefix = Data((0..<12).map { UInt8(0xA0 + $0) })
        let wrappedIV = prefix + Data(repeating: 0, count: 4)

        for blocksBeforeWrap in 1...20 {
            let low32 = UInt32(0) &- UInt32(blocksBeforeWrap)
            let ivData = prefix + Data([24, 16, 8, 0].map {
                UInt8(truncatingIfNeeded: low32 >> $0)
            })

            for length in [8 * 16 * 3 + 5, 1024] {
                let plaintext = Data((0..<length).map {
                    UInt8(truncatingIfNeeded: $0 &* 31 &+ 7)
                })
                let ours = try engine.encrypt(
                    plaintext,
                    mode: CTRMode(iv: try AESIV(ivData))
                )

                let split = min(length, blocksBeforeWrap * 16)
                let expected = try encryptWithCommonCrypto(
                    plaintext: Data(plaintext.prefix(split)),
                    key: keyData,
                    iv: ivData
                ) + encryptWithCommonCrypto(
                    plaintext: Data(plaintext.dropFirst(split)),
                    key: keyData,
                    iv: wrappedIV
                )

                XCTAssertEqual(
                    ours,
                    expected,
                    "blocksBeforeWrap=\(blocksBeforeWrap), length=\(length)"
                )
            }
        }
    }

    func testGuardPageBoundaries() throws {
        let keyData = Data(repeating: 0x42, count: 16)
        let ivData = Data((0..<16).map { UInt8($0) })
        let engine = try HardwareAESCTR(key: SecureKey(keyData))

        for size in [1, 15, 16, 17, 127, 128, 129, 3 * 8 * 16 + 5, 1024] {
            let input = GuardedBuffer(count: size)
            let output = GuardedBuffer(count: size)

            for index in 0..<size {
                input.base.storeBytes(
                    of: UInt8(truncatingIfNeeded: index &* 31 &+ 7),
                    toByteOffset: index,
                    as: UInt8.self
                )
                output.base.storeBytes(of: 0, toByteOffset: index, as: UInt8.self)
            }

            try engine.encrypt(
                input: UnsafeRawBufferPointer(start: input.base, count: size),
                output: UnsafeMutableRawBufferPointer(start: output.base, count: size),
                iv: ivData
            )

            let plaintext = Data(bytes: input.base, count: size)
            let expected = try encryptWithCommonCrypto(
                plaintext: plaintext,
                key: keyData,
                iv: ivData
            )
            XCTAssertEqual(
                Data(bytes: output.base, count: size),
                expected,
                "guard-page boundary size=\(size)"
            )
        }
    }

    func testCSideKnownAnswerTests() {
        XCTAssertEqual(haes_aes128_ctr_kat(), 1)
        XCTAssertEqual(haes_aes128_ecb_kat(), 1)
        XCTAssertEqual(haes_aes128_ctr_overflow_test(), 1)
    }

    func testDifferentialVsCommonCrypto() throws {
        let key = Data(repeating: 0x42, count: 16)
        let engine = try HardwareAESCTR(key: SecureKey(key))
        let iv = try AESIV(Data((0..<16).map { UInt8($0) }))
        let mode = CTRMode(iv: iv)

        for size in [1, 15, 16, 17, 31, 32, 33, 64, 1000, 4096, 65536, 1024 * 1024] {
            let plaintext = Data((0..<size).map { UInt8($0 & 0xff) })
            let ours = try engine.encrypt(plaintext, mode: mode)
            var commonCryptoOutput = Data(count: size)
            var cryptor: CCCryptorRef?

            let createStatus = key.withUnsafeBytes { keyBuffer in
                iv.data.withUnsafeBytes { ivBuffer in
                    CCCryptorCreateWithMode(
                        CCOperation(kCCEncrypt),
                        CCMode(kCCModeCTR),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCPadding(ccNoPadding),
                        ivBuffer.baseAddress,
                        keyBuffer.baseAddress,
                        key.count,
                        nil,
                        0,
                        0,
                        CCModeOptions(kCCModeOptionCTR_BE),
                        &cryptor
                    )
                }
            }
            XCTAssertEqual(createStatus, CCCryptorStatus(kCCSuccess))
            guard let cryptor else {
                XCTFail("CommonCrypto failed to create CTR cryptor")
                continue
            }

            var moved = 0
            let updateStatus = commonCryptoOutput.withUnsafeMutableBytes { outputBuffer in
                plaintext.withUnsafeBytes { plaintextBuffer in
                    CCCryptorUpdate(
                        cryptor,
                        plaintextBuffer.baseAddress,
                        size,
                        outputBuffer.baseAddress,
                        size,
                        &moved
                    )
                }
            }
            CCCryptorRelease(cryptor)

            XCTAssertEqual(updateStatus, CCCryptorStatus(kCCSuccess))
            XCTAssertEqual(moved, size)
            XCTAssertEqual(ours, commonCryptoOutput, "size=\(size)")
        }
    }
    
    func testDifferentialVsCommonCryptoRandomized() throws {
        let boundarySizes = [
            0, 1, 15, 16, 17, 31, 32, 33,
            63, 64, 65, 127, 128, 129,
            255, 256, 257, 1023, 1024, 1025,
            4095, 4096
        ]
        let largeSizes = [64 * 1024, 1024 * 1024, 4 * 1024 * 1024]

        var state: UInt64 = 0x9e3779b97f4a7c15
        func nextByte() -> UInt8 {
            state ^= state << 7
            state ^= state >> 9
            state ^= state << 8
            return UInt8(truncatingIfNeeded: state >> 32)
        }

        let sizes = boundarySizes + (0..<32).map { _ in
            Int(nextByte()) % 4097
        } + largeSizes

        for size in sizes {
            let keyData = Data((0..<16).map { _ in nextByte() })
            let ivData = Data((0..<16).map { _ in nextByte() })
            let plaintext = Data((0..<size).map { _ in nextByte() })

            let engine = try HardwareAESCTR(key: SecureKey(keyData))
            let iv = try AESIV(ivData)
            let ours = try engine.encrypt(plaintext, mode: CTRMode(iv: iv))
            let reference = try encryptWithCommonCrypto(
                plaintext: plaintext,
                key: keyData,
                iv: ivData
            )

            XCTAssertEqual(ours, reference, "randomized size=\(size)")
        }
    }


    
    func testDifferentialWithUnalignedBuffersAndInPlace() throws {
        let keyData = Data(repeating: 0x42, count: 16)
        let ivData = Data((0..<16).map { UInt8($0) })
        let engine = try HardwareAESCTR(key: SecureKey(keyData))

        for size in [0, 1, 15, 16, 17, 127, 128, 129, 4095, 4096, 4097] {
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
            if size > 0 {
                memcpy(inPlace, input, size)
            }

            try engine.encrypt(
                input: UnsafeRawBufferPointer(start: input, count: size),
                output: UnsafeMutableRawBufferPointer(start: output, count: size),
                iv: ivData
            )
            try engine.encryptInPlace(
                buffer: UnsafeMutableRawBufferPointer(start: inPlace, count: size),
                iv: ivData
            )

            let plaintext = Data(bytes: input, count: size)
            let expected = try encryptWithCommonCrypto(
                plaintext: plaintext,
                key: keyData,
                iv: ivData
            )
            XCTAssertEqual(Data(bytes: output, count: size), expected, "unaligned out-of-place size=\(size)")
            XCTAssertEqual(Data(bytes: inPlace, count: size), expected, "unaligned in-place size=\(size)")
        }
    }

    func testSegmentedProcessingMatchesSinglePass() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let ivData = Data((0..<16).map { UInt8($0) })
        let iv = try AESIV(ivData)
        let engine = try HardwareAESCTR(key: key)

        let segmentPairs = [
            (0, 0), (1, 1), (15, 1), (16, 1), (17, 15),
            (31, 33), (63, 65), (127, 129), (128, 1),
            (129, 127), (255, 257), (1023, 1025)
        ]

        for (firstLength, secondLength) in segmentPairs {
            let first = Data((0..<firstLength).map { UInt8($0 & 0xff) })
            let second = Data((0..<secondLength).map { UInt8(($0 + 91) & 0xff) })
            let combined = first + second

            let singlePass = try engine.encrypt(
                combined,
                mode: CTRMode(iv: iv)
            )
            let stream = HardwareAESCTRStream(engine: engine, iv: try AESIV(ivData))
            let firstCiphertext = try stream.update(first)
            let secondCiphertext = try stream.update(second)

            XCTAssertEqual(
                firstCiphertext + secondCiphertext,
                singlePass,
                "segments=\(firstLength)+\(secondLength)"
            )
        }
    }

    func testCounterOverflowPreservesInc32Prefix() throws {
        let keyData = Data(repeating: 0x42, count: 16)
        let engine = try HardwareAESCTR(key: SecureKey(keyData))
        let prefixes: [[UInt8]] = [
            Array(repeating: 0x00, count: 12),
            Array(repeating: 0xff, count: 12),
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
             0xfe, 0xdc, 0xba, 0x98]
        ]

        for prefix in prefixes {
            for start in [0xfc, 0xfd, 0xfe, 0xff] {
                let ivBytes: [UInt8] = prefix + [0xff, 0xff, 0xff, UInt8(start)]
                let ivData = Data(ivBytes)
                let plaintext = Data(repeating: 0, count: 16 * 4 + 7)
                let ours = try engine.encrypt(
                    plaintext,
                    mode: CTRMode(iv: try AESIV(ivData))
                )
                let blocksBeforeWrap = 0x100 - start
                let commonLength = min(plaintext.count, blocksBeforeWrap * 16)
                let reference = try encryptWithCommonCrypto(
                    plaintext: Data(plaintext.prefix(commonLength)),
                    key: keyData,
                    iv: ivData
                )
                XCTAssertEqual(
                    Data(ours.prefix(commonLength)),
                    reference,
                    "pre-wrap prefix=\(prefix), start=\(start)"
                )

                var expected = Data()
                for block in 0..<(plaintext.count + 15) / 16 {
                    let blockIV = incrementCTR(ivData, byBlocks: block)
                    let blockLength = min(16, plaintext.count - block * 16)
                    let blockOutput = try engine.encrypt(
                        Data(repeating: 0, count: blockLength),
                        mode: CTRMode(iv: try AESIV(blockIV))
                    )
                    expected.append(blockOutput)
                }
                XCTAssertEqual(ours, expected, "inc32 prefix=\(prefix), start=\(start)")
                
                let firstLength = start == 0xff ? 16 : 16 * 2 + 3
                let first = plaintext.prefix(firstLength)
                let second = plaintext.dropFirst(firstLength)
                let stream = HardwareAESCTRStream(engine: engine, iv: try AESIV(ivData))
                let firstCiphertext = try stream.update(Data(first))
                let secondCiphertext = try stream.update(Data(second))
                XCTAssertEqual(
                    firstCiphertext + secondCiphertext,
                    ours,
                    "segmented overflow prefix=\(prefix), start=\(start)"
                )
            }
        }
    }

    private func incrementCTR(_ iv: Data, byBlocks blocks: Int) -> Data {
        var result = iv
        var value = UInt64(result[12]) << 24
            | UInt64(result[13]) << 16
            | UInt64(result[14]) << 8
            | UInt64(result[15])
        value = (value + UInt64(blocks)) & 0xffff_ffff
        result[12] = UInt8((value >> 24) & 0xff)
        result[13] = UInt8((value >> 16) & 0xff)
        result[14] = UInt8((value >> 8) & 0xff)
        result[15] = UInt8(value & 0xff)
        return result
    }

    private enum CommonCryptoError: Error {
        case create(CCCryptorStatus)
        case update(CCCryptorStatus)
        case outputSizeMismatch
    }

    private func encryptWithCommonCrypto(
        plaintext: Data,
        key: Data,
        iv: Data
    ) throws -> Data {
        guard !plaintext.isEmpty else { return Data() }

        var cryptor: CCCryptorRef?
        let createStatus = key.withUnsafeBytes { keyBuffer in
            iv.withUnsafeBytes { ivBuffer in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt),
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivBuffer.baseAddress,
                    keyBuffer.baseAddress,
                    key.count,
                    nil,
                    0,
                    0,
                    CCModeOptions(kCCModeOptionCTR_BE),
                    &cryptor
                )
            }
        }
        guard createStatus == CCCryptorStatus(kCCSuccess),
              let cryptor else {
            throw CommonCryptoError.create(createStatus)
        }
        defer { CCCryptorRelease(cryptor) }

        var output = Data(count: plaintext.count)
        var moved = 0
        let updateStatus = output.withUnsafeMutableBytes { outputBuffer in
            plaintext.withUnsafeBytes { inputBuffer in
                CCCryptorUpdate(
                    cryptor,
                    inputBuffer.baseAddress,
                    plaintext.count,
                    outputBuffer.baseAddress,
                    plaintext.count,
                    &moved
                )
            }
        }
        guard updateStatus == CCCryptorStatus(kCCSuccess) else {
            throw CommonCryptoError.update(updateStatus)
        }
        guard moved == plaintext.count else {
            throw CommonCryptoError.outputSizeMismatch
        }
        return output
    }

}

private final class GuardedBuffer {
    let base: UnsafeMutableRawPointer
    let count: Int

    private let mapping: UnsafeMutableRawPointer
    private let mappingSize: Int

    init(count: Int) {
        let page = Int(getpagesize())
        let dataPages = max(1, (count + page - 1) / page)
        mappingSize = (dataPages + 1) * page

        guard let mapped = mmap(
            nil,
            mappingSize,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0
        ), mapped != UnsafeMutableRawPointer(bitPattern: -1) else {
            fatalError("mmap failed")
        }

        let guardPage = mapped + dataPages * page
        precondition(mprotect(guardPage, page, PROT_NONE) == 0)

        mapping = mapped
        self.count = count
        base = guardPage - count
    }

    deinit {
        munmap(mapping, mappingSize)
    }
}
