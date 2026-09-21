import Foundation
import XCTest
@testable import HardwareAESCore
@testable import HardwareAESCTR
@testable import HardwareAESECB

final class HardwareAESECCTests: XCTestCase {

    // MARK: - NIST SP 800-38A F.1.1 AES-128-ECB Test Vector

    func testHardwareAESECB_NIST() throws {
        // NIST SP 800-38A F.1.1 — AES-128-ECB
        let keyData = Data([
            0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
            0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
        ])
        let plaintext = Data([
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
        ])
        let expected = Data([
            0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,
            0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97
        ])

        let key = try SecureKey(keyData)
        let engine = try HardwareAESECB(key: key)
        let ciphertext = try engine.encrypt(plaintext, mode: .ecb)

        XCTAssertEqual(ciphertext, expected, "NIST AES-128-ECB test vector mismatch")
    }

    // MARK: - Round-Trip Tests

    func testHardwareAESECB_RoundTrip() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESECB(key: key)

        let plaintext = Data(repeating: 0x41, count: 64)

        let ciphertext = try engine.encrypt(plaintext, mode: .ecb)
        XCTAssertNotEqual(ciphertext, plaintext)

        let decrypted = try engine.decrypt(ciphertext, mode: .ecb)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testHardwareAESECB_SingleBlock() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESECB(key: key)

        let plaintext = Data(repeating: 0x55, count: 16)

        let ciphertext = try engine.encrypt(plaintext, mode: .ecb)
        let decrypted = try engine.decrypt(ciphertext, mode: .ecb)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testHardwareAESECB_MultipleBlocks() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESECB(key: key)

        let sizes = [32, 48, 64, 128, 256, 1024]
        for size in sizes {
            let plaintext = Data(repeating: UInt8(size % 256), count: size)
            let ciphertext = try engine.encrypt(plaintext, mode: .ecb)
            let decrypted = try engine.decrypt(ciphertext, mode: .ecb)
            XCTAssertEqual(decrypted, plaintext, "Round-trip failed for \(size) bytes")
        }
    }

    func testHardwareAESECB_InvalidLength() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESECB(key: key)

        // Non-multiple of 16 should fail
        let plaintext = Data(repeating: 0x41, count: 17)
        XCTAssertThrowsError(try engine.encrypt(plaintext, mode: .ecb))
    }

    // MARK: - Async Tests

    func testHardwareAESECB_AsyncRoundTrip() async throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESECB(key: key)

        let plaintext = Data(repeating: 0x41, count: 64)

        let ciphertext = try await engine.encrypt(plaintext, mode: .ecb)
        let decrypted = try await engine.decrypt(ciphertext, mode: .ecb)
        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Protocol Conformance

    func testHardwareAESECB_ProtocolConformance() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine: any HardwareAESEngineProtocol = try HardwareAESECB(key: key)

        let plaintext = Data(repeating: 0x41, count: 32)
        let ciphertext = try engine.encrypt(plaintext, mode: .ecb)
        let decrypted = try engine.decrypt(ciphertext, mode: .ecb)
        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Identical Blocks (ECB weakness demo)

    func testHardwareAESECB_IdenticalBlocksProduceIdenticalCiphertext() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESECB(key: key)

        // Two identical blocks
        let plaintext = Data(repeating: 0x41, count: 32)

        let ciphertext = try engine.encrypt(plaintext, mode: .ecb)

        // In ECB, first 16 bytes of ciphertext should equal second 16 bytes
        let block1 = ciphertext.prefix(16)
        let block2 = ciphertext.suffix(16)
        XCTAssertEqual(block1, block2, "ECB produces identical ciphertext for identical blocks")
    }

    // MARK: - Performance

    func testPerformance_ECBEncryption() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let engine = try HardwareAESECB(key: key)
        let plaintext = Data(repeating: 0x41, count: 1024 * 1024)

        measure {
            _ = try? engine.encrypt(plaintext, mode: .ecb)
        }
    }
}
