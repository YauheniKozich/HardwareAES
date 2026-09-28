import Foundation
import XCTest
import HardwareAESCore
import HardwareAESCTR
import HardwareAESAuthenticated

final class HardwareAESSimulatorTests: XCTestCase {
    func testCTRMatchesNISTKnownAnswerVector() throws {
        let key = try SecureKey(Data([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ]))
        let counter = try AESIV(Data([
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
            0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
        ]))
        let plaintext = Data([
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
        ])
        let expected = Data([
            0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
            0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce
        ])
        let engine = try HardwareAESCTR(key: key)

        XCTAssertEqual(try engine.encrypt(plaintext, mode: CTRMode(iv: counter)), expected)
    }

    func testAuthenticatedContainerRejectsTamperingAndRoundTrips() async throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let vault = try SecureFileVault(key: key, nonceSequence: RandomAESNonceSequence())
        let plaintext = Data("simulator authenticated container".utf8)
        let container = try await vault.encrypt(plaintext)
        let decrypted = try await vault.decrypt(container)
        XCTAssertEqual(decrypted, plaintext)

        var tampered = container
        tampered[tampered.index(before: tampered.endIndex)] ^= 1
        do {
            _ = try await vault.decrypt(tampered)
            XCTFail("Modified tag must be rejected")
        } catch AESError.authenticationFailed {
        }
    }

    func testAuthenticatedContainerMatchesKnownAnswer() async throws {
        let key = try SecureKey(Data((0..<16).map(UInt8.init)))
        let nonce = try AESIV(Data([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        ]))
        let expected = Data([
            0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x21, 0xa5, 0x92, 0xbc, 0x1d, 0x1a, 0x76, 0x55,
            0x99, 0x88, 0xe4, 0xa0, 0x3b, 0xf5, 0x91, 0x7b,
            0x06, 0x10, 0x13, 0x0b, 0x10, 0x4e, 0x11, 0x87,
            0xd1, 0xb0, 0x3a, 0x6a, 0x74, 0x4f, 0xa1, 0xcc
        ])
        let vault = try SecureFileVault(key: key, nonceSequence: FixedNonceSequence(nonce: nonce))

        let sealed = try await vault.encrypt(Data("HardwareAES KAT!".utf8))
        XCTAssertEqual(sealed, expected)
    }

    func testFileNonceSequencePersistsAcrossInstances() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let stateURL = directory.appendingPathComponent("nonce.state")

        let first = try await FileAESNonceSequence(stateFileURL: stateURL).nextNonce()
        let second = try await FileAESNonceSequence(stateFileURL: stateURL).nextNonce()

        XCTAssertNotEqual(first, second)
        XCTAssertEqual(first.data.suffix(4), Data(repeating: 0, count: 4))
        XCTAssertEqual(second.data.suffix(4), Data(repeating: 0, count: 4))
    }
}

private struct FixedNonceSequence: AESNonceSequence {
    let nonce: AESIV

    func nextNonce() async throws -> AESIV { nonce }
}
