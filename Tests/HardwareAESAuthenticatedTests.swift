import Foundation
import XCTest
@testable import HardwareAESCore
@testable import HardwareAESAuthenticated

final class HardwareAESAuthenticatedTests: XCTestCase {
    func testFileNonceSequencePersistsAndSerializesMultipleInstances() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let stateURL = directory.appendingPathComponent("vault.nonce-state")
        let firstSequence = try FileAESNonceSequence(stateFileURL: stateURL)
        let secondSequence = try FileAESNonceSequence(stateFileURL: stateURL)
        let nonceData = try await withThrowingTaskGroup(of: Data.self) { group in
            for index in 0..<24 {
                let sequence = index.isMultiple(of: 2) ? firstSequence : secondSequence
                group.addTask {
                    let nonce = try await sequence.nextNonce()
                    return nonce.data
                }
            }

            var values: [Data] = []
            for try await value in group { values.append(value) }
            return values
        }

        XCTAssertEqual(Set(nonceData).count, 24)
        XCTAssertTrue(nonceData.allSatisfy { $0.suffix(4) == Data([0, 0, 0, 0]) })

        let relaunchedSequence = try FileAESNonceSequence(stateFileURL: stateURL)
        let afterRelaunch = try await relaunchedSequence.nextNonce().data
        XCTAssertFalse(Set(nonceData).contains(afterRelaunch))
    }

#if os(macOS)
    func testFileNonceSequenceCoordinatesSeparateProcesses() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let stateURL = directory.appendingPathComponent("shared.nonce-state")
        let resultURLs = [
            directory.appendingPathComponent("first.nonce"),
            directory.appendingPathComponent("second.nonce")
        ]
        let xcrunURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        let testBundleURL = Bundle(for: Self.self).bundleURL
        let worker = "HardwareAESAuthenticatedTests.HardwareAESAuthenticatedTests/testNonceSequenceProcessWorker"
        let processes = zip(resultURLs, 0..<resultURLs.count).map { resultURL, index -> Process in
            let process = Process()
            process.executableURL = xcrunURL
            process.arguments = ["xctest", "-XCTest", worker, testBundleURL.path]
            var environment = ProcessInfo.processInfo.environment
            environment["HAES_NONCE_STATE_PATH"] = stateURL.path
            environment["HAES_NONCE_RESULT_PATH"] = resultURL.path
            environment["HAES_NONCE_PROCESS_ID"] = String(index)
            process.environment = environment
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            return process
        }

        for process in processes { try process.run() }
        for process in processes { process.waitUntilExit() }
        XCTAssertTrue(processes.allSatisfy { $0.terminationStatus == 0 })

        let nonces = try resultURLs.map { try Data(contentsOf: $0) }
        XCTAssertEqual(nonces.count, 2)
        XCTAssertNotEqual(nonces[0], nonces[1])
    }

    func testNonceSequenceProcessWorker() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard let statePath = environment["HAES_NONCE_STATE_PATH"],
              let resultPath = environment["HAES_NONCE_RESULT_PATH"],
              environment["HAES_NONCE_PROCESS_ID"] != nil
        else { return }

        let sequence = try FileAESNonceSequence(stateFileURL: URL(fileURLWithPath: statePath))
        let nonce = try await sequence.nextNonce()
        try nonce.data.write(to: URL(fileURLWithPath: resultPath), options: .atomic)
    }
#endif

    func testFileNonceSequenceRejectsCorruptState() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let stateURL = directory.appendingPathComponent("vault.nonce-state")
        try Data("bad-state".utf8).write(to: stateURL)
        let sequence = try FileAESNonceSequence(stateFileURL: stateURL)

        do {
            _ = try await sequence.nextNonce()
            XCTFail("corrupted nonce state must be rejected")
        } catch AESNonceSequenceError.corruptedState {
        }
    }

    func testVaultsShareNonceSequenceForSameKey() async throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let sequence = IncrementingTestNonceSequence()
        let firstVault = try SecureFileVault(key: key, nonceSequence: sequence)
        let secondVault = try SecureFileVault(key: key, nonceSequence: sequence)

        let first = try await firstVault.encrypt(Data("first".utf8))
        let second = try await secondVault.encrypt(Data("second".utf8))

        XCTAssertNotEqual(Data(first[1..<17]), Data(second[1..<17]))
        let firstPlaintext = try await firstVault.decrypt(first)
        let secondPlaintext = try await secondVault.decrypt(second)
        XCTAssertEqual(firstPlaintext, Data("first".utf8))
        XCTAssertEqual(secondPlaintext, Data("second".utf8))
    }

    func testAESCMAC_RFC4493KnownAnswerVectors() throws {
        let key = try SecureKey(Data([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        ]))
        let cmac = try AESCMAC(key: key)
        let message = Data([
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
            0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
            0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
            0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
            0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
        ])
        let vectors: [(Data, Data)] = [
            (Data(), Data([0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75, 0x67, 0x46])),
            (Data(message.prefix(16)), Data([0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c])),
            (Data(message.prefix(40)), Data([0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27])),
            (message, Data([0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92, 0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe]))
        ]

        for (message, expected) in vectors {
            XCTAssertEqual(try cmac.tag(for: message), expected)
        }
    }

    func testSecureFileVaultKnownAnswerVector() async throws {
        // Independent reference: Python cryptography AES-CTR and AES-CMAC.
        let key = try SecureKey(Data((0..<16).map(UInt8.init)))
        let nonce = try AESIV(Data([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
        ]))
        let plaintext = Data("HardwareAES KAT!".utf8)
        let expectedPackage = Data([
            0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x21, 0xa5, 0x92, 0xbc, 0x1d, 0x1a, 0x76, 0x55,
            0x99, 0x88, 0xe4, 0xa0, 0x3b, 0xf5, 0x91, 0x7b,
            0x06, 0x10, 0x13, 0x0b, 0x10, 0x4e, 0x11, 0x87,
            0xd1, 0xb0, 0x3a, 0x6a, 0x74, 0x4f, 0xa1, 0xcc
        ])
        let vault = try SecureFileVault(key: key, nonceSequence: FixedTestNonceSequence(nonce: nonce))

        let package = try await vault.encrypt(plaintext)
        XCTAssertEqual(package, expectedPackage)
        let decrypted = try await vault.decrypt(expectedPackage)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testRoundTripIncludingEmptyPlaintext() async throws {
        let vault = try SecureFileVault(key: SecureKey(Data(repeating: 0x42, count: 16)), nonceSequence: RandomAESNonceSequence())
        let empty = try await vault.encrypt(Data())
        let emptyPlaintext = try await vault.decrypt(empty)
        XCTAssertEqual(emptyPlaintext, Data())
        let plaintext = Data((0..<257).map { UInt8($0 & 0xff) })
        let package = try await vault.encrypt(plaintext)
        let decrypted = try await vault.decrypt(package)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testConcurrentDecryptionsShareImmutableVaultStateSafely() async throws {
        let plaintext = Data((0..<4096).map { UInt8(truncatingIfNeeded: $0) })
        let vault = try SecureFileVault(
            key: SecureKey(Data(repeating: 0x42, count: 16)),
            nonceSequence: RandomAESNonceSequence()
        )
        let package = try await vault.encrypt(plaintext)

        let results = try await withThrowingTaskGroup(of: Data.self) { group in
            for _ in 0..<16 {
                group.addTask { try await vault.decrypt(package) }
            }
            var values: [Data] = []
            for try await value in group { values.append(value) }
            return values
        }

        XCTAssertEqual(results.count, 16)
        XCTAssertTrue(results.allSatisfy { $0 == plaintext })
    }

    func testTamperingAndWrongKeyFailBeforeDecrypt() async throws {
        let vault = try SecureFileVault(key: SecureKey(Data(repeating: 0x42, count: 16)), nonceSequence: RandomAESNonceSequence())
        let package = try await vault.encrypt(Data("secret".utf8))
        for index in [0, 1, 17, package.count - 17, package.count - 1] {
            var tampered = package
            tampered[index] ^= 1
            do {
                _ = try await vault.decrypt(tampered)
                XCTFail("tampering at \(index) was accepted")
            } catch AESError.authenticationFailed {}
        }
        var appended = package
        appended.append(0)
        do {
            _ = try await vault.decrypt(appended)
            XCTFail("an appended byte was accepted")
        } catch AESError.authenticationFailed {}
        let wrong = try SecureFileVault(key: SecureKey(Data(repeating: 0x43, count: 16)), nonceSequence: RandomAESNonceSequence())
        do {
            _ = try await wrong.decrypt(package)
            XCTFail("wrong key was accepted")
        } catch AESError.authenticationFailed {
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    func testTruncatedPackageFails() async throws {
        let vault = try SecureFileVault(key: SecureKey(Data(repeating: 0x42, count: 16)), nonceSequence: RandomAESNonceSequence())
        let package = try await vault.encrypt(Data([1, 2, 3]))
        for length in 0..<package.count {
            do {
                _ = try await vault.decrypt(Data(package.prefix(length)))
                XCTFail("truncated package at length \(length) was accepted")
            } catch AESError.authenticationFailed {
            } catch {
                XCTFail("unexpected error at length \(length): \(error)")
            }
        }
    }
}

private actor IncrementingTestNonceSequence: AESNonceSequence {
    private var nextValue: UInt32 = 0

    func nextNonce() throws -> AESIV {
        defer { nextValue &+= 1 }
        let value = nextValue
        let bytes = [
            UInt8(truncatingIfNeeded: value >> 24),
            UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8),
            UInt8(truncatingIfNeeded: value)
        ]
        return try AESIV(Data(repeating: 0, count: 12) + Data(bytes))
    }
}

private struct FixedTestNonceSequence: AESNonceSequence {
    let nonce: AESIV

    func nextNonce() async throws -> AESIV { nonce }
}
