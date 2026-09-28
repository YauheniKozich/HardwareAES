import Foundation
import XCTest
@testable import HardwareAESCore

final class HardwareAESCoreTests: XCTestCase {

    private struct SynchronousEngine: HardwareAESEngineProtocol {
        func encrypt(_ plaintext: Data, mode: AESMode) throws -> Data { plaintext }
        func decrypt(_ ciphertext: Data, mode: AESMode) throws -> Data { ciphertext }
    }
    
    // MARK: - SecureKey Tests
    
    func testSecureKey_AcceptsAES128Only() throws {
        let key128 = try SecureKey(Data(repeating: 0x42, count: 16))
        XCTAssertEqual(key128.size, .bits128)
    }
    
    func testSecureKey_InvalidLength() {
        for length in [0, 8, 15, 24, 32] {
            XCTAssertThrowsError(try SecureKey(Data(repeating: 0x42, count: length))) { error in
                XCTAssertEqual(error as? AESError, .invalidKeyLength)
            }
        }
    }
    
    func testSecureKey_DescriptionDoesNotExposeKeyMaterial() throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        XCTAssertEqual(key.description, "SecureKey(128-bit)")
        XCTAssertFalse(key.description.contains("42"))
    }
    
    func testSecureKey_ConstantTimeEquality() throws {
        let key1 = try SecureKey(Data(repeating: 0x42, count: 16))
        let key2 = try SecureKey(Data(repeating: 0x42, count: 16))
        let key3 = try SecureKey(Data([0x42] + Array(repeating: 0x43, count: 15)))
        
        XCTAssertEqual(key1, key2)
        XCTAssertNotEqual(key1, key3)
    }
    
    // MARK: - AESIV Tests
    
    func testAESIV_StandardInit() throws {
        let iv = try AESIV(Data(repeating: 0x01, count: 16))
        XCTAssertEqual(iv.data.count, 16)
    }
    
    func testAESIV_InvalidLength() {
        XCTAssertThrowsError(try AESIV(Data(repeating: 0x01, count: 12))) { error in
            XCTAssertEqual(error as? AESError, .invalidIVLength)
        }
    }
    
    // MARK: - MockHardwareAESEngine Tests
    
    func testMockHardwareAESEngine() throws {
        let mock = MockHardwareAESEngine()
        
        let expectedOutput = Data(repeating: 0x55, count: 16)
        mock.encryptHandler = { data, mode in
            XCTAssertEqual(data.count, 16)
            return expectedOutput
        }
        
        let result = try mock.encrypt(Data(repeating: 0x41, count: 16), mode: .ctr(iv: try AESIV(Data(repeating: 0x01, count: 16))))
        XCTAssertEqual(result, expectedOutput)
        XCTAssertEqual(mock.encryptCallCount, 1)
        XCTAssertEqual(mock.decryptCallCount, 0)
    }

    func testSynchronousEngineUsesDefaultAsyncProtocolAdapters() async throws {
        let engine = SynchronousEngine()
        let payload = Data([0x01, 0x02, 0x03])
        let mode = AESMode.ctr(iv: try AESIV(Data(repeating: 0, count: 16)))

        let encrypted = try await engine.encrypt(payload, mode: mode)
        let decrypted = try await engine.decrypt(payload, mode: mode)
        XCTAssertEqual(encrypted, payload)
        XCTAssertEqual(decrypted, payload)
    }

    func testMockCountersRemainConsistentForConcurrentCalls() throws {
        let mock = MockHardwareAESEngine()
        let mode = AESMode.ctr(iv: try AESIV(Data(repeating: 0, count: 16)))

        DispatchQueue.concurrentPerform(iterations: 128) { _ in
            _ = try? mock.encrypt(Data([0x01]), mode: mode)
        }

        XCTAssertEqual(mock.encryptCallCount, 128)
        XCTAssertEqual(mock.decryptCallCount, 0)
    }

    func testMockHandlerCanChangeDuringConcurrentCalls() throws {
        let mock = MockHardwareAESEngine()
        let mode = AESMode.ctr(iv: try AESIV(Data(repeating: 0, count: 16)))

        DispatchQueue.concurrentPerform(iterations: 64) { index in
            mock.encryptHandler = { _, _ in Data([UInt8(truncatingIfNeeded: index)]) }
            _ = try? mock.encrypt(Data(), mode: mode)
        }

        XCTAssertEqual(mock.encryptCallCount, 64)
    }

}
