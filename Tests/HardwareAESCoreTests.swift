import Foundation
import XCTest
@testable import HardwareAESCore

final class HardwareAESCoreTests: XCTestCase {
    
    // MARK: - SecureKey Tests
    
    func testSecureKey_ValidLengths() throws {
        // 16 bytes (AES-128)
        let key128 = try SecureKey(Data(repeating: 0x42, count: 16))
        XCTAssertEqual(key128.size, .bits128)
        
        // 24 bytes (AES-192)
        let key192 = try SecureKey(Data(repeating: 0x42, count: 24))
        XCTAssertEqual(key192.size, .bits192)
        
        // 32 bytes (AES-256)
        let key256 = try SecureKey(Data(repeating: 0x42, count: 32))
        XCTAssertEqual(key256.size, .bits256)
    }
    
    func testSecureKey_InvalidLength() {
        XCTAssertThrowsError(try SecureKey(Data(repeating: 0x42, count: 8))) { error in
            XCTAssertEqual(error as? AESError, .invalidKeyLength)
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
    
    func testAESIV_GCMNonce() throws {
        let nonce = try AESIV.gcmNonce(Data(repeating: 0x02, count: 12))
        XCTAssertEqual(nonce.data.count, 16)
    }
    
    func testAESIV_CCMNonce() throws {
        let nonce = try AESIV.ccmNonce(Data(repeating: 0x03, count: 10))
        // CCM nonce is padded to 16 bytes internally
        XCTAssertEqual(nonce.data.count, 16)
    }
    
    // MARK: - CCMTagsLength Tests
    
    func testCCMTagsLength() {
        let tag64 = CCMTagsLength(8)
        XCTAssertEqual(tag64, .bits64)
        
        let tag128 = CCMTagsLength(16)
        XCTAssertEqual(tag128, .bits128)
        
        // Invalid: odd number
        XCTAssertNil(CCMTagsLength(7))
        
        // Invalid: too small
        XCTAssertNil(CCMTagsLength(2))
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
    
    // MARK: - SecureFileVault Tests
    
    func testSecureFileVault_AuthenticatesEmptyAndNonEmptyData() async throws {
        let key = try SecureKey(Data(repeating: 0x42, count: 16))
        let vault = SecureFileVault(engine: MockHardwareAESEngine(), key: key)

        let emptyPackage = try await vault.encryptCTR(data: Data())
        XCTAssertEqual(emptyPackage.count, 49)
        let emptyPlaintext = try await vault.decryptCTR(data: emptyPackage)
        XCTAssertEqual(emptyPlaintext, Data())

        var tamperedPackage = try await vault.encryptCTR(data: Data([0x01, 0x02]))
        tamperedPackage[17] ^= 0x01
        do {
            _ = try await vault.decryptCTR(data: tamperedPackage)
            XCTFail("Tampered container must be rejected")
        } catch {
            XCTAssertEqual(error as? AESError, .invalidCiphertextSize)
        }
    }
}
