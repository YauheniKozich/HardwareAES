import Foundation
import HardwareAESCore
import HardwareAESASM

private final class AESContextStorage: @unchecked Sendable {
    private let allocation: UnsafeMutableRawPointer
    var pointer: UnsafeMutablePointer<UInt8> {
        allocation.assumingMemoryBound(to: UInt8.self)
    }
    let count = Int(HAES_AES128_CTX_BYTES_FULL)

    init() throws {
        allocation = .allocate(byteCount: count, alignment: 16)
    }

    deinit {
        haes_secure_zero(pointer, count)
        allocation.deallocate()
    }

    func withUnsafeBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        try body(UnsafeRawBufferPointer(start: pointer, count: count))
    }
}

/// Hardware-accelerated AES encryption engine with CTR mode support.
///
/// Uses ARMv8 Crypto Extensions for maximum hardware performance.
/// Synchronous operations can run concurrently because the expanded key
/// context is immutable. Async operations use a private serial queue. The
/// stateful stream type has separate single-owner semantics.
public final class HardwareAESCTR: HardwareAESEngineProtocol, Sendable {
    // Контекст раундовых ключей иммутабелен. Класс является честным Sendable
    // без необходимости блокировок через DispatchQueue.
    private let context: AESContextStorage
    private let asyncQueue: DispatchQueue
    
    /// Initializes a new AES engine with the provided key.
    public init(key: SecureKey) throws {
        guard key.size == .bits128 else {
            throw AESError.invalidKeyLength
        }

        let context = try AESContextStorage()

        // Передаем указатель из SecureKey напрямую в Си, исключая промежуточную копию Data.
        let status = key.withUnsafeBytes { keyBuf in
            let keyPtr = keyBuf.bindMemory(to: UInt8.self).baseAddress
            guard let keyPtr else { return -1 }
            return Int(haes_aes128_init(context.pointer, keyPtr))
        }

        guard status == 0 else { throw AESError.internalError }
        self.context = context
        self.asyncQueue = DispatchQueue(label: "com.hardwareaes.ctr.async", qos: .userInitiated)
    }
    
    /// Encrypts synchronously. Immutable key state permits concurrent calls.
    public func encrypt(_ plaintext: Data, mode: CTRMode) throws -> Data {
        try process(input: plaintext, iv: mode.iv.data)
    }

    /// Decrypts synchronously. Immutable key state permits concurrent calls.
    public func decrypt(_ ciphertext: Data, mode: CTRMode) throws -> Data {
        try process(input: ciphertext, iv: mode.iv.data)
    }

    // MARK: - Async/Await API (Modern Swift Concurrency)

    /// Encrypts on a private serial queue. Cancellation does not interrupt a
    /// C operation that has already been enqueued.
    public func encrypt(_ plaintext: Data, mode: CTRMode) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            asyncQueue.async {
                do {
                    continuation.resume(returning: try self.encrypt(plaintext, mode: mode))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    /// Decrypts on a private serial queue. Cancellation does not interrupt a
    /// C operation that has already been enqueued.
    public func decrypt(_ ciphertext: Data, mode: CTRMode) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            asyncQueue.async {
                do {
                    continuation.resume(returning: try self.decrypt(ciphertext, mode: mode))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
    
    // MARK: - HardwareAESEngineProtocol Conformance

    public func encrypt(_ plaintext: Data, mode: AESMode) throws -> Data {
        guard case .ctr(let iv) = mode else { throw AESError.unsupportedMode }
        return try process(input: plaintext, iv: iv.data)
    }

    public func decrypt(_ ciphertext: Data, mode: AESMode) throws -> Data {
        guard case .ctr(let iv) = mode else { throw AESError.unsupportedMode }
        return try process(input: ciphertext, iv: iv.data)
    }

    public func encrypt(_ plaintext: Data, mode: AESMode) async throws -> Data {
        guard case .ctr(let iv) = mode else { throw AESError.unsupportedMode }
        return try await encrypt(plaintext, mode: CTRMode(iv: iv))
    }

    public func decrypt(_ ciphertext: Data, mode: AESMode) async throws -> Data {
        guard case .ctr(let iv) = mode else { throw AESError.unsupportedMode }
        return try await decrypt(ciphertext, mode: CTRMode(iv: iv))
    }
    
    // MARK: - NIST Self Test
    
    public static func runNISTSelfTest() -> Bool {
        let keyData = Data([0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c])
        let pt = Data([0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a])
        let iv = Data([0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff])
        let expectedCtr = Data([0x87,0x4d,0x61,0x91,0xb6,0x20,0xe3,0x26,0x1b,0xef,0x68,0x64,0x99,0x0d,0xb6,0xce])
        
        do {
            let engine = try HardwareAESCTR(key: SecureKey(keyData))
            let mode = try CTRMode(iv: iv)
            let ctCtr = try engine.encrypt(pt, mode: mode)
            guard ctCtr == expectedCtr else { return false }
            return try engine.decrypt(ctCtr, mode: mode) == pt
        } catch {
            return false
        }
    }
    
    // MARK: - Private Core Processing

    private func validateCounterCapacity(byteCount: Int) throws {
        // CTR follows NIST inc32 semantics: the low 32-bit word wraps modulo
        // 2^32. Only integer overflow in the host-side block calculation is
        // rejected; counter wrap itself is valid and deterministic.
        let blockCount = UInt64(byteCount / 16) + (byteCount % 16 == 0 ? 0 : 1)
        guard blockCount <= UInt64(UInt32.max) + 1 else {
            throw AESError.counterExhausted
        }
    }

    private func process(input: Data, iv: Data) throws -> Data {
        guard iv.count == 16 else {
            throw AESError.invalidIVLength
        }
        guard input.count > 0 else { return Data() }
        try validateCounterCapacity(byteCount: input.count)

        var output = Data(count: input.count)

        // Чтение иммутабельного контекста безопасно из любого количества потоков одновременно
        let status = context.withUnsafeBytes { ctxBuf in
            input.withUnsafeBytes { inBuf in
                output.withUnsafeMutableBytes { outBuf in
                    guard let ctxPtr = ctxBuf.bindMemory(to: UInt8.self).baseAddress,
                          let inPtr = inBuf.baseAddress?.assumingMemoryBound(to: UInt8.self),
                          let outPtr = outBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    else { return -1 }

                    return iv.withUnsafeBytes { ivBuf in
                        guard let ivPtr = ivBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
                        else { return -1 }
                        return Int(haes_aes128_ctr_xor(
                            inPtr, outPtr, input.count, ctxPtr, ivPtr
                        ))
                    }
                }
            }
        }
        
        guard status == 0 else { throw AESError.internalError }
        return output
    }

    // MARK: - Alloc-Free API

    /// In-place AES-CTR XOR. `buffer` serves as both input and output.
    ///
    /// - Note: C core supports `in == out` (block-by-block read-then-write).
    /// - Note: Low-level API. No locking — caller manages thread safety.
    public func encryptInPlace(
        buffer: UnsafeMutableRawBufferPointer,
        iv: Data
    ) throws {
        guard iv.count == 16 else {
            throw AESError.invalidIVLength
        }
        guard buffer.count > 0 else { return }
        try validateCounterCapacity(byteCount: buffer.count)
        guard let bufPtr = buffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
            throw AESError.internalError
        }

        let status = context.withUnsafeBytes { ctxBuf -> Int in
            iv.withUnsafeBytes { ivBuf -> Int in
                guard let ctxPtr = ctxBuf.bindMemory(to: UInt8.self).baseAddress,
                      let ivPtr = ivBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
                else { return -1 }
                return Int(haes_aes128_ctr_xor(
                    bufPtr, bufPtr, buffer.count, ctxPtr, ivPtr
                ))
            }
        }
        guard status == 0 else { throw AESError.internalError }
    }

    /// Out-of-place AES-CTR XOR without allocation.
    ///
    /// - Note: Low-level API. No locking — caller manages thread safety.
    public func encrypt(
        input: UnsafeRawBufferPointer,
        output: UnsafeMutableRawBufferPointer,
        iv: Data
    ) throws {
        guard iv.count == 16 else {
            throw AESError.invalidIVLength
        }
        guard input.count == output.count else {
            throw AESError.bufferSizeMismatch
        }
        guard input.count > 0 else { return }
        try validateCounterCapacity(byteCount: input.count)
        guard let inPtr = input.baseAddress?.assumingMemoryBound(to: UInt8.self),
              let outPtr = output.baseAddress?.assumingMemoryBound(to: UInt8.self)
        else { throw AESError.internalError }

        let status = context.withUnsafeBytes { ctxBuf -> Int in
            iv.withUnsafeBytes { ivBuf -> Int in
                guard let ctxPtr = ctxBuf.bindMemory(to: UInt8.self).baseAddress,
                      let ivPtr = ivBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
                else { return -1 }
                return Int(haes_aes128_ctr_xor(
                    inPtr, outPtr, input.count, ctxPtr, ivPtr
                ))
            }
        }
        guard status == 0 else { throw AESError.internalError }
    }
}

/// Stateful AES-CTR stream for callers that process one logical stream in
/// multiple updates. Unlike the stateless `encrypt(_:mode:)` API, this type
/// preserves partial-block keystream and counter state between updates.
/// across concurrent tasks; create one stream per logical producer/consumer.
public final class HardwareAESCTRStream {
    private static let maximumCounterBlocks = UInt64(UInt32.max) + 1
    private let engine: HardwareAESCTR
    private var counter: Data
    private var keystream = Data(count: 16)
    private var keystreamOffset = 16
    private var generatedBlockCount: UInt64 = 0

    public init(engine: HardwareAESCTR, iv: AESIV) {
        self.engine = engine
        self.counter = iv.data
    }

    /// Encrypts or decrypts the next segment of the stream.
    public func update(_ input: Data) throws -> Data {
        guard !input.isEmpty else { return Data() }

        let bufferedBytes = keystream.count - keystreamOffset
        let bytesNeedingBlocks = max(0, input.count - bufferedBytes)
        let requiredBlocks = UInt64(bytesNeedingBlocks / 16)
            + (bytesNeedingBlocks % 16 == 0 ? 0 : 1)
        guard requiredBlocks <= Self.maximumCounterBlocks - generatedBlockCount else {
            throw AESError.counterExhausted
        }

        var output = Data(count: input.count)
        var outputOffset = 0
        for inputByte in input {
            if keystreamOffset == keystream.count {
                keystream = try engine.encrypt(
                    Data(repeating: 0, count: 16),
                    mode: CTRMode(iv: AESIV(counter))
                )
                generatedBlockCount += 1
                incrementCounter()
                keystreamOffset = 0
            }
            output[outputOffset] = inputByte ^ keystream[keystreamOffset]
            outputOffset += 1
            keystreamOffset += 1
        }
        return output
    }

    private func incrementCounter() {
        var value = UInt32(counter[12]) << 24
            | UInt32(counter[13]) << 16
            | UInt32(counter[14]) << 8
            | UInt32(counter[15])
        value &+= 1
        counter[12] = UInt8((value >> 24) & 0xff)
        counter[13] = UInt8((value >> 16) & 0xff)
        counter[14] = UInt8((value >> 8) & 0xff)
        counter[15] = UInt8(value & 0xff)
    }
}
