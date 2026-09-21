import Foundation
import HardwareAESASM

/// Secure AES key wrapper with explicit best-effort zeroing on deallocation.
///
/// The key is kept in a private, explicitly allocated buffer rather than `Data`,
/// avoiding copy-on-write aliases under this type's control. The buffer is
/// immutable through the public API and is cleared with the C secure-zero helper
/// when the owner is released. As with all software memory wiping, this does not
/// guarantee removal of copies made by callers or by the operating system.
public final class SecureKey: Sendable, Equatable, CustomStringConvertible {

    // Явно аллоцированный буфер. UnsafeMutableBufferPointer — не CoW,
    // не управляется ARC, живёт ровно столько, сколько живёт SecureKey.
    //
    // nonisolated(unsafe): Swift 6 не знает что буфер немутабелен после init —
    // UnsafeMutableBufferPointer не conformит Sendable по определению.
    // Мы берём ответственность за потокобезопасность на себя: после init
    // запись в буфер происходит только в deinit, который вызывается однократно.
    nonisolated(unsafe) private let buffer: UnsafeMutableBufferPointer<UInt8>

    // MARK: - Init / Deinit

    /// Creates a SecureKey from raw key bytes.
    /// - Parameter bytes: Key data. Must be 16, 24, or 32 bytes.
    /// - Throws: `AESError.invalidKeyLength` for unsupported lengths.
    ///           `AESError.memoryAllocationFailed` if allocation fails.
    public init(_ bytes: Data) throws {
        guard [16, 24, 32].contains(bytes.count) else {
            throw AESError.invalidKeyLength
        }

        let buf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: bytes.count)
        guard buf.baseAddress != nil else {
            throw AESError.memoryAllocationFailed
        }

        // Копируем байты из Data в наш буфер
        _ = bytes.copyBytes(to: buf)
        self.buffer = buf
    }

    /// Creates a SecureKey from a byte array.
    public convenience init(_ bytes: [UInt8]) throws {
        try self.init(Data(bytes))
    }

    /// Гарантированное затирание: единственная копия ключа в памяти.
    /// `initialize(repeating:)` на `UnsafeMutableBufferPointer` не оптимизируется
    /// в dead store — компилятор не может доказать отсутствие наблюдателей.
    deinit {
        if let baseAddress = buffer.baseAddress {
            haes_secure_zero(baseAddress, buffer.count)
        }
        buffer.deallocate()
    }

    // MARK: - Public API

    public var size: AESKeySize {
        // Значения AESKeySize.rawValue совпадают с числом байт (16/24/32)
        AESKeySize(rawValue: buffer.count) ?? .bits128
    }

    /// Копия ключа в виде `Data` для передачи в C-функции.
    /// Используй `withUnsafeBytes` где возможно — он не создаёт копию.
    public var keyData: Data {
        Data(buffer)
    }

    /// Предоставляет доступ к сырым байтам без копирования.
    /// Указатель валиден только внутри замыкания.
    public func withUnsafeBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) rethrows -> T {
        try UnsafeRawBufferPointer(buffer).withMemoryRebound(to: UInt8.self) { ptr in
            try body(UnsafeRawBufferPointer(ptr))
        }
    }

    // MARK: - Equatable

    /// Constant-time сравнение через XOR-аккумулятор.
    /// Всегда проходит все байты независимо от содержимого — early-exit отсутствует.
    public static func == (lhs: SecureKey, rhs: SecureKey) -> Bool {
        guard lhs.buffer.count == rhs.buffer.count else { return false }

        var diff: UInt8 = 0
        for i in 0..<lhs.buffer.count {
            diff |= lhs.buffer[i] ^ rhs.buffer[i]
        }
        return diff == 0
    }

    // MARK: - CustomStringConvertible

    /// Does not expose any key material or derived identifier.
    public var description: String {
        "SecureKey(\(size.rawValue * 8)-bit)"
    }
}
