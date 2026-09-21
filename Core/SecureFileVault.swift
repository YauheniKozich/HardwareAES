import Foundation

/// Secure file encryption vault using hardware-accelerated AES.
/// Fully thread-safe and protected against IV reuse attacks.
public final actor SecureFileVault {
    private let engine: any HardwareAESEngineProtocol
    
    /// Создаем vault, привязавшись только к движку (который держит SecureKey).
    /// Режим (и IV) больше не фиксируются жестко в свойствах.
    public init(engine: any HardwareAESEngineProtocol) {
        self.engine = engine
    }
    
    /// Encrypts data using AES-CTR with a cryptographically secure random IV.
    ///
    /// - Parameter plaintext: The plaintext data to encrypt.
    /// - Returns: Packaged data containing: [16 bytes IV] + [Ciphertext].
    /// - Throws: `AESError` if encryption fails.
    public func encryptCTR(data plaintext: Data) throws -> Data {
        // 1. Генерируем уникальный IV для КАЖДОГО вызова шифрования
        let iv = try AESIV.random()
        let mode = AESMode.ctr(iv: iv)
        
        // 2. Шифруем данные
        let ciphertext = try engine.encrypt(plaintext, mode: mode)
        
        // 3. Упаковываем IV вместе с шифротекстом, чтобы дешифратор знал, как читать файл
        var packagedData = Data()
        packagedData.append(iv.data)
        packagedData.append(ciphertext)
        
        return packagedData
    }
    
    /// Decrypts data that was encrypted via `encryptCTR(data:)`.
    ///
    /// - Parameter packagedData: Packaged data containing: [16 bytes IV] + [Ciphertext].
    /// - Returns: The decrypted plaintext data.
    /// - Throws: `AESError` if decryption fails or data is corrupted.
    public func decryptCTR(data packagedData: Data) throws -> Data {
        // Минимальный размер файла должен быть больше размера IV (16 байт)
        guard packagedData.count > 16 else {
            throw AESError.invalidCiphertextSize
        }
        
        // 1. Извлекаем IV из первых 16 байт пакета
        let ivData = packagedData.prefix(16)
        let iv = try AESIV(ivData)
        let mode = AESMode.ctr(iv: iv)
        
        // 2. Извлекаем чистый шифротекст
        let ciphertext = packagedData.dropFirst(16)
        
        // 3. Дешифруем
        return try engine.decrypt(ciphertext, mode: mode)
    }
}
