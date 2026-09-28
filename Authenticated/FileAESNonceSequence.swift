import Darwin
import Foundation
import HardwareAESCore

public enum AESNonceSequenceError: Error, Equatable, Sendable {
    case storageUnavailable
    case corruptedState
    case exhausted
}

/// Durable single-store nonce sequence for a key reserved for SecureFileVault.
///
/// Each issued nonce has a distinct 96-bit prefix and a zero 32-bit counter.
/// The next prefix is committed before the nonce is returned. File locking
/// coordinates separate instances and processes that use the same state URL.
/// Keep one state file per key and never restore it to an earlier snapshot.
public actor FileAESNonceSequence: AESNonceSequence {
    private struct State {
        var prefix: [UInt8]
        var exhausted: Bool
    }

    private static let magic = Array("HAESNS01".utf8)
    private static let prefixLength = 12
    private static let stateLength = magic.count + 1 + prefixLength

    private let stateURL: URL
    private let lockURL: URL

    public init(stateFileURL: URL) throws {
        guard stateFileURL.isFileURL else {
            throw AESNonceSequenceError.storageUnavailable
        }
        stateURL = stateFileURL.standardizedFileURL
        lockURL = stateURL.appendingPathExtension("lock")
    }

    public func nextNonce() throws -> AESIV {
        try withExclusiveLock {
            var state = try readState() ?? State(prefix: try randomPrefix(), exhausted: false)
            guard !state.exhausted else {
                throw AESNonceSequenceError.exhausted
            }

            let issuedPrefix = state.prefix
            if let nextPrefix = incrementPrefix(state.prefix) {
                state.prefix = nextPrefix
            } else {
                state.exhausted = true
            }

            try writeState(state)
            return try AESIV(Data(issuedPrefix + [0, 0, 0, 0]))
        }
    }

    private func withExclusiveLock<T>(_ body: () throws -> T) throws -> T {
        let descriptor = lockURL.path.withCString {
            open($0, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, mode_t(S_IRUSR | S_IWUSR))
        }
        guard descriptor >= 0 else {
            throw AESNonceSequenceError.storageUnavailable
        }
        defer { _ = close(descriptor) }

        var lockStatus: Int32
        repeat {
            lockStatus = flock(descriptor, LOCK_EX)
        } while lockStatus != 0 && errno == EINTR
        guard lockStatus == 0 else {
            throw AESNonceSequenceError.storageUnavailable
        }
        defer { _ = flock(descriptor, LOCK_UN) }
        return try body()
    }

    private func readState() throws -> State? {
        let descriptor = stateURL.path.withCString {
            open($0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        if descriptor < 0 {
            if errno == ENOENT { return nil }
            throw AESNonceSequenceError.storageUnavailable
        }
        defer { _ = close(descriptor) }

        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFREG,
              metadata.st_size == off_t(Self.stateLength)
        else {
            throw AESNonceSequenceError.corruptedState
        }

        var bytes = [UInt8](repeating: 0, count: Self.stateLength)
        let hasFullRead = bytes.withUnsafeMutableBytes { buffer -> Bool in
            guard let baseAddress = buffer.baseAddress else { return false }
            var offset = 0
            while offset < buffer.count {
                let amount = read(descriptor, baseAddress.advanced(by: offset), buffer.count - offset)
                if amount < 0, errno == EINTR { continue }
                guard amount > 0 else { return false }
                offset += amount
            }
            return true
        }
        guard hasFullRead,
              Array(bytes.prefix(Self.magic.count)) == Self.magic,
              bytes[Self.magic.count] <= 1
        else {
            throw AESNonceSequenceError.corruptedState
        }

        let prefixStart = Self.magic.count + 1
        return State(
            prefix: Array(bytes[prefixStart..<(prefixStart + Self.prefixLength)]),
            exhausted: bytes[Self.magic.count] == 1
        )
    }

    private func writeState(_ state: State) throws {
        var bytes = Self.magic
        bytes.append(state.exhausted ? 1 : 0)
        bytes.append(contentsOf: state.prefix)

        let temporaryURL = stateURL.appendingPathExtension("tmp.\(UUID().uuidString)")
        let descriptor = temporaryURL.path.withCString {
            open($0, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                 mode_t(S_IRUSR | S_IWUSR))
        }
        guard descriptor >= 0 else {
            throw AESNonceSequenceError.storageUnavailable
        }

        var shouldRemoveTemporary = true
        defer {
            _ = close(descriptor)
            if shouldRemoveTemporary {
                _ = temporaryURL.path.withCString { unlink($0) }
            }
        }

        let hasFullWrite = bytes.withUnsafeBytes { buffer -> Bool in
            guard let baseAddress = buffer.baseAddress else { return false }
            var offset = 0
            while offset < buffer.count {
                let amount = write(descriptor, baseAddress.advanced(by: offset), buffer.count - offset)
                if amount < 0, errno == EINTR { continue }
                guard amount > 0 else { return false }
                offset += amount
            }
            return true
        }
        guard hasFullWrite, fsync(descriptor) == 0 else {
            throw AESNonceSequenceError.storageUnavailable
        }
        guard temporaryURL.path.withCString({ temporaryPath in
            stateURL.path.withCString { destinationPath in
                rename(temporaryPath, destinationPath)
            }
        }) == 0 else {
            throw AESNonceSequenceError.storageUnavailable
        }
        shouldRemoveTemporary = false

        let directoryURL = stateURL.deletingLastPathComponent()
        let directoryDescriptor = directoryURL.path.withCString {
            open($0, O_RDONLY | O_CLOEXEC | O_DIRECTORY)
        }
        guard directoryDescriptor >= 0 else {
            throw AESNonceSequenceError.storageUnavailable
        }
        defer { _ = close(directoryDescriptor) }
        guard fsync(directoryDescriptor) == 0 else {
            throw AESNonceSequenceError.storageUnavailable
        }
    }

    private func randomPrefix() throws -> [UInt8] {
        let random = try AESIV.random().data
        return Array(random.prefix(Self.prefixLength))
    }

    private func incrementPrefix(_ prefix: [UInt8]) -> [UInt8]? {
        var result = prefix
        for index in result.indices.reversed() {
            if result[index] != .max {
                result[index] += 1
                if index + 1 < result.count {
                    for resetIndex in (index + 1)..<result.count {
                        result[resetIndex] = 0
                    }
                }
                return result
            }
        }
        return nil
    }
}
