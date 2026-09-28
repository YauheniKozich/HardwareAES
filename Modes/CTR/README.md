# HardwareAES CTR Mode

> AES-128 only. Use exactly 16-byte keys; AES-192 and AES-256 are not supported.

## Overview

HardwareAES CTR (Counter) mode provides high-performance AES encryption using ARMv8 Crypto Extensions. CTR mode turns a block cipher into a stream cipher, offering excellent performance and parallel processing capabilities.

## Requirements

- iOS 15.0+
- macOS 12.0+
- ARM64 architecture (Apple Silicon)
- AES-128 only; keys must be exactly 16 bytes

## Features

- ✅ **Hardware Accelerated** - Uses ARMv8 AES instructions for maximum performance
- ✅ **Thread Safe** - Fully concurrent with proper synchronization
- ✅ **Modern Swift API** - Both synchronous and async/await support
- ✅ **NIST Validated** - Passes the complete 64-byte (4-block) NIST SP 800-38A F.5.1 CTR vector
- ✅ **Protocol Based** - Conforms to `HardwareAESEngineProtocol` for dependency injection

## Installation

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/your-org/HardwareAES", from: "1.0.0")
]

targets: [
    .target(
        name: "YourTarget",
        dependencies: [
            .product(name: "HardwareAESCore", package: "HardwareAES"),
            .product(name: "HardwareAESCTR", package: "HardwareAES")
        ]
    )
]
```

## Usage

### Synchronous Usage

```swift
import HardwareAESCore
import HardwareAESCTR

// Initialize
let keyData = Data(repeating: 0x42, count: 16)  // 16-byte key for AES-128
let key = try SecureKey(keyData)
let engine = try HardwareAESCTR(key: key)

// Create CTR mode with IV (must be unique for each encryption!)
let mode = try CTRMode(iv: try AESIV.random())

// Encrypt
let plaintext = Data("Hello, World!".utf8)
let ciphertext = try engine.encrypt(plaintext, mode: mode)

// Decrypt
let decrypted = try engine.decrypt(ciphertext, mode: mode)
assert(decrypted == plaintext)
```

### Async/Await Usage

```swift
import HardwareAESCore
import HardwareAESCTR

let key = try SecureKey(keyData)
let engine = try HardwareAESCTR(key: key)
let mode = try CTRMode(iv: try AESIV.random())

// Async encryption
let ciphertext = try await engine.encrypt(plaintext, mode: mode)

// Async decryption
let decrypted = try await engine.decrypt(ciphertext, mode: mode)
```

### SecureFileVault Usage

```swift
import HardwareAESCore
import HardwareAESAuthenticated

let key = try SecureKey(keyData)
let nonceStateURL = try FileManager.default
    .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
    .appendingPathComponent("vault-nonce-state")
let nonces = try FileAESNonceSequence(stateFileURL: nonceStateURL)
let vault = try SecureFileVault(key: key, nonceSequence: nonces)

// Encrypt/decrypt with vault
let encrypted = try await vault.encrypt(plaintext)
let decrypted = try await vault.decrypt(encrypted)
```

## API Reference

### HardwareAESCTR

#### Initialization

```swift
public init(key: SecureKey) throws
```

Creates a new CTR encryption engine.

- **Parameter** `key`: exactly 16 bytes for AES-128
- **Throws**: `AESError.invalidKeyLength`, `AESError.memoryAllocationFailed`

#### Synchronous Methods

```swift
public func encrypt(_ plaintext: Data, mode: CTRMode) throws -> Data
public func decrypt(_ ciphertext: Data, mode: CTRMode) throws -> Data
```

Encrypt/decrypt data synchronously.

- **Parameter** `plaintext/ciphertext`: Data to process (any length is allowed)
- **Parameter** `mode`: CTR mode configuration with IV
- **Returns**: Encrypted/decrypted data
- **Throws**: `AESError` if operation fails

#### Asynchronous Methods

```swift
public func encrypt(_ plaintext: Data, mode: CTRMode) async throws -> Data
public func decrypt(_ ciphertext: Data, mode: CTRMode) async throws -> Data
```

Encrypt/decrypt data asynchronously without blocking the calling thread.

### CTRMode

```swift
public struct CTRMode: Equatable, Sendable {
    public let iv: AESIV
    
    public init(iv: Data) throws
    public init(iv: AESIV)
}
```

CTR mode configuration.

- **Parameter** `iv`: 16-byte initialization vector (nonce)
- **Important**: IV must be **unique** for each encryption with the same key

## Low-Level Buffer Contracts

These contracts apply to the underlying C API used by the CTR implementation:

- CTR accepts arbitrary byte lengths, including zero.
- A zero-length call returns success after pointer validation; null pointers
  still return an error.
- Disjoint buffers and exact in-place operation are supported.
- Partial input/output overlap is undefined behavior.
- The AES context must be 16-byte aligned; input and output buffers do not
  need to be aligned.
- CTR uses NIST `inc32`: only the low 32-bit word increments in big-endian
  order; the 96-bit prefix is preserved and the low word wraps modulo 2^32.
- Temporary key-schedule and keystream buffers are securely zeroed, but copies in
  registers, caches, or compiler-generated temporaries cannot be guaranteed.

## Security Considerations

### IV Management

⚠️ **Critical**: The IV (nonce) must be **unique** for every encryption operation with the same key.

**Good Practices:**
```swift
// ✅ Generate a fresh random IV for each standalone CTR encryption
let iv = try AESIV.random()
let mode = try CTRMode(iv: iv)

// ✅ Store/transmit IV with ciphertext
let encryptedData = iv + ciphertext
```

**Bad Practices:**
```swift
// ❌ Reusing IV with same key
let iv = Data(repeating: 0, count: 16)  // NEVER do this!

// ❌ Hardcoded IV
let iv = Data([0x01, 0x02, ...])  // NEVER do this!
```

### Authentication

⚠️ **Warning**: CTR mode provides **confidentiality only**, NOT authentication.

An attacker can modify ciphertext without detection. For authenticated
storage, use `SecureFileVault`, which authenticates its versioned container
with AES-CMAC before decrypting. This package does not implement GCM.
- Add HMAC separately
- Use encrypt-then-MAC construction

### Key Management

- Use `SecureKey` for automatic memory zeroing
- Share one `AESNonceSequence` and one state file across vaults that use the same key
- Exclude the nonce state file from backups; after restoring a backup, rotate the key
- Use `RandomAESNonceSequence` only with an ephemeral key; its per-instance limit
  does not persist across launches
- Rotate the key when the sequence reaches its policy limit
- Use a 16-byte AES-128 key and protect it with an appropriate key-management system

## Performance

### 8-Way Interleaving Optimization

This implementation uses **8-way interleaving** for the main fast path and **4-way interleaving** for the remainder path. By processing multiple counter blocks simultaneously, the CPU can fill pipeline stalls with independent AES operations and keep the crypto unit saturated.

**How it works:**
```
Sequential:  [AES block 0] → wait → [AES block 1] → wait → ...
8-Way:       [AES block 0] ↘
             [AES block 1]  → parallel execution → [all done]
             [AES block 2] ↗
             [AES block 3] ↗
             [AES block 4] ↘
             [AES block 5] ↗
             [AES block 6] ↘
             [AES block 7] ↗
```

### Benchmarks on Apple Silicon

Latest release sample captured on 2026-09-28; the correctness preflight passed
551 checks, including 256 randomized cases:

```bash
swift run -c release HardwareAESBenchmarkCLI
```

Measured output from a release run on a MacBook Pro:

| Data Size | Out-of-place | In-place |
|-----------|-------------:|---------:|
| 256 B | 10790.75 MiB/s | 8217.92 MiB/s |
| 1 KB | 15761.60 MiB/s | 13803.00 MiB/s |
| 4 KB | 15703.52 MiB/s | 14880.95 MiB/s |
| 16 KB | 16025.64 MiB/s | 15495.87 MiB/s |
| 64 KB | 16094.42 MiB/s | 15706.81 MiB/s |
| 256 KB | 16129.03 MiB/s | 15915.12 MiB/s |
| 1 MB | 16085.79 MiB/s | 15915.12 MiB/s |
| 4 MB | 15992.00 MiB/s | 15909.84 MiB/s |
| 16 MB | 15932.29 MiB/s | 15776.50 MiB/s |
| 64 MB | 15790.45 MiB/s | 15819.72 MiB/s |
| 100 MB | 15584.82 MiB/s | 15884.26 MiB/s |

*Note:* small-buffer operations are batched before timing, so these throughput
values are not single-call `Time/op` latency measurements. This table is from a
single release run on one MacBook Pro and is not a universal performance claim.

These are median values from a single release run, not guaranteed performance
figures. Repeated runs can vary by roughly ±5–10% with device, OS version,
thermal state, power mode, background load, and CPU frequency. See `Assembly/README.md` for the benchmark methodology and caveats.
The root README contains the current three-run Release snapshot and the
reproducible command.

**Performance note:**
- Small inputs often show the highest apparent throughput because the benchmark overhead is amortized differently across sizes.
- Large inputs reflect sustained memory and cache pressure more accurately.
- Results vary by device, OS version, thermal state, and whether the target is built for `release`.

Performance varies by device. Apple Silicon shows the best results due to wider execution pipelines.

## Testing

Run the package tests with:

```bash
swift test --filter HardwareAESCTRTests
```

The test suite includes the 4-block NIST vector, CommonCrypto differential
checks, tails, unaligned and in-place buffers, segmented streams, guard-page
boundaries, and counter-wrap checks.

### Unit Tests

```swift
func testCTREncryptDecrypt() async throws {
    let key = try SecureKey(Data(repeating: 0x42, count: 16))
    let engine = try HardwareAESCTR(key: key)
    let mode = try CTRMode(iv: try AESIV.random())
    
    let plaintext = Data("Test message".utf8)
    let ciphertext = try await engine.encrypt(plaintext, mode: mode)
    let decrypted = try await engine.decrypt(ciphertext, mode: mode)
    
    XCTAssertEqual(plaintext, decrypted)
}
```

### NIST Validation

```swift
// Run NIST self-test on app launch
if !HardwareAESCTR.runNISTSelfTest() {
    fatalError("NIST CTR validation failed!")
}
```

## Error Handling

```swift
public enum AESError: Error {
    case invalidKeyLength      // Key must be exactly 16 bytes
    case invalidIVLength       // IV must be 16 bytes
    case unsupportedMode       // Mode not implemented
    case internalError         // Hardware operation failed
    case memoryAllocationFailed // Memory allocation failed
}
```

Handle errors appropriately:

```swift
do {
    let ciphertext = try engine.encrypt(plaintext, mode: mode)
} catch AESError.invalidKeyLength {
    print("Key must be exactly 16 bytes")
} catch AESError.invalidIVLength {
    print("IV must be 16 bytes")
} catch {
    print("Encryption failed: \(error)")
}
```

## Migration Guide

### From CommonCrypto

```swift
// Before (CommonCrypto)
let cryptor = CCCryptorCreate(...)
CCCryptorUpdate(cryptor, plaintext, ...)

// After (HardwareAESCTR)
let engine = try HardwareAESCTR(key: key)
let ciphertext = try engine.encrypt(plaintext, mode: mode)
```

### From CryptoSwift

```swift
// Before (CryptoSwift)
let encrypted = try AES(key: key, blockMode: CTR(iv: iv)).encrypt(plaintext)

// After (HardwareAESCTR)
let engine = try HardwareAESCTR(key: key)
let mode = try CTRMode(iv: iv)
let ciphertext = try engine.encrypt(plaintext, mode: mode)
```

## Troubleshooting

### "Invalid IV length" error

**Cause**: IV must be exactly 16 bytes.

**Solution**:
```swift
let iv = try AESIV.random()  // ✅ Correct
let iv = try AESIV(Data(repeating: 0, count: 12))  // ❌ Wrong
```

### "Input length must be multiple of 16" error

**Cause**: CTR mode does not require block-size multiples. If you see this error, the call is usually going through a block-mode API or a non-CTR mode by mistake.

**Solution**: Make sure you're calling `HardwareAESCTR` or `.ctr` mode, and verify that your IV is exactly 16 bytes.

### Performance issues

**Cause**: Processing many small blocks instead of large chunks.

**Solution**: Batch small writes into larger buffers (≥1 KB).

## License

MIT License - see LICENSE file for details.

## Support

- Documentation: [Link to docs]
- Issues: [Link to GitHub issues]
- Discussions: [Link to GitHub discussions]
