# HardwareAES Engine - Modular Architecture

## Overview

HardwareAES Engine is a hardware-accelerated AES-128 encryption library for iOS and macOS using ARMv8 Crypto Extensions. The implementation is AES-128 only: keys must be exactly 16 bytes; AES-192 and AES-256 are not supported.

## Requirements

- iOS 15.0+
- macOS 12.0+
- ARM64 architecture (Apple Silicon)
- AES-128 only; keys must be exactly 16 bytes

## Module Structure

```
HardwareAESEngine/
├── Core/                    # Public key, mode, and engine contracts
├── Modes/CTR/               # Public CTR engine and stateful stream
├── Primitives/              # Package-only AES block primitive for CMAC
├── Authenticated/           # Versioned authenticated container and nonce providers
├── Assembly/                # Low-level C/ARM Crypto Extensions implementation
└── Tests/                   # Core, CTR, block primitive, and container tests
```

## Modules

### HardwareAESCore
Basic types and protocols. Use this if you want to implement your own encryption modes.

```swift
import HardwareAESCore

let key = try SecureKey(keyData)
```

### HardwareAESCTR (Recommended)
CTR mode implementation - stable and production-ready.

```swift
import HardwareAESCore
import HardwareAESCTR

let key = try SecureKey(keyData)
let engine = try HardwareAESCTR(key: key)
let mode = try CTRMode(iv: try AESIV.random())
let ciphertext = try engine.encrypt(plaintext, mode: mode)
```

### HardwareAESAuthenticated
Authenticated versioned containers backed by AES-CTR and AES-CMAC.

```swift
import Foundation
import HardwareAESCore
import HardwareAESAuthenticated

let nonceStateURL = try FileManager.default
    .url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
    .appendingPathComponent("vault-nonce-state")
let nonces = try FileAESNonceSequence(stateFileURL: nonceStateURL)
let vault = try SecureFileVault(key: SecureKey(keyData), nonceSequence: nonces)
let package = try await vault.encrypt(plaintext)
```

Use a file in the app's Application Support directory for `nonceStateURL`.
Keep one state file per key, exclude it from backups, and rotate the key if a
backup containing an earlier copy of the state is restored.

### HardwareAES
The unified facade for the implemented CTR mode.

```swift
import HardwareAES
```

## Status

| Mode | Status | NIST Tests | Round-Trip | Production Ready |
|------|--------|------------|------------|------------------|
| CTR  | ✅ Stable | ✅ 4-block NIST vector | ✅ Works | ✅ Yes |
| Authenticated container | ✅ AES-CMAC + CTR | ✅ RFC 4493 CMAC KAT | ✅ Tamper rejection | ✅ Use for stored data |
| AES block primitive | Package-only implementation detail used by CMAC; no ECB API is exported |

## Security Considerations

### CTR Mode
- Provides confidentiality only (no authentication)
- Must use unique IV for each encryption
- Use `SecureFileVault` when authentication is required

### AES block primitive
The package uses a package-only AES block primitive to implement CMAC and run
known-answer tests. It is not a public encryption mode or package product.

## Low-Level Contracts

- The AES context must be 16-byte aligned; input and output buffers do not
  need to be aligned.
- The internal block primitive requires a length that is a multiple of 16 bytes;
  CTR accepts arbitrary lengths, including zero.
- CTR uses NIST `inc32`: only the low 32-bit word increments in big-endian order;
  the 96-bit prefix is preserved and the low word wraps modulo 2^32.
- A zero-length call returns success after pointer validation; null pointers
  still return an error.
- Disjoint buffers and exact in-place operation are supported. Partial overlap
  is undefined behavior.
- The temporary key schedule is securely zeroed after initialization. This does
  not guarantee removal of copies held in registers, caches, or compiler
  temporaries.

## Testing

Run all tests:
```bash
swift test
```

Run specific mode tests:
```bash
swift test --filter HardwareAESCTRTests
swift test --filter HardwareAESBlockCipherTests
```

## Performance

The CTR benchmark uses an 8-way fast path with 4-way and single-block tail
handling. The following median values are from the release run captured on
2026-09-28; its correctness preflight passed 551 checks, including 256
randomized cases. Results can vary by roughly ±5–10% with device, thermal state,
power mode, background load, and build configuration.

| Size | Out-of-place | In-place |
| --- | ---: | ---: |
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

The benchmark rotates in-place work across an independent buffer ring. In this
run, out-of-place was faster through 16 MB; in-place was slightly faster at
64 MB and 100 MB. These observations do not establish a microarchitectural cause.

The CLI also prints a separate CommonCrypto reference table. One cryptor is
created outside timing and reused for steady-state update calls. CommonCrypto
may use the same hardware AES accelerator as HardwareAES, so this is a
reference measurement rather than a universal faster/slower claim.
For small messages, the observed difference also includes CommonCrypto's
per-call validation and dispatch overhead; it does not demonstrate faster AES
round execution.
In this run HardwareAES led CommonCrypto at 256 B, 1 KB, and 4 KB. CommonCrypto
led from 16 KB through 100 MB. Results are API-level measurements from one
machine.

Reproduce with:

```bash
./Scripts/run-release-benchmark.sh 3
```

The script records OS, device/SoC, Swift compiler, and SDK metadata. The CLI
uses `mach_absolute_time()`, cached timebase conversion, buffer reuse, 3 warmup
iterations below 8 MB, 1 warmup iteration at or above 8 MB, a 0.5 second target
duration per size, and the median of 3 run medians. Run it after letting the
machine idle for 30–60 seconds. Thermal state,
power mode, background load, and CPU frequency affect peak measurements.

## License

MIT License
