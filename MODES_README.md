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
├── Core/                    # Basic types and protocols (always included)
│   ├── AESMode.swift        # AES modes and AESIV value type
│   ├── SecureKey.swift      # Secure key wrapper
│   ├── HardwareAESEngineProtocol.swift  # Protocol for DI
│   ├── HardwareAES.swift    # Full-library facade
│   └── SecureFileVault.swift # High-level encryption API
│
├── Modes/
│   ├── CTR/                 # CTR mode (stable, production-ready)
│   │   ├── CTRMode.swift
│   │   └── HardwareAES+CTR.swift  # Includes HardwareAESCTRStream
│   │
│   └── ECB/                 # ECB mode (experimental, not recommended)
│       ├── ECBMode.swift
│       └── HardwareAES+ECB.swift
│
├── Assembly/                # Low-level C/Assembly implementation
└── Tests/                   # Unit tests
    ├── HardwareAESCoreTests.swift
    ├── HardwareAESCTRTests.swift
    └── HardwareAESECCTests.swift
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

### HardwareAESECB (Experimental)
ECB mode implementation - **NOT recommended for production**.

```swift
import HardwareAESCore
import HardwareAESECB

let key = try SecureKey(keyData)
let engine = try HardwareAESECB(key: key)
let ciphertext = try engine.encrypt(plaintext, mode: .ecb)
```

### HardwareAES (Full Library)
All modes included.

```swift
import HardwareAES
```

## Status

| Mode | Status | NIST Tests | Round-Trip | Production Ready |
|------|--------|------------|------------|------------------|
| CTR  | ✅ Stable | ✅ 4-block NIST vector | ✅ Works | ✅ Yes |
| ECB  | ✅ Working | ✅ KAT | ✅ Works | ⚠️ Not recommended |

## Security Considerations

### CTR Mode
- Provides confidentiality only (no authentication)
- Must use unique IV for each encryption
- Consider using GCM mode if you need authentication

### ECB Mode
- **⚠️ Cryptographically insecure for most applications**
- Identical plaintext blocks produce identical ciphertext blocks
- Patterns in plaintext are visible in ciphertext
- Only use for:
  - Testing against known test vectors
  - Interoperability with legacy systems
  - Educational purposes

## Low-Level Contracts

- The AES context must be 16-byte aligned; input and output buffers do not
  need to be aligned.
- ECB requires a length that is a multiple of 16 bytes; CTR accepts arbitrary
  lengths, including zero.
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
swift test --filter HardwareAESECCTests
```

## Performance

The CTR benchmark uses an 8-way fast path with 4-way and single-block tail
handling. The following median values are from a single release run and can vary by
roughly ±5–10% with device, thermal state, power mode, background load, and
build configuration.

| Size | Out-of-place | In-place |
| --- | ---: | ---: |
| 256 B | 10137.33 MiB/s | 7473.69 MiB/s |
| 1 KB | 14611.91 MiB/s | 13279.04 MiB/s |
| 4 KB | 16801.08 MiB/s | 16025.64 MiB/s |
| 16 KB | 16816.14 MiB/s | 16447.37 MiB/s |
| 64 KB | 16703.79 MiB/s | 15873.02 MiB/s |
| 1 MB | 16075.02 MiB/s | 16010.67 MiB/s |
| 100 MB | 15749.37 MiB/s | 15893.72 MiB/s |

*Note:* small-buffer operations are batched before timing, so these throughput
values are not single-call `Time/op` latency measurements. This table is from a
single release run on one MacBook Pro and is not a universal performance claim.

The benchmark now rotates in-place work across an independent buffer ring.
Out-of-place remains faster at 256 B, 1 KB, and 4 KB; the ring experiment does
not support immediate reuse of one buffer as the sole explanation. Any
remaining in/out difference is a measured result, not proof of a particular
cache or store-to-load forwarding mechanism.

The CLI also prints a separate CommonCrypto reference table. One cryptor is
created outside timing and reused for steady-state update calls. CommonCrypto
may use the same hardware AES accelerator as HardwareAES, so this is a
reference measurement rather than a universal faster/slower claim.
For small messages, the observed difference also includes CommonCrypto's
per-call validation and dispatch overhead; it does not demonstrate faster AES
round execution.
In this single release run HardwareAES led CommonCrypto by about +83% (1.83×) at 256 B and +30% (1.30×) at 1 KB,
was about 10% faster at 4 KB, and trailed CommonCrypto by roughly 3–10%
from 64 KB through 100 MB.

Reproduce with:

```bash
swift run -c release HardwareAESBenchmarkCLI
```

The benchmark uses `mach_absolute_time()`, cached timebase conversion,
buffer reuse, 3 warmup iterations below 8 MB, 1 warmup iteration at or above
8 MB, and a 0.5 second target duration per size. Run it as a separate CLI
process after letting the machine idle for 30–60 seconds. Thermal state,
power mode, background load, and CPU frequency affect peak measurements.

## License

MIT License
