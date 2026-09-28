# HardwareAES ARM Crypto Extensions

> AES-128 only. All public engines and authenticated containers accept exactly
> 16-byte keys. AES-192 and AES-256 are not implemented.

HardwareAES is an Apple Silicon AES-128 Swift package focused on a small,
auditable surface: stateless CTR, a stateful CTR stream, and an authenticated
versioned container. It exists to make the ARM Crypto Extensions implementation
and its cryptographic contracts inspectable and testable; it is not a general
cryptography toolkit.

## Security Guarantees and Limits

The implementation provides AES-128 CTR with NIST `inc32` counter semantics,
AES-CMAC authentication for `SecureFileVault`, tag verification before
decryption, and explicit context/key-schedule zeroing on owner deallocation.
The tag comparison visits every byte of the fixed-size tag without a
content-dependent early exit. These are implementation properties, not a
formal constant-time certification.

CTR by itself does not authenticate ciphertext. Memory zeroing cannot remove
copies held by callers, Foundation, compiler temporaries, CPU registers, or
caches. `FileAESNonceSequence` protects against concurrent writers and commits
state before returning a nonce, but it cannot prevent a privileged/local actor
from replacing or rolling back its state file. Keep that file in trusted
private storage, exclude it from backups, and rotate the encryption key after
restore. A `RandomAESNonceSequence` is probabilistic and its usage counter is
per instance; use it only with an ephemeral key whose lifetime does not cross
process restarts. The container has no AAD or streaming format and currently
has no configured maximum input size.

## Directory Structure

```
Assembly/
├── Common/
│   ├── aes_common.h           # Shared constants and secure_zero declaration
│   ├── aes_key_expansion.c    # Encryption/decryption key schedule
│   ├── aes_secure_zero.c      # Non-elidable memory zeroization
│   └── aes_selftest.c         # C-side NIST KAT and counter-overflow tests
│
├── CTR/
│   └── aes_ctr.c              # CTR mode, 8-way interleaved
├── ECB/
│   └── aes_ecb.c              # Private block primitive for CMAC
└── include/
    └── aes_arm64.h            # Public CTR/core C API (no ECB declarations)
```

## API

The Swift package products are `HardwareAESCore`, `HardwareAESCTR`,
`HardwareAESAuthenticated`, and the `HardwareAES` facade. The package-only
`HardwareAESBlockCipher` target supplies AES-CMAC and is not a package product;
ECB is not exposed as an encryption mode.

```c
int haes_aes128_init(uint8_t *ctx, const uint8_t *key);

int haes_aes128_ctr_xor(
    const uint8_t *in, uint8_t *out, size_t len,
    const uint8_t *ctx, const uint8_t *iv
);
```

The AES context must be 16-byte aligned. Input and output buffers do not need
to be aligned. CTR accepts arbitrary lengths, including zero.

For a zero-length operation, the function returns `0` after validating all
pointers; a null pointer still returns `-1`. For CTR, disjoint buffers and
exact in-place operation (`in == out`) are supported. Partial overlap is
undefined behavior and must not be used. The ECB block primitive is private to
the package and has no declaration in the public C header.

The regular Swift CTR operation is stateless: each call starts at the IV
provided by the caller. For a logical stream split across arbitrary chunk
boundaries, use `HardwareAESCTRStream`; it preserves both the 32-bit
big-endian counter and any unused bytes of the current keystream block.

## Cryptographic contracts

- `HardwareAESCTR` implements AES-128-CTR with NIST `inc32`: the low
  big-endian 32-bit word wraps modulo 2^32; the upper 96 bits do not change.
  Each operation is stateless and starts from its supplied 16-byte IV.
- Never reuse a counter block with the same key. `SecureFileVault` requires an
  `AESNonceSequence`; share the sequence across every vault using that key and
  preserve its state across launches. `FileAESNonceSequence` stores and locks
  that state across instances/processes. Keep one state file per key, exclude
  it from backups, and rotate the key after restoring a backup. The bounded
  `RandomAESNonceSequence` is probabilistic and intended only for ephemeral
  keys; its limit is per sequence instance.
- Callers that need a stateful CTR stream across chunks must retain one
  `HardwareAESCTRStream` and must not share it between concurrent producers.
- CTR does not authenticate data. `SecureFileVault` is the authenticated
  container API. Version 1 encodes `version(1) || nonce(16) || ciphertext ||
  tag(16)`. The tag is AES-CMAC over version, nonce, and ciphertext, using a
  separate key derived with AES-CMAC over the fixed domain label
  `HardwareAES-CMAC-MAC-v1`. Decryption verifies the tag before decrypting.
- A single CTR operation or stream is limited to at most 2^32 generated
  counter blocks. `inc32` wrap is defined, but a counter block cannot be reused
  within one operation or stream.
- Authenticated containers use 128-bit nonces. AAD and streaming containers are not
  part of version 1. Treat the serialized format as versioned data.
- Engine contexts are immutable after initialization. CTR synchronous calls
  may run concurrently; its async API dispatches operations on a private
  serial queue. `HardwareAESCTRStream` is mutable, single-owner state.
  `SecureFileVault` coordinates nonce acquisition as an actor; authenticated
  decryption runs off the actor executor, so independent requests may overlap.
- The C API requires a 16-byte-aligned context; buffers may be unaligned.
  Exact in-place and disjoint buffers are supported; partial overlap is
  undefined. Zero-length C calls succeed after pointer validation.

## Usage

### Swift

```swift
let key = try SecureKey(Data(repeating: 0x42, count: 16))
let engine = try HardwareAESCTR(key: key)
let mode = try CTRMode(iv: try AESIV.random())
let ciphertext = try engine.encrypt(Data("Hello".utf8), mode: mode)
```

For authenticated storage, use the container API with durable nonce state:

```swift
let sequence = try FileAESNonceSequence(stateFileURL: nonceStateURL)
let vault = try SecureFileVault(key: key, nonceSequence: sequence)
let sealed = try await vault.encrypt(Data("Hello".utf8))
let opened = try await vault.decrypt(sealed)
```

### C

```c
#include <stdalign.h>
#include <stdint.h>
#include "aes_arm64.h"

alignas(16) uint8_t ctx[352];
uint8_t key[16] = { 0 };
uint8_t iv[16] = { 0 };
uint8_t input[] = "Hello";
uint8_t output[sizeof(input) - 1];

haes_aes128_init(ctx, key);
haes_aes128_ctr_xor(input, output, sizeof(output), ctx, iv);
```

## Key Schedule Layout

| Offset | Size | Content |
| --- | ---: | --- |
| 0–175 | 176 bytes | Encryption round keys |
| 176–351 | 176 bytes | Decryption round keys |

The temporary key schedule is securely zeroed after initialization.

## Implementation Details

- Uses ARMv8 Crypto Extensions: `vaeseq_u8`, `vaesmcq_u8`,
  `vaesdq_u8`, and `vaesimcq_u8`.
- CTR uses NIST `inc32`: only the low 32 bits of the counter are incremented
  in big-endian order; the 96-bit prefix is preserved and the low word wraps
  modulo 2^32.
- CTR uses an 8-way fast path, followed by 4-way and single-block paths.
- Tail bytes are handled without padding.
- C-side self-tests include the complete 64-byte (4-block) NIST SP 800-38A
  CTR vector and counter-wrap coverage.
- Swift tests cover randomized differential comparisons with CommonCrypto,
  unaligned buffers, exact in-place operation, tails, and segmented streams.
- The public low-level contract also covers zero-length calls, 16-byte context
  alignment, and undefined behavior for partial buffer overlap.
- The temporary key schedule and temporary keystream buffers are securely
  zeroed; this is an implementation guarantee for those buffers, not a promise
  about copies that may exist in registers, caches, or compiler temporaries.
- Counter-wrap tests cover prefixes that must remain unchanged by NIST `inc32`.

## Assembly Validation

The hot CTR path is structured as 8-way interleaving with vectorized counter
increment. A current `clang -O3 -mcpu=apple-m1` inspection shows ARM Crypto
instructions and no SIMD-register spill in the 8-way loop. The scalar tail
still materializes its temporary keystream buffer on the stack by design.
Assembly and register allocation must be rechecked for the exact compiler,
SDK, optimization level, and CPU target; these are build-level observations,
not source-level guarantees.

## Requirements

- iOS 15.0+
- macOS 12.0+
- ARM64 architecture (Apple Silicon)
- AES-128 only; keys must be exactly 16 bytes

## Testing

Run the package tests on macOS with `swift test`. Run the public API integration
tests on iOS Simulator with `./Scripts/test-ios-simulator.sh` (requires
XcodeGen). The benchmark CLI also runs a correctness preflight covering the
4-block NIST CTR vector, CommonCrypto differential checks, tails, in-place and
unaligned buffers, segmented streams, and counter-wrap behavior. XCTest also
covers RFC 4493 CMAC known-answer vectors, container tampering, malformed input,
and nonce coordination/persistence.

## Performance

The following values are the median across three Release runs captured on
2026-09-28 on a MacBook Pro 16-inch (Mac15,7, Apple M3 Pro), macOS 27.0,
Swift 6.4, macOS SDK 27.0. Correctness preflight passed 550 checks, including
256 randomized cases. The in-place path rotates across independent buffers.
Run-to-run variation remains hardware and system-load dependent.

| Size | Out-of-place | In-place |
| --- | ---: | ---: |
| 256 B | 11789.49 MiB/s | 8467.30 MiB/s |
| 1 KB | 15189.57 MiB/s | 14230.42 MiB/s |
| 4 KB | 16219.72 MiB/s | 15293.64 MiB/s |
| 16 KB | 16163.79 MiB/s | 15690.38 MiB/s |
| 64 KB | 16181.23 MiB/s | 15906.68 MiB/s |
| 256 KB | 16172.51 MiB/s | 16085.79 MiB/s |
| 1 MB | 16216.22 MiB/s | 16064.26 MiB/s |
| 4 MB | 16177.96 MiB/s | 16088.49 MiB/s |
| 16 MB | 16224.78 MiB/s | 16005.34 MiB/s |
| 64 MB | 16059.64 MiB/s | 16114.82 MiB/s |
| 100 MB | 15923.14 MiB/s | 16071.84 MiB/s |

*Note:* small-buffer operations are batched before timing, so these throughput
values are not single-call `Time/op` latency measurements. The table is a
three-run release measurement on one MacBook Pro, not a universal performance guarantee.

Out-of-place was faster through 16 MB in this run; in-place was slightly
faster at 64 MB and 100 MB. These measurements do not establish a
microarchitectural cause.

### CommonCrypto Reference

The CLI also prints a separate CommonCrypto reference table. One
`CCCryptor` is created outside the timed section and reused for steady-state
`CCCryptorUpdate` calls. CommonCrypto may use the same Apple Silicon AES
accelerator; these values are not a claim that either implementation is
universally better.
In this run HardwareAES led at 256 B, 1 KB, and 4 KB. CommonCrypto led at
16 KB and all larger measured sizes through 100 MB. These API-level results
are one-machine observations, not evidence about AES round speed.

| Size | HardwareAES | CommonCrypto |
| --- | ---: | ---: |
| 256 B | 11789.49 MiB/s | 5538.16 MiB/s |
| 1 KB | 15189.57 MiB/s | 11438.51 MiB/s |
| 4 KB | 16219.72 MiB/s | 15394.09 MiB/s |
| 16 KB | 16163.79 MiB/s | 16741.07 MiB/s |
| 64 KB | 16181.23 MiB/s | 17142.86 MiB/s |
| 256 KB | 16172.51 MiB/s | 17241.38 MiB/s |
| 1 MB | 16216.22 MiB/s | 17278.62 MiB/s |
| 4 MB | 16177.96 MiB/s | 17284.84 MiB/s |
| 16 MB | 16224.78 MiB/s | 17263.08 MiB/s |
| 64 MB | 16059.64 MiB/s | 17030.43 MiB/s |
| 100 MB | 15923.14 MiB/s | 17036.86 MiB/s |

## Methodology

- Timer: `mach_absolute_time()` with cached `mach_timebase_info`.
- Warmup: 3 iterations below 8 MB, 1 iteration at or above 8 MB.
- Target duration: 0.5 seconds per size.
- Iteration bounds: minimum 5, maximum 50,000,000; the cap only applies when
  the requested data volume would otherwise exceed it.
- Batching: operations are grouped for small buffers before each timer read.
- Statistics: within each run, batch-average times are collected per operation;
  final throughput uses the median of the run medians. Small-buffer samples are
  batched to amortize timer overhead, so these are not single-call latencies.
- Repeated runs: the CLI defaults to 3 complete runs; reported throughput is
  derived from the median of each run's median time. Pass `--runs N` to choose
  another positive run count.
- Output validation: benchmark outputs are consumed after timing with a
  checksum to prevent dead-code elimination.
- Execution: implementations run sequentially in one process; OS scheduling and
  background load are not controlled.
- Buffer reuse: buffers are allocated once and reused between measurements.
- Build: `swift run -c release HardwareAESBenchmarkCLI --runs 3`.
- Run the benchmark as a separate CLI process, outside the test suite.
- For peak reproducibility, let the machine idle for 30–60 seconds before running.

## Reproduce

```bash
./Scripts/run-release-benchmark.sh 3
```

The script records macOS version, machine model, available CPU/SoC string,
architecture, Swift compiler version, and macOS SDK, then builds and runs the
CLI in Release configuration. It runs the correctness preflight once, performs
warmup on each implementation per run, reports the median across repeated run
medians, and exits without an interactive prompt. `swift run` compiles before
the benchmark process starts, so build time is excluded from measured samples.

The CLI runs a correctness preflight before timing. It includes the complete
4-block NIST CTR vector, deterministic randomized differential
checks against CommonCrypto, tail/boundary sizes, round trips, unaligned and
in-place buffers, segmented stream updates, and NIST `inc32` counter-wrap
checks. Performance results are not produced if this preflight fails. The
zero-length, partial-overlap, context-alignment, and key-schedule-zeroization
contracts are documented separately and are not all runtime-tested by this
preflight.

## Known Caveats

- Benchmark results depend on thermal state, power mode, background load,
  and CPU frequency. Run on a cool, idle chip when comparing peak values.
- Temperature and frequency are intentionally not sampled inside the timed
  section; `powermetrics` may require privileges and would perturb the run.
- The in-place benchmark rotates across an independent buffer ring to avoid
  making every operation immediately consume the previous operation's stores.
  Remaining in/out differences are measurements, not an established
  microarchitectural explanation.
- Throughput plateaus near 15–16 GiB/s for the larger tested buffers.
- CTR provides confidentiality but not authentication; use an authenticated
  mode when integrity protection is required.
- `haes_secure_zero` clears the temporary key schedule and temporary
  keystream buffers. It cannot guarantee destruction of copies held in CPU
  registers, caches, compiler-generated temporaries, or unrelated memory.

## License

MIT License
