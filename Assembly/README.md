# HardwareAES ARM Crypto Extensions

> AES-128 only. This implementation accepts exactly 16-byte keys and does not
> implement AES-192 or AES-256.

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
│   └── aes_ecb.c              # Private AES block primitive for CMAC
└── include/
    └── aes_arm64.h            # Public core/CTR C API; ECB is not declared
```

## API

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
undefined behavior and must not be used. The internal ECB block primitive is
not declared in the public C header.

The regular Swift CTR operation is stateless: each call starts at the IV
provided by the caller. For a logical stream split across arbitrary chunk
boundaries, use `HardwareAESCTRStream`; it preserves both the 32-bit
big-endian counter and any unused bytes of the current keystream block.

## Usage

### Swift

```swift
let key = try SecureKey(Data(repeating: 0x42, count: 16))
let engine = try HardwareAESCTR(key: key)
let mode = try CTRMode(iv: try AESIV.random())
let ciphertext = try engine.encrypt(Data("Hello".utf8), mode: mode)
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

Run the package tests with `swift test`. The benchmark CLI also runs a
correctness preflight covering the 4-block NIST CTR vector,
CommonCrypto differential checks, tails, in-place and unaligned buffers,
segmented streams, and counter-wrap behavior.

## Performance

The following median values are from the `-c release` run captured on
2026-09-28 on a MacBook Pro. Its correctness preflight passed 551 checks,
including 256 randomized cases. The in-place path rotates across independent
buffers. Repeated
runs can vary by roughly ±5–10% with thermal state, power mode, background load,
and CPU frequency.

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
values are not single-call `Time/op` latency measurements. The table is a
single release run on one MacBook Pro, not a universal performance guarantee.

Out-of-place was faster through 16 MB in this run; in-place was slightly faster
at 64 MB and 100 MB. These observations do not establish a microarchitectural
cause.

### CommonCrypto Reference

The CLI also prints a separate CommonCrypto reference table. One
`CCCryptor` is created outside the timed section and reused for steady-state
`CCCryptorUpdate` calls. CommonCrypto may use the same Apple Silicon AES
accelerator; these values are not a claim that either implementation is
universally better.
In this run HardwareAES led CommonCrypto at 256 B, 1 KB, and 4 KB. CommonCrypto
led from 16 KB through 100 MB. Results are API-level measurements from one
machine, not evidence about AES round speed.

| Size | HardwareAES | CommonCrypto |
| --- | ---: | ---: |
| 256 B | 10790.75 MiB/s | 5527.71 MiB/s |
| 1 KB | 15761.60 MiB/s | 11534.20 MiB/s |
| 4 KB | 15703.52 MiB/s | 15470.30 MiB/s |
| 16 KB | 16025.64 MiB/s | 16592.92 MiB/s |
| 64 KB | 16094.42 MiB/s | 17103.76 MiB/s |
| 256 KB | 16129.03 MiB/s | 17241.38 MiB/s |
| 1 MB | 16085.79 MiB/s | 17278.62 MiB/s |
| 4 MB | 15992.00 MiB/s | 17284.84 MiB/s |
| 16 MB | 15932.29 MiB/s | 17263.86 MiB/s |
| 64 MB | 15790.45 MiB/s | 17010.91 MiB/s |
| 100 MB | 15584.82 MiB/s | 17008.61 MiB/s |

## Methodology

- Timer: `mach_absolute_time()` with cached `mach_timebase_info`.
- Warmup: 3 iterations below 8 MB, 1 iteration at or above 8 MB.
- Target duration: 0.5 seconds per size.
- Iteration bounds: minimum 5, maximum 50,000,000.
- Batching: operations are grouped for small buffers before each timer read.
- Statistics: final throughput is based on the median of per-run median times.
  Small-buffer samples are batched to amortize timer overhead, so these are not
  single-call latency measurements.
- Output validation: benchmark outputs are consumed after timing with a
  checksum to prevent dead-code elimination.
- Implementations run sequentially in one process; OS scheduling and background
  load are not controlled.
- Buffer reuse: buffers are allocated once and reused between measurements.
- Build: `swift run -c release HardwareAESBenchmarkCLI --runs 3`.
- Run the benchmark as a separate CLI process, outside the test suite.
- For peak reproducibility, let the machine idle for 30–60 seconds before running.

## Reproduce

```bash
./Scripts/run-release-benchmark.sh 3
```

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
