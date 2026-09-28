// HardwareAES ARM Crypto Extensions - Main Header
#ifndef AES_ARM64_H
#define AES_ARM64_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Context sizes for AES-128
// HAES_AES128_CTX_BYTES_ENCRYPT: 176 bytes (encryption keys only, for CTR)
// HAES_AES128_CTX_BYTES_FULL: 352 bytes (encryption + decryption keys, for ECB)
#define HAES_AES128_CTX_BYTES 352
#define HAES_AES128_CTX_BYTES_ENCRYPT 176
#define HAES_AES128_CTX_BYTES_FULL 352

// ============================================================================
// Common Functions (always available)
// ============================================================================

// Initialize AES-128 context with the provided key
// ctx: output buffer (must be at least HAES_AES128_CTX_BYTES)
// key: 16-byte AES key
// Returns: 0 on success, -1 on error
int haes_aes128_init(uint8_t *ctx, const uint8_t *key);

// Securely clears a memory region before it is released.
void haes_secure_zero(void *ptr, size_t len);

// Compares equal-length secret tags without content-dependent early exit.
// Callers must validate that both buffers contain `len` readable bytes.
int haes_constant_time_equal(const uint8_t *lhs, const uint8_t *rhs, size_t len);

// C-side CTR known-answer and counter-wrap self-tests.
int haes_aes128_ctr_kat(void);
int haes_aes128_ctr_overflow_test(void);

// ============================================================================
// CTR Mode Functions (HardwareAESCTR module)
// ============================================================================

// AES-128 CTR encryption/decryption (XOR with encrypted counter)
// in: input buffer (any length)
// out: output buffer (same size as input)
// len: length in bytes
// ctx: AES context initialized with haes_aes128_init
// iv: 16-byte initialization vector (counter start value)
// Buffer overlap contract:
//   - Disjoint buffers: supported.
//   - Exact in-place (in == out): supported.
//   - Partial overlap: undefined behavior.
// Returns: 0 on success, -1 on error
int haes_aes128_ctr_xor(const uint8_t *in, uint8_t *out, size_t len, const uint8_t *ctx, const uint8_t *iv);

#ifdef __cplusplus
}
#endif

#endif // AES_ARM64_H
