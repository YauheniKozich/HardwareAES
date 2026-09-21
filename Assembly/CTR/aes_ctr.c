// ============================================================================
// AES-128 CTR Mode — Optimized for Apple Silicon (AArch64)
// Standard: NIST SP 800-38A (big-endian 32-bit counter increment)
//
// Microarchitecture Notes (Apple Silicon P-cores):
//   1. Preloads round keys (k0..k10) into NEON registers ONCE upon entry,
//      reducing Load-Store Unit (LSU) pressure in the hot loop.
//   2. 8-way interleaving: targets saturation of Apple's 4-wide AES pipeline.
//   3. Fully unrolled round loop: eliminates branch prediction overhead.
//   4. Vectorized ctr_add: pure NEON domain counter increment without
//      GPR <-> NEON cross-domain penalties.
//   5. Register footprint: ~21 NEON registers used. Check generated assembly
//      via `clang -S` to verify zero stack spilling for target microarchitecture.
// ============================================================================

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(HAES_DEBUG)
#include <assert.h>
#endif

#if !defined(__aarch64__)

int haes_aes128_ctr_xor(const uint8_t *in, uint8_t *out, size_t len,
                         const uint8_t *ctx, const uint8_t *iv) {
    if (!in || !out || !ctx || !iv) return -1;
    if (len == 0) return 0;
    return -1;
}

#else

#include <arm_neon.h>
#include "../Common/aes_common.h"

#ifndef AES_BLOCK
#define AES_BLOCK 16
#endif

// ============================================================================
// Векторный инкремент 32-битного Big-Endian счётчика (NIST SP 800-38A F.5.1).
// Выполняется строго в NEON-домене (без GPR-пересылок).
// ============================================================================
static inline uint8x16_t ctr_add_le(uint32x4_t ctr_le, uint32_t delta) {
    uint32x4_t inc = vsetq_lane_u32(delta, vdupq_n_u32(0), 3);
    uint32x4_t res_le = vaddq_u32(ctr_le, inc);
    return vrev32q_u8(vreinterpretq_u8_u32(res_le));
}

static inline uint8x16_t ctr_add(uint8x16_t v, uint32_t delta) {
    uint32x4_t v_le = vreinterpretq_u32_u8(vrev32q_u8(v));
    return ctr_add_le(v_le, delta);
}

// Макрос одного раунда для 8 параллельных блоков
#define AES_ROUND_8(s0, s1, s2, s3, s4, s5, s6, s7, k)                   \
    do {                                                                 \
        s0 = vaesmcq_u8(vaeseq_u8((s0), (k)));                           \
        s1 = vaesmcq_u8(vaeseq_u8((s1), (k)));                           \
        s2 = vaesmcq_u8(vaeseq_u8((s2), (k)));                           \
        s3 = vaesmcq_u8(vaeseq_u8((s3), (k)));                           \
        s4 = vaesmcq_u8(vaeseq_u8((s4), (k)));                           \
        s5 = vaesmcq_u8(vaeseq_u8((s5), (k)));                           \
        s6 = vaesmcq_u8(vaeseq_u8((s6), (k)));                           \
        s7 = vaesmcq_u8(vaeseq_u8((s7), (k)));                           \
    } while (0)

// Макрос одного раунда для 4 параллельных блоков
#define AES_ROUND_4(s0, s1, s2, s3, k)                                   \
    do {                                                                 \
        s0 = vaesmcq_u8(vaeseq_u8((s0), (k)));                           \
        s1 = vaesmcq_u8(vaeseq_u8((s1), (k)));                           \
        s2 = vaesmcq_u8(vaeseq_u8((s2), (k)));                           \
        s3 = vaesmcq_u8(vaeseq_u8((s3), (k)));                           \
    } while (0)

// ============================================================================
// 8-way interleaved encryption — главный высокоскоростной путь Apple Silicon.
// ============================================================================
static inline void aes_ctr_encrypt_8_blocks(
    const uint8_t *in, uint8_t *out,
    uint8x16_t k0, uint8x16_t k1, uint8x16_t k2, uint8x16_t k3,
    uint8x16_t k4, uint8x16_t k5, uint8x16_t k6, uint8x16_t k7,
    uint8x16_t k8, uint8x16_t k9, uint8x16_t k10,
    uint8x16_t *ctr_vec)
{
    uint32x4_t ctr_le = vreinterpretq_u32_u8(vrev32q_u8(*ctr_vec));

    uint8x16_t s0 = *ctr_vec;
    uint8x16_t s1 = ctr_add_le(ctr_le, 1);
    uint8x16_t s2 = ctr_add_le(ctr_le, 2);
    uint8x16_t s3 = ctr_add_le(ctr_le, 3);
    uint8x16_t s4 = ctr_add_le(ctr_le, 4);
    uint8x16_t s5 = ctr_add_le(ctr_le, 5);
    uint8x16_t s6 = ctr_add_le(ctr_le, 6);
    uint8x16_t s7 = ctr_add_le(ctr_le, 7);

    *ctr_vec = ctr_add_le(ctr_le, 8);

    // Развернутые раунды 0–8
    AES_ROUND_8(s0, s1, s2, s3, s4, s5, s6, s7, k0);
    AES_ROUND_8(s0, s1, s2, s3, s4, s5, s6, s7, k1);
    AES_ROUND_8(s0, s1, s2, s3, s4, s5, s6, s7, k2);
    AES_ROUND_8(s0, s1, s2, s3, s4, s5, s6, s7, k3);
    AES_ROUND_8(s0, s1, s2, s3, s4, s5, s6, s7, k4);
    AES_ROUND_8(s0, s1, s2, s3, s4, s5, s6, s7, k5);
    AES_ROUND_8(s0, s1, s2, s3, s4, s5, s6, s7, k6);
    AES_ROUND_8(s0, s1, s2, s3, s4, s5, s6, s7, k7);
    AES_ROUND_8(s0, s1, s2, s3, s4, s5, s6, s7, k8);

    // Раунд 9 + финальный XOR с ключом k10
    s0 = veorq_u8(vaeseq_u8(s0, k9), k10);
    s1 = veorq_u8(vaeseq_u8(s1, k9), k10);
    s2 = veorq_u8(vaeseq_u8(s2, k9), k10);
    s3 = veorq_u8(vaeseq_u8(s3, k9), k10);
    s4 = veorq_u8(vaeseq_u8(s4, k9), k10);
    s5 = veorq_u8(vaeseq_u8(s5, k9), k10);
    s6 = veorq_u8(vaeseq_u8(s6, k9), k10);
    s7 = veorq_u8(vaeseq_u8(s7, k9), k10);

    vst1q_u8(out +   0, veorq_u8(s0, vld1q_u8(in +   0)));
    vst1q_u8(out +  16, veorq_u8(s1, vld1q_u8(in +  16)));
    vst1q_u8(out +  32, veorq_u8(s2, vld1q_u8(in +  32)));
    vst1q_u8(out +  48, veorq_u8(s3, vld1q_u8(in +  48)));
    vst1q_u8(out +  64, veorq_u8(s4, vld1q_u8(in +  64)));
    vst1q_u8(out +  80, veorq_u8(s5, vld1q_u8(in +  80)));
    vst1q_u8(out +  96, veorq_u8(s6, vld1q_u8(in +  96)));
    vst1q_u8(out + 112, veorq_u8(s7, vld1q_u8(in + 112)));
}

// ============================================================================
// 4-way interleaved encryption — обработка остатка после 8-way цикла.
// ============================================================================
static inline void aes_ctr_encrypt_4_blocks(
    const uint8_t *in, uint8_t *out,
    uint8x16_t k0, uint8x16_t k1, uint8x16_t k2, uint8x16_t k3,
    uint8x16_t k4, uint8x16_t k5, uint8x16_t k6, uint8x16_t k7,
    uint8x16_t k8, uint8x16_t k9, uint8x16_t k10,
    uint8x16_t *ctr_vec)
{
    uint32x4_t ctr_le = vreinterpretq_u32_u8(vrev32q_u8(*ctr_vec));

    uint8x16_t s0 = *ctr_vec;
    uint8x16_t s1 = ctr_add_le(ctr_le, 1);
    uint8x16_t s2 = ctr_add_le(ctr_le, 2);
    uint8x16_t s3 = ctr_add_le(ctr_le, 3);

    *ctr_vec = ctr_add_le(ctr_le, 4);

    AES_ROUND_4(s0, s1, s2, s3, k0);
    AES_ROUND_4(s0, s1, s2, s3, k1);
    AES_ROUND_4(s0, s1, s2, s3, k2);
    AES_ROUND_4(s0, s1, s2, s3, k3);
    AES_ROUND_4(s0, s1, s2, s3, k4);
    AES_ROUND_4(s0, s1, s2, s3, k5);
    AES_ROUND_4(s0, s1, s2, s3, k6);
    AES_ROUND_4(s0, s1, s2, s3, k7);
    AES_ROUND_4(s0, s1, s2, s3, k8);

    s0 = veorq_u8(vaeseq_u8(s0, k9), k10);
    s1 = veorq_u8(vaeseq_u8(s1, k9), k10);
    s2 = veorq_u8(vaeseq_u8(s2, k9), k10);
    s3 = veorq_u8(vaeseq_u8(s3, k9), k10);

    vst1q_u8(out +  0, veorq_u8(s0, vld1q_u8(in +  0)));
    vst1q_u8(out + 16, veorq_u8(s1, vld1q_u8(in + 16)));
    vst1q_u8(out + 32, veorq_u8(s2, vld1q_u8(in + 32)));
    vst1q_u8(out + 48, veorq_u8(s3, vld1q_u8(in + 48)));
}

// ============================================================================
// Single-block encryption — для финальных 1-3 полных блоков.
// ============================================================================
static inline void aes_ctr_encrypt_1_block(
    const uint8_t *in, uint8_t *out,
    uint8x16_t k0, uint8x16_t k1, uint8x16_t k2, uint8x16_t k3,
    uint8x16_t k4, uint8x16_t k5, uint8x16_t k6, uint8x16_t k7,
    uint8x16_t k8, uint8x16_t k9, uint8x16_t k10,
    uint8x16_t *ctr_vec)
{
    uint8x16_t state = *ctr_vec;
    *ctr_vec = ctr_add(state, 1);

    state = vaesmcq_u8(vaeseq_u8(state, k0));
    state = vaesmcq_u8(vaeseq_u8(state, k1));
    state = vaesmcq_u8(vaeseq_u8(state, k2));
    state = vaesmcq_u8(vaeseq_u8(state, k3));
    state = vaesmcq_u8(vaeseq_u8(state, k4));
    state = vaesmcq_u8(vaeseq_u8(state, k5));
    state = vaesmcq_u8(vaeseq_u8(state, k6));
    state = vaesmcq_u8(vaeseq_u8(state, k7));
    state = vaesmcq_u8(vaeseq_u8(state, k8));
    state = veorq_u8(vaeseq_u8(state, k9), k10);

    vst1q_u8(out, veorq_u8(state, vld1q_u8(in)));
}

// ============================================================================
// Точка входа: AES-128-CTR XOR.
// ============================================================================
int haes_aes128_ctr_xor(const uint8_t *in, uint8_t *out, size_t len,
                         const uint8_t *ctx, const uint8_t *iv) {
    if (!in || !out || !ctx || !iv) return -1;
    if (len == 0) return 0;

#if defined(HAES_DEBUG)
    if (in != out) {
        uintptr_t inAddress = (uintptr_t)in;
        uintptr_t outAddress = (uintptr_t)out;
        uintptr_t diff = outAddress > inAddress
            ? outAddress - inAddress
            : inAddress - outAddress;
        assert(diff >= len && "partial overlap is undefined behavior");
    }
#endif

    if (((uintptr_t)ctx & 15) != 0) return -1;

    const uint8x16_t *keys = (const uint8x16_t *)__builtin_assume_aligned(ctx, 16);

    const uint8x16_t k0  = keys[0];
    const uint8x16_t k1  = keys[1];
    const uint8x16_t k2  = keys[2];
    const uint8x16_t k3  = keys[3];
    const uint8x16_t k4  = keys[4];
    const uint8x16_t k5  = keys[5];
    const uint8x16_t k6  = keys[6];
    const uint8x16_t k7  = keys[7];
    const uint8x16_t k8  = keys[8];
    const uint8x16_t k9  = keys[9];
    const uint8x16_t k10 = keys[10];

    uint8x16_t ctr_vec = vld1q_u8(iv);
    size_t offset = 0;

    size_t blocks8 = len / (AES_BLOCK * 8);
    for (size_t i = 0; i < blocks8; i++, offset += AES_BLOCK * 8) {
        aes_ctr_encrypt_8_blocks(in + offset, out + offset,
                                 k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10,
                                 &ctr_vec);
    }

    if ((len / AES_BLOCK) & 4) {
        aes_ctr_encrypt_4_blocks(in + offset, out + offset,
                                 k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10,
                                 &ctr_vec);
        offset += AES_BLOCK * 4;
    }

    size_t tail_blocks = (len / AES_BLOCK) & 3;
    for (size_t i = 0; i < tail_blocks; i++, offset += AES_BLOCK) {
        aes_ctr_encrypt_1_block(in + offset, out + offset,
                                k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10,
                                &ctr_vec);
    }

    size_t tail_bytes = len % AES_BLOCK;
    if (tail_bytes > 0) {
        uint8x16_t state = ctr_vec;
        state = vaesmcq_u8(vaeseq_u8(state, k0));
        state = vaesmcq_u8(vaeseq_u8(state, k1));
        state = vaesmcq_u8(vaeseq_u8(state, k2));
        state = vaesmcq_u8(vaeseq_u8(state, k3));
        state = vaesmcq_u8(vaeseq_u8(state, k4));
        state = vaesmcq_u8(vaeseq_u8(state, k5));
        state = vaesmcq_u8(vaeseq_u8(state, k6));
        state = vaesmcq_u8(vaeseq_u8(state, k7));
        state = vaesmcq_u8(vaeseq_u8(state, k8));
        state = veorq_u8(vaeseq_u8(state, k9), k10);

        uint8_t keystream[AES_BLOCK];
        vst1q_u8(keystream, state);

        for (size_t i = 0; i < tail_bytes; i++) {
            out[offset + i] = in[offset + i] ^ keystream[i];
        }

        haes_secure_zero(keystream, sizeof(keystream));
    }

    ctr_vec = vdupq_n_u8(0);
    __asm__ __volatile__("" : "+w"(ctr_vec) : : "memory");

    return 0;
}

#endif
