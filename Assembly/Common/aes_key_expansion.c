// AES-128 Key Expansion for ARM Crypto Extensions
#include <stdint.h>
#include <string.h>

#if !defined(__aarch64__)

int haes_aes128_init(uint8_t *ctx, const uint8_t *key) {
    (void)ctx;
    (void)key;
    return -1;
}

#else

#include "aes_common.h"

int haes_aes128_init(uint8_t *ctx, const uint8_t *key) {
    if (!ctx || !key || ((uintptr_t)ctx & 15) != 0) return -1;

    uint8_t rk[16 * 11];
    memcpy(rk, key, 16);

    for (int i = 0; i < 10; i++) {
        uint8_t *prev = rk + i * 16;
        uint8_t *next = rk + (i + 1) * 16;
        uint8_t t0 = aes_sbox[prev[13]] ^ aes_rcon[i];
        uint8_t t1 = aes_sbox[prev[14]];
        uint8_t t2 = aes_sbox[prev[15]];
        uint8_t t3 = aes_sbox[prev[12]];

        next[0] = prev[0] ^ t0;
        next[1] = prev[1] ^ t1;
        next[2] = prev[2] ^ t2;
        next[3] = prev[3] ^ t3;

        for (int j = 4; j < 16; j++) {
            next[j] = prev[j] ^ next[j - 4];
        }
    }

    // Encryption keys at offset 0: big-endian (no swap) for CTR and ECB encrypt.
    memcpy(ctx, rk, 176);

    // Decryption keys at offset 176: big-endian for ECB decrypt.
    // K'_0 = K_10, K'_r = AESIMC(K_r) for r=1..9, K'_10 = K_0
    uint8_t *dec = ctx + 176;

    memcpy(dec, rk + 160, 16);

    for (int i = 1; i < 10; i++) {
        uint8x16_t t = vld1q_u8(rk + (10 - i) * 16);
        t = vaesimcq_u8(t);
        vst1q_u8(dec + i * 16, t);
    }

    memcpy(dec + 160, rk, 16);

    haes_secure_zero(rk, sizeof(rk));
    return 0;
}

#endif
