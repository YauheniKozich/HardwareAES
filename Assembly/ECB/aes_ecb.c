// AES-128 ECB Mode Implementation for ARM Crypto Extensions
#include <stddef.h>
#include <stdint.h>

#if !defined(__aarch64__)

int haes_aes128_ecb_encrypt(const uint8_t *in, uint8_t *out, size_t len, const uint8_t *ctx) {
    (void)in;
    (void)out;
    (void)len;
    (void)ctx;
    return -1;
}

int haes_aes128_ecb_decrypt(const uint8_t *in, uint8_t *out, size_t len, const uint8_t *ctx) {
    (void)in;
    (void)out;
    (void)len;
    (void)ctx;
    return -1;
}

#else

#include "../Common/aes_common.h"

// AES-128 ECB encrypt using hardware instructions
// vaeseq_u8 does: AddRoundKey -> ShiftRows -> SubBytes
// Keys and data are both in big-endian format — no byte-swapping needed.
int haes_aes128_ecb_encrypt(const uint8_t *in, uint8_t *out, size_t len, const uint8_t *ctx) {
    if (!in || !out || !ctx || len % AES_BLOCK != 0) return -1;
    if (((uintptr_t)ctx & 15) != 0) return -1;

    const uint8x16_t *keys = (const uint8x16_t *)ctx;

    for (size_t i = 0; i < len; i += AES_BLOCK) {
        uint8x16_t state = vld1q_u8(in + i);

        for (int r = 0; r < 9; r++) {
            state = vaesmcq_u8(vaeseq_u8(state, keys[r]));
        }
        state = veorq_u8(vaeseq_u8(state, keys[9]), keys[10]);

        vst1q_u8(out + i, state);
    }
    return 0;
}

// AES-128 ECB decrypt using hardware instructions
// Uses equivalent decryption: InvSubBytes → InvShiftRows → InvMixColumns → AddRoundKey
// vaesdq_u8(state, 0) = InvShiftRows(InvSubBytes(state))
// vaesimcq_u8(state) = InvMixColumns
// Decryption keys at ctx+176 in big-endian:
//   K'_0 = K_10, K'_r = InvMixColumns(K_r) for r=1..9, K'_10 = K_0
int haes_aes128_ecb_decrypt(const uint8_t *in, uint8_t *out, size_t len, const uint8_t *ctx) {
    if (!in || !out || !ctx || len % AES_BLOCK != 0) return -1;

    // Смещение +176 указывает на начало раундовых ключей дешифрования
    const uint8x16_t *keys = (const uint8x16_t *)(ctx + 176);

    for (size_t i = 0; i < len; i += AES_BLOCK) {
        uint8x16_t state = vld1q_u8(in + i);

        // Раунды 0-8: vaesdq делает AddRoundKey(keys[r]) -> InvSubBytes -> InvShiftRows
        // затем vaesimcq делает InvMixColumns
        for (int r = 0; r < 9; r++) {
            state = vaesimcq_u8(vaesdq_u8(state, keys[r]));
        }

        // Финальный раунд 9: без InvMixColumns
        // vaesdq делает AddRoundKey(keys[9]) -> InvSubBytes -> InvShiftRows
        // Затем снимаем остаточный XOR последним ключом keys[10]
        state = veorq_u8(vaesdq_u8(state, keys[9]), keys[10]);

        vst1q_u8(out + i, state);
    }
    return 0;
}

#endif
