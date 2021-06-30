/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#include "basics.h"
#include "console.h"
#include "aes.h"
#include "stm32l4xx_hal.h"
#include "constant_time.h"
#include <string.h>

// aes_init()
//
    void
aes_init(AES_CTX *ctx)
{
    memset(ctx, 0, sizeof(AES_CTX));
}

// aes_add()
//
// - capture more data to be encrypted/decrypted
//
    void
aes_add(AES_CTX *ctx, const uint8_t data_in[], uint32_t len)
{
    memcpy(ctx->pending+ctx->num_pending, data_in, len);
    ctx->num_pending += len;

    ASSERT(ctx->num_pending < sizeof(ctx->pending));
}

// word_pump_bytes()
//
// Return bytes as words. Handles misaligned inputs. Also byte-reverses.
//
    static inline uint32_t
word_pump_bytes(const uint8_t **src)
{
    uint32_t rv;

    if(((uint32_t)src) & 0x3) {
        memcpy(&rv, *src, 4);
    } else {
        rv = *(uint32_t *)(*src);
    }
    (*src) += 4;

    return __REV(rv);
}

// aes_done()
//
// Do the decryption.
//
    void
aes_done(AES_CTX *ctx, uint8_t data_out[], uint32_t len, const uint8_t key[32], const uint8_t nonce[AES_BLOCK_SIZE])
{
    ASSERT(len <= ctx->num_pending);

    // enable clock to block
    __HAL_RCC_AES_CLK_ENABLE();

    // most settings done w/ disable in effect
    AES->CR &=  ~AES_CR_EN;

    // Set the Key size selection, operation mode
    MODIFY_REG(AES->CR, AES_CR_KEYSIZE, CRYP_KEYSIZE_256B);
    MODIFY_REG(AES->CR, AES_CR_DATATYPE|AES_CR_MODE|AES_CR_CHMOD, 
            CRYP_DATATYPE_8B | CRYP_ALGOMODE_ENCRYPT | CRYP_CHAINMODE_AES_CTR);

    // load key and IV values
    const uint8_t *K = key;
    AES->KEYR7 = word_pump_bytes(&K);
    AES->KEYR6 = word_pump_bytes(&K);
    AES->KEYR5 = word_pump_bytes(&K);
    AES->KEYR4 = word_pump_bytes(&K);
    AES->KEYR3 = word_pump_bytes(&K);
    AES->KEYR2 = word_pump_bytes(&K);
    AES->KEYR1 = word_pump_bytes(&K);
    AES->KEYR0 = word_pump_bytes(&K);

    if(nonce) {
        const uint8_t *N = nonce;
        AES->IVR3 = word_pump_bytes(&N);
        AES->IVR2 = word_pump_bytes(&N);
        AES->IVR1 = word_pump_bytes(&N);
        AES->IVR0 = word_pump_bytes(&N);
    } else {
        AES->IVR3 = 0;
        AES->IVR2 = 0;
        AES->IVR1 = 0;
        AES->IVR0 = 0;          // maybe should be byte-swapped one, but whatever
    }

    // Enable the Peripheral
    AES->CR |= AES_CR_EN;

    ASSERT((((uint32_t)&ctx->pending) & 3) == 0);      // safe because of special attr

    uint32_t    *p = (uint32_t *)ctx->pending;
    for(int i=0; i < ctx->num_pending; i += 16) {
        // Write the block to the AES engine
        AES->DINR = *p; p++;
        AES->DINR = *p; p++;
        AES->DINR = *p; p++;
        AES->DINR = *p; p++;

        // Wait for CCF flag to be raised
        while(HAL_IS_BIT_CLR(AES->SR, AES_SR_CCF)) {
            // no timeout -- just 75 cycles?
        }

        // clear CCF flag
        SET_BIT(AES->CR, CRYP_CCF_CLEAR);

        // work in place, overwrite what we just wrote
        uint32_t    *out = p - 4;
        *out = AES->DOUTR; out++;
        *out = AES->DOUTR; out++;
        *out = AES->DOUTR; out++;
        *out = AES->DOUTR;
    }

    memcpy(data_out, ctx->pending, len);

    memset(ctx, 0, sizeof(AES_CTX));

    // reset state of chip block, and leave clock off as well
    __HAL_RCC_AES_CLK_ENABLE();
    __HAL_RCC_AES_FORCE_RESET();
    __HAL_RCC_AES_RELEASE_RESET();
    __HAL_RCC_AES_CLK_DISABLE();
}


#ifndef RELEASE
// aes_selftest()
//
    void
aes_selftest(void)
{
    puts2("AES selftest: ");

/*
    >>> import pyaes
    >>> pyaes.AESModeOfOperationCTR(bytes(32), pyaes.Counter(0)).encrypt(b'Zack')
    b'\x86\xf4\xa3\x13'
*/

    AES_CTX ctx;
    static const uint8_t key[32] = { };
    static const uint8_t nonce[16] = { };
    static const uint8_t msg[4] = "Zack";
    static const uint8_t expect[4] = { 0x86, 0xf4, 0xa3, 0x13 };

    uint8_t tmp[4];

    aes_init(&ctx);
    aes_add(&ctx, msg, 4);
    aes_done(&ctx, tmp, 4, key, nonce);
    ASSERT(check_equal(tmp, expect, 4));

    aes_init(&ctx);
    aes_add(&ctx, expect, 4);
    aes_done(&ctx, tmp, 4, key, nonce);
    ASSERT(check_equal(tmp, msg, 4));

#if 0
    // passes, but big
/*
    >>> pyaes.Counter(0x102030405060708090a0b0c0d0e0f0).value
    [0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240]
    >>> pyaes.AESModeOfOperationCTR(bytes(32), pyaes.Counter(0x102030405060708090a0b0c0d0e0f0)).encrypt(bytes(512)).hex()
*/
    static const uint8_t long_nonce[16] = { 0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240 };
    static const uint8_t long_exp[512] = {
0x88, 0x6f, 0x2f, 0x0c, 0xa7, 0x1f, 0x00, 0xed, 0xfd, 0xf8, 0x2d, 0x62, 0xf7, 0xf2, 0xc9,
0xd3, 0x0e, 0xb3, 0xc4, 0xf6, 0xff, 0x3e, 0x3d, 0xc9, 0x6d, 0x26, 0x09, 0x70, 0x97, 0x6a,
0xef, 0x60, 0x59, 0x20, 0xb2, 0xb1, 0x61, 0x92, 0xe1, 0x19, 0xa5, 0xcb, 0x24, 0xf3, 0x1e,
0x9a, 0x82, 0x71, 0x4f, 0x73, 0x21, 0x1e, 0x51, 0x4f, 0xed, 0x05, 0x77, 0xd8, 0x8b, 0x11,
0x5b, 0x38, 0x64, 0xb8, 0xf8, 0x6c, 0xf3, 0xb0, 0xa8, 0x3f, 0xe2, 0x17, 0xd5, 0x6f, 0xc2,
0xc1, 0x2b, 0x9e, 0x9d, 0x0c, 0x89, 0xc1, 0x65, 0x8e, 0xce, 0xb3, 0x21, 0x6d, 0xbb, 0x23,
0x5f, 0x5e, 0x3d, 0x52, 0x61, 0x7f, 0x61, 0x37, 0xd9, 0xea, 0x3a, 0x27, 0xce, 0x80, 0x05,
0xf0, 0x85, 0x73, 0xed, 0xc5, 0x1f, 0x72, 0x3b, 0x91, 0x6d, 0x75, 0xd8, 0x70, 0xc1, 0x07,
0x0f, 0xf3, 0x96, 0x2d, 0x68, 0x6e, 0x44, 0x6b, 0x6c, 0x5f, 0x81, 0x28, 0xe5, 0x0a, 0xb1,
0xff, 0x29, 0x79, 0x55, 0xda, 0x95, 0x9b, 0x29, 0xd6, 0x55, 0x87, 0x59, 0xf9, 0xc0, 0xbf,
0x90, 0xba, 0xb1, 0xc1, 0x0c, 0x91, 0xb5, 0x90, 0x3a, 0x9b, 0xf9, 0x0d, 0xa1, 0xcd, 0x47,
0x9b, 0xad, 0xa4, 0x8f, 0xa4, 0x98, 0x42, 0x88, 0x65, 0x36, 0x8d, 0x29, 0xb1, 0xa3, 0x78,
0x76, 0x6a, 0x17, 0xee, 0xa5, 0x32, 0xed, 0x3c, 0x79, 0x2d, 0xa7, 0x6c, 0x91, 0x36, 0x56,
0x8b, 0x30, 0x45, 0xf2, 0x9e, 0xef, 0x12, 0xc3, 0x5e, 0x59, 0xdf, 0x6d, 0x8b, 0xf5, 0x80,
0xf4, 0x45, 0x37, 0xcb, 0x6a, 0x8f, 0x68, 0x11, 0x0e, 0x11, 0x90, 0x3c, 0xd4, 0x95, 0xaa,
0x43, 0xad, 0xa1, 0x1d, 0x44, 0x19, 0x23, 0xcc, 0xb9, 0xa8, 0x8e, 0x55, 0xbd, 0xb3, 0x7c,
0xa0, 0x99, 0xbc, 0xeb, 0x77, 0x89, 0xf7, 0x35, 0x1e, 0x2b, 0x7c, 0x02, 0x31, 0x2b, 0x0e,
0xc2, 0x40, 0x0a, 0x9f, 0xe0, 0xbf, 0x10, 0xac, 0xec, 0x22, 0x19, 0x4c, 0x73, 0x96, 0xad,
0x46, 0x58, 0x71, 0x58, 0x64, 0x4d, 0x16, 0xb6, 0xc8, 0x9d, 0x3c, 0x10, 0x39, 0x15, 0x41,
0x60, 0xb0, 0xd3, 0xa1, 0xd9, 0x5a, 0x74, 0xef, 0x94, 0x1e, 0xbd, 0xff, 0x21, 0x01, 0x66,
0x3d, 0xbf, 0x02, 0x94, 0xf8, 0x8f, 0xb6, 0xab, 0xf6, 0x66, 0xc5, 0xdd, 0x31, 0x02, 0x90,
0xcc, 0x71, 0x73, 0xd8, 0xb8, 0x52, 0x20, 0xa6, 0x5f, 0xcf, 0x9d, 0xcb, 0xae, 0x34, 0xee,
0xa1, 0x4a, 0x42, 0x68, 0x1e, 0x02, 0x71, 0x08, 0x67, 0xaf, 0xe5, 0x05, 0xb4, 0x17, 0x0d,
0x90, 0xba, 0x96, 0x0d, 0x22, 0x99, 0xb1, 0xd4, 0x30, 0xf5, 0x6b, 0x5f, 0xab, 0xf3, 0xbf,
0x85, 0xee, 0xf0, 0xde, 0x52, 0x79, 0x36, 0xec, 0x0f, 0x87, 0x9f, 0xb9, 0x66, 0xe5, 0x71,
0x1b, 0x57, 0x88, 0x83, 0x84, 0x7e, 0xbb, 0x16, 0x12, 0x10, 0xda, 0x8a, 0x69, 0x67, 0x10,
0x97, 0x53, 0x22, 0x32, 0x3a, 0x22, 0x03, 0x1f, 0xa8, 0x3a, 0x65, 0xec, 0x64, 0x5b, 0x2e,
0x33, 0xdc, 0x03, 0x64, 0x35, 0xfb, 0xca, 0x43, 0x4d, 0x41, 0xd2, 0xbd, 0x32, 0xa0, 0xe0,
0xff, 0x74, 0x30, 0xa0, 0x39, 0x72, 0x57, 0xf0, 0xa7, 0xd3, 0xa7, 0xb0, 0x05, 0x19, 0x7d,
0xbe, 0x6b, 0x49, 0x76, 0x2d, 0x23, 0x8a, 0x58, 0x2e, 0xfc, 0x75, 0x39, 0xe2, 0xf9, 0x4c,
0xcc, 0x4b, 0x71, 0x94, 0x4c, 0xe1, 0x57, 0x95, 0xf8, 0x83, 0x2d, 0x00, 0x30, 0xca, 0xca,
0xc0, 0x1c, 0xb5, 0x8f, 0xc9, 0x4f, 0xdf, 0x82, 0x41, 0x6f, 0x64, 0xbf, 0x9c, 0xa7, 0xa1,
0x2f, 0xdb, 0x28, 0x6c, 0xda, 0x16, 0x2f, 0x25, 0x9d, 0x81, 0x44, 0xd7, 0xee, 0x8e, 0x7b,
0x59, 0x8a, 0x24, 0x59, 0x03, 0x4e, 0x48, 0x7a, 0xfd, 0x3c, 0x76, 0x97, 0xa5, 0xac, 0xbb,
0xea, 0x83 };

    aes_init(&ctx);
    ctx.num_pending = 512;
    uint8_t tmp2[512];
    aes_done(&ctx, tmp2, 512, key, long_nonce);
    ASSERT(check_equal(tmp2, long_exp, 512));
#endif


    puts("PASS");
}
#endif

// EOF