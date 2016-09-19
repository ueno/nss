/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifdef FREEBL_NO_DEPEND
#include "stubs.h"
#endif

#include "blapi.h"
#include "prtypes.h"
#include "pbkdf2.h"
#include "salsa20.h"
#include "secport.h"
#include "secerr.h"

#define U8TO32_LITTLE(p)                                        \
    (((PRUint32)((p)[0])      ) | ((PRUint32)((p)[1]) <<  8) |  \
     ((PRUint32)((p)[2]) << 16) | ((PRUint32)((p)[3]) << 24))

static void
SCRYPT_BlockMix(unsigned char *output, unsigned char *input, size_t r)
{
    unsigned char x[64];
    size_t i, j;

    for (j = 0; j < 64; j++) {
        x[j] = input[(2 * r - 1) * 64 + j];
    }

    for (i = 0; i < 2 * r; i++) {
        for (j = 0; j < 64; j++)
            x[j] ^= input[i * 64 + j];

        Salsa20(x, x, 8);

        for (j = 0; j < 64; j++) {
            input[i * 64 + j] = x[j];
        }
    }

    for (i = 0; i <  r; i++) {
        for (j = 0; j < 64; j++) {
            output[i * 64 + j] = input[i * 2 * 64 + j];
        }
    }
    for (i = 0; i <  r; i++) {
        for (j = 0; j < 64; j++) {
            output[(r + i) * 64 + j] = input[(i * 2 + 1) * 64 + j];
        }
    }
}

static void
SCRYPT_ROMix(unsigned char *output, const unsigned char *input, size_t r,
             size_t N, unsigned char *v, unsigned char *x, unsigned char *y)
{
    size_t i;

    PORT_Memcpy(x, input, 128 * r);

    for (i = 0; i < N; i++) {
        PORT_Memcpy(&v[(128 * r) * i], x, 128 * r);
        SCRYPT_BlockMix(y, x, r);
        PORT_Memcpy(x, y, 128 * r);
    }

    for (i = 0; i < N; i++) {
        PRUint32 j0, j1;
        PRUint64 j;
        size_t k;

        j0 = U8TO32_LITTLE (&x[128 * r - 64]);
        j1 = U8TO32_LITTLE (&x[128 * r - 32]);
        j = (((PRUint64) j1 << 32) | j0) % N;
        for (k = 0; k < 128 * r; k++) {
            x[k] ^= v[(128 * r) * j + k];
        }
        SCRYPT_BlockMix(y, x, r);
        PORT_Memcpy(x, y, 128 * r);
    }

    PORT_Memcpy(output, x, 128 * r);
}

SECStatus
SCRYPT_Hash(const SCRYPTParams *params,
            const unsigned char *password, unsigned int passwordLen,
            const unsigned char *salt, unsigned int saltLen,
            unsigned char *dk, unsigned int dkLen)
{
    unsigned char *v = NULL, *x = NULL, *y = NULL;
    unsigned char *inputBlocks = NULL, *outputBlocks = NULL;
    unsigned int r = params->blockSize;
    unsigned int N = params->cost;
    unsigned int p = params->parallelization;
    size_t i;
    const SECHashObject *hashObj;
    SECStatus rv = SECFailure;

    hashObj = HASH_GetRawHashObject(HASH_AlgSHA256);

    inputBlocks = PORT_ZAlloc(128 * r * p);
    if (inputBlocks == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        rv = SECFailure;
        goto out;
    }

    rv = PBKDF2_HMAC(hashObj, password, passwordLen, salt, saltLen,
                     1, inputBlocks, p * 128 * r);
    if (rv != SECSuccess) {
        goto out;
    }

    outputBlocks = PORT_ZAlloc(128 * r * p);
    if (outputBlocks == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        rv = SECFailure;
        goto out;
    }

    v = PORT_ZAlloc(128 * r * N);
    if (v == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        rv = SECFailure;
        goto out;
    }
    x = PORT_ZAlloc(128 * r);
    if (x == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        rv = SECFailure;
        goto out;
    }
    y = PORT_ZAlloc(128 * r);
    if (y == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        rv = SECFailure;
        goto out;
    }

    for (i = 0; i < p; i++) {
        SCRYPT_ROMix(&outputBlocks[128 * r * i], &inputBlocks[128 * r * i],
                     r, N, v, x, y);
    }

    rv = PBKDF2_HMAC(hashObj, password, passwordLen,
                     outputBlocks, p * 128 * r, 1, dk, dkLen);

 out:
    if (inputBlocks != NULL)
        PORT_ZFree (inputBlocks, p * 128 * r);
    if (outputBlocks != NULL)
        PORT_ZFree (outputBlocks, p * 128 * r);
    if (v != NULL)
        PORT_ZFree (v, 128 * r * N);
    if (x != NULL)
        PORT_ZFree (x, 128 * r);
    if (y != NULL)
        PORT_ZFree (y, 128 * r);

    return rv;
}
