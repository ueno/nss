/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Adopted from the public domain code in NaCl by djb. */

#include "salsa20.h"
#include "prtypes.h"
#include "secport.h"

#if defined(_MSC_VER)
#pragma intrinsic(_lrotl)
#define ROTL32(x, n) _lrotl(x, n)
#else
#define ROTL32(x, n) ((x << n) | (x >> ((8 * sizeof x) - n)))
#endif

#define ROTATE(v, c) ROTL32((v), (c))

#define U32TO8_LITTLE(p, v)                                             \
    { (p)[0] = ((v)      ) & 0xff; (p)[1] = ((v) >>  8) & 0xff;         \
      (p)[2] = ((v) >> 16) & 0xff; (p)[3] = ((v) >> 24) & 0xff; }
#define U8TO32_LITTLE(p)                                        \
    (((PRUint32)((p)[0])      ) | ((PRUint32)((p)[1]) <<  8) |  \
     ((PRUint32)((p)[2]) << 16) | ((PRUint32)((p)[3]) << 24))

static void
SalsaCore(PRUint32 output[16], const PRUint32 input[16], int num_rounds)
{
    PRUint32 x[16];
    int i;

    PORT_Memcpy(x, input, sizeof(PRUint32) * 16);
    for (i = num_rounds; i > 0; i -= 2) {
        x[4] ^= ROTATE(x[0] + x[12], 7);
        x[8] ^= ROTATE(x[4] + x[0], 9);
        x[12] ^= ROTATE(x[8] + x[4], 13);
        x[0] ^= ROTATE(x[12] + x[8], 18);
        x[9] ^= ROTATE(x[5] + x[1], 7);
        x[13] ^= ROTATE(x[9] + x[5], 9);
        x[1] ^= ROTATE(x[13] + x[9], 13);
        x[5] ^= ROTATE(x[1] + x[13], 18);
        x[14] ^= ROTATE(x[10] + x[6], 7);
        x[2] ^= ROTATE(x[14] + x[10], 9);
        x[6] ^= ROTATE(x[2] + x[14], 13);
        x[10] ^= ROTATE(x[6] + x[2], 18);
        x[3] ^= ROTATE(x[15] + x[11], 7);
        x[7] ^= ROTATE(x[3] + x[15], 9);
        x[11] ^= ROTATE(x[7] + x[3], 13);
        x[15] ^= ROTATE(x[11] + x[7], 18);
        x[1] ^= ROTATE(x[0] + x[3], 7);
        x[2] ^= ROTATE(x[1] + x[0], 9);
        x[3] ^= ROTATE(x[2] + x[1], 13);
        x[0] ^= ROTATE(x[3] + x[2], 18);
        x[6] ^= ROTATE(x[5] + x[4], 7);
        x[7] ^= ROTATE(x[6] + x[5], 9);
        x[4] ^= ROTATE(x[7] + x[6], 13);
        x[5] ^= ROTATE(x[4] + x[7], 18);
        x[11] ^= ROTATE(x[10] + x[9], 7);
        x[8] ^= ROTATE(x[11] + x[10], 9);
        x[9] ^= ROTATE(x[8] + x[11], 13);
        x[10] ^= ROTATE(x[9] + x[8], 18);
        x[12] ^= ROTATE(x[15] + x[14], 7);
        x[13] ^= ROTATE(x[12] + x[15], 9);
        x[14] ^= ROTATE(x[13] + x[12], 13);
        x[15] ^= ROTATE(x[14] + x[13], 18);
    }

    for (i = 0; i < 16; i++) {
        x[i] += input[i];
    }
    PORT_Memcpy(output, x, sizeof(PRUint32) * 16);
}

void
Salsa20(unsigned char *output, unsigned char *input, int rounds)
{
    PRUint32 input_blocks[16];
    PRUint32 output_blocks[16];
    size_t i;

    for (i = 0; i < 16; i++) {
        input_blocks[i] = U8TO32_LITTLE(input + i * 4);
    }
    SalsaCore(output_blocks, input_blocks, rounds);
    for (i = 0; i < 16; i++) {
        U32TO8_LITTLE(output + 4 * i, output_blocks[i]);
    }
}
