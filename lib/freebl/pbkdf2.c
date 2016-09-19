/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

/* Based on the code in lib/softoken/lowpbe.c. */

#ifdef FREEBL_NO_DEPEND
#include "stubs.h"
#endif

#include <stdio.h>
#include "pbkdf2.h"
#include "blapi.h"
#include "secerr.h"

static void
do_xor(unsigned char *dest, unsigned char *src, int len)
{
    /* use byte xor, not all platforms are happy about inaligned
     * integer fetches */
    while (len--) {
        *dest = *dest ^ *src;
        dest++;
        src++;
    }
}

static SECStatus
PBKDF2_HMAC_F(const SECHashObject *hashobj,
              const unsigned char *password, unsigned int passwordLen,
              const unsigned char *salt, unsigned int saltLen,
              int iterations, unsigned int i, unsigned char *T)
{
    int j;
    HMACContext *cx = NULL;
    unsigned int hLen = hashobj->length;
    SECStatus rv = SECFailure;
    unsigned char *last = NULL;
    unsigned int lastLength = saltLen + 4;
    unsigned int lastBufLength;

    cx = HMAC_Create(hashobj, password, passwordLen, PR_FALSE);
    if (cx == NULL) {
        goto loser;
    }
    PORT_Memset(T, 0, hLen);
    lastBufLength = PR_MAX(lastLength, hLen);
    last = PORT_Alloc(lastBufLength);
    if (last == NULL) {
        goto loser;
    }
    PORT_Memcpy(last, salt, saltLen);
    last[saltLen] = (i >> 24) & 0xff;
    last[saltLen + 1] = (i >> 16) & 0xff;
    last[saltLen + 2] = (i >> 8) & 0xff;
    last[saltLen + 3] = i & 0xff;

    /* NOTE: we need at least one iteration to return success! */
    for (j = 0; j < iterations; j++) {
        HMAC_Begin(cx);
        HMAC_Update(cx, last, lastLength);
        rv = HMAC_Finish(cx, last, &lastLength, hLen);
        if (rv != SECSuccess) {
            break;
        }
        do_xor(T, last, hLen);
    }
loser:
    if (cx) {
        HMAC_Destroy(cx, PR_TRUE);
    }
    if (last) {
        PORT_ZFree(last, lastBufLength);
    }
    return rv;
}

SECStatus
PBKDF2_HMAC(const SECHashObject *hashobj,
            const unsigned char *password, unsigned int passwordLen,
            const unsigned char *salt, unsigned int saltLen,
            int iterations,
            unsigned char *dk, unsigned int dkLen)
{
    unsigned int hLen = hashobj->length;
    unsigned int l = (dkLen + hLen - 1) / hLen;
    unsigned int r = dkLen - (l - 1) * hLen;
    unsigned int i;
    unsigned char *rp;
    unsigned char *T = NULL;
    SECStatus rv = SECFailure;

    T = PORT_Alloc(hLen);
    if (T == NULL) {
        PORT_SetError(SEC_ERROR_NO_MEMORY);
        return SECFailure;
    }

    for (i = 1, rp = dk; i < l; i++, rp += hLen) {
        rv = PBKDF2_HMAC_F(hashobj, password, passwordLen,
                           salt, saltLen, iterations, i, T);
        if (rv != SECSuccess) {
            goto loser;
        }
        PORT_Memcpy(rp, T, hLen);
    }

    rv = PBKDF2_HMAC_F(hashobj, password, passwordLen,
                       salt, saltLen, iterations, i, T);
    if (rv != SECSuccess) {
        goto loser;
    }
    PORT_Memcpy(rp, T, r);

 loser:
    PORT_ZFree(T, hLen);

    return rv;
}
