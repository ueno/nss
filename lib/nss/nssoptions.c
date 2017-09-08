/*
 * NSS utility functions
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <ctype.h>
#include <string.h>
#include <assert.h>

#include "seccomon.h"
#include "secoidt.h"
#include "secoid.h"
#include "nss.h"
#include "nssoptions.h"

/* Until NSS 3.30, PKCS#12 routines used BMPString encoding for
 * passwords, even if PBE algorithm is PBES2 defined in PKCS#5.
 *
 * This option reverts the behavior to the old NSS versions.
 * This is only used by pk12util; don't expose it in a public header file. */
#define NSS_PKCS12_DECODE_COMPAT_PBES2 0x00c

struct nssOps {
    PRInt32 rsaMinKeySize;
    PRInt32 dhMinKeySize;
    PRInt32 dsaMinKeySize;
    PRInt32 tlsVersionMinPolicy;
    PRInt32 tlsVersionMaxPolicy;
    PRInt32 dtlsVersionMinPolicy;
    PRInt32 dtlsVersionMaxPolicy;
    PRInt32 pkcs12DecodeCompatPBES2;
};

static struct nssOps nss_ops = {
    SSL_RSA_MIN_MODULUS_BITS,
    SSL_DH_MIN_P_BITS,
    SSL_DSA_MIN_P_BITS,
    1,      /* Set TLS min to less the the smallest legal SSL value */
    0xffff, /* set TLS max to more than the largest legal SSL value */
    1,
    0xffff,
    PR_FALSE
};

SECStatus
NSS_OptionSet(PRInt32 which, PRInt32 value)
{
    SECStatus rv = SECSuccess;

    switch (which) {
        case NSS_RSA_MIN_KEY_SIZE:
            nss_ops.rsaMinKeySize = value;
            break;
        case NSS_DH_MIN_KEY_SIZE:
            nss_ops.dhMinKeySize = value;
            break;
        case NSS_DSA_MIN_KEY_SIZE:
            nss_ops.dsaMinKeySize = value;
            break;
        case NSS_TLS_VERSION_MIN_POLICY:
            nss_ops.tlsVersionMinPolicy = value;
            break;
        case NSS_TLS_VERSION_MAX_POLICY:
            nss_ops.tlsVersionMaxPolicy = value;
            break;
        case NSS_DTLS_VERSION_MIN_POLICY:
            nss_ops.dtlsVersionMinPolicy = value;
            break;
        case NSS_DTLS_VERSION_MAX_POLICY:
            nss_ops.dtlsVersionMaxPolicy = value;
            break;
        case NSS_PKCS12_DECODE_COMPAT_PBES2:
            nss_ops.pkcs12DecodeCompatPBES2 = value;
            break;
        default:
            rv = SECFailure;
    }

    return rv;
}

SECStatus
NSS_OptionGet(PRInt32 which, PRInt32 *value)
{
    SECStatus rv = SECSuccess;

    switch (which) {
        case NSS_RSA_MIN_KEY_SIZE:
            *value = nss_ops.rsaMinKeySize;
            break;
        case NSS_DH_MIN_KEY_SIZE:
            *value = nss_ops.dhMinKeySize;
            break;
        case NSS_DSA_MIN_KEY_SIZE:
            *value = nss_ops.dsaMinKeySize;
            break;
        case NSS_TLS_VERSION_MIN_POLICY:
            *value = nss_ops.tlsVersionMinPolicy;
            break;
        case NSS_TLS_VERSION_MAX_POLICY:
            *value = nss_ops.tlsVersionMaxPolicy;
            break;
        case NSS_DTLS_VERSION_MIN_POLICY:
            *value = nss_ops.dtlsVersionMinPolicy;
            break;
        case NSS_DTLS_VERSION_MAX_POLICY:
            *value = nss_ops.dtlsVersionMaxPolicy;
            break;
        case NSS_PKCS12_DECODE_COMPAT_PBES2:
            *value = nss_ops.pkcs12DecodeCompatPBES2;
            break;
        default:
            rv = SECFailure;
    }

    return rv;
}
