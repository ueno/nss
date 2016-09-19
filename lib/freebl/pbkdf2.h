/*
 * pbkdf2.h - header file for PKCS#5 PBKDF2 implementation.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef FREEBL_PBKDF2_H_
#define FREEBL_PBKDF2_H_

#include "blapi.h"

/* PBKDF2_HMAC derives key from |pwitem| and |salt|, using the HMAC
 * algorithm specified by |hashobj| as a pseudo random function. */
SECStatus
PBKDF2_HMAC(const SECHashObject *hashobj,
	    const unsigned char *password, unsigned int passwordLen,
	    const unsigned char *salt, unsigned int saltLen,
	    int iterations,
	    unsigned char *dk, unsigned int dkLen);

#endif /* FREEBL_PBKDF2_H_ */
