/*
 * scrypt.h - header file for scrypt PBKDF implementation.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef FREEBL_SCRYPT_H_
#define FREEBL_SCRYPT_H_

#include "blapi.h"

extern SECStatus
SCRYPT_Hash(const SCRYPTParams *params,
            const unsigned char *password, unsigned int passwordLen,
            const unsigned char *salt, unsigned int saltLen,
            unsigned char *dk, unsigned int dkLen);

#endif /* FREEBL_SCRYPT_H_ */
