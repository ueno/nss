/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

provider nss_crypto {
  probe cert_signature_verify(uint32_t encAlgProbe, uint32_t curveAlg,
                              uint32_t keySize, uint32_t hashAlg);
}
