/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

provider nss_crypto {
  probe tls13_key_exchange(size_t connectionID, unsigned char isServer,
                           uint32_t keaAlg, uint32_t curveAlg,
                           uint32_t keaKeySize);
  probe tls_cipher(size_t connectionID, uint8_t isServer, uint32_t cipherAlg);
  probe tls_client_key_exchange(size_t connectionID, uint32_t keaAlg,
                                uint32_t curveAlg, uint32_t keySize);
  probe tls_server_key_exchange(size_t connectionID, uint32_t keaAlg,
                                uint32_t curveAlg, uint32_t keySize);
  probe tls_signature_verify(size_t connectionID, uint8_t isServer,
                             uint32_t encAlg, uint32_t curveAlg,
                             uint32_t keySize, uint32_t hashAlg);
  probe tls_version(size_t connectionID, uint8_t isServer, uint16_t version);
}
