/*
 * quic_ssl_utils.h
 *
 * OpenSSL utility wrapper for encoding, decoding, ... the quic header
 *
 * =========================================================================
 * Copyright (c) 2020 SoftAtHome (david.cluytens@gmail.com)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * =========================================================================
 */

/* GCM AES ENCRYPTION */
int aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len, const EVP_CIPHER *cipher_type,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag);

/* GCM AES DECRYPTION */
int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, const EVP_CIPHER *cipher_type,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext);

/* AES ENCRYPTION */
int aes_encrypt(unsigned char *plaintext, int plaintext_len, const EVP_CIPHER *cipher_type, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext);

/* AES DECRYPTION */
int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, const EVP_CIPHER *cipher_type, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);

/* HKDF Extract */
int HKDF_Extract(const unsigned char *salt, const size_t salt_len, const unsigned char *key, const size_t key_len, unsigned char *hash, size_t hash_len);

/* HKDF Expand */
int HKDF_Expand(const unsigned char *key, const size_t key_len, const unsigned char *label, const size_t label_len, unsigned char *hash, size_t hash_len);

/* HKDF/TLS13 Create compatible label(s) */
int hkdf_create_tls13_label(const unsigned int a, const unsigned char *label, unsigned char *out, size_t out_len);

int md5_digest_message(const unsigned char *message, size_t message_len, unsigned char *digest);
