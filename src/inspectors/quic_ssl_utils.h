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
