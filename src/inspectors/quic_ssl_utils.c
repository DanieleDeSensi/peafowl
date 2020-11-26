#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/kdf.h>

#include "quic_ssl_utils.h"

int aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len, const EVP_CIPHER *cipher_type,
		unsigned char *aad, int aad_len,
		unsigned char *key,
		unsigned char *iv, int iv_len,
		unsigned char *ciphertext,
		unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;


	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) {
		fprintf(stderr, "Error creating context\n");
		return -1;
	}

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, cipher_type, NULL, NULL, NULL)) {
                fprintf(stderr, "Error initialising operation\n");
                EVP_CIPHER_CTX_free(ctx);
                return -1;
        }

	/*
	 * Set IV length if default 12 bytes (96 bits) is not appropriate
	 */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
                fprintf(stderr, "Error setting IV\n");
                EVP_CIPHER_CTX_free(ctx);
                return -1;
        }

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
                fprintf(stderr, "Error setting key and IV\n");
                EVP_CIPHER_CTX_free(ctx);
                return -1;
        }

	/*
	 * Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
                fprintf(stderr, "Error setting AAD\n");
                EVP_CIPHER_CTX_free(ctx);
                return -1;
        }

	/*
	 * Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
                fprintf(stderr, "Error setting message to encrypt\n");
                EVP_CIPHER_CTX_free(ctx);
                return -1;
        }
	ciphertext_len = len;

	/*
	 * Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
                fprintf(stderr, "Error finalising encryption\n");
		EVP_CIPHER_CTX_free(ctx);
                return -1;
        }
	ciphertext_len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
                fprintf(stderr, "Error retrieving GCM-TAG\n");
		EVP_CIPHER_CTX_free(ctx);
                return -1;
        }

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, const EVP_CIPHER *cipher_type,
		unsigned char *aad, int aad_len,
		unsigned char *tag,
		unsigned char *key,
		unsigned char *iv, int iv_len,
		unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) {
                fprintf(stderr, "Error initialising operation\n");
                return -1;
        }

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, cipher_type, NULL, NULL, NULL)) {
                fprintf(stderr, "Error decrypt init\n");
                EVP_CIPHER_CTX_free(ctx);
                return -1;
        }

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
                fprintf(stderr, "Error setting IV\n");
                EVP_CIPHER_CTX_free(ctx);
                return -1;
        }

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
                fprintf(stderr, "Error setting key and IV\n");
                EVP_CIPHER_CTX_free(ctx);
                return -1;
        }

	/*
	 * Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
                fprintf(stderr, "Error setting AAD\n");
                EVP_CIPHER_CTX_free(ctx);
                return -1;
        }

	/*
	 * Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
                fprintf(stderr, "Error setting message\n");
                EVP_CIPHER_CTX_free(ctx);
                return -1;
        }
	plaintext_len = len;

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
                fprintf(stderr, "Error setting GCM/TAG\n");
                EVP_CIPHER_CTX_free(ctx);
                return -1;
        }

	/*
	 * Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0) {
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	} else {
		/* Verify failed */
		return -1;
	}
}

int aes_encrypt(unsigned char *plaintext, int plaintext_len, const EVP_CIPHER *type, unsigned char *key,
		unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) {
                fprintf(stderr, "Error aes encrypt\n");
                return -1;
        }

	/*
	 * Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if(1 != EVP_EncryptInit_ex(ctx, type, NULL, key, iv)) {
		fprintf(stderr, "Error aes encrypt\n");
		EVP_CIPHER_CTX_free(ctx);
		return -1;
        }

	/*
	 * Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
		fprintf(stderr, "Error aes encrypt\n");
		EVP_CIPHER_CTX_free(ctx);
                return -1;
        }
	ciphertext_len = len;

	/*
	 * Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
                fprintf(stderr, "Error aes encrypt\n");
                EVP_CIPHER_CTX_free(ctx);
                return -1;
        }
	ciphertext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, const EVP_CIPHER *type, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
	    fprintf(stderr, "Error aes decrypt\n");
	    return -1;
    }

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, type, NULL, key, iv)) {
            fprintf(stderr, "Error aes decrypt\n");
	    EVP_CIPHER_CTX_free(ctx);
	    return -1;
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
            fprintf(stderr, "Error aes decrypt\n");
	    EVP_CIPHER_CTX_free(ctx);
	    return -1;
    }
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
	    fprintf(stderr, "Error aes decrypt\n");
	    EVP_CIPHER_CTX_free(ctx);
	    return -1;
    }
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int HKDF_Extract(const unsigned char *salt, const size_t salt_len, const unsigned char *key, const size_t key_len, unsigned char *hash, size_t hash_len) {
	EVP_PKEY_CTX 	*pctx;
	int		mode = EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY;


	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

	if (EVP_PKEY_derive_init(pctx) <= 0) {
		printf("Error init\n");
		EVP_PKEY_CTX_free(pctx);
		return -1;
	}
	
	if (EVP_PKEY_CTX_hkdf_mode(pctx, mode) <= 0) {
		printf("Error set_hkdf_mode\n");
                EVP_PKEY_CTX_free(pctx);
		return -1;
	}

	if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
		printf("Error set_hkdf_md\n");
                EVP_PKEY_CTX_free(pctx);
		return -1;
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_len) <= 0) {
		printf("Error set1_hkdf_key\n");
                EVP_PKEY_CTX_free(pctx);
		return -1;
	}

	if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
		printf("Error set1_hkdf_salt\n");
                EVP_PKEY_CTX_free(pctx);
		return -1;
	}

	size_t len = hash_len;
	if (EVP_PKEY_derive(pctx, hash, &len) <= 0) {
		printf("Error deriving key\n");
		return -1;
	}
	EVP_PKEY_CTX_free(pctx);
	return len;
}

int HKDF_Expand(const unsigned char *key, const size_t key_len, const unsigned char *label, const size_t label_len, unsigned char *hash, size_t hash_len) {
	EVP_PKEY_CTX 	*pctx;
	int		mode = EVP_PKEY_HKDEF_MODE_EXPAND_ONLY;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (EVP_PKEY_derive_init(pctx) <= 0) {
		printf("Error init\n");
                EVP_PKEY_CTX_free(pctx);
		return -1;
	}
	
	if (EVP_PKEY_CTX_hkdf_mode(pctx, mode) <= 0) {
		printf("Error set_hkdf_mode\n");
                EVP_PKEY_CTX_free(pctx);
		return -1;
	}

	if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
		printf("Error set_hkdf_md\n");
                EVP_PKEY_CTX_free(pctx);
		return -1;
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_len) <= 0) {
		printf("Error set1_hkdf_key\n");
                EVP_PKEY_CTX_free(pctx);
		return -1;
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(pctx, label, label_len) <= 0) {
                EVP_PKEY_CTX_free(pctx);
		return -1;
	}

	size_t len = hash_len;
	if (EVP_PKEY_derive(pctx, hash, &len) <= 0) {
		printf("Error deriving key\n");
                EVP_PKEY_CTX_free(pctx);
		return -1;
	}
	EVP_PKEY_CTX_free(pctx);
	return len;
}

int hkdf_create_tls13_label(const unsigned int a, const unsigned char *label, unsigned char *out, size_t out_len) {
	unsigned char	pref_label[] 	= "tls13 ";
	size_t		pref_label_len 	= strlen(pref_label);
	size_t 		label_len    	= strlen(label);
	size_t 		v_label_len 	= pref_label_len + label_len;
	size_t		len		= 0;
	const uint16_t 	length 		= htons(a);

	memcpy(&out[len], &length, sizeof(length));
        len += sizeof(length);	

        memcpy(&out[len], &v_label_len, 1);
	len +=1;

        memcpy(&out[len], pref_label, pref_label_len);
        len += pref_label_len;

        memcpy(&out[len], label, label_len);
        len += label_len;

	unsigned int context_length = 0;
	memcpy(&out[len], &context_length, 1);
	len += 1;
	return len;
}
