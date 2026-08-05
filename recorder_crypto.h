#ifndef RECORDER_CRYPTO_H
#define RECORDER_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RECORDER_CRYPTO_DEK_SIZE 32u
#define RECORDER_CRYPTO_GCM_NONCE_SIZE 12u
#define RECORDER_CRYPTO_GCM_TAG_SIZE 16u

typedef struct RecorderPublicKey RecorderPublicKey;
typedef struct RecorderPrivateKey RecorderPrivateKey;

enum RecorderCryptoStatus {
    RECORDER_CRYPTO_OK = 0,
    RECORDER_CRYPTO_ERR_ARGUMENT = -1,
    RECORDER_CRYPTO_ERR_MEMORY = -2,
    RECORDER_CRYPTO_ERR_IO = -3,
    RECORDER_CRYPTO_ERR_KEY_FORMAT = -4,
    RECORDER_CRYPTO_ERR_KEY_TYPE = -5,
    RECORDER_CRYPTO_ERR_LENGTH = -6,
    RECORDER_CRYPTO_ERR_RANDOM = -7,
    RECORDER_CRYPTO_ERR_ENCRYPT = -8,
    RECORDER_CRYPTO_ERR_DECRYPT = -9,
    RECORDER_CRYPTO_ERR_AUTHENTICATION = -10,
    RECORDER_CRYPTO_ERR_WRAPPED_KEY = -11
};

/* Load an unencrypted PEM key from path. */
int recorder_public_key_load_pem(const char *path,
                                 RecorderPublicKey **key_out);
int recorder_private_key_load_pem(const char *path,
                                  RecorderPrivateKey **key_out);
void recorder_public_key_free(RecorderPublicKey *key);
void recorder_private_key_free(RecorderPrivateKey *key);

int recorder_crypto_random(void *buf, size_t len);

/*
 * Wrap a 32-byte data-encryption key with RSA-OAEP using SHA-256 for both
 * OAEP and MGF1. wrapped_out is allocated with malloc and belongs to the
 * caller. On failure it is set to NULL and wrapped_len_out to zero.
 */
int recorder_crypto_wrap_dek(const RecorderPublicKey *key,
                             const uint8_t dek[RECORDER_CRYPTO_DEK_SIZE],
                             uint8_t **wrapped_out,
                             size_t *wrapped_len_out);

/* Unwrap an RSA-OAEP-SHA-256 value, accepting only a 32-byte result. */
int recorder_crypto_unwrap_dek(const RecorderPrivateKey *key,
                               const uint8_t *wrapped, size_t wrapped_len,
                               uint8_t dek_out[RECORDER_CRYPTO_DEK_SIZE]);

/* Ciphertext has exactly plaintext_len bytes. */
int recorder_crypto_aes_gcm_encrypt(
    const uint8_t dek[RECORDER_CRYPTO_DEK_SIZE],
    const uint8_t nonce[RECORDER_CRYPTO_GCM_NONCE_SIZE],
    const void *aad, size_t aad_len,
    const void *plaintext, size_t plaintext_len,
    void *ciphertext,
    uint8_t tag[RECORDER_CRYPTO_GCM_TAG_SIZE]);

/* Plaintext has exactly ciphertext_len bytes and is cleansed on failure. */
int recorder_crypto_aes_gcm_decrypt(
    const uint8_t dek[RECORDER_CRYPTO_DEK_SIZE],
    const uint8_t nonce[RECORDER_CRYPTO_GCM_NONCE_SIZE],
    const void *aad, size_t aad_len,
    const void *ciphertext, size_t ciphertext_len,
    const uint8_t tag[RECORDER_CRYPTO_GCM_TAG_SIZE],
    void *plaintext);

void recorder_crypto_cleanse(void *buf, size_t len);
const char *recorder_crypto_strerror(int status);

#ifdef __cplusplus
}
#endif

#endif
