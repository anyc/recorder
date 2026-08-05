#include "recorder_crypto.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

struct RecorderPublicKey {
    EVP_PKEY *pkey;
};

struct RecorderPrivateKey {
    EVP_PKEY *pkey;
};

static int no_password_cb(char *buf, int size, int rwflag, void *userdata)
{
    (void)buf;
    (void)size;
    (void)rwflag;
    (void)userdata;
    return 0;
}

static int pkey_is_rsa(const EVP_PKEY *pkey)
{
    return pkey != NULL && EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA;
}

int recorder_public_key_load_pem(const char *path,
                                 RecorderPublicKey **key_out)
{
    RecorderPublicKey *key = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    int status = RECORDER_CRYPTO_ERR_KEY_FORMAT;

    if (path == NULL || key_out == NULL)
        return RECORDER_CRYPTO_ERR_ARGUMENT;
    *key_out = NULL;

    bio = BIO_new_file(path, "rb");
    if (bio == NULL)
        return RECORDER_CRYPTO_ERR_IO;

    pkey = PEM_read_bio_PUBKEY(bio, NULL, no_password_cb, NULL);
    if (pkey == NULL)
        goto out;
    if (!pkey_is_rsa(pkey)) {
        status = RECORDER_CRYPTO_ERR_KEY_TYPE;
        goto out;
    }

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        status = RECORDER_CRYPTO_ERR_MEMORY;
        goto out;
    }
    key->pkey = pkey;
    pkey = NULL;
    *key_out = key;
    status = RECORDER_CRYPTO_OK;

out:
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return status;
}

int recorder_private_key_load_pem(const char *path,
                                  RecorderPrivateKey **key_out)
{
    RecorderPrivateKey *key = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;
    int status = RECORDER_CRYPTO_ERR_KEY_FORMAT;

    if (path == NULL || key_out == NULL)
        return RECORDER_CRYPTO_ERR_ARGUMENT;
    *key_out = NULL;

    bio = BIO_new_file(path, "rb");
    if (bio == NULL)
        return RECORDER_CRYPTO_ERR_IO;

    pkey = PEM_read_bio_PrivateKey(bio, NULL, no_password_cb, NULL);
    if (pkey == NULL)
        goto out;
    if (!pkey_is_rsa(pkey)) {
        status = RECORDER_CRYPTO_ERR_KEY_TYPE;
        goto out;
    }

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        status = RECORDER_CRYPTO_ERR_MEMORY;
        goto out;
    }
    key->pkey = pkey;
    pkey = NULL;
    *key_out = key;
    status = RECORDER_CRYPTO_OK;

out:
    EVP_PKEY_free(pkey);
    BIO_free(bio);
    return status;
}

void recorder_public_key_free(RecorderPublicKey *key)
{
    if (key == NULL)
        return;
    EVP_PKEY_free(key->pkey);
    OPENSSL_clear_free(key, sizeof(*key));
}

void recorder_private_key_free(RecorderPrivateKey *key)
{
    if (key == NULL)
        return;
    EVP_PKEY_free(key->pkey);
    OPENSSL_clear_free(key, sizeof(*key));
}

int recorder_crypto_random(void *buf, size_t len)
{
    unsigned char *p = buf;

    if (len != 0 && buf == NULL)
        return RECORDER_CRYPTO_ERR_ARGUMENT;
    while (len != 0) {
        int chunk = len > INT_MAX ? INT_MAX : (int)len;
        if (RAND_bytes(p, chunk) != 1)
            return RECORDER_CRYPTO_ERR_RANDOM;
        p += chunk;
        len -= (size_t)chunk;
    }
    return RECORDER_CRYPTO_OK;
}

static int configure_rsa_oaep(EVP_PKEY_CTX *ctx)
{
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0)
        return 0;
    return 1;
}

int recorder_crypto_wrap_dek(const RecorderPublicKey *key,
                             const uint8_t dek[RECORDER_CRYPTO_DEK_SIZE],
                             uint8_t **wrapped_out,
                             size_t *wrapped_len_out)
{
    EVP_PKEY_CTX *ctx = NULL;
    uint8_t *wrapped = NULL;
    size_t wrapped_len = 0;
    int status = RECORDER_CRYPTO_ERR_ENCRYPT;

    if (wrapped_out == NULL || wrapped_len_out == NULL)
        return RECORDER_CRYPTO_ERR_ARGUMENT;
    *wrapped_out = NULL;
    *wrapped_len_out = 0;
    if (key == NULL || key->pkey == NULL || dek == NULL)
        return RECORDER_CRYPTO_ERR_ARGUMENT;

    ctx = EVP_PKEY_CTX_new(key->pkey, NULL);
    if (ctx == NULL) {
        status = RECORDER_CRYPTO_ERR_MEMORY;
        goto out;
    }
    if (EVP_PKEY_encrypt_init(ctx) <= 0 || !configure_rsa_oaep(ctx) ||
        EVP_PKEY_encrypt(ctx, NULL, &wrapped_len, dek,
                         RECORDER_CRYPTO_DEK_SIZE) <= 0)
        goto out;

    wrapped = malloc(wrapped_len);
    if (wrapped == NULL) {
        status = RECORDER_CRYPTO_ERR_MEMORY;
        goto out;
    }
    if (EVP_PKEY_encrypt(ctx, wrapped, &wrapped_len, dek,
                         RECORDER_CRYPTO_DEK_SIZE) <= 0)
        goto out;

    *wrapped_out = wrapped;
    *wrapped_len_out = wrapped_len;
    wrapped = NULL;
    status = RECORDER_CRYPTO_OK;

out:
    free(wrapped);
    EVP_PKEY_CTX_free(ctx);
    return status;
}

int recorder_crypto_unwrap_dek(const RecorderPrivateKey *key,
                               const uint8_t *wrapped, size_t wrapped_len,
                               uint8_t dek_out[RECORDER_CRYPTO_DEK_SIZE])
{
    EVP_PKEY_CTX *ctx = NULL;
    uint8_t *clear = NULL;
    size_t clear_capacity = 0;
    size_t clear_len;
    int status = RECORDER_CRYPTO_ERR_DECRYPT;

    if (key == NULL || key->pkey == NULL || wrapped == NULL ||
        wrapped_len == 0 || dek_out == NULL)
        return RECORDER_CRYPTO_ERR_ARGUMENT;
    recorder_crypto_cleanse(dek_out, RECORDER_CRYPTO_DEK_SIZE);

    ctx = EVP_PKEY_CTX_new(key->pkey, NULL);
    if (ctx == NULL) {
        status = RECORDER_CRYPTO_ERR_MEMORY;
        goto out;
    }
    if (EVP_PKEY_decrypt_init(ctx) <= 0 || !configure_rsa_oaep(ctx) ||
        EVP_PKEY_decrypt(ctx, NULL, &clear_capacity, wrapped, wrapped_len) <= 0)
        goto out;

    clear = OPENSSL_malloc(clear_capacity);
    if (clear == NULL) {
        status = RECORDER_CRYPTO_ERR_MEMORY;
        goto out;
    }
    clear_len = clear_capacity;
    if (EVP_PKEY_decrypt(ctx, clear, &clear_len, wrapped, wrapped_len) <= 0) {
        status = RECORDER_CRYPTO_ERR_WRAPPED_KEY;
        goto out;
    }
    if (clear_len != RECORDER_CRYPTO_DEK_SIZE) {
        status = RECORDER_CRYPTO_ERR_WRAPPED_KEY;
        goto out;
    }

    memcpy(dek_out, clear, RECORDER_CRYPTO_DEK_SIZE);
    status = RECORDER_CRYPTO_OK;

out:
    if (status != RECORDER_CRYPTO_OK)
        recorder_crypto_cleanse(dek_out, RECORDER_CRYPTO_DEK_SIZE);
    OPENSSL_clear_free(clear, clear_capacity);
    EVP_PKEY_CTX_free(ctx);
    return status;
}

static int lengths_fit_evp(size_t aad_len, size_t input_len)
{
    return aad_len <= INT_MAX && input_len <= INT_MAX;
}

int recorder_crypto_aes_gcm_encrypt(
    const uint8_t dek[RECORDER_CRYPTO_DEK_SIZE],
    const uint8_t nonce[RECORDER_CRYPTO_GCM_NONCE_SIZE],
    const void *aad, size_t aad_len,
    const void *plaintext, size_t plaintext_len,
    void *ciphertext,
    uint8_t tag[RECORDER_CRYPTO_GCM_TAG_SIZE])
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char dummy[1];
    unsigned char *out = plaintext_len == 0 ? dummy : ciphertext;
    int len = 0;
    int final_len = 0;
    int status = RECORDER_CRYPTO_ERR_ENCRYPT;

    if (dek == NULL || nonce == NULL || tag == NULL ||
        (aad_len != 0 && aad == NULL) ||
        (plaintext_len != 0 && (plaintext == NULL || ciphertext == NULL)))
        return RECORDER_CRYPTO_ERR_ARGUMENT;
    if (!lengths_fit_evp(aad_len, plaintext_len))
        return RECORDER_CRYPTO_ERR_LENGTH;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        status = RECORDER_CRYPTO_ERR_MEMORY;
        goto out;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            RECORDER_CRYPTO_GCM_NONCE_SIZE, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, dek, nonce) != 1)
        goto out;
    if (aad_len != 0 &&
        EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
        goto out;
    if (plaintext_len != 0 &&
        EVP_EncryptUpdate(ctx, out, &len, plaintext, (int)plaintext_len) != 1)
        goto out;
    if (EVP_EncryptFinal_ex(ctx, out + len, &final_len) != 1 ||
        (size_t)(len + final_len) != plaintext_len ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            RECORDER_CRYPTO_GCM_TAG_SIZE, tag) != 1)
        goto out;
    status = RECORDER_CRYPTO_OK;

out:
    if (status != RECORDER_CRYPTO_OK) {
        if (ciphertext != NULL && plaintext_len != 0)
            recorder_crypto_cleanse(ciphertext, plaintext_len);
        recorder_crypto_cleanse(tag, RECORDER_CRYPTO_GCM_TAG_SIZE);
    }
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

int recorder_crypto_aes_gcm_decrypt(
    const uint8_t dek[RECORDER_CRYPTO_DEK_SIZE],
    const uint8_t nonce[RECORDER_CRYPTO_GCM_NONCE_SIZE],
    const void *aad, size_t aad_len,
    const void *ciphertext, size_t ciphertext_len,
    const uint8_t tag[RECORDER_CRYPTO_GCM_TAG_SIZE],
    void *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char dummy[1];
    unsigned char *out = ciphertext_len == 0 ? dummy : plaintext;
    int len = 0;
    int final_len = 0;
    int status = RECORDER_CRYPTO_ERR_DECRYPT;

    if (dek == NULL || nonce == NULL || tag == NULL ||
        (aad_len != 0 && aad == NULL) ||
        (ciphertext_len != 0 && (ciphertext == NULL || plaintext == NULL)))
        return RECORDER_CRYPTO_ERR_ARGUMENT;
    if (!lengths_fit_evp(aad_len, ciphertext_len))
        return RECORDER_CRYPTO_ERR_LENGTH;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        status = RECORDER_CRYPTO_ERR_MEMORY;
        goto out;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            RECORDER_CRYPTO_GCM_NONCE_SIZE, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, dek, nonce) != 1)
        goto out;
    if (aad_len != 0 &&
        EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
        goto out;
    if (ciphertext_len != 0 &&
        EVP_DecryptUpdate(ctx, out, &len, ciphertext,
                          (int)ciphertext_len) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            RECORDER_CRYPTO_GCM_TAG_SIZE, (void *)tag) != 1)
        goto out;
    if (EVP_DecryptFinal_ex(ctx, out + len, &final_len) != 1) {
        status = RECORDER_CRYPTO_ERR_AUTHENTICATION;
        goto out;
    }
    if ((size_t)(len + final_len) != ciphertext_len)
        goto out;
    status = RECORDER_CRYPTO_OK;

out:
    if (status != RECORDER_CRYPTO_OK && plaintext != NULL &&
        ciphertext_len != 0)
        recorder_crypto_cleanse(plaintext, ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);
    return status;
}

void recorder_crypto_cleanse(void *buf, size_t len)
{
    if (buf != NULL && len != 0)
        OPENSSL_cleanse(buf, len);
}

const char *recorder_crypto_strerror(int status)
{
    switch (status) {
    case RECORDER_CRYPTO_OK:
        return "success";
    case RECORDER_CRYPTO_ERR_ARGUMENT:
        return "invalid cryptography argument";
    case RECORDER_CRYPTO_ERR_MEMORY:
        return "cryptography allocation failed";
    case RECORDER_CRYPTO_ERR_IO:
        return "unable to open key file";
    case RECORDER_CRYPTO_ERR_KEY_FORMAT:
        return "invalid or encrypted PEM key";
    case RECORDER_CRYPTO_ERR_KEY_TYPE:
        return "key is not an RSA key";
    case RECORDER_CRYPTO_ERR_LENGTH:
        return "cryptography input is too large";
    case RECORDER_CRYPTO_ERR_RANDOM:
        return "secure random generation failed";
    case RECORDER_CRYPTO_ERR_ENCRYPT:
        return "encryption failed";
    case RECORDER_CRYPTO_ERR_DECRYPT:
        return "decryption failed";
    case RECORDER_CRYPTO_ERR_AUTHENTICATION:
        return "ciphertext authentication failed";
    case RECORDER_CRYPTO_ERR_WRAPPED_KEY:
        return "wrapped data key is invalid";
    default:
        return "unknown cryptography error";
    }
}
