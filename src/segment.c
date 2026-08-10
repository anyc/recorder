#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <zstd.h>

#include "helper.h"
#ifdef errno
#pragma push_macro("errno")
#undef errno
#define RECORDER_SEGMENT_C_RESTORE_ERRNO 1
#endif
#include "recorder_verifier.h"
#ifdef RECORDER_SEGMENT_C_RESTORE_ERRNO
#pragma pop_macro("errno")
#undef RECORDER_SEGMENT_C_RESTORE_ERRNO
#endif
#include "recorder_crypto.h"
#include "segment.h"

enum {
	SEGMENT_HEADER_FIXED_SIZE =
		8 + 4 + 4 + 4 + 8 + 4 + RECORDER_BOOT_ID_SIZE +
		RECORDER_SEGMENT_TZ_SIZE + 8 + 8 + 4 + 4,
	SEGMENT_FRAME_HEADER_SIZE = 4 + 4 + 4 + 4,
	SEGMENT_ENCRYPTION_EXTENSION_FIXED_SIZE = 8 + 4 + 4 + 4 + 4 + 4 + 4,
	SEGMENT_DEK_SIZE = 32,
	SEGMENT_NONCE_PREFIX_SIZE = 4,
	SEGMENT_GCM_NONCE_SIZE = 12,
	SEGMENT_GCM_TAG_SIZE = 16,
	SEGMENT_KEY_WRAP_RSA_OAEP_SHA256 = 1,
	SEGMENT_CIPHER_AES_256_GCM = 1,
	SEGMENT_FOOTER_BODY_SIZE = 4 + 4 + 8 + 8 + 8 + 4,
	SEGMENT_FOOTER_TRAILER_SIZE = 4 + 8
};

#define SEGMENT_ENCRYPTION_EXTENSION_MAGIC "RECENC01"
#define SEGMENT_ENCRYPTION_EXTENSION_VERSION 1u

struct SegmentEncryptor {
	RecorderPublicKey *public_key;
	unsigned char dek[SEGMENT_DEK_SIZE];
	unsigned char nonce_prefix[SEGMENT_NONCE_PREFIX_SIZE];
	uint64_t frame_index;
	int initialized;
};

struct SegmentDecryptor {
	RecorderPrivateKey *private_key;
};

typedef struct {
	const unsigned char *wrapped_dek;
	uint32_t wrapped_dek_len;
	unsigned char nonce_prefix[SEGMENT_NONCE_PREFIX_SIZE];
} SegmentEncryptionInfo;

static void secure_clear(void *ptr, size_t len)
{
	volatile unsigned char *p = ptr;

	while (len-- != 0) {
		*p++ = 0;
	}
}

int segment_encryptor_create(const char *public_key_pem_path,
							 SegmentEncryptor **encryptor_out)
{
	SegmentEncryptor *encryptor;

	if (!public_key_pem_path || !encryptor_out) {
		errno = EINVAL;
		return -1;
	}
	*encryptor_out = NULL;
	encryptor = calloc(1, sizeof(*encryptor));
	if (!encryptor) {
		return -1;
	}
	if (recorder_public_key_load_pem(public_key_pem_path,
								 &encryptor->public_key) != 0) {
		free(encryptor);
		return -1;
	}
	*encryptor_out = encryptor;
	return 0;
}

void segment_encryptor_free(SegmentEncryptor *encryptor)
{
	if (!encryptor) {
		return;
	}
	recorder_public_key_free(encryptor->public_key);
	secure_clear(encryptor->dek, sizeof(encryptor->dek));
	free(encryptor);
}

int segment_decryptor_create(const char *private_key_pem_path,
							 SegmentDecryptor **decryptor_out)
{
	SegmentDecryptor *decryptor;

	if (!private_key_pem_path || !decryptor_out) {
		errno = EINVAL;
		return -1;
	}
	*decryptor_out = NULL;
	decryptor = calloc(1, sizeof(*decryptor));
	if (!decryptor) {
		return -1;
	}
	if (recorder_private_key_load_pem(private_key_pem_path,
								  &decryptor->private_key) != 0) {
		free(decryptor);
		return -1;
	}
	*decryptor_out = decryptor;
	return 0;
}

void segment_decryptor_free(SegmentDecryptor *decryptor)
{
	if (!decryptor) {
		return;
	}
	recorder_private_key_free(decryptor->private_key);
	free(decryptor);
}

static int write_all(FILE *fp, const void *buf, size_t len)
{
	return fwrite(buf, 1, len, fp) == len ? 0 : -1;
}

size_t segment_header_encoded_size(void)
{
	return SEGMENT_HEADER_FIXED_SIZE;
}

size_t segment_footer_encoded_size(void)
{
	return SEGMENT_FOOTER_BODY_SIZE + SEGMENT_FOOTER_TRAILER_SIZE;
}

int segment_write_header(FILE *fp, const SegmentHeader *header,
							const void *dict_bytes, size_t dict_len,
							SegmentEncryptor *encryptor)
{
	unsigned char buf[SEGMENT_HEADER_FIXED_SIZE];
	unsigned char *extension = NULL;
	unsigned char *wrapped_dek = NULL;
	size_t wrapped_dek_len = 0;
	size_t extension_len = 0;
	unsigned char dek[SEGMENT_DEK_SIZE];
	unsigned char nonce_prefix[SEGMENT_NONCE_PREFIX_SIZE];
	uint32_t crc;
	int rv = -1;

	memset(dek, 0, sizeof(dek));
	memset(nonce_prefix, 0, sizeof(nonce_prefix));
	if (!fp || !header || (dict_len != 0 && !dict_bytes)) {
		errno = EINVAL;
		return -1;
	}
	if (dict_len > UINT32_MAX) {
		errno = EOVERFLOW;
		return -1;
	}
	if (((header->flags & SEGMENT_FLAG_ENCRYPTED) != 0) !=
		(encryptor != NULL)) {
		errno = EINVAL;
		return -1;
	}
	if (encryptor) {
		encryptor->initialized = 0;
		recorder_crypto_cleanse(encryptor->dek, sizeof(encryptor->dek));
		if (recorder_crypto_random(dek, sizeof(dek)) != 0 ||
			recorder_crypto_random(nonce_prefix, sizeof(nonce_prefix)) != 0 ||
			recorder_crypto_wrap_dek(encryptor->public_key, dek,
									 &wrapped_dek, &wrapped_dek_len) != 0) {
			goto out;
		}
		if (wrapped_dek_len > UINT32_MAX - SEGMENT_HEADER_FIXED_SIZE -
				SEGMENT_ENCRYPTION_EXTENSION_FIXED_SIZE -
				SEGMENT_NONCE_PREFIX_SIZE) {
			errno = EOVERFLOW;
			goto out;
		}
		extension_len = SEGMENT_ENCRYPTION_EXTENSION_FIXED_SIZE +
			SEGMENT_NONCE_PREFIX_SIZE + wrapped_dek_len;
		extension = malloc(extension_len);
		if (!extension) {
			goto out;
		}
		memcpy(extension + 0, SEGMENT_ENCRYPTION_EXTENSION_MAGIC, 8);
		write_u32_le(extension + 8, SEGMENT_ENCRYPTION_EXTENSION_VERSION);
		write_u32_le(extension + 12, (uint32_t)extension_len);
		write_u32_le(extension + 16, SEGMENT_KEY_WRAP_RSA_OAEP_SHA256);
		write_u32_le(extension + 20, SEGMENT_CIPHER_AES_256_GCM);
		write_u32_le(extension + 24, (uint32_t)wrapped_dek_len);
		write_u32_le(extension + 28, SEGMENT_NONCE_PREFIX_SIZE);
		memcpy(extension + SEGMENT_ENCRYPTION_EXTENSION_FIXED_SIZE,
			   nonce_prefix, sizeof(nonce_prefix));
		memcpy(extension + SEGMENT_ENCRYPTION_EXTENSION_FIXED_SIZE +
			   SEGMENT_NONCE_PREFIX_SIZE, wrapped_dek, wrapped_dek_len);
	}

	memcpy(buf, RECORDER_SEGMENT_MAGIC, 8);
	write_u32_le(buf + 8, RECORDER_SEGMENT_VERSION);
	write_u32_le(buf + 12, SEGMENT_HEADER_FIXED_SIZE + (uint32_t)extension_len);
	write_u32_le(buf + 16, header->flags);
	write_u64_le(buf + 20, header->segment_seq);
	write_u32_le(buf + 28, header->boot_seq);
	memset(buf + 32, 0, RECORDER_BOOT_ID_SIZE);
	strncpy((char *)buf + 32, header->boot_id, RECORDER_BOOT_ID_SIZE);
	memset(buf + 64, 0, RECORDER_SEGMENT_TZ_SIZE);
	strncpy((char *)buf + 64, header->timezone, RECORDER_SEGMENT_TZ_SIZE - 1);
	write_u64_le(buf + 128, header->first_realtime_ts);
	write_u64_le(buf + 136, header->first_monotonic_ts);
	write_u32_le(buf + 144, (uint32_t)dict_len);
	crc = recorder_crc32(buf, 148);
	if (extension_len != 0) {
		crc ^= recorder_crc32(extension, extension_len);
	}
	write_u32_le(buf + 148, crc);

	if (write_all(fp, buf, sizeof(buf)) != 0 ||
		(extension_len != 0 && write_all(fp, extension, extension_len) != 0) ||
		(dict_len != 0 && write_all(fp, dict_bytes, dict_len) != 0)) {
		goto out;
	}
	if (encryptor) {
		memcpy(encryptor->dek, dek, sizeof(dek));
		memcpy(encryptor->nonce_prefix, nonce_prefix, sizeof(nonce_prefix));
		encryptor->frame_index = 0;
		encryptor->initialized = 1;
	}
	rv = 0;

out:
	recorder_crypto_cleanse(dek, sizeof(dek));
	free(wrapped_dek);
	free(extension);
	return rv;
}

int segment_write_frame(FILE *fp, SegmentEncryptor *encryptor, uint32_t flags,
						const void *payload, uint32_t stored_len,
						uint32_t uncompressed_len)
{
	unsigned char header[SEGMENT_FRAME_HEADER_SIZE];
	unsigned char nonce[SEGMENT_GCM_NONCE_SIZE];
	unsigned char tag[SEGMENT_GCM_TAG_SIZE];
	unsigned char crc_buf[4];
	unsigned char *encrypted_payload = NULL;
	const void *stored_payload = payload;
	uint32_t trailer_size = 4;
	uint32_t frame_len;
	uint32_t crc;
	uint64_t frame_index;
	int rv = -1;
	unsigned int i;

	if (!fp || (stored_len != 0 && !payload) ||
		(encryptor && !encryptor->initialized)) {
		errno = EINVAL;
		return -1;
	}
	if (encryptor) {
		trailer_size += SEGMENT_GCM_TAG_SIZE;
	}
	if (stored_len > UINT32_MAX - SEGMENT_FRAME_HEADER_SIZE - trailer_size) {
		errno = EOVERFLOW;
		return -1;
	}
	frame_len = SEGMENT_FRAME_HEADER_SIZE + stored_len + trailer_size;
	write_u32_le(header + 0, flags);
	write_u32_le(header + 4, stored_len);
	write_u32_le(header + 8, uncompressed_len);
	write_u32_le(header + 12, frame_len);

	if (encryptor) {
		if (encryptor->frame_index == UINT64_MAX) {
			errno = EOVERFLOW;
			return -1;
		}
		encrypted_payload = malloc(stored_len ? stored_len : 1);
		if (!encrypted_payload) {
			return -1;
		}
		frame_index = encryptor->frame_index++;
		memcpy(nonce, encryptor->nonce_prefix, SEGMENT_NONCE_PREFIX_SIZE);
		for (i = 0; i < 8; i++) {
			nonce[SEGMENT_NONCE_PREFIX_SIZE + i] =
				(unsigned char)(frame_index >> (56 - i * 8));
		}
		if (recorder_crypto_aes_gcm_encrypt(encryptor->dek, nonce,
				header, sizeof(header), payload, stored_len,
				encrypted_payload, tag) != 0) {
			goto out;
		}
		stored_payload = encrypted_payload;
	}

	crc = recorder_crc32(header, sizeof(header));
	crc ^= recorder_crc32(stored_payload, stored_len);
	if (encryptor) {
		crc ^= recorder_crc32(tag, sizeof(tag));
	}
	write_u32_le(crc_buf, crc);
	if (write_all(fp, header, sizeof(header)) != 0 ||
		write_all(fp, stored_payload, stored_len) != 0 ||
		(encryptor && write_all(fp, tag, sizeof(tag)) != 0) ||
		write_all(fp, crc_buf, sizeof(crc_buf)) != 0) {
		goto out;
	}
	rv = 0;

out:
	free(encrypted_payload);
	return rv;
}

int segment_write_footer(FILE *fp, const SegmentFooter *footer)
{
	unsigned char buf[SEGMENT_FOOTER_BODY_SIZE + SEGMENT_FOOTER_TRAILER_SIZE];
	uint32_t crc;

	if ((footer->footer_flags & SEGMENT_FOOTER_FLAG_HAS_SIGNATURE) != 0) {
		errno = ENOTSUP;
		return -1;
	}
	write_u32_le(buf + 0, footer->footer_flags);
	write_u32_le(buf + 4, footer->rotation_reason);
	write_u64_le(buf + 8, footer->entry_count);
	write_u64_le(buf + 16, footer->last_realtime_ts);
	write_u64_le(buf + 24, footer->last_monotonic_ts);
	write_u32_le(buf + 32, 0);
	write_u32_le(buf + 36, RECORDER_SEGMENT_VERSION);
	memcpy(buf + 40, RECORDER_SEGMENT_FOOTER_MAGIC, 8);
	crc = recorder_crc32(buf, sizeof(buf));
	write_u32_le(buf + 32, crc);
	return write_all(fp, buf, sizeof(buf));
}

static int decompress_payload(const SegmentHeader *header,
								const void *dict_bytes,
								const SegmentFrameInfo *frame,
								const void *payload, void **chunk_out,
								size_t *chunk_size_out)
{
	void *decoded = NULL;
	size_t rv;

	if ((frame->flags & SEGMENT_FRAME_FLAG_ZSTD) == 0) {
		/* The frame payload may start at an unaligned mmap offset. */
		void *aligned = malloc(frame->stored_len);

		if (!aligned) {
			return -1;
		}
		memcpy(aligned, payload, frame->stored_len);
		*chunk_out = aligned;
		*chunk_size_out = frame->stored_len;
		return 1;
	}

	decoded = malloc(frame->uncompressed_len);
	if (!decoded) {
		return -1;
	}
	if ((header->flags & SEGMENT_FLAG_HAS_STATIC_DICT) != 0 && header->dict_len != 0) {
		ZSTD_DCtx *dctx = ZSTD_createDCtx();

		if (!dctx) {
			free(decoded);
			return -1;
		}
		rv = ZSTD_decompress_usingDict(dctx, decoded, frame->uncompressed_len,
										payload, frame->stored_len,
										dict_bytes, header->dict_len);
		ZSTD_freeDCtx(dctx);
	} else {
		rv = ZSTD_decompress(decoded, frame->uncompressed_len,
								payload, frame->stored_len);
	}
	if (ZSTD_isError(rv) || rv != frame->uncompressed_len) {
		free(decoded);
		return -1;
	}
	*chunk_out = decoded;
	*chunk_size_out = rv;
	return 1;
}

static int segment_parse_header(const void *buf, size_t size,
								SegmentHeader *header, size_t *offset_out,
								SegmentEncryptionInfo *encryption_out)
{
	uint32_t header_size;
	uint32_t crc;
	const unsigned char *bytes = buf;
	const unsigned char *extension;
	size_t extension_len;
	uint32_t wrapped_dek_len;
	uint32_t nonce_prefix_len;

	if (!buf || !header || !offset_out || size < SEGMENT_HEADER_FIXED_SIZE) {
		return -1;
	}
	if (memcmp(buf, RECORDER_SEGMENT_MAGIC, 8) != 0) {
		return -1;
	}
	if (read_u32_le(bytes + 8) != RECORDER_SEGMENT_VERSION) {
		return -1;
	}
	header_size = read_u32_le(bytes + 12);
	if (header_size < SEGMENT_HEADER_FIXED_SIZE || header_size > size) {
		return -1;
	}

	memset(header, 0, sizeof(*header));
	if (encryption_out) {
		memset(encryption_out, 0, sizeof(*encryption_out));
	}
	header->flags = read_u32_le(bytes + 16);
	header->segment_seq = read_u64_le(bytes + 20);
	header->boot_seq = read_u32_le(bytes + 28);
	memcpy(header->boot_id, bytes + 32, RECORDER_BOOT_ID_SIZE);
	header->boot_id[RECORDER_BOOT_ID_SIZE] = '\0';
	memcpy(header->timezone, bytes + 64, RECORDER_SEGMENT_TZ_SIZE - 1);
	header->timezone[RECORDER_SEGMENT_TZ_SIZE - 1] = '\0';
	header->first_realtime_ts = read_u64_le(bytes + 128);
	header->first_monotonic_ts = read_u64_le(bytes + 136);
	header->dict_len = read_u32_le(bytes + 144);

	extension = bytes + SEGMENT_HEADER_FIXED_SIZE;
	extension_len = header_size - SEGMENT_HEADER_FIXED_SIZE;
	if ((header->flags & SEGMENT_FLAG_ENCRYPTED) != 0) {
		if (extension_len < SEGMENT_ENCRYPTION_EXTENSION_FIXED_SIZE +
				SEGMENT_NONCE_PREFIX_SIZE ||
			memcmp(extension, SEGMENT_ENCRYPTION_EXTENSION_MAGIC, 8) != 0 ||
			read_u32_le(extension + 8) != SEGMENT_ENCRYPTION_EXTENSION_VERSION ||
			read_u32_le(extension + 12) != extension_len ||
			read_u32_le(extension + 16) != SEGMENT_KEY_WRAP_RSA_OAEP_SHA256 ||
			read_u32_le(extension + 20) != SEGMENT_CIPHER_AES_256_GCM) {
			return -1;
		}
		wrapped_dek_len = read_u32_le(extension + 24);
		nonce_prefix_len = read_u32_le(extension + 28);
		if (nonce_prefix_len != SEGMENT_NONCE_PREFIX_SIZE ||
			wrapped_dek_len == 0 ||
			(size_t)wrapped_dek_len != extension_len -
				SEGMENT_ENCRYPTION_EXTENSION_FIXED_SIZE - nonce_prefix_len) {
			return -1;
		}
		if (encryption_out) {
			memcpy(encryption_out->nonce_prefix,
				   extension + SEGMENT_ENCRYPTION_EXTENSION_FIXED_SIZE,
				   SEGMENT_NONCE_PREFIX_SIZE);
			encryption_out->wrapped_dek = extension +
				SEGMENT_ENCRYPTION_EXTENSION_FIXED_SIZE + nonce_prefix_len;
			encryption_out->wrapped_dek_len = wrapped_dek_len;
		}
	} else if (extension_len != 0) {
		return -1;
	}

	crc = recorder_crc32(buf, 148);
	if (extension_len != 0) {
		crc ^= recorder_crc32(extension, extension_len);
	}
	if (read_u32_le(bytes + 148) != crc) {
		return -1;
	}
	if (header->dict_len > size - header_size) {
		return -1;
	}
	*offset_out = header_size + header->dict_len;
	return 0;
}

int segment_read_header(const void *buf, size_t size,
						SegmentHeader *header, size_t *offset_out)
{
	return segment_parse_header(buf, size, header, offset_out, NULL);
}

static int segment_scan_impl(const void *buf, size_t size,
								SegmentDecryptor *decryptor, segment_frame_cb cb,
								void *ctx, SegmentHeader *header_out,
								SegmentFooter *footer_out, size_t *committed_end_out)
{
	SegmentHeader header;
	SegmentEncryptionInfo encryption;
	unsigned char dek[SEGMENT_DEK_SIZE];
	size_t offset = 0;
	size_t committed_end;
	SegmentFooter footer;
	const unsigned char *dict_bytes = NULL;
	uint64_t frame_index = 0;
	int encrypted;
	int rv = -1;

	memset(dek, 0, sizeof(dek));
	if (segment_parse_header(buf, size, &header, &offset, &encryption) != 0) {
		return -1;
	}
	encrypted = (header.flags & SEGMENT_FLAG_ENCRYPTED) != 0;
	if (encrypted && cb) {
		if (!decryptor) {
			errno = EACCES;
			return -1;
		}
		if (recorder_crypto_unwrap_dek(decryptor->private_key,
				encryption.wrapped_dek, encryption.wrapped_dek_len, dek) != 0) {
			errno = EACCES;
			return -1;
		}
	}
	if (header.dict_len != 0) {
		dict_bytes = (const unsigned char *)buf + offset - header.dict_len;
	}
	committed_end = offset;
	memset(&footer, 0, sizeof(footer));

	while (offset < size) {
		const unsigned char *p = (const unsigned char *)buf + offset;
		uint32_t total_len;
		uint32_t stored_crc;
		uint32_t tag_len = encrypted ? SEGMENT_GCM_TAG_SIZE : 0;
		size_t expected_len;
		SegmentFrameInfo frame;

		if (size - offset >= SEGMENT_FOOTER_BODY_SIZE +
				SEGMENT_FOOTER_TRAILER_SIZE &&
			memcmp(p + 40, RECORDER_SEGMENT_FOOTER_MAGIC, 8) == 0 &&
			read_u32_le(p + 36) == RECORDER_SEGMENT_VERSION) {
			uint32_t expect_crc = read_u32_le(p + 32);
			unsigned char tmp[SEGMENT_FOOTER_BODY_SIZE + SEGMENT_FOOTER_TRAILER_SIZE];

			memcpy(tmp, p, sizeof(tmp));
			write_u32_le(tmp + 32, 0);
			if (expect_crc == recorder_crc32(tmp, sizeof(tmp))) {
				footer.footer_flags = read_u32_le(p + 0);
				footer.rotation_reason = read_u32_le(p + 4);
				footer.entry_count = read_u64_le(p + 8);
				footer.last_realtime_ts = read_u64_le(p + 16);
				footer.last_monotonic_ts = read_u64_le(p + 24);
				committed_end = offset + sizeof(tmp);
				offset = committed_end;
				break;
			}
		}

		if (size - offset < SEGMENT_FRAME_HEADER_SIZE + 4 + tag_len) {
			break;
		}
		frame.flags = read_u32_le(p + 0);
		frame.stored_len = read_u32_le(p + 4);
		frame.uncompressed_len = read_u32_le(p + 8);
		total_len = read_u32_le(p + 12);
		frame.file_offset = offset;
		frame.frame_len = total_len;
		expected_len = SEGMENT_FRAME_HEADER_SIZE + (size_t)frame.stored_len +
			tag_len + 4;
		if (expected_len > UINT32_MAX || total_len != expected_len) {
			if (encrypted) {
				errno = EIO;
				goto out;
			}
			break;
		}
		if (total_len > size - offset) {
			break;
		}
		stored_crc = read_u32_le(p + SEGMENT_FRAME_HEADER_SIZE +
			frame.stored_len + tag_len);
		{
			uint32_t calc_crc = recorder_crc32(p, SEGMENT_FRAME_HEADER_SIZE) ^
				recorder_crc32(p + SEGMENT_FRAME_HEADER_SIZE,
							   frame.stored_len);

			if (encrypted) {
				calc_crc ^= recorder_crc32(p + SEGMENT_FRAME_HEADER_SIZE +
					frame.stored_len, tag_len);
			}
			if (stored_crc != calc_crc) {
				if (encrypted) {
					errno = EIO;
					goto out;
				}
				break;
			}
		}
		if (cb) {
			const void *payload = p + SEGMENT_FRAME_HEADER_SIZE;
			void *decrypted_payload = NULL;
			void *chunk_buf = NULL;
			size_t chunk_size;
			int drv;
			int verify_rv;
			int cb_rv;

			if (encrypted) {
				unsigned char nonce[SEGMENT_GCM_NONCE_SIZE];
				const unsigned char *tag = p + SEGMENT_FRAME_HEADER_SIZE +
					frame.stored_len;
				unsigned int i;

				decrypted_payload = malloc(frame.stored_len ? frame.stored_len : 1);
				if (!decrypted_payload) {
					goto out;
				}
				memcpy(nonce, encryption.nonce_prefix, SEGMENT_NONCE_PREFIX_SIZE);
				for (i = 0; i < 8; i++) {
					nonce[SEGMENT_NONCE_PREFIX_SIZE + i] =
						(unsigned char)(frame_index >> (56 - i * 8));
				}
				if (recorder_crypto_aes_gcm_decrypt(dek, nonce,
						p, SEGMENT_FRAME_HEADER_SIZE, payload, frame.stored_len,
						tag, decrypted_payload) != 0) {
					free(decrypted_payload);
					errno = EIO;
					goto out;
				}
				payload = decrypted_payload;
			}
			drv = decompress_payload(&header, dict_bytes, &frame, payload,
									 &chunk_buf, &chunk_size);
			free(decrypted_payload);
			if (drv < 0) {
				if (encrypted) {
					errno = EIO;
					goto out;
				}
				break;
			}
			if ((header.flags & SEGMENT_FLAG_COMPACT_ENTRIES) != 0) {
				verify_rv = journal_DefaultChunk_verify_as_root(chunk_buf, chunk_size);
			} else {
				verify_rv = journal_Chunk_verify_as_root(chunk_buf, chunk_size);
			}
			if (verify_rv != flatcc_verify_ok) {
				free(chunk_buf);
				if (encrypted) {
					errno = EIO;
					goto out;
				}
				break;
			}
			cb_rv = cb(&header, &frame, chunk_buf, chunk_size, ctx);
			free(chunk_buf);
			if (cb_rv != 0) {
				rv = cb_rv;
				goto out;
			}
		}
		if (encrypted && frame_index == UINT64_MAX) {
			errno = EOVERFLOW;
			goto out;
		}
		frame_index++;
		offset += total_len;
		committed_end = offset;
	}

	if (header_out) {
		*header_out = header;
	}
	if (footer_out) {
		*footer_out = footer;
	}
	if (committed_end_out) {
		*committed_end_out = committed_end;
	}
	rv = 0;

out:
	recorder_crypto_cleanse(dek, sizeof(dek));
	return rv;
}

int segment_scan_buffer(const void *buf, size_t size,
						SegmentDecryptor *decryptor, segment_frame_cb cb,
						void *ctx, SegmentHeader *header_out,
						SegmentFooter *footer_out, size_t *committed_end_out)
{
	return segment_scan_impl(buf, size, decryptor, cb, ctx, header_out,
								footer_out, committed_end_out);
}

int segment_scan_path(const char *path, SegmentDecryptor *decryptor,
						segment_frame_cb cb, void *ctx,
						SegmentHeader *header_out, SegmentFooter *footer_out,
						size_t *committed_end_out)
{
	int fd = -1;
	struct stat st;
	void *map = MAP_FAILED;
	int rv = -1;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	if (fstat(fd, &st) != 0) {
		goto out;
	}
	if (st.st_size == 0) {
		errno = EINVAL;
		goto out;
	}
	map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == MAP_FAILED) {
		goto out;
	}

	rv = segment_scan_impl(map, (size_t)st.st_size, decryptor, cb, ctx, header_out,
							footer_out, committed_end_out);

out:
	if (map != MAP_FAILED) {
		munmap(map, st.st_size);
	}
	if (fd >= 0) {
		close(fd);
	}
	return rv;
}
