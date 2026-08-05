#ifndef SEGMENT_H
#define SEGMENT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef errno
#pragma push_macro("errno")
#undef errno
#define RECORDER_SEGMENT_RESTORE_ERRNO 1
#endif

#include "recorder_reader.h"

#ifdef RECORDER_SEGMENT_RESTORE_ERRNO
#pragma pop_macro("errno")
#undef RECORDER_SEGMENT_RESTORE_ERRNO
#endif

#define RECORDER_SEGMENT_MAGIC "RECSEG01"
#define RECORDER_SEGMENT_FOOTER_MAGIC "RECEND01"
#define RECORDER_SEGMENT_VERSION 1u
#define RECORDER_SEGMENT_TZ_SIZE 64u
#define RECORDER_BOOT_ID_SIZE 32u

enum {
    SEGMENT_FLAG_HAS_STATIC_DICT = 1u << 0,
    SEGMENT_FLAG_WHOLE_COMPRESSED = 1u << 1,
    SEGMENT_FLAG_COMPACT_ENTRIES = 1u << 2,
    SEGMENT_FLAG_ENCRYPTED = 1u << 3,
    /* Reserved for a future plaintext-but-signed segment mode. */
    SEGMENT_FLAG_SIGNED = 1u << 4
};

enum {
    SEGMENT_FRAME_FLAG_NONE = 0u,
    SEGMENT_FRAME_FLAG_ZSTD = 1u << 0
};

enum {
    SEGMENT_FOOTER_FLAG_HAS_SIGNATURE = 1u << 0
};

enum {
    SEGMENT_SIGNATURE_ALGORITHM_NONE = 0,
    SEGMENT_SIGNATURE_ALGORITHM_ED25519 = 1
};

enum {
    SEGMENT_ROTATION_REASON_NONE = 0,
    SEGMENT_ROTATION_REASON_BOOT_ID,
    SEGMENT_ROTATION_REASON_TIMEZONE,
    SEGMENT_ROTATION_REASON_CLOCK_BACKWARD,
    SEGMENT_ROTATION_REASON_CLOCK_FORWARD,
    SEGMENT_ROTATION_REASON_AGE,
    SEGMENT_ROTATION_REASON_SIZE,
    SEGMENT_ROTATION_REASON_SHUTDOWN
};

typedef struct {
    uint32_t flags;
    uint64_t segment_seq;
    uint32_t boot_seq;
    char boot_id[RECORDER_BOOT_ID_SIZE + 1];
    char timezone[RECORDER_SEGMENT_TZ_SIZE];
    uint64_t first_realtime_ts;
    uint64_t first_monotonic_ts;
    uint32_t dict_len;
} SegmentHeader;

typedef struct {
    uint32_t flags;
    uint32_t stored_len;
    uint32_t uncompressed_len;
    uint64_t file_offset;
    uint32_t frame_len;
} SegmentFrameInfo;

typedef struct {
    uint32_t signature_algorithm;
    uint32_t signature_len;
    const void *signature_bytes;
    uint32_t footer_flags;
    uint32_t rotation_reason;
    uint64_t entry_count;
    uint64_t last_realtime_ts;
    uint64_t last_monotonic_ts;
} SegmentFooter;

typedef int (*segment_frame_cb)(const SegmentHeader *header,
                                const SegmentFrameInfo *frame,
                                const void *chunk_buf, size_t chunk_size,
                                void *ctx);

typedef struct SegmentEncryptor SegmentEncryptor;
typedef struct SegmentDecryptor SegmentDecryptor;

/*
 * An encryptor owns the public key and the current segment's generated DEK.
 * Writing an encrypted header initializes it; pass the same object to every
 * frame in that segment. It may be reused for a later header, which generates
 * fresh key and nonce material.
 */
int segment_encryptor_create(const char *public_key_pem_path,
                             SegmentEncryptor **encryptor_out);
void segment_encryptor_free(SegmentEncryptor *encryptor);
int segment_decryptor_create(const char *private_key_pem_path,
                             SegmentDecryptor **decryptor_out);
void segment_decryptor_free(SegmentDecryptor *decryptor);

size_t segment_header_encoded_size(void);
size_t segment_footer_encoded_size(void);
int segment_write_header(FILE *fp, const SegmentHeader *header,
                         const void *dict_bytes, size_t dict_len,
                         SegmentEncryptor *encryptor);
int segment_write_frame(FILE *fp, SegmentEncryptor *encryptor,
                        uint32_t flags,
                        const void *payload, uint32_t stored_len,
                        uint32_t uncompressed_len);
int segment_write_footer(FILE *fp, const SegmentFooter *footer);
int segment_read_header(const void *buf, size_t size,
                        SegmentHeader *header, size_t *offset_out);
/* A decryptor is optional for metadata-only scans (cb == NULL). */
int segment_scan_path(const char *path, SegmentDecryptor *decryptor,
                      segment_frame_cb cb, void *ctx,
                      SegmentHeader *header_out, SegmentFooter *footer_out,
                      size_t *committed_end_out);
int segment_scan_buffer(const void *buf, size_t size,
                        SegmentDecryptor *decryptor, segment_frame_cb cb,
                        void *ctx, SegmentHeader *header_out,
                        SegmentFooter *footer_out, size_t *committed_end_out);

#endif
