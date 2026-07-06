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
    SEGMENT_FLAG_WHOLE_COMPRESSED = 1u << 1
};

enum {
    SEGMENT_FRAME_FLAG_NONE = 0u,
    SEGMENT_FRAME_FLAG_ZSTD = 1u << 0
};

enum {
    SEGMENT_FOOTER_FLAG_HAS_SIGNATURE = 1u << 0
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
    uint64_t entry_count;
    uint64_t last_realtime_ts;
    uint64_t last_monotonic_ts;
} SegmentFooter;

typedef int (*segment_frame_cb)(const SegmentHeader *header,
                                const SegmentFrameInfo *frame,
                                const void *chunk_buf, size_t chunk_size,
                                void *ctx);

size_t segment_header_encoded_size(void);
size_t segment_footer_encoded_size(void);
int segment_write_header(FILE *fp, const SegmentHeader *header,
                         const void *dict_bytes, size_t dict_len);
int segment_write_frame(FILE *fp, uint32_t flags,
                        const void *payload, uint32_t stored_len,
                        uint32_t uncompressed_len);
int segment_write_footer(FILE *fp, const SegmentFooter *footer);
int segment_read_header(const void *buf, size_t size,
                        SegmentHeader *header, size_t *offset_out);
int segment_scan_path(const char *path, segment_frame_cb cb, void *ctx,
                      SegmentHeader *header_out, SegmentFooter *footer_out,
                      size_t *committed_end_out);
int segment_scan_buffer(const void *buf, size_t size, segment_frame_cb cb,
                        void *ctx, SegmentHeader *header_out,
                        SegmentFooter *footer_out, size_t *committed_end_out);

#endif
