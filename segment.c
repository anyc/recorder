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
#include "segment.h"

enum {
    SEGMENT_HEADER_FIXED_SIZE =
        8 + 4 + 4 + 4 + 8 + 4 + RECORDER_BOOT_ID_SIZE +
        RECORDER_SEGMENT_TZ_SIZE + 8 + 8 + 4 + 4,
    SEGMENT_FRAME_HEADER_SIZE = 4 + 4 + 4 + 4,
    SEGMENT_FOOTER_BODY_SIZE = 4 + 8 + 8 + 8 + 4,
    SEGMENT_FOOTER_TRAILER_SIZE = 4 + 8
};

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
                         const void *dict_bytes, size_t dict_len)
{
    unsigned char buf[SEGMENT_HEADER_FIXED_SIZE];
    uint32_t crc;

    if (dict_len > UINT32_MAX) {
        errno = EOVERFLOW;
        return -1;
    }

    memcpy(buf, RECORDER_SEGMENT_MAGIC, 8);
    write_u32_le(buf + 8, RECORDER_SEGMENT_VERSION);
    write_u32_le(buf + 12, SEGMENT_HEADER_FIXED_SIZE);
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
    write_u32_le(buf + 148, crc);

    if (write_all(fp, buf, sizeof(buf)) != 0) {
        return -1;
    }
    if (dict_len != 0 && write_all(fp, dict_bytes, dict_len) != 0) {
        return -1;
    }
    return 0;
}

int segment_write_frame(FILE *fp, uint32_t flags,
                        const void *payload, uint32_t stored_len,
                        uint32_t uncompressed_len)
{
    unsigned char header[SEGMENT_FRAME_HEADER_SIZE];
    unsigned char crc_buf[4];
    uint32_t crc;

    write_u32_le(header + 0, flags);
    write_u32_le(header + 4, stored_len);
    write_u32_le(header + 8, uncompressed_len);
    write_u32_le(header + 12, SEGMENT_FRAME_HEADER_SIZE + stored_len + 4);

    crc = recorder_crc32(header, sizeof(header));
    crc ^= recorder_crc32(payload, stored_len);
    write_u32_le(crc_buf, crc);

    if (write_all(fp, header, sizeof(header)) != 0 ||
        write_all(fp, payload, stored_len) != 0 ||
        write_all(fp, crc_buf, sizeof(crc_buf)) != 0) {
        return -1;
    }
    return 0;
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
    write_u64_le(buf + 4, footer->entry_count);
    write_u64_le(buf + 12, footer->last_realtime_ts);
    write_u64_le(buf + 20, footer->last_monotonic_ts);
    write_u32_le(buf + 28, 0);
    write_u32_le(buf + 32, RECORDER_SEGMENT_VERSION);
    memcpy(buf + 36, RECORDER_SEGMENT_FOOTER_MAGIC, 8);
    crc = recorder_crc32(buf, sizeof(buf));
    write_u32_le(buf + 28, crc);
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
        *chunk_out = (void *)payload;
        *chunk_size_out = frame->stored_len;
        return 0;
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

int segment_read_header(const void *buf, size_t size,
                        SegmentHeader *header, size_t *offset_out)
{
    uint32_t header_size;
    uint32_t crc;

    if (size < SEGMENT_HEADER_FIXED_SIZE) {
        return -1;
    }
    if (memcmp(buf, RECORDER_SEGMENT_MAGIC, 8) != 0) {
        return -1;
    }
    if (read_u32_le((const unsigned char *)buf + 8) != RECORDER_SEGMENT_VERSION) {
        return -1;
    }
    header_size = read_u32_le((const unsigned char *)buf + 12);
    if (header_size != SEGMENT_HEADER_FIXED_SIZE) {
        return -1;
    }
    crc = read_u32_le((const unsigned char *)buf + 148);
    if (crc != recorder_crc32(buf, 148)) {
        return -1;
    }

    memset(header, 0, sizeof(*header));
    header->flags = read_u32_le((const unsigned char *)buf + 16);
    header->segment_seq = read_u64_le((const unsigned char *)buf + 20);
    header->boot_seq = read_u32_le((const unsigned char *)buf + 28);
    memcpy(header->boot_id, (const unsigned char *)buf + 32, RECORDER_BOOT_ID_SIZE);
    header->boot_id[RECORDER_BOOT_ID_SIZE] = '\0';
    memcpy(header->timezone, (const unsigned char *)buf + 64, RECORDER_SEGMENT_TZ_SIZE - 1);
    header->timezone[RECORDER_SEGMENT_TZ_SIZE - 1] = '\0';
    header->first_realtime_ts = read_u64_le((const unsigned char *)buf + 128);
    header->first_monotonic_ts = read_u64_le((const unsigned char *)buf + 136);
    header->dict_len = read_u32_le((const unsigned char *)buf + 144);
    if (size < SEGMENT_HEADER_FIXED_SIZE + header->dict_len) {
        return -1;
    }
    *offset_out = SEGMENT_HEADER_FIXED_SIZE + header->dict_len;
    return 0;
}

static int segment_scan_impl(const void *buf, size_t size, segment_frame_cb cb,
                             void *ctx, SegmentHeader *header_out,
                             SegmentFooter *footer_out, size_t *committed_end_out)
{
    SegmentHeader header;
    size_t offset = 0;
    size_t committed_end;
    SegmentFooter footer;
    const unsigned char *dict_bytes = NULL;

    if (segment_read_header(buf, size, &header, &offset) != 0) {
        return -1;
    }
    if (header.dict_len != 0) {
        dict_bytes = (const unsigned char *)buf + SEGMENT_HEADER_FIXED_SIZE;
    }
    committed_end = offset;
    memset(&footer, 0, sizeof(footer));

    while (offset + SEGMENT_FOOTER_BODY_SIZE + SEGMENT_FOOTER_TRAILER_SIZE <= size) {
        const unsigned char *p = (const unsigned char *)buf + offset;
        uint32_t total_len;
        uint32_t stored_crc;
        SegmentFrameInfo frame;

        if (memcmp(p + 36, RECORDER_SEGMENT_FOOTER_MAGIC, 8) == 0 &&
            read_u32_le(p + 32) == RECORDER_SEGMENT_VERSION) {
            uint32_t expect_crc = read_u32_le(p + 28);
            unsigned char tmp[SEGMENT_FOOTER_BODY_SIZE + SEGMENT_FOOTER_TRAILER_SIZE];

            memcpy(tmp, p, sizeof(tmp));
            write_u32_le(tmp + 28, 0);
            if (expect_crc == recorder_crc32(tmp, sizeof(tmp))) {
                footer.footer_flags = read_u32_le(p + 0);
                footer.entry_count = read_u64_le(p + 4);
                footer.last_realtime_ts = read_u64_le(p + 12);
                footer.last_monotonic_ts = read_u64_le(p + 20);
                committed_end = offset + sizeof(tmp);
                offset = committed_end;
                break;
            }
        }

        if (offset + SEGMENT_FRAME_HEADER_SIZE + 4 > size) {
            break;
        }
        frame.flags = read_u32_le(p + 0);
        frame.stored_len = read_u32_le(p + 4);
        frame.uncompressed_len = read_u32_le(p + 8);
        total_len = read_u32_le(p + 12);
        frame.file_offset = offset;
        frame.frame_len = total_len;
        if (total_len != SEGMENT_FRAME_HEADER_SIZE + frame.stored_len + 4) {
            break;
        }
        if (offset + total_len > size) {
            break;
        }
        stored_crc = read_u32_le(p + SEGMENT_FRAME_HEADER_SIZE + frame.stored_len);
        {
            uint32_t calc_crc = recorder_crc32(p, SEGMENT_FRAME_HEADER_SIZE) ^
                                recorder_crc32(p + SEGMENT_FRAME_HEADER_SIZE,
                                               frame.stored_len);
            if (stored_crc != calc_crc) {
                break;
            }
        }
        if (cb) {
            const void *payload = p + SEGMENT_FRAME_HEADER_SIZE;
            void *chunk_buf;
            size_t chunk_size;
            int drv = decompress_payload(&header, dict_bytes, &frame, payload,
                                         &chunk_buf, &chunk_size);
            int cb_rv;

            if (drv < 0) {
                break;
            }
            if (journal_Chunk_verify_as_root(chunk_buf, chunk_size) != flatcc_verify_ok) {
                if (drv > 0) {
                    free(chunk_buf);
                }
                break;
            }
            cb_rv = cb(&header, &frame, chunk_buf, chunk_size, ctx);
            if (drv > 0) {
                free(chunk_buf);
            }
            if (cb_rv != 0) {
                return cb_rv;
            }
        }
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
    return 0;
}

int segment_scan_buffer(const void *buf, size_t size, segment_frame_cb cb,
                        void *ctx, SegmentHeader *header_out,
                        SegmentFooter *footer_out, size_t *committed_end_out)
{
    return segment_scan_impl(buf, size, cb, ctx, header_out, footer_out,
                             committed_end_out);
}

int segment_scan_path(const char *path, segment_frame_cb cb, void *ctx,
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

    rv = segment_scan_impl(map, (size_t)st.st_size, cb, ctx, header_out,
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
