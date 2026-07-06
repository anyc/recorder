#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "helper.h"
#include "index.h"
#include "segment.h"

#define RECORDER_INDEX_MAGIC "RECIDX01"
#define RECORDER_INDEX_VERSION 1u
#define RECORDER_SERVICE_HASH_SLOTS 4u
#define RECORDER_SERVICE_HASH_BYTES (RECORDER_SERVICE_HASH_SLOTS * sizeof(uint64_t))

typedef struct {
    FILE *fp;
} IndexBuildContext;

static uint64_t fnv1a64(const char *s)
{
    uint64_t hash = 1469598103934665603ull;

    while (*s) {
        hash ^= (unsigned char)*s++;
        hash *= 1099511628211ull;
    }
    return hash;
}

static void store_u64(FILE *fp, uint64_t value)
{
    unsigned char buf[8];
    write_u64_le(buf, value);
    fwrite(buf, 1, sizeof(buf), fp);
}

static void store_u32(FILE *fp, uint32_t value)
{
    unsigned char buf[4];
    write_u32_le(buf, value);
    fwrite(buf, 1, sizeof(buf), fp);
}

static int write_index_frame(const SegmentHeader *header,
                             const SegmentFrameInfo *frame,
                             const void *chunk_buf, size_t chunk_size,
                             void *ctx)
{
    IndexBuildContext *ib = ctx;
    journal_Chunk_table_t chunk = journal_Chunk_as_root(chunk_buf);
    flatbuffers_uint32_vec_t entries = journal_Chunk_entries(chunk);
    size_t n = flatbuffers_uint32_vec_len(entries);
    size_t i;
    uint64_t min_rt = 0, max_rt = 0, min_mono = 0, max_mono = 0;
    uint8_t priority = 0;
    uint8_t service_kind = 1;
    uint8_t overflow = 0;
    uint64_t service_hashes[RECORDER_SERVICE_HASH_SLOTS] = {0};
    size_t service_count = 0;

    (void)header;
    (void)chunk_size;

    for (i = 0; i < n; i++) {
        journal_Entry_table_t e = journal_Entry_vec_at(entries, i);
        uint64_t rt = journal_Entry_realtime_ts(e);
        uint64_t mono = journal_Entry_monotonic_ts(e);
        const char *unit = journal_Entry_unit(e);
        size_t j;
        int seen = 0;

        if (i == 0 || rt < min_rt) min_rt = rt;
        if (i == 0 || rt > max_rt) max_rt = rt;
        if (i == 0 || mono < min_mono) min_mono = mono;
        if (i == 0 || mono > max_mono) max_mono = mono;
        priority = journal_Entry_priority(e);
        if (!unit) {
            continue;
        }
        {
            uint64_t hash = fnv1a64(unit);
            for (j = 0; j < service_count; j++) {
                if (service_hashes[j] == hash) {
                    seen = 1;
                    break;
                }
            }
            if (!seen) {
                if (service_count < RECORDER_SERVICE_HASH_SLOTS) {
                    service_hashes[service_count++] = hash;
                } else {
                    overflow = 1;
                }
            }
        }
    }

    store_u64(ib->fp, frame->file_offset);
    store_u32(ib->fp, frame->frame_len);
    store_u64(ib->fp, min_rt);
    store_u64(ib->fp, max_rt);
    store_u64(ib->fp, min_mono);
    store_u64(ib->fp, max_mono);
    fputc(priority, ib->fp);
    store_u32(ib->fp, (uint32_t)n);
    fputc(service_kind, ib->fp);
    fwrite(service_hashes, 1, RECORDER_SERVICE_HASH_BYTES, ib->fp);
    fputc(overflow, ib->fp);
    return ferror(ib->fp) ? -1 : 0;
}

int index_rebuild_for_segment(const char *segment_path, const char *index_path)
{
    char tmp_path[512];
    FILE *fp;
    SegmentHeader header;
    SegmentFooter footer;
    unsigned char head[8 + 4 + 8 + 8 + 8];
    IndexBuildContext ctx;
    int rc = -1;
    size_t committed_end = 0;

    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", index_path);
    fp = fopen(tmp_path, "wb");
    if (!fp) {
        return -1;
    }
    if (segment_scan_path(segment_path, NULL, NULL, &header, &footer, &committed_end) != 0) {
        fclose(fp);
        unlink(tmp_path);
        return -1;
    }
    memcpy(head, RECORDER_INDEX_MAGIC, 8);
    write_u32_le(head + 8, RECORDER_INDEX_VERSION);
    write_u64_le(head + 12, header.segment_seq);
    write_u64_le(head + 20, (uint64_t)footer.entry_count);
    write_u64_le(head + 28, (uint64_t)committed_end);
    if (fwrite(head, 1, sizeof(head), fp) != sizeof(head)) {
        fclose(fp);
        unlink(tmp_path);
        return -1;
    }
    ctx.fp = fp;
    if (segment_scan_path(segment_path, write_index_frame, &ctx, NULL, NULL, NULL) != 0) {
        fclose(fp);
        unlink(tmp_path);
        return -1;
    }
    if (fflush(fp) != 0 || fsync(fileno(fp)) != 0) {
        fclose(fp);
        unlink(tmp_path);
        return -1;
    }
    fclose(fp);
    rc = rename(tmp_path, index_path);
    if (rc != 0) {
        unlink(tmp_path);
        return -1;
    }
    return 0;
}
