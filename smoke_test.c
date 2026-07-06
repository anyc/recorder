#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <flatcc/flatcc_builder.h>

#include "recorder_builder.h"
#include "segment.h"

typedef struct {
    int seen;
} SmokeContext;

static int check_frame(const SegmentHeader *header,
                       const SegmentFrameInfo *frame,
                       const void *chunk_buf, size_t chunk_size,
                       void *ctx)
{
    SmokeContext *sc = ctx;
    journal_Chunk_table_t chunk = journal_Chunk_as_root(chunk_buf);
    flatbuffers_uint32_vec_t entries = journal_Chunk_entries(chunk);
    journal_Entry_table_t entry;

    (void)frame;
    (void)chunk_size;

    if (strcmp(header->boot_id, "boot-a") != 0 || strcmp(header->timezone, "+0000") != 0) {
        fprintf(stderr, "smoke: bad segment header\n");
        return -1;
    }
    if (flatbuffers_uint32_vec_len(entries) != 1) {
        fprintf(stderr, "smoke: bad entry count\n");
        return -1;
    }
    entry = journal_Entry_vec_at(entries, 0);
    if (strcmp(journal_Entry_message(entry), "hello smoke") != 0 ||
        strcmp(journal_Entry_unit(entry), "smoke.service") != 0 ||
        journal_Entry_priority(entry) != 5) {
        fprintf(stderr, "smoke: bad entry payload\n");
        return -1;
    }
    sc->seen++;
    return 0;
}

int main(void)
{
    flatcc_builder_t B;
    flatbuffers_string_ref_t message_ref;
    flatbuffers_string_ref_t unit_ref;
    journal_Entry_ref_t entry_ref;
    journal_Entry_vec_ref_t entries_ref;
    void *chunk_buf = NULL;
    size_t chunk_size_raw;
    FILE *fp = NULL;
    SegmentHeader header;
    SegmentFooter footer;
    SmokeContext ctx;
    char path[] = "/tmp/recorder-segment-smoke-XXXXXX";
    int fd;
    size_t committed_end = 0;

    fd = mkstemp(path);
    if (fd < 0) {
        perror("mkstemps");
        return 1;
    }
    fp = fdopen(fd, "wb");
    if (!fp) {
        perror("fdopen");
        close(fd);
        unlink(path);
        return 1;
    }

    memset(&header, 0, sizeof(header));
    header.segment_seq = 7;
    header.boot_seq = 3;
    strcpy(header.boot_id, "boot-a");
    strcpy(header.timezone, "+0000");
    header.first_realtime_ts = 1234;
    header.first_monotonic_ts = 5678;
    if (segment_write_header(fp, &header, NULL, 0) != 0) {
        fprintf(stderr, "smoke: write header failed\n");
        fclose(fp);
        unlink(path);
        return 1;
    }

    flatcc_builder_init(&B);
    message_ref = flatbuffers_string_create_str(&B, "hello smoke");
    unit_ref = flatbuffers_string_create_str(&B, "smoke.service");

    journal_Entry_start(&B);
    journal_Entry_realtime_ts_add(&B, 1234);
    journal_Entry_monotonic_ts_add(&B, 5678);
    journal_Entry_priority_add(&B, 5);
    journal_Entry_message_add(&B, message_ref);
    journal_Entry_unit_add(&B, unit_ref);
    entry_ref = journal_Entry_end(&B);

    entries_ref = journal_Entry_vec_create(&B, &entry_ref, 1);
    if (!entries_ref || !journal_Chunk_create_as_root(&B, entries_ref)) {
        fprintf(stderr, "smoke: build chunk failed\n");
        fclose(fp);
        unlink(path);
        return 1;
    }
    chunk_buf = flatcc_builder_finalize_buffer(&B, &chunk_size_raw);
    if (!chunk_buf) {
        fprintf(stderr, "smoke: finalize failed\n");
        fclose(fp);
        unlink(path);
        return 1;
    }
    if (segment_write_frame(fp, 0, chunk_buf, (uint32_t)chunk_size_raw, (uint32_t)chunk_size_raw) != 0) {
        fprintf(stderr, "smoke: write frame failed\n");
        free(chunk_buf);
        fclose(fp);
        unlink(path);
        return 1;
    }
    memset(&footer, 0, sizeof(footer));
    footer.entry_count = 1;
    footer.last_realtime_ts = 1234;
    footer.last_monotonic_ts = 5678;
    if (segment_write_footer(fp, &footer) != 0) {
        fprintf(stderr, "smoke: write footer failed\n");
        free(chunk_buf);
        fclose(fp);
        unlink(path);
        return 1;
    }
    free(chunk_buf);
    flatcc_builder_clear(&B);
    fclose(fp);

    ctx.seen = 0;
    if (segment_scan_path(path, check_frame, &ctx, &header, &footer, &committed_end) != 0) {
        fprintf(stderr, "smoke: scan failed\n");
        unlink(path);
        return 1;
    }
    if (ctx.seen != 1 || footer.entry_count != 1 || committed_end == 0) {
        fprintf(stderr, "smoke: wrong scan result\n");
        unlink(path);
        return 1;
    }
    unlink(path);
    printf("smoke ok\n");
    return 0;
}
