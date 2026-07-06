#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "recorder_reader.h"
#include "segment.h"

typedef struct {
    char path[512];
    uint64_t segment_seq;
} SegmentPath;

typedef struct {
    size_t chunk_index;
} PrintContext;

static int valid_group_name(const char *name)
{
    size_t i;

    if (!name || !name[0] || strcmp(name, "state") == 0) {
        return 0;
    }
    for (i = 0; name[i]; i++) {
        unsigned char ch = (unsigned char)name[i];
        if (!((ch >= 'a' && ch <= 'z') ||
              (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') ||
              ch == '_' || ch == '-')) {
            return 0;
        }
    }
    return 1;
}

static int segment_seq_from_name(const char *name, uint64_t *seq_out)
{
    char *end = NULL;
    unsigned long long value;

    value = strtoull(name, &end, 10);
    if (!end || strcmp(end, ".seg") != 0) {
        return -1;
    }
    *seq_out = value;
    return 0;
}

static int print_frame(const SegmentHeader *header,
                       const SegmentFrameInfo *frame,
                       const void *chunk_buf, size_t chunk_size,
                       void *ctx)
{
    PrintContext *pc = ctx;
    journal_Chunk_table_t chunk = journal_Chunk_as_root(chunk_buf);
    flatbuffers_uint32_vec_t entries = journal_Chunk_entries(chunk);
    size_t n = flatbuffers_uint32_vec_len(entries);
    size_t i;

    (void)frame;
    (void)chunk_size;

    printf("segment seq=%llu boot_seq=%u boot_id=%s timezone=%s\n",
           (unsigned long long)header->segment_seq,
           header->boot_seq,
           header->boot_id,
           header->timezone);
    printf("chunk %zu: %zu entries\n", pc->chunk_index, n);
    for (i = 0; i < n; i++) {
        journal_Entry_table_t e = journal_Entry_vec_at(entries, i);

        printf("Entry %zu:\n", i);
        printf("  priority=%u pid=%u uid=%u gid=%u errno=%u\n",
               journal_Entry_priority(e),
               journal_Entry_pid(e),
               journal_Entry_uid(e),
               journal_Entry_gid(e),
               journal_Entry_errno(e));
        printf("  realtime_ts=%llu monotonic_ts=%llu\n",
               (unsigned long long)journal_Entry_realtime_ts(e),
               (unsigned long long)journal_Entry_monotonic_ts(e));
        printf("  message=%s\n", journal_Entry_message(e) ? journal_Entry_message(e) : "(null)");
        printf("  message_id=%s\n", journal_Entry_message_id(e) ? journal_Entry_message_id(e) : "(null)");
        printf("  unit=%s\n", journal_Entry_unit(e) ? journal_Entry_unit(e) : "(null)");
        printf("  hostname=%s\n", journal_Entry_hostname(e) ? journal_Entry_hostname(e) : "(null)");
        printf("  comm=%s\n", journal_Entry_comm(e) ? journal_Entry_comm(e) : "(null)");
        printf("  exe=%s\n", journal_Entry_exe(e) ? journal_Entry_exe(e) : "(null)");
    }
    pc->chunk_index++;
    return 0;
}

static int scan_segment_file(const char *path)
{
    SegmentHeader header;
    SegmentFooter footer;
    PrintContext ctx;
    size_t committed_end = 0;

    ctx.chunk_index = 0;
    if (segment_scan_path(path, print_frame, &ctx, &header, &footer, &committed_end) != 0) {
        fprintf(stderr, "player: failed to scan %s\n", path);
        return -1;
    }

    printf("footer: flags=%u entries=%llu last_realtime=%llu last_monotonic=%llu committed_end=%zu\n",
           footer.footer_flags,
           (unsigned long long)footer.entry_count,
           (unsigned long long)footer.last_realtime_ts,
           (unsigned long long)footer.last_monotonic_ts,
           committed_end);
    return 0;
}

static int add_segment_file(SegmentPath **items, size_t *count, size_t *cap,
                            const char *path, uint64_t segment_seq)
{
    SegmentPath *tmp;

    if (*count == *cap) {
        size_t new_cap = *cap ? (*cap * 2) : 32;
        tmp = realloc(*items, new_cap * sizeof(**items));
        if (!tmp) {
            return -1;
        }
        *items = tmp;
        *cap = new_cap;
    }
    strncpy((*items)[*count].path, path, sizeof((*items)[*count].path) - 1);
    (*items)[*count].path[sizeof((*items)[*count].path) - 1] = '\0';
    (*items)[*count].segment_seq = segment_seq;
    (*count)++;
    return 0;
}

static void sort_segment_files(SegmentPath *items, size_t count)
{
    size_t i;
    size_t j;

    for (i = 0; i < count; i++) {
        for (j = i + 1; j < count; j++) {
            if (items[j].segment_seq < items[i].segment_seq) {
                SegmentPath tmp = items[i];
                items[i] = items[j];
                items[j] = tmp;
            }
        }
    }
}

static int collect_segments_in_dir(const char *dir_path, SegmentPath **items,
                                   size_t *count, size_t *cap)
{
    DIR *dir = opendir(dir_path);
    struct dirent *de;

    if (!dir) {
        return -1;
    }
    while ((de = readdir(dir)) != NULL) {
        uint64_t seq;
        char path[512];

        if (segment_seq_from_name(de->d_name, &seq) != 0) {
            continue;
        }
        snprintf(path, sizeof(path), "%s/%s", dir_path, de->d_name);
        if (add_segment_file(items, count, cap, path, seq) != 0) {
            closedir(dir);
            return -1;
        }
    }
    closedir(dir);
    return 0;
}

static int scan_log_root(const char *root_path)
{
    struct stat st;
    DIR *dir;
    struct dirent *de;
    SegmentPath *items = NULL;
    size_t count = 0;
    size_t cap = 0;
    size_t i;
    int rc = 0;

    if (stat(root_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "player: %s is not a directory\n", root_path);
        return 1;
    }
    dir = opendir(root_path);
    if (!dir) {
        perror("opendir");
        return 1;
    }
    while ((de = readdir(dir)) != NULL) {
        char path[512];
        struct stat child_st;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }
        snprintf(path, sizeof(path), "%s/%s", root_path, de->d_name);
        if (stat(path, &child_st) != 0) {
            continue;
        }
        if (S_ISREG(child_st.st_mode)) {
            uint64_t seq;

            if (segment_seq_from_name(de->d_name, &seq) == 0 &&
                add_segment_file(&items, &count, &cap, path, seq) != 0) {
                rc = 1;
                break;
            }
        } else if (S_ISDIR(child_st.st_mode) && valid_group_name(de->d_name)) {
            if (collect_segments_in_dir(path, &items, &count, &cap) != 0) {
                rc = 1;
                break;
            }
        }
    }
    closedir(dir);
    if (rc != 0) {
        free(items);
        return rc;
    }
    sort_segment_files(items, count);
    for (i = 0; i < count; i++) {
        if (scan_segment_file(items[i].path) != 0) {
            free(items);
            return 1;
        }
    }
    free(items);
    return 0;
}

int main(int argc, char **argv)
{
    struct stat st;

    if (argc < 2) {
        fprintf(stderr, "usage: %s file.seg|log_dir\n", argv[0]);
        return 1;
    }

    if (stat(argv[1], &st) != 0) {
        perror("stat");
        return 1;
    }
    if (S_ISDIR(st.st_mode)) {
        return scan_log_root(argv[1]);
    }
    return scan_segment_file(argv[1]) == 0 ? 0 : 1;
}
