#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <jansson.h>
#include <limits.h>
#include <stdarg.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <flatcc/flatcc_builder.h>
#include <systemd/sd-journal.h>
#include <zstd.h>

#include "helper.h"
#include "index.h"
#ifdef errno
#pragma push_macro("errno")
#undef errno
#define RECORDER_RESTORE_ERRNO 1
#endif
#include "recorder_builder.h"
#include "segment.h"
#ifdef RECORDER_RESTORE_ERRNO
#pragma pop_macro("errno")
#undef RECORDER_RESTORE_ERRNO
#endif

#define CHUNK_SIZE 512
#define MAX_BOOTS 256
#define DEFAULT_SEGMENT_MAX_BYTES (4ULL * 1024ULL * 1024ULL)
#define DEFAULT_SEGMENT_MAX_AGE_SEC 900u
#define DEFAULT_DURABLE_PRIORITY_MAX 3
#define DEFAULT_DURABILITY_FLUSH_FRAMES 32
#define DEFAULT_DURABILITY_FLUSH_INTERVAL_SEC 5
#define DEFAULT_LOG_MAX_BYTES (64ULL * 1024ULL * 1024ULL)
#define DEFAULT_COMPRESS_ENABLED 1
#define DEFAULT_COMPRESS_MIN_FRAME_BYTES 256
#define DEFAULT_COMPRESS_IF_SMALLER 1
#define DEFAULT_CAPTURE_MESSAGE_ID 1
#define DEFAULT_CAPTURE_UNIT 1
#define DEFAULT_CAPTURE_HOSTNAME 0
#define DEFAULT_CAPTURE_COMM 0
#define DEFAULT_CAPTURE_EXE 0
#define DEFAULT_CAPTURE_PID 0
#define DEFAULT_CAPTURE_UID 0
#define DEFAULT_CAPTURE_GID 0
#define JOURNAL_WAIT_USEC (5 * 1000000ULL)
#define TIME_DELTA_ROTATE_THRESHOLD_USEC (10000ULL)
#define MAX_PRIORITY_GROUPS 8
#define MAX_GROUP_NAME_LEN 63

typedef struct {
    char name[MAX_GROUP_NAME_LEN + 1];
    uint8_t priorities[8];
    size_t priority_count;
    uint8_t min_priority;
    int durable_per_frame;
    unsigned durability_flush_frames;
    unsigned durability_flush_interval_sec;
    const char *static_dict_path;
} PriorityGroup;

typedef struct {
    int capture_message_id;
    int capture_unit;
    int capture_hostname;
    int capture_comm;
    int capture_exe;
    int capture_pid;
    int capture_uid;
    int capture_gid;
    int durable_priority_max;
    unsigned durability_flush_frames;
    unsigned durability_flush_interval_sec;
    uint64_t log_max_bytes;
    uint64_t segment_max_bytes;
    unsigned segment_max_age_sec;
    int compress_enabled;
    unsigned compress_min_frame_bytes;
    int compress_if_smaller;
    char *static_dict_paths[8];
    PriorityGroup groups[MAX_PRIORITY_GROUPS];
    size_t group_count;
    int priority_to_group[8];
} RecorderConfig;

typedef struct {
    char id[RECORDER_BOOT_ID_SIZE + 1];
    uint32_t seq;
    uint64_t first_realtime_ts;
    uint64_t last_clean_realtime_ts;
} BootEntry;

typedef struct {
    BootEntry boots[MAX_BOOTS];
    uint32_t count;
} BootRegistry;

typedef struct {
    uint64_t realtime_ts;
    uint64_t monotonic_ts;
    uint32_t pid;
    uint32_t uid;
    uint32_t gid;
    uint32_t boot_seq;
    uint8_t priority;
    uint16_t errno_value;
    const char *boot_id;
    const char *message;
    const char *message_id;
    const char *hostname;
    const char *unit;
    const char *comm;
    const char *exe;
} LogEntry;

typedef struct {
    uint8_t group_index;
    FILE *fp;
    int open;
    char path[512];
    char tmp_path[512];
    char group_name[MAX_GROUP_NAME_LEN + 1];
    char boot_id[RECORDER_BOOT_ID_SIZE + 1];
    char timezone[RECORDER_SEGMENT_TZ_SIZE];
    uint32_t boot_seq;
    uint64_t segment_seq;
    uint64_t bytes_written;
    uint64_t entry_count;
    uint64_t first_realtime_ts;
    uint64_t first_monotonic_ts;
    uint64_t last_realtime_ts;
    uint64_t last_monotonic_ts;
    int64_t initial_time_delta;
    time_t opened_mono_sec;
    time_t last_sync_mono_sec;
    unsigned unsynced_frames;
    int compress_enabled;
    unsigned compress_min_frame_bytes;
    int compress_if_smaller;
    int durable_per_frame;
    unsigned durability_flush_frames;
    unsigned durability_flush_interval_sec;
    void *dict_bytes;
    size_t dict_len;
    flatcc_builder_t builder;
    int builder_live;
    journal_Entry_ref_t entries[CHUNK_SIZE];
    size_t count;
} PriorityWriter;

typedef struct {
    sd_journal *j;
    RecorderConfig config;
    BootRegistry boots;
    uint64_t next_segment_seq;
    int verbose;
    int current_entry_pending;
    PriorityWriter writers[MAX_PRIORITY_GROUPS];
} Recorder;

typedef struct {
    char path[512];
    char dir_name[MAX_GROUP_NAME_LEN + 1];
    uint8_t min_priority;
    uint64_t segment_seq;
    uint64_t size;
} RetainedFile;

typedef enum {
    ROTATE_REASON_NONE = 0,
    ROTATE_REASON_BOOT_ID,
    ROTATE_REASON_TIMEZONE,
    ROTATE_REASON_TIME_DELTA,
    ROTATE_REASON_AGE,
    ROTATE_REASON_SIZE,
} RotateReason;

typedef struct {
    RotateReason reason;
    int64_t delta_diff;
} RotateDecision;

static volatile sig_atomic_t g_shutdown = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_shutdown = 1;
}

static void recorder_config_init(RecorderConfig *cfg)
{
    size_t i;

    memset(cfg, 0, sizeof(*cfg));
    cfg->capture_message_id = DEFAULT_CAPTURE_MESSAGE_ID;
    cfg->capture_unit = DEFAULT_CAPTURE_UNIT;
    cfg->capture_hostname = DEFAULT_CAPTURE_HOSTNAME;
    cfg->capture_comm = DEFAULT_CAPTURE_COMM;
    cfg->capture_exe = DEFAULT_CAPTURE_EXE;
    cfg->capture_pid = DEFAULT_CAPTURE_PID;
    cfg->capture_uid = DEFAULT_CAPTURE_UID;
    cfg->capture_gid = DEFAULT_CAPTURE_GID;
    cfg->durable_priority_max = DEFAULT_DURABLE_PRIORITY_MAX;
    cfg->durability_flush_frames = DEFAULT_DURABILITY_FLUSH_FRAMES;
    cfg->durability_flush_interval_sec = DEFAULT_DURABILITY_FLUSH_INTERVAL_SEC;
    cfg->log_max_bytes = DEFAULT_LOG_MAX_BYTES;
    cfg->segment_max_bytes = DEFAULT_SEGMENT_MAX_BYTES;
    cfg->segment_max_age_sec = DEFAULT_SEGMENT_MAX_AGE_SEC;
    cfg->compress_enabled = DEFAULT_COMPRESS_ENABLED;
    cfg->compress_min_frame_bytes = DEFAULT_COMPRESS_MIN_FRAME_BYTES;
    cfg->compress_if_smaller = DEFAULT_COMPRESS_IF_SMALLER;
    for (i = 0; i < 8; i++) {
        snprintf(cfg->groups[i].name, sizeof(cfg->groups[i].name), "p%zu", i);
        cfg->groups[i].priorities[0] = (uint8_t)i;
        cfg->groups[i].priority_count = 1;
        cfg->groups[i].min_priority = (uint8_t)i;
        cfg->priority_to_group[i] = (int)i;
    }
    cfg->group_count = 8;
}

static void recorder_config_destroy(RecorderConfig *cfg)
{
    size_t i;

    for (i = 0; i < 8; i++) {
        free(cfg->static_dict_paths[i]);
        cfg->static_dict_paths[i] = NULL;
    }
}

static const char *recorder_config_path(void)
{
    const char *path = getenv("RECORDER_CONFIG");
    return (path && path[0]) ? path : RECORDER_CONFIG_PATH;
}

static void recorder_verbose_log(const Recorder *r, const char *fmt, ...)
{
    va_list ap;

    if (!r || !r->verbose) {
        return;
    }
    fprintf(stderr, "recorder: ");
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static const char *rotate_reason_text(RotateReason reason)
{
    switch (reason) {
    case ROTATE_REASON_BOOT_ID:
        return "boot_id changed";
    case ROTATE_REASON_TIMEZONE:
        return "timezone changed";
    case ROTATE_REASON_TIME_DELTA:
        return "realtime/monotonic delta changed beyond threshold";
    case ROTATE_REASON_AGE:
        return "segment age limit reached";
    case ROTATE_REASON_SIZE:
        return "segment size limit reached";
    case ROTATE_REASON_NONE:
    default:
        return "none";
    }
}

static void current_timezone_string(char out[RECORDER_SEGMENT_TZ_SIZE]);
static time_t monotonic_now_sec(void);
static uint64_t recorder_segment_limit(const Recorder *r);

static RotateDecision writer_should_rotate(const Recorder *r, const PriorityWriter *w,
                                         const LogEntry *entry)
{
    char timezone[RECORDER_SEGMENT_TZ_SIZE];
    int64_t current_delta;
    RotateDecision decision;

    decision.reason = ROTATE_REASON_NONE;
    decision.delta_diff = 0;

    if (!w->open) {
        return decision;
    }
    if (w->boot_id[0] != '\0' && entry->boot_id && entry->boot_id[0] != '\0' &&
        strcmp(w->boot_id, entry->boot_id) != 0) {
        decision.reason = ROTATE_REASON_BOOT_ID;
        return decision;
    }
    current_timezone_string(timezone);
    if (strcmp(w->timezone, timezone) != 0) {
        decision.reason = ROTATE_REASON_TIMEZONE;
        return decision;
    }
    current_delta = (int64_t)entry->realtime_ts - (int64_t)entry->monotonic_ts;
    decision.delta_diff = current_delta - w->initial_time_delta;
    if (llabs(decision.delta_diff) > (long long)TIME_DELTA_ROTATE_THRESHOLD_USEC) {
        decision.reason = ROTATE_REASON_TIME_DELTA;
        return decision;
    }
    if (r->config.segment_max_age_sec != 0 &&
        monotonic_now_sec() - w->opened_mono_sec >= (time_t)r->config.segment_max_age_sec) {
        decision.reason = ROTATE_REASON_AGE;
        return decision;
    }
    if (w->bytes_written >= recorder_segment_limit(r)) {
        decision.reason = ROTATE_REASON_SIZE;
        return decision;
    }
    return decision;
}

static char *slurp_file(const char *path, size_t *size_out)
{
    FILE *fp;
    long size_long;
    size_t size;
    char *buf;

    fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "recorder: fopen(%s): %m\n", path);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "recorder: fseek(%s): %m\n", path);
        fclose(fp);
        return NULL;
    }
    size_long = ftell(fp);
    if (size_long < 0) {
        fprintf(stderr, "recorder: ftell(%s): %m\n", path);
        fclose(fp);
        return NULL;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fprintf(stderr, "recorder: fseek(%s): %m\n", path);
        fclose(fp);
        return NULL;
    }
    size = (size_t)size_long;
    buf = malloc(size + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    if (size != 0 && fread(buf, 1, size, fp) != size) {
        fprintf(stderr, "recorder: fread(%s): %m\n", path);
        free(buf);
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    buf[size] = '\0';
    if (size_out) {
        *size_out = size;
    }
    return buf;
}

static char *strip_hash_comment_lines(const char *input, size_t len)
{
    char *out;
    size_t in = 0;
    size_t out_len = 0;

    out = malloc(len + 1);
    if (!out) {
        return NULL;
    }
    while (in < len) {
        size_t line_start = in;
        size_t line_end = in;
        size_t first = in;

        while (first < len && (input[first] == ' ' || input[first] == '\t')) {
            first++;
        }
        while (line_end < len && input[line_end] != '\n') {
            line_end++;
        }
        if (!(first < len && input[first] == '#')) {
            memcpy(out + out_len, input + line_start, line_end - line_start);
            out_len += line_end - line_start;
        }
        if (line_end < len) {
            out[out_len++] = '\n';
            line_end++;
        }
        in = line_end;
    }
    out[out_len] = '\0';
    return out;
}

static int json_get_bool_default(json_t *root, const char *key, int *dst)
{
    json_t *node = json_object_get(root, key);

    if (!node) {
        return 0;
    }
    if (!json_is_boolean(node)) {
        fprintf(stderr, "recorder: config key '%s' must be boolean\n", key);
        return -1;
    }
    *dst = json_is_true(node);
    return 0;
}

static int json_get_uint_default(json_t *root, const char *key, unsigned *dst)
{
    json_t *node = json_object_get(root, key);
    json_int_t value;

    if (!node) {
        return 0;
    }
    if (!json_is_integer(node)) {
        fprintf(stderr, "recorder: config key '%s' must be integer\n", key);
        return -1;
    }
    value = json_integer_value(node);
    if (value < 0 || value > UINT_MAX) {
        fprintf(stderr, "recorder: config key '%s' out of range\n", key);
        return -1;
    }
    *dst = (unsigned)value;
    return 0;
}

static int json_get_int_default(json_t *root, const char *key, int min_value,
                                int max_value, int *dst)
{
    json_t *node = json_object_get(root, key);
    json_int_t value;

    if (!node) {
        return 0;
    }
    if (!json_is_integer(node)) {
        fprintf(stderr, "recorder: config key '%s' must be integer\n", key);
        return -1;
    }
    value = json_integer_value(node);
    if (value < min_value || value > max_value) {
        fprintf(stderr, "recorder: config key '%s' out of range\n", key);
        return -1;
    }
    *dst = (int)value;
    return 0;
}

static int parse_size_string(const char *text, uint64_t *value_out)
{
    char *end = NULL;
    unsigned long long base;
    uint64_t scale = 1;

    errno = 0;
    base = strtoull(text, &end, 10);
    if (errno != 0 || end == text) {
        return -1;
    }
    if (*end != '\0') {
        if (end[1] != '\0') {
            return -1;
        }
        switch (toupper((unsigned char)*end)) {
        case 'K': scale = 1024ULL; break;
        case 'M': scale = 1024ULL * 1024ULL; break;
        case 'G': scale = 1024ULL * 1024ULL * 1024ULL; break;
        default: return -1;
        }
    }
    if (base > UINT64_MAX / scale) {
        return -1;
    }
    *value_out = (uint64_t)base * scale;
    return 0;
}

static int json_get_size_default(json_t *root, const char *key, uint64_t *dst)
{
    json_t *node = json_object_get(root, key);
    uint64_t value;

    if (!node) {
        return 0;
    }
    if (json_is_integer(node)) {
        json_int_t raw = json_integer_value(node);
        if (raw < 0) {
            fprintf(stderr, "recorder: config key '%s' must be non-negative\n", key);
            return -1;
        }
        *dst = (uint64_t)raw;
        return 0;
    }
    if (json_is_string(node)) {
        if (parse_size_string(json_string_value(node), &value) != 0) {
            fprintf(stderr, "recorder: config key '%s' has invalid size value\n", key);
            return -1;
        }
        *dst = value;
        return 0;
    }
    fprintf(stderr, "recorder: config key '%s' must be integer or size string\n", key);
    return -1;
}

static int json_get_static_dict_paths(json_t *root, RecorderConfig *cfg)
{
    json_t *node = json_object_get(root, "static_dict_paths");
    const char *key;
    json_t *value;

    if (!node) {
        return 0;
    }
    if (!json_is_object(node)) {
        fprintf(stderr, "recorder: config key 'static_dict_paths' must be an object\n");
        return -1;
    }
    json_object_foreach(node, key, value)
    {
        char *end = NULL;
        long prio;

        if (!json_is_string(value)) {
            fprintf(stderr, "recorder: static_dict_paths[%s] must be a string\n", key);
            return -1;
        }
        errno = 0;
        prio = strtol(key, &end, 10);
        if (errno != 0 || !end || *end != '\0' || prio < 0 || prio > 7) {
            fprintf(stderr, "recorder: static_dict_paths key '%s' must be 0..7\n", key);
            return -1;
        }
        free(cfg->static_dict_paths[prio]);
        cfg->static_dict_paths[prio] = strdup(json_string_value(value));
        if (!cfg->static_dict_paths[prio]) {
            return -1;
        }
    }
    return 0;
}

static int valid_group_name(const char *name)
{
    size_t i;

    if (!name || !name[0]) {
        return 0;
    }
    for (i = 0; name[i]; i++) {
        unsigned char ch = (unsigned char)name[i];

        if (!(isalnum(ch) || ch == '_' || ch == '-')) {
            return 0;
        }
    }
    return 1;
}

static int json_get_priority_groups(json_t *root, RecorderConfig *cfg)
{
    json_t *node = json_object_get(root, "priority_groups");
    size_t i;
    unsigned seen_mask = 0;

    if (!node) {
        return 0;
    }
    if (!json_is_array(node)) {
        fprintf(stderr, "recorder: config key 'priority_groups' must be an array\n");
        return -1;
    }
    if (json_array_size(node) == 0 || json_array_size(node) > MAX_PRIORITY_GROUPS) {
        fprintf(stderr, "recorder: priority_groups must have 1..%d entries\n", MAX_PRIORITY_GROUPS);
        return -1;
    }

    memset(cfg->groups, 0, sizeof(cfg->groups));
    for (i = 0; i < 8; i++) {
        cfg->priority_to_group[i] = -1;
    }
    cfg->group_count = json_array_size(node);

    for (i = 0; i < cfg->group_count; i++) {
        json_t *group = json_array_get(node, i);
        json_t *name = json_object_get(group, "name");
        json_t *priorities = json_object_get(group, "priorities");
        size_t j;

        if (!json_is_object(group) || !json_is_string(name) || !json_is_array(priorities)) {
            fprintf(stderr, "recorder: each priority_groups entry needs string 'name' and array 'priorities'\n");
            return -1;
        }
        if (!valid_group_name(json_string_value(name))) {
            fprintf(stderr, "recorder: invalid priority group name '%s'\n", json_string_value(name));
            return -1;
        }
        strncpy(cfg->groups[i].name, json_string_value(name), MAX_GROUP_NAME_LEN);
        cfg->groups[i].name[MAX_GROUP_NAME_LEN] = '\0';
        cfg->groups[i].min_priority = 255;

        for (j = 0; j < i; j++) {
            if (strcmp(cfg->groups[j].name, cfg->groups[i].name) == 0) {
                fprintf(stderr, "recorder: duplicate priority group name '%s'\n", cfg->groups[i].name);
                return -1;
            }
        }
        if (json_array_size(priorities) == 0 || json_array_size(priorities) > 8) {
            fprintf(stderr, "recorder: priority group '%s' must contain 1..8 priorities\n", cfg->groups[i].name);
            return -1;
        }
        for (j = 0; j < json_array_size(priorities); j++) {
            json_t *prio_node = json_array_get(priorities, j);
            json_int_t prio;

            if (!json_is_integer(prio_node)) {
                fprintf(stderr, "recorder: priority group '%s' priorities must be integers\n", cfg->groups[i].name);
                return -1;
            }
            prio = json_integer_value(prio_node);
            if (prio < 0 || prio > 7) {
                fprintf(stderr, "recorder: priority group '%s' contains invalid priority %" JSON_INTEGER_FORMAT "\n",
                        cfg->groups[i].name, prio);
                return -1;
            }
            if (seen_mask & (1u << prio)) {
                fprintf(stderr, "recorder: priority %" JSON_INTEGER_FORMAT " appears in more than one group\n", prio);
                return -1;
            }
            seen_mask |= 1u << prio;
            cfg->groups[i].priorities[cfg->groups[i].priority_count++] = (uint8_t)prio;
            if ((uint8_t)prio < cfg->groups[i].min_priority) {
                cfg->groups[i].min_priority = (uint8_t)prio;
            }
            cfg->priority_to_group[prio] = (int)i;
        }
    }

    if (seen_mask != 0xffu) {
        fprintf(stderr, "recorder: priority_groups must cover every priority 0..7 exactly once\n");
        return -1;
    }
    return 0;
}

static int recorder_config_load(RecorderConfig *cfg, const char *path)
{
    char *raw = NULL;
    char *stripped = NULL;
    size_t raw_len = 0;
    json_t *root = NULL;
    json_error_t err;
    int rc = -1;

    raw = slurp_file(path, &raw_len);
    if (!raw) {
        return -1;
    }
    stripped = strip_hash_comment_lines(raw, raw_len);
    if (!stripped) {
        goto out;
    }
    root = json_loads(stripped, 0, &err);
    if (!root) {
        fprintf(stderr, "recorder: invalid config %s:%d:%d: %s\n",
                path, err.line, err.column, err.text);
        goto out;
    }
    if (!json_is_object(root)) {
        fprintf(stderr, "recorder: config root must be a JSON object\n");
        goto out;
    }

    if (json_get_bool_default(root, "capture_message_id", &cfg->capture_message_id) != 0 ||
        json_get_bool_default(root, "capture_unit", &cfg->capture_unit) != 0 ||
        json_get_bool_default(root, "capture_hostname", &cfg->capture_hostname) != 0 ||
        json_get_bool_default(root, "capture_comm", &cfg->capture_comm) != 0 ||
        json_get_bool_default(root, "capture_exe", &cfg->capture_exe) != 0 ||
        json_get_bool_default(root, "capture_pid", &cfg->capture_pid) != 0 ||
        json_get_bool_default(root, "capture_uid", &cfg->capture_uid) != 0 ||
        json_get_bool_default(root, "capture_gid", &cfg->capture_gid) != 0 ||
        json_get_int_default(root, "durable_priority_max", -1, 7, &cfg->durable_priority_max) != 0 ||
        json_get_uint_default(root, "durability_flush_frames", &cfg->durability_flush_frames) != 0 ||
        json_get_uint_default(root, "durability_flush_interval_sec", &cfg->durability_flush_interval_sec) != 0 ||
        json_get_size_default(root, "log_max_bytes", &cfg->log_max_bytes) != 0 ||
        json_get_size_default(root, "segment_max_bytes", &cfg->segment_max_bytes) != 0 ||
        json_get_uint_default(root, "segment_max_age_sec", &cfg->segment_max_age_sec) != 0 ||
        json_get_bool_default(root, "compress_enabled", &cfg->compress_enabled) != 0 ||
        json_get_uint_default(root, "compress_min_frame_bytes", &cfg->compress_min_frame_bytes) != 0 ||
        json_get_bool_default(root, "compress_if_smaller", &cfg->compress_if_smaller) != 0 ||
        json_get_static_dict_paths(root, cfg) != 0 ||
        json_get_priority_groups(root, cfg) != 0) {
        goto out;
    }
    {
        size_t i;

        for (i = 0; i < 8; i++) {
            if (cfg->static_dict_paths[i] && access(cfg->static_dict_paths[i], R_OK) != 0) {
                fprintf(stderr, "recorder: static dictionary for priority %zu is not readable: %s\n",
                        i, cfg->static_dict_paths[i]);
                goto out;
            }
        }
        for (i = 0; i < cfg->group_count; i++) {
            size_t j;
            const char *dict_path = NULL;
            int durable_per_frame = 0;

            cfg->groups[i].durability_flush_frames = cfg->durability_flush_frames;
            cfg->groups[i].durability_flush_interval_sec = cfg->durability_flush_interval_sec;
            for (j = 0; j < cfg->groups[i].priority_count; j++) {
                uint8_t prio = cfg->groups[i].priorities[j];
                const char *candidate = cfg->static_dict_paths[prio];

                if (cfg->durable_priority_max >= 0 &&
                    prio <= (uint8_t)cfg->durable_priority_max) {
                    durable_per_frame = 1;
                }
                if (candidate) {
                    if (!dict_path) {
                        dict_path = candidate;
                    } else if (strcmp(dict_path, candidate) != 0) {
                        fprintf(stderr,
                                "recorder: priorities in group '%s' must share the same static dictionary path or none\n",
                                cfg->groups[i].name);
                        goto out;
                    }
                }
            }
            cfg->groups[i].durable_per_frame = durable_per_frame;
            cfg->groups[i].static_dict_path = dict_path;
        }
    }

    rc = 0;
out:
    json_decref(root);
    free(stripped);
    free(raw);
    return rc;
}

static const char *journal_get(sd_journal *j, const char *field)
{
    const void *data;
    size_t len;
    const char *eq;

    if (sd_journal_get_data(j, field, &data, &len) < 0) {
        return NULL;
    }
    eq = memchr(data, '=', len);
    return eq ? eq + 1 : NULL;
}

static uint64_t journal_get_u64(sd_journal *j, const char *field)
{
    const char *v = journal_get(j, field);
    return v ? strtoull(v, NULL, 10) : 0;
}

static uint32_t journal_get_u32(sd_journal *j, const char *field)
{
    return (uint32_t)journal_get_u64(j, field);
}

static const char *nonempty_or_null(const char *s)
{
    return (s && s[0] != '\0') ? s : NULL;
}

static uint16_t clamp_u16(uint64_t value)
{
    return value > UINT16_MAX ? UINT16_MAX : (uint16_t)value;
}

static void boot_registry_init(BootRegistry *r)
{
    r->count = 0;
}

static BootEntry *boot_registry_get(BootRegistry *r, const char *boot_id)
{
    uint32_t i;

    if (!boot_id) {
        return NULL;
    }
    for (i = 0; i < r->count; i++) {
        if (strncmp(r->boots[i].id, boot_id, RECORDER_BOOT_ID_SIZE) == 0) {
            return &r->boots[i];
        }
    }
    if (r->count >= MAX_BOOTS) {
        return &r->boots[r->count - 1];
    }
    strncpy(r->boots[r->count].id, boot_id, RECORDER_BOOT_ID_SIZE);
    r->boots[r->count].id[RECORDER_BOOT_ID_SIZE] = '\0';
    r->boots[r->count].seq = r->count;
    r->boots[r->count].first_realtime_ts = 0;
    r->boots[r->count].last_clean_realtime_ts = 0;
    r->count++;
    return &r->boots[r->count - 1];
}

static uint32_t boot_registry_seq(BootRegistry *r, const char *boot_id)
{
    BootEntry *boot = boot_registry_get(r, boot_id);
    return boot ? boot->seq : 0;
}

static void current_timezone_string(char out[RECORDER_SEGMENT_TZ_SIZE])
{
    time_t now = time(NULL);
    struct tm tmv;

    localtime_r(&now, &tmv);
    if (strftime(out, RECORDER_SEGMENT_TZ_SIZE, "%z", &tmv) == 0) {
        snprintf(out, RECORDER_SEGMENT_TZ_SIZE, "UTC");
    }
}

static time_t monotonic_now_sec(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

static int is_state_dir_name(const char *name)
{
    return strcmp(name, "state") == 0;
}

static int is_segment_dir_name(const char *name)
{
    return valid_group_name(name) && !is_state_dir_name(name);
}

static void build_segment_dir(char *buf, size_t bufsz, const char *dir_name)
{
    snprintf(buf, bufsz, LOG_DIR "/%s", dir_name);
}

static void build_state_segment_seq_path(char *buf, size_t bufsz)
{
    snprintf(buf, bufsz, LOG_DIR "/state/segment_seq");
}

static void build_state_boots_path(char *buf, size_t bufsz)
{
    snprintf(buf, bufsz, LOG_DIR "/state/boots");
}

static int atomic_write_text_file(const char *path, const char *text);
static int segment_seq_from_name(const char *name, uint64_t *seq_out);
static int boot_registry_rebuild_from_segments(BootRegistry *boots);
static int persist_boot_state(const BootRegistry *boots);
static void for_each_segment_dir(void (*fn)(const char *dir_name, void *ctx), void *ctx);

static void build_segment_path(char *buf, size_t bufsz, const char *dir_name,
                               uint64_t seq)
{
    char dir[256];

    build_segment_dir(dir, sizeof(dir), dir_name);
    snprintf(buf, bufsz, "%s/%" PRIu64 ".seg", dir, seq);
}

static void build_segment_tmp_path(char *buf, size_t bufsz, const char *dir_name,
                                   uint64_t seq)
{
    char dir[256];

    build_segment_dir(dir, sizeof(dir), dir_name);
    snprintf(buf, bufsz, "%s/%" PRIu64 ".seg.tmp", dir, seq);
}

static void build_index_path(char *buf, size_t bufsz, const char *dir_name,
                             uint64_t seq)
{
    char dir[256];

    build_segment_dir(dir, sizeof(dir), dir_name);
    snprintf(buf, bufsz, "%s/%" PRIu64 ".idx", dir, seq);
}

typedef struct {
    uint64_t max_seq;
    int found;
} ScanMaxCtx;

static void scan_existing_segment_seq_max_cb(const char *dir_name, void *ctx)
{
    ScanMaxCtx *scan = ctx;
    char dir_path[256];
    DIR *dir;
    struct dirent *de;

    build_segment_dir(dir_path, sizeof(dir_path), dir_name);
    dir = opendir(dir_path);
    if (!dir) {
        return;
    }
    while ((de = readdir(dir)) != NULL) {
        uint64_t seq;

        if (segment_seq_from_name(de->d_name, &seq) != 0) {
            continue;
        }
        if (!scan->found || seq > scan->max_seq) {
            scan->max_seq = seq;
            scan->found = 1;
        }
    }
    closedir(dir);
}

static uint64_t scan_existing_segment_seq_max(void)
{
    ScanMaxCtx ctx;

    memset(&ctx, 0, sizeof(ctx));
    for_each_segment_dir(scan_existing_segment_seq_max_cb, &ctx);
    return ctx.found ? ctx.max_seq : 0;
}

static int read_persisted_next_segment_seq(uint64_t *value_out)
{
    char path[512];
    char *raw;
    size_t raw_len = 0;
    char *end = NULL;
    unsigned long long value;

    build_state_segment_seq_path(path, sizeof(path));
    if (access(path, F_OK) != 0) {
        return -1;
    }
    raw = slurp_file(path, &raw_len);
    if (!raw) {
        return -1;
    }
    errno = 0;
    value = strtoull(raw, &end, 10);
    free(raw);
    if (errno != 0 || !end || (*end != '\0' && *end != '\n')) {
        return -1;
    }
    *value_out = value;
    return 0;
}

static int persist_next_segment_seq(uint64_t value)
{
    char path[512];
    char text[64];

    build_state_segment_seq_path(path, sizeof(path));
    snprintf(text, sizeof(text), "%" PRIu64 "\n", value);
    return atomic_write_text_file(path, text);
}

static int flush_and_sync_file(FILE *fp)
{
    if (fflush(fp) != 0) {
        return -1;
    }
    if (fsync(fileno(fp)) != 0) {
        return -1;
    }
    return 0;
}

static int atomic_write_text_file(const char *path, const char *text)
{
    char tmp_path[512];
    char dir_path[512];
    const char *slash;
    FILE *fp;

    slash = strrchr(path, '/');
    if (!slash) {
        return 0;
    }
    memcpy(dir_path, path, (size_t)(slash - path));
    dir_path[slash - path] = '\0';
    if (mkdir_p(dir_path) != 0) {
        return -1;
    }
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);
    fp = fopen(tmp_path, "wb");
    if (!fp) {
        return -1;
    }
    if (fwrite(text, 1, strlen(text), fp) != strlen(text) ||
        flush_and_sync_file(fp) != 0) {
        fclose(fp);
        unlink(tmp_path);
        return -1;
    }
    fclose(fp);
    if (rename(tmp_path, path) != 0) {
        unlink(tmp_path);
        return -1;
    }
    return fsync_dir_path(dir_path);
}

static void cleanup_segment_dir_cb(const char *dir_name, void *ctx)
{
    char dir_path[256];
    DIR *dir;
    struct dirent *de;
    int changed = 0;
    (void)ctx;

    build_segment_dir(dir_path, sizeof(dir_path), dir_name);
    dir = opendir(dir_path);
    if (!dir) {
        return;
    }
    while ((de = readdir(dir)) != NULL) {
        size_t len = strlen(de->d_name);

        if (len > 8 && strcmp(de->d_name + len - 8, ".seg.tmp") == 0) {
            char path[512];

            snprintf(path, sizeof(path), "%s/%s", dir_path, de->d_name);
            if (unlink(path) == 0) {
                changed = 1;
            }
        } else if (len > 8 && strcmp(de->d_name + len - 8, ".idx.tmp") == 0) {
            char path[512];

            snprintf(path, sizeof(path), "%s/%s", dir_path, de->d_name);
            if (unlink(path) == 0) {
                changed = 1;
            }
        }
    }
    closedir(dir);
    if (changed) {
        fsync_dir_path(dir_path);
    }
}

static void recover_segment_dir_cb(const char *dir_name, void *ctx)
{
    char dir_path[256];
    DIR *dir;
    struct dirent *de;
    int changed = 0;
    (void)ctx;

    build_segment_dir(dir_path, sizeof(dir_path), dir_name);
    dir = opendir(dir_path);
    if (!dir) {
        return;
    }
    while ((de = readdir(dir)) != NULL) {
        size_t len = strlen(de->d_name);
        char path[512];
        uint64_t seq = 0;
        SegmentHeader header;
        SegmentFooter footer;
        size_t committed_end = 0;
        struct stat st;

        if (len < 5 || strcmp(de->d_name + len - 4, ".seg") != 0) {
            continue;
        }
        segment_seq_from_name(de->d_name, &seq);
        snprintf(path, sizeof(path), "%s/%s", dir_path, de->d_name);
        if (stat(path, &st) != 0) {
            continue;
        }
        if (st.st_size == 0) {
            char idx_path[512];

            build_index_path(idx_path, sizeof(idx_path), dir_name, seq);
            unlink(idx_path);
            if (unlink(path) == 0) {
                changed = 1;
            }
            continue;
        }
        if (segment_scan_path(path, NULL, NULL, &header, &footer, &committed_end) != 0) {
            char idx_path[512];

            build_index_path(idx_path, sizeof(idx_path), dir_name, seq);
            unlink(idx_path);
            if (unlink(path) == 0) {
                changed = 1;
            }
            continue;
        }
        if ((off_t)committed_end < st.st_size) {
            if (truncate(path, (off_t)committed_end) == 0) {
                int fd = open(path, O_WRONLY);

                if (fd >= 0) {
                    fsync(fd);
                    close(fd);
                }
                changed = 1;
            }
        }
        {
            char idx_path[512];
            struct stat idx_st;

            build_index_path(idx_path, sizeof(idx_path), dir_name, header.segment_seq);
            if (stat(idx_path, &idx_st) != 0 || idx_st.st_mtime < st.st_mtime) {
                index_rebuild_for_segment(path, idx_path);
            }
        }
    }
    closedir(dir);
    if (changed) {
        fsync_dir_path(dir_path);
    }
}

static int recover_store(void)
{
    for_each_segment_dir(cleanup_segment_dir_cb, NULL);
    for_each_segment_dir(recover_segment_dir_cb, NULL);
    return 0;
}

static int path_is_active_segment(const Recorder *r, const char *path)
{
    size_t i;

    for (i = 0; i < r->config.group_count; i++) {
        if (r->writers[i].open && strcmp(r->writers[i].path, path) == 0) {
            return 1;
        }
    }
    return 0;
}

static int segment_seq_from_name(const char *name, uint64_t *seq_out)
{
    char *end = NULL;
    unsigned long long value;

    errno = 0;
    value = strtoull(name, &end, 10);
    if (errno != 0 || !end || strcmp(end, ".seg") != 0) {
        return -1;
    }
    *seq_out = value;
    return 0;
}

static void for_each_segment_dir(void (*fn)(const char *dir_name, void *ctx), void *ctx)
{
    DIR *dir = opendir(LOG_DIR);
    struct dirent *de;

    if (!dir) {
        return;
    }
    while ((de = readdir(dir)) != NULL) {
        char path[512];
        struct stat st;

        if (!is_segment_dir_name(de->d_name)) {
            continue;
        }
        build_segment_dir(path, sizeof(path), de->d_name);
        if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
            fn(de->d_name, ctx);
        }
    }
    closedir(dir);
}

typedef struct {
    uint64_t total;
} CountBytesCtx;

static void count_store_bytes_cb(const char *dir_name, void *ctx)
{
    CountBytesCtx *count = ctx;
    char dir_path[256];
    DIR *dir;
    struct dirent *de;

    build_segment_dir(dir_path, sizeof(dir_path), dir_name);
    dir = opendir(dir_path);
    if (!dir) {
        return;
    }
    while ((de = readdir(dir)) != NULL) {
        char path[512];
        struct stat st;

        snprintf(path, sizeof(path), "%s/%s", dir_path, de->d_name);
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
            count->total += (uint64_t)st.st_size;
        }
    }
    closedir(dir);
}

static uint64_t count_store_bytes(void)
{
    CountBytesCtx ctx;

    memset(&ctx, 0, sizeof(ctx));
    for_each_segment_dir(count_store_bytes_cb, &ctx);
    {
        DIR *dir = opendir(LOG_DIR "/state");
        struct dirent *de;

        if (dir) {
            while ((de = readdir(dir)) != NULL) {
                char path[512];
                struct stat st;

                snprintf(path, sizeof(path), LOG_DIR "/state/%s", de->d_name);
                if (stat(path, &st) == 0 && S_ISREG(st.st_mode)) {
                    ctx.total += (uint64_t)st.st_size;
                }
            }
            closedir(dir);
        }
    }
    return ctx.total;
}

typedef struct {
    const Recorder *recorder;
    RetainedFile *files;
    size_t count;
} CollectSegmentsCtx;

static void collect_closed_segments_cb(const char *dir_name, void *ctx)
{
    CollectSegmentsCtx *collect = ctx;
    char dir_path[256];
    DIR *dir;
    struct dirent *de;

    build_segment_dir(dir_path, sizeof(dir_path), dir_name);
    dir = opendir(dir_path);
    if (!dir) {
        return;
    }
    while ((de = readdir(dir)) != NULL) {
        char path[512];
        struct stat st;
        uint64_t seq;

        if (collect->count >= 4096) {
            closedir(dir);
            return;
        }
        if (segment_seq_from_name(de->d_name, &seq) != 0) {
            continue;
        }
        snprintf(path, sizeof(path), "%s/%s", dir_path, de->d_name);
        if (path_is_active_segment(collect->recorder, path) ||
            stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        strncpy(collect->files[collect->count].path, path,
                sizeof(collect->files[collect->count].path) - 1);
        collect->files[collect->count].path[sizeof(collect->files[collect->count].path) - 1] = '\0';
        strncpy(collect->files[collect->count].dir_name, dir_name,
                sizeof(collect->files[collect->count].dir_name) - 1);
        collect->files[collect->count].dir_name[sizeof(collect->files[collect->count].dir_name) - 1] = '\0';
        collect->files[collect->count].min_priority = 7;
        collect->files[collect->count].segment_seq = seq;
        collect->files[collect->count].size = (uint64_t)st.st_size;
        {
            SegmentHeader header;
            SegmentFooter footer;
            size_t committed_end = 0;

            if (segment_scan_path(path, NULL, NULL, &header, &footer, &committed_end) == 0) {
                size_t i;
                for (i = 0; i < 8; i++) {
                    if (collect->recorder->config.priority_to_group[i] >= 0) {
                        const PriorityGroup *group = &collect->recorder->config.groups[collect->recorder->config.priority_to_group[i]];
                        if (strcmp(group->name, dir_name) == 0) {
                            collect->files[collect->count].min_priority = group->min_priority;
                            break;
                        }
                    }
                }
            }
        }
        collect->count++;
    }
    closedir(dir);
}

static int collect_closed_segments(const Recorder *r, RetainedFile *files, size_t *count_out)
{
    CollectSegmentsCtx ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.recorder = r;
    ctx.files = files;
    for_each_segment_dir(collect_closed_segments_cb, &ctx);
    *count_out = ctx.count;
    return 0;
}

static void retention_sort(RetainedFile *files, size_t count)
{
    size_t i;
    size_t j;

    for (i = 0; i < count; i++) {
        for (j = i + 1; j < count; j++) {
            if (files[j].min_priority > files[i].min_priority ||
                (files[j].min_priority == files[i].min_priority &&
                 files[j].segment_seq < files[i].segment_seq)) {
                RetainedFile tmp = files[i];
                files[i] = files[j];
                files[j] = tmp;
            }
        }
    }
}

static void retention_enforce(Recorder *r)
{
    uint64_t total;
    RetainedFile files[4096];
    size_t count = 0;
    size_t i;
    int changed = 0;

    if (r->config.log_max_bytes == 0) {
        return;
    }
    total = count_store_bytes();
    if (total <= r->config.log_max_bytes) {
        return;
    }
    collect_closed_segments(r, files, &count);
    retention_sort(files, count);
    for (i = 0; i < count && total > r->config.log_max_bytes; i++) {
        if (unlink(files[i].path) == 0) {
            char idx_path[512];
            char dir_path[256];

            build_index_path(idx_path, sizeof(idx_path), files[i].dir_name,
                             files[i].segment_seq);
            unlink(idx_path);
            total = total > files[i].size ? total - files[i].size : 0;
            build_segment_dir(dir_path, sizeof(dir_path), files[i].dir_name);
            fsync_dir_path(dir_path);
            recorder_verbose_log(r,
                                 "retention removed segment seq=%" PRIu64 " group=%s size=%" PRIu64 " bytes",
                                 files[i].segment_seq, files[i].dir_name,
                                 (uint64_t)files[i].size);
            changed = 1;
        }
    }
    if (changed) {
        boot_registry_rebuild_from_segments(&r->boots);
        persist_boot_state(&r->boots);
    }
}

typedef struct {
    BootRegistry *boots;
} BootRebuildCtx;

static void boot_registry_rebuild_from_segments_cb(const char *dir_name, void *ctx)
{
    BootRebuildCtx *rebuild = ctx;
    char dir_path[256];
    DIR *dir;
    struct dirent *de;

    build_segment_dir(dir_path, sizeof(dir_path), dir_name);
    dir = opendir(dir_path);
    if (!dir) {
        return;
    }
    while ((de = readdir(dir)) != NULL) {
        char path[512];
        SegmentHeader header;
        SegmentFooter footer;
        size_t committed_end = 0;
        BootEntry *boot;

        if (!strstr(de->d_name, ".seg")) {
            continue;
        }
        snprintf(path, sizeof(path), "%s/%s", dir_path, de->d_name);
        if (segment_scan_path(path, NULL, NULL, &header, &footer, &committed_end) != 0) {
            continue;
        }
        boot = boot_registry_get(rebuild->boots, header.boot_id);
        if (!boot) {
            continue;
        }
        boot->seq = header.boot_seq;
        if (boot->first_realtime_ts == 0 ||
            header.first_realtime_ts < boot->first_realtime_ts) {
            boot->first_realtime_ts = header.first_realtime_ts;
        }
        if (footer.last_realtime_ts > boot->last_clean_realtime_ts) {
            boot->last_clean_realtime_ts = footer.last_realtime_ts;
        }
    }
    closedir(dir);
}

static int boot_registry_rebuild_from_segments(BootRegistry *boots)
{
    BootRebuildCtx ctx;

    boot_registry_init(boots);
    ctx.boots = boots;
    for_each_segment_dir(boot_registry_rebuild_from_segments_cb, &ctx);
    return 0;
}

static int load_boot_state(BootRegistry *boots)
{
    char path[512];
    char *raw;
    size_t raw_len = 0;
    json_t *root = NULL;
    json_error_t err;
    size_t idx;
    json_t *node;

    build_state_boots_path(path, sizeof(path));
    if (access(path, F_OK) != 0) {
        return -1;
    }
    raw = slurp_file(path, &raw_len);
    if (!raw) {
        return -1;
    }
    root = json_loads(raw, 0, &err);
    free(raw);
    if (!root || !json_is_array(root)) {
        json_decref(root);
        return -1;
    }
    boot_registry_init(boots);
    json_array_foreach(root, idx, node)
    {
        json_t *id = json_object_get(node, "boot_id");
        json_t *seq = json_object_get(node, "boot_seq");
        json_t *first = json_object_get(node, "first_realtime_ts");
        json_t *last = json_object_get(node, "last_realtime_ts_on_clean_shutdown");
        BootEntry *boot;

        if (!json_is_string(id) || !json_is_integer(seq) || !json_is_integer(first)) {
            continue;
        }
        boot = boot_registry_get(boots, json_string_value(id));
        if (!boot) {
            continue;
        }
        boot->seq = (uint32_t)json_integer_value(seq);
        boot->first_realtime_ts = (uint64_t)json_integer_value(first);
        boot->last_clean_realtime_ts = json_is_integer(last) ?
            (uint64_t)json_integer_value(last) : 0;
    }
    json_decref(root);
    return 0;
}

static int persist_boot_state(const BootRegistry *boots)
{
    char path[512];
    json_t *root = json_array();
    char *text;
    uint32_t i;
    int rc = -1;

    if (!root) {
        return -1;
    }
    for (i = 0; i < boots->count; i++) {
        json_t *node = json_object();

        if (!node ||
            json_object_set_new(node, "boot_id", json_string(boots->boots[i].id)) != 0 ||
            json_object_set_new(node, "boot_seq", json_integer(boots->boots[i].seq)) != 0 ||
            json_object_set_new(node, "first_realtime_ts",
                                json_integer((json_int_t)boots->boots[i].first_realtime_ts)) != 0) {
            json_decref(node);
            goto out;
        }
        if (boots->boots[i].last_clean_realtime_ts != 0 &&
            json_object_set_new(node, "last_realtime_ts_on_clean_shutdown",
                                json_integer((json_int_t)boots->boots[i].last_clean_realtime_ts)) != 0) {
            json_decref(node);
            goto out;
        }
        if (json_array_append_new(root, node) != 0) {
            json_decref(node);
            goto out;
        }
    }
    text = json_dumps(root, JSON_INDENT(2));
    if (!text) {
        goto out;
    }
    build_state_boots_path(path, sizeof(path));
    rc = atomic_write_text_file(path, text);
    free(text);
out:
    json_decref(root);
    return rc;
}

static void extract_entry(LogEntry *entry, sd_journal *j, RecorderConfig *cfg,
                          BootRegistry *boots)
{
    const char *boot_id = nonempty_or_null(journal_get(j, "_BOOT_ID"));
    uint64_t monotonic_ts = 0;
    sd_id128_t monotonic_boot_id;

    memset(entry, 0, sizeof(*entry));
    sd_journal_get_realtime_usec(j, &entry->realtime_ts);
    if (sd_journal_get_monotonic_usec(j, &monotonic_ts, &monotonic_boot_id) >= 0) {
        entry->monotonic_ts = monotonic_ts;
    }
    entry->priority = (uint8_t)journal_get_u32(j, "PRIORITY");
    entry->errno_value = clamp_u16(journal_get_u64(j, "ERRNO"));
    entry->boot_id = boot_id ? boot_id : "";
    entry->boot_seq = boot_registry_seq(boots, boot_id);
    {
        BootEntry *boot = boot_registry_get(boots, entry->boot_id);
        if (boot && boot->first_realtime_ts == 0) {
            boot->first_realtime_ts = entry->realtime_ts;
        }
    }
    entry->message = nonempty_or_null(journal_get(j, "MESSAGE"));
    entry->message_id = cfg->capture_message_id ? nonempty_or_null(journal_get(j, "MESSAGE_ID")) : NULL;
    entry->unit = cfg->capture_unit ? nonempty_or_null(journal_get(j, "_SYSTEMD_UNIT")) : NULL;
    entry->hostname = cfg->capture_hostname ? nonempty_or_null(journal_get(j, "_HOSTNAME")) : NULL;
    entry->comm = cfg->capture_comm ? nonempty_or_null(journal_get(j, "_COMM")) : NULL;
    entry->exe = cfg->capture_exe ? nonempty_or_null(journal_get(j, "_EXE")) : NULL;
    entry->pid = cfg->capture_pid ? journal_get_u32(j, "_PID") : 0;
    entry->uid = cfg->capture_uid ? journal_get_u32(j, "_UID") : 0;
    entry->gid = cfg->capture_gid ? journal_get_u32(j, "_GID") : 0;
}

static journal_Entry_ref_t serialize_entry(flatcc_builder_t *B, const LogEntry *entry)
{
    flatbuffers_string_ref_t message_ref = entry->message ? flatbuffers_string_create_str(B, entry->message) : 0;
    flatbuffers_string_ref_t message_id_ref = entry->message_id ? flatbuffers_string_create_str(B, entry->message_id) : 0;
    flatbuffers_string_ref_t unit_ref = entry->unit ? flatbuffers_string_create_str(B, entry->unit) : 0;
    flatbuffers_string_ref_t hostname_ref = entry->hostname ? flatbuffers_string_create_str(B, entry->hostname) : 0;
    flatbuffers_string_ref_t comm_ref = entry->comm ? flatbuffers_string_create_str(B, entry->comm) : 0;
    flatbuffers_string_ref_t exe_ref = entry->exe ? flatbuffers_string_create_str(B, entry->exe) : 0;

    if (journal_Entry_start(B)) {
        return 0;
    }
    journal_Entry_realtime_ts_add(B, entry->realtime_ts);
    journal_Entry_monotonic_ts_add(B, entry->monotonic_ts);
    journal_Entry_priority_add(B, entry->priority);
    if (message_ref) journal_Entry_message_add(B, message_ref);
    if (message_id_ref) journal_Entry_message_id_add(B, message_id_ref);
    if (unit_ref) journal_Entry_unit_add(B, unit_ref);
    if (entry->pid) journal_Entry_pid_add(B, entry->pid);
    if (entry->uid) journal_Entry_uid_add(B, entry->uid);
    if (entry->gid) journal_Entry_gid_add(B, entry->gid);
    if (hostname_ref) journal_Entry_hostname_add(B, hostname_ref);
    if (comm_ref) journal_Entry_comm_add(B, comm_ref);
    if (exe_ref) journal_Entry_exe_add(B, exe_ref);
    if (entry->errno_value) journal_Entry_errno_add(B, entry->errno_value);
    return journal_Entry_end(B);
}

static void writer_init(PriorityWriter *w, const PriorityGroup *group, uint8_t group_index)
{
    memset(w, 0, sizeof(*w));
    w->group_index = group_index;
    strncpy(w->group_name, group->name, sizeof(w->group_name) - 1);
    w->group_name[sizeof(w->group_name) - 1] = '\0';
}

static int writer_open_segment(Recorder *r, PriorityWriter *w, const LogEntry *entry,
                               const char *reason)
{
    SegmentHeader header;
    char dir[256];
    char *dict_buf = NULL;
    size_t dict_len = 0;

    build_segment_dir(dir, sizeof(dir), w->group_name);
    if (mkdir_p(dir) != 0) {
        return -1;
    }
    w->segment_seq = r->next_segment_seq++;
    if (persist_next_segment_seq(r->next_segment_seq) != 0) {
        return -1;
    }
    build_segment_path(w->path, sizeof(w->path), w->group_name, w->segment_seq);
    build_segment_tmp_path(w->tmp_path, sizeof(w->tmp_path), w->group_name, w->segment_seq);
    w->fp = fopen(w->tmp_path, "wb");
    if (!w->fp) {
        fprintf(stderr, "recorder: fopen(%s): %m\n", w->tmp_path);
        return -1;
    }

    memset(&header, 0, sizeof(header));
    header.segment_seq = w->segment_seq;
    header.boot_seq = entry->boot_seq;
    strncpy(header.boot_id, entry->boot_id ? entry->boot_id : "", RECORDER_BOOT_ID_SIZE);
    current_timezone_string(header.timezone);
    header.first_realtime_ts = entry->realtime_ts;
    header.first_monotonic_ts = entry->monotonic_ts;
    if (r->config.groups[w->group_index].static_dict_path) {
        dict_buf = slurp_file(r->config.groups[w->group_index].static_dict_path, &dict_len);
        if (!dict_buf || dict_len == 0) {
            free(dict_buf);
            fclose(w->fp);
            unlink(w->tmp_path);
            w->fp = NULL;
            return -1;
        }
        header.flags |= SEGMENT_FLAG_HAS_STATIC_DICT;
    }
    if (segment_write_header(w->fp, &header, dict_buf, dict_len) != 0) {
        fclose(w->fp);
        free(dict_buf);
        w->fp = NULL;
        return -1;
    }
    if (flush_and_sync_file(w->fp) != 0) {
        fclose(w->fp);
        unlink(w->tmp_path);
        w->fp = NULL;
        return -1;
    }
    if (rename(w->tmp_path, w->path) != 0) {
        fclose(w->fp);
        unlink(w->tmp_path);
        w->fp = NULL;
        return -1;
    }
    if (fsync_dir_path(dir) != 0) {
        fclose(w->fp);
        w->fp = NULL;
        return -1;
    }

    strncpy(w->boot_id, header.boot_id, RECORDER_BOOT_ID_SIZE);
    w->boot_id[RECORDER_BOOT_ID_SIZE] = '\0';
    strncpy(w->timezone, header.timezone, sizeof(w->timezone) - 1);
    w->timezone[sizeof(w->timezone) - 1] = '\0';
    w->boot_seq = entry->boot_seq;
    w->bytes_written = segment_header_encoded_size();
    w->entry_count = 0;
    w->first_realtime_ts = entry->realtime_ts;
    w->first_monotonic_ts = entry->monotonic_ts;
    w->last_realtime_ts = entry->realtime_ts;
    w->last_monotonic_ts = entry->monotonic_ts;
    w->initial_time_delta = (int64_t)entry->realtime_ts - (int64_t)entry->monotonic_ts;
    w->opened_mono_sec = monotonic_now_sec();
    w->last_sync_mono_sec = w->opened_mono_sec;
    w->unsynced_frames = 0;
    w->compress_enabled = r->config.compress_enabled;
    w->compress_min_frame_bytes = r->config.compress_min_frame_bytes;
    w->compress_if_smaller = r->config.compress_if_smaller;
    w->durable_per_frame = r->config.groups[w->group_index].durable_per_frame;
    w->durability_flush_frames = r->config.groups[w->group_index].durability_flush_frames;
    w->durability_flush_interval_sec = r->config.groups[w->group_index].durability_flush_interval_sec;
    w->dict_bytes = dict_buf;
    w->dict_len = dict_len;
    w->open = 1;
    recorder_verbose_log(r,
                         "opened segment seq=%" PRIu64 " group=%s reason=%s",
                         w->segment_seq, w->group_name, reason ? reason : "new entry");
    return 0;
}

static int writer_flush_chunk(PriorityWriter *w)
{
    journal_Entry_vec_ref_t vec;
    size_t raw_size;
    void *raw_buf = NULL;
    void *stored_buf = NULL;
    size_t stored_size = 0;
    uint32_t raw_size32;
    uint32_t stored_size32;
    uint32_t frame_flags = SEGMENT_FRAME_FLAG_NONE;
    int rv = -1;

    if (!w->builder_live || w->count == 0) {
        return 0;
    }

    vec = journal_Entry_vec_create(&w->builder, w->entries, w->count);
    if (!vec || !journal_Chunk_create_as_root(&w->builder, vec)) {
        goto out;
    }
    raw_buf = flatcc_builder_finalize_buffer(&w->builder, &raw_size);
    if (!raw_buf || raw_size > UINT32_MAX) {
        goto out;
    }
    raw_size32 = (uint32_t)raw_size;
    stored_buf = raw_buf;
    stored_size = raw_size;

    if (w->compress_enabled && raw_size >= w->compress_min_frame_bytes) {
        size_t bound = ZSTD_compressBound(raw_size);
        void *compressed = malloc(bound);

        if (!compressed) {
            goto out;
        }
        if (w->dict_bytes && w->dict_len != 0) {
            ZSTD_CCtx *cctx = ZSTD_createCCtx();

            if (!cctx) {
                free(compressed);
                goto out;
            }
            stored_size = ZSTD_compress_usingDict(cctx, compressed, bound,
                                                  raw_buf, raw_size,
                                                  w->dict_bytes, w->dict_len, 1);
            ZSTD_freeCCtx(cctx);
        } else {
            stored_size = ZSTD_compress(compressed, bound, raw_buf, raw_size, 1);
        }
        if (!ZSTD_isError(stored_size) &&
            (!w->compress_if_smaller || stored_size < raw_size)) {
            stored_buf = compressed;
            frame_flags = SEGMENT_FRAME_FLAG_ZSTD;
        } else {
            free(compressed);
            stored_size = raw_size;
        }
    }

    stored_size32 = (uint32_t)stored_size;
    if (segment_write_frame(w->fp, frame_flags, stored_buf, stored_size32, raw_size32) != 0) {
        goto out;
    }
    w->bytes_written += 16 + stored_size + 4;
    w->unsynced_frames++;
    if (w->durable_per_frame ||
        (w->durability_flush_frames != 0 && w->unsynced_frames >= w->durability_flush_frames) ||
        (w->durability_flush_interval_sec != 0 &&
         monotonic_now_sec() - w->last_sync_mono_sec >= (time_t)w->durability_flush_interval_sec)) {
        if (flush_and_sync_file(w->fp) != 0) {
            goto out;
        }
        w->unsynced_frames = 0;
        w->last_sync_mono_sec = monotonic_now_sec();
    }
    rv = 0;

out:
    if (stored_buf != raw_buf) {
        free(stored_buf);
    }
    free(raw_buf);
    if (w->builder_live) {
        flatcc_builder_clear(&w->builder);
        w->builder_live = 0;
    }
    w->count = 0;
    return rv;
}

static int writer_close_segment(Recorder *r, PriorityWriter *w, const char *reason)
{
    SegmentFooter footer;

    if (!w->open) {
        return 0;
    }
    if (writer_flush_chunk(w) != 0) {
        return -1;
    }
    memset(&footer, 0, sizeof(footer));
    footer.entry_count = w->entry_count;
    footer.last_realtime_ts = w->last_realtime_ts;
    footer.last_monotonic_ts = w->last_monotonic_ts;
    if (segment_write_footer(w->fp, &footer) != 0) {
        fclose(w->fp);
        w->fp = NULL;
        w->open = 0;
        return -1;
    }
    if (flush_and_sync_file(w->fp) != 0) {
        fclose(w->fp);
        w->fp = NULL;
        w->open = 0;
        return -1;
    }
    w->bytes_written += segment_footer_encoded_size();
    fclose(w->fp);
    {
        char dir[256];

        build_segment_dir(dir, sizeof(dir), w->group_name);
        fsync_dir_path(dir);
    }
    w->fp = NULL;
    w->open = 0;
    w->boot_id[0] = '\0';
    w->timezone[0] = '\0';
    free(w->dict_bytes);
    w->dict_bytes = NULL;
    w->dict_len = 0;
    recorder_verbose_log(r,
                         "closed segment seq=%" PRIu64 " group=%s reason=%s",
                         w->segment_seq, w->group_name, reason ? reason : "shutdown");
    return 0;
}

static int writer_sync_if_due(PriorityWriter *w)
{
    if (!w->open || w->fp == NULL || w->unsynced_frames == 0) {
        return 0;
    }
    if (w->durable_per_frame ||
        (w->durability_flush_interval_sec != 0 &&
         monotonic_now_sec() - w->last_sync_mono_sec >= (time_t)w->durability_flush_interval_sec)) {
        if (flush_and_sync_file(w->fp) != 0) {
            return -1;
        }
        w->unsynced_frames = 0;
        w->last_sync_mono_sec = monotonic_now_sec();
    }
    return 0;
}

static int recorder_close_writer(Recorder *r, PriorityWriter *w, const char *reason)
{
    char seg_path[512];
    char idx_path[512];
    uint64_t segment_seq = w->segment_seq;
    const char *group_name = w->group_name;

    strncpy(seg_path, w->path, sizeof(seg_path) - 1);
    seg_path[sizeof(seg_path) - 1] = '\0';
    if (writer_close_segment(r, w, reason) != 0) {
        return -1;
    }
    if (seg_path[0] != '\0') {
        build_index_path(idx_path, sizeof(idx_path), group_name, segment_seq);
        index_rebuild_for_segment(seg_path, idx_path);
    }
    retention_enforce(r);
    return 0;
}

static flatcc_builder_t *writer_builder(PriorityWriter *w)
{
    if (!w->builder_live) {
        flatcc_builder_init(&w->builder);
        w->builder_live = 1;
    }
    return &w->builder;
}

static uint64_t recorder_segment_limit(const Recorder *r)
{
    return r->config.segment_max_bytes ? r->config.segment_max_bytes : DEFAULT_SEGMENT_MAX_BYTES;
}

static int recorder_init(Recorder *r, sd_journal *j, const RecorderConfig *cfg, int verbose)
{
    uint8_t prio;
    uint64_t scanned_next;
    uint64_t persisted_next;
    BootRegistry rebuilt_boots;

    memset(r, 0, sizeof(*r));
    r->j = j;
    r->config = *cfg;
    r->verbose = verbose;
    boot_registry_init(&r->boots);
    mkdir_p(LOG_DIR);
    for (prio = 0; prio < r->config.group_count; prio++) {
        writer_init(&r->writers[prio], &r->config.groups[prio], prio);
    }
    recover_store();
    scanned_next = scan_existing_segment_seq_max() + 1;
    if (read_persisted_next_segment_seq(&persisted_next) == 0 && persisted_next > scanned_next) {
        r->next_segment_seq = persisted_next;
    } else {
        r->next_segment_seq = scanned_next;
    }
    persist_next_segment_seq(r->next_segment_seq);
    if (load_boot_state(&r->boots) != 0) {
        boot_registry_rebuild_from_segments(&r->boots);
        persist_boot_state(&r->boots);
    } else {
        boot_registry_rebuild_from_segments(&rebuilt_boots);
        r->boots = rebuilt_boots;
        persist_boot_state(&r->boots);
    }
    retention_enforce(r);
    return 0;
}

static int recorder_ensure_writer(Recorder *r, const LogEntry *entry)
{
    int group_index = r->config.priority_to_group[entry->priority];
    PriorityWriter *w;
    RotateDecision decision;
    const char *reason_text;
    uint64_t segment_limit;
    char timezone[RECORDER_SEGMENT_TZ_SIZE];
    time_t now_sec;

    if (group_index < 0 || (size_t)group_index >= r->config.group_count) {
        return -1;
    }
    w = &r->writers[group_index];
    segment_limit = recorder_segment_limit(r);

    decision = writer_should_rotate(r, w, entry);
    if (decision.reason != ROTATE_REASON_NONE) {
        reason_text = rotate_reason_text(decision.reason);
        switch (decision.reason) {
        case ROTATE_REASON_BOOT_ID:
            recorder_verbose_log(r,
                                 "rotating segment seq=%" PRIu64 " group=%s because %s (current_boot_id=%s, segment_boot_id=%s)",
                                 w->segment_seq, w->group_name, reason_text,
                                 entry->boot_id ? entry->boot_id : "(null)",
                                 w->boot_id[0] ? w->boot_id : "(empty)");
            break;
        case ROTATE_REASON_TIMEZONE:
            current_timezone_string(timezone);
            recorder_verbose_log(r,
                                 "rotating segment seq=%" PRIu64 " group=%s because %s (current_timezone=%s, segment_timezone=%s)",
                                 w->segment_seq, w->group_name, reason_text,
                                 timezone, w->timezone);
            break;
        case ROTATE_REASON_TIME_DELTA:
            recorder_verbose_log(r,
                                 "rotating segment seq=%" PRIu64 " group=%s because %s (current_delta=%" PRId64 " usec, initial_delta=%" PRId64 " usec, diff=%" PRId64 " usec, threshold=%" PRIu64 " usec)",
                                 w->segment_seq, w->group_name, reason_text,
                                 (int64_t)entry->realtime_ts - (int64_t)entry->monotonic_ts,
                                 w->initial_time_delta,
                                 decision.delta_diff,
                                 (uint64_t)TIME_DELTA_ROTATE_THRESHOLD_USEC);
            break;
        case ROTATE_REASON_AGE:
            now_sec = monotonic_now_sec();
            recorder_verbose_log(r,
                                 "rotating segment seq=%" PRIu64 " group=%s because %s (opened_at=%lld sec, now=%lld sec, age=%lld sec, limit=%u sec)",
                                 w->segment_seq, w->group_name, reason_text,
                                 (long long)w->opened_mono_sec,
                                 (long long)now_sec,
                                 (long long)(now_sec - w->opened_mono_sec),
                                 r->config.segment_max_age_sec);
            break;
        case ROTATE_REASON_SIZE:
            recorder_verbose_log(r,
                                 "rotating segment seq=%" PRIu64 " group=%s because %s (bytes_written=%" PRIu64 ", limit=%" PRIu64 ")",
                                 w->segment_seq, w->group_name, reason_text,
                                 w->bytes_written, segment_limit);
            break;
        case ROTATE_REASON_NONE:
        default:
            recorder_verbose_log(r,
                                 "rotating segment seq=%" PRIu64 " group=%s because %s",
                                 w->segment_seq, w->group_name, reason_text);
            break;
        }
        if (recorder_close_writer(r, w, reason_text) != 0) {
            return -1;
        }
    }
    if (!w->open) {
        reason_text = decision.reason != ROTATE_REASON_NONE ? rotate_reason_text(decision.reason)
                         : (w->entry_count > 0 ? "segment reopened after close" : "initial segment");
        if (writer_open_segment(r, w, entry, reason_text) != 0) {
            return -1;
        }
    }
    return 0;
}

static int recorder_submit_entry(Recorder *r, const LogEntry *entry)
{
    int group_index = r->config.priority_to_group[entry->priority];
    PriorityWriter *w;
    flatcc_builder_t *B;
    journal_Entry_ref_t entry_ref;

    if (group_index < 0 || (size_t)group_index >= r->config.group_count) {
        return -1;
    }
    w = &r->writers[group_index];

    if (recorder_ensure_writer(r, entry) != 0) {
        return -1;
    }

    B = writer_builder(w);
    entry_ref = serialize_entry(B, entry);
    if (!entry_ref) {
        return -1;
    }
    w->entries[w->count++] = entry_ref;
    w->entry_count++;
    w->last_realtime_ts = entry->realtime_ts;
    w->last_monotonic_ts = entry->monotonic_ts;

    if (w->count == CHUNK_SIZE) {
        if (writer_flush_chunk(w) != 0) {
            return -1;
        }
    }
    if (w->bytes_written >= recorder_segment_limit(r)) {
        if (recorder_close_writer(r, w, "segment size limit reached after write") != 0) {
            return -1;
        }
    }
    return 0;
}

static size_t recorder_step(Recorder *r)
{
    size_t processed = 0;

    while (processed < CHUNK_SIZE) {
        LogEntry entry;
        uint32_t boot_count_before = r->boots.count;

        if (!r->current_entry_pending) {
            if (sd_journal_next(r->j) <= 0) {
                break;
            }
        } else {
            r->current_entry_pending = 0;
        }
        extract_entry(&entry, r->j, &r->config, &r->boots);
        if (r->boots.count != boot_count_before) {
            persist_boot_state(&r->boots);
        }
        if (recorder_submit_entry(r, &entry) != 0) {
            fprintf(stderr, "recorder: failed to store entry\n");
            break;
        }
        processed++;
    }
    return processed;
}

static void recorder_flush_all(Recorder *r)
{
    size_t i;

    for (i = 0; i < r->config.group_count; i++) {
        writer_flush_chunk(&r->writers[i]);
        writer_sync_if_due(&r->writers[i]);
    }
}

static void recorder_shutdown(Recorder *r)
{
    size_t i;
    uint64_t max_last_rt[MAX_PRIORITY_GROUPS] = {0};
    char boot_ids[MAX_PRIORITY_GROUPS][RECORDER_BOOT_ID_SIZE + 1];

    memset(boot_ids, 0, sizeof(boot_ids));

    recorder_flush_all(r);
    for (i = 0; i < r->config.group_count; i++) {
        if (r->writers[i].open &&
            r->writers[i].last_realtime_ts > max_last_rt[i]) {
            max_last_rt[i] = r->writers[i].last_realtime_ts;
        }
        strncpy(boot_ids[i], r->writers[i].boot_id, RECORDER_BOOT_ID_SIZE);
        boot_ids[i][RECORDER_BOOT_ID_SIZE] = '\0';
        recorder_close_writer(r, &r->writers[i], "shutdown");
    }
    for (i = 0; i < r->config.group_count; i++) {
        if (boot_ids[i][0] != '\0') {
            BootEntry *boot = boot_registry_get(&r->boots, boot_ids[i]);
            if (boot && max_last_rt[i] > boot->last_clean_realtime_ts) {
                boot->last_clean_realtime_ts = max_last_rt[i];
            }
        }
    }
    persist_boot_state(&r->boots);
    persist_next_segment_seq(r->next_segment_seq);
}

int main(int argc, char **argv)
{
    sd_journal *j;
    Recorder r;
    RecorderConfig cfg;
    const char *cfg_path;
    int verbose = 0;
    int opt;

    opterr = 0;
    while ((opt = getopt(argc, argv, "v")) != -1) {
        switch (opt) {
        case 'v':
            verbose = 1;
            break;
        default:
            fprintf(stderr, "usage: %s [-v]\n", argv[0]);
            return 1;
        }
    }

    recorder_config_init(&cfg);
    cfg_path = recorder_config_path();
    if (recorder_config_load(&cfg, cfg_path) != 0) {
        recorder_config_destroy(&cfg);
        return 1;
    }

    if (sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY) < 0) {
        fprintf(stderr, "recorder: failed to open journal\n");
        recorder_config_destroy(&cfg);
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    recorder_init(&r, j, &cfg, verbose);
    if (sd_journal_seek_tail(j) < 0) {
        fprintf(stderr, "recorder: failed to seek to journal tail\n");
        sd_journal_close(j);
        recorder_config_destroy(&cfg);
        return 1;
    }
    r.current_entry_pending = sd_journal_previous(j) > 0;

    while (!g_shutdown) {
        size_t n = recorder_step(&r);

        if (n > 0) {
            continue;
        }
        recorder_flush_all(&r);
        if (sd_journal_wait(j, JOURNAL_WAIT_USEC) < 0) {
            break;
        }
    }

    recorder_shutdown(&r);
    sd_journal_close(j);
    recorder_config_destroy(&cfg);
    return 0;
}
