#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <jansson.h>
#include <limits.h>
#include <stdarg.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <time.h>
#include <unistd.h>

#include <linux/magic.h>

#ifdef HAVE_PCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#elif defined(HAVE_LIBC_REGEX)
#include <regex.h>
#endif

#include <flatcc/flatcc_builder.h>
#ifdef HAVE_SYSTEMD
#include <systemd/sd-journal.h>
#else
typedef void sd_journal;
#endif
#include <zstd.h>

#include "helper.h"
#include "index.h"
#include "script_worker.h"
#include "fallback_source.h"
#ifdef errno
#pragma push_macro("errno")
#undef errno
#define RECORDER_RESTORE_ERRNO 1
#endif
#include "recorder_builder.h"
#include "segment.h"
#include "index.h"
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
#define DEFAULT_DURABILITY_FLUSH_INTERVAL_SEC 60
#define DEFAULT_LOG_MAX_BYTES (64ULL * 1024ULL * 1024ULL)
#define DEFAULT_COMPRESS_ENABLED 1
#define DEFAULT_COMPRESS_MIN_FRAME_BYTES 256
#define DEFAULT_COMPRESS_IF_SMALLER 1
#define DEFAULT_CAPTURE_MESSAGE_ID 0
#define DEFAULT_CAPTURE_UNIT 1
#define DEFAULT_CAPTURE_HOSTNAME 0
#define DEFAULT_CAPTURE_COMM 0
#define DEFAULT_CAPTURE_EXE 0
#define DEFAULT_CAPTURE_PID 1
#define DEFAULT_CAPTURE_UID 0
#define DEFAULT_CAPTURE_GID 0
#define DEFAULT_CAPTURE_ALL_FIELDS 0
#define DEFAULT_SANITIZE_OUTPUT 1
#define JOURNAL_WAIT_USEC (300 * 1000ULL)
#define CLOCK_BACKWARD_JUMP_THRESHOLD_USEC (1000LL)
#define CLOCK_FORWARD_JUMP_THRESHOLD_USEC (1000000LL)
#define MAX_PRIORITY_GROUPS 8
#define MAX_GROUP_NAME_LEN 63
#define MAX_MODIFIER_REROUTES 8
#define RECORDER_CURSOR_PATH "/run/recorder/journal.cursor"
#define RECORDER_CURSOR_MAX_BYTES 512

static char g_log_dir[PATH_MAX] = LOG_DIR;

static int build_log_path(char *path, size_t path_size, const char *suffix)
{
	size_t base_len = strlen(g_log_dir);
	size_t suffix_len = strlen(suffix);

	if (base_len + suffix_len + 1 > path_size) {
		return -1;
	}
	memcpy(path, g_log_dir, base_len);
	memcpy(path + base_len, suffix, suffix_len + 1);
	return 0;
}

typedef enum {
	MODIFIER_MATCH_EXACT,
	MODIFIER_MATCH_PRESENT,
	MODIFIER_MATCH_REGEX,
} ModifierMatchKind;

typedef struct {
	char *match_field;
	ModifierMatchKind match_kind;
	char *match_exact;
	int match_present;
	int negate;
#ifdef HAVE_PCRE2
	pcre2_code *match_regex;
	pcre2_match_context *match_context;
#elif defined(HAVE_LIBC_REGEX)
	regex_t match_regex;
	int match_regex_compiled;
#endif
	char *rewrite_field;
	char *replacement;
	int drop;
	int set_priority;
	/* Fire-and-forget action.  The command is an argv-style vector. */
	char **script_command;
	size_t script_command_count;
	int script_run_on_replay;
	unsigned script_timeout_sec;
} EntryModifier;

typedef struct {
	EntryModifier *items;
	size_t count;
} ModifierList;

typedef struct {
	char name[MAX_GROUP_NAME_LEN + 1];
	uint8_t priorities[8];
	size_t priority_count;
	uint8_t min_priority;
	int durable_per_frame;
	unsigned durability_flush_frames;
	unsigned durability_flush_interval_sec;
	const char *static_dict_path;
	ModifierList modifiers;
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
	int capture_all_fields;
	char **capture_fields_whitelist;
	size_t capture_fields_whitelist_count;
	char **capture_fields_blacklist;
	size_t capture_fields_blacklist_count;
	int sanitize_output;
	int durable_priority_max;
	unsigned durability_flush_frames;
	unsigned durability_flush_interval_sec;
	uint64_t log_max_bytes;
	uint64_t segment_max_bytes;
	unsigned segment_max_age_sec;
	int compress_enabled;
	unsigned compress_min_frame_bytes;
	int compress_if_smaller;
	char *encryption_public_key;
	char *static_dict_paths[8];
	ModifierList modifiers;
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
	const char *data;
	size_t len;
} JournalField;

typedef struct {
	JournalField name;
	JournalField value;
} JournalExtraField;

typedef struct {
	uint64_t realtime_ts;
	uint64_t monotonic_ts;
	uint32_t pid;
	uint32_t uid;
	uint32_t gid;
	uint32_t boot_seq;
	uint8_t priority;
	uint16_t errno_value;
	char boot_id[RECORDER_BOOT_ID_SIZE + 1];
	JournalField message;
	JournalField message_id;
	JournalField hostname;
	JournalField unit;
	JournalField comm;
	JournalField exe;
	char *owned_message;
	char *owned_message_id;
	char *owned_hostname;
	char *owned_unit;
	char *owned_comm;
	char *owned_exe;
	JournalExtraField *extra_fields;
	size_t extra_field_count;
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
	uint64_t clock_jump_seen_seq;
	uint64_t bytes_written;
	uint64_t entry_count;
	uint64_t first_realtime_ts;
	uint64_t first_monotonic_ts;
	uint64_t last_realtime_ts;
	uint64_t last_monotonic_ts;
	time_t opened_mono_sec;
	time_t last_chunk_flush_mono_sec;
	time_t last_sync_mono_sec;
	unsigned unsynced_frames;
	int compress_enabled;
	unsigned compress_min_frame_bytes;
	int compress_if_smaller;
	SegmentEncryptor *encryptor;
	IndexWriter *index_writer;
	SegmentHeader index_header;
	int durable_per_frame;
	unsigned durability_flush_frames;
	unsigned durability_flush_interval_sec;
	void *dict_bytes;
	size_t dict_len;
	flatcc_builder_t builder;
	int builder_live;
	journal_FullEntry_ref_t entries[CHUNK_SIZE];
	journal_CompactEntry_ref_t compact_entries[CHUNK_SIZE];
	int use_compact_entries;
	size_t count;
} PriorityWriter;

typedef struct {
	sd_journal *j;
	FallbackSource *fallback;
	RecorderConfig config;
	BootRegistry boots;
	uint64_t next_segment_seq;
	int verbose;
	int current_entry_pending;
	int cursor_enabled;
	int persistent_cursor_enabled;
	char cursor_path[PATH_MAX];
	char persistent_cursor_path[PATH_MAX];
	char *pending_cursor;
	PriorityWriter writers[MAX_PRIORITY_GROUPS];
	uint64_t clock_jump_seq;
	int64_t clock_jump_usec;
	int clock_offset_initialized;
	int64_t last_clock_offset_usec;
	ScriptWorker *script_worker;
	int startup_catchup;
	uint64_t startup_replayed_entries;
} Recorder;

/*
 * Script modifiers are deliberately fire-and-forget.  The worker implementation
 * can replace this weak hook; keeping a no-op default makes configurations with
 * script modifiers harmless in builds that do not enable the worker.
 */
static void recorder_script_modifier_enqueue(Recorder *recorder,
								 const EntryModifier *modifier,
								 const LogEntry *entry, int is_replay);

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
	ROTATE_REASON_CLOCK_BACKWARD,
	ROTATE_REASON_CLOCK_FORWARD,
	ROTATE_REASON_AGE,
	ROTATE_REASON_SIZE,
} RotateReason;

typedef struct {
	RotateReason reason;
	int64_t delta_diff;
} RotateDecision;

static volatile sig_atomic_t g_shutdown = 0;

static void recorder_verbose_log(const Recorder *r, const char *fmt, ...);

static void on_signal(int sig)
{
	static const char message[] = "recorder: shutdown requested, flushing pending entries\n";

	(void)sig;
	g_shutdown = 1;
	(void)write(STDERR_FILENO, message, sizeof(message) - 1);
}

static int install_signal_handlers(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(action));
	action.sa_handler = on_signal;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGINT, &action, NULL) != 0 ||
		sigaction(SIGTERM, &action, NULL) != 0) {
		return -1;
	}
	return 0;
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
	cfg->capture_all_fields = DEFAULT_CAPTURE_ALL_FIELDS;
	cfg->sanitize_output = DEFAULT_SANITIZE_OUTPUT;
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

static void modifier_list_destroy(ModifierList *list)
{
	size_t i;

	for (i = 0; i < list->count; i++) {
		free(list->items[i].match_field);
		free(list->items[i].match_exact);
#ifdef HAVE_PCRE2
		pcre2_code_free(list->items[i].match_regex);
		pcre2_match_context_free(list->items[i].match_context);
#elif defined(HAVE_LIBC_REGEX)
		if (list->items[i].match_regex_compiled) regfree(&list->items[i].match_regex);
#endif
		free(list->items[i].rewrite_field);
		free(list->items[i].replacement);
		if (list->items[i].script_command) {
			size_t j;
			for (j = 0; j < list->items[i].script_command_count; j++)
				free(list->items[i].script_command[j]);
			free(list->items[i].script_command);
		}
	}
	free(list->items);
	list->items = NULL;
	list->count = 0;
}

static void recorder_config_destroy(RecorderConfig *cfg)
{
	size_t i;

	for (i = 0; i < 8; i++) {
		free(cfg->static_dict_paths[i]);
		cfg->static_dict_paths[i] = NULL;
		modifier_list_destroy(&cfg->groups[i].modifiers);
	}
	free(cfg->encryption_public_key);
	cfg->encryption_public_key = NULL;
	modifier_list_destroy(&cfg->modifiers);
	for (i = 0; i < cfg->capture_fields_whitelist_count; i++) {
		free(cfg->capture_fields_whitelist[i]);
	}
	free(cfg->capture_fields_whitelist);
	cfg->capture_fields_whitelist = NULL;
	cfg->capture_fields_whitelist_count = 0;
	for (i = 0; i < cfg->capture_fields_blacklist_count; i++) {
		free(cfg->capture_fields_blacklist[i]);
	}
	free(cfg->capture_fields_blacklist);
	cfg->capture_fields_blacklist = NULL;
	cfg->capture_fields_blacklist_count = 0;
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
	case ROTATE_REASON_CLOCK_BACKWARD:
		return "realtime clock jumped backwards";
	case ROTATE_REASON_CLOCK_FORWARD:
		return "realtime clock jumped forwards";
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
	RotateDecision decision;

	decision.reason = ROTATE_REASON_NONE;
	decision.delta_diff = 0;

	if (!w->open) {
		return decision;
	}
	if (w->clock_jump_seen_seq != r->clock_jump_seq) {
		decision.delta_diff = r->clock_jump_usec;
		decision.reason = decision.delta_diff < 0 ? ROTATE_REASON_CLOCK_BACKWARD :
			ROTATE_REASON_CLOCK_FORWARD;
		return decision;
	}
	if (w->boot_id[0] != '\0' && entry->boot_id[0] != '\0' &&
		strcmp(w->boot_id, entry->boot_id) != 0) {
		decision.reason = ROTATE_REASON_BOOT_ID;
		return decision;
	}
	current_timezone_string(timezone);
	if (strcmp(w->timezone, timezone) != 0) {
		decision.reason = ROTATE_REASON_TIMEZONE;
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

static int json_get_group_uint_default(json_t *group, const char *group_name,
										const char *key, unsigned *dst)
{
	json_t *node = json_object_get(group, key);
	json_int_t value;

	if (!node) {
		return 0;
	}
	if (!json_is_integer(node)) {
		fprintf(stderr, "recorder: priority group '%s' key '%s' must be integer\n",
				group_name, key);
		return -1;
	}
	value = json_integer_value(node);
	if (value < 0 || value > UINT_MAX) {
		fprintf(stderr, "recorder: priority group '%s' key '%s' out of range\n",
				group_name, key);
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

static int json_get_optional_nonempty_string(json_t *root, const char *key,
									  char **dst)
{
	json_t *node = json_object_get(root, key);
	const char *value;
	char *copy;

	if (!node) return 0;
	if (!json_is_string(node) || !(value = json_string_value(node)) || !value[0]) {
		fprintf(stderr, "recorder: config key '%s' must be a non-empty string\n", key);
		return -1;
	}
	copy = strdup(value);
	if (!copy) return -1;
	free(*dst);
	*dst = copy;
	return 0;
}

static int json_get_string_array(json_t *root, const char *key,
								char ***dst, size_t *count)
{
	json_t *node = json_object_get(root, key);
	char **values = NULL;
	size_t value_count;
	size_t i;

	if (!node) {
		return 0;
	}
	if (!json_is_array(node)) {
		fprintf(stderr, "recorder: config key '%s' must be an array\n", key);
		return -1;
	}
	value_count = json_array_size(node);
	if (value_count > 0) {
		values = calloc(value_count, sizeof(*values));
		if (!values) {
			return -1;
		}
	}
	for (i = 0; i < value_count; i++) {
		json_t *value = json_array_get(node, i);
		const char *text;

		if (!json_is_string(value) || !(text = json_string_value(value)) || !text[0]) {
			fprintf(stderr, "recorder: config key '%s' must contain non-empty strings\n", key);
			while (i > 0) {
				free(values[--i]);
			}
			free(values);
			return -1;
		}
		values[i] = strdup(text);
		if (!values[i]) {
			while (i > 0) {
				free(values[--i]);
			}
			free(values);
			return -1;
		}
	}
	*dst = values;
	*count = value_count;
	return 0;
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

static int json_get_modifier_list(json_t *owner, const char *scope, ModifierList *list)
{
	json_t *node = json_object_get(owner, "modifiers");
	size_t i;

	if (!node) return 0;
	if (!json_is_array(node)) {
		fprintf(stderr, "recorder: modifiers in %s must be an array\n", scope);
		return -1;
	}
	for (i = 0; i < json_array_size(node); i++) {
		json_t *item = json_array_get(node, i);
		json_t *match;
		json_t *field;
		json_t *regex;
		json_t *exact;
		json_t *present;
		json_t *negate;
		json_t *rewrite;
		json_t *drop;
		json_t *set_priority;
		json_t *script;
		EntryModifier *modifier;
		EntryModifier *tmp;

		if (!json_is_object(item) || !(match = json_object_get(item, "match")) ||
			!json_is_object(match) || ((field = json_object_get(match, "field")) &&
			(!json_is_string(field) || !json_string_value(field)[0]))) {
			fprintf(stderr, "recorder: modifier %zu in %s has an invalid match.field\n", i, scope);
			return -1;
		}
		regex = json_object_get(match, "regex");
		exact = json_object_get(match, "exact");
		present = json_object_get(match, "present");
		negate = json_object_get(match, "not");
		if ((regex != NULL) + (exact != NULL) + (present != NULL) != 1 ||
			(regex && !json_is_string(regex)) || (exact && !json_is_string(exact)) ||
			(present && !json_is_boolean(present)) || (negate && !json_is_boolean(negate))) {
			fprintf(stderr, "recorder: modifier %zu in %s needs exactly one of match.regex, match.exact, or match.present (and optional boolean match.not)\n", i, scope);
			return -1;
		}
		tmp = realloc(list->items, (list->count + 1) * sizeof(*tmp));
		if (!tmp) return -1;
		list->items = tmp;
		modifier = &list->items[list->count];
		memset(modifier, 0, sizeof(*modifier));
		modifier->set_priority = -1;
		modifier->script_timeout_sec = 10;
		list->count++;
		modifier->match_field = strdup(field ? json_string_value(field) : "MESSAGE");
		if (!modifier->match_field) return -1;
		modifier->negate = negate && json_is_true(negate);
		if (exact) {
			modifier->match_kind = MODIFIER_MATCH_EXACT;
			modifier->match_exact = strdup(json_string_value(exact));
			if (!modifier->match_exact) return -1;
		} else if (present) {
			modifier->match_kind = MODIFIER_MATCH_PRESENT;
			modifier->match_present = json_is_true(present);
		} else {
			modifier->match_kind = MODIFIER_MATCH_REGEX;
#ifdef HAVE_PCRE2
			{
				int error_code;
				PCRE2_SIZE error_offset;
				modifier->match_regex = pcre2_compile((PCRE2_SPTR)json_string_value(regex),
					PCRE2_ZERO_TERMINATED, 0, &error_code, &error_offset, NULL);
				if (!modifier->match_regex) {
					PCRE2_UCHAR message[128];
					pcre2_get_error_message(error_code, message, sizeof(message));
					fprintf(stderr, "recorder: invalid modifier regex in %s: %s at offset %zu\n",
						scope, (char *)message, (size_t)error_offset);
					return -1;
				}
				modifier->match_context = pcre2_match_context_create(NULL);
				if (!modifier->match_context) return -1;
				pcre2_set_match_limit(modifier->match_context, 100000);
				pcre2_set_depth_limit(modifier->match_context, 1000);
				(void)pcre2_jit_compile(modifier->match_regex, PCRE2_JIT_COMPLETE);
			}
#elif defined(HAVE_LIBC_REGEX)
			if (regcomp(&modifier->match_regex, json_string_value(regex), REG_EXTENDED | REG_NOSUB) != 0) {
				fprintf(stderr, "recorder: invalid libc regex in modifier %zu in %s\n", i, scope);
				return -1;
			}
			modifier->match_regex_compiled = 1;
#else
			fprintf(stderr, "recorder: modifier %zu in %s uses regex, but this build has no regex support\n", i, scope);
			return -1;
#endif
		}
		drop = json_object_get(item, "drop");
		if (drop && !json_is_boolean(drop)) {
			fprintf(stderr, "recorder: modifier %zu in %s has non-boolean drop\n", i, scope);
			return -1;
		}
		modifier->drop = drop && json_is_true(drop);
		set_priority = json_object_get(item, "set_priority");
		if (set_priority) {
			json_int_t value;
			if (!json_is_integer(set_priority) || (value = json_integer_value(set_priority)) < 0 || value > 7) {
				fprintf(stderr, "recorder: modifier %zu in %s has invalid set_priority\n", i, scope);
				return -1;
			}
			modifier->set_priority = (int)value;
		}
		rewrite = json_object_get(item, "rewrite");
		if (rewrite) {
			json_t *rewrite_field = json_object_get(rewrite, "field");
			json_t *replacement = json_object_get(rewrite, "replacement");
			if (!json_is_object(rewrite) || !json_is_string(rewrite_field) ||
				!json_is_string(replacement) || !json_string_value(rewrite_field)[0]) {
				fprintf(stderr, "recorder: modifier %zu in %s has invalid rewrite\n", i, scope);
				return -1;
			}
			modifier->rewrite_field = strdup(json_string_value(rewrite_field));
			modifier->replacement = strdup(json_string_value(replacement));
			if (!modifier->rewrite_field || !modifier->replacement) return -1;
			if (modifier->match_kind != MODIFIER_MATCH_REGEX) {
				fprintf(stderr, "recorder: modifier %zu in %s uses rewrite without a regex match\n", i, scope);
				return -1;
			}
			if (modifier->negate) {
				fprintf(stderr, "recorder: modifier %zu in %s uses rewrite with a negated match\n", i, scope);
				return -1;
			}
#ifndef HAVE_PCRE2
			fprintf(stderr, "recorder: modifier %zu in %s uses rewrite, which requires PCRE2 support\n", i, scope);
			return -1;
#endif
		}
		script = json_object_get(item, "script");
		if (script) {
			json_t *command = json_object_get(script, "command");
			json_t *run_on_replay = json_object_get(script, "run_on_replay");
			json_t *timeout = json_object_get(script, "timeout_sec");
			size_t command_count;
			size_t j;
			json_int_t timeout_value;

			if (!json_is_object(script) || !json_is_array(command) ||
				(json_array_size(command) == 0) ||
				(run_on_replay && !json_is_boolean(run_on_replay)) ||
				(timeout && (!json_is_integer(timeout) ||
					(timeout_value = json_integer_value(timeout)) < 1 || timeout_value > 86400))) {
				fprintf(stderr, "recorder: modifier %zu in %s has invalid script (expected command array, optional run_on_replay and timeout_sec)\n", i, scope);
				return -1;
			}
			command_count = json_array_size(command);
			modifier->script_command = calloc(command_count + 1, sizeof(char *));
			if (!modifier->script_command) return -1;
			modifier->script_command_count = command_count;
			for (j = 0; j < command_count; j++) {
				json_t *arg = json_array_get(command, j);
				if (!json_is_string(arg) || !json_string_value(arg)[0]) {
					fprintf(stderr, "recorder: modifier %zu in %s has a non-string or empty script argument\n", i, scope);
					return -1;
				}
				if (j == 0 && json_string_value(arg)[0] != '/') {
					fprintf(stderr, "recorder: modifier %zu in %s script command must use an absolute executable path\n", i, scope);
					return -1;
				}
				modifier->script_command[j] = strdup(json_string_value(arg));
				if (!modifier->script_command[j]) return -1;
			}
			modifier->script_run_on_replay = run_on_replay && json_is_true(run_on_replay);
			if (timeout) modifier->script_timeout_sec = (unsigned)json_integer_value(timeout);
		}
		if (!modifier->drop && modifier->set_priority < 0 && !modifier->rewrite_field &&
			!modifier->script_command) {
			fprintf(stderr, "recorder: modifier %zu in %s has no action\n", i, scope);
			return -1;
		}
	}
	return 0;
}

static int modifier_rewrite_field_is_supported(const char *field)
{
	return strcmp(field, "MESSAGE") == 0 || strcmp(field, "MESSAGE_ID") == 0 ||
		strcmp(field, "_HOSTNAME") == 0 || strcmp(field, "_SYSTEMD_UNIT") == 0 ||
		strcmp(field, "_COMM") == 0 || strcmp(field, "_EXE") == 0;
}

static int validate_modifier_list(const ModifierList *list, const RecorderConfig *cfg,
						  const char *scope)
{
	size_t i;
	(void)cfg;

	for (i = 0; i < list->count; i++) {
		const EntryModifier *modifier = &list->items[i];

		if (!modifier->rewrite_field) continue;
		if (!modifier_rewrite_field_is_supported(modifier->rewrite_field)) {
			fprintf(stderr, "recorder: modifier %zu in %s rewrites unsupported field '%s'\n",
				i, scope, modifier->rewrite_field);
			return -1;
		}
	}
	return 0;
}

static int modifier_list_uses_full_entries(const ModifierList *list)
{
	size_t i;

	for (i = 0; i < list->count; i++) {
		const char *field = list->items[i].rewrite_field;
		if (field && strcmp(field, "MESSAGE") != 0 && strcmp(field, "_SYSTEMD_UNIT") != 0) {
			return 1;
		}
	}
	return 0;
}

static int config_uses_full_entries(const RecorderConfig *cfg)
{
	size_t i;

	if (cfg->capture_all_fields || cfg->capture_message_id || cfg->capture_hostname ||
		cfg->capture_comm || cfg->capture_exe || cfg->capture_uid || cfg->capture_gid) {
		return 1;
	}
	if (modifier_list_uses_full_entries(&cfg->modifiers)) {
		return 1;
	}
	for (i = 0; i < cfg->group_count; i++) {
		if (modifier_list_uses_full_entries(&cfg->groups[i].modifiers)) {
			return 1;
		}
	}
	return 0;
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
		cfg->groups[i].durability_flush_frames = cfg->durability_flush_frames;
		cfg->groups[i].durability_flush_interval_sec = cfg->durability_flush_interval_sec;
		if (json_get_group_uint_default(group, cfg->groups[i].name,
										"durability_flush_frames",
										&cfg->groups[i].durability_flush_frames) != 0 ||
			json_get_group_uint_default(group, cfg->groups[i].name,
										"durability_flush_interval_sec",
										&cfg->groups[i].durability_flush_interval_sec) != 0) {
			return -1;
		}
		if (json_get_modifier_list(group, cfg->groups[i].name,
				&cfg->groups[i].modifiers) != 0) {
			return -1;
		}

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
		json_get_bool_default(root, "capture_all_fields", &cfg->capture_all_fields) != 0 ||
		json_get_string_array(root, "capture_fields_whitelist",
							&cfg->capture_fields_whitelist,
							&cfg->capture_fields_whitelist_count) != 0 ||
		json_get_string_array(root, "capture_fields_blacklist",
							&cfg->capture_fields_blacklist,
							&cfg->capture_fields_blacklist_count) != 0 ||
		json_get_bool_default(root, "sanitize_output", &cfg->sanitize_output) != 0 ||
		json_get_int_default(root, "durable_priority_max", -1, 7, &cfg->durable_priority_max) != 0 ||
		json_get_uint_default(root, "durability_flush_frames", &cfg->durability_flush_frames) != 0 ||
		json_get_uint_default(root, "durability_flush_interval_sec", &cfg->durability_flush_interval_sec) != 0 ||
		json_get_size_default(root, "log_max_bytes", &cfg->log_max_bytes) != 0 ||
		json_get_size_default(root, "segment_max_bytes", &cfg->segment_max_bytes) != 0 ||
		json_get_uint_default(root, "segment_max_age_sec", &cfg->segment_max_age_sec) != 0 ||
		json_get_bool_default(root, "compress_enabled", &cfg->compress_enabled) != 0 ||
		json_get_uint_default(root, "compress_min_frame_bytes", &cfg->compress_min_frame_bytes) != 0 ||
		json_get_bool_default(root, "compress_if_smaller", &cfg->compress_if_smaller) != 0 ||
		json_get_optional_nonempty_string(root, "encryption_public_key",
									  &cfg->encryption_public_key) != 0 ||
		json_get_static_dict_paths(root, cfg) != 0 ||
		json_get_modifier_list(root, "top-level config", &cfg->modifiers) != 0 ||
		json_get_priority_groups(root, cfg) != 0) {
		goto out;
	}
	if (cfg->encryption_public_key && access(cfg->encryption_public_key, R_OK) != 0) {
		fprintf(stderr, "recorder: encryption public key is not readable: %s\n",
				cfg->encryption_public_key);
		goto out;
	}
	if (validate_modifier_list(&cfg->modifiers, cfg, "top-level config") != 0) {
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

			if (validate_modifier_list(&cfg->groups[i].modifiers, cfg,
					cfg->groups[i].name) != 0) {
				goto out;
			}

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

static JournalField journal_get_field(sd_journal *j, const char *field)
{
	#ifndef HAVE_SYSTEMD
	(void)j;
	(void)field;
	return (JournalField){0};
	#else
	const void *data;
	size_t len;
	const char *eq;
	JournalField value = {0};

	if (!j || sd_journal_get_data(j, field, &data, &len) < 0) {
		return value;
	}
	eq = memchr(data, '=', len);
	if (!eq) {
		return value;
	}
	value.data = eq + 1;
	value.len = len - (size_t)(eq + 1 - (const char *)data);
	return value;
	#endif
}

static uint64_t journal_get_u64(sd_journal *j, const char *field)
{
	JournalField v = journal_get_field(j, field);
	char buf[32];
	size_t len;

	if (!v.data || v.len == 0) {
		return 0;
	}
	len = v.len < sizeof(buf) - 1 ? v.len : sizeof(buf) - 1;
	memcpy(buf, v.data, len);
	buf[len] = '\0';
	return strtoull(buf, NULL, 10);
}

static uint32_t journal_get_u32(sd_journal *j, const char *field)
{
	return (uint32_t)journal_get_u64(j, field);
}

static JournalField journal_field_nonempty(JournalField value)
{
	if (!value.data || value.len == 0) {
		value.data = NULL;
		value.len = 0;
	}
	return value;
}

static uint16_t clamp_u16(uint64_t value)
{
	return value > UINT16_MAX ? UINT16_MAX : (uint16_t)value;
}

static void copy_journal_field(char *dst, size_t dst_size, JournalField value)
{
	size_t len;

	if (dst_size == 0) {
		return;
	}
	if (!value.data || value.len == 0) {
		dst[0] = '\0';
		return;
	}
	len = value.len < dst_size - 1 ? value.len : dst_size - 1;
	memcpy(dst, value.data, len);
	dst[len] = '\0';
}

static void print_journal_field(JournalField value, int sanitize)
{
	size_t i;

	if (!value.data) {
		return;
	}
	for (i = 0; i < value.len; i++) {
		unsigned char c = (unsigned char)value.data[i];

		if (sanitize && ((c < 0x20 && c != '\n' && c != '\t') || c == 0x7f)) {
			printf("\\x%02X", c);
		} else {
			putchar(c);
		}
	}
}

static JournalField journal_basename_field(JournalField value)
{
	size_t i;

	if (!value.data || value.len == 0) {
		return value;
	}
	for (i = value.len; i > 0; i--) {
		if (value.data[i - 1] == '/') {
			value.data += i;
			value.len -= i;
			break;
		}
	}
	return value;
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

static int64_t clock_usec(clockid_t clock_id)
{
	struct timespec ts;

	if (clock_gettime(clock_id, &ts) != 0) return -1;
	return (int64_t)ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

/* BOOTTIME includes suspend time, preventing suspend/resume from looking
 * like a realtime jump. */
static void recorder_sample_clock(Recorder *r)
{
	int64_t realtime;
	int64_t boot1;
	int64_t boot2;
	int64_t offset;
	int64_t jump;

#ifdef CLOCK_BOOTTIME
	boot1 = clock_usec(CLOCK_BOOTTIME);
	realtime = clock_usec(CLOCK_REALTIME);
	boot2 = clock_usec(CLOCK_BOOTTIME);
#else
	boot1 = clock_usec(CLOCK_MONOTONIC);
	realtime = clock_usec(CLOCK_REALTIME);
	boot2 = boot1;
#endif
	if (realtime < 0 || boot1 < 0 || boot2 < 0) return;
	offset = realtime - (boot1 + (boot2 - boot1) / 2);
	if (!r->clock_offset_initialized) {
		r->last_clock_offset_usec = offset;
		r->clock_offset_initialized = 1;
		return;
	}
	jump = offset - r->last_clock_offset_usec;
	r->last_clock_offset_usec = offset;
	if (jump < -CLOCK_BACKWARD_JUMP_THRESHOLD_USEC ||
		jump > CLOCK_FORWARD_JUMP_THRESHOLD_USEC) {
		r->clock_jump_usec = jump;
		r->clock_jump_seq++;
		recorder_verbose_log(r, "detected realtime clock jump: diff=%" PRId64 " usec", jump);
	}
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
	snprintf(buf, bufsz, "%s/%s", g_log_dir, dir_name);
}

static void build_state_segment_seq_path(char *buf, size_t bufsz)
{
	snprintf(buf, bufsz, "%s/state/segment_seq", g_log_dir);
}

static void build_state_boots_path(char *buf, size_t bufsz)
{
	snprintf(buf, bufsz, "%s/state/boots", g_log_dir);
}

static void build_state_lock_path(char *buf, size_t bufsz)
{
	snprintf(buf, bufsz, "%s/state/store.lock", g_log_dir);
}

static void build_state_store_id_path(char *buf, size_t bufsz)
{
	snprintf(buf, bufsz, "%s/state/store-id", g_log_dir);
}

static int atomic_write_text_file(const char *path, const char *text);
static int segment_seq_from_name(const char *name, uint64_t *seq_out);
static int boot_registry_rebuild_from_segments(BootRegistry *boots);
static int persist_boot_state(const BootRegistry *boots);
static void for_each_segment_dir(void (*fn)(const char *dir_name, void *ctx), void *ctx);

static int ensure_store_id(void)
{
	char path[PATH_MAX];
	char text[32];
	char *raw;
	size_t raw_len = 0;
	uint64_t random_value;
	ssize_t n;

	build_state_store_id_path(path, sizeof(path));
	if (access(path, F_OK) == 0) {
		char *end = NULL;
		int valid;

		raw = slurp_file(path, &raw_len);
		if (!raw) {
			fprintf(stderr, "recorder: failed to read store ID %s\n", path);
			return -1;
		}
		errno = 0;
		(void)strtoull(raw, &end, 16);
		valid = errno == 0 && end && (*end == '\0' || *end == '\n') && raw_len == 17;
		free(raw);
		if (valid) {
			return 0;
		}
		fprintf(stderr, "recorder: invalid store ID %s\n", path);
		return -1;
	}
	if (errno != ENOENT) {
		fprintf(stderr, "recorder: failed to read store ID %s: %m\n", path);
		return -1;
	}
	do {
		n = getrandom(&random_value, sizeof(random_value), 0);
	} while (n < 0 && errno == EINTR);
	if (n != (ssize_t)sizeof(random_value)) {
		fprintf(stderr, "recorder: failed to generate store ID: %m\n");
		return -1;
	}
	snprintf(text, sizeof(text), "%016" PRIx64 "\n", random_value);
	if (atomic_write_text_file(path, text) != 0) {
		fprintf(stderr, "recorder: failed to persist store ID %s: %m\n", path);
		return -1;
	}
	return 0;
}

static void build_segment_path(char *buf, size_t bufsz, const char *dir_name,
								uint64_t seq)
{
	char dir[PATH_MAX];

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

static int path_is_tmpfs(const char *path)
{
	struct statfs fs;

	return statfs(path, &fs) == 0 &&
		(unsigned long)fs.f_type == (unsigned long)TMPFS_MAGIC;
}

static int select_runtime_cursor_path(char *path, size_t path_size)
{
	const char *user_runtime_dir = getenv("XDG_RUNTIME_DIR");

	if (path_is_tmpfs("/run") &&
		(access("/run/recorder", W_OK | X_OK) == 0 ||
		 access("/run", W_OK | X_OK) == 0)) {
		return snprintf(path, path_size, "%s", RECORDER_CURSOR_PATH) <
			(int)path_size ? 0 : -1;
	}
	if (user_runtime_dir && path_is_tmpfs(user_runtime_dir) &&
		access(user_runtime_dir, W_OK | X_OK) == 0) {
		return snprintf(path, path_size, "%s/recorder/journal.cursor",
				user_runtime_dir) < (int)path_size ? 0 : -1;
	}
	return -1;
}

static char *read_journal_cursor(const char *path)
{
	int fd;
	ssize_t n;
	char *cursor;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno != ENOENT) {
			fprintf(stderr, "recorder: failed to open cursor path %s: %m\n", path);
		}
		return NULL;
	}
	cursor = malloc(RECORDER_CURSOR_MAX_BYTES + 1);
	if (!cursor) {
		close(fd);
		return NULL;
	}
	n = read(fd, cursor, RECORDER_CURSOR_MAX_BYTES);
	close(fd);
	if (n <= 0 || !memchr(cursor, '\0', (size_t)n)) {
		free(cursor);
		return NULL;
	}
	cursor[n] = '\0';
	if (cursor[0] == '\0') {
		free(cursor);
		return NULL;
	}
	return cursor;
}

static int ensure_cursor_parent(const char *path)
{
	char parent[PATH_MAX];
	const char *slash = strrchr(path, '/');
	size_t len;

	if (!slash) {
		return 0;
	}
	len = (size_t)(slash - path);
	if (len == 0) {
		len = 1;
	}
	if (len >= sizeof(parent)) {
		return -1;
	}
	memcpy(parent, path, len);
	parent[len] = '\0';
	return mkdir_p(parent);
}

static int write_journal_cursor(const char *path, const char *cursor)
{
	struct stat st;
	ssize_t written;
	int fd;
	size_t len;

	len = strlen(cursor) + 1;
	if (len > RECORDER_CURSOR_MAX_BYTES) {
		return -1;
	}
	if (ensure_cursor_parent(path) != 0) {
		return -1;
	}
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0 && errno == ENOENT) {
		fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
	}
	if (fd < 0) {
		return -1;
	}
	if (fstat(fd, &st) != 0 || lseek(fd, 0, SEEK_SET) < 0) {
		close(fd);
		return -1;
	}
	written = write(fd, cursor, len);
	if (written != (ssize_t)len) {
		close(fd);
		return -1;
	}
	if (S_ISREG(st.st_mode) && ftruncate(fd, (off_t)len) != 0) {
		close(fd);
		return -1;
	}
	if (fsync(fd) != 0) {
		close(fd);
		return -1;
	}
	if (close(fd) != 0) {
		return -1;
	}
	return 0;
}

static int persist_journal_cursor_at(const Recorder *r, const char *path)
{
	if (!r->cursor_enabled || !r->pending_cursor) {
		return 0;
	}
	return write_journal_cursor(path, r->pending_cursor);
}

static int persist_journal_cursor(const Recorder *r)
{
	int rc = persist_journal_cursor_at(r, r->cursor_path);

	if (rc != 0) {
		fprintf(stderr, "recorder: failed to write journal cursor %s: %m\n",
				r->cursor_path);
	}
	return rc;
}

static int recorder_acquire_store_lock(void)
{
	char path[512];
	char dir[PATH_MAX];
	int fd;

	if (build_log_path(dir, sizeof(dir), "/state") != 0) {
		return -1;
	}
	if (mkdir_p(g_log_dir) != 0 || mkdir_p(dir) != 0) {
		return -1;
	}
	build_state_lock_path(path, sizeof(path));
	fd = open(path, O_CREAT | O_RDWR | O_CLOEXEC, 0644);
	if (fd < 0) {
		return -1;
	}
	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		if (errno == EWOULDBLOCK || errno == EAGAIN) {
			fprintf(stderr, "recorder: another recorder is already using %s\n", g_log_dir);
		} else {
			fprintf(stderr, "recorder: failed to lock %s: %m\n", path);
		}
		close(fd);
		return -1;
	}
	return fd;
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
		if (segment_scan_path(path, NULL, NULL, NULL, &header, &footer, &committed_end) != 0) {
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
			if ((header.flags & SEGMENT_FLAG_ENCRYPTED) == 0 &&
				(stat(idx_path, &idx_st) != 0 || idx_st.st_mtime < st.st_mtime)) {
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
	DIR *dir = opendir(g_log_dir);
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
		char state_dir[PATH_MAX];
		DIR *dir;
		struct dirent *de;

		if (build_log_path(state_dir, sizeof(state_dir), "/state") != 0) {
			return ctx.total;
		}
		dir = opendir(state_dir);
		if (dir) {
			while ((de = readdir(dir)) != NULL) {
				char path[PATH_MAX];
				char suffix[NAME_MAX + 8];
				struct stat st;

				if (snprintf(suffix, sizeof(suffix), "/state/%s", de->d_name) >=
					(int)sizeof(suffix) ||
					build_log_path(path, sizeof(path), suffix) != 0) {
					continue;
				}
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

			if (segment_scan_path(path, NULL, NULL, NULL, &header, &footer, &committed_end) == 0) {
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
		if (segment_scan_path(path, NULL, NULL, NULL, &header, &footer, &committed_end) != 0) {
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

static int journal_field_name_is_fixed(const char *name, size_t len)
{
	static const char *const fixed[] = {
		"MESSAGE", "MESSAGE_ID", "_SYSTEMD_UNIT", "_HOSTNAME",
		"_COMM", "_EXE", "_PID", "_UID", "_GID", "PRIORITY", "ERRNO",
	};
	size_t i;

	for (i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) {
		if (strlen(fixed[i]) == len && memcmp(name, fixed[i], len) == 0) {
			return 1;
		}
	}
	return 0;
}

static int journal_field_name_is_listed(const char *name, size_t len,
								char *const *list, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (strlen(list[i]) == len && memcmp(name, list[i], len) == 0) {
			return 1;
		}
	}
	return 0;
}

static int capture_extra_journal_fields(LogEntry *entry, sd_journal *j,
								const RecorderConfig *cfg)
{
	#ifndef HAVE_SYSTEMD
	(void)entry;
	(void)j;
	(void)cfg;
	return 0;
	#else
	const void *data;
	size_t len;

	if (!entry->extra_fields) {
		sd_journal_restart_data(j);
		while (sd_journal_enumerate_data(j, &data, &len) > 0) {
			const char *equals = memchr(data, '=', len);
			JournalExtraField *tmp;
			size_t name_len;

			if (!equals) {
				continue;
			}
			name_len = (size_t)(equals - (const char *)data);
			if (name_len == 0 || journal_field_name_is_fixed(data, name_len) ||
				(cfg->capture_fields_whitelist_count > 0 &&
				 !journal_field_name_is_listed(data, name_len,
						cfg->capture_fields_whitelist,
						cfg->capture_fields_whitelist_count)) ||
				journal_field_name_is_listed(data, name_len,
					cfg->capture_fields_blacklist,
					cfg->capture_fields_blacklist_count)) {
				continue;
			}
			tmp = realloc(entry->extra_fields,
					(entry->extra_field_count + 1) * sizeof(*tmp));
			if (!tmp) {
				return -1;
			}
			entry->extra_fields = tmp;
			entry->extra_fields[entry->extra_field_count].name.data = data;
			entry->extra_fields[entry->extra_field_count].name.len = name_len;
			entry->extra_fields[entry->extra_field_count].value.data =
				(const char *)equals + 1;
			entry->extra_fields[entry->extra_field_count].value.len =
				len - name_len - 1;
			entry->extra_field_count++;
		}
	}
	return 0;
	#endif
}

static void free_extra_journal_fields(LogEntry *entry)
{
	free(entry->extra_fields);
	entry->extra_fields = NULL;
	entry->extra_field_count = 0;
}

static void free_owned_journal_fields(LogEntry *entry)
{
	free(entry->owned_message);
	free(entry->owned_message_id);
	free(entry->owned_hostname);
	free(entry->owned_unit);
	free(entry->owned_comm);
	free(entry->owned_exe);
	entry->owned_message = NULL;
	entry->owned_message_id = NULL;
	entry->owned_hostname = NULL;
	entry->owned_unit = NULL;
	entry->owned_comm = NULL;
	entry->owned_exe = NULL;
}

static void free_log_entry(LogEntry *entry)
{
	free_extra_journal_fields(entry);
	free_owned_journal_fields(entry);
}

static JournalField journal_field_for_capture(sd_journal *j, const char *name,
									int capture_all_fields)
{
	JournalField value = journal_get_field(j, name);

	return capture_all_fields ? value : journal_field_nonempty(value);
}

static int extract_entry(LogEntry *entry, sd_journal *j, RecorderConfig *cfg,
								BootRegistry *boots)
{
	#ifndef HAVE_SYSTEMD
	(void)entry;
	(void)j;
	(void)cfg;
	(void)boots;
	return -1;
	#else
	JournalField boot_id = journal_field_nonempty(journal_get_field(j, "_BOOT_ID"));
	uint64_t monotonic_ts = 0;
	sd_id128_t monotonic_boot_id;

	memset(entry, 0, sizeof(*entry));
	copy_journal_field(entry->boot_id, sizeof(entry->boot_id), boot_id);
	sd_journal_get_realtime_usec(j, &entry->realtime_ts);
	if (sd_journal_get_monotonic_usec(j, &monotonic_ts, &monotonic_boot_id) >= 0) {
		entry->monotonic_ts = monotonic_ts;
	}
	entry->priority = (uint8_t)journal_get_u32(j, "PRIORITY");
	entry->errno_value = clamp_u16(journal_get_u64(j, "ERRNO"));
	entry->boot_seq = boot_registry_seq(boots, entry->boot_id[0] ? entry->boot_id : NULL);
	{
		BootEntry *boot = boot_registry_get(boots, entry->boot_id);
		if (boot && boot->first_realtime_ts == 0) {
			boot->first_realtime_ts = entry->realtime_ts;
		}
	}
	entry->message = journal_field_for_capture(j, "MESSAGE", cfg->capture_all_fields);
	entry->message_id = (cfg->capture_all_fields || cfg->capture_message_id) ?
						journal_field_for_capture(j, "MESSAGE_ID", cfg->capture_all_fields) : (JournalField){0};
	entry->unit = (cfg->capture_all_fields || cfg->capture_unit) ?
					journal_field_for_capture(j, "_SYSTEMD_UNIT", cfg->capture_all_fields) : (JournalField){0};
	entry->hostname = (cfg->capture_all_fields || cfg->capture_hostname) ?
						journal_field_for_capture(j, "_HOSTNAME", cfg->capture_all_fields) : (JournalField){0};
	entry->comm = (cfg->capture_all_fields || cfg->capture_comm) ?
					journal_field_for_capture(j, "_COMM", cfg->capture_all_fields) : (JournalField){0};
	entry->exe = (cfg->capture_all_fields || cfg->capture_exe) ?
					journal_field_for_capture(j, "_EXE", cfg->capture_all_fields) : (JournalField){0};
	entry->pid = (cfg->capture_all_fields || cfg->capture_pid || !config_uses_full_entries(cfg)) ?
		journal_get_u32(j, "_PID") : 0;
	entry->uid = (cfg->capture_all_fields || cfg->capture_uid) ? journal_get_u32(j, "_UID") : 0;
	entry->gid = (cfg->capture_all_fields || cfg->capture_gid) ? journal_get_u32(j, "_GID") : 0;
	if (cfg->capture_all_fields && capture_extra_journal_fields(entry, j, cfg) != 0) {
		free_extra_journal_fields(entry);
		return -1;
	}
	return 0;
	#endif
}

static int set_owned_log_field(JournalField *field, char **owned, const char *value)
{
	if (!value || !value[0]) return 0;
	*owned = strdup(value);
	if (!*owned) return -1;
	field->data = *owned;
	field->len = strlen(*owned);
	return 0;
}

static int extract_fallback_entry(LogEntry *entry, FallbackRecord *record,
					  RecorderConfig *cfg, BootRegistry *boots)
{
	BootEntry *boot;

	memset(entry, 0, sizeof(*entry));
	entry->realtime_ts = record->realtime_ts;
	entry->monotonic_ts = record->monotonic_ts;
	entry->priority = record->priority <= 7 ? record->priority : 5;
	entry->pid = (cfg->capture_all_fields || cfg->capture_pid || !config_uses_full_entries(cfg)) ?
		record->pid : 0;
	entry->uid = (cfg->capture_all_fields || cfg->capture_uid) ? record->uid : 0;
	entry->gid = (cfg->capture_all_fields || cfg->capture_gid) ? record->gid : 0;
	if (snprintf(entry->boot_id, sizeof(entry->boot_id), "%s", record->boot_id) >=
		(int)sizeof(entry->boot_id) ||
		set_owned_log_field(&entry->message, &entry->owned_message, record->message) != 0 ||
		((cfg->capture_all_fields || cfg->capture_hostname) &&
		 set_owned_log_field(&entry->hostname, &entry->owned_hostname, record->hostname) != 0) ||
		((cfg->capture_all_fields || cfg->capture_comm) &&
		 set_owned_log_field(&entry->comm, &entry->owned_comm, record->comm) != 0) ||
		((cfg->capture_all_fields || cfg->capture_exe) &&
		 set_owned_log_field(&entry->exe, &entry->owned_exe, record->exe) != 0)) {
		free_log_entry(entry);
		return -1;
	}
	entry->boot_seq = boot_registry_seq(boots, entry->boot_id[0] ? entry->boot_id : NULL);
	boot = boot_registry_get(boots, entry->boot_id);
	if (boot && boot->first_realtime_ts == 0) boot->first_realtime_ts = entry->realtime_ts;
	return 0;
}

static JournalField entry_field_for_modifier(const LogEntry *entry, const char *name)
{
	if (strcmp(name, "MESSAGE") == 0) return entry->message;
	if (strcmp(name, "MESSAGE_ID") == 0) return entry->message_id;
	if (strcmp(name, "_HOSTNAME") == 0) return entry->hostname;
	if (strcmp(name, "_SYSTEMD_UNIT") == 0) return entry->unit;
	if (strcmp(name, "_COMM") == 0) return entry->comm;
	if (strcmp(name, "_EXE") == 0) return entry->exe;
	return (JournalField){0};
}

#ifdef HAVE_PCRE2
static JournalField *entry_field_for_rewrite(LogEntry *entry, const char *name, char ***owned_out)
{
	if (strcmp(name, "MESSAGE") == 0) {
		*owned_out = &entry->owned_message;
		return &entry->message;
	}
	if (strcmp(name, "MESSAGE_ID") == 0) {
		*owned_out = &entry->owned_message_id;
		return &entry->message_id;
	}
	if (strcmp(name, "_HOSTNAME") == 0) {
		*owned_out = &entry->owned_hostname;
		return &entry->hostname;
	}
	if (strcmp(name, "_SYSTEMD_UNIT") == 0) {
		*owned_out = &entry->owned_unit;
		return &entry->unit;
	}
	if (strcmp(name, "_COMM") == 0) {
		*owned_out = &entry->owned_comm;
		return &entry->comm;
	}
	if (strcmp(name, "_EXE") == 0) {
		*owned_out = &entry->owned_exe;
		return &entry->exe;
	}
	return NULL;
}

static int build_regex_replacement(const EntryModifier *modifier, JournalField subject,
							 pcre2_match_data *match_data, char **result_out)
{
	PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
	uint32_t ovector_count = pcre2_get_ovector_count(match_data);
	const char *text = modifier->replacement;
	char *result = NULL;
	size_t result_len = 0;
	size_t i;

	for (i = 0; text[i]; i++) {
		const char *part = &text[i];
		size_t part_len = 1;
		if (text[i] == '$' && text[i + 1] == '$') {
			part = "$";
			part_len = 1;
			i++;
		} else if (text[i] == '$' && text[i + 1] >= '0' && text[i + 1] <= '9') {
			unsigned int group = (unsigned int)(text[++i] - '0');
			if (group >= ovector_count || ovector[2 * group] == PCRE2_UNSET) {
				continue;
			}
			part = subject.data + ovector[2 * group];
			part_len = ovector[2 * group + 1] - ovector[2 * group];
		}
		if (part_len > SIZE_MAX - result_len - 1) {
			free(result);
			return -1;
		}
		{
			char *tmp = realloc(result, result_len + part_len + 1);
			if (!tmp) {
				free(result);
				return -1;
			}
			result = tmp;
			memcpy(result + result_len, part, part_len);
			result_len += part_len;
			result[result_len] = '\0';
		}
	}
	if (!result) {
		result = strdup("");
		if (!result) return -1;
	}
	*result_out = result;
	return 0;
}

static int apply_modifier_list(const ModifierList *list, LogEntry *entry, sd_journal *j,
					void *recorder, int is_replay)
{
	size_t i;

	for (i = 0; i < list->count; i++) {
		const EntryModifier *modifier = &list->items[i];
		JournalField subject = entry_field_for_modifier(entry, modifier->match_field);
		pcre2_match_data *match_data = NULL;
		int match_result;
		int matched;

		if (!subject.data) subject = journal_get_field(j, modifier->match_field);
		if (modifier->match_kind == MODIFIER_MATCH_PRESENT) {
			matched = (subject.data != NULL) == modifier->match_present;
		} else if (modifier->match_kind == MODIFIER_MATCH_EXACT) {
			matched = subject.data && subject.len == strlen(modifier->match_exact) &&
				memcmp(subject.data, modifier->match_exact, subject.len) == 0;
		} else {
			matched = 0;
			if (subject.data) {
				match_data = pcre2_match_data_create_from_pattern(modifier->match_regex, NULL);
				if (!match_data) return -1;
				match_result = pcre2_match(modifier->match_regex, (PCRE2_SPTR)subject.data,
					subject.len, 0, 0, match_data, modifier->match_context);
				if (match_result < 0) {
					pcre2_match_data_free(match_data);
					if (match_result != PCRE2_ERROR_NOMATCH) return -1;
					match_data = NULL;
				} else {
					matched = 1;
				}
			}
		}
		if (modifier->negate) matched = !matched;
		if (!matched) continue;
		if (modifier->rewrite_field) {
			JournalField *target;
			char **owned;
			char *replacement;

			target = entry_field_for_rewrite(entry, modifier->rewrite_field, &owned);
			if (!target || build_regex_replacement(modifier, subject, match_data, &replacement) != 0) {
				pcre2_match_data_free(match_data);
				return -1;
			}
			free(*owned);
			*owned = replacement;
			target->data = replacement;
			target->len = strlen(replacement);
		}
		if (match_data) pcre2_match_data_free(match_data);
		if (modifier->set_priority >= 0) entry->priority = (uint8_t)modifier->set_priority;
		if (modifier->script_command)
			recorder_script_modifier_enqueue(recorder, modifier, entry, is_replay);
		if (modifier->drop) return 1;
	}
	return 0;
}
#elif defined(HAVE_LIBC_REGEX)
static int apply_modifier_list(const ModifierList *list, LogEntry *entry, sd_journal *j,
					void *recorder, int is_replay)
{
	size_t i;

	for (i = 0; i < list->count; i++) {
		const EntryModifier *modifier = &list->items[i];
		JournalField subject = entry_field_for_modifier(entry, modifier->match_field);
		if (!subject.data) subject = journal_get_field(j, modifier->match_field);
		int matched;

		if (modifier->match_kind == MODIFIER_MATCH_PRESENT) {
			matched = (subject.data != NULL) == modifier->match_present;
		} else if (modifier->match_kind == MODIFIER_MATCH_EXACT) {
			matched = subject.data && subject.len == strlen(modifier->match_exact) &&
				memcmp(subject.data, modifier->match_exact, subject.len) == 0;
		} else {
			char *text;

			matched = 0;
			if (subject.data && !memchr(subject.data, '\0', subject.len)) {
				text = malloc(subject.len + 1);
				if (!text) return -1;
				memcpy(text, subject.data, subject.len);
				text[subject.len] = '\0';
				matched = regexec(&modifier->match_regex, text, 0, NULL, 0) == 0;
				free(text);
			}
		}
		if (modifier->negate) matched = !matched;
		if (!matched) continue;
		if (modifier->set_priority >= 0) entry->priority = (uint8_t)modifier->set_priority;
		if (modifier->script_command)
			recorder_script_modifier_enqueue(recorder, modifier, entry, is_replay);
		if (modifier->drop) return 1;
	}
	return 0;
}
#else
static int apply_modifier_list(const ModifierList *list, LogEntry *entry, sd_journal *j,
					void *recorder, int is_replay)
{
	size_t i;

	for (i = 0; i < list->count; i++) {
		const EntryModifier *modifier = &list->items[i];
		JournalField subject = entry_field_for_modifier(entry, modifier->match_field);
		if (!subject.data) subject = journal_get_field(j, modifier->match_field);
		int matched;

		if (modifier->match_kind == MODIFIER_MATCH_PRESENT) {
			matched = (subject.data != NULL) == modifier->match_present;
		} else if (modifier->match_kind == MODIFIER_MATCH_EXACT) {
			matched = subject.data && subject.len == strlen(modifier->match_exact) &&
				memcmp(subject.data, modifier->match_exact, subject.len) == 0;
		} else {
			return -1;
		}
		if (modifier->negate) matched = !matched;
		if (!matched) continue;
		if (modifier->set_priority >= 0) entry->priority = (uint8_t)modifier->set_priority;
		if (modifier->script_command)
			recorder_script_modifier_enqueue(recorder, modifier, entry, is_replay);
		if (modifier->drop) return 1;
	}
	return 0;
}
#endif

static void recorder_print_received_entry(sd_journal *j, int sanitize_output)
{
	#ifndef HAVE_SYSTEMD
	(void)j;
	(void)sanitize_output;
	#else
	JournalField hostname = journal_field_nonempty(journal_get_field(j, "_HOSTNAME"));
	JournalField identifier = journal_field_nonempty(journal_get_field(j, "_COMM"));
	JournalField unit = journal_field_nonempty(journal_get_field(j, "_SYSTEMD_UNIT"));
	JournalField exe = journal_field_nonempty(journal_get_field(j, "_EXE"));
	JournalField message = journal_field_nonempty(journal_get_field(j, "MESSAGE"));
	uint64_t realtime_ts = 0;
	uint32_t pid = journal_get_u32(j, "_PID");
	char ts[32];
	time_t sec;
	struct tm tm;

	if (!identifier.data) {
		identifier = unit;
	}
	if (!identifier.data && exe.data) {
		identifier = journal_basename_field(exe);
	}
	sd_journal_get_realtime_usec(j, &realtime_ts);
	sec = (time_t)(realtime_ts / 1000000u);
	if (localtime_r(&sec, &tm)) {
		strftime(ts, sizeof(ts), "%b %d %H:%M:%S", &tm);
	} else {
		snprintf(ts, sizeof(ts), "%" PRIu64, realtime_ts);
	}
	printf("%s", ts);
	if (hostname.data) {
		printf(" ");
		print_journal_field(hostname, sanitize_output);
	}
	if (identifier.data && pid != 0) {
		printf(" ");
		print_journal_field(identifier, sanitize_output);
		printf("[%u]: ", pid);
		print_journal_field(message, sanitize_output);
		printf("\n");
	} else if (identifier.data) {
		printf(" ");
		print_journal_field(identifier, sanitize_output);
		printf(": ");
		print_journal_field(message, sanitize_output);
		printf("\n");
	} else {
		printf(" ");
		print_journal_field(message, sanitize_output);
		printf("\n");
	}
	fflush(stdout);
	#endif
}

static flatbuffers_string_ref_t create_journal_string(flatcc_builder_t *B,
																JournalField value)
{
	return value.data ? flatbuffers_string_create(B, value.data, value.len) : 0;
}

static flatbuffers_uint8_vec_ref_t create_journal_bytes(flatcc_builder_t *B,
												JournalField value)
{
	return flatbuffers_uint8_vec_create(B, (const uint8_t *)value.data, value.len);
}

static journal_FullEntry_ref_t serialize_entry(flatcc_builder_t *B, const LogEntry *entry)
{
	flatbuffers_string_ref_t message_ref = create_journal_string(B, entry->message);
	flatbuffers_string_ref_t message_id_ref = create_journal_string(B, entry->message_id);
	flatbuffers_string_ref_t unit_ref = create_journal_string(B, entry->unit);
	flatbuffers_string_ref_t hostname_ref = create_journal_string(B, entry->hostname);
	flatbuffers_string_ref_t comm_ref = create_journal_string(B, entry->comm);
	flatbuffers_string_ref_t exe_ref = create_journal_string(B, entry->exe);
	journal_Field_ref_t *extra_refs = NULL;
	journal_Field_vec_ref_t extra_vec = 0;
	size_t i;

	if (entry->extra_field_count > 0) {
		extra_refs = calloc(entry->extra_field_count, sizeof(*extra_refs));
		if (!extra_refs) {
			return 0;
		}
		for (i = 0; i < entry->extra_field_count; i++) {
			flatbuffers_string_ref_t name_ref = create_journal_string(
				B, entry->extra_fields[i].name);
			flatbuffers_uint8_vec_ref_t value_ref = create_journal_bytes(
				B, entry->extra_fields[i].value);

			if (!name_ref || !value_ref || journal_Field_start(B) != 0) {
				free(extra_refs);
				return 0;
			}
			journal_Field_name_add(B, name_ref);
			journal_Field_value_add(B, value_ref);
			extra_refs[i] = journal_Field_end(B);
			if (!extra_refs[i]) {
				free(extra_refs);
				return 0;
			}
		}
		extra_vec = journal_Field_vec_create(B, extra_refs,
				entry->extra_field_count);
		free(extra_refs);
		if (!extra_vec) {
			return 0;
		}
	}

	if (journal_FullEntry_start(B)) {
		return 0;
	}
	journal_FullEntry_realtime_ts_add(B, entry->realtime_ts);
	journal_FullEntry_monotonic_ts_add(B, entry->monotonic_ts);
	journal_FullEntry_priority_add(B, entry->priority);
	if (message_ref) journal_FullEntry_message_add(B, message_ref);
	if (message_id_ref) journal_FullEntry_message_id_add(B, message_id_ref);
	if (unit_ref) journal_FullEntry_unit_add(B, unit_ref);
	if (entry->pid) journal_FullEntry_pid_add(B, entry->pid);
	if (entry->uid) journal_FullEntry_uid_add(B, entry->uid);
	if (entry->gid) journal_FullEntry_gid_add(B, entry->gid);
	if (hostname_ref) journal_FullEntry_hostname_add(B, hostname_ref);
	if (comm_ref) journal_FullEntry_comm_add(B, comm_ref);
	if (exe_ref) journal_FullEntry_exe_add(B, exe_ref);
	if (entry->errno_value) journal_FullEntry_errno_add(B, entry->errno_value);
	if (extra_vec) journal_FullEntry_fields_add(B, extra_vec);
	return journal_FullEntry_end(B);
}

static journal_CompactEntry_ref_t serialize_compact_entry(flatcc_builder_t *B,
									const LogEntry *entry)
{
	flatbuffers_string_ref_t message_ref = create_journal_string(B, entry->message);
	flatbuffers_string_ref_t unit_ref = create_journal_string(B, entry->unit);

	if (journal_CompactEntry_start(B) != 0) {
		return 0;
	}
	journal_CompactEntry_realtime_ts_add(B, entry->realtime_ts);
	journal_CompactEntry_monotonic_ts_add(B, entry->monotonic_ts);
	journal_CompactEntry_priority_add(B, entry->priority);
	if (entry->pid) journal_CompactEntry_pid_add(B, entry->pid);
	if (message_ref) journal_CompactEntry_message_add(B, message_ref);
	if (unit_ref) journal_CompactEntry_unit_add(B, unit_ref);
	return journal_CompactEntry_end(B);
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
	char idx_path[512];
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
	if (r->config.encryption_public_key &&
		segment_encryptor_create(r->config.encryption_public_key, &w->encryptor) != 0) {
		fprintf(stderr, "recorder: failed to initialize encryption for segment %s\n",
				w->path);
		fclose(w->fp);
		unlink(w->tmp_path);
		w->fp = NULL;
		return -1;
	}

	memset(&header, 0, sizeof(header));
	header.segment_seq = w->segment_seq;
	header.boot_seq = entry->boot_seq;
	strncpy(header.boot_id, entry->boot_id, RECORDER_BOOT_ID_SIZE);
	current_timezone_string(header.timezone);
	header.first_realtime_ts = entry->realtime_ts;
	header.first_monotonic_ts = entry->monotonic_ts;
	if (!config_uses_full_entries(&r->config)) {
		header.flags |= SEGMENT_FLAG_COMPACT_ENTRIES;
	}
	if (w->encryptor) {
		header.flags |= SEGMENT_FLAG_ENCRYPTED;
	}
	if (r->config.groups[w->group_index].static_dict_path) {
		dict_buf = slurp_file(r->config.groups[w->group_index].static_dict_path, &dict_len);
		if (!dict_buf || dict_len == 0) {
			free(dict_buf);
			fclose(w->fp);
			unlink(w->tmp_path);
			segment_encryptor_free(w->encryptor);
			w->encryptor = NULL;
			w->fp = NULL;
			return -1;
		}
		header.flags |= SEGMENT_FLAG_HAS_STATIC_DICT;
	}
	if (segment_write_header(w->fp, &header, dict_buf, dict_len, w->encryptor) != 0) {
		fclose(w->fp);
		free(dict_buf);
		segment_encryptor_free(w->encryptor);
		w->encryptor = NULL;
		w->fp = NULL;
		return -1;
	}
	build_index_path(idx_path, sizeof(idx_path), w->group_name, w->segment_seq);
	if (index_writer_open(idx_path, header.segment_seq, header.flags, &w->index_writer) != 0) {
		fclose(w->fp);
		free(dict_buf);
		segment_encryptor_free(w->encryptor);
		w->encryptor = NULL;
		w->fp = NULL;
		unlink(w->tmp_path);
		return -1;
	}
	w->index_header = header;
	if (flush_and_sync_file(w->fp) != 0) {
		fclose(w->fp);
		index_writer_abort(w->index_writer, 1);
		w->index_writer = NULL;
		unlink(w->tmp_path);
		segment_encryptor_free(w->encryptor);
		w->encryptor = NULL;
		w->fp = NULL;
		return -1;
	}
	if (rename(w->tmp_path, w->path) != 0) {
		fclose(w->fp);
		index_writer_abort(w->index_writer, 1);
		w->index_writer = NULL;
		unlink(w->tmp_path);
		segment_encryptor_free(w->encryptor);
		w->encryptor = NULL;
		w->fp = NULL;
		return -1;
	}
	if (fsync_dir_path(dir) != 0) {
		fclose(w->fp);
		index_writer_abort(w->index_writer, 1);
		w->index_writer = NULL;
		segment_encryptor_free(w->encryptor);
		w->encryptor = NULL;
		w->fp = NULL;
		return -1;
	}

	strncpy(w->boot_id, header.boot_id, RECORDER_BOOT_ID_SIZE);
	w->boot_id[RECORDER_BOOT_ID_SIZE] = '\0';
	strncpy(w->timezone, header.timezone, sizeof(w->timezone) - 1);
	w->timezone[sizeof(w->timezone) - 1] = '\0';
	w->boot_seq = entry->boot_seq;
	{
		off_t pos = ftello(w->fp);
		if (pos < 0) {
			fclose(w->fp);
			index_writer_abort(w->index_writer, 1);
			w->index_writer = NULL;
			segment_encryptor_free(w->encryptor);
			w->encryptor = NULL;
			w->fp = NULL;
			w->open = 0;
			return -1;
		}
		w->bytes_written = (uint64_t)pos;
	}
	w->entry_count = 0;
	w->first_realtime_ts = entry->realtime_ts;
	w->first_monotonic_ts = entry->monotonic_ts;
	w->last_realtime_ts = entry->realtime_ts;
	w->last_monotonic_ts = entry->monotonic_ts;
	w->clock_jump_seen_seq = r->clock_jump_seq;
	w->opened_mono_sec = monotonic_now_sec();
	w->last_chunk_flush_mono_sec = w->opened_mono_sec;
	w->last_sync_mono_sec = w->opened_mono_sec;
	w->unsynced_frames = 0;
	w->compress_enabled = r->config.compress_enabled;
	w->compress_min_frame_bytes = r->config.compress_min_frame_bytes;
	w->compress_if_smaller = r->config.compress_if_smaller;
	w->use_compact_entries = !config_uses_full_entries(&r->config);
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
	journal_FullEntry_vec_ref_t vec;
	journal_CompactEntry_vec_ref_t default_vec;
	size_t raw_size;
	void *raw_buf = NULL;
	void *stored_buf = NULL;
	size_t stored_size = 0;
	uint32_t raw_size32;
	uint32_t stored_size32;
	uint32_t frame_flags = SEGMENT_FRAME_FLAG_NONE;
	SegmentFrameInfo frame_info;
	off_t frame_offset;
	int rv = -1;

	if (!w->builder_live || w->count == 0) {
		return 0;
	}

	if (w->use_compact_entries) {
		default_vec = journal_CompactEntry_vec_create(&w->builder,
				w->compact_entries, w->count);
		if (!default_vec || !journal_DefaultChunk_create_as_root(&w->builder, default_vec)) {
			goto out;
		}
	} else {
		vec = journal_FullEntry_vec_create(&w->builder, w->entries, w->count);
		if (!vec || !journal_Chunk_create_as_root(&w->builder, vec)) {
			goto out;
		}
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
	frame_offset = ftello(w->fp);
	if (frame_offset < 0) goto out;
	if (segment_write_frame(w->fp, w->encryptor, frame_flags, stored_buf,
						stored_size32, raw_size32) != 0) {
		goto out;
	}
	if (fflush(w->fp) != 0) goto out;
	memset(&frame_info, 0, sizeof(frame_info));
	frame_info.flags = frame_flags;
	frame_info.stored_len = stored_size32;
	frame_info.uncompressed_len = raw_size32;
	frame_info.file_offset = (uint64_t)frame_offset;
	frame_info.frame_len = 16u + stored_size32 + 4u + (w->encryptor ? 16u : 0u);
	if (index_writer_append(w->index_writer, &w->index_header, &frame_info,
						raw_buf, raw_size) != 0) goto out;
	{
		off_t pos = ftello(w->fp);
		if (pos < 0) goto out;
		w->bytes_written = (uint64_t)pos;
	}
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
	w->last_chunk_flush_mono_sec = monotonic_now_sec();
	return rv;
}

static int writer_close_segment(Recorder *r, PriorityWriter *w, const char *reason,
							uint32_t rotation_reason)
{
	SegmentFooter footer;

	if (!w->open) {
		return 0;
	}
	if (writer_flush_chunk(w) != 0) {
		return -1;
	}
	memset(&footer, 0, sizeof(footer));
	footer.rotation_reason = rotation_reason;
	footer.entry_count = w->entry_count;
	footer.last_realtime_ts = w->last_realtime_ts;
	footer.last_monotonic_ts = w->last_monotonic_ts;
	if (segment_write_footer(w->fp, &footer) != 0) {
		fclose(w->fp);
		segment_encryptor_free(w->encryptor);
		w->encryptor = NULL;
		w->fp = NULL;
		w->open = 0;
		return -1;
	}
	if (flush_and_sync_file(w->fp) != 0) {
		fclose(w->fp);
		segment_encryptor_free(w->encryptor);
		w->encryptor = NULL;
		w->fp = NULL;
		w->open = 0;
		return -1;
	}
	{
		off_t pos = ftello(w->fp);
		if (pos >= 0) w->bytes_written = (uint64_t)pos;
	}
	if (index_writer_close(w->index_writer, w->bytes_written) != 0) {
		w->index_writer = NULL;
		fclose(w->fp);
		segment_encryptor_free(w->encryptor);
		w->encryptor = NULL;
		w->fp = NULL;
		w->open = 0;
		return -1;
	}
	w->index_writer = NULL;
	fclose(w->fp);
	segment_encryptor_free(w->encryptor);
	w->encryptor = NULL;
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

static int recorder_close_writer(Recorder *r, PriorityWriter *w, const char *reason,
							uint32_t rotation_reason)
{
	if (writer_close_segment(r, w, reason, rotation_reason) != 0) {
		return -1;
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

static int recorder_init(Recorder *r, sd_journal *j, const RecorderConfig *cfg,
						int verbose, const char *cursor_path,
						const char *journal_namespace, int journal_mode)
{
	char runtime_cursor_path[PATH_MAX];
	uint8_t prio;
	uint64_t scanned_next;
	uint64_t persisted_next;
	BootRegistry rebuilt_boots;

	memset(r, 0, sizeof(*r));
	r->j = j;
	r->config = *cfg;
	r->verbose = verbose;
	r->startup_catchup = 1;
	if (script_worker_create(256, 2, &r->script_worker) != 0) {
		fprintf(stderr, "recorder: script modifiers disabled (worker unavailable)\n");
		r->script_worker = NULL;
	}
	r->persistent_cursor_enabled = journal_mode;
	if (snprintf(r->persistent_cursor_path, sizeof(r->persistent_cursor_path),
				 "%s/state/journal.cursor%s%s", g_log_dir,
				 journal_namespace ? "." : "",
				 journal_namespace ? journal_namespace : "") >=
		(int)sizeof(r->persistent_cursor_path)) {
		return -1;
	}
	if (!journal_mode) {
		/* Datagram and kmsg inputs have no replayable source cursor. */
	} else if (cursor_path) {
		if (snprintf(r->cursor_path, sizeof(r->cursor_path), "%s", cursor_path) >=
			(int)sizeof(r->cursor_path)) {
			return -1;
		}
		r->cursor_enabled = 1;
	} else if (select_runtime_cursor_path(r->cursor_path,
										 sizeof(r->cursor_path)) == 0) {
		r->cursor_enabled = 1;
		if (journal_namespace &&
			snprintf(runtime_cursor_path, sizeof(runtime_cursor_path), "%s.%s",
					 r->cursor_path, journal_namespace) >=
			(int)sizeof(runtime_cursor_path)) {
			return -1;
		}
		if (journal_namespace) {
			strcpy(r->cursor_path, runtime_cursor_path);
		}
		if (verbose >= 1) {
			fprintf(stderr, "recorder: using journal cursor path %s\n", r->cursor_path);
		}
	}
	if (journal_mode && verbose >= 1 && !r->cursor_enabled) {
		fprintf(stderr, "recorder: /run is not tmpfs; journal cursor checkpoint disabled\n");
	}
	boot_registry_init(&r->boots);
	if (mkdir_p(g_log_dir) != 0 || ensure_store_id() != 0) {
		return -1;
	}
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
									entry->boot_id[0] ? entry->boot_id : "(empty)",
									w->boot_id[0] ? w->boot_id : "(empty)");
			break;
		case ROTATE_REASON_TIMEZONE:
			current_timezone_string(timezone);
			recorder_verbose_log(r,
									"rotating segment seq=%" PRIu64 " group=%s because %s (current_timezone=%s, segment_timezone=%s)",
									w->segment_seq, w->group_name, reason_text,
									timezone, w->timezone);
			break;
		case ROTATE_REASON_CLOCK_BACKWARD:
		case ROTATE_REASON_CLOCK_FORWARD:
			recorder_verbose_log(r,
									"rotating segment seq=%" PRIu64 " group=%s because %s (jump=%" PRId64 " usec)",
									w->segment_seq, w->group_name, reason_text,
									decision.delta_diff);
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
		if (recorder_close_writer(r, w, reason_text, (uint32_t)decision.reason) != 0) {
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
	journal_FullEntry_ref_t entry_ref;
	journal_CompactEntry_ref_t default_entry_ref;

	if (group_index < 0 || (size_t)group_index >= r->config.group_count) {
		return -1;
	}
	w = &r->writers[group_index];

	if (recorder_ensure_writer(r, entry) != 0) {
		return -1;
	}

	B = writer_builder(w);
	if (w->use_compact_entries) {
		default_entry_ref = serialize_compact_entry(B, entry);
		if (!default_entry_ref) {
			return -1;
		}
		w->compact_entries[w->count++] = default_entry_ref;
	} else {
		entry_ref = serialize_entry(B, entry);
		if (!entry_ref) {
			return -1;
		}
		w->entries[w->count++] = entry_ref;
	}
	w->entry_count++;
	w->last_realtime_ts = entry->realtime_ts;
	w->last_monotonic_ts = entry->monotonic_ts;

	if (w->count == CHUNK_SIZE) {
		if (writer_flush_chunk(w) != 0) {
			return -1;
		}
	}
	if (w->bytes_written >= recorder_segment_limit(r)) {
		if (recorder_close_writer(r, w, "segment size limit reached after write",
							SEGMENT_ROTATION_REASON_SIZE) != 0) {
			return -1;
		}
	}
	return 0;
}

static int script_add_field(json_t *json, const char *name, JournalField field,
						const char **env_names, const char **env_values,
						size_t *env_count, char **owned_values, size_t *owned_count)
{
	char *value;
	json_t *json_value;

	if (!field.data || field.len == 0 || field.len > 64u * 1024u ||
		memchr(field.data, '\0', field.len) != NULL || *env_count >= 32) {
		return 0;
	}
	value = strndup(field.data, field.len);
	if (!value || *owned_count >= 32) {
		free(value);
		return -1;
	}
	json_value = json_stringn(field.data, field.len);
	if (!json_value) {
		free(value);
		return 0;
	}
	if (json_object_set_new(json, name, json_value) != 0) {
		json_decref(json_value);
		free(value);
		return -1;
	}
	env_names[*env_count] = name;
	env_values[*env_count] = value;
	(*env_count)++;
	owned_values[(*owned_count)++] = value;
	return 0;
}

static void recorder_script_modifier_enqueue(Recorder *recorder,
								 const EntryModifier *modifier,
								 const LogEntry *entry, int is_replay)
{
	json_t *json;
	char *payload = NULL;
	const char *env_names[32];
	const char *env_values[32];
	char *owned_values[32] = {0};
	char numeric[8][32];
	size_t env_count = 0, owned_count = 0, i;
	ScriptJobSpec spec;

	if (!recorder || !recorder->script_worker || !modifier || !entry ||
		(is_replay && !modifier->script_run_on_replay)) return;
	json = json_object();
	if (!json) return;
	for (i = 0; i < 8; i++) numeric[i][0] = '\0';
	snprintf(numeric[0], sizeof(numeric[0]), "%" PRIu64, entry->realtime_ts);
	snprintf(numeric[1], sizeof(numeric[1]), "%" PRIu64, entry->monotonic_ts);
	snprintf(numeric[2], sizeof(numeric[2]), "%u", entry->boot_seq);
	snprintf(numeric[3], sizeof(numeric[3]), "%u", entry->priority);
	snprintf(numeric[4], sizeof(numeric[4]), "%u", entry->pid);
	snprintf(numeric[5], sizeof(numeric[5]), "%u", entry->uid);
	snprintf(numeric[6], sizeof(numeric[6]), "%u", entry->gid);
	{
		const char *names[] = {"REC_REALTIME_TS", "REC_MONOTONIC_TS", "REC_BOOT_SEQ",
			"REC_PRIORITY", "REC_PID", "REC_UID", "REC_GID"};
		for (i = 0; i < 7; i++) {
			JournalField f = {(const char *)numeric[i], strlen(numeric[i])};
			if (script_add_field(json, names[i], f, env_names, env_values,
								&env_count, owned_values, &owned_count) != 0) goto out;
		}
	}
	{
		const char *names[] = {"REC_BOOT_ID", "REC_MESSAGE", "REC_MESSAGE_ID",
			"REC_HOSTNAME", "REC_SYSTEMD_UNIT", "REC_COMM", "REC_EXE"};
		JournalField fields[] = {
			{entry->boot_id, strlen(entry->boot_id)}, entry->message, entry->message_id,
			entry->hostname, entry->unit, entry->comm, entry->exe
		};
		for (i = 0; i < 7; i++) {
			if (script_add_field(json, names[i], fields[i], env_names, env_values,
								&env_count, owned_values, &owned_count) != 0) goto out;
		}
	}
	json_object_set_new(json, "REC_IS_REPLAY", json_boolean(is_replay));
	payload = json_dumps(json, JSON_COMPACT);
	if (!payload) goto out;
	memset(&spec, 0, sizeof(spec));
	spec.argv = (const char *const *)modifier->script_command;
	spec.argc = modifier->script_command_count;
	spec.json_payload = payload;
	spec.env_names = env_names;
	spec.env_values = env_values;
	spec.env_count = env_count;
	spec.timeout_sec = modifier->script_timeout_sec;
	if (script_worker_submit(recorder->script_worker, &spec) != 0 && recorder->verbose) {
		recorder_verbose_log(recorder, "script modifier queue is full or rejected the job");
	}
out:
	free(payload);
	json_decref(json);
	for (i = 0; i < owned_count; i++) free(owned_values[i]);
}

static int apply_entry_modifiers(Recorder *r, LogEntry *entry, int is_replay)
{
	unsigned seen_priorities;
	unsigned reroutes;
	int result;

	result = apply_modifier_list(&r->config.modifiers, entry, r->j, r, is_replay);
	if (result != 0) return result;
	seen_priorities = 1u << entry->priority;
	for (reroutes = 0; reroutes < MAX_MODIFIER_REROUTES; reroutes++) {
		int group_index = r->config.priority_to_group[entry->priority];
		uint8_t previous_priority = entry->priority;

		if (group_index < 0 || (size_t)group_index >= r->config.group_count) return -1;
		result = apply_modifier_list(&r->config.groups[group_index].modifiers, entry, r->j, r, is_replay);
		if (result != 0) return result;
		if (entry->priority == previous_priority) return 0;
		if (seen_priorities & (1u << entry->priority)) {
			fprintf(stderr, "recorder: dropping entry because modifiers reroute priority in a loop\n");
			return 1;
		}
		seen_priorities |= 1u << entry->priority;
	}
	fprintf(stderr, "recorder: dropping entry after too many modifier priority reroutes\n");
	return 1;
}

static size_t recorder_step_fallback(Recorder *r)
{
	FallbackRecord record;
	LogEntry entry;
	uint32_t boot_count_before;
	int source_result;
	int modifier_result;

	source_result = fallback_source_next(r->fallback, &record,
							 (int)(JOURNAL_WAIT_USEC / 1000u));
	if (source_result < 0) {
		fprintf(stderr, "recorder: fallback source failed: %m\n");
		g_shutdown = 1;
		return 0;
	}
	if (source_result == 0) return 0;
	boot_count_before = r->boots.count;
	if (extract_fallback_entry(&entry, &record, &r->config, &r->boots) != 0) {
		fprintf(stderr, "recorder: failed to extract fallback log fields\n");
		fallback_record_destroy(&record);
		return 0;
	}
	fallback_record_destroy(&record);
	if (r->boots.count != boot_count_before) persist_boot_state(&r->boots);
	modifier_result = apply_entry_modifiers(r, &entry, r->startup_catchup);
	if (modifier_result < 0) {
		fprintf(stderr, "recorder: failed to apply entry modifiers\n");
		free_log_entry(&entry);
		return 0;
	}
	if (modifier_result == 0 && recorder_submit_entry(r, &entry) != 0) {
		fprintf(stderr, "recorder: failed to store entry\n");
		free_log_entry(&entry);
		return 0;
	}
	if (r->verbose >= 2 && entry.message.data) {
		fprintf(stderr, "recorder: fallback priority=%u pid=%u message=%.*s\n",
			entry.priority, entry.pid, (int)entry.message.len, entry.message.data);
	}
	free_log_entry(&entry);
	return 1;
}

static size_t recorder_step(Recorder *r)
{
	size_t processed = 0;

	if (r->fallback) return recorder_step_fallback(r);

	#ifdef HAVE_SYSTEMD
	while (processed < CHUNK_SIZE) {
		LogEntry entry;
		uint32_t boot_count_before = r->boots.count;
		int modifier_result;

		if (!r->current_entry_pending) {
			if (sd_journal_next(r->j) <= 0) {
				break;
			}
		} else {
			r->current_entry_pending = 0;
		}
		if (extract_entry(&entry, r->j, &r->config, &r->boots) != 0) {
			fprintf(stderr, "recorder: failed to extract journal fields\n");
			free_log_entry(&entry);
			break;
		}
		if (r->boots.count != boot_count_before) {
			persist_boot_state(&r->boots);
		}
		modifier_result = apply_entry_modifiers(r, &entry, r->startup_catchup);
		if (modifier_result < 0) {
			fprintf(stderr, "recorder: failed to apply entry modifiers\n");
			free_log_entry(&entry);
			break;
		}
		if (modifier_result == 0 && recorder_submit_entry(r, &entry) != 0) {
			fprintf(stderr, "recorder: failed to store entry\n");
			free_log_entry(&entry);
			break;
		}
		if (r->cursor_enabled || r->persistent_cursor_enabled) {
			char *cursor = NULL;

			if (sd_journal_get_cursor(r->j, &cursor) < 0) {
				fprintf(stderr, "recorder: failed to read journal cursor\n");
				free_log_entry(&entry);
				break;
			}
			free(r->pending_cursor);
			r->pending_cursor = cursor;
		}
		if (r->verbose >= 2) {
			recorder_print_received_entry(r->j, r->config.sanitize_output);
		}
		free_log_entry(&entry);
		processed++;
	}
	#endif
	return processed;
}

static int recorder_flush_all(Recorder *r, int checkpoint_cursor)
{
	size_t i;

	for (i = 0; i < r->config.group_count; i++) {
		if (writer_flush_chunk(&r->writers[i]) != 0 ||
			writer_sync_if_due(&r->writers[i]) != 0) {
			return -1;
		}
	}
	if (checkpoint_cursor && persist_journal_cursor(r) != 0) {
		fprintf(stderr, "recorder: failed to persist journal cursor; disabling cursor checkpointing\n");
		r->cursor_enabled = 0;
	}
	return 0;
}

static void recorder_shutdown(Recorder *r)
{
	size_t i;
	uint64_t max_last_rt[MAX_PRIORITY_GROUPS] = {0};
	char boot_ids[MAX_PRIORITY_GROUPS][RECORDER_BOOT_ID_SIZE + 1];
	int close_ok = 1;

	memset(boot_ids, 0, sizeof(boot_ids));

	fprintf(stderr, "recorder: flushing pending entries\n");
	if (recorder_flush_all(r, 0) != 0) {
		fprintf(stderr, "recorder: failed to flush pending entries during shutdown\n");
		close_ok = 0;
	}
	for (i = 0; i < r->config.group_count; i++) {
		if (r->writers[i].open &&
			r->writers[i].last_realtime_ts > max_last_rt[i]) {
			max_last_rt[i] = r->writers[i].last_realtime_ts;
		}
		strncpy(boot_ids[i], r->writers[i].boot_id, RECORDER_BOOT_ID_SIZE);
		boot_ids[i][RECORDER_BOOT_ID_SIZE] = '\0';
		if (r->writers[i].open) {
			if (writer_close_segment(r, &r->writers[i], "shutdown",
							SEGMENT_ROTATION_REASON_SHUTDOWN) != 0) {
				close_ok = 0;
			}
		}
	}
	if (r->script_worker) {
		script_worker_destroy(r->script_worker);
		r->script_worker = NULL;
	}
	if (close_ok && r->pending_cursor) {
		if (r->cursor_enabled && persist_journal_cursor(r) != 0) {
			fprintf(stderr, "recorder: failed to persist volatile journal cursor during shutdown\n");
			r->cursor_enabled = 0;
		}
		if (r->persistent_cursor_enabled &&
			write_journal_cursor(r->persistent_cursor_path, r->pending_cursor) != 0) {
			fprintf(stderr, "recorder: failed to persist journal cursor to %s: %m\n",
					r->persistent_cursor_path);
		}
	}
	free(r->pending_cursor);
	r->pending_cursor = NULL;
	/* Index files are appended while segments are written and finalized on close. */
	retention_enforce(r);
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
	fprintf(stderr, "recorder: shutdown complete\n");
}

int main(int argc, char **argv)
{
	sd_journal *j = NULL;
	FallbackSource fallback_source;
	Recorder r;
	RecorderConfig cfg;
	const char *cfg_path;
	const char *cursor_path = NULL;
	const char *journal_namespace = NULL;
	const char *syslog_path = NULL;
	const char *kernel_path = "/dev/kmsg";
	int verbose = 0;
	int start_last = 0;
	int fallback_mode = 0;
	int fallback_open = 0;
	int lock_fd = -1;
	int opt;
	static const struct option options[] = {
		{ "last", no_argument, NULL, '1' },
		{ "cursor", required_argument, NULL, 'c' },
		{ "namespace", required_argument, NULL, 'n' },
		{ "log-dir", required_argument, NULL, 'l' },
		{ "fallback", no_argument, NULL, 'F' },
		{ "syslog-socket", required_argument, NULL, 's' },
		{ "kernel-path", required_argument, NULL, 'k' },
		{ "no-kmsg", no_argument, NULL, 'K' },
		{ NULL, 0, NULL, 0 }
	};

	opterr = 0;
	while ((opt = getopt_long(argc, argv, "v1c:n:l:Fs:k:K", options, NULL)) != -1) {
		switch (opt) {
		case 'v':
			verbose++;
			break;
		case '1':
			start_last = 1;
			break;
		case 'c':
			cursor_path = optarg;
			break;
		case 'n':
			journal_namespace = optarg;
			break;
		case 'l':
			if (snprintf(g_log_dir, sizeof(g_log_dir), "%s", optarg) >=
				(int)sizeof(g_log_dir)) {
				fprintf(stderr, "recorder: log directory path is too long\n");
				return 1;
			}
			break;
		case 'F':
			fallback_mode = 1;
			break;
		case 's':
			fallback_mode = 1;
			syslog_path = optarg;
			break;
		case 'k':
			fallback_mode = 1;
			kernel_path = optarg;
			break;
		case 'K':
			fallback_mode = 1;
			kernel_path = NULL;
			break;
		default:
			fprintf(stderr, "usage: %s [-v] [-1|--last] [-c PATH|--cursor PATH] [-n NAME|--namespace NAME] [-l PATH|--log-dir PATH] [--fallback [--syslog-socket PATH] [--kernel-path PATH|--no-kmsg]]\n", argv[0]);
			return 1;
		}
	}
	if (fallback_mode && (start_last || cursor_path || journal_namespace)) {
		fprintf(stderr, "recorder: --last, --cursor, and --namespace require journald input\n");
		return 1;
	}
	#ifndef HAVE_SYSTEMD
	if (!fallback_mode) {
		fprintf(stderr, "recorder: this build has no journald input; use --fallback\n");
		return 1;
	}
	#endif

	recorder_config_init(&cfg);
	cfg_path = recorder_config_path();
	if (recorder_config_load(&cfg, cfg_path) != 0) {
		recorder_config_destroy(&cfg);
		return 1;
	}

	lock_fd = recorder_acquire_store_lock();
	if (lock_fd < 0) {
		recorder_config_destroy(&cfg);
		return 1;
	}

	if (fallback_mode) {
		if (!syslog_path) syslog_path = "/dev/log";
		if (fallback_source_open(&fallback_source, syslog_path, kernel_path) != 0) {
			fprintf(stderr, "recorder: failed to open fallback sources: %m\n");
			close(lock_fd);
			recorder_config_destroy(&cfg);
			return 1;
		}
		fallback_open = 1;
	}
	#ifdef HAVE_SYSTEMD
	else if ((journal_namespace ?
		sd_journal_open_namespace(&j, journal_namespace, SD_JOURNAL_LOCAL_ONLY) :
		sd_journal_open(&j, SD_JOURNAL_LOCAL_ONLY)) < 0) {
		fprintf(stderr, "recorder: failed to open journal\n");
		close(lock_fd);
		recorder_config_destroy(&cfg);
		return 1;
	}
	#endif

	if (install_signal_handlers() != 0) {
		fprintf(stderr, "recorder: failed to install signal handlers\n");
		#ifdef HAVE_SYSTEMD
		if (j) sd_journal_close(j);
		#endif
		if (fallback_open) fallback_source_close(&fallback_source);
		close(lock_fd);
		recorder_config_destroy(&cfg);
		return 1;
	}

	if (recorder_init(&r, j, &cfg, verbose, cursor_path, journal_namespace,
				  !fallback_mode) != 0) {
		fprintf(stderr, "recorder: failed to initialize cursor path\n");
		script_worker_destroy(r.script_worker);
		#ifdef HAVE_SYSTEMD
		if (j) sd_journal_close(j);
		#endif
		if (fallback_open) fallback_source_close(&fallback_source);
		close(lock_fd);
		recorder_config_destroy(&cfg);
		return 1;
	}
	r.fallback = fallback_mode ? &fallback_source : NULL;
	#ifdef HAVE_SYSTEMD
	if (!fallback_mode && !start_last) {
		char *cursor = r.cursor_enabled ? read_journal_cursor(r.cursor_path) : NULL;
		int resumed = 0;

		if (!cursor && r.persistent_cursor_enabled) {
			cursor = read_journal_cursor(r.persistent_cursor_path);
		}
		if (cursor) {
			int n = sd_journal_seek_cursor(j, cursor);

			if (n >= 0) {
				n = sd_journal_next(j);
				if (n >= 0) {
					int matches = sd_journal_test_cursor(j, cursor);

					if (matches < 0) {
						fprintf(stderr, "recorder: failed to verify journal cursor; importing available entries\n");
					} else {
						/* seek_cursor + next selects the saved entry itself. */
						if (matches > 0) {
							n = sd_journal_next(j);
						}
						if (n >= 0) {
							r.current_entry_pending = n > 0;
							resumed = 1;
						}
					}
				} else {
					fprintf(stderr, "recorder: failed to seek after journal cursor; importing available entries\n");
				}
			} else {
				fprintf(stderr, "recorder: journal cursor is unavailable; importing available entries\n");
			}
			free(cursor);
		}
		if (!resumed) {
			if (sd_journal_seek_head(j) < 0) {
				fprintf(stderr, "recorder: failed to seek to journal head\n");
				sd_journal_close(j);
				close(lock_fd);
				recorder_config_destroy(&cfg);
				return 1;
			}
		}
	} else if (!fallback_mode && start_last) {
		if (sd_journal_seek_tail(j) < 0) {
			fprintf(stderr, "recorder: failed to seek to journal tail\n");
			sd_journal_close(j);
			close(lock_fd);
			recorder_config_destroy(&cfg);
			return 1;
		}
		r.current_entry_pending = sd_journal_previous(j) > 0;
	} else if (!fallback_mode && sd_journal_seek_head(j) < 0) {
		fprintf(stderr, "recorder: failed to seek to journal head\n");
		sd_journal_close(j);
		close(lock_fd);
		recorder_config_destroy(&cfg);
		return 1;
	}
	#endif

	while (!g_shutdown) {
		recorder_sample_clock(&r);
		size_t n = recorder_step(&r);
		if (r.startup_catchup && n > 0)
			r.startup_replayed_entries += n;

		if (n > 0) {
			if (recorder_flush_all(&r, 1) != 0) {
				fprintf(stderr, "recorder: failed to flush stored entries\n");
				break;
			}
			continue;
		}
		if (recorder_flush_all(&r, 1) != 0) {
			fprintf(stderr, "recorder: failed to flush stored entries\n");
			break;
		}
		if (r.startup_catchup && r.verbose >= 1) {
			printf("recorder: replay complete; replayed %" PRIu64 " entries\n",
				r.startup_replayed_entries);
			fflush(stdout);
		}
		r.startup_catchup = 0;
		#ifdef HAVE_SYSTEMD
		if (!fallback_mode && sd_journal_wait(j, JOURNAL_WAIT_USEC) < 0) {
			break;
		}
		#endif
	}

	recorder_shutdown(&r);
	#ifdef HAVE_SYSTEMD
	if (j) sd_journal_close(j);
	#endif
	if (fallback_open) fallback_source_close(&fallback_source);
	close(lock_fd);
	recorder_config_destroy(&cfg);
	return 0;
}
