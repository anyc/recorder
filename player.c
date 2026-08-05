#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <dirent.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "segment.h"

typedef struct {
	char path[512];
	uint64_t segment_seq;
} SegmentPath;

typedef struct {
	const char *unit_filter;
	const char *boot_id_filter;
	uint32_t boot_seq_filter;
	int have_boot_seq_filter;
	uint64_t since_ts;
	uint64_t until_ts;
	int have_since;
	int have_until;
	uint64_t min_frame_offset;
	size_t printed_entries;
} PrintContext;

typedef struct {
	char path[512];
	uint64_t committed_end;
} SeenSegment;

typedef struct {
	const char *path;
	const char *dir_path;
	const char *file_path;
	const char *unit_filter;
	const char *boot_filter;
	const char *since_arg;
	const char *until_arg;
	const char *boot_id_filter;
	uint32_t boot_seq_filter;
	int have_boot_seq_filter;
	uint64_t since_ts;
	uint64_t until_ts;
	int have_since;
	int have_until;
	int follow;
	int list_boots;
} PlayerOptions;

typedef struct {
	uint32_t boot_seq;
	char boot_id[RECORDER_BOOT_ID_SIZE + 1];
	uint64_t first_realtime_ts;
	uint64_t last_realtime_ts;
	uint64_t first_segment_seq;
} BootInfo;

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

static int parse_u32(const char *text, uint32_t *value_out)
{
	char *end = NULL;
	unsigned long value;

	if (!text || text[0] == '-') {
		return -1;
	}
	errno = 0;
	value = strtoul(text, &end, 10);
	if (errno != 0 || !end || *end != '\0' || value > UINT32_MAX) {
		return -1;
	}
	*value_out = (uint32_t)value;
	return 0;
}

static int parse_i32(const char *text, int *value_out)
{
	char *end = NULL;
	long value;

	errno = 0;
	value = strtol(text, &end, 10);
	if (errno != 0 || !end || *end != '\0' || value < INT32_MIN || value > INT32_MAX) {
		return -1;
	}
	*value_out = (int)value;
	return 0;
}

static int boot_matches(const PrintContext *pc, const SegmentHeader *header)
{
	size_t filter_len;

	if (pc->have_boot_seq_filter) {
		return header->boot_seq == pc->boot_seq_filter;
	}
	if (!pc->boot_id_filter) {
		return 1;
	}
	filter_len = strlen(pc->boot_id_filter);
	return filter_len > 0 &&
			strncmp(header->boot_id, pc->boot_id_filter, filter_len) == 0;
}

static int entry_matches(const PrintContext *pc, journal_Entry_table_t entry)
{
	const char *unit;
	uint64_t realtime_ts = journal_Entry_realtime_ts(entry);

	if (pc->have_since && realtime_ts < pc->since_ts) {
		return 0;
	}
	if (pc->have_until && realtime_ts > pc->until_ts) {
		return 0;
	}
	if (!pc->unit_filter) {
		return 1;
	}
	unit = journal_Entry_unit(entry);
	return unit && strcmp(unit, pc->unit_filter) == 0;
}

static void format_realtime(uint64_t realtime_ts, char *buf, size_t bufsz)
{
	time_t sec = (time_t)(realtime_ts / 1000000u);
	struct tm tm;

	if (localtime_r(&sec, &tm)) {
		strftime(buf, bufsz, "%b %d %H:%M:%S", &tm);
	} else {
		snprintf(buf, bufsz, "%" PRIu64, realtime_ts);
	}
}

static void format_realtime_full(uint64_t realtime_ts, char *buf, size_t bufsz)
{
	time_t sec = (time_t)(realtime_ts / 1000000u);
	struct tm tm;

	if (localtime_r(&sec, &tm)) {
		strftime(buf, bufsz, "%Y-%m-%d %H:%M:%S", &tm);
	} else {
		snprintf(buf, bufsz, "%" PRIu64, realtime_ts);
	}
}

static int parse_datetime_fields(const char *text, struct tm *tm)
{
	int year;
	int mon;
	int day;
	int hour = 0;
	int min = 0;
	int sec = 0;
	char extra;
	int n;

	memset(tm, 0, sizeof(*tm));
	n = sscanf(text, "%d-%d-%d %d:%d:%d%c", &year, &mon, &day, &hour, &min, &sec, &extra);
	if (n != 6) {
		n = sscanf(text, "%d-%d-%dT%d:%d:%d%c", &year, &mon, &day, &hour, &min, &sec, &extra);
	}
	if (n != 6) {
		n = sscanf(text, "%d-%d-%d %d:%d%c", &year, &mon, &day, &hour, &min, &extra);
		if (n != 5) {
			n = sscanf(text, "%d-%d-%dT%d:%d%c", &year, &mon, &day, &hour, &min, &extra);
		}
	}
	if (n != 5 && n != 6) {
		n = sscanf(text, "%d-%d-%d%c", &year, &mon, &day, &extra);
		if (n != 3) {
			return -1;
		}
	}
	if (year < 1970 || mon < 1 || mon > 12 || day < 1 || day > 31 ||
		hour < 0 || hour > 23 || min < 0 || min > 59 || sec < 0 || sec > 60) {
		return -1;
	}
	tm->tm_year = year - 1900;
	tm->tm_mon = mon - 1;
	tm->tm_mday = day;
	tm->tm_hour = hour;
	tm->tm_min = min;
	tm->tm_sec = sec;
	tm->tm_isdst = -1;
	return 0;
}

static int parse_time_arg(const char *text, uint64_t *value_out)
{
	char *end = NULL;
	unsigned long long value;
	struct tm tm;
	time_t sec;

	errno = 0;
	value = strtoull(text, &end, 10);
	if (errno == 0 && end && *end == '\0') {
		if (value < 1000000000000ull) {
			value *= 1000000ull;
		}
		*value_out = (uint64_t)value;
		return 0;
	}
	if (parse_datetime_fields(text, &tm) != 0) {
		return -1;
	}
	sec = mktime(&tm);
	if (sec < 0) {
		return -1;
	}
	*value_out = (uint64_t)sec * 1000000ull;
	return 0;
}

static void print_entry(journal_Entry_table_t entry)
{
	const char *hostname = journal_Entry_hostname(entry);
	const char *comm = journal_Entry_comm(entry);
	const char *unit = journal_Entry_unit(entry);
	const char *exe = journal_Entry_exe(entry);
	const char *message = journal_Entry_message(entry);
	const char *identifier = comm;
	const char *slash;
	char ts[32];
	uint32_t pid = journal_Entry_pid(entry);
	int have_hostname;
	int have_identifier;

	format_realtime(journal_Entry_realtime_ts(entry), ts, sizeof(ts));
	if (!identifier || !identifier[0]) {
		identifier = unit;
	}
	if ((!identifier || !identifier[0]) && exe && exe[0]) {
		slash = strrchr(exe, '/');
		identifier = slash ? slash + 1 : exe;
	}
	if (!message) {
		message = "";
	}
	have_hostname = hostname && hostname[0] && strcmp(hostname, "-") != 0;
	have_identifier = identifier && identifier[0];
	printf("%s", ts);
	if (have_hostname) {
		printf(" %s", hostname);
	}
	if (have_identifier && pid != 0) {
		printf(" %s[%u]: %s\n", identifier, pid, message);
	} else if (have_identifier) {
		printf(" %s: %s\n", identifier, message);
	} else {
		printf(" %s\n", message);
	}
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

	(void)chunk_size;

	if (frame->file_offset < pc->min_frame_offset || !boot_matches(pc, header)) {
		return 0;
	}
	for (i = 0; i < n; i++) {
		journal_Entry_table_t e = journal_Entry_vec_at(entries, i);

		if (entry_matches(pc, e)) {
			print_entry(e);
			pc->printed_entries++;
		}
	}
	return 0;
}

static int scan_segment_file(const char *path, const PlayerOptions *opts,
								uint64_t min_frame_offset, uint64_t *committed_end_out)
{
	SegmentHeader header;
	SegmentFooter footer;
	PrintContext ctx;
	size_t committed_end = 0;

	memset(&ctx, 0, sizeof(ctx));
	ctx.unit_filter = opts->unit_filter;
	ctx.boot_id_filter = opts->boot_id_filter;
	ctx.boot_seq_filter = opts->boot_seq_filter;
	ctx.have_boot_seq_filter = opts->have_boot_seq_filter;
	ctx.since_ts = opts->since_ts;
	ctx.until_ts = opts->until_ts;
	ctx.have_since = opts->have_since;
	ctx.have_until = opts->have_until;
	ctx.min_frame_offset = min_frame_offset;
	if (segment_scan_path(path, print_frame, &ctx, &header, &footer, &committed_end) != 0) {
		fprintf(stderr, "player: failed to scan %s\n", path);
		return -1;
	}
	if (committed_end_out) {
		*committed_end_out = (uint64_t)committed_end;
	}
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

static void sort_boots(BootInfo *boots, size_t count)
{
	size_t i;
	size_t j;

	for (i = 0; i < count; i++) {
		for (j = i + 1; j < count; j++) {
			if (boots[j].boot_seq < boots[i].boot_seq) {
				BootInfo tmp = boots[i];
				boots[i] = boots[j];
				boots[j] = tmp;
			}
		}
	}
}

static BootInfo *find_boot(BootInfo *boots, size_t count, uint32_t boot_seq,
							const char *boot_id)
{
	size_t i;

	for (i = 0; i < count; i++) {
		if (boots[i].boot_seq == boot_seq ||
			strncmp(boots[i].boot_id, boot_id, RECORDER_BOOT_ID_SIZE) == 0) {
			return &boots[i];
		}
	}
	return NULL;
}

static int add_boot(BootInfo **boots, size_t *count, size_t *cap,
					const SegmentHeader *header, const SegmentFooter *footer)
{
	BootInfo *boot = find_boot(*boots, *count, header->boot_seq, header->boot_id);
	BootInfo *tmp;
	uint64_t last_realtime_ts = footer->last_realtime_ts ?
								footer->last_realtime_ts : header->first_realtime_ts;

	if (boot) {
		if (header->first_realtime_ts != 0 &&
			(boot->first_realtime_ts == 0 ||
				header->first_realtime_ts < boot->first_realtime_ts)) {
			boot->first_realtime_ts = header->first_realtime_ts;
		}
		if (last_realtime_ts > boot->last_realtime_ts) {
			boot->last_realtime_ts = last_realtime_ts;
		}
		if (header->segment_seq < boot->first_segment_seq) {
			boot->first_segment_seq = header->segment_seq;
		}
		return 0;
	}
	if (*count == *cap) {
		size_t new_cap = *cap ? (*cap * 2) : 16;

		tmp = realloc(*boots, new_cap * sizeof(**boots));
		if (!tmp) {
			return -1;
		}
		*boots = tmp;
		*cap = new_cap;
	}
	memset(&(*boots)[*count], 0, sizeof((*boots)[*count]));
	(*boots)[*count].boot_seq = header->boot_seq;
	strncpy((*boots)[*count].boot_id, header->boot_id, RECORDER_BOOT_ID_SIZE);
	(*boots)[*count].boot_id[RECORDER_BOOT_ID_SIZE] = '\0';
	(*boots)[*count].first_realtime_ts = header->first_realtime_ts;
	(*boots)[*count].last_realtime_ts = last_realtime_ts;
	(*boots)[*count].first_segment_seq = header->segment_seq;
	(*count)++;
	return 0;
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

static SeenSegment *find_seen_segment(SeenSegment *seen, size_t seen_count,
										const char *path)
{
	size_t i;

	for (i = 0; i < seen_count; i++) {
		if (strcmp(seen[i].path, path) == 0) {
			return &seen[i];
		}
	}
	return NULL;
}

static int remember_seen_segment(SeenSegment **seen, size_t *seen_count,
									size_t *seen_cap, const char *path,
									uint64_t committed_end)
{
	SeenSegment *item = find_seen_segment(*seen, *seen_count, path);
	SeenSegment *tmp;

	if (item) {
		item->committed_end = committed_end;
		return 0;
	}
	if (*seen_count == *seen_cap) {
		size_t new_cap = *seen_cap ? (*seen_cap * 2) : 32;

		tmp = realloc(*seen, new_cap * sizeof(**seen));
		if (!tmp) {
			return -1;
		}
		*seen = tmp;
		*seen_cap = new_cap;
	}
	strncpy((*seen)[*seen_count].path, path, sizeof((*seen)[*seen_count].path) - 1);
	(*seen)[*seen_count].path[sizeof((*seen)[*seen_count].path) - 1] = '\0';
	(*seen)[*seen_count].committed_end = committed_end;
	(*seen_count)++;
	return 0;
}

static int collect_log_segments(const char *root_path, SegmentPath **items,
								size_t *count, size_t *cap)
{
	struct stat st;
	DIR *dir;
	struct dirent *de;
	int rc = 0;

	if (stat(root_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
		fprintf(stderr, "player: %s is not a directory\n", root_path);
		return -1;
	}
	dir = opendir(root_path);
	if (!dir) {
		perror("opendir");
		return -1;
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
				add_segment_file(items, count, cap, path, seq) != 0) {
				rc = -1;
				break;
			}
		} else if (S_ISDIR(child_st.st_mode) && valid_group_name(de->d_name)) {
			if (collect_segments_in_dir(path, items, count, cap) != 0) {
				rc = -1;
				break;
			}
		}
	}
	closedir(dir);
	return rc;
}

static int collect_boots_from_segments(const SegmentPath *items, size_t count,
										BootInfo **boots, size_t *boot_count)
{
	size_t cap = 0;
	size_t i;

	*boots = NULL;
	*boot_count = 0;
	for (i = 0; i < count; i++) {
		SegmentHeader header;
		SegmentFooter footer;
		size_t committed_end;

		if (segment_scan_path(items[i].path, NULL, NULL, &header, &footer,
								&committed_end) != 0) {
			fprintf(stderr, "player: failed to scan %s\n", items[i].path);
			free(*boots);
			*boots = NULL;
			*boot_count = 0;
			return -1;
		}
		if (add_boot(boots, boot_count, &cap, &header, &footer) != 0) {
			free(*boots);
			*boots = NULL;
			*boot_count = 0;
			return -1;
		}
	}
	sort_boots(*boots, *boot_count);
	return 0;
}

static int collect_boots_for_path(const char *path, BootInfo **boots,
									size_t *boot_count)
{
	SegmentPath *items = NULL;
	size_t count = 0;
	size_t cap = 0;
	struct stat st;
	int rc;

	if (stat(path, &st) != 0) {
		perror("stat");
		return -1;
	}
	if (S_ISDIR(st.st_mode)) {
		rc = collect_log_segments(path, &items, &count, &cap);
		if (rc != 0) {
			free(items);
			return -1;
		}
		sort_segment_files(items, count);
	} else {
		uint64_t seq = 0;

		segment_seq_from_name(path, &seq);
		if (add_segment_file(&items, &count, &cap, path, seq) != 0) {
			return -1;
		}
	}
	rc = collect_boots_from_segments(items, count, boots, boot_count);
	free(items);
	return rc;
}

static int print_boots(const PlayerOptions *opts)
{
	BootInfo *boots;
	size_t boot_count;
	size_t i;

	if (collect_boots_for_path(opts->path, &boots, &boot_count) != 0) {
		return 1;
	}
	for (i = 0; i < boot_count; i++) {
		char first[32];
		char last[32];
		int idx = (int)i - (int)boot_count + 1;

		format_realtime_full(boots[i].first_realtime_ts, first, sizeof(first));
		format_realtime_full(boots[i].last_realtime_ts, last, sizeof(last));
		printf("%3d %10u %s %s - %s\n", idx, boots[i].boot_seq,
				boots[i].boot_id, first, last);
	}
	free(boots);
	return 0;
}

static int resolve_boot_filter(PlayerOptions *opts)
{
	int offset;
	BootInfo *boots;
	size_t boot_count;
	size_t idx;

	opts->boot_id_filter = opts->boot_filter;
	opts->have_boot_seq_filter = 0;
	if (!opts->boot_filter) {
		return 0;
	}
	if (parse_i32(opts->boot_filter, &offset) == 0 && offset < 0) {
		if (collect_boots_for_path(opts->path, &boots, &boot_count) != 0) {
			return -1;
		}
		if ((size_t)(-offset) >= boot_count) {
			fprintf(stderr, "player: boot offset %d is out of range\n", offset);
			free(boots);
			return -1;
		}
		idx = boot_count - 1u + offset;
		opts->boot_seq_filter = boots[idx].boot_seq;
		opts->have_boot_seq_filter = 1;
		opts->boot_id_filter = NULL;
		free(boots);
		return 0;
	}
	if (parse_u32(opts->boot_filter, &opts->boot_seq_filter) == 0) {
		opts->have_boot_seq_filter = 1;
		opts->boot_id_filter = NULL;
	}
	return 0;
}

static int scan_log_once(const PlayerOptions *opts, SeenSegment **seen,
							size_t *seen_count, size_t *seen_cap)
{
	SegmentPath *items = NULL;
	size_t count = 0;
	size_t cap = 0;
	size_t i;
	int rc = 0;

	if (collect_log_segments(opts->path, &items, &count, &cap) != 0) {
		return 1;
	}
	sort_segment_files(items, count);
	for (i = 0; i < count; i++) {
		SeenSegment *seen_item = find_seen_segment(*seen, *seen_count, items[i].path);
		uint64_t min_offset = seen_item ? seen_item->committed_end : 0;
		uint64_t committed_end = min_offset;

		if (scan_segment_file(items[i].path, opts, min_offset, &committed_end) != 0 ||
			remember_seen_segment(seen, seen_count, seen_cap, items[i].path, committed_end) != 0) {
			rc = 1;
			break;
		}
	}
	free(items);
	return rc;
}

static int scan_log_root(const PlayerOptions *opts)
{
	SeenSegment *seen = NULL;
	size_t seen_count = 0;
	size_t seen_cap = 0;
	int rc;

	do {
		rc = scan_log_once(opts, &seen, &seen_count, &seen_cap);
		if (rc != 0 || !opts->follow) {
			break;
		}
		fflush(stdout);
		sleep(1);
	} while (1);
	free(seen);
	return rc;
}

static void usage(const char *prog)
{
	fprintf(stderr,
			"usage: %s [-f] [-D DIR|-i FILE] [-u UNIT] [-b BOOT_ID|BOOT_SEQ|-N] "
			"[--since TIME] [--until TIME] [--list-boots]\n",
			prog);
	fprintf(stderr, "       TIME is usec, seconds, YYYY-MM-DD, or YYYY-MM-DD HH:MM[:SS]\n");
}

static int parse_options(int argc, char **argv, PlayerOptions *opts)
{
	int i;

	memset(opts, 0, sizeof(*opts));
	for (i = 1; i < argc; i++) {
		const char *arg = argv[i];

		if (strcmp(arg, "-f") == 0) {
			opts->follow = 1;
		} else if (strcmp(arg, "-D") == 0) {
			if (++i >= argc) {
				return -1;
			}
			opts->dir_path = argv[i];
		} else if (strncmp(arg, "-D", 2) == 0 && arg[2] != '\0') {
			opts->dir_path = arg + 2;
		} else if (strcmp(arg, "-i") == 0) {
			if (++i >= argc) {
				return -1;
			}
			opts->file_path = argv[i];
		} else if (strncmp(arg, "-i", 2) == 0 && arg[2] != '\0') {
			opts->file_path = arg + 2;
		} else if (strcmp(arg, "-u") == 0) {
			if (++i >= argc) {
				return -1;
			}
			opts->unit_filter = argv[i];
		} else if (strncmp(arg, "-u", 2) == 0 && arg[2] != '\0') {
			opts->unit_filter = arg + 2;
		} else if (strcmp(arg, "-b") == 0) {
			if (++i >= argc) {
				return -1;
			}
			opts->boot_filter = argv[i];
		} else if (strncmp(arg, "-b", 2) == 0 && arg[2] != '\0') {
			opts->boot_filter = arg + 2;
		} else if (strcmp(arg, "--list-boots") == 0) {
			opts->list_boots = 1;
		} else if (strcmp(arg, "--since") == 0) {
			if (++i >= argc) {
				return -1;
			}
			opts->since_arg = argv[i];
		} else if (strncmp(arg, "--since=", 8) == 0) {
			opts->since_arg = arg + 8;
		} else if (strcmp(arg, "--until") == 0) {
			if (++i >= argc) {
				return -1;
			}
			opts->until_arg = argv[i];
		} else if (strncmp(arg, "--until=", 8) == 0) {
			opts->until_arg = arg + 8;
		} else if (arg[0] == '-') {
			return -1;
		} else {
			return -1;
		}
	}
	if (opts->dir_path && opts->file_path) {
		return -1;
	}
	opts->path = opts->file_path ? opts->file_path :
					(opts->dir_path ? opts->dir_path : LOG_DIR);
	if (opts->since_arg) {
		if (parse_time_arg(opts->since_arg, &opts->since_ts) != 0) {
			fprintf(stderr, "player: invalid --since value: %s\n", opts->since_arg);
			return -1;
		}
		opts->have_since = 1;
	}
	if (opts->until_arg) {
		if (parse_time_arg(opts->until_arg, &opts->until_ts) != 0) {
			fprintf(stderr, "player: invalid --until value: %s\n", opts->until_arg);
			return -1;
		}
		opts->have_until = 1;
	}
	if (opts->have_since && opts->have_until && opts->since_ts > opts->until_ts) {
		fprintf(stderr, "player: --since is after --until\n");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	PlayerOptions opts;
	struct stat st;

	if (parse_options(argc, argv, &opts) != 0) {
		usage(argv[0]);
		return 1;
	}

	if (stat(opts.path, &st) != 0) {
		perror("stat");
		return 1;
	}
	if (opts.list_boots) {
		return print_boots(&opts);
	}
	if (resolve_boot_filter(&opts) != 0) {
		return 1;
	}
	if (S_ISDIR(st.st_mode)) {
		return scan_log_root(&opts);
	}
	if (opts.dir_path) {
		fprintf(stderr, "player: -D path is not a directory: %s\n", opts.path);
		return 1;
	}
	if (opts.file_path && !S_ISREG(st.st_mode)) {
		fprintf(stderr, "player: -i path is not a file: %s\n", opts.path);
		return 1;
	}
	if (opts.follow) {
		fprintf(stderr, "player: -f requires a log directory\n");
		return 1;
	}
	return scan_segment_file(opts.path, &opts, 0, NULL) == 0 ? 0 : 1;
}
