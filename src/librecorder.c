#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "librecorder.h"
#include "index.h"
#include "segment.h"

typedef struct SegmentPath SegmentPath;
typedef struct IteratorSource IteratorSource;

enum {
	ITERATOR_STATE_NONE = 0,
	ITERATOR_STATE_FORWARD = 1,
	ITERATOR_STATE_REVERSE = -1,
	ITERATOR_STATE_FOLLOW = 2,
	ITERATOR_STATE_CURSOR_PENDING = 3,
};

struct RecorderPlayer {
	char *path;
	int inotify_fd;
	int reliable_fd;
	int path_is_directory;
	uint64_t store_id;
	int have_store_id;
	struct StoredEntry *entries;
	size_t entry_count;
	size_t entry_capacity;
	size_t current;
	int lazy_history;
	int history_initialized;
	SegmentPath *history_paths;
	unsigned char *history_loaded;
	size_t history_count;
	char *data;
	SegmentDecryptor *decryptor;
	int repair_indexes;
	int force_repair_indexes;
	char *unit_filter;
	struct FollowSegment *follow_segments;
	size_t follow_count;
	size_t follow_capacity;
	int follow_initialized;
	int follow_pending;
	int follow_topology_pending;
	const struct StoredEntry *current_entry_ptr;
	int current_valid;
	IteratorSource *sources;
	size_t source_count;
	size_t current_source;
	int iterator_state;
};

typedef struct StoredEntry {
	RecorderEntry entry;
	char *group;
	char *boot_id;
	char *hostname;
	char *comm;
	char *unit;
	char *exe;
	char *message;
	char *message_id;
	RecorderField *fields;
} StoredEntry;

typedef struct {
	rec_player_entry_cb callback;
	void *userdata;
	uint64_t min_frame_offset;
	char group[64];
} ScanContext;

struct SegmentPath {
	char path[512];
	uint64_t segment_seq;
};

struct IteratorSource {
	char group[64];
	SegmentPath *segments;
	size_t segment_count;
	size_t segment_capacity;
	size_t segment_index;
	size_t frame_count;
	size_t frame_index;
	int segment_scan_fallback;
	IndexReader *index_reader;
	char index_reader_path[512];
	SegmentFrameReader *frame_reader;
	char frame_reader_path[512];
	StoredEntry *entries;
	size_t entry_count;
	size_t entry_capacity;
	ssize_t entry_index;
	int ready;
};

typedef struct FollowSegment {
	char group[64];
	char path[512];
	uint64_t segment_seq;
	uint64_t committed_end;
} FollowSegment;

static FollowSegment *find_follow_segment(RecorderPlayer *reader, const char *path);
static int remember_follow_segment(RecorderPlayer *reader, const char *path,
								   uint64_t segment_seq, uint64_t committed_end);
static void iterator_reset(RecorderPlayer *reader);
static void source_clear_frame(IteratorSource *source);
static int source_has_current(const IteratorSource *source);
static int source_add_segment(IteratorSource *source, const SegmentPath *path);
static int source_load_index(RecorderPlayer *reader, IteratorSource *source);
static int source_load_indexed_from(RecorderPlayer *reader, IteratorSource *source,
								size_t frame_index, int direction);
static int source_load_frame(RecorderPlayer *reader, IteratorSource *source,
							 size_t frame_index, int direction);
static int source_load_segment_fallback(RecorderPlayer *reader,
									IteratorSource *source, int direction);
static int source_advance(RecorderPlayer *reader, IteratorSource *source, int direction);
static int iterator_initialize(RecorderPlayer *reader, int direction);

static int valid_group_name(const char *name)
{
	size_t i;

	if (!name || !name[0] || strcmp(name, "state") == 0) return 0;
	for (i = 0; name[i]; i++) {
		unsigned char ch = (unsigned char)name[i];
		if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
				(ch >= '0' && ch <= '9') || ch == '_' || ch == '-')) return 0;
	}
	return 1;
}

static int read_store_id(const char *dir_path, uint64_t *store_id_out)
{
	char path[512];
	char text[32];
	char *end = NULL;
	unsigned long long value;
	FILE *fp;

	if (snprintf(path, sizeof(path), "%s/state/store-id", dir_path) >= (int)sizeof(path)) {
		return -1;
	}
	fp = fopen(path, "rb");
	if (!fp) return -1;
	if (!fgets(text, sizeof(text), fp) || fclose(fp) != 0 || strlen(text) != 17) return -1;
	errno = 0;
	value = strtoull(text, &end, 16);
	if (errno != 0 || !end || *end != '\n') return -1;
	*store_id_out = value;
	return 0;
}

static void load_store_id(RecorderPlayer *reader)
{
	char dir[512];
	char *slash;
	unsigned int depth;

	if (snprintf(dir, sizeof(dir), "%s", reader->path) >= (int)sizeof(dir)) return;
	if (!reader->path_is_directory) {
		slash = strrchr(dir, '/');
		if (!slash) return;
		if (slash == dir) slash[1] = '\0';
		else *slash = '\0';
	}
	for (depth = 0; depth < 2; depth++) {
		if (read_store_id(dir, &reader->store_id) == 0) {
			reader->have_store_id = 1;
			return;
		}
		slash = strrchr(dir, '/');
		if (!slash || slash == dir) return;
		*slash = '\0';
	}
}

static int add_watch(RecorderPlayer *reader, const char *path)
{
	if (reader->inotify_fd < 0) return -1;
	if (inotify_add_watch(reader->inotify_fd, path,
				IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM |
				IN_MODIFY | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF) < 0) return -1;
	return 0;
}

static int add_directory_watches(RecorderPlayer *reader)
{
	DIR *dir;
	struct dirent *de;
	int rv = 0;

	if (add_watch(reader, reader->path) != 0) rv = -1;
	dir = opendir(reader->path);
	if (!dir) return -1;
	while ((de = readdir(dir)) != NULL) {
		char child[512];
		struct stat st;

		if (!valid_group_name(de->d_name) ||
			snprintf(child, sizeof(child), "%s/%s", reader->path, de->d_name) >=
				(int)sizeof(child) || stat(child, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
		if (add_watch(reader, child) != 0) rv = -1;
	}
	closedir(dir);
	return rv;
}

static int scan_frame(const SegmentHeader *header, const SegmentFrameInfo *frame,
					  const void *chunk_buf, size_t chunk_size, void *userdata)
{
	ScanContext *ctx = userdata;
	RecorderEntry entry;
	size_t i;

	(void)chunk_size;
	if (frame->file_offset < ctx->min_frame_offset) return 0;
	memset(&entry, 0, sizeof(entry));
	entry.boot_seq = header->boot_seq;
	entry.boot_id = header->boot_id;
	entry.group = ctx->group;
	entry.segment_seq = header->segment_seq;
	entry.frame_offset = frame->file_offset;
	if ((header->flags & SEGMENT_FLAG_COMPACT_ENTRIES) != 0) {
		journal_DefaultChunk_table_t chunk = journal_DefaultChunk_as_root(chunk_buf);
		flatbuffers_uint32_vec_t entries = journal_DefaultChunk_entries(chunk);
		for (i = 0; i < flatbuffers_uint32_vec_len(entries); i++) {
			journal_CompactEntry_table_t item = journal_CompactEntry_vec_at(entries, i);
			entry.realtime_ts = journal_CompactEntry_realtime_ts(item);
			entry.monotonic_ts = journal_CompactEntry_monotonic_ts(item);
			entry.priority = journal_CompactEntry_priority(item);
			entry.pid = journal_CompactEntry_pid(item);
			entry.message = journal_CompactEntry_message(item);
			entry.unit = journal_CompactEntry_unit(item);
			entry.frame_entry_index = (uint32_t)i;
			if (ctx->callback(&entry, ctx->userdata) != 0) return -1;
		}
	} else {
		journal_Chunk_table_t chunk = journal_Chunk_as_root(chunk_buf);
		flatbuffers_uint32_vec_t entries = journal_Chunk_entries(chunk);
		for (i = 0; i < flatbuffers_uint32_vec_len(entries); i++) {
			journal_FullEntry_table_t item = journal_FullEntry_vec_at(entries, i);
			journal_Field_vec_t fields = journal_FullEntry_fields(item);
			size_t field_count = journal_Field_vec_len(fields);
			RecorderField *field_copy = NULL;
			size_t field_index;

			if (field_count != 0 && !(field_copy = calloc(field_count, sizeof(*field_copy))))
				return -1;
			for (field_index = 0; field_index < field_count; field_index++) {
				journal_Field_table_t field = journal_Field_vec_at(fields, field_index);
				flatbuffers_uint8_vec_t value = journal_Field_value(field);
				size_t value_size = flatbuffers_uint8_vec_len(value);
				unsigned char *value_copy = NULL;

				if (value_size != 0 && !(value_copy = malloc(value_size))) {
					while (field_index > 0) free((void *)field_copy[--field_index].value);
					free(field_copy);
					return -1;
				}
				for (size_t value_index = 0; value_index < value_size; value_index++)
					value_copy[value_index] = flatbuffers_uint8_vec_at(value, value_index);
				field_copy[field_index].name = journal_Field_name(field);
				field_copy[field_index].value = value_copy;
				field_copy[field_index].value_size = value_size;
			}
			entry.realtime_ts = journal_FullEntry_realtime_ts(item);
			entry.monotonic_ts = journal_FullEntry_monotonic_ts(item);
			entry.priority = journal_FullEntry_priority(item);
			entry.pid = journal_FullEntry_pid(item);
			entry.uid = journal_FullEntry_uid(item);
			entry.gid = journal_FullEntry_gid(item);
			entry.errno_value = journal_FullEntry_errno(item);
			entry.hostname = journal_FullEntry_hostname(item);
			entry.comm = journal_FullEntry_comm(item);
			entry.unit = journal_FullEntry_unit(item);
			entry.exe = journal_FullEntry_exe(item);
			entry.message = journal_FullEntry_message(item);
			entry.message_id = journal_FullEntry_message_id(item);
			entry.fields = field_copy;
			entry.field_count = field_count;
			entry.frame_entry_index = (uint32_t)i;
			if (ctx->callback(&entry, ctx->userdata) != 0) {
				for (field_index = 0; field_index < field_count; field_index++)
					free((void *)field_copy[field_index].value);
				free(field_copy);
				return -1;
			}
			for (field_index = 0; field_index < field_count; field_index++)
				free((void *)field_copy[field_index].value);
			free(field_copy);
		}
	}
	return 0;
}

static void free_stored_entry(StoredEntry *stored)
{
	size_t i;

	if (!stored) return;
	free(stored->boot_id);
	free(stored->group);
	free(stored->hostname);
	free(stored->comm);
	free(stored->unit);
	free(stored->exe);
	free(stored->message);
	free(stored->message_id);
	for (i = 0; i < stored->entry.field_count; i++) {
		free((void *)stored->fields[i].name);
		free((void *)stored->fields[i].value);
	}
	free(stored->fields);
	memset(stored, 0, sizeof(*stored));
}

static int copy_stored_fields(StoredEntry *stored, const RecorderEntry *entry)
{
	size_t i;

	if (entry->field_count == 0) return 0;
	stored->fields = calloc(entry->field_count, sizeof(*stored->fields));
	if (!stored->fields) return -1;
	stored->entry.fields = stored->fields;
	stored->entry.field_count = entry->field_count;
	for (i = 0; i < entry->field_count; i++) {
		stored->fields[i].name = entry->fields[i].name ?
			strdup(entry->fields[i].name) : NULL;
		if (entry->fields[i].name && !stored->fields[i].name) return -1;
		if (entry->fields[i].value_size != 0) {
			stored->fields[i].value = malloc(entry->fields[i].value_size);
			if (!stored->fields[i].value) return -1;
			memcpy((void *)stored->fields[i].value, entry->fields[i].value,
				entry->fields[i].value_size);
		}
		stored->fields[i].value_size = entry->fields[i].value_size;
	}
	return 0;
}

static void clear_entries(RecorderPlayer *reader)
{
	size_t i;

	for (i = 0; i < reader->entry_count; i++) free_stored_entry(&reader->entries[i]);
	free(reader->entries);
	reader->entries = NULL;
	reader->entry_count = 0;
	reader->entry_capacity = 0;
	reader->current = SIZE_MAX;
	reader->lazy_history = 0;
	reader->history_initialized = 0;
	free(reader->history_paths);
	reader->history_paths = NULL;
	free(reader->history_loaded);
	reader->history_loaded = NULL;
	reader->history_count = 0;
	rec_player_follow_reset(reader);
	reader->follow_pending = 0;
	reader->follow_topology_pending = 0;
	iterator_reset(reader);
}

static int copy_string(char **out, const char *value)
{
	*out = value ? strdup(value) : NULL;
	return !value || *out ? 0 : -1;
}

static int group_from_path(const char *path, const char *root_path,
						  char *group, size_t group_size)
{
	const char *end;
	const char *start;
	const char *relative;
	size_t len;

	if (!path || !group || group_size == 0) return -1;
	strcpy(group, "-");
	if (root_path) {
		size_t root_len = strlen(root_path);
		if (strncmp(path, root_path, root_len) == 0 && path[root_len] == '/') {
			relative = path + root_len + 1;
			end = strchr(relative, '/');
			if (!end) return 0;
			len = (size_t)(end - relative);
			if (len == 0 || len >= group_size) return 0;
			memcpy(group, relative, len);
			group[len] = '\0';
			if (!valid_group_name(group)) strcpy(group, "-");
			return 0;
		}
	}
	end = strrchr(path, '/');
	if (!end || end == path) return 0;
	start = end - 1;
	while (start > path && start[-1] != '/') start--;
	len = (size_t)(end - start);
	if (len == 0 || len >= group_size) return 0;
	memcpy(group, start, len);
	group[len] = '\0';
	if (!valid_group_name(group)) strcpy(group, "-");
	return 0;
}

static int append_stored_entry(const RecorderEntry *entry, void *userdata)
{
	RecorderPlayer *reader = userdata;
	StoredEntry *stored;
	StoredEntry *tmp;

	if (reader->entry_count == reader->entry_capacity) {
		size_t new_capacity = reader->entry_capacity ? reader->entry_capacity * 2 : 256;
		tmp = realloc(reader->entries, new_capacity * sizeof(*tmp));
		if (!tmp) return -1;
		reader->entries = tmp;
		reader->entry_capacity = new_capacity;
	}
	stored = &reader->entries[reader->entry_count];
	memset(stored, 0, sizeof(*stored));
	stored->entry = *entry;
	if (copy_string(&stored->group, entry->group) != 0 ||
		copy_string(&stored->boot_id, entry->boot_id) != 0 ||
		copy_string(&stored->hostname, entry->hostname) != 0 ||
		copy_string(&stored->comm, entry->comm) != 0 ||
		copy_string(&stored->unit, entry->unit) != 0 ||
		copy_string(&stored->exe, entry->exe) != 0 ||
		copy_string(&stored->message, entry->message) != 0 ||
		copy_string(&stored->message_id, entry->message_id) != 0 ||
		copy_stored_fields(stored, entry) != 0) {
		free_stored_entry(stored);
		return -1;
	}
	stored->entry.group = stored->group;
	stored->entry.boot_id = stored->boot_id;
	stored->entry.hostname = stored->hostname;
	stored->entry.comm = stored->comm;
	stored->entry.unit = stored->unit;
	stored->entry.exe = stored->exe;
	stored->entry.message = stored->message;
	stored->entry.message_id = stored->message_id;
	stored->entry.fields = stored->fields;
	reader->entry_count++;
	return 0;
}

static int append_stored_entry_array(StoredEntry **entries, size_t *count,
						 size_t *capacity, const RecorderEntry *entry)
{
	StoredEntry *stored;
	StoredEntry *tmp;

	if (*count == *capacity) {
		size_t new_capacity = *capacity ? *capacity * 2 : 32;
		tmp = realloc(*entries, new_capacity * sizeof(*tmp));
		if (!tmp) return -1;
		*entries = tmp;
		*capacity = new_capacity;
	}
	stored = &(*entries)[*count];
	memset(stored, 0, sizeof(*stored));
	stored->entry = *entry;
	if (copy_string(&stored->group, entry->group) != 0 ||
		copy_string(&stored->boot_id, entry->boot_id) != 0 ||
		copy_string(&stored->hostname, entry->hostname) != 0 ||
		copy_string(&stored->comm, entry->comm) != 0 ||
		copy_string(&stored->unit, entry->unit) != 0 ||
		copy_string(&stored->exe, entry->exe) != 0 ||
		copy_string(&stored->message, entry->message) != 0 ||
		copy_string(&stored->message_id, entry->message_id) != 0 ||
		copy_stored_fields(stored, entry) != 0) {
		free_stored_entry(stored);
		return -1;
	}
	stored->entry.group = stored->group;
	stored->entry.boot_id = stored->boot_id;
	stored->entry.hostname = stored->hostname;
	stored->entry.comm = stored->comm;
	stored->entry.unit = stored->unit;
	stored->entry.exe = stored->exe;
	stored->entry.message = stored->message;
	stored->entry.message_id = stored->message_id;
	stored->entry.fields = stored->fields;
	(*count)++;
	return 0;
}

static int compare_stored_entries(const void *left, const void *right)
{
	const StoredEntry *a = left;
	const StoredEntry *b = right;
	int result;

	if (a->entry.realtime_ts < b->entry.realtime_ts) return -1;
	if (a->entry.realtime_ts > b->entry.realtime_ts) return 1;
	if (a->entry.boot_seq < b->entry.boot_seq) return -1;
	if (a->entry.boot_seq > b->entry.boot_seq) return 1;
	result = strcmp(a->entry.group ? a->entry.group : "-",
				b->entry.group ? b->entry.group : "-");
	if (result != 0) return result;
	if (a->entry.segment_seq < b->entry.segment_seq) return -1;
	if (a->entry.segment_seq > b->entry.segment_seq) return 1;
	if (a->entry.frame_offset < b->entry.frame_offset) return -1;
	if (a->entry.frame_offset > b->entry.frame_offset) return 1;
	if (a->entry.frame_entry_index < b->entry.frame_entry_index) return -1;
	if (a->entry.frame_entry_index > b->entry.frame_entry_index) return 1;
	return 0;
}

static void rebind_stored_entry_strings(RecorderPlayer *reader)
{
	size_t i;

	for (i = 0; i < reader->entry_count; i++) {
		StoredEntry *stored = &reader->entries[i];

		stored->entry.group = stored->group;
		stored->entry.boot_id = stored->boot_id;
		stored->entry.hostname = stored->hostname;
		stored->entry.comm = stored->comm;
		stored->entry.unit = stored->unit;
		stored->entry.exe = stored->exe;
		stored->entry.message = stored->message;
		stored->entry.message_id = stored->message_id;
		stored->entry.fields = stored->fields;
	}
}

static int append_pending_entries(RecorderPlayer *reader)
{
	RecorderPlayer pending;
	StoredEntry *tmp;
	size_t required;
	size_t capacity;
	size_t i;

	memset(&pending, 0, sizeof(pending));
	if (rec_player_scan_follow(reader, append_stored_entry, &pending, 0) != 0) {
		for (i = 0; i < pending.entry_count; i++) free_stored_entry(&pending.entries[i]);
		free(pending.entries);
		return -1;
	}
	if (pending.entry_count == 0) {
		free(pending.entries);
		return 0;
	}
	qsort(pending.entries, pending.entry_count, sizeof(*pending.entries),
			compare_stored_entries);
	rebind_stored_entry_strings(&pending);
	if (pending.entry_count > SIZE_MAX - reader->entry_count) goto fail;
	required = reader->entry_count + pending.entry_count;
	if (required > SIZE_MAX / sizeof(*reader->entries)) goto fail;
	capacity = reader->entry_capacity;
	if (capacity < required) {
		if (capacity == 0) capacity = 256;
		while (capacity < required) {
			if (capacity > SIZE_MAX / 2) {
				capacity = required;
				break;
			}
			capacity *= 2;
		}
		tmp = realloc(reader->entries, capacity * sizeof(*tmp));
		if (!tmp) goto fail;
		reader->entries = tmp;
		reader->entry_capacity = capacity;
	}
	memcpy(reader->entries + reader->entry_count, pending.entries,
			pending.entry_count * sizeof(*pending.entries));
	reader->entry_count = required;
	free(pending.entries);
	return 0;

fail:
	for (i = 0; i < pending.entry_count; i++) free_stored_entry(&pending.entries[i]);
	free(pending.entries);
	return -1;
}

static int segment_seq_from_name(const char *name, uint64_t *seq_out)
{
	char *end = NULL;
	unsigned long long value = strtoull(name, &end, 10);

	if (!end || strcmp(end, ".seg") != 0) return -1;
	*seq_out = value;
	return 0;
}

static int add_segment_path(SegmentPath **paths, size_t *count, size_t *capacity,
						const char *path, uint64_t segment_seq)
{
	SegmentPath *tmp;

	if (*count == *capacity) {
		size_t new_capacity = *capacity ? *capacity * 2 : 32;
		tmp = realloc(*paths, new_capacity * sizeof(*tmp));
		if (!tmp) return -1;
		*paths = tmp;
		*capacity = new_capacity;
	}
	if (snprintf((*paths)[*count].path, sizeof((*paths)[*count].path), "%s", path) >=
		(int)sizeof((*paths)[*count].path)) return -1;
	(*paths)[*count].segment_seq = segment_seq;
	(*count)++;
	return 0;
}

static int collect_segment_paths_in_dir(const char *dir_path, SegmentPath **paths,
								size_t *count, size_t *capacity)
{
	DIR *dir = opendir(dir_path);
	struct dirent *de;

	if (!dir) return -1;
	while ((de = readdir(dir)) != NULL) {
		uint64_t seq;
		char path[512];

		if (segment_seq_from_name(de->d_name, &seq) != 0) continue;
		if (snprintf(path, sizeof(path), "%s/%s", dir_path, de->d_name) >= (int)sizeof(path) ||
			add_segment_path(paths, count, capacity, path, seq) != 0) {
			closedir(dir);
			return -1;
		}
	}
	closedir(dir);
	return 0;
}

static int collect_segment_paths(const char *root_path, SegmentPath **paths,
								 size_t *count, size_t *capacity)
{
	DIR *dir = opendir(root_path);
	struct dirent *de;

	if (!dir) return -1;
	while ((de = readdir(dir)) != NULL) {
		char path[512];
		struct stat st;
		uint64_t seq;

		if (snprintf(path, sizeof(path), "%s/%s", root_path, de->d_name) >= (int)sizeof(path) ||
			stat(path, &st) != 0) continue;
		if (S_ISREG(st.st_mode) && segment_seq_from_name(de->d_name, &seq) == 0) {
			if (add_segment_path(paths, count, capacity, path, seq) != 0) goto fail;
		} else if (S_ISDIR(st.st_mode) && valid_group_name(de->d_name) &&
			collect_segment_paths_in_dir(path, paths, count, capacity) != 0) {
			goto fail;
		}
	}
	closedir(dir);
	return 0;
fail:
	closedir(dir);
	return -1;
}

static int collect_latest_segment_in_dir(const char *dir_path,
							 SegmentPath **paths, size_t *count, size_t *capacity)
{
	DIR *dir = opendir(dir_path);
	struct dirent *de;
	char latest_path[512] = { 0 };
	uint64_t latest_seq = 0;
	int have_latest = 0;

	if (!dir) return -1;
	while ((de = readdir(dir)) != NULL) {
		uint64_t seq;

		if (segment_seq_from_name(de->d_name, &seq) != 0) continue;
		if (!have_latest || seq > latest_seq) {
			if (snprintf(latest_path, sizeof(latest_path), "%s/%s", dir_path,
					de->d_name) >= (int)sizeof(latest_path)) {
				closedir(dir);
				return -1;
			}
			latest_seq = seq;
			have_latest = 1;
		}
	}
	closedir(dir);
	return have_latest ? add_segment_path(paths, count, capacity, latest_path, latest_seq) : 0;
}

static int collect_latest_segment_paths(const char *root_path, SegmentPath **paths,
								size_t *count, size_t *capacity)
{
	DIR *dir = opendir(root_path);
	struct dirent *de;
	char latest_path[512] = { 0 };
	uint64_t latest_seq = 0;
	int have_root_latest = 0;

	if (!dir) return -1;
	while ((de = readdir(dir)) != NULL) {
		char path[512];
		struct stat st;
		uint64_t seq;

		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0 ||
			snprintf(path, sizeof(path), "%s/%s", root_path, de->d_name) >=
				(int)sizeof(path)) continue;
		if (segment_seq_from_name(de->d_name, &seq) == 0) {
			if (!have_root_latest || seq > latest_seq) {
				strcpy(latest_path, path);
				latest_seq = seq;
				have_root_latest = 1;
			}
		} else if (valid_group_name(de->d_name) && stat(path, &st) == 0 &&
			S_ISDIR(st.st_mode) &&
				collect_latest_segment_in_dir(path, paths, count, capacity) != 0) {
			closedir(dir);
			return -1;
		}
	}
	closedir(dir);
	return have_root_latest ? add_segment_path(paths, count, capacity,
											latest_path, latest_seq) : 0;
}

static int compare_segment_path(const void *a, const void *b)
{
	const SegmentPath *left = a;
	const SegmentPath *right = b;

	return left->segment_seq < right->segment_seq ? -1 :
		left->segment_seq > right->segment_seq;
}

int rec_player_open(RecorderPlayer **reader_out, const char *path)
{
	RecorderPlayer *reader;
	struct stat st;

	if (!reader_out || !path || stat(path, &st) != 0) return -1;
	reader = calloc(1, sizeof(*reader));
	if (!reader) return -1;
	reader->path = strdup(path);
	if (!reader->path) {
		free(reader);
		return -1;
	}
	reader->inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	reader->reliable_fd = reader->inotify_fd >= 0;
	reader->path_is_directory = S_ISDIR(st.st_mode);
	reader->current = SIZE_MAX;
	load_store_id(reader);
	if (reader->inotify_fd >= 0) {
		if ((S_ISDIR(st.st_mode) && add_directory_watches(reader) != 0) ||
			(!S_ISDIR(st.st_mode) && add_watch(reader, path) != 0))
			reader->reliable_fd = 0;
	}
	*reader_out = reader;
	return 0;
}

void rec_player_close(RecorderPlayer *reader)
{
	if (!reader) return;
	if (reader->inotify_fd >= 0) close(reader->inotify_fd);
	clear_entries(reader);
	segment_decryptor_free(reader->decryptor);
	free(reader->unit_filter);
	free(reader->follow_segments);
	free(reader->data);
	free(reader->path);
	free(reader);
}

static FollowSegment *find_follow_segment(RecorderPlayer *reader, const char *path)
{
	char group[64];
	size_t i;

	if (group_from_path(path, reader->path_is_directory ? reader->path : NULL,
			group, sizeof(group)) != 0) return NULL;
	for (i = 0; i < reader->follow_count; i++) {
		if (strcmp(reader->follow_segments[i].group, group) == 0) {
			return &reader->follow_segments[i];
		}
	}
	return NULL;
}

static int remember_follow_segment(RecorderPlayer *reader, const char *path,
								   uint64_t segment_seq, uint64_t committed_end)
{
	char group[64];
	FollowSegment *item = NULL;
	FollowSegment *tmp;
	size_t i;

	if (group_from_path(path, reader->path_is_directory ? reader->path : NULL,
			group, sizeof(group)) != 0) return -1;
	for (i = 0; i < reader->follow_count; i++) {
		if (strcmp(reader->follow_segments[i].group, group) == 0) {
			item = &reader->follow_segments[i];
			break;
		}
	}
	if (item && segment_seq < item->segment_seq) return 0;
	if (item) {
		if (snprintf(item->path, sizeof(item->path), "%s", path) >=
				(int)sizeof(item->path)) return -1;
		item->segment_seq = segment_seq;
		item->committed_end = committed_end;
		return 0;
	}
	if (reader->follow_count == reader->follow_capacity) {
		size_t new_capacity = reader->follow_capacity ? reader->follow_capacity * 2 : 32;
		tmp = realloc(reader->follow_segments, new_capacity * sizeof(*tmp));
		if (!tmp) return -1;
		reader->follow_segments = tmp;
		reader->follow_capacity = new_capacity;
	}
	if (snprintf(reader->follow_segments[reader->follow_count].group,
				 sizeof(reader->follow_segments[reader->follow_count].group), "%s", group) >=
			(int)sizeof(reader->follow_segments[reader->follow_count].group) ||
		snprintf(reader->follow_segments[reader->follow_count].path,
				 sizeof(reader->follow_segments[reader->follow_count].path), "%s", path) >=
			(int)sizeof(reader->follow_segments[reader->follow_count].path)) return -1;
	reader->follow_segments[reader->follow_count].segment_seq = segment_seq;
	reader->follow_segments[reader->follow_count].committed_end = committed_end;
	reader->follow_count++;
	return 0;
}

int rec_player_set_private_key(RecorderPlayer *reader, const char *path)
{
	SegmentDecryptor *decryptor = NULL;

	if (!reader) return -1;
	if (path && (!path[0] || segment_decryptor_create(path, &decryptor) != 0)) {
		return -1;
	}
	clear_entries(reader);
	segment_decryptor_free(reader->decryptor);
	reader->decryptor = decryptor;
	return 0;
}

int rec_player_set_unit_filter(RecorderPlayer *reader, const char *unit)
{
	char *copy = NULL;

	if (!reader || (unit && (!unit[0] || !(copy = strdup(unit))))) return -1;
	clear_entries(reader);
	free(reader->unit_filter);
	reader->unit_filter = copy;
	return 0;
}

int rec_player_set_repair_indexes(RecorderPlayer *reader, int enabled)
{
	if (!reader) return -1;
	reader->repair_indexes = enabled != 0;
	return 0;
}

int rec_player_set_force_repair_indexes(RecorderPlayer *reader, int enabled)
{
	if (!reader) return -1;
	reader->force_repair_indexes = enabled != 0;
	return 0;
}

int rec_player_scan_file(RecorderPlayer *reader, const char *path,
						  rec_player_entry_cb callback, void *userdata,
						  uint64_t min_frame_offset,
						  uint64_t *committed_end_out)
{
	ScanContext ctx;
	SegmentHeader header;
	SegmentFooter footer;
	size_t committed_end = 0;

	if (!reader || !path || !callback) return -1;
	ctx.callback = callback;
	ctx.userdata = userdata;
	ctx.min_frame_offset = min_frame_offset;
	if (group_from_path(path, reader->path_is_directory ? reader->path : NULL,
			ctx.group, sizeof(ctx.group)) != 0) return -1;
	if (segment_scan_path_from_offset(path, reader->decryptor, scan_frame, &ctx,
							min_frame_offset, &header,
						  &footer, &committed_end) != 0) return -1;
	if (committed_end_out) *committed_end_out = committed_end;
	return 0;
}

typedef struct {
	rec_player_entry_cb callback;
	void *userdata;
	size_t *entry_count;
} FollowScanContext;

static int follow_scan_entry(const RecorderEntry *entry, void *userdata)
{
	FollowScanContext *ctx = userdata;

	(*ctx->entry_count)++;
	return ctx->callback(entry, ctx->userdata);
}

static int scan_path_with_context(RecorderPlayer *reader, const char *path,
							 uint64_t min_frame_offset,
							 rec_player_entry_cb callback, void *userdata,
							 size_t *entry_count, uint64_t *committed_end_out)
{
	FollowScanContext ctx = {
		.callback = callback,
		.userdata = userdata,
		.entry_count = entry_count,
	};

	return rec_player_scan_file(reader, path, follow_scan_entry, &ctx,
							min_frame_offset, committed_end_out);
}

int rec_player_scan_all(RecorderPlayer *reader, rec_player_entry_cb callback,
						void *userdata)
{
	SegmentPath *paths = NULL;
	size_t path_count = 0;
	size_t path_capacity = 0;
	size_t i;
	int rc = -1;

	if (!reader || !callback) return -1;
	if (reader->path_is_directory) {
		if (collect_segment_paths(reader->path, &paths, &path_count, &path_capacity) != 0) goto out;
	} else if (add_segment_path(&paths, &path_count, &path_capacity, reader->path, 0) != 0) {
		goto out;
	}
	qsort(paths, path_count, sizeof(*paths), compare_segment_path);
	for (i = 0; i < path_count; i++) {
		if (rec_player_scan_file(reader, paths[i].path, callback, userdata, 0, NULL) != 0) goto out;
	}
	rc = 0;
out:
	free(paths);
	return rc;
}

typedef struct {
	StoredEntry *entries;
	size_t count;
	size_t capacity;
} WallclockEntryList;

typedef struct {
	SegmentPath path;
	uint64_t min_realtime_ts;
	uint64_t max_realtime_ts;
	int needs_sort;
	StoredEntry *entries;
	size_t entry_count;
	size_t entry_capacity;
} WallclockSegment;

static int append_wallclock_entry(const RecorderEntry *entry, void *userdata)
{
	WallclockEntryList *list = userdata;

	return append_stored_entry_array(&list->entries, &list->count,
			&list->capacity, entry);
}

static int wallclock_segment_metadata(RecorderPlayer *reader,
						WallclockSegment *segment)
{
	SegmentHeader header;
	SegmentFooter footer;

	if (segment_scan_path(segment->path.path, reader->decryptor, NULL, NULL,
					&header, &footer, NULL) != 0) return -1;
	segment->min_realtime_ts = header.first_realtime_ts;
	segment->max_realtime_ts = footer.present && footer.last_realtime_ts ?
			footer.last_realtime_ts : header.first_realtime_ts;
	if (segment->max_realtime_ts < segment->min_realtime_ts)
		segment->needs_sort = 1;
	if (!footer.present ||
		(footer.footer_flags & SEGMENT_FOOTER_FLAG_REALTIME_NONMONOTONIC) != 0)
		segment->needs_sort = 1;
	return 0;
}

static int wallclock_load_segment(RecorderPlayer *reader,
						WallclockSegment *segment)
{
	WallclockEntryList list = {
		.entries = segment->entries,
		.count = segment->entry_count,
		.capacity = segment->entry_capacity
	};
	size_t i;

	if (rec_player_scan_file(reader, segment->path.path,
			append_wallclock_entry, &list, 0, NULL) != 0) return -1;
	segment->entries = list.entries;
	segment->entry_count = list.count;
	segment->entry_capacity = list.capacity;
	if (segment->entry_count == 0) return 0;
	segment->min_realtime_ts = segment->entries[0].entry.realtime_ts;
	segment->max_realtime_ts = segment->entries[0].entry.realtime_ts;
	for (i = 1; i < segment->entry_count; i++) {
		uint64_t timestamp = segment->entries[i].entry.realtime_ts;
		if (timestamp < segment->min_realtime_ts)
			segment->min_realtime_ts = timestamp;
		if (timestamp > segment->max_realtime_ts)
			segment->max_realtime_ts = timestamp;
	}
	qsort(segment->entries, segment->entry_count, sizeof(*segment->entries),
			compare_stored_entries);
	return 0;
}

static void wallclock_free_segment(WallclockSegment *segment)
{
	size_t i;

	for (i = 0; i < segment->entry_count; i++)
		free_stored_entry(&segment->entries[i]);
	free(segment->entries);
	segment->entries = NULL;
	segment->entry_count = 0;
	segment->entry_capacity = 0;
}

static int wallclock_prepare_source(RecorderPlayer *reader,
						WallclockSegment *segment, IteratorSource *source)
{
	int rc;

	memset(source, 0, sizeof(*source));
	source->entry_index = -1;
	if (group_from_path(segment->path.path,
			reader->path_is_directory ? reader->path : NULL,
			source->group, sizeof(source->group)) != 0 ||
		source_add_segment(source, &segment->path) != 0) return -1;
	if (segment->needs_sort) {
		source->entries = segment->entries;
		source->entry_count = segment->entry_count;
		source->entry_capacity = segment->entry_capacity;
		source->segment_scan_fallback = 1;
		segment->entries = NULL;
		segment->entry_count = 0;
		segment->entry_capacity = 0;
		source->entry_index = source->entry_count != 0 ? 0 : -1;
		return source->entry_count != 0;
	}
	if (source_load_index(reader, source) == 0 && source->frame_count != 0) {
		rc = source_load_indexed_from(reader, source, 0, 1);
		if (rc >= 0) return rc;
	}
	return source_load_segment_fallback(reader, source, 1);
}

static int wallclock_heap_less(const IteratorSource *sources,
						 size_t left, size_t right)
{
	return compare_stored_entries(
		&sources[left].entries[sources[left].entry_index],
		&sources[right].entries[sources[right].entry_index]) < 0;
}

static void wallclock_heap_sift_up(const IteratorSource *sources,
							 size_t *heap, size_t index)
{
	while (index != 0) {
		size_t parent = (index - 1) / 2;
		if (!wallclock_heap_less(sources, heap[index], heap[parent])) break;
		{
			size_t tmp = heap[index];
			heap[index] = heap[parent];
			heap[parent] = tmp;
		}
		index = parent;
	}
}

static void wallclock_heap_sift_down(const IteratorSource *sources,
							 size_t *heap, size_t count, size_t index)
{
	for (;;) {
		size_t left = index * 2 + 1;
		size_t right = left + 1;
		size_t smallest = index;
		if (left < count && wallclock_heap_less(sources, heap[left], heap[smallest]))
			smallest = left;
		if (right < count && wallclock_heap_less(sources, heap[right], heap[smallest]))
			smallest = right;
		if (smallest == index) break;
		{
			size_t tmp = heap[index];
			heap[index] = heap[smallest];
			heap[smallest] = tmp;
		}
		index = smallest;
	}
}

int rec_player_scan_wallclock(RecorderPlayer *reader, rec_player_entry_cb callback,
						 void *userdata)
{
	SegmentPath *paths = NULL;
	WallclockSegment *segments = NULL;
	IteratorSource *sources = NULL;
	size_t *heap = NULL;
	size_t path_count = 0;
	size_t path_capacity = 0;
	size_t segment_count = 0;
	size_t heap_count = 0;
	size_t i;
	int rc = -1;

	if (!reader || !callback) return -1;
	if (reader->path_is_directory) {
		if (collect_segment_paths(reader->path, &paths, &path_count,
						&path_capacity) != 0) goto out;
	} else if (add_segment_path(&paths, &path_count, &path_capacity,
					reader->path, 0) != 0) goto out;
	qsort(paths, path_count, sizeof(*paths), compare_segment_path);
	segments = calloc(path_count ? path_count : 1, sizeof(*segments));
	if (!segments) goto out;
	for (i = 0; i < path_count; i++) {
		segments[segment_count].path = paths[i];
		if (wallclock_segment_metadata(reader, &segments[segment_count]) != 0)
			goto out;
		if (segments[segment_count].needs_sort &&
			wallclock_load_segment(reader, &segments[segment_count]) != 0)
			goto out;
		if (segments[segment_count].entry_count != 0 ||
			segments[segment_count].min_realtime_ts != 0)
			segment_count++;
	}
	sources = calloc(segment_count ? segment_count : 1, sizeof(*sources));
	heap = malloc((segment_count ? segment_count : 1) * sizeof(*heap));
	if (!sources || !heap) goto out;
	for (i = 0; i < segment_count; i++) {
		int prepared = wallclock_prepare_source(reader, &segments[i], &sources[i]);
		if (prepared < 0) goto out;
		if (prepared > 0) {
			heap[heap_count] = i;
			wallclock_heap_sift_up(sources, heap, heap_count);
			heap_count++;
		}
	}
	while (heap_count != 0) {
		size_t source_index = heap[0];
		if (callback(&sources[source_index].entries[sources[source_index].entry_index].entry,
				userdata) != 0) goto out;
		if (source_advance(reader, &sources[source_index], 1) < 0) goto out;
		if (!source_has_current(&sources[source_index])) {
			heap[0] = heap[--heap_count];
		}
		if (heap_count != 0) wallclock_heap_sift_down(sources, heap, heap_count, 0);
	}
	rc = 0;
out:
	if (sources) {
		for (i = 0; i < segment_count; i++) {
			source_clear_frame(&sources[i]);
			index_reader_close(sources[i].index_reader);
			segment_frame_reader_close(sources[i].frame_reader);
			free(sources[i].segments);
		}
	}
	free(heap);
	free(sources);
	for (i = 0; i < segment_count; i++) wallclock_free_segment(&segments[i]);
	free(segments);
	free(paths);
	return rc;
}

int rec_player_scan_follow(RecorderPlayer *reader, rec_player_entry_cb callback,
						   void *userdata, size_t initial_entries)
{
	SegmentPath *paths = NULL;
	size_t path_count = 0;
	size_t path_capacity = 0;
	size_t i;
	size_t scanned_entries = 0;
	int rc = -1;

	if (!reader || !callback) return -1;
	if (reader->path_is_directory) {
		if (reader->follow_initialized && reader->follow_topology_pending) {
			if (collect_segment_paths(reader->path, &paths, &path_count,
									  &path_capacity) != 0) goto out;
		} else if (collect_latest_segment_paths(reader->path, &paths, &path_count,
										 &path_capacity) != 0) goto out;
	} else if (add_segment_path(&paths, &path_count, &path_capacity, reader->path, 0) != 0) {
		goto out;
	}
	qsort(paths, path_count, sizeof(*paths), compare_segment_path);
	for (i = 0; i < path_count; i++) {
		FollowSegment *seen = find_follow_segment(reader, paths[i].path);
		uint64_t committed_end;

		if (seen && paths[i].segment_seq < seen->segment_seq) continue;
		committed_end = seen && paths[i].segment_seq == seen->segment_seq ?
			seen->committed_end : 0;

		if (scan_path_with_context(reader, paths[i].path, committed_end, callback, userdata,
							&scanned_entries, &committed_end) != 0) goto out;
		if (remember_follow_segment(reader, paths[i].path, paths[i].segment_seq,
								committed_end) != 0) goto out;
	}
	if (!reader->follow_initialized && scanned_entries < initial_entries && reader->path_is_directory) {
		SegmentPath *history = NULL;
		size_t history_count = 0;
		size_t history_capacity = 0;

		if (collect_segment_paths(reader->path, &history, &history_count, &history_capacity) != 0) {
			free(history);
			goto out;
		}
		qsort(history, history_count, sizeof(*history), compare_segment_path);
		for (i = history_count; i > 0 && scanned_entries < initial_entries; i--) {
			FollowSegment *seen = find_follow_segment(reader, history[i - 1].path);

			if (seen && history[i - 1].segment_seq >= seen->segment_seq) continue;
			if (scan_path_with_context(reader, history[i - 1].path, 0, callback, userdata,
								&scanned_entries, NULL) != 0) {
				free(history);
				goto out;
			}
		}
		free(history);
	}
	reader->follow_initialized = 1;
	reader->follow_topology_pending = 0;
	rc = 0;
out:
	free(paths);
	return rc;
}

void rec_player_follow_reset(RecorderPlayer *reader)
{
	if (!reader) return;
	free(reader->follow_segments);
	reader->follow_segments = NULL;
	reader->follow_count = 0;
	reader->follow_capacity = 0;
	reader->follow_initialized = 0;
}

static int scan_segment_end(RecorderPlayer *reader, const char *path,
						uint64_t *committed_end_out)
{
	SegmentHeader header;
	SegmentFooter footer;
	size_t committed_end = 0;

	if (segment_scan_path_from_offset(path, reader->decryptor, NULL, NULL, 0,
			&header, &footer, &committed_end) != 0) return -1;
	*committed_end_out = committed_end;
	return 0;
}

static int initialize_tail_follow(RecorderPlayer *reader)
{
	SegmentPath *paths = NULL;
	size_t path_count = 0;
	size_t path_capacity = 0;
	size_t i;
	int rc = -1;

	if (reader->path_is_directory) {
		if (collect_latest_segment_paths(reader->path, &paths, &path_count,
								 &path_capacity) != 0) goto out;
	} else if (add_segment_path(&paths, &path_count, &path_capacity,
			reader->path, 0) != 0) {
		goto out;
	}
	qsort(paths, path_count, sizeof(*paths), compare_segment_path);
	for (i = 0; i < path_count; i++) {
		uint64_t committed_end;

		if (scan_segment_end(reader, paths[i].path, &committed_end) != 0 ||
			remember_follow_segment(reader, paths[i].path, paths[i].segment_seq,
				committed_end) != 0) goto out;
	}
	reader->follow_initialized = 1;
	reader->follow_topology_pending = 0;
	reader->follow_pending = 0;
	rc = 0;
out:
	free(paths);
	return rc;
}

static void source_clear_frame(IteratorSource *source)
{
	size_t i;
	for (i = 0; i < source->entry_count; i++) free_stored_entry(&source->entries[i]);
	free(source->entries);
	source->entries = NULL;
	source->entry_count = 0;
	source->entry_capacity = 0;
	source->entry_index = -1;
}

static void iterator_reset(RecorderPlayer *reader)
{
	size_t i;
	for (i = 0; i < reader->source_count; i++) {
		source_clear_frame(&reader->sources[i]);
		index_reader_close(reader->sources[i].index_reader);
		segment_frame_reader_close(reader->sources[i].frame_reader);
		free(reader->sources[i].segments);
	}
	free(reader->sources);
	reader->sources = NULL;
	reader->source_count = 0;
	reader->current_source = SIZE_MAX;
	reader->current_entry_ptr = NULL;
	reader->current_valid = 0;
	reader->iterator_state = ITERATOR_STATE_NONE;
}

static int source_add_segment(IteratorSource *source, const SegmentPath *path)
{
	if (source->segment_count == source->segment_capacity) {
		size_t capacity = source->segment_capacity ? source->segment_capacity * 2 : 8;
		SegmentPath *items = realloc(source->segments, capacity * sizeof(*items));
		if (!items) return -1;
		source->segments = items;
		source->segment_capacity = capacity;
	}
	source->segments[source->segment_count++] = *path;
	return 0;
}

static int segment_index_path(const char *segment_path, char *index_path, size_t size)
{
	size_t len = strlen(segment_path);
	if (len < 5 || strcmp(segment_path + len - 4, ".seg") != 0 || len + 1 > size) return -1;
	if (snprintf(index_path, size, "%.*s.idx", (int)(len - 4), segment_path) >= (int)size)
		return -1;
	return 0;
}

static int source_repair_index(RecorderPlayer *reader, IteratorSource *source,
						 const char *index_path)
{
	SegmentFooter footer;
	struct stat st;
	size_t committed_end = 0;
	const char *segment_path;

	if (!reader->repair_indexes) return -1;
	if (!reader->force_repair_indexes &&
		source->segment_index + 1 == source->segment_count) {
		errno = EAGAIN;
		return -1;
	}
	segment_path = source->segments[source->segment_index].path;
	if (stat(segment_path, &st) != 0 ||
		segment_scan_path(segment_path, reader->decryptor, NULL, NULL, NULL,
			&footer, &committed_end) != 0 || !footer.present ||
		committed_end != (size_t)st.st_size) {
		errno = EAGAIN;
		return -1;
	}
	if (index_rebuild_for_segment(segment_path,
			index_path, reader->decryptor) != 0) return -1;
	return 0;
}

static int source_load_index(RecorderPlayer *reader, IteratorSource *source)
{
	char path[512];
	source->frame_count = 0;
	source->segment_scan_fallback = 0;
	if (source->segment_index >= source->segment_count ||
		segment_index_path(source->segments[source->segment_index].path, path, sizeof(path)) != 0)
		return -1;
	if (!source->index_reader || strcmp(source->index_reader_path, path) != 0) {
		index_reader_close(source->index_reader);
		source->index_reader = NULL;
		if ((index_reader_open(path, source->segments[source->segment_index].path,
			&source->index_reader) != 0 &&
			(source_repair_index(reader, source, path) != 0 ||
			 index_reader_open(path, source->segments[source->segment_index].path,
				&source->index_reader) != 0)) ||
			snprintf(source->index_reader_path, sizeof(source->index_reader_path), "%s", path) >=
				(int)sizeof(source->index_reader_path)) return -1;
	}
	source->frame_count = index_reader_frame_count(source->index_reader);
	return 0;
}

typedef struct { IteratorSource *source; } SourceFrameContext;

static int append_source_entry(const RecorderEntry *entry, void *userdata)
{
	IteratorSource *source = userdata;
	return append_stored_entry_array(&source->entries, &source->entry_count,
							 &source->entry_capacity, entry);
}

static int scan_source_frame(const SegmentHeader *header, const SegmentFrameInfo *frame,
					 const void *chunk_buf, size_t chunk_size, void *userdata)
{
	SourceFrameContext *context = userdata;
	ScanContext scan = {
		.callback = append_source_entry,
		.userdata = context->source,
		.min_frame_offset = frame->file_offset,
	};
	if (snprintf(scan.group, sizeof(scan.group), "%s", context->source->group) >=
		(int)sizeof(scan.group)) return -1;
	return scan_frame(header, frame, chunk_buf, chunk_size, &scan);
}

static int source_load_frame(RecorderPlayer *reader, IteratorSource *source,
					 size_t frame_index, int direction)
{
	SourceFrameContext context = { .source = source };
	const SegmentPath *segment;
	IndexFrame frame;

	if (frame_index >= source->frame_count) return -1;
	source_clear_frame(source);
	segment = &source->segments[source->segment_index];
	if (!source->index_reader || index_reader_read_frame(source->index_reader, frame_index,
			&frame) != 0) return -1;
	source->frame_index = frame_index;
	if (!index_frame_may_contain_service(&frame, reader->unit_filter)) return 1;
	if (!source->frame_reader || strcmp(source->frame_reader_path, segment->path) != 0) {
		segment_frame_reader_close(source->frame_reader);
		source->frame_reader = NULL;
		if (segment_frame_reader_open(segment->path, reader->decryptor,
				&source->frame_reader) != 0 ||
			snprintf(source->frame_reader_path, sizeof(source->frame_reader_path), "%s",
				segment->path) >= (int)sizeof(source->frame_reader_path)) return -1;
	}
	if (segment_frame_reader_scan(source->frame_reader, scan_source_frame,
							&context, frame.file_offset, frame_index) != 0)
		return -1;
	source->entry_index = direction > 0 ? 0 : (ssize_t)source->entry_count - 1;
	return 0;
}

static int source_load_indexed_from(RecorderPlayer *reader, IteratorSource *source,
									size_t frame_index, int direction)
{
	for (;;) {
		int rc = source_load_frame(reader, source, frame_index, direction);

		if (rc < 0) return -1;
		if (rc == 0 && source->entry_count != 0) return 1;
		if ((direction > 0 && ++frame_index >= source->frame_count) ||
			(direction < 0 && frame_index-- == 0)) return 0;
	}
}

static int source_load_segment_fallback(RecorderPlayer *reader, IteratorSource *source,
									int direction)
{
	source_clear_frame(source);
	if (rec_player_scan_file(reader, source->segments[source->segment_index].path,
			append_source_entry, source, 0, NULL) != 0) {
		if (errno == ENOENT) return 0;
		return -1;
	}
	qsort(source->entries, source->entry_count, sizeof(*source->entries),
			compare_stored_entries);
	source->segment_scan_fallback = 1;
	source->frame_count = 0;
	source->entry_index = direction > 0 ? 0 : (ssize_t)source->entry_count - 1;
	return source->entry_count != 0;
}

static int source_position_fallback_after(RecorderPlayer *reader, IteratorSource *source,
									  const RecorderEntry *previous, int direction)
{
	StoredEntry key = { .entry = *previous };
	ssize_t i;

	key.entry.group = source->group;
	if (source_load_segment_fallback(reader, source, direction) < 0) return -1;
	if (direction > 0) {
		for (i = 0; i < (ssize_t)source->entry_count; i++) {
			if (compare_stored_entries(&source->entries[i], &key) > 0) {
				source->entry_index = i;
				return 1;
			}
		}
	} else {
		for (i = (ssize_t)source->entry_count - 1; i >= 0; i--) {
			if (compare_stored_entries(&source->entries[i], &key) < 0) {
				source->entry_index = i;
				return 1;
			}
		}
	}
	source_clear_frame(source);
	return 0;
}

static int source_load_segment_edge(RecorderPlayer *reader, IteratorSource *source,
								 int direction)
{
	if (source_load_index(reader, source) == 0) {
		if (source->frame_count == 0) return 0;
		{
			int rc = source_load_indexed_from(reader, source,
				direction > 0 ? 0 : source->frame_count - 1, direction);
			if (rc >= 0) return rc;
		}
	}
	return source_load_segment_fallback(reader, source, direction);
}

static int source_position_edge(RecorderPlayer *reader, IteratorSource *source, int direction)
{
	if (source->segment_count == 0) return 0;
	source->segment_index = direction > 0 ? 0 : source->segment_count - 1;
	for (;;) {
		int rc = source_load_segment_edge(reader, source, direction);
		if (rc < 0) return -1;
		if (rc > 0) return 1;
		if ((direction > 0 && ++source->segment_index >= source->segment_count) ||
			(direction < 0 && source->segment_index-- == 0)) break;
	}
	return 0;
}

static int source_advance(RecorderPlayer *reader, IteratorSource *source, int direction)
{
	RecorderEntry previous;
	int have_previous;

	if (!source->entries) return 0;
	source->entry_index += direction;
	if (source->entry_index >= 0 && source->entry_index < (ssize_t)source->entry_count) return 1;
	have_previous = source->entry_count != 0;
	if (have_previous) previous = source->entries[direction > 0 ?
		source->entry_count - 1 : 0].entry;
	for (;;) {
		if (!source->segment_scan_fallback &&
			((direction > 0 && ++source->frame_index < source->frame_count) ||
			(direction < 0 && source->frame_index-- > 0))) {
			int load_rc = source_load_indexed_from(reader, source, source->frame_index,
				direction);
			if (load_rc > 0) return 1;
			if (load_rc == 0) continue;
			if (have_previous) {
				int rc = source_position_fallback_after(reader, source, &previous, direction);
				if (rc != 0) return rc;
			} else {
				if (source_load_segment_fallback(reader, source, direction) < 0) return -1;
				if (source->entry_count != 0) return 1;
			}
			continue;
		}
		if ((direction > 0 && ++source->segment_index >= source->segment_count) ||
			(direction < 0 && source->segment_index-- == 0)) break;
		{
			int rc = source_load_segment_edge(reader, source, direction);
			if (rc < 0) return -1;
			if (rc > 0) return 1;
		}
	}
	source_clear_frame(source);
	return 0;
}

static int source_seek_realtime(RecorderPlayer *reader, IteratorSource *source,
						uint64_t usec)
{
	size_t i;

	source_clear_frame(source);
	source->frame_count = 0;
	for (i = 0; i < source->segment_count; i++) {
		char index_path[512];
		IndexFrame frame;
		size_t frame_index;
		size_t j;
		int find_rc;
		if (segment_index_path(source->segments[i].path, index_path, sizeof(index_path)) != 0)
			find_rc = -1;
		else find_rc = index_find_realtime_frame(index_path, source->segments[i].path,
			usec, &frame, &frame_index);
		if (find_rc < 0) source->segment_index = i;
		if (find_rc < 0 && source_repair_index(reader, source, index_path) == 0)
			find_rc = index_find_realtime_frame(index_path, source->segments[i].path,
				usec, &frame, &frame_index);
		if (find_rc > 0) continue;
		if (find_rc < 0) {
			source->segment_index = i;
			if (source_load_segment_fallback(reader, source, 1) < 0) return -1;
			for (j = 0; j < source->entry_count; j++) {
				if (source->entries[j].entry.realtime_ts >= usec) {
					source->entry_index = (ssize_t)j;
					return 0;
				}
			}
			continue;
		}
		source->segment_index = i;
		if (source_load_index(reader, source) != 0) return -1;
		{
			int load_rc = source_load_indexed_from(reader, source, frame_index, 1);
			if (load_rc < 0) return -1;
			if (load_rc == 0) continue;
		}
		for (j = 0; j < source->entry_count; j++) {
			if (source->entries[j].entry.realtime_ts >= usec) {
				source->entry_index = (ssize_t)j;
				return 0;
			}
		}
		return source_advance(reader, source, 1) < 0 ? -1 : 0;
	}
	return 0;
}

static int iterator_seek_realtime(RecorderPlayer *reader, uint64_t usec)
{
	size_t i;
	if (iterator_initialize(reader, 1) != 0) return -1;
	for (i = 0; i < reader->source_count; i++)
		if (source_seek_realtime(reader, &reader->sources[i], usec) != 0) return -1;
	reader->current_valid = 0;
	reader->current_entry_ptr = NULL;
	return 0;
}

static int source_seek_cursor(RecorderPlayer *reader, IteratorSource *source,
				  uint64_t segment_seq, uint64_t frame_offset,
				  uint32_t frame_entry_index, uint64_t *realtime_ts_out)
{
	IndexFrame frame;
	char index_path[512];
	size_t i;
	size_t frame_index;

	if (!source || !realtime_ts_out) return -1;
	for (i = 0; i < source->segment_count; i++)
		if (source->segments[i].segment_seq == segment_seq) break;
	if (i == source->segment_count) {
		errno = ENOENT;
		return -1;
	}
	source->segment_index = i;
	if (segment_index_path(source->segments[i].path, index_path, sizeof(index_path)) != 0 ||
		index_find_offset_frame(index_path, source->segments[i].path, frame_offset,
			&frame, &frame_index) != 0 ||
		source_load_index(reader, source) != 0 ||
		source_load_frame(reader, source, frame_index, 1) != 0) {
		if (source_load_segment_fallback(reader, source, 1) < 0) return -1;
	}
	for (i = 0; i < source->entry_count; i++) {
		const RecorderEntry *entry = &source->entries[i].entry;

		if (entry->frame_offset == frame_offset &&
			entry->frame_entry_index == frame_entry_index) {
			source->entry_index = (ssize_t)i;
			*realtime_ts_out = entry->realtime_ts;
			return 0;
		}
	}
	if (!source->segment_scan_fallback &&
		source_load_segment_fallback(reader, source, 1) >= 0) {
		for (i = 0; i < source->entry_count; i++) {
			const RecorderEntry *entry = &source->entries[i].entry;

			if (entry->frame_offset == frame_offset &&
				entry->frame_entry_index == frame_entry_index) {
				source->entry_index = (ssize_t)i;
				*realtime_ts_out = entry->realtime_ts;
				return 0;
			}
		}
	}
	errno = ENOENT;
	return -1;
}

static int source_has_current(const IteratorSource *source)
{
	return source && source->entry_index >= 0 &&
		source->entry_index < (ssize_t)source->entry_count;
}

static int iterator_position_at_cursor(RecorderPlayer *reader, size_t source_index)
{
	IteratorSource *cursor_source;
	StoredEntry cursor_entry;
	size_t i;

	if (!reader || source_index >= reader->source_count) return -1;
	cursor_source = &reader->sources[source_index];
	if (!source_has_current(cursor_source)) return -1;
	cursor_entry = cursor_source->entries[cursor_source->entry_index];

	/* source_seek_realtime() leaves every source near the cursor timestamp.
	 * Normalize each one to its first entry at or after the exact cursor so
	 * either direction can be selected by the next iterator operation. */
	for (i = 0; i < reader->source_count; i++) {
		IteratorSource *source = &reader->sources[i];

		while (source_has_current(source) &&
			compare_stored_entries(&source->entries[source->entry_index],
				&cursor_entry) < 0) {
			int rc = source_advance(reader, source, ITERATOR_STATE_FORWARD);

			if (rc < 0) return -1;
			if (rc == 0) break;
		}
	}
	if (!source_has_current(cursor_source) ||
		compare_stored_entries(&cursor_source->entries[cursor_source->entry_index],
			&cursor_entry) != 0) return -1;
	reader->current_source = source_index;
	reader->current_entry_ptr = NULL;
	reader->current_valid = 0;
	reader->iterator_state = ITERATOR_STATE_CURSOR_PENDING;
	return 0;
}

static int iterator_seek_other_sources_realtime(RecorderPlayer *reader,
									 size_t cursor_source_index, uint64_t usec)
{
	size_t i;

	if (!reader || cursor_source_index >= reader->source_count) return -1;
	for (i = 0; i < reader->source_count; i++) {
		if (i == cursor_source_index) continue;
		if (source_seek_realtime(reader, &reader->sources[i], usec) != 0) return -1;
	}
	return 0;
}

static int iterator_collect_sources(RecorderPlayer *reader)
{
	SegmentPath *paths = NULL;
	size_t path_count = 0, path_capacity = 0, i;

	iterator_reset(reader);
	if (reader->path_is_directory) {
		if (collect_segment_paths(reader->path, &paths, &path_count, &path_capacity) != 0) goto fail;
	} else if (add_segment_path(&paths, &path_count, &path_capacity, reader->path, 0) != 0) goto fail;
	qsort(paths, path_count, sizeof(*paths), compare_segment_path);
	for (i = 0; i < path_count; i++) {
		char group[64];
		size_t j;
		if (group_from_path(paths[i].path, reader->path_is_directory ? reader->path : NULL,
				group, sizeof(group)) != 0) goto fail;
		for (j = 0; j < reader->source_count; j++)
			if (strcmp(reader->sources[j].group, group) == 0) break;
		if (j == reader->source_count) {
			IteratorSource *sources = realloc(reader->sources,
				(reader->source_count + 1) * sizeof(*sources));
			if (!sources) goto fail;
			reader->sources = sources;
			memset(&reader->sources[j], 0, sizeof(reader->sources[j]));
			strcpy(reader->sources[j].group, group);
			reader->source_count++;
		}
		if (source_add_segment(&reader->sources[j], &paths[i]) != 0) goto fail;
	}
	free(paths);
	return 0;
fail:
	free(paths);
	iterator_reset(reader);
	return -1;
}

static int iterator_initialize(RecorderPlayer *reader, int direction)
{
	size_t i;

	if (iterator_collect_sources(reader) != 0) return -1;
	for (i = 0; i < reader->source_count; i++)
		if (source_position_edge(reader, &reader->sources[i], direction) < 0) goto fail_reset;
	reader->iterator_state = direction;
	return 0;
fail_reset:
	iterator_reset(reader);
	return -1;
}

static ssize_t iterator_pick(RecorderPlayer *reader, int direction)
{
	ssize_t result = -1;
	size_t i;
	for (i = 0; i < reader->source_count; i++) {
		IteratorSource *source = &reader->sources[i];
		if (source->entry_index < 0 || source->entry_index >= (ssize_t)source->entry_count) continue;
		if (result < 0 || compare_stored_entries(&source->entries[source->entry_index],
			&reader->sources[result].entries[reader->sources[result].entry_index]) * direction < 0)
			result = (ssize_t)i;
	}
	return result;
}

#if 0 /* Superseded cache-based iterator. */
static int initialize_lazy_history(RecorderPlayer *reader)
{
	SegmentPath *paths = NULL;
	unsigned char *loaded = NULL;
	size_t path_count = 0;
	size_t path_capacity = 0;
	size_t i;
	int rc = -1;

	/* Entries delivered while following are also present in their current
	 * segments. Rebuild this bounded cache from those segments to avoid adding
	 * duplicate entries when reverse iteration begins. */
	if (reader->entry_count != 0) {
		clear_entries(reader);
		if (initialize_tail_follow(reader) != 0) return -1;
		reader->lazy_history = 1;
	}
	if (!reader->path_is_directory) {
		if (add_segment_path(&paths, &path_count, &path_capacity, reader->path, 0) != 0)
			goto out;
	} else if (collect_segment_paths(reader->path, &paths, &path_count,
									&path_capacity) != 0) {
		goto out;
	}
	qsort(paths, path_count, sizeof(*paths), compare_segment_path);
	loaded = calloc(path_count ? path_count : 1, sizeof(*loaded));
	if (!loaded) goto out;
	for (i = 0; i < path_count; i++) {
		FollowSegment *follow = find_follow_segment(reader, paths[i].path);
		uint64_t committed_end;

		if (!follow || follow->segment_seq != paths[i].segment_seq) continue;
		if (rec_player_scan_file(reader, paths[i].path, append_stored_entry, reader, 0,
								&committed_end) != 0 ||
			remember_follow_segment(reader, paths[i].path, paths[i].segment_seq,
				committed_end) != 0) goto out;
		loaded[i] = 1;
	}
	qsort(reader->entries, reader->entry_count, sizeof(*reader->entries),
			compare_stored_entries);
	rebind_stored_entry_strings(reader);
	reader->history_paths = paths;
	reader->history_loaded = loaded;
	reader->history_count = path_count;
	reader->lazy_history = 1;
	reader->history_initialized = 1;
	reader->current = reader->entry_count;
	paths = NULL;
	loaded = NULL;
	rc = 0;
out:
	free(paths);
	free(loaded);
	return rc;
}

static int initialize_lazy_head(RecorderPlayer *reader)
{
	SegmentPath *paths = NULL;
	unsigned char *loaded = NULL;
	size_t path_count = 0, path_capacity = 0, i, j;
	int rc = -1;

	if (!reader->path_is_directory) {
		if (add_segment_path(&paths, &path_count, &path_capacity, reader->path, 0) != 0)
			goto out;
	} else if (collect_segment_paths(reader->path, &paths, &path_count,
									&path_capacity) != 0) goto out;
	qsort(paths, path_count, sizeof(*paths), compare_segment_path);
	loaded = calloc(path_count ? path_count : 1, sizeof(*loaded));
	if (!loaded) goto out;
	reader->history_paths = paths;
	reader->history_loaded = loaded;
	reader->history_count = path_count;
	reader->lazy_history = 1;
	reader->history_initialized = 1;
	paths = NULL;
	loaded = NULL;
	for (i = 0; i < reader->history_count; i++) {
		char group[64];
		int first = 1;
		uint64_t committed_end;

		if (group_from_path(reader->history_paths[i].path, reader->path,
			group, sizeof(group)) != 0) goto out;
		for (j = 0; j < i; j++) {
			char prior_group[64];
			if (group_from_path(reader->history_paths[j].path, reader->path,
				prior_group, sizeof(prior_group)) == 0 && strcmp(group, prior_group) == 0) {
				first = 0;
				break;
			}
		}
		if (!first || rec_player_scan_file(reader, reader->history_paths[i].path,
			append_stored_entry, reader, 0, &committed_end) != 0 ||
			remember_follow_segment(reader, reader->history_paths[i].path,
				reader->history_paths[i].segment_seq, committed_end) != 0) goto out;
		reader->history_loaded[i] = 1;
	}
	qsort(reader->entries, reader->entry_count, sizeof(*reader->entries),
			compare_stored_entries);
	rebind_stored_entry_strings(reader);
	reader->current = SIZE_MAX;
	rc = 0;
out:
	free(paths);
	free(loaded);
	if (rc != 0) clear_entries(reader);
	return rc;
}

static int load_previous_history_segment(RecorderPlayer *reader,
								  const RecorderEntry *current, int *loaded_out)
{
	char group[64];
	size_t best = SIZE_MAX;
	size_t i;
	uint64_t committed_end;

	*loaded_out = 0;
	if (!current || !current->group ||
		snprintf(group, sizeof(group), "%s", current->group) >= (int)sizeof(group)) return -1;
	for (i = 0; i < reader->history_count; i++) {
		char path_group[64];

		if (reader->history_loaded[i] ||
			reader->history_paths[i].segment_seq >= current->segment_seq ||
			group_from_path(reader->history_paths[i].path, reader->path,
				path_group, sizeof(path_group)) != 0 ||
			strcmp(group, path_group) != 0) continue;
		if (best == SIZE_MAX || reader->history_paths[i].segment_seq >
			reader->history_paths[best].segment_seq) best = i;
	}
	if (best == SIZE_MAX) return 0;
	if (rec_player_scan_file(reader, reader->history_paths[best].path,
			append_stored_entry, reader, 0, &committed_end) != 0 ||
		remember_follow_segment(reader, reader->history_paths[best].path,
			reader->history_paths[best].segment_seq, committed_end) != 0) return -1;
	reader->history_loaded[best] = 1;
	qsort(reader->entries, reader->entry_count, sizeof(*reader->entries),
			compare_stored_entries);
	rebind_stored_entry_strings(reader);
	*loaded_out = 1;
	return 0;
}

static int load_next_history_segment(RecorderPlayer *reader,
							  const RecorderEntry *current, int *loaded_out)
{
	char group[64];
	size_t best = SIZE_MAX, i;
	uint64_t committed_end;

	*loaded_out = 0;
	if (!current || !current->group ||
		snprintf(group, sizeof(group), "%s", current->group) >= (int)sizeof(group)) return -1;
	for (i = 0; i < reader->history_count; i++) {
		char path_group[64];
		if (reader->history_loaded[i] ||
			reader->history_paths[i].segment_seq <= current->segment_seq ||
			group_from_path(reader->history_paths[i].path, reader->path,
				path_group, sizeof(path_group)) != 0 || strcmp(group, path_group) != 0) continue;
		if (best == SIZE_MAX || reader->history_paths[i].segment_seq <
			reader->history_paths[best].segment_seq) best = i;
	}
	if (best == SIZE_MAX) return 0;
	if (rec_player_scan_file(reader, reader->history_paths[best].path,
			append_stored_entry, reader, 0, &committed_end) != 0 ||
		remember_follow_segment(reader, reader->history_paths[best].path,
			reader->history_paths[best].segment_seq, committed_end) != 0) return -1;
	reader->history_loaded[best] = 1;
	qsort(reader->entries, reader->entry_count, sizeof(*reader->entries), compare_stored_entries);
	rebind_stored_entry_strings(reader);
	*loaded_out = 1;
	return 0;
}

static int is_first_segment_entry(RecorderPlayer *reader, const RecorderEntry *entry)
{
	size_t i;

	for (i = 0; i < reader->entry_count; i++) {
		const RecorderEntry *other = &reader->entries[i].entry;

		if (other == entry || !other->group || !entry->group ||
			strcmp(other->group, entry->group) != 0 ||
			other->segment_seq != entry->segment_seq) continue;
		if (other->realtime_ts < entry->realtime_ts ||
			(other->realtime_ts == entry->realtime_ts &&
				(other->frame_offset < entry->frame_offset ||
					(other->frame_offset == entry->frame_offset &&
					 other->frame_entry_index < entry->frame_entry_index)))) return 0;
	}
	return 1;
}

static int is_last_segment_entry(RecorderPlayer *reader, const RecorderEntry *entry)
{
	size_t i;
	for (i = 0; i < reader->entry_count; i++) {
		const RecorderEntry *other = &reader->entries[i].entry;
		if (other == entry || !other->group || !entry->group ||
			strcmp(other->group, entry->group) != 0 || other->segment_seq != entry->segment_seq) continue;
		if (other->realtime_ts > entry->realtime_ts ||
			(other->realtime_ts == entry->realtime_ts &&
				(other->frame_offset > entry->frame_offset ||
					(other->frame_offset == entry->frame_offset &&
					 other->frame_entry_index > entry->frame_entry_index)))) return 0;
	}
	return 1;
}

#endif

static const RecorderEntry *current_entry(RecorderPlayer *reader)
{
	if (!reader || !reader->current_valid || !reader->current_entry_ptr) return NULL;
	return &reader->current_entry_ptr->entry;
}

static int parse_cursor(const char *cursor, uint64_t *store_id, char *group,
						size_t group_size, uint64_t *segment_seq, uint64_t *frame_offset,
						uint32_t *frame_entry_index)
{
	unsigned long long store;
	unsigned long long segment;
	unsigned long long frame;
	unsigned int entry;
	char tail;

	if (!cursor || !group || group_size < 64 ||
		sscanf(cursor, "rec1:%llx:%63[^:]:%llx:%llx:%x%c", &store, group,
			&segment, &frame, &entry, &tail) != 5 ||
		!valid_group_name(group)) return -1;
	*store_id = store;
	*segment_seq = segment;
	*frame_offset = frame;
	*frame_entry_index = entry;
	return 0;
}

int rec_player_seek_head(RecorderPlayer *reader)
{
	if (!reader) return -1;
	clear_entries(reader);
	return iterator_initialize(reader, 1);
}

int rec_player_seek_tail(RecorderPlayer *reader)
{
	if (!reader) return -1;
	clear_entries(reader);
	if (initialize_tail_follow(reader) != 0 || iterator_initialize(reader, -1) != 0) {
		clear_entries(reader);
		return -1;
	}
	/* The frame cursors are retained for previous(); next() after tail is fed
	 * only by the high-water-mark follow queue. */
	reader->iterator_state = ITERATOR_STATE_FOLLOW;
	reader->current = 0;
	return 0;
}

int rec_player_seek_realtime_usec(RecorderPlayer *reader, uint64_t usec)
{
	return reader ? iterator_seek_realtime(reader, usec) : -1;
}

static int rec_player_seek_cursor_once(RecorderPlayer *reader, const char *group,
								 uint64_t segment_seq, uint64_t frame_offset,
								 uint32_t frame_entry_index)
{
	IteratorSource *source = NULL;
	size_t i;
	size_t source_index;
	uint64_t realtime_ts;

	if (iterator_collect_sources(reader) != 0) return -1;
	for (i = 0; i < reader->source_count; i++) {
		if (strcmp(reader->sources[i].group, group) == 0) {
			source = &reader->sources[i];
			break;
		}
	}
	if (!source) {
		errno = ENOENT;
		return -1;
	}
	if (source_seek_cursor(reader, source, segment_seq, frame_offset,
		frame_entry_index, &realtime_ts) != 0) return -1;
	source_index = (size_t)(source - reader->sources);
	if (iterator_seek_other_sources_realtime(reader, source_index, realtime_ts) != 0 ||
		iterator_position_at_cursor(reader, source_index) != 0) return -1;
	return 0;
}

int rec_player_seek_cursor(RecorderPlayer *reader, const char *cursor)
{
	uint64_t segment_seq;
	uint64_t frame_offset;
	uint64_t store_id;
	uint32_t frame_entry_index;
	char group[64];

	if (!reader || !reader->have_store_id ||
		parse_cursor(cursor, &store_id, group, sizeof(group), &segment_seq, &frame_offset,
			&frame_entry_index) != 0) {
		errno = EINVAL;
		return -1;
	}
	if (store_id != reader->store_id) {
		errno = ESTALE;
		return -1;
	}
	if (rec_player_seek_cursor_once(reader, group, segment_seq, frame_offset,
			frame_entry_index) == 0) return 0;
	{
		int saved_errno = errno;

		iterator_reset(reader);
		errno = saved_errno ? saved_errno : ENOENT;
	}
	return -1;
}

int rec_player_test_cursor(RecorderPlayer *reader, const char *cursor)
{
	const RecorderEntry *entry = current_entry(reader);
	uint64_t segment_seq;
	uint64_t frame_offset;
	uint64_t store_id;
	uint32_t frame_entry_index;
	char group[64];

	if (!entry || !reader->have_store_id ||
		parse_cursor(cursor, &store_id, group, sizeof(group), &segment_seq, &frame_offset,
			&frame_entry_index) != 0 ||
		store_id != reader->store_id) return -1;
	return entry->group && strcmp(entry->group, group) == 0 &&
		entry->segment_seq == segment_seq && entry->frame_offset == frame_offset &&
		entry->frame_entry_index == frame_entry_index;
}

static int iterator_reposition_after_current(RecorderPlayer *reader, int direction)
{
	const RecorderEntry *current = current_entry(reader);
	StoredEntry key;
	char group[64];
	size_t i;

	if (!current || !current->group ||
		snprintf(group, sizeof(group), "%s", current->group) >= (int)sizeof(group)) return -1;
	memset(&key, 0, sizeof(key));
	key.entry = *current;
	key.entry.group = group;
	if (iterator_seek_realtime(reader, key.entry.realtime_ts) != 0) return -1;
	for (i = 0; i < reader->source_count; i++) {
		IteratorSource *source = &reader->sources[i];

		if (direction == ITERATOR_STATE_FORWARD) {
			while (source_has_current(source) &&
				compare_stored_entries(&source->entries[source->entry_index], &key) <= 0) {
				int rc = source_advance(reader, source, ITERATOR_STATE_FORWARD);

				if (rc < 0) return -1;
				if (rc == 0) break;
			}
		} else {
			while (source_has_current(source) &&
				compare_stored_entries(&source->entries[source->entry_index], &key) < 0) {
				int rc = source_advance(reader, source, ITERATOR_STATE_FORWARD);

				if (rc < 0) return -1;
				if (rc == 0) break;
			}
			if (source_has_current(source)) {
				if (source_advance(reader, source, ITERATOR_STATE_REVERSE) < 0) return -1;
			} else if (source_position_edge(reader, source, ITERATOR_STATE_REVERSE) < 0) {
				return -1;
			}
		}
	}
	reader->current_source = SIZE_MAX;
	reader->current_entry_ptr = NULL;
	reader->current_valid = 0;
	reader->iterator_state = direction;
	return 0;
}

int rec_player_next(RecorderPlayer *reader)
{
	ssize_t pick;
	if (!reader) return -1;
	if (reader->iterator_state == ITERATOR_STATE_FOLLOW) {
		if (reader->follow_pending) {
			if (append_pending_entries(reader) != 0) return -1;
			reader->follow_pending = 0;
		}
		if (reader->current >= reader->entry_count) return 0;
		reader->current_entry_ptr = &reader->entries[reader->current++];
		reader->current_valid = 1;
		return 1;
	}
	if (reader->iterator_state == ITERATOR_STATE_CURSOR_PENDING) {
		reader->iterator_state = ITERATOR_STATE_FORWARD;
	} else if (reader->iterator_state == ITERATOR_STATE_REVERSE && reader->current_valid) {
		if (iterator_reposition_after_current(reader, ITERATOR_STATE_FORWARD) != 0) return -1;
	} else if (reader->iterator_state != ITERATOR_STATE_FORWARD &&
		rec_player_seek_head(reader) != 0) return -1;
	else if (reader->current_valid && source_advance(reader,
		&reader->sources[reader->current_source], ITERATOR_STATE_FORWARD) < 0) return -1;
	pick = iterator_pick(reader, ITERATOR_STATE_FORWARD);
	if (pick < 0) {
		reader->current_entry_ptr = NULL;
		reader->current_valid = 0;
		return 0;
	}
	reader->current_source = (size_t)pick;
	reader->current_entry_ptr = &reader->sources[pick].entries[
		reader->sources[pick].entry_index];
	reader->current_valid = 1;
	return 1;
}

int rec_player_previous(RecorderPlayer *reader)
{
	ssize_t pick;
	size_t i;
	if (!reader) return -1;
	if (reader->iterator_state == ITERATOR_STATE_CURSOR_PENDING) {
		for (i = 0; i < reader->source_count; i++) {
			IteratorSource *source = &reader->sources[i];
			int rc = source_has_current(source) ?
				source_advance(reader, source, ITERATOR_STATE_REVERSE) :
				source_position_edge(reader, source, ITERATOR_STATE_REVERSE);

			if (rc < 0) return -1;
		}
		reader->current_valid = 0;
		reader->current_entry_ptr = NULL;
		reader->iterator_state = ITERATOR_STATE_REVERSE;
	} else if ((reader->iterator_state == ITERATOR_STATE_FORWARD ||
		reader->iterator_state == ITERATOR_STATE_FOLLOW) && reader->current_valid) {
		if (iterator_reposition_after_current(reader, ITERATOR_STATE_REVERSE) != 0) return -1;
	} else if (reader->iterator_state == ITERATOR_STATE_FOLLOW) {
		reader->iterator_state = ITERATOR_STATE_REVERSE;
	} else if (reader->iterator_state != ITERATOR_STATE_REVERSE &&
		rec_player_seek_tail(reader) != 0) return -1;
	else if (reader->current_valid && source_advance(reader,
		&reader->sources[reader->current_source], ITERATOR_STATE_REVERSE) < 0) return -1;
	pick = iterator_pick(reader, ITERATOR_STATE_REVERSE);
	if (pick < 0) {
		reader->current_entry_ptr = NULL;
		reader->current_valid = 0;
		return 0;
	}
	reader->current_source = (size_t)pick;
	reader->current_entry_ptr = &reader->sources[pick].entries[
		reader->sources[pick].entry_index];
	reader->current_valid = 1;
	return 1;
}

int rec_player_get_entry(RecorderPlayer *reader, const RecorderEntry **entry_out)
{
	const RecorderEntry *entry = current_entry(reader);

	if (!entry || !entry_out) return -1;
	*entry_out = entry;
	return 0;
}

static int format_data(RecorderPlayer *reader, const char *field, const char *value)
{
	int size;
	char *data;

	if (!value) return -1;
	size = snprintf(NULL, 0, "%s=%s", field, value);
	if (size < 0) return -1;
	data = malloc((size_t)size + 1);
	if (!data) return -1;
	snprintf(data, (size_t)size + 1, "%s=%s", field, value);
	free(reader->data);
	reader->data = data;
	return size;
}

static int format_data_u64(RecorderPlayer *reader, const char *field, uint64_t value)
{
	char text[32];

	snprintf(text, sizeof(text), "%llu", (unsigned long long)value);
	return format_data(reader, field, text);
}

int rec_player_get_data(RecorderPlayer *reader, const char *field,
					 const void **data_out, size_t *size_out)
{
	const RecorderEntry *entry = current_entry(reader);
	int size;

	if (!entry || !field || !data_out || !size_out) return -1;
	if (strcmp(field, "MESSAGE") == 0) size = format_data(reader, field, entry->message);
	else if (strcmp(field, "PRIORITY") == 0) size = format_data_u64(reader, field, entry->priority);
	else if (strcmp(field, "_PID") == 0) size = format_data_u64(reader, field, entry->pid);
	else if (strcmp(field, "_UID") == 0) size = format_data_u64(reader, field, entry->uid);
	else if (strcmp(field, "_GID") == 0) size = format_data_u64(reader, field, entry->gid);
	else if (strcmp(field, "_HOSTNAME") == 0) size = format_data(reader, field, entry->hostname);
	else if (strcmp(field, "_COMM") == 0) size = format_data(reader, field, entry->comm);
	else if (strcmp(field, "_SYSTEMD_UNIT") == 0) size = format_data(reader, field, entry->unit);
	else if (strcmp(field, "_EXE") == 0) size = format_data(reader, field, entry->exe);
	else if (strcmp(field, "MESSAGE_ID") == 0) size = format_data(reader, field, entry->message_id);
	else if (strcmp(field, "ERRNO") == 0) size = format_data_u64(reader, field, entry->errno_value);
	else if (strcmp(field, "__REALTIME_TIMESTAMP") == 0) size = format_data_u64(reader, field, entry->realtime_ts);
	else if (strcmp(field, "_BOOT_ID") == 0) size = format_data(reader, field, entry->boot_id);
	else return -1;
	if (size < 0) return -1;
	*data_out = reader->data;
	*size_out = (size_t)size;
	return 0;
}

int rec_player_get_realtime_usec(RecorderPlayer *reader, uint64_t *usec_out)
{
	const RecorderEntry *entry = current_entry(reader);

	if (!entry || !usec_out) return -1;
	*usec_out = entry->realtime_ts;
	return 0;
}

int rec_player_get_monotonic_usec(RecorderPlayer *reader, uint64_t *usec_out,
							const char **boot_id_out)
{
	const RecorderEntry *entry = current_entry(reader);

	if (!entry || !usec_out) return -1;
	*usec_out = entry->monotonic_ts;
	if (boot_id_out) *boot_id_out = entry->boot_id;
	return 0;
}

int rec_player_get_cursor(RecorderPlayer *reader, char **cursor_out)
{
	const RecorderEntry *entry = current_entry(reader);
	char cursor[192];

	if (!entry || !cursor_out || !reader->have_store_id) return -1;
	if (!entry->group || !valid_group_name(entry->group)) return -1;
	snprintf(cursor, sizeof(cursor), "rec1:%016llx:%s:%llx:%llx:%x",
			(unsigned long long)reader->store_id,
			entry->group,
			(unsigned long long)entry->segment_seq,
			(unsigned long long)entry->frame_offset, entry->frame_entry_index);
	*cursor_out = strdup(cursor);
	return *cursor_out ? 0 : -1;
}

int rec_player_get_fd(RecorderPlayer *reader)
{
	return reader ? reader->inotify_fd : -1;
}

int rec_player_get_events(RecorderPlayer *reader)
{
	return reader && reader->inotify_fd >= 0 ? POLLIN : 0;
}

int rec_player_get_timeout(RecorderPlayer *reader, uint64_t *timeout_usec)
{
	struct timespec ts;

	if (!reader || !timeout_usec) return -1;
	if (reader->reliable_fd) {
		*timeout_usec = UINT64_MAX;
		return 0;
	}
	clock_gettime(CLOCK_MONOTONIC, &ts);
	*timeout_usec = (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000 + 1000000;
	return 0;
}

int rec_player_reliable_fd(RecorderPlayer *reader)
{
	return reader ? reader->reliable_fd : -1;
}

static int is_segment_event_name(const struct inotify_event *event)
{
	size_t len;

	if (!event->len || !event->name[0]) return 0;
	len = strlen(event->name);
	return len > 4 && strcmp(event->name + len - 4, ".seg") == 0;
}

int rec_player_process(RecorderPlayer *reader)
{
	char buffer[4096];
	ssize_t n;
	int result = RECORDER_PROCESS_NOP;

	if (!reader) return -1;
	if (reader->inotify_fd < 0) {
		reader->follow_pending = 1;
		reader->follow_topology_pending = 1;
		return RECORDER_PROCESS_INVALIDATE;
	}
	for (;;) {
		n = read(reader->inotify_fd, buffer, sizeof(buffer));
		if (n < 0 && errno == EAGAIN) break;
		if (n <= 0) return n == 0 ? RECORDER_PROCESS_INVALIDATE : -1;
		{
			size_t offset = 0;
			while (offset < (size_t)n) {
				struct inotify_event *event = (struct inotify_event *)(buffer + offset);
				if (event->mask & (IN_Q_OVERFLOW | IN_DELETE_SELF | IN_MOVE_SELF |
									IN_IGNORED)) {
					result = RECORDER_PROCESS_INVALIDATE;
				} else if (reader->path_is_directory && (event->mask & IN_ISDIR)) {
					if (event->mask & (IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM))
						result = RECORDER_PROCESS_INVALIDATE;
				} else if (!reader->path_is_directory || is_segment_event_name(event)) {
					if (event->mask & (IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM))
						result = RECORDER_PROCESS_INVALIDATE;
					else if (result != RECORDER_PROCESS_INVALIDATE &&
						(event->mask & (IN_MODIFY | IN_CLOSE_WRITE)))
						result = RECORDER_PROCESS_APPEND;
				}
				offset += sizeof(*event) + event->len;
			}
		}
	}
	if (result != RECORDER_PROCESS_NOP) {
		reader->follow_pending = 1;
	}
	if (result == RECORDER_PROCESS_INVALIDATE) {
		reader->follow_topology_pending = 1;
		if (add_directory_watches(reader) != 0) reader->reliable_fd = 0;
	}
	return result;
}
