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
#include "segment.h"

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
	int entries_loaded;
	char *data;
	SegmentDecryptor *decryptor;
};

typedef struct StoredEntry {
	RecorderEntry entry;
	char *boot_id;
	char *hostname;
	char *comm;
	char *unit;
	char *exe;
	char *message;
	char *message_id;
} StoredEntry;

typedef struct {
	rec_player_entry_cb callback;
	void *userdata;
	uint64_t min_frame_offset;
} ScanContext;

typedef struct {
	char path[512];
	uint64_t segment_seq;
} SegmentPath;

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

static void add_watch(RecorderPlayer *reader, const char *path)
{
	if (reader->inotify_fd >= 0) {
		(void)inotify_add_watch(reader->inotify_fd, path,
				IN_CREATE | IN_DELETE | IN_MOVED_TO | IN_MOVED_FROM |
				IN_MODIFY | IN_CLOSE_WRITE | IN_DELETE_SELF | IN_MOVE_SELF);
	}
}

static void add_directory_watches(RecorderPlayer *reader)
{
	DIR *dir;
	struct dirent *de;

	add_watch(reader, reader->path);
	dir = opendir(reader->path);
	if (!dir) return;
	while ((de = readdir(dir)) != NULL) {
		char child[512];
		struct stat st;

		if (!valid_group_name(de->d_name) ||
			snprintf(child, sizeof(child), "%s/%s", reader->path, de->d_name) >=
				(int)sizeof(child) || stat(child, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
		add_watch(reader, child);
	}
	closedir(dir);
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
			entry.frame_entry_index = (uint32_t)i;
			if (ctx->callback(&entry, ctx->userdata) != 0) return -1;
		}
	}
	return 0;
}

static void free_stored_entry(StoredEntry *stored)
{
	if (!stored) return;
	free(stored->boot_id);
	free(stored->hostname);
	free(stored->comm);
	free(stored->unit);
	free(stored->exe);
	free(stored->message);
	free(stored->message_id);
	memset(stored, 0, sizeof(*stored));
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
	reader->entries_loaded = 0;
}

static int copy_string(char **out, const char *value)
{
	*out = value ? strdup(value) : NULL;
	return !value || *out ? 0 : -1;
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
	if (copy_string(&stored->boot_id, entry->boot_id) != 0 ||
		copy_string(&stored->hostname, entry->hostname) != 0 ||
		copy_string(&stored->comm, entry->comm) != 0 ||
		copy_string(&stored->unit, entry->unit) != 0 ||
		copy_string(&stored->exe, entry->exe) != 0 ||
		copy_string(&stored->message, entry->message) != 0 ||
		copy_string(&stored->message_id, entry->message_id) != 0) {
		free_stored_entry(stored);
		return -1;
	}
	stored->entry.boot_id = stored->boot_id;
	stored->entry.hostname = stored->hostname;
	stored->entry.comm = stored->comm;
	stored->entry.unit = stored->unit;
	stored->entry.exe = stored->exe;
	stored->entry.message = stored->message;
	stored->entry.message_id = stored->message_id;
	reader->entry_count++;
	return 0;
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

static int compare_segment_path(const void *a, const void *b)
{
	const SegmentPath *left = a;
	const SegmentPath *right = b;

	return left->segment_seq < right->segment_seq ? -1 :
		left->segment_seq > right->segment_seq;
}

static int load_entries(RecorderPlayer *reader)
{
	SegmentPath *paths = NULL;
	size_t path_count = 0;
	size_t path_capacity = 0;
	size_t i;
	int rc = -1;

	if (reader->entries_loaded) return 0;
	if (reader->path_is_directory) {
		if (collect_segment_paths(reader->path, &paths, &path_count, &path_capacity) != 0) goto out;
	} else if (add_segment_path(&paths, &path_count, &path_capacity, reader->path, 0) != 0) {
		goto out;
	}
	qsort(paths, path_count, sizeof(*paths), compare_segment_path);
	for (i = 0; i < path_count; i++) {
		if (rec_player_scan_file(reader, paths[i].path, append_stored_entry, reader, 0, NULL) != 0) {
			clear_entries(reader);
			goto out;
		}
	}
	reader->entries_loaded = 1;
	rc = 0;
out:
	free(paths);
	return rc;
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
		if (S_ISDIR(st.st_mode)) add_directory_watches(reader);
		else add_watch(reader, path);
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
	free(reader->data);
	free(reader->path);
	free(reader);
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
	if (segment_scan_path(path, reader->decryptor, scan_frame, &ctx, &header,
						  &footer, &committed_end) != 0) return -1;
	if (committed_end_out) *committed_end_out = committed_end;
	return 0;
}

static const RecorderEntry *current_entry(RecorderPlayer *reader)
{
	if (!reader || reader->current == SIZE_MAX || reader->current >= reader->entry_count) return NULL;
	return &reader->entries[reader->current].entry;
}

static int parse_cursor(const char *cursor, uint64_t *store_id, uint64_t *segment_seq, uint64_t *frame_offset,
						uint32_t *frame_entry_index)
{
	unsigned long long store;
	unsigned long long segment;
	unsigned long long frame;
	unsigned int entry;
	char tail;

	if (!cursor || sscanf(cursor, "rec1:%llx:%llx:%llx:%x%c", &store, &segment, &frame, &entry, &tail) != 4) return -1;
	*store_id = store;
	*segment_seq = segment;
	*frame_offset = frame;
	*frame_entry_index = entry;
	return 0;
}

int rec_player_seek_head(RecorderPlayer *reader)
{
	if (!reader || load_entries(reader) != 0) return -1;
	reader->current = SIZE_MAX;
	return 0;
}

int rec_player_seek_tail(RecorderPlayer *reader)
{
	if (!reader || load_entries(reader) != 0) return -1;
	reader->current = reader->entry_count;
	return 0;
}

int rec_player_seek_cursor(RecorderPlayer *reader, const char *cursor)
{
	uint64_t segment_seq;
	uint64_t frame_offset;
	uint64_t store_id;
	uint32_t frame_entry_index;
	size_t i;

	if (!reader || !reader->have_store_id ||
		parse_cursor(cursor, &store_id, &segment_seq, &frame_offset, &frame_entry_index) != 0 ||
		store_id != reader->store_id ||
		load_entries(reader) != 0) return -1;
	for (i = 0; i < reader->entry_count; i++) {
		const RecorderEntry *entry = &reader->entries[i].entry;
		if (entry->segment_seq == segment_seq && entry->frame_offset == frame_offset &&
			entry->frame_entry_index == frame_entry_index) {
			reader->current = i == 0 ? SIZE_MAX : i - 1;
			return 0;
		}
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

	if (!entry || !reader->have_store_id ||
		parse_cursor(cursor, &store_id, &segment_seq, &frame_offset, &frame_entry_index) != 0 ||
		store_id != reader->store_id) return -1;
	return entry->segment_seq == segment_seq && entry->frame_offset == frame_offset &&
		entry->frame_entry_index == frame_entry_index;
}

int rec_player_next(RecorderPlayer *reader)
{
	if (!reader || load_entries(reader) != 0) return -1;
	if (reader->current == SIZE_MAX) reader->current = 0;
	else if (reader->current < reader->entry_count) reader->current++;
	return reader->current < reader->entry_count;
}

int rec_player_previous(RecorderPlayer *reader)
{
	if (!reader || load_entries(reader) != 0) return -1;
	if (reader->current == reader->entry_count && reader->entry_count > 0) {
		reader->current--;
	} else if (reader->current != SIZE_MAX) {
		if (reader->current == 0) {
			reader->current = SIZE_MAX;
			return 0;
		}
		reader->current--;
	} else {
		return 0;
	}
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
	char cursor[96];

	if (!entry || !cursor_out || !reader->have_store_id) return -1;
	snprintf(cursor, sizeof(cursor), "rec1:%016llx:%llx:%llx:%x",
			(unsigned long long)reader->store_id,
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

int rec_player_process(RecorderPlayer *reader)
{
	char buffer[4096];
	ssize_t n;
	int result = RECORDER_PROCESS_NOP;

	if (!reader || reader->inotify_fd < 0) return RECORDER_PROCESS_INVALIDATE;
	for (;;) {
		n = read(reader->inotify_fd, buffer, sizeof(buffer));
		if (n < 0 && errno == EAGAIN) break;
		if (n <= 0) return n == 0 ? RECORDER_PROCESS_INVALIDATE : -1;
		{
			size_t offset = 0;
			while (offset < (size_t)n) {
				struct inotify_event *event = (struct inotify_event *)(buffer + offset);
				if (event->mask & (IN_Q_OVERFLOW | IN_DELETE | IN_MOVED_FROM |
									IN_DELETE_SELF | IN_MOVE_SELF | IN_ISDIR)) result = RECORDER_PROCESS_INVALIDATE;
				else if (result != RECORDER_PROCESS_INVALIDATE) result = RECORDER_PROCESS_APPEND;
				offset += sizeof(*event) + event->len;
			}
		}
	}
	if (result != RECORDER_PROCESS_NOP) clear_entries(reader);
	if (result == RECORDER_PROCESS_INVALIDATE) add_directory_watches(reader);
	return result;
}
