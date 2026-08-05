#ifndef LIBRECORDER_H
#define LIBRECORDER_H

#include <stddef.h>
#include <stdint.h>

typedef struct RecorderPlayer RecorderPlayer;

typedef struct {
	/* Identity of the boot that produced this entry. */
	uint32_t boot_seq;
	const char *boot_id;
	uint64_t segment_seq;
	uint64_t frame_offset;
	uint32_t frame_entry_index;
	uint64_t realtime_ts;
	uint64_t monotonic_ts;
	uint32_t pid;
	uint32_t uid;
	uint32_t gid;
	uint8_t priority;
	uint16_t errno_value;
	const char *hostname;
	const char *comm;
	const char *unit;
	const char *exe;
	const char *message;
	const char *message_id;
} RecorderEntry;

typedef int (*rec_player_entry_cb)(const RecorderEntry *entry, void *userdata);

enum {
	RECORDER_PROCESS_NOP = 0,
	RECORDER_PROCESS_APPEND = 1,
	RECORDER_PROCESS_INVALIDATE = 2,
};

int rec_player_open(RecorderPlayer **reader, const char *path);
/*
 * Configure the PEM private key used for encrypted segments. This invalidates
 * any entries already loaded by the iterator. Pass NULL to clear the key.
 */
int rec_player_set_private_key(RecorderPlayer *reader, const char *path);
void rec_player_close(RecorderPlayer *reader);

/*
 * sd-journal-style iterator API.  next()/previous() return 1 when positioned
 * on an entry, 0 at the end, and a negative value on failure.  get_data()
 * returns a FIELD=value byte sequence whose lifetime ends at the next reader
 * call. Cursors use the opaque rec1: format and include the 64-bit store ID;
 * they require a store with state/store-id. get_cursor() allocates its result;
 * release it with free().
 */
int rec_player_seek_head(RecorderPlayer *reader);
int rec_player_seek_tail(RecorderPlayer *reader);
int rec_player_seek_cursor(RecorderPlayer *reader, const char *cursor);
int rec_player_test_cursor(RecorderPlayer *reader, const char *cursor);
int rec_player_next(RecorderPlayer *reader);
int rec_player_previous(RecorderPlayer *reader);
int rec_player_get_entry(RecorderPlayer *reader, const RecorderEntry **entry_out);
int rec_player_get_data(RecorderPlayer *reader, const char *field,
					 const void **data_out, size_t *size_out);
int rec_player_get_realtime_usec(RecorderPlayer *reader, uint64_t *usec_out);
int rec_player_get_monotonic_usec(RecorderPlayer *reader, uint64_t *usec_out,
							const char **boot_id_out);
int rec_player_get_cursor(RecorderPlayer *reader, char **cursor_out);

/* Scan one segment. Entry pointers are valid only for the duration of callback. */
int rec_player_scan_file(RecorderPlayer *reader, const char *path,
						  rec_player_entry_cb callback, void *userdata,
						  uint64_t min_frame_offset,
						  uint64_t *committed_end_out);

/* Poll integration, equivalent in shape to sd_journal_get_fd/events/timeout/process. */
int rec_player_get_fd(RecorderPlayer *reader);
int rec_player_get_events(RecorderPlayer *reader);
int rec_player_get_timeout(RecorderPlayer *reader, uint64_t *timeout_usec);
int rec_player_reliable_fd(RecorderPlayer *reader);
int rec_player_process(RecorderPlayer *reader);

#endif
