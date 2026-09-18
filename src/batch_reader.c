#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "librecorder.h"

static uint64_t monotonic_usec(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
	return (uint64_t)ts.tv_sec * UINT64_C(1000000) + (uint64_t)ts.tv_nsec / 1000;
}

static void usage(const char *name)
{
	fprintf(stderr, "Usage: %s [-b BATCH-SIZE] [--sort wallclock] LOG-DIRECTORY\n", name);
}

static int print_entry(RecorderPlayer *reader)
{
	const RecorderEntry *entry;

	if (rec_player_get_entry(reader, &entry) != 0 || !entry) return -1;
	printf("%" PRIu64 " %s:%" PRIu64 ":%" PRIu64 ":%u %s\n",
		entry->realtime_ts, entry->group ? entry->group : "-", entry->segment_seq,
		entry->frame_offset, entry->frame_entry_index,
		entry->message ? entry->message : "");
	return fflush(stdout) == 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
	RecorderPlayer *reader = NULL;
	char *cursor = NULL;
	const char *path;
	uint64_t started;
	uint64_t elapsed;
	size_t batch_size = 50;
	size_t entries = 0;
	size_t batches = 0;
	size_t resumes = 0;
	RecorderPlayerOrder order = RECORDER_ORDER_RECORDED;
	int argi = 1;
	int rc = 1;

	while (argi < argc - 1) {
		if (strcmp(argv[argi], "-b") == 0) {
			char *end = NULL;
			unsigned long long value;

			if (++argi >= argc - 1) {
				usage(argv[0]);
				return 2;
			}
			errno = 0;
			value = strtoull(argv[argi], &end, 10);
			if (errno != 0 || !end || *end != '\0' || value == 0 || value > SIZE_MAX) {
				usage(argv[0]);
				return 2;
			}
			batch_size = (size_t)value;
		} else if (strcmp(argv[argi], "--sort") == 0) {
			if (++argi >= argc - 1 || strcmp(argv[argi], "wallclock") != 0) {
				usage(argv[0]);
				return 2;
			}
			order = RECORDER_ORDER_WALLCLOCK;
		} else if (strncmp(argv[argi], "--sort=", 7) == 0 &&
			strcmp(argv[argi] + 7, "wallclock") == 0) {
			order = RECORDER_ORDER_WALLCLOCK;
		} else {
			usage(argv[0]);
			return 2;
		}
		argi++;
	}
	if (argc - argi != 1) {
		usage(argv[0]);
		return 2;
	}
	path = argv[argi];
	if (rec_player_open(&reader, path) != 0 || rec_player_set_order(reader, order) != 0 ||
		rec_player_seek_head(reader) != 0) {
		fprintf(stderr, "batch-reader: cannot open or seek %s\n", path);
		goto out;
	}

	started = monotonic_usec();
	for (;;) {
		size_t in_batch = 0;

		if (cursor) {
			if (rec_player_seek_cursor(reader, cursor) != 0) {
				fprintf(stderr, "batch-reader: cannot resume from cursor\n");
				goto out;
			}
			/* Like sd_journal_seek_cursor(), seeking does not make an entry
			 * current. Select and skip the last entry from the prior batch. */
			if (rec_player_next(reader) != 1 ||
				rec_player_test_cursor(reader, cursor) != 1) {
				fprintf(stderr, "batch-reader: resume cursor is unavailable\n");
				goto out;
			}
			free(cursor);
			cursor = NULL;
			resumes++;
		}
		while (in_batch < batch_size && (rc = rec_player_next(reader)) > 0) {
			if (print_entry(reader) != 0) {
				fprintf(stderr, "batch-reader: cannot print entry\n");
				goto out;
			}
			entries++;
			in_batch++;
		}
		if (rc < 0) {
			fprintf(stderr, "batch-reader: iteration failed\n");
			goto out;
		}
		if (in_batch == 0) break;
		batches++;
		if (rc == 0) break;
		if (rec_player_get_cursor(reader, &cursor) != 0) {
			fprintf(stderr, "batch-reader: cannot get cursor\n");
			goto out;
		}
	}
	elapsed = monotonic_usec() - started;
	printf("entries: %zu\nbatches: %zu\ncursor resumes: %zu\nelapsed: %.3f s\n",
		entries, batches, resumes, elapsed / 1000000.0);
	rc = 0;

out:
	free(cursor);
	rec_player_close(reader);
	return rc;
}
