#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
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
	fprintf(stderr, "Usage: %s [-f] [-b BATCH-SIZE] [--sort wallclock] LOG-DIRECTORY\n", name);
}

static void wait_for_reader_change(RecorderPlayer *reader)
{
	uint64_t deadline;
	struct timespec now;
	int timeout_ms = 1000;
	int fd = rec_player_get_fd(reader);
	struct pollfd pfd = {
		.fd = fd,
		.events = (short)rec_player_get_events(reader),
	};

	if (rec_player_get_timeout(reader, &deadline) == 0) {
		if (deadline == UINT64_MAX) {
			timeout_ms = -1;
		} else if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
			uint64_t current = (uint64_t)now.tv_sec * UINT64_C(1000000) + now.tv_nsec / 1000;
			uint64_t wait_usec = deadline > current ? deadline - current : 0;
			timeout_ms = (int)((wait_usec + 999) / 1000);
		}
	}
	(void)poll(fd >= 0 ? &pfd : NULL, fd >= 0 ? 1 : 0, timeout_ms);
	if (fd >= 0 && pfd.revents) (void)rec_player_process(reader);
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
	int follow = 0;
	int argi = 1;
	int rc = 1;

	while (argi < argc && argv[argi][0] == '-') {
		if (strcmp(argv[argi], "-f") == 0) {
			follow = 1;
		} else if (strcmp(argv[argi], "-b") == 0) {
			char *end = NULL;
			unsigned long long value;

			if (++argi >= argc) {
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
			if (++argi >= argc || strcmp(argv[argi], "wallclock") != 0) {
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
		if (in_batch == 0) {
			if (!follow) break;
			wait_for_reader_change(reader);
			/* An initially empty store has no cursor to resume from. */
			if (!cursor && rec_player_seek_head(reader) != 0) {
				fprintf(stderr, "batch-reader: cannot rescan %s\n", path);
				goto out;
			}
			continue;
		}
		batches++;
		if ((follow || rc != 0) && rec_player_get_cursor(reader, &cursor) != 0) {
			fprintf(stderr, "batch-reader: cannot get cursor\n");
			goto out;
		}
		if (rc == 0) {
			if (!follow) break;
			wait_for_reader_change(reader);
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
