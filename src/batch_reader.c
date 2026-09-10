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
	fprintf(stderr, "Usage: %s [-b BATCH-SIZE] LOG-DIRECTORY\n", name);
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
	int argi = 1;
	int rc = 1;

	if (argi + 2 <= argc && strcmp(argv[argi], "-b") == 0) {
		char *end = NULL;
		unsigned long long value;

		errno = 0;
		value = strtoull(argv[argi + 1], &end, 10);
		if (errno != 0 || !end || *end != '\0' || value == 0 || value > SIZE_MAX) {
			usage(argv[0]);
			return 2;
		}
		batch_size = (size_t)value;
		argi += 2;
	}
	if (argc - argi != 1) {
		usage(argv[0]);
		return 2;
	}
	path = argv[argi];
	if (rec_player_open(&reader, path) != 0 || rec_player_seek_head(reader) != 0) {
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
			free(cursor);
			cursor = NULL;
			resumes++;
		}
		while (in_batch < batch_size && (rc = rec_player_next(reader)) > 0) {
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
