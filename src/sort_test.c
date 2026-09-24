#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <flatcc/flatcc_builder.h>

#include "recorder_builder.h"
#include "librecorder.h"
#include "index.h"
#include "segment.h"

typedef struct {
	uint64_t *timestamps;
	size_t count;
	size_t capacity;
} TimestampList;

static int collect_timestamp(const RecorderEntry *entry, void *userdata)
{
	TimestampList *list = userdata;
	uint64_t *tmp;

	if (list->count == list->capacity) {
		size_t capacity = list->capacity ? list->capacity * 2 : 8;
		tmp = realloc(list->timestamps, capacity * sizeof(*tmp));
		if (!tmp) return -1;
		list->timestamps = tmp;
		list->capacity = capacity;
	}
	list->timestamps[list->count++] = entry->realtime_ts;
	return 0;
}

static int write_test_segment(const char *path, uint64_t sequence,
						 const uint64_t *timestamps, const uint64_t *monotonic,
						 size_t count,
						 int nonmonotonic)
{
	flatcc_builder_t builder;
	journal_CompactEntry_ref_t *entries = NULL;
	flatbuffers_string_ref_t message;
	flatbuffers_string_ref_t unit;
	journal_CompactEntry_vec_ref_t entry_vector;
	void *chunk = NULL;
	SegmentHeader header;
	SegmentFooter footer;
	FILE *fp = NULL;
	size_t chunk_size;
	size_t i;
	uint64_t max_realtime_ts;
	int rc = -1;

	entries = calloc(count, sizeof(*entries));
	if (!entries) goto out;
	flatcc_builder_init(&builder);
	max_realtime_ts = timestamps[0];
	message = flatbuffers_string_create_str(&builder, "sort-test");
	unit = flatbuffers_string_create_str(&builder, "sort-test.service");
	for (i = 0; i < count; i++) {
		if (journal_CompactEntry_start(&builder) != 0) goto builder_out;
		journal_CompactEntry_realtime_ts_add(&builder, timestamps[i]);
		journal_CompactEntry_monotonic_ts_add(&builder,
			monotonic ? monotonic[i] : timestamps[i]);
		journal_CompactEntry_priority_add(&builder, 5);
		journal_CompactEntry_message_add(&builder, message);
		journal_CompactEntry_unit_add(&builder, unit);
		entries[i] = journal_CompactEntry_end(&builder);
		if (!entries[i]) goto builder_out;
		if (timestamps[i] > max_realtime_ts) max_realtime_ts = timestamps[i];
	}
	entry_vector = journal_CompactEntry_vec_create(&builder, entries, count);
	if (!entry_vector || !journal_DefaultChunk_create_as_root(&builder, entry_vector) ||
		!(chunk = flatcc_builder_finalize_buffer(&builder, &chunk_size))) goto builder_out;

	memset(&header, 0, sizeof(header));
	header.flags = SEGMENT_FLAG_COMPACT_ENTRIES;
	header.segment_seq = sequence;
	header.boot_seq = 1;
	strcpy(header.boot_id, "sort-test-boot");
	strcpy(header.timezone, "+0000");
	header.first_realtime_ts = timestamps[0];
	header.first_monotonic_ts = monotonic ? monotonic[0] : timestamps[0];
	memset(&footer, 0, sizeof(footer));
	footer.entry_count = count;
	footer.last_realtime_ts = max_realtime_ts;
	footer.last_monotonic_ts = monotonic ? monotonic[count - 1] : timestamps[count - 1];
	if (nonmonotonic)
		footer.footer_flags |= SEGMENT_FOOTER_FLAG_REALTIME_NONMONOTONIC;

	fp = fopen(path, "wb");
	if (!fp || segment_write_header(fp, &header, NULL, 0, NULL) != 0 ||
		segment_write_frame(fp, NULL, 0, chunk, (uint32_t)chunk_size,
						(uint32_t)chunk_size) != 0 || segment_write_footer(fp, &footer) != 0 ||
		fclose(fp) != 0) {
		fp = NULL;
		goto builder_out;
	}
	fp = NULL;
	rc = 0;

builder_out:
	flatcc_builder_clear(&builder);
out:
	if (fp) fclose(fp);
	free(entries);
	free(chunk);
	return rc;
}

static int expect_timestamps(const char *label, const uint64_t *expected,
						 size_t expected_count, const TimestampList *actual)
{
	size_t i;

	if (actual->count != expected_count) {
		fprintf(stderr, "sort-test: %s count=%zu want=%zu\n", label,
				actual->count, expected_count);
		return -1;
	}
	for (i = 0; i < expected_count; i++) {
		if (actual->timestamps[i] != expected[i]) {
			fprintf(stderr, "sort-test: %s[%zu]=%" PRIu64 " want=%" PRIu64 "\n",
					label, i, actual->timestamps[i], expected[i]);
			return -1;
		}
	}
	return 0;
}

static int collect_iterator(RecorderPlayer *reader, TimestampList *list)
{
	const RecorderEntry *entry;
	int rc;

	while ((rc = rec_player_next(reader)) > 0) {
		if (rec_player_get_entry(reader, &entry) != 0 ||
			collect_timestamp(entry, list) != 0) return -1;
	}
	return rc;
}

static int current_timestamp_is(RecorderPlayer *reader, uint64_t timestamp)
{
	const RecorderEntry *entry;

	return rec_player_get_entry(reader, &entry) == 0 && entry->realtime_ts == timestamp;
}

static int has_current_entry(RecorderPlayer *reader)
{
	const RecorderEntry *entry;

	return rec_player_get_entry(reader, &entry) == 0;
}

int main(void)
{
	const uint64_t first[] = {100, 300};
	const uint64_t second[] = {50, 200};
	const uint64_t third[] = {400, 350};
	const uint64_t first_monotonic[] = {100, 300};
	const uint64_t second_monotonic[] = {400, 500};
	const uint64_t third_monotonic[] = {600, 700};
	const uint64_t other[] = {1000, 2000};
	const uint64_t other_monotonic[] = {200, 550};
	const uint64_t recorded[] = {100, 300, 50, 200, 400, 350};
	const uint64_t wallclock[] = {50, 100, 200, 300, 350, 400};
	char store_template[] = "/tmp/recorder-sort-test-XXXXXX";
	char group_path[512] = {0};
	char state_path[512] = {0};
	char store_id_path[512] = {0};
	char other_group_path[512] = {0};
	char empty_group_path[512] = {0};
	char root_segment_path[512] = {0};
	char path[3][512] = {{0}};
	char index_path[3][512] = {{0}};
	char other_path[512] = {0};
	char other_index_path[512] = {0};
	RecorderPlayer *reader = NULL;
	char **listed_groups = NULL;
	size_t listed_count = 0;
	TimestampList actual = {0};
	SegmentHeader header;
	SegmentFooter footer;
	int store_fd = -1;
	FILE *state_fp = NULL;
	int rc = 1;
	int i;

	store_fd = mkstemp(store_template);
	if (store_fd < 0 || close(store_fd) != 0 || unlink(store_template) != 0 ||
		mkdir(store_template, 0755) != 0 ||
		snprintf(state_path, sizeof(state_path), "%s/state", store_template) >=
			(int)sizeof(state_path) || mkdir(state_path, 0755) != 0 ||
		snprintf(store_id_path, sizeof(store_id_path), "%s/store-id", state_path) >=
			(int)sizeof(store_id_path) ||
		snprintf(group_path, sizeof(group_path), "%s/p5", store_template) >=
			(int)sizeof(group_path) || mkdir(group_path, 0755) != 0) {
		fprintf(stderr, "sort-test: create store failed\n");
		goto out;
	}
	state_fp = fopen(store_id_path, "w");
	if (!state_fp) {
		fprintf(stderr, "sort-test: create store ID failed\n");
		goto out;
	}
	if (fputs("0123456789abcdef\n", state_fp) == EOF) {
		fclose(state_fp);
		state_fp = NULL;
		fprintf(stderr, "sort-test: create store ID failed\n");
		goto out;
	}
	if (fclose(state_fp) != 0) {
		state_fp = NULL;
		fprintf(stderr, "sort-test: create store ID failed\n");
		goto out;
	}
	state_fp = NULL;
	for (i = 0; i < 3; i++) {
		if (snprintf(path[i], sizeof(path[i]), "%s/%d.seg", group_path, i + 1) >=
				(int)sizeof(path[i]) || snprintf(index_path[i], sizeof(index_path[i]),
					"%s/%d.idx", group_path, i + 1) >= (int)sizeof(index_path[i])) goto out;
	}
	if (write_test_segment(path[0], 1, first, first_monotonic, 2, 0) != 0 ||
		write_test_segment(path[1], 2, second, second_monotonic, 2, 0) != 0 ||
		write_test_segment(path[2], 3, third, third_monotonic, 2, 1) != 0) {
		fprintf(stderr, "sort-test: write segments failed\n");
		goto out;
	}
	if (snprintf(root_segment_path, sizeof(root_segment_path), "%s/4.seg",
		store_template) >= (int)sizeof(root_segment_path) ||
		write_test_segment(root_segment_path, 4, other, other_monotonic, 2, 0) != 0) {
		fprintf(stderr, "sort-test: write root-level fixture failed\n");
		goto out;
	}
	for (i = 0; i < 3; i++) {
		if (index_rebuild_for_segment(path[i], index_path[i], NULL) != 0) {
			fprintf(stderr, "sort-test: build index %d failed\n", i + 1);
			goto out;
		}
	}
	if (segment_scan_path(path[2], NULL, NULL, NULL, &header, &footer, NULL) != 0 ||
		(footer.footer_flags & SEGMENT_FOOTER_FLAG_REALTIME_NONMONOTONIC) == 0 ||
		footer.last_realtime_ts != 400) {
		fprintf(stderr, "sort-test: nonmonotonic footer metadata invalid\n");
		goto out;
	}
	if (rec_player_open(&reader, store_template) != 0) goto out;
	if (rec_player_scan_file(reader, root_segment_path, collect_timestamp,
		&actual, 0, NULL) == 0) {
		fprintf(stderr, "sort-test: root-level segment was accepted\n");
		goto out;
	}
	if (rec_player_scan_all(reader, collect_timestamp, &actual) != 0 ||
		expect_timestamps("recorded", recorded, 6, &actual) != 0) goto out;
	free(actual.timestamps);
	actual = (TimestampList){0};
	if (rec_player_scan_wallclock(reader, collect_timestamp, &actual) != 0 ||
		expect_timestamps("wallclock", wallclock, 6, &actual) != 0) goto out;
	free(actual.timestamps);
	actual = (TimestampList){0};
	if (rec_player_set_order(reader, RECORDER_ORDER_RECORDED) != 0 ||
		rec_player_seek_head(reader) != 0 || collect_iterator(reader, &actual) != 0 ||
		expect_timestamps("iterator recorded", recorded, 6, &actual) != 0) goto out;
	free(actual.timestamps);
	actual = (TimestampList){0};
	if (rec_player_seek_head(reader) != 0 || rec_player_next(reader) != 1 ||
		!current_timestamp_is(reader, 100) || rec_player_next(reader) != 1 ||
		!current_timestamp_is(reader, 300) ||
		rec_player_set_order(reader, RECORDER_ORDER_WALLCLOCK) != 0 ||
		!current_timestamp_is(reader, 300) || rec_player_next(reader) != 1 ||
		rec_player_set_order(reader, RECORDER_ORDER_RECORDED) != 0 ||
		!has_current_entry(reader)) {
		fprintf(stderr, "sort-test: order change did not preserve position\n");
		goto out;
	}
	if (rec_player_set_order(reader, RECORDER_ORDER_WALLCLOCK) != 0 ||
		rec_player_seek_head(reader) != 0) goto out;
	rec_player_close(reader);
	reader = NULL;
	if (snprintf(other_group_path, sizeof(other_group_path), "%s/p6", store_template) >=
			(int)sizeof(other_group_path) || mkdir(other_group_path, 0755) != 0 ||
		snprintf(other_path, sizeof(other_path), "%s/1.seg", other_group_path) >=
			(int)sizeof(other_path) ||
		snprintf(other_index_path, sizeof(other_index_path), "%s/1.idx", other_group_path) >=
			(int)sizeof(other_index_path) ||
		write_test_segment(other_path, 1, other, other_monotonic, 2, 0) != 0 ||
		index_rebuild_for_segment(other_path, other_index_path, NULL) != 0 ||
		rec_player_open(&reader, store_template) != 0 ||
		rec_player_set_order(reader, RECORDER_ORDER_RECORDED) != 0 ||
		rec_player_seek_head(reader) != 0 || rec_player_next(reader) != 1 ||
		!current_timestamp_is(reader, 100) || rec_player_next(reader) != 1 ||
		!current_timestamp_is(reader, 1000)) {
		fprintf(stderr, "sort-test: recorded cross-group order failed\n");
		goto out;
	}
	{
		char *cursor = NULL;

		if (rec_player_get_cursor(reader, &cursor) != 0) goto out;
		rec_player_close(reader);
		reader = NULL;
		if (rec_player_open(&reader, store_template) != 0 ||
			rec_player_set_order(reader, RECORDER_ORDER_RECORDED) != 0 ||
			rec_player_seek_cursor(reader, cursor) != 0) {
			fprintf(stderr, "sort-test: recorded cursor seek failed\n");
			free(cursor);
			goto out;
		}
		if (rec_player_next(reader) != 1 || !current_timestamp_is(reader, 1000)) {
			fprintf(stderr, "sort-test: cursor entry mismatch\n");
			free(cursor);
			goto out;
		}
		if (rec_player_next(reader) != 1 || !current_timestamp_is(reader, 300)) {
			fprintf(stderr, "sort-test: cursor successor mismatch\n");
			free(cursor);
			goto out;
		}
		if (rec_player_seek_cursor(reader, cursor) != 0 ||
			rec_player_previous(reader) != 1 || !current_timestamp_is(reader, 100)) {
			fprintf(stderr, "sort-test: recorded cross-group cursor resume failed\n");
			free(cursor);
			goto out;
		}
		free(cursor);
	}
	{
		const char *only_p6[] = {"p6"};
		const char *both[] = {"p5", "p6"};
		char *excluded_cursor = NULL;

		if (snprintf(empty_group_path, sizeof(empty_group_path), "%s/p7",
			store_template) >= (int)sizeof(empty_group_path) ||
			mkdir(empty_group_path, 0755) != 0 ||
			rec_player_set_group_filter(reader, only_p6, 1) != 0 ||
			rec_player_list_groups(reader, &listed_groups, &listed_count) != 0 ||
			listed_count != 2 || strcmp(listed_groups[0], "p5") != 0 ||
			strcmp(listed_groups[1], "p6") != 0) {
			fprintf(stderr, "sort-test: available group listing failed\n");
			goto out;
		}
		for (size_t j = 0; j < listed_count; j++) free(listed_groups[j]);
		free(listed_groups);
		listed_groups = NULL;
		listed_count = 0;
		if (rec_player_scan_all(reader, collect_timestamp, &actual) != 0 ||
			expect_timestamps("filtered scan", other, 2, &actual) != 0) goto out;
		free(actual.timestamps);
		actual = (TimestampList){0};
		if (rec_player_scan_wallclock(reader, collect_timestamp, &actual) != 0 ||
			expect_timestamps("filtered wallclock", other, 2, &actual) != 0) goto out;
		free(actual.timestamps);
		actual = (TimestampList){0};
		if (rec_player_scan_follow(reader, collect_timestamp, &actual, 2) != 0 ||
			expect_timestamps("filtered follow", other, 2, &actual) != 0) goto out;
		free(actual.timestamps);
		actual = (TimestampList){0};
		if (rec_player_seek_head(reader) != 0 || collect_iterator(reader, &actual) != 0 ||
			expect_timestamps("filtered iterator", other, 2, &actual) != 0) goto out;
		free(actual.timestamps);
		actual = (TimestampList){0};
		if (rec_player_seek_head(reader) != 0 || rec_player_next(reader) != 1 ||
			rec_player_get_cursor(reader, &excluded_cursor) != 0 ||
			rec_player_set_group_filter(reader, both, 2) != 0 ||
			rec_player_scan_all(reader, collect_timestamp, &actual) != 0 ||
			actual.count != 8 ||
			rec_player_set_group_filter(reader, only_p6, 1) != 0 ||
			rec_player_seek_cursor(reader, excluded_cursor) != 0) {
			fprintf(stderr, "sort-test: group selection failed\n");
			free(excluded_cursor);
			goto out;
		}
		free(actual.timestamps);
		actual = (TimestampList){0};
		if (unlink(other_index_path) != 0 ||
			rec_player_set_group_filter(reader, both, 1) != 0 ||
			rec_player_set_order(reader, RECORDER_ORDER_RECORDED) != 0 ||
			rec_player_seek_cursor(reader, excluded_cursor) != 0 ||
			rec_player_next(reader) != 1 || !current_timestamp_is(reader, 300)) {
			fprintf(stderr, "sort-test: excluded cursor did not resume in recorded order\n");
			free(excluded_cursor);
			goto out;
		}
		free(excluded_cursor);
		if (rec_player_seek_head(reader) != 0 || rec_player_next(reader) != 1 ||
			rec_player_get_cursor(reader, &excluded_cursor) != 0 ||
			rec_player_set_group_filter(reader, only_p6, 1) != 0 ||
			rec_player_set_order(reader, RECORDER_ORDER_WALLCLOCK) != 0 ||
			rec_player_seek_cursor(reader, excluded_cursor) != 0 ||
			rec_player_next(reader) != 1 || !current_timestamp_is(reader, 1000)) {
			fprintf(stderr, "sort-test: excluded cursor did not resume in wallclock order\n");
			free(excluded_cursor);
			goto out;
		}
		free(excluded_cursor);
		if (rec_player_set_group_filter(reader, NULL, 0) != 0 ||
			rec_player_scan_all(reader, collect_timestamp, &actual) != 0 ||
			actual.count != 8) {
			fprintf(stderr, "sort-test: clearing group selection failed\n");
			goto out;
		}
		free(actual.timestamps);
		actual = (TimestampList){0};
	}
	rc = 0;

out:
	if (state_fp) fclose(state_fp);
	for (size_t j = 0; j < listed_count; j++) free(listed_groups[j]);
	free(listed_groups);
	free(actual.timestamps);
	rec_player_close(reader);
	for (i = 0; i < 3; i++) {
		unlink(index_path[i]);
		unlink(path[i]);
	}
	unlink(other_index_path);
	unlink(other_path);
	unlink(root_segment_path);
	rmdir(group_path);
	rmdir(other_group_path);
	rmdir(empty_group_path);
	unlink(store_id_path);
	rmdir(state_path);
	rmdir(store_template);
	if (rc == 0) printf("sort ordering ok\n");
	return rc;
}
