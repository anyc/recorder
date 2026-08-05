#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <flatcc/flatcc_builder.h>

#include "recorder_builder.h"
#include "segment.h"

typedef struct {
	int seen;
} SmokeContext;

static int check_active_unclosed_tiny_frame(void)
{
	FILE *fp = NULL;
	SegmentHeader header;
	SegmentFooter footer;
	char path[] = "/tmp/recorder-active-segment-smoke-XXXXXX";
	size_t committed_end = 0;
	size_t expect_end;
	int fd;
	unsigned char payload = 0;

	fd = mkstemp(path);
	if (fd < 0) {
		perror("mkstemp");
		return -1;
	}
	fp = fdopen(fd, "wb");
	if (!fp) {
		perror("fdopen");
		close(fd);
		unlink(path);
		return -1;
	}

	memset(&header, 0, sizeof(header));
	header.segment_seq = 8;
	header.boot_seq = 3;
	strcpy(header.boot_id, "boot-a");
	strcpy(header.timezone, "+0000");
	header.first_realtime_ts = 1234;
	header.first_monotonic_ts = 5678;
	if (segment_write_header(fp, &header, NULL, 0) != 0 ||
		segment_write_frame(fp, 0, &payload, 0, 0) != 0 ||
		fflush(fp) != 0) {
		fprintf(stderr, "smoke: write active segment failed\n");
		fclose(fp);
		unlink(path);
		return -1;
	}

	memset(&footer, 0, sizeof(footer));
	if (segment_scan_path(path, NULL, NULL, &header, &footer, &committed_end) != 0) {
		fprintf(stderr, "smoke: scan active segment failed\n");
		fclose(fp);
		unlink(path);
		return -1;
	}
	expect_end = segment_header_encoded_size() + 16 + 4;
	if (committed_end != expect_end) {
		fprintf(stderr, "smoke: active segment committed_end=%zu want=%zu\n",
				committed_end, expect_end);
		fclose(fp);
		unlink(path);
		return -1;
	}
	fclose(fp);
	unlink(path);
	return 0;
}

static int check_frame(const SegmentHeader *header,
						const SegmentFrameInfo *frame,
						const void *chunk_buf, size_t chunk_size,
						void *ctx)
{
	SmokeContext *sc = ctx;
	journal_Chunk_table_t chunk = journal_Chunk_as_root(chunk_buf);
	flatbuffers_uint32_vec_t entries = journal_Chunk_entries(chunk);
	journal_FullEntry_table_t entry;
	journal_Field_vec_t fields;
	journal_Field_table_t field;
	flatbuffers_uint8_vec_t field_value;

	(void)frame;
	(void)chunk_size;

	if (strcmp(header->boot_id, "boot-a") != 0 || strcmp(header->timezone, "+0000") != 0) {
		fprintf(stderr, "smoke: bad segment header\n");
		return -1;
	}
	if (flatbuffers_uint32_vec_len(entries) != 1) {
		fprintf(stderr, "smoke: bad entry count\n");
		return -1;
	}
	entry = journal_FullEntry_vec_at(entries, 0);
	fields = journal_FullEntry_fields(entry);
	if (journal_Field_vec_len(fields) != 1) {
		fprintf(stderr, "smoke: bad extra field count\n");
		return -1;
	}
	field = journal_Field_vec_at(fields, 0);
	field_value = journal_Field_value(field);
	if (strcmp(journal_FullEntry_message(entry), "hello smoke") != 0 ||
		strcmp(journal_FullEntry_unit(entry), "smoke.service") != 0 ||
		journal_FullEntry_priority(entry) != 5 ||
		strcmp(journal_Field_name(field), "CUSTOM_FIELD") != 0 ||
		flatbuffers_uint8_vec_len(field_value) != 3 ||
		flatbuffers_uint8_vec_at(field_value, 0) != 0x00 ||
		flatbuffers_uint8_vec_at(field_value, 1) != 0xff ||
		flatbuffers_uint8_vec_at(field_value, 2) != 0x7f) {
		fprintf(stderr, "smoke: bad entry payload\n");
		return -1;
	}
	sc->seen++;
	return 0;
}

int main(void)
{
	flatcc_builder_t B;
	flatbuffers_string_ref_t message_ref;
	flatbuffers_string_ref_t unit_ref;
	flatbuffers_string_ref_t field_name_ref;
	flatbuffers_uint8_vec_ref_t field_value_ref;
	journal_Field_ref_t field_ref;
	journal_Field_vec_ref_t fields_ref;
	journal_FullEntry_ref_t entry_ref;
	journal_FullEntry_vec_ref_t entries_ref;
	void *chunk_buf = NULL;
	size_t chunk_size_raw;
	FILE *fp = NULL;
	SegmentHeader header;
	SegmentFooter footer;
	SmokeContext ctx;
	char path[] = "/tmp/recorder-segment-smoke-XXXXXX";
	int fd;
	size_t committed_end = 0;

	if (check_active_unclosed_tiny_frame() != 0) {
		return 1;
	}

	fd = mkstemp(path);
	if (fd < 0) {
		perror("mkstemp");
		return 1;
	}
	fp = fdopen(fd, "wb");
	if (!fp) {
		perror("fdopen");
		close(fd);
		unlink(path);
		return 1;
	}

	memset(&header, 0, sizeof(header));
	header.segment_seq = 7;
	header.boot_seq = 3;
	strcpy(header.boot_id, "boot-a");
	strcpy(header.timezone, "+0000");
	header.first_realtime_ts = 1234;
	header.first_monotonic_ts = 5678;
	if (segment_write_header(fp, &header, NULL, 0) != 0) {
		fprintf(stderr, "smoke: write header failed\n");
		fclose(fp);
		unlink(path);
		return 1;
	}

	flatcc_builder_init(&B);
	message_ref = flatbuffers_string_create_str(&B, "hello smoke");
	unit_ref = flatbuffers_string_create_str(&B, "smoke.service");
	field_name_ref = flatbuffers_string_create_str(&B, "CUSTOM_FIELD");
	{
		const uint8_t value[] = {0x00, 0xff, 0x7f};
		field_value_ref = flatbuffers_uint8_vec_create(&B, value, sizeof(value));
	}
	journal_Field_start(&B);
	journal_Field_name_add(&B, field_name_ref);
	journal_Field_value_add(&B, field_value_ref);
	field_ref = journal_Field_end(&B);
	fields_ref = journal_Field_vec_create(&B, &field_ref, 1);

	journal_FullEntry_start(&B);
	journal_FullEntry_realtime_ts_add(&B, 1234);
	journal_FullEntry_monotonic_ts_add(&B, 5678);
	journal_FullEntry_priority_add(&B, 5);
	journal_FullEntry_message_add(&B, message_ref);
	journal_FullEntry_unit_add(&B, unit_ref);
	journal_FullEntry_fields_add(&B, fields_ref);
	entry_ref = journal_FullEntry_end(&B);

	entries_ref = journal_FullEntry_vec_create(&B, &entry_ref, 1);
	if (!entries_ref || !journal_Chunk_create_as_root(&B, entries_ref)) {
		fprintf(stderr, "smoke: build chunk failed\n");
		fclose(fp);
		unlink(path);
		return 1;
	}
	chunk_buf = flatcc_builder_finalize_buffer(&B, &chunk_size_raw);
	if (!chunk_buf) {
		fprintf(stderr, "smoke: finalize failed\n");
		fclose(fp);
		unlink(path);
		return 1;
	}
	if (segment_write_frame(fp, 0, chunk_buf, (uint32_t)chunk_size_raw, (uint32_t)chunk_size_raw) != 0) {
		fprintf(stderr, "smoke: write frame failed\n");
		free(chunk_buf);
		fclose(fp);
		unlink(path);
		return 1;
	}
	memset(&footer, 0, sizeof(footer));
	footer.entry_count = 1;
	footer.last_realtime_ts = 1234;
	footer.last_monotonic_ts = 5678;
	if (segment_write_footer(fp, &footer) != 0) {
		fprintf(stderr, "smoke: write footer failed\n");
		free(chunk_buf);
		fclose(fp);
		unlink(path);
		return 1;
	}
	free(chunk_buf);
	flatcc_builder_clear(&B);
	fclose(fp);

	ctx.seen = 0;
	if (segment_scan_path(path, check_frame, &ctx, &header, &footer, &committed_end) != 0) {
		fprintf(stderr, "smoke: scan failed\n");
		unlink(path);
		return 1;
	}
	if (ctx.seen != 1 || footer.entry_count != 1 || committed_end == 0) {
		fprintf(stderr, "smoke: wrong scan result\n");
		unlink(path);
		return 1;
	}
	unlink(path);
	printf("smoke ok\n");
	return 0;
}
