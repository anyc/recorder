#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <flatcc/flatcc_builder.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "recorder_builder.h"
#include "helper.h"
#include "librecorder.h"
#include "segment.h"

typedef struct {
	int seen;
} SmokeContext;

static int create_rsa_keypair(char *private_path, char *public_path)
{
	EVP_PKEY_CTX *key_ctx = NULL;
	EVP_PKEY *key = NULL;
	FILE *private_fp = NULL;
	FILE *public_fp = NULL;
	int private_fd = -1;
	int public_fd = -1;
	int rv = -1;

	private_fd = mkstemp(private_path);
	public_fd = mkstemp(public_path);
	if (private_fd < 0 || public_fd < 0) {
		goto out;
	}
	private_fp = fdopen(private_fd, "wb");
	if (!private_fp) {
		goto out;
	}
	private_fd = -1;
	public_fp = fdopen(public_fd, "wb");
	if (!public_fp) {
		goto out;
	}
	public_fd = -1;

	key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!key_ctx || EVP_PKEY_keygen_init(key_ctx) <= 0 ||
		EVP_PKEY_CTX_set_rsa_keygen_bits(key_ctx, 2048) <= 0 ||
		EVP_PKEY_keygen(key_ctx, &key) <= 0 ||
		PEM_write_PrivateKey(private_fp, key, NULL, NULL, 0, NULL, NULL) != 1 ||
		PEM_write_PUBKEY(public_fp, key) != 1 ||
		fclose(private_fp) != 0) {
		goto out;
	}
	private_fp = NULL;
	if (fclose(public_fp) != 0) {
		public_fp = NULL;
		goto out;
	}
	public_fp = NULL;
	rv = 0;

out:
	if (private_fp) {
		fclose(private_fp);
	}
	if (public_fp) {
		fclose(public_fp);
	}
	if (private_fd >= 0) {
		close(private_fd);
	}
	if (public_fd >= 0) {
		close(public_fd);
	}
	EVP_PKEY_free(key);
	EVP_PKEY_CTX_free(key_ctx);
	if (rv != 0) {
		unlink(private_path);
		unlink(public_path);
	}
	return rv;
}

static int read_file(const char *path, unsigned char **buf_out, size_t *size_out)
{
	FILE *fp = NULL;
	unsigned char *buf = NULL;
	long end;
	int rv = -1;

	*buf_out = NULL;
	*size_out = 0;
	fp = fopen(path, "rb");
	if (!fp || fseek(fp, 0, SEEK_END) != 0 || (end = ftell(fp)) < 0 ||
		fseek(fp, 0, SEEK_SET) != 0) {
		goto out;
	}
	buf = malloc(end ? (size_t)end : 1);
	if (!buf || fread(buf, 1, (size_t)end, fp) != (size_t)end) {
		goto out;
	}
	*buf_out = buf;
	*size_out = (size_t)end;
	buf = NULL;
	rv = 0;

out:
	free(buf);
	if (fp) {
		fclose(fp);
	}
	return rv;
}

static void update_encrypted_frame_crc(unsigned char *frame)
{
	uint32_t stored_len = read_u32_le(frame + 4);
	unsigned char *tag = frame + 16 + stored_len;
	uint32_t crc = recorder_crc32(frame, 16) ^
		recorder_crc32(frame + 16, stored_len) ^ recorder_crc32(tag, 16);

	write_u32_le(tag + 16, crc);
}

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
	if (segment_write_header(fp, &header, NULL, 0, NULL) != 0 ||
		segment_write_frame(fp, NULL, 0, &payload, 0, 0) != 0 ||
		fflush(fp) != 0) {
		fprintf(stderr, "smoke: write active segment failed\n");
		fclose(fp);
		unlink(path);
		return -1;
	}

	memset(&footer, 0, sizeof(footer));
	if (segment_scan_path(path, NULL, NULL, NULL, &header, &footer, &committed_end) != 0) {
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

static int check_encrypted_segment(const void *chunk_buf, size_t chunk_size)
{
	char private_path[] = "/tmp/recorder-private-key-XXXXXX";
	char public_path[] = "/tmp/recorder-public-key-XXXXXX";
	char wrong_private_path[] = "/tmp/recorder-wrong-private-key-XXXXXX";
	char wrong_public_path[] = "/tmp/recorder-wrong-public-key-XXXXXX";
	char segment_path[] = "/tmp/recorder-encrypted-segment-XXXXXX";
	SegmentEncryptor *encryptor = NULL;
	SegmentDecryptor *decryptor = NULL;
	SegmentDecryptor *wrong_decryptor = NULL;
	SegmentHeader header;
	SegmentFooter footer;
	SmokeContext ctx;
	unsigned char *segment_buf = NULL;
	size_t segment_size = 0;
	size_t frame_offset = 0;
	size_t committed_end = 0;
	uint32_t stored_len;
	uint32_t frame_len;
	FILE *fp = NULL;
	int fd = -1;
	int rv = -1;

	if (create_rsa_keypair(private_path, public_path) != 0 ||
		create_rsa_keypair(wrong_private_path, wrong_public_path) != 0 ||
		segment_encryptor_create(public_path, &encryptor) != 0 ||
		segment_decryptor_create(private_path, &decryptor) != 0 ||
		segment_decryptor_create(wrong_private_path, &wrong_decryptor) != 0) {
		fprintf(stderr, "smoke: create encryption keys failed\n");
		goto out;
	}

	fd = mkstemp(segment_path);
	if (fd < 0 || !(fp = fdopen(fd, "wb"))) {
		fprintf(stderr, "smoke: create encrypted segment failed\n");
		goto out;
	}
	fd = -1;
	memset(&header, 0, sizeof(header));
	header.flags = SEGMENT_FLAG_ENCRYPTED;
	header.segment_seq = 9;
	header.boot_seq = 3;
	strcpy(header.boot_id, "boot-a");
	strcpy(header.timezone, "+0000");
	header.first_realtime_ts = 1234;
	header.first_monotonic_ts = 5678;
	memset(&footer, 0, sizeof(footer));
	footer.entry_count = 1;
	footer.last_realtime_ts = 1234;
	footer.last_monotonic_ts = 5678;
	if (segment_write_header(fp, &header, NULL, 0, encryptor) != 0 ||
		segment_write_frame(fp, encryptor, 0, chunk_buf, (uint32_t)chunk_size,
							(uint32_t)chunk_size) != 0 ||
		segment_write_footer(fp, &footer) != 0 || fclose(fp) != 0) {
		fprintf(stderr, "smoke: write encrypted segment failed\n");
		fp = NULL;
		goto out;
	}
	fp = NULL;

	memset(&header, 0, sizeof(header));
	memset(&footer, 0, sizeof(footer));
	if (segment_scan_path(segment_path, NULL, NULL, NULL, &header, &footer,
						  &committed_end) != 0 ||
		(header.flags & SEGMENT_FLAG_ENCRYPTED) == 0 ||
		footer.entry_count != 1 || committed_end == 0) {
		fprintf(stderr, "smoke: encrypted metadata-only scan failed\n");
		goto out;
	}
	ctx.seen = 0;
	if (segment_scan_path(segment_path, NULL, check_frame, &ctx, NULL, NULL,
						  NULL) == 0) {
		fprintf(stderr, "smoke: encrypted scan accepted missing key\n");
		goto out;
	}
	ctx.seen = 0;
	if (segment_scan_path(segment_path, wrong_decryptor, check_frame, &ctx,
						  NULL, NULL, NULL) == 0) {
		fprintf(stderr, "smoke: encrypted scan accepted wrong key\n");
		goto out;
	}
	ctx.seen = 0;
	if (segment_scan_path(segment_path, decryptor, check_frame, &ctx, &header,
						  &footer, &committed_end) != 0 || ctx.seen != 1 ||
		footer.entry_count != 1) {
		fprintf(stderr, "smoke: encrypted round-trip failed\n");
		goto out;
	}

	if (read_file(segment_path, &segment_buf, &segment_size) != 0 ||
		segment_read_header(segment_buf, segment_size, &header, &frame_offset) != 0 ||
		frame_offset + 16 > segment_size) {
		fprintf(stderr, "smoke: read encrypted segment bytes failed\n");
		goto out;
	}
	stored_len = read_u32_le(segment_buf + frame_offset + 4);
	frame_len = read_u32_le(segment_buf + frame_offset + 12);
	if (stored_len != chunk_size ||
		frame_len != 16u + stored_len + 16u + 4u ||
		frame_len > segment_size - frame_offset || stored_len == 0 ||
		memcmp(segment_buf + frame_offset + 16, chunk_buf, stored_len) == 0) {
		fprintf(stderr, "smoke: encrypted frame layout is invalid\n");
		goto out;
	}

	/* Recompute the CRC so these mutations reach GCM authentication. */
	segment_buf[frame_offset + 16] ^= 1;
	update_encrypted_frame_crc(segment_buf + frame_offset);
	ctx.seen = 0;
	if (segment_scan_buffer(segment_buf, segment_size, decryptor, check_frame,
							&ctx, NULL, NULL, NULL) == 0) {
		fprintf(stderr, "smoke: encrypted scan accepted ciphertext tampering\n");
		goto out;
	}
	segment_buf[frame_offset + 16] ^= 1;
	segment_buf[frame_offset + 16 + stored_len] ^= 1;
	update_encrypted_frame_crc(segment_buf + frame_offset);
	ctx.seen = 0;
	if (segment_scan_buffer(segment_buf, segment_size, decryptor, check_frame,
							&ctx, NULL, NULL, NULL) == 0) {
		fprintf(stderr, "smoke: encrypted scan accepted tag tampering\n");
		goto out;
	}
	rv = 0;

out:
	if (fp) {
		fclose(fp);
	}
	if (fd >= 0) {
		close(fd);
	}
	free(segment_buf);
	segment_encryptor_free(encryptor);
	segment_decryptor_free(decryptor);
	segment_decryptor_free(wrong_decryptor);
	unlink(segment_path);
	unlink(private_path);
	unlink(public_path);
	unlink(wrong_private_path);
	unlink(wrong_public_path);
	return rv;
}

static int check_reader_entry(const RecorderEntry *entry, void *ctx)
{
	SmokeContext *sc = ctx;

	if (entry->boot_seq != 3 || !entry->boot_id || strcmp(entry->boot_id, "boot-a") != 0 ||
		!entry->message || strcmp(entry->message, "hello smoke") != 0 ||
		!entry->unit || strcmp(entry->unit, "smoke.service") != 0 || entry->priority != 5) {
		fprintf(stderr, "smoke: bad librecorder entry\n");
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
	char store_dir[] = "/tmp/recorder-store-smoke-XXXXXX";
	char segment_path[512];
	char state_path[512];
	char group_path[512];
	char store_id_path[512];
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
	if (segment_write_header(fp, &header, NULL, 0, NULL) != 0) {
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
	if (segment_write_frame(fp, NULL, 0, chunk_buf, (uint32_t)chunk_size_raw, (uint32_t)chunk_size_raw) != 0) {
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
	if (fclose(fp) != 0) {
		fprintf(stderr, "smoke: close segment failed\n");
		free(chunk_buf);
		flatcc_builder_clear(&B);
		unlink(path);
		return 1;
	}
	fp = NULL;
	if (check_encrypted_segment(chunk_buf, chunk_size_raw) != 0) {
		free(chunk_buf);
		flatcc_builder_clear(&B);
		unlink(path);
		return 1;
	}
	free(chunk_buf);
	flatcc_builder_clear(&B);

	ctx.seen = 0;
	if (segment_scan_path(path, NULL, check_frame, &ctx, &header, &footer, &committed_end) != 0) {
		fprintf(stderr, "smoke: scan failed\n");
		unlink(path);
		return 1;
	}
	if (ctx.seen != 1 || footer.entry_count != 1 || committed_end == 0) {
		fprintf(stderr, "smoke: wrong scan result\n");
		unlink(path);
		return 1;
	}
	if (!mkdtemp(store_dir) ||
		snprintf(state_path, sizeof(state_path), "%s/state", store_dir) >= (int)sizeof(state_path) ||
		snprintf(group_path, sizeof(group_path), "%s/p4", store_dir) >= (int)sizeof(group_path) ||
		snprintf(segment_path, sizeof(segment_path), "%s/7.seg", group_path) >= (int)sizeof(segment_path) ||
		snprintf(store_id_path, sizeof(store_id_path), "%s/store-id", state_path) >= (int)sizeof(store_id_path) ||
		mkdir(state_path, 0755) != 0 || mkdir(group_path, 0755) != 0 || rename(path, segment_path) != 0) {
		fprintf(stderr, "smoke: create reader store failed\n");
		unlink(path);
		return 1;
	}
	fp = fopen(store_id_path, "wb");
	if (!fp || fputs("0123456789abcdef\n", fp) < 0) {
		fprintf(stderr, "smoke: write store ID failed\n");
		if (fp) fclose(fp);
		unlink(segment_path);
		rmdir(group_path);
		rmdir(state_path);
		rmdir(store_dir);
		return 1;
	}
	if (fclose(fp) != 0) {
		fprintf(stderr, "smoke: close store ID failed\n");
		unlink(segment_path);
		unlink(store_id_path);
		rmdir(group_path);
		rmdir(state_path);
		rmdir(store_dir);
		return 1;
	}
	{
		RecorderPlayer *reader = NULL;
		const void *data;
		size_t data_size;
		char *cursor = NULL;

		ctx.seen = 0;
		if (rec_player_open(&reader, store_dir) != 0 ||
			rec_player_scan_file(reader, segment_path, check_reader_entry, &ctx, 0, NULL) != 0 ||
			ctx.seen != 1) {
			fprintf(stderr, "smoke: librecorder scan failed\n");
			rec_player_close(reader);
			unlink(segment_path);
			return 1;
		}
		if (rec_player_seek_head(reader) != 0 || rec_player_next(reader) != 1 ||
			rec_player_get_data(reader, "MESSAGE", &data, &data_size) != 0 ||
			data_size != strlen("MESSAGE=hello smoke") ||
			memcmp(data, "MESSAGE=hello smoke", data_size) != 0 ||
			rec_player_get_cursor(reader, &cursor) != 0 ||
			rec_player_test_cursor(reader, cursor) != 1 ||
			rec_player_seek_cursor(reader, cursor) != 0 ||
			rec_player_next(reader) != 1) {
			fprintf(stderr, "smoke: librecorder iterator failed\n");
			free(cursor);
			rec_player_close(reader);
			unlink(segment_path);
			return 1;
		}
		free(cursor);
		rec_player_close(reader);
	}
	unlink(segment_path);
	unlink(store_id_path);
	rmdir(group_path);
	rmdir(state_path);
	rmdir(store_dir);
	printf("smoke ok\n");
	return 0;
}
