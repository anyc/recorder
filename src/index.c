#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "helper.h"
#include "index.h"
#include "segment.h"

#define RECORDER_INDEX_MAGIC "RECIDX01"
#define RECORDER_INDEX_VERSION 1u
#define RECORDER_INDEX_HEADER_SIZE 24u
#define RECORDER_INDEX_FOOTER_MAGIC "RECIF001"
#define RECORDER_INDEX_FOOTER_SIZE 28u
#define RECORDER_SERVICE_HASH_SLOTS 4u
#define RECORDER_SERVICE_HASH_BYTES (RECORDER_SERVICE_HASH_SLOTS * sizeof(uint64_t))

typedef struct {
	FILE *fp;
} IndexBuildContext;

typedef struct {
	IndexWriter *writer;
} IndexWriterBuildContext;

struct IndexWriter {
	FILE *fp;
	char *path;
	uint64_t record_count;
};

static int append_index_frame_cb(const SegmentHeader *header,
							 const SegmentFrameInfo *frame,
							 const void *chunk_buf, size_t chunk_size, void *ctx)
{
	IndexWriterBuildContext *bc = ctx;
	return index_writer_append(bc->writer, header, frame, chunk_buf, chunk_size);
}

static uint64_t fnv1a64(const char *s)
{
	uint64_t hash = 1469598103934665603ull;

	while (*s) {
		hash ^= (unsigned char)*s++;
		hash *= 1099511628211ull;
	}
	return hash;
}

static void store_u64(FILE *fp, uint64_t value)
{
	unsigned char buf[8];
	write_u64_le(buf, value);
	fwrite(buf, 1, sizeof(buf), fp);
}

static void store_u32(FILE *fp, uint32_t value)
{
	unsigned char buf[4];
	write_u32_le(buf, value);
	fwrite(buf, 1, sizeof(buf), fp);
}

static void index_add_entry(uint64_t rt, uint64_t mono, uint8_t entry_priority,
							const char *unit, size_t entry_index,
							uint64_t *min_rt, uint64_t *max_rt,
							uint64_t *min_mono, uint64_t *max_mono,
							uint8_t *priority,
							uint64_t *service_hashes, size_t *service_count,
							uint8_t *overflow)
{
	size_t j;
	int seen = 0;

	if (entry_index == 0 || rt < *min_rt) *min_rt = rt;
	if (entry_index == 0 || rt > *max_rt) *max_rt = rt;
	if (entry_index == 0 || mono < *min_mono) *min_mono = mono;
	if (entry_index == 0 || mono > *max_mono) *max_mono = mono;
	*priority = entry_priority;
	if (!unit) {
		return;
	}
	{
		uint64_t hash = fnv1a64(unit);
		for (j = 0; j < *service_count; j++) {
			if (service_hashes[j] == hash) {
				seen = 1;
				break;
			}
		}
		if (!seen) {
			if (*service_count < RECORDER_SERVICE_HASH_SLOTS) {
				service_hashes[(*service_count)++] = hash;
			} else {
				*overflow = 1;
			}
		}
	}
}

static int write_index_frame(const SegmentHeader *header,
								const SegmentFrameInfo *frame,
								const void *chunk_buf, size_t chunk_size,
								void *ctx)
{
	IndexBuildContext *ib = ctx;
	size_t n = 0;
	size_t i;
	uint64_t min_rt = 0, max_rt = 0, min_mono = 0, max_mono = 0;
	uint8_t priority = 0;
	uint8_t service_kind = 1;
	uint8_t overflow = 0;
	uint64_t service_hashes[RECORDER_SERVICE_HASH_SLOTS] = {0};
	size_t service_count = 0;

	(void)header;
	(void)chunk_size;

	if ((header->flags & SEGMENT_FLAG_COMPACT_ENTRIES) != 0) {
		journal_DefaultChunk_table_t chunk = journal_DefaultChunk_as_root(chunk_buf);
		flatbuffers_uint32_vec_t entries = journal_DefaultChunk_entries(chunk);
		n = flatbuffers_uint32_vec_len(entries);
		for (i = 0; i < n; i++) {
			journal_CompactEntry_table_t e = journal_CompactEntry_vec_at(entries, i);
			index_add_entry(journal_CompactEntry_realtime_ts(e),
					journal_CompactEntry_monotonic_ts(e),
					journal_CompactEntry_priority(e),
					journal_CompactEntry_unit(e), i, &min_rt, &max_rt,
					&min_mono, &max_mono, &priority, service_hashes,
					&service_count, &overflow);
		}
	} else {
		journal_Chunk_table_t chunk = journal_Chunk_as_root(chunk_buf);
		flatbuffers_uint32_vec_t entries = journal_Chunk_entries(chunk);
		n = flatbuffers_uint32_vec_len(entries);
		for (i = 0; i < n; i++) {
			journal_FullEntry_table_t e = journal_FullEntry_vec_at(entries, i);
			index_add_entry(journal_FullEntry_realtime_ts(e),
					journal_FullEntry_monotonic_ts(e), journal_FullEntry_priority(e),
					journal_FullEntry_unit(e), i, &min_rt, &max_rt, &min_mono,
					&max_mono, &priority, service_hashes, &service_count,
					&overflow);
		}
	}

	store_u64(ib->fp, frame->file_offset);
	store_u32(ib->fp, frame->frame_len);
	store_u64(ib->fp, min_rt);
	store_u64(ib->fp, max_rt);
	store_u64(ib->fp, min_mono);
	store_u64(ib->fp, max_mono);
	fputc(priority, ib->fp);
	store_u32(ib->fp, (uint32_t)n);
	fputc(service_kind, ib->fp);
	fwrite(service_hashes, 1, RECORDER_SERVICE_HASH_BYTES, ib->fp);
	fputc(overflow, ib->fp);
	return ferror(ib->fp) ? -1 : 0;
}

int index_writer_open(const char *path, uint64_t segment_seq, uint32_t flags,
					  IndexWriter **writer_out)
{
	IndexWriter *writer;
	unsigned char head[RECORDER_INDEX_HEADER_SIZE];
	if (!path || !writer_out) return -1;
	writer = calloc(1, sizeof(*writer));
	if (!writer) return -1;
	writer->path = strdup(path);
	if (!writer->path) { free(writer); return -1; }
	writer->fp = fopen(path, "w+b");
	if (!writer->fp) { free(writer->path); free(writer); return -1; }
	/* Indexes are advisory and intentionally not forced to storage. Keep the
	 * stream unbuffered so the active final-path file remains readable. */
	if (setvbuf(writer->fp, NULL, _IONBF, 0) != 0) {
		fclose(writer->fp);
		unlink(path);
		free(writer->path);
		free(writer);
		return -1;
	}
	memcpy(head, RECORDER_INDEX_MAGIC, 8);
	write_u32_le(head + 8, RECORDER_INDEX_VERSION);
	write_u64_le(head + 12, segment_seq);
	write_u32_le(head + 20, flags);
	if (fwrite(head, 1, sizeof(head), writer->fp) != sizeof(head)) {
		fclose(writer->fp); unlink(path); free(writer->path); free(writer); return -1;
	}
	*writer_out = writer;
	return 0;
}

int index_writer_append(IndexWriter *writer, const SegmentHeader *header,
						const SegmentFrameInfo *frame,
						const void *chunk_buf, size_t chunk_size)
{
	IndexBuildContext ctx;
	if (!writer || !writer->fp || !header || !frame || !chunk_buf) return -1;
	ctx.fp = writer->fp;
	if (write_index_frame(header, frame, chunk_buf, chunk_size, &ctx) != 0) return -1;
	writer->record_count++;
	return 0;
}

int index_writer_close(IndexWriter *writer, uint64_t segment_committed_end)
{
	unsigned char body[RECORDER_INDEX_FOOTER_SIZE];
	unsigned char *all = NULL;
	long end;
	uint32_t crc;
	int rc = -1;
	if (!writer || !writer->fp) return -1;
	if (fseek(writer->fp, 0, SEEK_END) != 0 || (end = ftell(writer->fp)) < 0) goto out;
	if ((uint64_t)end > SIZE_MAX) goto out;
	all = malloc((size_t)end);
	if (!all || fseek(writer->fp, 0, SEEK_SET) != 0 ||
		fread(all, 1, (size_t)end, writer->fp) != (size_t)end) goto out;
	crc = recorder_crc32(all, (size_t)end);
	memcpy(body, RECORDER_INDEX_FOOTER_MAGIC, 8);
	write_u64_le(body + 8, writer->record_count);
	write_u64_le(body + 16, segment_committed_end);
	write_u32_le(body + 24, crc);
	if (fseek(writer->fp, 0, SEEK_END) != 0 ||
		fwrite(body, 1, sizeof(body), writer->fp) != sizeof(body)) goto out;
	rc = 0;
out:
	free(all);
	fclose(writer->fp);
	free(writer->path);
	free(writer);
	return rc;
}

void index_writer_abort(IndexWriter *writer, int unlink_path)
{
	if (!writer) return;
	if (writer->fp) fclose(writer->fp);
	if (unlink_path && writer->path) unlink(writer->path);
	free(writer->path);
	free(writer);
}

int index_rebuild_for_segment(const char *segment_path, const char *index_path)
{
	char tmp_path[512];
	SegmentHeader header;
	SegmentFooter footer;
	IndexWriter *writer = NULL;
	IndexWriterBuildContext ctx;
	int rc = -1;
	size_t committed_end = 0;

	snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", index_path);
	if (segment_scan_path(segment_path, NULL, NULL, NULL, &header, &footer, &committed_end) != 0) {
		unlink(tmp_path);
		return -1;
	}
	if (index_writer_open(tmp_path, header.segment_seq, header.flags, &writer) != 0) return -1;
	ctx.writer = writer;
	if (segment_scan_path(segment_path, NULL, append_index_frame_cb, &ctx, NULL, NULL, NULL) != 0) {
		index_writer_abort(writer, 1);
		return -1;
	}
	if (index_writer_close(writer, committed_end) != 0) {
		unlink(tmp_path);
		return -1;
	}
	rc = rename(tmp_path, index_path);
	if (rc != 0) {
		unlink(tmp_path);
		return -1;
	}
	return 0;
}
