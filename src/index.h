#ifndef INDEX_H
#define INDEX_H

#include <stdint.h>
#include <stddef.h>
#include "segment.h"

typedef struct IndexWriter IndexWriter;

/* One record per committed segment frame.  The reader owns the returned
 * array from index_read_frames(). */
typedef struct {
	uint64_t file_offset;
	uint32_t frame_len;
	uint64_t min_realtime_ts;
	uint64_t max_realtime_ts;
	uint64_t min_monotonic_ts;
	uint64_t max_monotonic_ts;
	uint8_t priority;
	uint32_t entry_count;
} IndexFrame;

int index_writer_open(const char *path, uint64_t segment_seq, uint32_t flags,
                      IndexWriter **writer_out);
int index_writer_append(IndexWriter *writer, const SegmentHeader *header,
                        const SegmentFrameInfo *frame,
                        const void *chunk_buf, size_t chunk_size);
int index_writer_close(IndexWriter *writer, uint64_t segment_committed_end);
void index_writer_abort(IndexWriter *writer, int unlink_path);

int index_rebuild_for_segment(const char *segment_path, const char *index_path);
int index_read_frames(const char *path, IndexFrame **frames_out, size_t *count_out);
/* Locate the first frame whose realtime range can contain usec. */
int index_find_realtime_frame(const char *path, uint64_t usec,
					  IndexFrame *frame_out, size_t *frame_index_out);
int index_find_offset_frame(const char *path, uint64_t file_offset,
					IndexFrame *frame_out, size_t *frame_index_out);

#endif
