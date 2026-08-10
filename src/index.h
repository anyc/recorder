#ifndef INDEX_H
#define INDEX_H

#include <stdint.h>
#include <stddef.h>
#include "segment.h"

typedef struct IndexWriter IndexWriter;

int index_writer_open(const char *path, uint64_t segment_seq, uint32_t flags,
                      IndexWriter **writer_out);
int index_writer_append(IndexWriter *writer, const SegmentHeader *header,
                        const SegmentFrameInfo *frame,
                        const void *chunk_buf, size_t chunk_size);
int index_writer_close(IndexWriter *writer, uint64_t segment_committed_end);
void index_writer_abort(IndexWriter *writer, int unlink_path);

int index_rebuild_for_segment(const char *segment_path, const char *index_path);

#endif
