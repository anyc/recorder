#ifndef HELPER_H
#define HELPER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

int mkdir_p(const char *path);
int fsync_dir_path(const char *path);
uint32_t read_u32_le(const void *src);
uint64_t read_u64_le(const void *src);
void write_u32_le(void *dst, uint32_t value);
void write_u64_le(void *dst, uint64_t value);
uint32_t recorder_crc32(const void *data, size_t len);
enum { RECORDER_FRAME_HEADER_SIZE = 8 };
int write_framed_chunk(FILE *fp, const void *buf, uint32_t size);
int read_framed_chunk_header(const void *buf, size_t remaining,
                             uint32_t *chunk_size, size_t *header_size);

#endif
