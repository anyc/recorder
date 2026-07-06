#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "helper.h"

int mkdir_p(const char *path) {
	char tmp[512];
	char *p = NULL;
	size_t len;
	
	snprintf(tmp, sizeof(tmp), "%s", path);
	len = strlen(tmp);
	
	if (tmp[len - 1] == '/')
		tmp[len - 1] = '\0';
	
	for (p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			
			if (mkdir(tmp, 0755) != 0) {
				if (errno != EEXIST) return -1;
			}
			
			*p = '/';
		}
	}
	
	if (mkdir(tmp, 0755) != 0) {
		if (errno != EEXIST) return -1;
	}
	
	return 0;
}

int fsync_dir_path(const char *path)
{
	int fd = open(path, O_RDONLY | O_DIRECTORY);

	if (fd < 0) {
		return -1;
	}
	if (fsync(fd) != 0) {
		int saved = errno;
		close(fd);
		errno = saved;
		return -1;
	}
	close(fd);
	return 0;
}

uint32_t read_u32_le(const void *src)
{
	const unsigned char *p = src;

	return ((uint32_t)p[0])
	     | ((uint32_t)p[1] << 8)
	     | ((uint32_t)p[2] << 16)
	     | ((uint32_t)p[3] << 24);
}

uint64_t read_u64_le(const void *src)
{
	const unsigned char *p = src;

	return ((uint64_t)p[0])
	     | ((uint64_t)p[1] << 8)
	     | ((uint64_t)p[2] << 16)
	     | ((uint64_t)p[3] << 24)
	     | ((uint64_t)p[4] << 32)
	     | ((uint64_t)p[5] << 40)
	     | ((uint64_t)p[6] << 48)
	     | ((uint64_t)p[7] << 56);
}

void write_u32_le(void *dst, uint32_t value)
{
	unsigned char *p = dst;

	p[0] = (unsigned char)(value & 0xff);
	p[1] = (unsigned char)((value >> 8) & 0xff);
	p[2] = (unsigned char)((value >> 16) & 0xff);
	p[3] = (unsigned char)((value >> 24) & 0xff);
}

void write_u64_le(void *dst, uint64_t value)
{
	unsigned char *p = dst;

	p[0] = (unsigned char)(value & 0xff);
	p[1] = (unsigned char)((value >> 8) & 0xff);
	p[2] = (unsigned char)((value >> 16) & 0xff);
	p[3] = (unsigned char)((value >> 24) & 0xff);
	p[4] = (unsigned char)((value >> 32) & 0xff);
	p[5] = (unsigned char)((value >> 40) & 0xff);
	p[6] = (unsigned char)((value >> 48) & 0xff);
	p[7] = (unsigned char)((value >> 56) & 0xff);
}

uint32_t recorder_crc32(const void *data, size_t len)
{
	const unsigned char *p = data;
	uint32_t crc = 0xffffffffu;
	size_t i;

	for (i = 0; i < len; i++) {
		unsigned int bit;

		crc ^= p[i];
		for (bit = 0; bit < 8; bit++) {
			crc = (crc >> 1) ^ (0xedb88320u & (uint32_t)-(int32_t)(crc & 1u));
		}
	}
	return ~crc;
}

int write_framed_chunk(FILE *fp, const void *buf, uint32_t size)
{
	unsigned char header[RECORDER_FRAME_HEADER_SIZE];

	if (!fp) {
		return -1;
	}

	write_u32_le(header, size);
	write_u32_le(header + 4, 0);
	if (fwrite(header, 1, sizeof(header), fp) != sizeof(header)) {
		return -1;
	}
	if (fwrite(buf, 1, size, fp) != size) {
		return -1;
	}
	return 0;
}

int read_framed_chunk_header(const void *buf, size_t remaining,
                             uint32_t *chunk_size, size_t *header_size)
{
	if (remaining < RECORDER_FRAME_HEADER_SIZE) {
		return -1;
	}

	*chunk_size = read_u32_le(buf);
	*header_size = RECORDER_FRAME_HEADER_SIZE;
	return 0;
}
