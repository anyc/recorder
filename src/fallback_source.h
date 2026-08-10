#ifndef FALLBACK_SOURCE_H
#define FALLBACK_SOURCE_H

#include <limits.h>
#include <stdint.h>

typedef struct {
	int syslog_fd;
	int kmsg_fd;
	int unlink_syslog_path;
	char syslog_path[PATH_MAX];
	char hostname[256];
	char boot_id[33];
} FallbackSource;

typedef struct {
	uint64_t realtime_ts;
	uint64_t monotonic_ts;
	uint32_t pid;
	uint32_t uid;
	uint32_t gid;
	uint8_t priority;
	char boot_id[33];
	char hostname[256];
	char comm[256];
	char exe[PATH_MAX];
	char *message;
} FallbackRecord;

/* Bind a syslog socket and optionally open a kernel message source. */
int fallback_source_open(FallbackSource *source, const char *syslog_path,
					 const char *kernel_path);
void fallback_source_close(FallbackSource *source);

/* Returns one record, zero after timeout, or a negative errno-style failure. */
int fallback_source_next(FallbackSource *source, FallbackRecord *record,
					 int timeout_ms);
void fallback_record_destroy(FallbackRecord *record);

#endif
