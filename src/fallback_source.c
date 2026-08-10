#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "fallback_source.h"

#define FALLBACK_MESSAGE_MAX (64 * 1024)

static uint64_t clock_usec(clockid_t clock_id)
{
	struct timespec ts;

	if (clock_gettime(clock_id, &ts) != 0) return 0;
	return (uint64_t)ts.tv_sec * 1000000u + (uint64_t)ts.tv_nsec / 1000u;
}

static void read_text_file(const char *path, char *dst, size_t dst_size)
{
	int fd;
	ssize_t n;

	if (dst_size == 0) return;
	dst[0] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return;
	n = read(fd, dst, dst_size - 1);
	close(fd);
	if (n <= 0) return;
	dst[n] = '\0';
	dst[strcspn(dst, "\r\n")] = '\0';
}

static void read_boot_id(char dst[33])
{
	char raw[64];
	size_t i;
	size_t out = 0;

	read_text_file("/proc/sys/kernel/random/boot_id", raw, sizeof(raw));
	for (i = 0; raw[i] && out < 32; i++) {
		if (isxdigit((unsigned char)raw[i])) dst[out++] = raw[i];
	}
	dst[out] = '\0';
	if (out != 32) dst[0] = '\0';
}

static void read_process_metadata(FallbackRecord *record)
{
	char path[64];
	ssize_t n;

	if (record->pid == 0) return;
	if (record->comm[0] == '\0') {
		snprintf(path, sizeof(path), "/proc/%u/comm", record->pid);
		read_text_file(path, record->comm, sizeof(record->comm));
	}
	snprintf(path, sizeof(path), "/proc/%u/exe", record->pid);
	n = readlink(path, record->exe, sizeof(record->exe) - 1);
	if (n > 0) record->exe[n] = '\0';
}

static int duplicate_message(FallbackRecord *record, const char *message, size_t len)
{
	record->message = malloc(len + 1);
	if (!record->message) return -1;
	memcpy(record->message, message, len);
	record->message[len] = '\0';
	return 0;
}

static void parse_syslog_payload(FallbackRecord *record, const char *data, size_t len)
{
	const char *message = data;
	size_t message_len = len;
	unsigned long pri = 13;
	char *end;

	if (len >= 3 && data[0] == '<') {
		char number[16];
		size_t i = 1;
		while (i < len && i < sizeof(number) && data[i] >= '0' && data[i] <= '9') {
			number[i - 1] = data[i];
			i++;
		}
		if (i > 1 && i < len && data[i] == '>') {
			number[i - 1] = '\0';
			pri = strtoul(number, &end, 10);
			if (*end == '\0' && pri <= 191) {
				message = data + i + 1;
				message_len = len - i - 1;
			}
		}
	}
	record->priority = (uint8_t)(pri & 7u);

	/* Most local syslog clients emit TAG[PID]: message. Keep the text intact
	 * if it does not match that conventional local format. */
	{
		const char *colon = memchr(message, ':', message_len);
		const char *tag_end = colon;
		if (colon && colon + 1 < message + message_len && colon[1] == ' ' &&
			(size_t)(colon - message) < sizeof(record->comm)) {
			const char *bracket = memchr(message, '[', (size_t)(colon - message));
			if (bracket) tag_end = bracket;
			if (tag_end > message) {
				memcpy(record->comm, message, (size_t)(tag_end - message));
				record->comm[tag_end - message] = '\0';
				message = colon + 2;
				message_len = (size_t)((data + len) - message);
			}
		}
	}
	(void)duplicate_message(record, message, message_len);
}

static int receive_syslog(FallbackSource *source, FallbackRecord *record)
{
	char data[FALLBACK_MESSAGE_MAX];
	char control[CMSG_SPACE(sizeof(struct ucred))];
	struct iovec iov = { .iov_base = data, .iov_len = sizeof(data) };
	struct msghdr msg;
	struct cmsghdr *cmsg;
	ssize_t n;

	memset(&msg, 0, sizeof(msg));
	memset(control, 0, sizeof(control));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);
	n = recvmsg(source->syslog_fd, &msg, 0);
	if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
	if (msg.msg_flags & MSG_TRUNC) return 0;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS &&
			cmsg->cmsg_len >= CMSG_LEN(sizeof(struct ucred))) {
			const struct ucred *cred = (const struct ucred *)CMSG_DATA(cmsg);
			record->pid = (uint32_t)cred->pid;
			record->uid = (uint32_t)cred->uid;
			record->gid = (uint32_t)cred->gid;
			break;
		}
	}
	parse_syslog_payload(record, data, (size_t)n);
	if (!record->message) return -1;
	read_process_metadata(record);
	return 1;
}

static int receive_kmsg(FallbackSource *source, FallbackRecord *record)
{
	char data[FALLBACK_MESSAGE_MAX];
	char *semicolon;
	char *comma;
	ssize_t n;
	unsigned long priority = 6;

	n = read(source->kmsg_fd, data, sizeof(data) - 1);
	if (n < 0) return errno == EAGAIN || errno == EWOULDBLOCK ? 0 : -1;
	if (n == 0) return 0;
	data[n] = '\0';
	semicolon = memchr(data, ';', (size_t)n);
	comma = memchr(data, ',', (size_t)n);
	if (comma) {
		*comma = '\0';
		priority = strtoul(data, NULL, 10);
		*comma = ',';
	}
	record->priority = priority <= 7 ? (uint8_t)priority : 6;
	strcpy(record->comm, "kernel");
	if (!semicolon) semicolon = data;
	else semicolon++;
	if (duplicate_message(record, semicolon, strlen(semicolon)) != 0) return -1;
	return 1;
}

int fallback_source_open(FallbackSource *source, const char *syslog_path,
					 const char *kernel_path)
{
	struct sockaddr_un addr;
	int enabled = 0;
	int one = 1;

	memset(source, 0, sizeof(*source));
	source->syslog_fd = -1;
	source->kmsg_fd = -1;
	if (gethostname(source->hostname, sizeof(source->hostname)) != 0) {
		source->hostname[0] = '\0';
	} else {
		source->hostname[sizeof(source->hostname) - 1] = '\0';
	}
	read_boot_id(source->boot_id);
	if (syslog_path) {
		if (strlen(syslog_path) >= sizeof(addr.sun_path)) {
			errno = ENAMETOOLONG;
			goto fail;
		}
		source->syslog_fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (source->syslog_fd < 0 ||
			setsockopt(source->syslog_fd, SOL_SOCKET, SO_PASSCRED, &one, sizeof(one)) != 0) {
			goto fail;
		}
		memset(&addr, 0, sizeof(addr));
		addr.sun_family = AF_UNIX;
		strcpy(addr.sun_path, syslog_path);
		if (bind(source->syslog_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
			chmod(syslog_path, 0666) != 0) goto fail;
		if (fcntl(source->syslog_fd, F_SETFL, fcntl(source->syslog_fd, F_GETFL) | O_NONBLOCK) != 0) goto fail;
		strcpy(source->syslog_path, syslog_path);
		source->unlink_syslog_path = 1;
		enabled = 1;
	}
	if (kernel_path) {
		source->kmsg_fd = open(kernel_path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
		if (source->kmsg_fd < 0) goto fail;
		enabled = 1;
	}
	if (enabled) return 0;
	errno = EINVAL;
fail:
	fallback_source_close(source);
	return -1;
}

void fallback_source_close(FallbackSource *source)
{
	if (source->syslog_fd >= 0) close(source->syslog_fd);
	if (source->kmsg_fd >= 0) close(source->kmsg_fd);
	if (source->unlink_syslog_path && source->syslog_path[0]) unlink(source->syslog_path);
	source->syslog_fd = -1;
	source->kmsg_fd = -1;
}

int fallback_source_next(FallbackSource *source, FallbackRecord *record, int timeout_ms)
{
	struct pollfd fds[2];
	nfds_t count = 0;
	int rc;

	memset(record, 0, sizeof(*record));
	if (source->syslog_fd >= 0) fds[count++] = (struct pollfd){ .fd = source->syslog_fd, .events = POLLIN };
	if (source->kmsg_fd >= 0) fds[count++] = (struct pollfd){ .fd = source->kmsg_fd, .events = POLLIN };
	rc = poll(fds, count, timeout_ms);
	if (rc <= 0) return rc;
	if ((source->syslog_fd >= 0 && fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) ||
		(source->kmsg_fd >= 0 && fds[count - 1].revents & (POLLERR | POLLHUP | POLLNVAL))) {
		errno = EIO;
		return -1;
	}
	record->realtime_ts = clock_usec(CLOCK_REALTIME);
	record->monotonic_ts = clock_usec(CLOCK_MONOTONIC);
	strcpy(record->boot_id, source->boot_id);
	strcpy(record->hostname, source->hostname);
	if (source->syslog_fd >= 0 && fds[0].revents & POLLIN) return receive_syslog(source, record);
	if (source->kmsg_fd >= 0 && fds[count - 1].revents & POLLIN) return receive_kmsg(source, record);
	return 0;
}

void fallback_record_destroy(FallbackRecord *record)
{
	free(record->message);
	record->message = NULL;
}
