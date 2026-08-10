
PREFIX ?= /usr
bindir ?= $(PREFIX)/bin
libdir ?= $(PREFIX)/lib
includedir ?= $(PREFIX)/include
sysconfdir ?= /etc
localstatedir ?= /var
systemd_system_unitdir ?= $(PREFIX)/lib/systemd/system
PKG_CONFIG ?= pkg-config
PYTHON ?= python3
LOG_DIR ?= $(localstatedir)/log/recorder
RECORDER_CONFIG_PATH ?= /etc/recorder.json
RECORDER_CONFIG_DIR ?= $(sysconfdir)/recorder.d
RECORDER_TEST_FREE_BYTES ?=
REPO_LOG_DIR ?= $(CURDIR)/.recorder-log
REPO_CONFIG_PATH ?= $(CURDIR)/packaging/recorder.json
REPO_CONFIG_DIR ?= $(CURDIR)/packaging/recorder.d
FLATCC_PKG ?= flatccrt
PCRE2_PKG ?= libpcre2-8
OPENSSL_PKG ?= libcrypto
PCRE2 ?= auto
LIBC_REGEX ?= 1
SYSTEMD ?= auto
COMPARE_STORAGE_ARGS ?=
BENCHMARK_STORAGE_ARGS ?=
BENCHMARK_CAPACITY_ARGS ?=
FLATCC_MODE ?= sysroot
FLATCC_RUNTIME_OBJS = $(if $(filter repo,$(FLATCC_MODE)),\
	flatcc/src/runtime/builder.o \
	flatcc/src/runtime/refmap.o \
	flatcc/src/runtime/emitter.o \
	flatcc/src/runtime/verifier.o,)
FLATCC_CPPFLAGS = $(if $(filter repo,$(FLATCC_MODE)),-Iflatcc/include/,$(shell $(PKG_CONFIG) --cflags $(FLATCC_PKG)))
FLATCC_LIBS = $(if $(filter repo,$(FLATCC_MODE)),,$(shell $(PKG_CONFIG) --libs $(FLATCC_PKG)))
ifeq ($(PCRE2),auto)
HAVE_PCRE2 := $(shell $(PKG_CONFIG) --exists $(PCRE2_PKG) && echo 1)
else ifeq ($(PCRE2),1)
HAVE_PCRE2 := 1
endif
ifeq ($(SYSTEMD),auto)
HAVE_SYSTEMD := $(shell $(PKG_CONFIG) --exists libsystemd && echo 1)
else ifeq ($(SYSTEMD),1)
HAVE_SYSTEMD := 1
endif

CPPFLAGS += $(FLATCC_CPPFLAGS)
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags jansson)
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags libzstd)
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags $(OPENSSL_PKG))
CPPFLAGS += $(if $(HAVE_SYSTEMD),$(shell $(PKG_CONFIG) --cflags libsystemd) -DHAVE_SYSTEMD)
CPPFLAGS += $(if $(HAVE_PCRE2),$(shell $(PKG_CONFIG) --cflags $(PCRE2_PKG)) -DHAVE_PCRE2)
CPPFLAGS += $(if $(filter 1 yes true,$(LIBC_REGEX)),-DHAVE_LIBC_REGEX)
CPPFLAGS += -DLOG_DIR=\"$(LOG_DIR)\"
CPPFLAGS += -DRECORDER_CONFIG_PATH=\"$(RECORDER_CONFIG_PATH)\"
CPPFLAGS += -DRECORDER_CONFIG_DIR=\"$(RECORDER_CONFIG_DIR)\"
ifneq ($(strip $(RECORDER_TEST_FREE_BYTES)),)
CPPFLAGS += -DRECORDER_TEST_FREE_BYTES=$(RECORDER_TEST_FREE_BYTES)
endif

LDLIBS += $(shell $(PKG_CONFIG) --libs jansson)
LDLIBS += $(shell $(PKG_CONFIG) --libs libzstd)
LDLIBS += $(shell $(PKG_CONFIG) --libs $(OPENSSL_PKG))
LDLIBS += $(if $(HAVE_SYSTEMD),$(shell $(PKG_CONFIG) --libs libsystemd))
LDLIBS += $(if $(HAVE_PCRE2),$(shell $(PKG_CONFIG) --libs $(PCRE2_PKG)))
LDLIBS += $(FLATCC_LIBS)

CFLAGS += -ggdb -Wall -MMD -MP -pthread
LDLIBS += -pthread

all: recorder player librecorder.a

repo:
	$(MAKE) FLATCC_MODE=repo LOG_DIR=$(REPO_LOG_DIR) RECORDER_CONFIG_PATH=$(REPO_CONFIG_PATH) RECORDER_CONFIG_DIR=$(REPO_CONFIG_DIR) all

recorder: src/recorder.o src/fallback_source.o src/helper.o src/segment.o src/index.o src/recorder_crypto.o src/script_worker.o $(FLATCC_RUNTIME_OBJS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

player: src/player.o src/librecorder.o src/helper.o src/segment.o src/index.o src/recorder_crypto.o src/script_worker.o $(FLATCC_RUNTIME_OBJS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

librecorder.a: src/librecorder.o src/segment.o src/recorder_crypto.o src/script_worker.o $(FLATCC_RUNTIME_OBJS)
	$(AR) rcs $@ $^

smoke-test: src/smoke_test.o src/librecorder.o src/helper.o src/segment.o src/index.o src/recorder_crypto.o $(FLATCC_RUNTIME_OBJS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

install: all
	install -d $(DESTDIR)$(bindir)
	install -d $(DESTDIR)$(libdir)
	install -d $(DESTDIR)$(includedir)
	install -d $(DESTDIR)$(systemd_system_unitdir)
	install -d $(DESTDIR)$(dir $(RECORDER_CONFIG_PATH))
	install -d $(DESTDIR)$(RECORDER_CONFIG_DIR)
	install -m 0755 recorder $(DESTDIR)$(bindir)/recorder
	install -m 0755 player $(DESTDIR)$(bindir)/player
	install -m 0644 librecorder.a $(DESTDIR)$(libdir)/librecorder.a
	install -m 0644 src/librecorder.h $(DESTDIR)$(includedir)/librecorder.h
	install -m 0644 packaging/recorder.json $(DESTDIR)$(RECORDER_CONFIG_PATH)
	install -m 0644 packaging/recorder.service $(DESTDIR)$(systemd_system_unitdir)/recorder.service

test-fallback: recorder player
	$(PYTHON) scripts/test_fallback.py --recorder ./recorder --player ./player

test-storage-policy: recorder
	$(PYTHON) scripts/test_storage_policy.py

test-python:
	$(PYTHON) -m unittest scripts.test_benchmark_storage scripts.test_benchmark_capacity

test-smoke: smoke-test
	./smoke-test

# Build test binaries against the repository's bundled FlatCC checkout and
# sample configuration, then run every non-privileged test suite.
test:
	$(MAKE) FLATCC_MODE=repo LOG_DIR=$(REPO_LOG_DIR) RECORDER_CONFIG_PATH=$(REPO_CONFIG_PATH) RECORDER_CONFIG_DIR=$(REPO_CONFIG_DIR) test-smoke
	$(MAKE) FLATCC_MODE=repo LOG_DIR=$(REPO_LOG_DIR) RECORDER_CONFIG_PATH=$(REPO_CONFIG_PATH) test-python
	$(MAKE) FLATCC_MODE=repo LOG_DIR=$(REPO_LOG_DIR) RECORDER_CONFIG_PATH=$(REPO_CONFIG_PATH) test-fallback
	$(MAKE) FLATCC_MODE=repo LOG_DIR=$(REPO_LOG_DIR) RECORDER_CONFIG_PATH=$(REPO_CONFIG_PATH) RECORDER_CONFIG_DIR=$(REPO_CONFIG_DIR) RECORDER_TEST_FREE_BYTES=0 test-storage-policy

# These workflows can interact with the live journal and may prompt for sudo.
# Pass script options through the corresponding *_ARGS variable.
benchmark-compare-storage:
	$(PYTHON) scripts/compare_storage.py $(COMPARE_STORAGE_ARGS)

benchmark-storage: repo
	$(PYTHON) scripts/benchmark_storage.py interactive --recorder ./recorder --player ./player $(BENCHMARK_STORAGE_ARGS)

benchmark-capacity: repo
	$(PYTHON) scripts/benchmark_capacity.py --recorder ./recorder --player ./player $(BENCHMARK_CAPACITY_ARGS)

.PHONY: all repo clean install test-fallback test-storage-policy test-python test-smoke test \
	benchmark-compare-storage benchmark-storage benchmark-capacity

clean:
	rm -f recorder player smoke-test librecorder.a *.o *.d src/*.o src/*.d

-include $(wildcard *.d) $(wildcard src/*.d)
