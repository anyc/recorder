
PREFIX ?= /usr
bindir ?= $(PREFIX)/bin
sysconfdir ?= /etc
localstatedir ?= /var
systemd_system_unitdir ?= $(PREFIX)/lib/systemd/system
PKG_CONFIG ?= pkg-config
LOG_DIR ?= /var/log/recorder
RECORDER_CONFIG_PATH ?= /etc/recorder.json
REPO_LOG_DIR ?= $(CURDIR)/.recorder-log
REPO_CONFIG_PATH ?= $(CURDIR)/packaging/recorder.json
FLATCC_PKG ?= flatccrt
FLATCC_MODE ?= sysroot
FLATCC_RUNTIME_OBJS = $(if $(filter repo,$(FLATCC_MODE)),flatcc/src/runtime/builder.o flatcc/src/runtime/refmap.o flatcc/src/runtime/emitter.o flatcc/src/runtime/verifier.o,)
FLATCC_CPPFLAGS = $(if $(filter repo,$(FLATCC_MODE)),-Iflatcc/include/,$(shell $(PKG_CONFIG) --cflags $(FLATCC_PKG)))
FLATCC_LIBS = $(if $(filter repo,$(FLATCC_MODE)),,$(shell $(PKG_CONFIG) --libs $(FLATCC_PKG)))

CPPFLAGS += $(FLATCC_CPPFLAGS)
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags jansson)
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags libzstd)
CPPFLAGS += $(shell $(PKG_CONFIG) --cflags libsystemd)
CPPFLAGS += -DLOG_DIR=\"$(LOG_DIR)\"
CPPFLAGS += -DRECORDER_CONFIG_PATH=\"$(RECORDER_CONFIG_PATH)\"

LDLIBS += $(shell $(PKG_CONFIG) --libs jansson)
LDLIBS += $(shell $(PKG_CONFIG) --libs libzstd)
LDLIBS += $(shell $(PKG_CONFIG) --libs libsystemd)
LDLIBS += $(FLATCC_LIBS)

CFLAGS += -ggdb -Wall

all: recorder player

repo:
	$(MAKE) FLATCC_MODE=repo LOG_DIR=$(REPO_LOG_DIR) RECORDER_CONFIG_PATH=$(REPO_CONFIG_PATH) all

recorder: recorder.o helper.o segment.o index.o $(FLATCC_RUNTIME_OBJS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

player: player.o helper.o segment.o index.o $(FLATCC_RUNTIME_OBJS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

smoke-test: smoke_test.o helper.o segment.o index.o $(FLATCC_RUNTIME_OBJS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

install: all
	install -d $(DESTDIR)$(bindir)
	install -d $(DESTDIR)$(systemd_system_unitdir)
	install -d $(DESTDIR)$(dir $(RECORDER_CONFIG_PATH))
	install -m 0755 recorder $(DESTDIR)$(bindir)/recorder
	install -m 0755 player $(DESTDIR)$(bindir)/player
	install -m 0644 packaging/recorder.json $(DESTDIR)$(RECORDER_CONFIG_PATH)
	install -m 0644 packaging/recorder.service $(DESTDIR)$(systemd_system_unitdir)/recorder.service

.PHONY: all repo clean install

clean:
	rm -f recorder player smoke-test *.o
