# recorder

recorder is an alternative log backend targeting embedded Linux systems. It
focuses on efficient, fault-tolerant log storage while still providing
fast read access to logs.

Author: Mario Kicherer <dev@kicherer.org>

## What It Does

- Reads from the local systemd journal.
- Writes retained logs into segment files under a configurable log directory.
- Rotates segments by size, age, boot changes, timezone changes, and significant
  realtime clock jumps (backward jumps over 1 ms or forward jumps over 1 s).
- Enforces a configurable total disk usage limit.
- Can group multiple journal priorities into the same segment directory to
  reduce storage wear.
- Can optionally compress stored frames with zstd.

## Build

Host build requirements:

- `pkg-config`
- `jansson`
- `libsystemd`
- optionally, `libpcre2-8` for regex modifiers
- `zstd`

Build with:

```sh
make
```

`libsystemd` and journald input are enabled automatically when available. To
build a fallback-only recorder with no `libsystemd` dependency, use:

```sh
make SYSTEMD=0
```

PCRE2 is autodetected. When it is unavailable, recorder can use POSIX libc
regular expressions. To build without any regex-modifier support, use:

```sh
make PCRE2=0 LIBC_REGEX=0
```

This produces `./recorder` and `./player`.

To build binaries that run directly from the repository checkout, use:

```sh
make repo
```

That mode uses a local log directory under `.recorder-log/` and the sample
config at `packaging/recorder.json`.

## Basic Usage

Run the recorder:

```sh
./recorder
```

By default, recorder resumes after the last journal cursor checkpoint stored
under `/run` when that directory is `tmpfs`-backed. A cursor from the last
clean shutdown is also stored in the log directory's `state/journal.cursor`
and is used as a fallback after reboot. If no checkpoint exists, it imports
all journal entries still available. To start with only the current last
journal entry, use:

```sh
./recorder --last
```

An explicit cursor path can be selected with `--cursor PATH` (or `-c PATH`).
When specified, recorder uses that path regardless of its filesystem type and
updates an existing file or device in place. A missing path is created.

To read a systemd journal namespace instead of the default namespace, use
`--namespace NAME` (or `-n NAME`).

### Non-systemd fallback input

On systems without a running journald instance, recorder can collect local
syslog datagrams and kernel messages directly:

```sh
recorder --fallback
```

Fallback mode binds `/dev/log` and reads `/dev/kmsg`. It must own `/dev/log`;
stop or configure any existing syslog daemon before starting it. Kernel access
typically requires root or `CAP_SYSLOG`. Use `--no-kmsg` if kernel collection
is unavailable, `--syslog-socket PATH` to use a different syslog socket, and
`--kernel-path PATH` to use a different kernel-message source. The fallback
collector records socket credentials and process metadata when available, but
it cannot provide a systemd unit or journald-style replay cursor.

Run its end-to-end test with:

```sh
make test-fallback
```

Run the smoke test, Python tests, and fallback integration test together with
`make test`. The benchmark entry points are `make benchmark-compare-storage`,
`make benchmark-storage`, and `make benchmark-capacity`; pass script options
via `COMPARE_STORAGE_ARGS`, `BENCHMARK_STORAGE_ARGS`, or
`BENCHMARK_CAPACITY_ARGS` respectively. The latter two operate on the live
journal and may prompt for `sudo`.

For isolated tests, recorder's storage directory can be overridden with
`--log-dir PATH` (or `-l PATH`). This directory includes the segments, indexes,
state, lock, and cursor files for that run.

Run the player on one segment:

```sh
./player -i /var/log/recorder/high/42.seg
```

Run the player on a whole recorder directory:

```sh
./player -D /var/log/recorder
```

Encrypted segments require the corresponding PEM private key:

```sh
./player -D /var/log/recorder \
  --encryption-private-key /path/to/encryption-private.pem
```

## Storage Comparison

To measure how much space journald and recorder consume over the same period:

```sh
python3 scripts/compare_storage.py \
  --duration 3600 \
  --interval 60 \
  --csv /tmp/recorder-storage.csv
```

The script reports absolute logical and physical usage, allocation growth,
journal entries observed during the test, file counts, and the physical space
saved by recorder relative to journald. Journald may reuse preallocated file
space, so entry counts can increase even when allocation growth is zero. It
measures storage only and does not compare stored fields.

For a repeatable namespace benchmark, use `scripts/benchmark_storage.py`:

```sh
python3 scripts/benchmark_storage.py config \
  --namespace recorder-bench \
  --output /tmp/journald@recorder-bench.conf

python3 scripts/benchmark_storage.py capture \
  --since "1 day ago" \
  --output /tmp/recorder-bench.log
```

Copy the generated config as instructed by the script, clear the namespace's
old journal files, and run the baseline replay:

```sh
python3 scripts/benchmark_storage.py replay \
  --namespace recorder-bench \
  --input /tmp/recorder-bench.log
```

Replay uses `sudo systemd-run` so it can create a system service assigned to
the namespace. Use `--run-as USER` to run the replay process unprivileged, or
`--no-sudo` when already running as root.

For the recorder run, configure the namespace with `Storage=volatile`, start
recorder with a fresh output directory, and replay the same input again:

```sh
recorder --namespace recorder-bench --log-dir /tmp/recorder-bench-output
```

Measure the persistent namespace directory for the journald run and
`/tmp/recorder-bench-output` for the recorder run with `compare_storage.py`.

The complete workflow can also be run interactively. It captures the input,
creates and installs the namespace configuration through prompted `sudo`
commands, runs both fresh-storage phases, prints the result, and offers to
remove the namespace data and temporary files. A differing existing namespace
configuration is backed up and always restored afterward; an identical config
does not create a redundant backup. Existing journal data must be explicitly
approved for deletion:

Before the first privileged operation, it prints the complete `sudo` command
plan. The recorder transient unit is started with `User=` set to the user who
invoked the benchmark, so recorder itself does not run as root.

```sh
python3 scripts/benchmark_storage.py interactive \
  --since "1 day ago" \
  --capture-all-fields \
  --recorder ./recorder
```

Add `--capture-all-fields` to enable all optional journald metadata fields
that recorder currently represents (`MESSAGE_ID`, unit, hostname, comm,
executable, PID, UID, and GID). Timestamps, priority, boot identity, and
errno are stored by recorder regardless of this option. With the option
enabled, arbitrary journald fields are also preserved in the entry's
`fields` vector, including binary values. This makes the benchmark compare
the fuller recorder entry representation.

The interactive run disables journald and per-service rate limiting, verifies
that both replays contain every input message, and waits for recorder's cursor
to reach a fixed journal-tail cursor. `--drain-seconds` controls the short
additional settling delay after that cursor is reached.

The result compares journald and recorder physical allocation directly for the
headline space saving. It also reports apparent size, the value from
`journalctl --header`, and a nonzero-data extent calculated by ignoring
trailing zero-filled journal preallocation. That extent is an upper bound, not
an exact measure of journal object bytes. The export size is reported
separately to show the serialized entries and metadata rather than on-disk
storage.

To compare retention capacity under an equal storage budget, use the separate
capacity benchmark:

```sh
python3 scripts/benchmark_capacity.py \
  --budget 20M \
  --capture-all-fields \
  --recorder ./recorder \
  --player ./player
```

The script generates one oversized, random-looking workload and replays the
same generated messages into both phases. Journald and recorder use separate
fresh namespaces, so changing the baseline limit cannot affect recorder's
input transport. Before recorder starts, the script verifies that its larger
transport journal retained every generated sequence. Journald rate limiting is
disabled in both benchmark namespaces so burst drops cannot distort the result.
Both stores are considered full only after the oldest generated sequences have
actually been evicted; rotation log messages and preallocated file size are
not used as proof. The result reports retained entries, oldest retained
sequence, actual budget utilization, logical/physical usage, and recorder's
retention advantage.

`player` scans all subdirectories under the given log root and reads any valid `.seg` files it finds.
Player output sanitizes terminal control characters by default. Use
`--no-sanitize-output` when raw stored fields are required.

## Configuration

By default, the build uses:

- log directory: `/var/log/recorder`
- config file: `/etc/recorder.json`

The package ships a commented sample config at [packaging/recorder.json](packaging/recorder.json).

At runtime, you can override the config file path with:

```sh
RECORDER_CONFIG=/path/to/recorder.json ./recorder
```

The config file is JSON. Before parsing, lines starting with `#` are removed, so this is valid:

```json
# recorder config
{
  "log_max_bytes": "64M"
}
```

### Modifiers

`modifiers` is an ordered list of transformations applied to every journal
entry before it is assigned to a priority group. Each priority group may also
have its own `modifiers` list. A modifier has one match predicate and one or
more actions: `drop`, `set_priority`, and `rewrite`. `field` defaults to
`MESSAGE`. `match.exact` and `match.present` work in every build;
`match.regex` uses PCRE2 when available and otherwise POSIX libc regex.
Capture-group `rewrite` requires PCRE2.

```json
{
  "modifiers": [
    {
      "match": { "field": "MESSAGE", "regex": "^debug: (.*)$" },
      "set_priority": 7,
      "rewrite": { "field": "MESSAGE", "replacement": "$1" }
    },
    {
      "match": { "field": "_SYSTEMD_UNIT", "regex": "^chatty\\.service$" },
      "drop": true
    }
  ],
  "priority_groups": [
    {
      "name": "important",
      "priorities": [0, 1, 2, 3],
      "modifiers": [
        {
          "match": { "field": "MESSAGE", "regex": "^retryable: (.*)$" },
          "set_priority": 4
        }
      ]
    }
  ]
}
```

Matches use the original journal field, including fields that are not stored.
`match.present` is a boolean and can also match field absence with `false`.
Set `match.not` to `true` to negate any predicate. Negated regex matches cannot
be used with `rewrite`, because there are no capture groups when the expression
does not match.
`rewrite` replaces the complete target field using capture references `$0`
through `$9`; `$$` inserts a literal dollar sign. Rewriting `MESSAGE` or
`_SYSTEMD_UNIT` works with either entry format. Rewriting the other supported
fixed fields (`MESSAGE_ID`, `_HOSTNAME`, `_COMM`, `_EXE`) requires
`"entry_format": "full"`.

Global modifiers run once. If a group modifier changes priority, recorder
selects the new group and applies that group's modifiers. It drops an entry if
modifiers would route it in a priority loop or after eight reroutes.

#### Script modifiers

A matching `script` modifier queues an external program for asynchronous,
fire-and-forget execution. The script does not change the entry or recorder
state, and it is never invoked through a shell. `command` is an argv array and
must name an executable using an absolute path. The matching entry is supplied
as compact JSON on standard input; convenience environment variables with the
`REC_` prefix contain the supported scalar fields (unsuitable or unavailable
values are omitted). The worker queue is bounded, so a saturated queue drops
the script invocation without affecting recording.

By default scripts run only for live entries. Set `run_on_replay` to `true` to
also run during recorder startup catch-up (the period before the first empty
journal scan); the JSON input includes `REC_IS_REPLAY` so a script can tell the
two cases apart. `timeout_sec` defaults to 10 seconds and limits each child.

```json
{
  "modifiers": [
    {
      "match": { "field": "MESSAGE", "exact": "rotate-now" },
      "script": {
        "command": ["/usr/local/libexec/recorder-hook", "rotate"],
        "run_on_replay": false,
        "timeout_sec": 10
      }
    }
  ]
}
```

## Example Configuration

```json
{
  "log_max_bytes": "64M",
  "segment_max_bytes": "4M",
  "segment_max_age_sec": 900,
  "durable_priority_max": 3,
  "durability_flush_frames": 32,
  "durability_flush_interval_sec": 5,
  "compress_enabled": true,
  "compress_min_frame_bytes": 256,
  "compress_if_smaller": true,
  "capture_message_id": false,
  "capture_unit": true,
  "capture_hostname": false,
  "capture_comm": false,
  "capture_exe": false,
  "capture_pid": false,
  "capture_uid": false,
  "capture_gid": false,
  "capture_all_fields": false,
  "entry_format": "default",
  "capture_fields_whitelist": [],
  "capture_fields_blacklist": [],
  "priority_groups": [
    { "name": "high", "priorities": [0, 1, 2, 3] },
    { "name": "low", "priorities": [4, 5, 6, 7] }
  ]
}
```

## Configuration Keys

- `log_max_bytes`
  Maximum total space used by recorder-owned files. Accepts an integer byte count or a size string such as `64M`.
- `segment_max_bytes`
  Maximum size of a single segment before rotation.
- `segment_max_age_sec`
  Maximum age of a segment before rotation.
- `durable_priority_max`
  Priorities `0..N` are written with the durable policy automatically enabled. Use `-1` to disable this.
- `durability_flush_frames`
  Flush after this many frames when durable mode is active.
- `durability_flush_interval_sec`
  Flush after this many seconds when durable mode is active.
- `compress_enabled`
  Enables zstd compression for eligible frames.
- `compress_min_frame_bytes`
  Minimum uncompressed frame size before compression is attempted.
- `compress_if_smaller`
  If `true`, compressed output is only kept when it is smaller than the original frame.
- `encryption_public_key`
  Optional path to a readable PEM public key. When set, recorder encrypts frame payloads in newly opened segments. The player must be given the matching private key with `--encryption-private-key`. Encrypted segments receive indexes while they are written; the player still needs the private key to read their payloads.
- `capture_message_id`
  Store `MESSAGE_ID` when present.
- `capture_unit`
  Store `_SYSTEMD_UNIT` when present.
- `capture_hostname`
  Store `_HOSTNAME` when present.
- `capture_comm`
  Store `_COMM` when present.
- `capture_exe`
  Store `_EXE` when present.
- `capture_pid`
  Store `_PID` when present.
- `capture_uid`
  Store `_UID` when present.
- `capture_gid`
  Store `_GID` when present.
- `capture_all_fields`
  Store all optional fixed fields and arbitrary journald fields in the
  entry's `fields` vector. Field values are preserved as bytes.
- `entry_format`
  Select `default` for the compact entry representation or `full` for the
  representation containing arbitrary journald fields. `capture_all_fields`
  and `capture_message_id`, `capture_hostname`, `capture_comm`,
  `capture_exe`, `capture_uid`, and `capture_gid` require `full`. Compact
  entries always retain PID and support unit storage.
- `capture_fields_whitelist`
  Optional array of custom journald field names to store. When non-empty,
  custom fields not in this list are skipped.
- `capture_fields_blacklist`
  Optional array of custom journald field names to skip. The blacklist takes
  precedence over the whitelist.
- `sanitize_output`
  Escape terminal control characters in `recorder -vv` output. Enabled by default.
- `priority_groups`
  Optional grouping of priorities into named segment directories. Each priority `0..7` must appear exactly once.
- `static_dict_paths`
  Optional map from priority number to a zstd static dictionary path. If priorities are grouped together, all priorities in that group must use the same dictionary path or no dictionary path.

## Default Behavior

If `priority_groups` is not set, recorder uses one directory per priority:

- `p0`
- `p1`
- `p2`
- `p3`
- `p4`
- `p5`
- `p6`
- `p7`

With explicit groups, the directory names come from the configured group names.

## Storage Layout

Inside the log directory, recorder creates:

- one subdirectory per priority group
- `state/segment_seq`
- `state/boots`
- `state/journal.cursor` (last cursor from a clean shutdown)

Example:

```text
/var/log/recorder/
  high/
    100.seg
    100.idx
    101.seg
  low/
    102.seg
    102.idx
  state/
    segment_seq
    boots
    journal.cursor
```

## Retention

Recorder keeps the total on-disk size within `log_max_bytes`.

When space must be reclaimed:

- lower-priority data is deleted before higher-priority data
- within the same priority group, older segments are removed before newer ones

## Notes

- The detailed on-disk design work is tracked separately in
  [RECORDER_STORAGE_PLAN.md](RECORDER_STORAGE_PLAN.md).
- Project code is MIT licensed. The build also depends on `jansson` (MIT),
  `zstd` (BSD-style), and `systemd/libsystemd` (LGPL-2.1-or-later). If you
  redistribute binaries, include the relevant dependency license texts in your
  package as required.
