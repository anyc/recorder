# recorder

recorder is an alternative log backend targeting embedded Linux systems. It
focuses on efficient, fault-tolerant log storage while still providing
fast read access to logs.

## Why Use Recorder?

- Protects important logs when disk space runs low: it removes older,
  lower-priority logs before higher-priority ones. You can set different
  retention limits for each priority group.
- Stores logs in a compact FlatBuffers format, with optional zstd compression.
- Lets you choose which journal fields to store, so you can keep only the
  metadata your application needs.
- Detects when the system clock jumps and starts a new log file. Logs can still
  be read in the order they were recorded, even if timestamps move backward.
- Builds indexes that help find logs by time or service without scanning every
  entry. If an index is damaged or missing, it can read the log files directly.
- Can encrypt logs for confidentiality.

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
and is used as a fallback after reboot. After a successful clean shutdown the
volatile checkpoint is removed. If no checkpoint exists, it imports
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

## Configuration

By default, the build uses:

- log directory: `/var/log/recorder`
- config file: `/etc/recorder.json`

The package ships a commented sample config at
[packaging/recorder.json](packaging/recorder.json).

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
`_SYSTEMD_UNIT` works with compact entries. Rewriting the other supported
fixed fields (`MESSAGE_ID`, `_HOSTNAME`, `_COMM`, `_EXE`) automatically selects
`FullEntry`.

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
  "capture_pid": true,
  "capture_uid": false,
  "capture_gid": false,
  "capture_all_fields": false,
  "capture_fields_whitelist": [],
  "capture_fields_blacklist": [],
  "priority_groups": [
    {
      "name": "high",
      "priorities": [0, 1, 2, 3],
      "max_bytes": "48M",
      "max_age_sec": 604800
    },
    {
      "name": "low",
      "priorities": [4, 5, 6, 7],
      "max_bytes": "16M",
      "max_age_sec": 86400
    }
  ]
}
```

## Configuration Keys

- `log_max_bytes`
  Maximum total space used by recorder-owned files. Accepts an integer byte
  count or a size string such as `64M`.
- `min_free_bytes`
  Minimum free space to preserve on the log filesystem. When set, recorder
  removes closed lower-priority segments before writing higher-priority data.
  Zero disables the reserve.
- `segment_max_bytes`
  Maximum size of a single segment before rotation.
- `segment_max_age_sec`
  Maximum age of a segment before rotation.
- `durable_priority_max`
  Priorities `0..N` are written with the durable policy automatically enabled.
  Use `-1` to disable this.
- `durability_flush_frames`
  Flush after this many frames when durable mode is active.
- `durability_flush_interval_sec`
  Flush after this many seconds when durable mode is active.
- `compress_enabled`
  Enables zstd compression for eligible frames.
- `compress_min_frame_bytes`
  Minimum uncompressed frame size before compression is attempted.
- `compress_if_smaller`
  If `true`, compressed output is only kept when it is smaller than the original
  frame.
- `encryption_public_key`
  Optional path to a readable PEM public key. When set, recorder encrypts frame
  payloads in newly opened segments. The player must be given the matching
  private key with `--encryption-private-key`. Encrypted segments receive
  indexes while they are written; the player still needs the private key to read
  their payloads.
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
- Entry format
  Recorder uses `CompactEntry` by default. Enabling `capture_all_fields`,
  `capture_message_id`, `capture_hostname`, `capture_comm`, `capture_exe`,
  `capture_uid`, or `capture_gid` automatically selects `FullEntry`; no
  explicit format setting is required. Compact entries always retain PID and
  support unit storage.
- `capture_fields_whitelist`
  Optional array of custom journald field names to store. When non-empty,
  custom fields not in this list are skipped.
- `capture_fields_blacklist`
  Optional array of custom journald field names to skip. The blacklist takes
  precedence over the whitelist.
- `sanitize_output`
  Escape terminal control characters in `recorder -vv` output. Enabled by
  default.
- `priority_groups`
  Assign priorities to named storage groups with optional per-group retention
  limits. See [Priority Groups](#priority-groups).
- `static_dict_paths`
  Optional map from priority number to a zstd static dictionary path. If
  priorities are grouped together, all priorities in that group must use the
  same dictionary path or no dictionary path.

## Priority Groups

If `priority_groups` is omitted, recorder creates one group per priority:
`p0` through `p7`. Each configured group has these keys:

- `name` (required): Unique name for the segment directory.
- `priorities` (required): Non-empty list of priorities assigned to the group.
- `max_bytes` (optional): Maximum combined size of the group's closed `.seg`
  files. Give a byte count or a size string such as `16M`. When the total is
  greater than this value, recorder deletes older closed segments until the
  total is within the limit. Active segments and `.idx` files do not count.
- `max_age_sec` (optional): Maximum age of each closed `.seg` file, in seconds.
  Age starts at the file's last modification time. Recorder deletes a file
  once its age reaches this value, even if the group is below `max_bytes`.

Omitting a limit or setting it to zero disables that limit for the group.
Either limit can cause a closed segment to be deleted independently.

Every priority from `0` through `7` must appear in exactly one group. Group
names may contain letters, digits, underscores, and hyphens. Recorder rejects
duplicate names and overlapping or missing priorities.

### Different retention times

This example sets a seven-day age limit for closed segments in `important` and
a one-day limit for those in `routine`:

```json
{
  "log_max_bytes": "128M",
  "priority_groups": [
    {
      "name": "important",
      "priorities": [0, 1, 2, 3],
      "max_age_sec": 604800
    },
    {
      "name": "routine",
      "priorities": [4, 5, 6, 7],
      "max_age_sec": 86400
    }
  ]
}
```

Recorder checks retention at startup, when a segment closes, and at shutdown.
There is no exact expiry timer, so a file may remain past its age limit until
the next check. Active segments remain until they close. The global
`log_max_bytes` limit may remove closed segments sooner if space is needed.

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

When a write fails because the filesystem is full or over quota, recorder
removes closed segments from lower-priority groups and retries the write. If no
lower-priority data can be reclaimed, ingestion pauses until storage recovers.

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
