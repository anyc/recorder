# recorder

recorder is an alternative log backend targeting embedded Linux systems. It
focuses on efficient, fault-tolerant log storage while still providing
fast read access to logs.

Author: Mario Kicherer <dev@kicherer.org>

## What It Does

- Reads from the local systemd journal.
- Writes retained logs into segment files under a configurable log directory.
- Rotates segments by size, age, boot changes, and some time metadata changes.
- Enforces a configurable total disk usage limit.
- Can group multiple journal priorities into the same segment directory to
  reduce storage wear.
- Can optionally compress stored frames with zstd.

## Build

Host build requirements:

- `pkg-config`
- `jansson`
- `libsystemd`
- `zstd`

Build with:

```sh
make
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

Run the player on one segment:

```sh
./player /var/log/recorder/high/42.seg
```

Run the player on a whole recorder directory:

```sh
./player /var/log/recorder
```

`player` scans all subdirectories under the given log root and reads any valid `.seg` files it finds.

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
  "capture_message_id": true,
  "capture_unit": true,
  "capture_hostname": false,
  "capture_comm": false,
  "capture_exe": false,
  "capture_pid": false,
  "capture_uid": false,
  "capture_gid": false,
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
