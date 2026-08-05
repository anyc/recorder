# Recorder Segment Storage, Indexing, Retention, And Recovery Plan

## Summary

- Store logs as rotated FlatBuffers segment files grouped by configurable priority retention groups.
- Use one durable global `uint64_t segment_seq` for segment identity and store ordering; never derive identity or ordering from wall-clock time.
- Keep each segment limited to one `boot_id`; rotate an active segment when the observed `_BOOT_ID` changes.
- Store selected strings directly in entries and keep `.seg` files self-contained authoritative data.
- Treat `.idx` files and state files as recoverable caches/state; correctness comes from validated segment frames.
- Drive optional capture, compression, durability, and retention behavior from a recorder config file.

## Key Changes

- Add recorder config file support:
  - Store recorder settings in a JSON config file parsed with `libjansson`.
  - Before parsing, preprocess the file content and drop any line whose first non-whitespace character is `#`.
  - Pass the stripped JSON text to `libjansson` for parsing.
  - Startup fails with a clear error if the config file is unreadable or invalid.
  - Keep one explicit config surface for all optional behavior instead of scattered hard-coded toggles.
  - Config file controls optional field capture, retention budget, durability policy, compression policy, configurable priority groups, and per-priority static dictionary selection.
  - Add a `priority_groups` config section.
  - Each group record has a unique filesystem-safe `name` and a `priorities` list.
  - Every journald priority `0..7` must belong to exactly one configured group.
  - Group names are used as segment/index directory names under `LOG_DIR`.

- Update `recorder.fbs` and generated FlatBuffers headers:
  - Store direct default strings: `message`, `message_id`, and `unit`.
  - Keep `priority` in each `Entry`; do not move it to segment-level metadata.
  - Keep `hostname`, `comm`, and `exe` as optional string fields in the `Entry` schema.
  - Only add `hostname`, `comm`, and `exe` to a FlatBuffer entry when the matching capture option is enabled and journald provides a non-empty value.
  - Only add `message_id` when journald provides a non-empty value.
  - Make `pid`, `uid`, and `gid` optional captured scalar fields instead of mandatory per-entry identity fields.
  - When `pid`, `uid`, or `gid` capture is disabled, leave the corresponding scalar field at its default value.
  - Store journald `ERRNO` as `errno:ushort = 0`; `0` means either unset or errno zero.
  - Remove `StringTable`, interned `*_id` fields, `KV`, and `extra`.
  - Do not store `boot_id` or `boot_seq` in each `Entry`; entries inherit boot identity from the segment header.
  - Keep per-entry `realtime_ts` and `monotonic_ts`; combine segment `boot_seq` with entry `monotonic_ts` when event ordering is needed.

- Change storage layout:
  - Segment path: `LOG_DIR/<group_name>/<segment_seq>.seg`.
  - Index path: `LOG_DIR/<group_name>/<segment_seq>.idx`.
  - `segment_seq` filename format is plain decimal, e.g. `42.seg`.
  - Maintain `LOG_DIR/state/segment_seq` for the next global sequence.
  - Maintain `LOG_DIR/state/boots` for durable `_BOOT_ID` to `boot_seq` mapping and boot-level realtime metadata.
  - Each boot state record stores `boot_seq`, `boot_id`, and `first_realtime_ts`.
  - On clean shutdown, write `last_realtime_ts_on_clean_shutdown` for each active boot; omit that field when no clean shutdown timestamp is known.
  - On startup, recover `next_segment_seq` from `max(persisted_next, max(existing segment_seq) + 1)`.
  - `player` must not depend on the current `priority_groups` config for reading retained data; it should scan all available segment directories under `LOG_DIR` and treat any directory containing valid `.seg` files as a candidate segment directory.

- Keep boot state clean:
  - Treat `LOG_DIR/state/boots` as recoverable state derived from retained segment headers and committed frames.
  - During startup recovery, after retention, and on clean shutdown, rewrite `state/boots` to contain only boots referenced by retained segments plus the current active boot.
  - Do not renumber `boot_seq` during boot-state cleanup; gaps are allowed so retained segment headers never need rewriting.
  - If `state/boots` is missing or stale, rebuild known boot records from segment headers and committed frames, then assign new boot sequences above the recovered maximum.
  - Rewrite `state/boots` through temp-file, `fsync`, atomic `rename`, and parent-directory `fsync`.

- Define segment format:
  - Header: `magic`, `version`, `flags`, `segment_seq`, `boot_seq`, `boot_id`, `timezone`, `first_realtime_ts`, `first_monotonic_ts`, `header_crc32`.
  - When `SEGMENT_FLAG_ENCRYPTED` is set, place a versioned `RECENC01`
    extension after the fixed header and before dictionary bytes. It records
    RSA-OAEP-SHA256/AES-256-GCM algorithm identifiers, a wrapped per-segment
    data key, and the random nonce prefix.
  - Header flags include `SEGMENT_HAS_STATIC_DICT` and reserved `SEGMENT_WHOLE_COMPRESSED`.
  - Optional dictionary area immediately after the header: dictionary metadata plus dictionary bytes, or an explicit empty dictionary marker.
  - Frame: `uint32_t frame_len_le`, frame metadata, stored payload bytes, `uint32_t frame_crc32_le`.
  - Frame metadata records compression mode, stored payload length, and uncompressed payload length.
  - Footer body v1: `footer_flags`, numeric `rotation_reason`, `entry_count`, `last_realtime_ts`, `last_monotonic_ts`, `footer_crc32`.
  - `footer_flags` reserves `FOOTER_HAS_SIGNATURE`.
  - When `FOOTER_HAS_SIGNATURE` is set, place `signature_algorithm`, `signature_len`, and `signature_bytes` before `footer_flags`.
  - Reserve `SEGMENT_FLAG_SIGNED` and the Ed25519 algorithm identifier for a
    future plaintext-but-authenticated mode. Encryption does not depend on or
    enable this flag.
  - Fixed footer trailer: `version`, `magic`.
  - Footer is optional and only marks clean rotation/shutdown; missing or invalid footer falls back to frame scanning.
  - The v1 footer layout includes `rotation_reason`; this unreleased format does not preserve compatibility with earlier development layouts.
  - `header_crc32` protects the header only, excluding its own checksum field.
  - `footer_crc32` protects the footer body and fixed trailer fields, excluding its own checksum field.

- Add compression:
  - Use per-frame zstd compression by default.
  - Compress each FlatBuffer `Chunk` independently so index-based random access only decompresses the selected frame.
  - Make `COMPRESS_MIN_FRAME_BYTES` and the compress-if-smaller policy configurable in the config file.
  - Support uncompressed frames through the same frame format for small frames, incompressible frames, recovery tooling, and compatibility.
  - Store the CRC over the bytes written to disk for the frame payload and metadata needed to verify/decompress it.
  - Support optional static zstd dictionaries configured per priority.
  - Load static dictionary paths from the config file, keyed by priority, and copy the selected dictionary bytes into the segment dictionary area when a segment is created.
  - Set `SEGMENT_HAS_STATIC_DICT` when a static dictionary is embedded in the segment dictionary area.
  - If no dictionary is configured for a priority, write an explicit empty dictionary marker and use normal zstd compression for that priority.
  - Reserve `SEGMENT_WHOLE_COMPRESSED` for a future whole-segment compression mode where all chunks are compressed together for users willing to trade random access latency for better disk compression.
  - Whole-segment compression is not implemented in v1 and must remain opt-in if added later.

- Refactor recorder behavior:
  - Accumulate chunks by configured priority group, not by service and not by detailed priority.
  - Keep one active segment per `(group_name, boot_id)`.
  - Allow multiple detailed priorities inside one segment; keep the exact detailed `priority` in each entry.
  - Use named group directories so a configuration like `high = [0,1,2,3]` and `low = [4,5,6,7]` produces only two active segment streams instead of eight.
  - Capture `hostname`, `_COMM`, and `_EXE` only when enabled by configuration.
  - Create a segment lazily when the first frame is ready so header metadata is known.
  - Rotate by size, default `4 MiB`.
  - Rotate by age, default `15 minutes`, using `CLOCK_MONOTONIC` elapsed time from active segment open.
  - Rotate immediately when `_BOOT_ID` changes.
  - Rotate immediately when the local timezone changes.
  - Sample `CLOCK_REALTIME - CLOCK_BOOTTIME` while running and rotate on a
    backward realtime jump greater than `1 ms` or a forward jump greater than
    `1 s`. `CLOCK_BOOTTIME` includes suspend time, so suspend/resume is not
    mistaken for a wall-clock jump.
  - Never append to an old segment from a previous recorder process.

- Make writes power-fail robust:
  - Reserve `segment_seq` before segment creation.
  - Write state files through temp-file, `fsync`, atomic `rename`, and parent-directory `fsync`.
  - Create segment temp files, write and `fsync` the header, rename to final name, then `fsync` the directory.
  - A frame is committed only when length is sane, FlatBuffer verification passes, and CRC matches.
  - For encrypted segments, compress first and encrypt each stored frame with
    AES-256-GCM. Use `nonce_prefix || BE64(frame_index)` and authenticate the
    frame header as additional data. Metadata, indexes, and footers remain
    plaintext; index rows are generated from the plaintext chunk before it is
    encrypted.
  - Recovery scans frames from the start and ignores the first torn, invalid, or incomplete frame and everything after it.
  - Startup takes an exclusive store lock, cleans stale temp files, validates segments, repairs or removes stale indexes, and recomputes missing or stale boot state from segment headers and committed frames.

- Add priority-aware durability:
  - Add `DURABLE_PRIORITY_MAX`, default `3`.
  - Priorities `0..DURABLE_PRIORITY_MAX` flush userspace buffers and `fsync` the segment after each frame.
  - Priorities above the threshold use batched sync via `DURABILITY_FLUSH_FRAMES` or `DURABILITY_FLUSH_INTERVAL_SEC`.
  - `DURABLE_PRIORITY_MAX = -1` disables per-frame durable writes.
  - Rotation always performs final flush and `fsync` regardless of priority.
  - When multiple priorities share one segment through a configured group, the effective durability for that segment is the strongest durability required by any priority present in the flushed frame set.

- Add rebuildable chunk-level indexes:
  - Each `.idx` file starts with an immutable header containing `magic`, `version`, `segment_seq`, and segment flags.
  - One index row is appended per committed frame while the segment is active.
  - A clean-close footer records the row count, segment committed end, and footer CRC; an active index has no footer yet and remains usable up to its last complete row.
  - Row fields: frame offset, frame length, min/max realtime timestamp, min/max monotonic timestamp, priority, entry count, `service_filter_kind`, fixed-size service filter payload, and service overflow flag.
  - Define the service filter payload size so either a small fixed hash set or a Bloom filter can fit without changing row size.
  - Reserve `service_filter_kind = hash_set` and `service_filter_kind = bloom`.
  - Implement only `hash_set` in v1; reserve `bloom` for future use.
  - Exact service strings remain in entries; service filter data is only a skip hint.
  - Active indexes use their final `.idx` filename from segment open; repair/rebuild uses `.idx.tmp`, `fsync`, atomic `rename`, and directory `fsync`.
  - Index writes are advisory and must not force `fsync` or storage flushes;
    active index streams are unbuffered so readers can observe appended rows.
  - If an index is missing, stale, or doubtful, rebuild it by scanning the bounded segment.

- Add configurable retention:
  - Add `LOG_MAX_BYTES`, default `64 MiB`.
  - Accept raw byte counts and suffixes such as `64M` and `1G`; invalid values fail startup.
  - `LOG_MAX_BYTES = 0` disables retention quota enforcement.
  - Count recorder-owned persistent files under `LOG_DIR`, including `.seg`, `.idx`, and state files.
  - Retention runs after startup recovery, segment rotation, and successful cleanup.
  - Retention operates on configured priority groups, not on individual priorities.
  - Allow group-specific retention policies later, but in v1 at minimum preserve group identity so high-retention and low-retention groups can be separated.
  - Delete closed segments from the lowest-retention over-budget group first, then by lowest `segment_seq`.
  - Delete matching `.idx` files with deleted segments and `fsync` affected directories.
  - Active segments are rotated before deletion is considered; if one active segment exceeds quota, keep writing and report quota pressure.

- Add configurable optional field capture:
  - Add config-file booleans for `hostname`, `comm`, and `exe` capture, all defaulting to disabled.
  - Add config-file booleans for `pid`, `uid`, and `gid` capture, all defaulting to disabled.
  - When disabled or empty, omit the corresponding FlatBuffers string field from each entry rather than storing an empty string.
  - When disabled, leave the corresponding scalar field at its default value.
  - Keep `unit` enabled by default because service filtering depends on exact service strings.
  - Keep `message_id` enabled by default because it is compact and useful for structured event matching.

- Define segment sequence overflow handling:
  - Never wrap or reuse `segment_seq` during normal recording.
  - If `next_segment_seq == UINT64_MAX`, stop ingestion and enter exclusive maintenance mode.
  - Renumber existing closed segments densely from `0..N-1`, update segment headers, delete/rebuild indexes, and write `next_segment_seq = N`.
  - If renumbering fails midway, recovery scans segment headers and filenames and resumes only after unique sequence consistency is restored.

- Update `player.c`:
  - Iterate framed chunks instead of treating a file as one FlatBuffer.
  - Support `--since`, `--until`, `--service`, `--priority-min`, and `--priority-max`.
  - Default playback order is `segment_seq`, frame offset, entry index.
  - Use realtime min/max only as overlap filters; never stop early because later segments have lower or higher realtime timestamps.
  - Use indexes for skip hints, but rebuild or scan when indexes are missing or stale.
  - Detect footers only by reading the fixed trailer from EOF, never by scanning for magic inside payload data.
  - Scan all available subdirectories under `LOG_DIR` for retained segments instead of relying on the current configured `priority_groups`.

## Time, Ordering, And Recovery Rules

- `segment_seq` is the authoritative segment identity and store-order key.
- Segment `boot_seq` plus entry `monotonic_ts` is the event-order key within and across boots.
- `realtime_ts` is retained for display and user-facing time filters only.
- Wall-clock time and file mtime must not be used for segment naming, ordering, retention age, or rotation age.
- Full segment scans are acceptable because segment size is bounded.
- Indexes must never be required for correctness.
- Segment files are authoritative only up to the last committed frame.

## Test Plan

- Build/regeneration:
  - Regenerate FlatBuffers headers from `recorder.fbs`.
  - Compile `recorder` and `player` with warnings enabled.

- Config tests:
  - Verify valid config files load all optional settings correctly.
  - Verify lines starting with `#` are ignored before JSON parsing.
  - Verify `#` handling works with leading whitespace before the comment marker.
  - Verify invalid config syntax or invalid option values fail startup clearly.
  - Verify omitted config keys fall back to documented defaults.
  - Verify `priority_groups` reject overlaps, omissions, duplicate names, and invalid directory-name characters.

- Writer and schema tests:
  - Feed synthetic entries across many priorities and services.
  - Verify default direct string fields are written and read correctly.
  - Verify `hostname`, `comm`, and `exe` are omitted by default and present when enabled.
  - Verify `pid`, `uid`, and `gid` remain at their default values when disabled and are populated when enabled.
  - Verify segment-level `boot_seq` and `boot_id`, headers, frames, delayed index flushes, and footers.
  - Verify entries do not duplicate `boot_id` or `boot_seq`.
  - Verify priorities mapped to the same configured group land in the same segment stream while preserving exact per-entry priority.
  - Verify priorities mapped to different groups create separate segment streams.
  - Verify writer rotates on size, monotonic age, and `_BOOT_ID` change.
  - Verify realtime jumps rotate active writers: backward jumps over `1 ms`
    and forward jumps over `1 s`; verify suspend/resume alone does not rotate.

- Time-jump tests:
  - Move realtime forward, backward, and repeat values while recording.
  - Verify segment IDs remain strictly increasing.
  - Verify age rotation uses `CLOCK_MONOTONIC`.
  - Verify queries return all matching entries when realtime ranges overlap or move backward.
  - Change the local timezone while recording and verify the active segment rotates and the new segment header records the new timezone.

- Power-fail tests:
  - Truncate during header, frame length, frame body, frame CRC, and footer.
  - Verify recovery keeps valid committed frames and ignores torn tails.
  - Crash during segment rename, index write, and state-file update.
  - Verify stale temp files and stale indexes are cleaned or rebuilt deterministically.

- Compression tests:
  - Verify default per-frame zstd compression round-trips chunks.
  - Verify small or incompressible frames are stored uncompressed.
  - Verify index-based reads decompress only selected frames.
  - Configure static zstd dictionaries for selected priorities and verify new segments store and use the matching priority dictionary.
  - Verify priorities without configured dictionaries write an explicit empty dictionary marker.
  - Verify recovery rejects corrupted compressed frames by CRC or decompression failure.

- Durability tests:
  - With `DURABLE_PRIORITY_MAX=3`, verify priorities `0-3` call `fsync` after each frame.
  - Verify priorities `4-7` use batched sync.
  - Verify `-1` disables per-frame durable writes and `7` makes all priorities durable.
  - Verify rotation always syncs final segment state.

- Retention tests:
  - Parse `LOG_MAX_BYTES` values including bytes, `64M`, `1G`, `0`, and invalid input.
  - Force tiny quotas and verify deletion by configured retention group tier, then lowest `segment_seq`.
  - Verify active segments are not deleted before rotation.
  - Verify matching `.idx` files are removed and directories are synced.

- Directory-discovery tests:
  - Change `priority_groups` in the config and verify `player` still reads retained segments from both old and new group directories.
  - Verify `player` can read valid `.seg` files from all discovered subdirectories under `LOG_DIR` without requiring the current recorder config.

- Recovery and overflow tests:
  - Delete or stale `state/segment_seq`; verify recovery uses existing segment maximum.
  - Delete or stale `state/boots`; verify recovery from segment headers and committed frames.
  - Delete segments through retention and verify unreferenced boots are removed from `state/boots`.
  - Verify boot-state cleanup preserves existing `boot_seq` values and allows gaps.
  - Cleanly shut down and verify boot state includes `last_realtime_ts_on_clean_shutdown`.
  - Simulate a crash and verify boot state omits or recomputes stale clean-shutdown last realtime metadata.
  - Delete `.idx` files and verify rebuild from segments.
  - Simulate `UINT64_MAX` sequence exhaustion and verify exclusive dense renumbering.

## Assumptions

- The first query surface is the local CLI reader/player.
- Segments are grouped by configurable priority retention groups so multiple detailed priorities can share one segment stream and reduce storage wear.
- One global `segment_seq` is used across all priorities.
- One segment contains entries from exactly one `boot_id`.
- Optional behavior is configured through one recorder config file loaded at startup.
- The current recorder config maps priorities `0..7` to exactly one named group each.
- `player` discovers retained segment directories from the filesystem rather than from the current group configuration.
- `pid`, `uid`, and `gid` are optional because they are not required for the default query surface.
- `hostname`, `comm`, and `exe` are optional because they are repetitive and not needed for the default query surface.
- A small amount of newest low-priority data may be lost under the batched durability policy.
- Severe logs use automatic per-frame durability according to `DURABLE_PRIORITY_MAX`.
- Per-frame zstd compression is enabled by default, with uncompressed frames allowed when compression is not beneficial.
- Static zstd dictionaries may be configured per priority; rolling dictionary generation is out of scope.
- Whole-segment compression is reserved as a future opt-in mode.
