#!/usr/bin/env python3
"""Compare on-disk growth of journald and recorder directories.

The comparison intentionally measures storage only. It does not attempt to
compare or normalize the fields stored by either program.
"""

import argparse
import csv
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TextIO


@dataclass
class Usage:
    logical_bytes: int = 0
    physical_bytes: int = 0
    files: int = 0


def measure(path: str) -> Usage:
    usage = Usage()
    if not os.path.isdir(path):
        raise NotADirectoryError(path)

    def scan_error(error: OSError) -> None:
        raise error

    try:
        for root, _dirs, files in os.walk(path, onerror=scan_error):
            for name in files:
                filename = os.path.join(root, name)
                try:
                    stat = os.stat(filename, follow_symlinks=False)
                except OSError as error:
                    print(f"warning: cannot stat {filename}: {error}", file=sys.stderr)
                    continue
                if not os.path.isfile(filename):
                    continue
                usage.files += 1
                usage.logical_bytes += stat.st_size
                # st_blocks is expressed in 512-byte units on Unix systems.
                usage.physical_bytes += stat.st_blocks * 512
    except OSError:
        raise
    return usage


def format_bytes(value: float) -> str:
    sign = "-" if value < 0 else ""
    value = abs(value)
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{sign}{value:.2f} {unit}"
        value /= 1024
    return f"{sign}{value:.2f} TiB"


def percentage(value: float, base: float) -> str:
    if base == 0:
        return "n/a"
    return f"{value / base * 100:.2f}%"


def count_journal_entries(path: str, since: float, until: float) -> int | None:
    """Count journal records written during the measurement interval."""
    command = [
        "journalctl", f"--directory={path}", f"--since=@{since:.6f}",
        f"--until=@{until:.6f}", "--output=json", "--no-pager", "--quiet",
    ]
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"warning: cannot count journal entries: {error}", file=sys.stderr)
        return None
    return sum(1 for line in result.stdout.splitlines() if line.strip())


def write_row(writer: csv.writer, started: float, journal: Usage, recorder: Usage) -> None:
    writer.writerow(
        [
            datetime.now(timezone.utc).isoformat(),
            f"{time.monotonic() - started:.3f}",
            journal.logical_bytes,
            journal.physical_bytes,
            journal.files,
            recorder.logical_bytes,
            recorder.physical_bytes,
            recorder.files,
        ]
    )


def report(name: str, start: Usage, end: Usage, elapsed: float) -> None:
    print(f"{name}:")
    for label, attribute in (("logical", "logical_bytes"), ("physical", "physical_bytes")):
        initial = getattr(start, attribute)
        final = getattr(end, attribute)
        gained = final - initial
        rate = gained / elapsed * 3600 if elapsed > 0 else 0
        print(f"  {label} usage: {format_bytes(initial)} -> {format_bytes(final)}")
        print(f"  {label} allocation growth: {format_bytes(gained)} ({format_bytes(rate)}/hour)")
    print(f"  files: {start.files} -> {end.files}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal-dir", default="/var/log/journal")
    parser.add_argument("--recorder-dir", default="/var/log/recorder")
    parser.add_argument("--interval", type=float, default=60.0,
                        help="seconds between samples (default: 60)")
    parser.add_argument("--duration", type=float, default=3600.0,
                        help="total measurement time in seconds; 0 measures once (default: 3600)")
    parser.add_argument("--csv", metavar="PATH",
                        help="also write samples to PATH, or '-' for stdout")
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error("--interval must be greater than zero")
    if args.duration < 0:
        parser.error("--duration must not be negative")
    return args


def main() -> int:
    args = parse_args()
    csv_file: TextIO | None = None
    close_csv = False
    writer = None

    if args.csv:
        if args.csv == "-":
            csv_file = sys.stdout
        else:
            csv_file = open(args.csv, "w", newline="", encoding="utf-8")
            close_csv = True
        writer = csv.writer(csv_file)
        writer.writerow([
            "timestamp", "elapsed_seconds", "journal_logical_bytes",
            "journal_physical_bytes", "journal_files", "recorder_logical_bytes",
            "recorder_physical_bytes", "recorder_files",
        ])

    for name, path in (("journal", args.journal_dir), ("recorder", args.recorder_dir)):
        if not os.path.isdir(path):
            print(f"error: {name} directory does not exist or is not readable: {path}",
                  file=sys.stderr)
            return 2

    started = time.monotonic()
    started_wall = time.time()
    try:
        first_journal = measure(args.journal_dir)
        first_recorder = measure(args.recorder_dir)
    except OSError as error:
        print(f"error: cannot measure storage: {error}", file=sys.stderr)
        return 2
    last_journal = first_journal
    last_recorder = first_recorder
    if writer:
        write_row(writer, started, last_journal, last_recorder)

    try:
        while time.monotonic() - started < args.duration:
            remaining = args.duration - (time.monotonic() - started)
            time.sleep(min(args.interval, remaining))
            try:
                last_journal = measure(args.journal_dir)
                last_recorder = measure(args.recorder_dir)
            except OSError as error:
                print(f"error: cannot measure storage: {error}", file=sys.stderr)
                return 2
            if writer:
                write_row(writer, started, last_journal, last_recorder)
    except KeyboardInterrupt:
        print("\nMeasurement interrupted; reporting samples collected so far.", file=sys.stderr)
    finally:
        if close_csv and csv_file:
            csv_file.close()

    elapsed = time.monotonic() - started
    journal_entries = count_journal_entries(args.journal_dir, started_wall, time.time())
    journal_physical = last_journal.physical_bytes - first_journal.physical_bytes
    recorder_physical = last_recorder.physical_bytes - first_recorder.physical_bytes
    saved = journal_physical - recorder_physical

    print(f"Measurement time: {elapsed:.1f} seconds ({elapsed / 3600:.2f} hours)")
    print(f"Journal directory: {args.journal_dir}")
    print(f"Recorder directory: {args.recorder_dir}")
    if journal_entries is not None:
        print(f"Journald entries during measurement: {journal_entries}")
    print()
    report("journald", first_journal, last_journal, elapsed)
    print()
    report("recorder", first_recorder, last_recorder, elapsed)
    print()
    print("Physical storage comparison:")
    print(f"  journald final usage: {format_bytes(last_journal.physical_bytes)}")
    print(f"  recorder final usage: {format_bytes(last_recorder.physical_bytes)}")
    final_saved = last_journal.physical_bytes - last_recorder.physical_bytes
    if final_saved >= 0:
        print(f"  recorder uses less space at end: {format_bytes(final_saved)}")
        print(f"  reduction versus journald: {percentage(final_saved, last_journal.physical_bytes)}")
    else:
        print(f"  recorder uses more space at end: {format_bytes(-final_saved)}")
        print(f"  increase versus journald: {percentage(-final_saved, last_journal.physical_bytes)}")
    print(f"  journald growth: {format_bytes(journal_physical)}")
    print(f"  recorder growth: {format_bytes(recorder_physical)}")
    if saved >= 0:
        print(f"  space saved by recorder: {format_bytes(saved)}")
        print(f"  reduction versus journald: {percentage(saved, journal_physical)}")
    else:
        print(f"  extra space used by recorder: {format_bytes(-saved)}")
        print(f"  increase versus journald: {percentage(-saved, journal_physical)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
