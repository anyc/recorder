#!/usr/bin/env python3

import argparse
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import benchmark_storage as storage


class StorageBenchmarkTests(unittest.TestCase):
    def test_parse_size(self) -> None:
        self.assertEqual(20 * storage.MIB, storage.parse_size("20M"))
        with self.assertRaises(argparse.ArgumentTypeError):
            storage.parse_size("")

    def test_config_disables_limits_that_can_drop_or_shrink_replay(self) -> None:
        config = storage.generated_journald_config("persistent", 20 * storage.MIB)
        self.assertIn("RateLimitIntervalSec=0", config)
        self.assertIn("LineMax=8M", config)
        self.assertIn("SystemKeepFree=0", config)
        self.assertIn("SystemMaxUse=20971520", config)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recorder.json"
            storage.write_recorder_config(path, True)
            recorder = path.read_text(encoding="utf-8")
        for field in ("hostname", "comm", "exe", "pid", "uid", "gid"):
            self.assertIn(f'"capture_{field}": true', recorder)
        self.assertIn('"capture_all_fields": true', recorder)
        self.assertIn('"entry_format": "full"', recorder)

    def test_replay_disables_service_rate_limiting(self) -> None:
        args = storage.replay_command(
            Path("input.log"), Path("replay.py"), "bench", "bench-replay",
            "alice", True,
        )
        self.assertEqual("sudo", args[0])
        self.assertIn("--property=LogRateLimitIntervalSec=0", args)
        self.assertIn("--property=LogRateLimitBurst=0", args)
        self.assertIn("--property=User=alice", args)

    def test_header_usage_parser(self) -> None:
        output = "Disk usage: 8M\nDisk usage: 512K\n"
        self.assertEqual(8 * storage.MIB + 512 * 1024,
                         storage.parse_header_usage(output))

    def test_extent_helper_ignores_trailing_zero_preallocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, helper = storage.write_helpers(root)
            journals = root / "journals"
            journals.mkdir()
            (journals / "one.journal").write_bytes(b"abc" + b"\0" * 100)
            (journals / "two.journal~").write_bytes(b"\0x" + b"\0" * 50)
            result = subprocess.run(
                [sys.executable, str(helper), str(journals)], check=True,
                stdout=subprocess.PIPE, text=True,
            )

        self.assertEqual(5, int(result.stdout))

    def test_matching_config_needs_no_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            system = root / "installed.conf"
            persistent = root / "persistent.conf"
            system.write_bytes(b"same\n")
            persistent.write_bytes(b"same\n")
            state = storage.make_config_state(system, persistent, root)

        self.assertIsNone(state.backup_path)

    def test_different_config_has_recovery_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            system = root / "installed.conf"
            persistent = root / "persistent.conf"
            system.write_bytes(b"original\n")
            persistent.write_bytes(b"benchmark\n")
            state = storage.make_config_state(system, persistent, root)

            self.assertIsNotNone(state.backup_path)
            assert state.backup_path is not None
            self.assertEqual(b"original\n", state.backup_path.read_bytes())

    def test_nul_terminated_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cursor = Path(directory) / "cursor"
            cursor.write_bytes(b"s=value\0")
            self.assertEqual("s=value", storage.read_cursor(cursor))

    def test_journal_has_entries_after_cursor_uses_cursor_output(self) -> None:
        original_run = storage.run

        def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            del command, kwargs
            return subprocess.CompletedProcess([], 0, "-- cursor: s=next\n", "")

        storage.run = fake_run
        try:
            self.assertTrue(storage.journal_has_entries_after_cursor(
                "bench", "s=current"))
        finally:
            storage.run = original_run

    def test_current_cursor_is_not_later_entry(self) -> None:
        original_run = storage.run

        def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess:
            del command, kwargs
            return subprocess.CompletedProcess([], 0, "-- cursor: s=current\n", "")

        storage.run = fake_run
        try:
            self.assertFalse(storage.journal_has_entries_after_cursor(
                "bench", "s=current"))
        finally:
            storage.run = original_run


if __name__ == "__main__":
    unittest.main()
