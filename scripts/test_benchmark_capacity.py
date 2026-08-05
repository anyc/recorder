#!/usr/bin/env python3

import argparse
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import benchmark_capacity as capacity


class CapacityBenchmarkTests(unittest.TestCase):
    def test_generated_message_size_and_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "batch.log"
            capacity.generate_batch(path, 42, 3, 64)
            lines = path.read_text(encoding="ascii").splitlines()

        self.assertEqual(3, len(lines))
        self.assertTrue(all(len(line) == 64 for line in lines))
        self.assertTrue(lines[0].startswith("capacity-benchmark-000000000042-"))

    def test_sequence_stats_ignore_unrelated_messages(self) -> None:
        stats = capacity.EntryStats()
        capacity.update_stats(stats, "unrelated service message")
        capacity.update_stats(stats, "capacity-benchmark-000000000010-data")
        capacity.update_stats(stats, "capacity-benchmark-000000000003-data")

        self.assertEqual(2, stats.count)
        self.assertEqual(3, stats.oldest)
        self.assertEqual(10, stats.newest)
        self.assertFalse(stats.contiguous)

    def test_sequence_stats_accept_contiguous_tail(self) -> None:
        stats = capacity.EntryStats()
        for sequence in (42, 43, 44):
            capacity.update_stats(
                stats, f"capacity-benchmark-{sequence:012d}-data")

        self.assertTrue(stats.contiguous)
        self.assertEqual(42, stats.oldest)
        self.assertEqual(44, stats.newest)
        self.assertTrue(capacity.is_complete_range(stats, 42, 44))
        self.assertTrue(capacity.is_evicted_suffix(stats, 45))

    def test_suffix_validation_rejects_missing_or_unconsumed_tail(self) -> None:
        missing = capacity.EntryStats()
        for sequence in (42, 44):
            capacity.update_stats(
                missing, f"capacity-benchmark-{sequence:012d}-data")
        self.assertFalse(capacity.is_evicted_suffix(missing, 45))

        stopped_early = capacity.EntryStats()
        for sequence in (42, 43):
            capacity.update_stats(
                stopped_early, f"capacity-benchmark-{sequence:012d}-data")
        self.assertFalse(capacity.is_evicted_suffix(stopped_early, 45))

    def test_nul_terminated_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cursor"
            path.write_bytes(b"s=cursor-value\0")
            self.assertEqual("s=cursor-value", capacity.read_cursor(path))

    def test_configs_apply_limits_and_disable_rate_limiting(self) -> None:
        journal = capacity.generated_journald_config("persistent", 20 * capacity.MIB)
        self.assertIn("RateLimitIntervalSec=0", journal)
        self.assertIn("SystemKeepFree=0", journal)
        self.assertIn("SystemMaxUse=20971520", journal)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recorder.json"
            capacity.write_recorder_config(path, 20 * capacity.MIB, capacity.MIB)
            recorder = path.read_text(encoding="utf-8")
        self.assertIn('"log_max_bytes": 20971520', recorder)
        self.assertIn('"segment_max_bytes": 1048576', recorder)
        self.assertIn('"entry_format": "default"', recorder)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recorder-all.json"
            capacity.write_recorder_config(
                path, 20 * capacity.MIB, capacity.MIB, True)
            recorder_all = path.read_text(encoding="utf-8")
        for field in ("hostname", "comm", "exe", "pid", "uid", "gid"):
            self.assertIn(f'"capture_{field}": true', recorder_all)
        self.assertIn('"capture_all_fields": true', recorder_all)
        self.assertIn('"entry_format": "full"', recorder_all)

    def test_prepare_batches_rejects_truncated_workload(self) -> None:
        args = argparse.Namespace(
            budget=capacity.MIB,
            oversubscribe=4,
            message_bytes=64,
            batch_messages=32,
            max_batches=1,
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "increase --max-batches"):
                capacity.prepare_batches(args, Path(directory))

    def test_disk_usage_parser(self) -> None:
        output = "Archived and active journals take up 18.1M in the file system."
        self.assertEqual(int(18.1 * capacity.MIB),
                         capacity.parse_disk_usage(output))

    def test_matching_config_does_not_create_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work_dir = Path(directory)
            namespace = "capacity-test"
            system_path = work_dir / "installed.conf"
            system_path.write_text("wanted\n", encoding="utf-8")
            state = capacity.make_config_state(
                namespace, work_dir, "wanted\n", system_path)

        self.assertEqual(b"wanted\n", state.original)
        self.assertIsNone(state.restore_path)

    def test_changed_config_creates_recovery_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work_dir = Path(directory)
            system_path = work_dir / "installed.conf"
            system_path.write_text("original\n", encoding="utf-8")
            state = capacity.make_config_state(
                "capacity-test", work_dir, "wanted\n", system_path)

            self.assertIsNotNone(state.restore_path)
            assert state.restore_path is not None
            self.assertEqual(b"original\n", state.restore_path.read_bytes())


if __name__ == "__main__":
    unittest.main()
