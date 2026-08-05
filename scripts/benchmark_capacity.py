#!/usr/bin/env python3
"""Compare retained generated messages under equal storage budgets."""

import argparse
import hashlib
import os
import pwd
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


MESSAGE_PREFIX = "capacity-benchmark-"
SEQUENCE_RE = re.compile(r"capacity-benchmark-([0-9]{12})-")
MIB = 1024**2
GIB = 1024**3


@dataclass
class EntryStats:
    count: int = 0
    oldest: int | None = None
    newest: int | None = None
    previous: int | None = None
    contiguous: bool = True


@dataclass
class Usage:
    logical: int = 0
    physical: int = 0


@dataclass
class PhaseResult:
    generated: int
    retained: EntryStats
    usage: Usage


@dataclass
class ConfigState:
    namespace: str
    system_path: Path
    generated_path: Path
    original: bytes | None
    restore_path: Path | None
    changed: bool = False


def parse_size(value: str) -> int:
    units = {"K": 1024, "M": MIB, "G": GIB, "T": 1024**4}
    text = value.strip().upper()
    if not text:
        raise argparse.ArgumentTypeError("size must not be empty")
    multiplier = units.get(text[-1], 1)
    if multiplier != 1:
        text = text[:-1]
    try:
        result = int(text) * multiplier
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid size: {value}") from error
    if result <= 0:
        raise argparse.ArgumentTypeError("size must be greater than zero")
    return result


def command_text(command: list[str]) -> str:
    return shlex.join(command)


def run(command: list[str], check: bool = True, quiet: bool = False,
        **kwargs: object) -> subprocess.CompletedProcess:
    if not quiet:
        print("$ " + command_text(command))
    return subprocess.run(command, check=check, **kwargs)


def sudo_run(command: list[str], check: bool = True,
             quiet: bool = False, **kwargs: object) -> subprocess.CompletedProcess:
    return run(["sudo", *command], check=check, quiet=quiet, **kwargs)


def namespace_paths(namespace: str, machine_id: str) -> list[Path]:
    suffix = f"{machine_id}.{namespace}"
    return [Path("/var/log/journal") / suffix,
            Path("/run/log/journal") / suffix]


def namespace_stop_commands(namespace: str) -> list[list[str]]:
    return [["systemctl", "stop", unit] for unit in (
        f"systemd-journald@{namespace}.socket",
        f"systemd-journald-varlink@{namespace}.socket",
        f"systemd-journald@{namespace}.service",
        f"systemd-journald-sync@{namespace}.service",
    )]


def stop_namespace(namespace: str) -> None:
    # Stop socket activation before the service so it cannot immediately
    # restart while its files/configuration are being changed.
    for command in namespace_stop_commands(namespace):
        sudo_run(command, check=False,
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def clear_namespace(namespace: str, machine_id: str) -> None:
    stop_namespace(namespace)
    for path in namespace_paths(namespace, machine_id):
        sudo_run(["rm", "-rf", "--", str(path)])


def generated_journald_config(storage: str, budget: int) -> str:
    return (
        "[Journal]\n"
        f"Storage={storage}\n"
        "Compress=yes\n"
        "Seal=no\n"
        "RateLimitIntervalSec=0\n"
        "SystemKeepFree=0\n"
        "RuntimeKeepFree=0\n"
        f"SystemMaxUse={budget}\n"
        f"RuntimeMaxUse={budget}\n"
        "MaxRetentionSec=0\n"
    )


def make_config_state(namespace: str, work_dir: Path, contents: str,
                      system_path: Path | None = None) -> ConfigState:
    if system_path is None:
        system_path = Path(f"/etc/systemd/journald@{namespace}.conf")
    generated_path = work_dir / f"journald@{namespace}.conf"
    generated_path.write_text(contents, encoding="utf-8")
    original = system_path.read_bytes() if system_path.exists() else None
    restore_path = None
    if original is not None and original != generated_path.read_bytes():
        restore_path = work_dir / f"journald@{namespace}.conf.original"
        restore_path.write_bytes(original)
    return ConfigState(namespace, system_path, generated_path, original,
                       restore_path)


def install_config(state: ConfigState) -> None:
    desired = state.generated_path.read_bytes()
    if state.original == desired:
        print(f"Namespace configuration already matches: {state.system_path}")
        return
    sudo_run(["install", "-m", "0644", str(state.generated_path),
              str(state.system_path)])
    state.changed = True


def restore_config(state: ConfigState) -> None:
    if not state.changed:
        return
    if state.original is None:
        sudo_run(["rm", "-f", "--", str(state.system_path)], check=False)
        return
    if state.restore_path is None:
        raise RuntimeError(f"missing backup for {state.system_path}")
    sudo_run(["install", "-m", "0644", str(state.restore_path),
              str(state.system_path)], check=False)


def generate_batch(path: Path, first: int, count: int,
                   message_bytes: int) -> None:
    with path.open("w", encoding="ascii") as output:
        for number in range(first, first + count):
            prefix = f"{MESSAGE_PREFIX}{number:012d}-"
            body_parts: list[str] = []
            body_length = 0
            counter = 0
            while body_length < message_bytes - len(prefix):
                part = hashlib.sha256(f"{number}:{counter}".encode()).hexdigest()
                body_parts.append(part)
                body_length += len(part)
                counter += 1
            output.write((prefix + "".join(body_parts))[:message_bytes] + "\n")


def planned_batch_count(args: argparse.Namespace) -> int:
    requested_messages = max(
        args.batch_messages,
        (args.budget * args.oversubscribe + args.message_bytes - 1)
        // args.message_bytes,
    )
    requested_batches = (
        requested_messages + args.batch_messages - 1
    ) // args.batch_messages
    if requested_batches > args.max_batches:
        raise RuntimeError(
            f"workload requires {requested_batches} batches but --max-batches is "
            f"{args.max_batches}; increase --max-batches"
        )
    return requested_batches


def prepare_batches(args: argparse.Namespace, work_dir: Path) -> list[Path]:
    requested_batches = planned_batch_count(args)
    batches = []
    for batch_number in range(requested_batches):
        path = work_dir / f"batch-{batch_number:05d}.log"
        generate_batch(path, batch_number * args.batch_messages,
                       args.batch_messages, args.message_bytes)
        batches.append(path)
    manifest = work_dir / "batches.manifest"
    manifest.write_text("".join(f"{path}\n" for path in batches),
                        encoding="utf-8")
    return batches


def write_recorder_config(path: Path, budget: int,
                          segment_bytes: int,
                          capture_all_fields: bool = False) -> None:
    capture = "true" if capture_all_fields else "false"
    path.write_text(
        "{\n"
        f'  "log_max_bytes": {budget},\n'
        f'  "segment_max_bytes": {segment_bytes},\n'
        '  "segment_max_age_sec": 0,\n'
        '  "durable_priority_max": -1,\n'
        '  "compress_enabled": true,\n'
        '  "compress_min_frame_bytes": 256,\n'
        '  "compress_if_smaller": true,\n'
        f'  "capture_message_id": {capture},\n'
        '  "capture_unit": true,\n'
        f'  "capture_hostname": {capture},\n'
        f'  "capture_comm": {capture},\n'
        f'  "capture_exe": {capture},\n'
        f'  "capture_pid": {capture},\n'
        f'  "capture_uid": {capture},\n'
        f'  "capture_gid": {capture},\n'
        f'  "capture_all_fields": {capture},\n'
        f'  "entry_format": "{"full" if capture_all_fields else "default"}",\n'
        '  "sanitize_output": true\n'
        "}\n",
        encoding="utf-8",
    )


def update_stats(stats: EntryStats, text: str) -> None:
    match = SEQUENCE_RE.search(text)
    if not match:
        return
    sequence = int(match.group(1))
    if stats.previous is not None and sequence != stats.previous + 1:
        stats.contiguous = False
    stats.count += 1
    stats.oldest = sequence if stats.oldest is None else min(stats.oldest, sequence)
    stats.newest = sequence if stats.newest is None else max(stats.newest, sequence)
    stats.previous = sequence


def is_complete_range(stats: EntryStats, first: int, last: int) -> bool:
    return (
        stats.contiguous and
        stats.oldest == first and
        stats.newest == last and
        stats.count == last - first + 1
    )


def is_evicted_suffix(stats: EntryStats, generated: int) -> bool:
    return (
        stats.oldest is not None and
        stats.oldest > 0 and
        stats.count < generated and
        is_complete_range(stats, stats.oldest, generated - 1)
    )


def stream_stats(command: list[str]) -> EntryStats:
    print("$ " + command_text(command))
    process = subprocess.Popen(command, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    stats = EntryStats()
    assert process.stdout is not None
    for line in process.stdout:
        update_stats(stats, line)
    stderr = process.stderr.read() if process.stderr else ""
    returncode = process.wait()
    if returncode != 0:
        raise RuntimeError(
            f"command failed with status {returncode}: {command_text(command)}\n"
            f"{stderr.strip()}"
        )
    return stats


def journal_stats_command(namespace: str) -> list[str]:
    return [
        "sudo", "journalctl", "--namespace", namespace, "--output=cat",
        "--no-pager", "--quiet",
    ]


def journal_stats(namespace: str) -> EntryStats:
    return stream_stats(journal_stats_command(namespace))


def recorder_stats(player: str, directory: Path) -> EntryStats:
    return stream_stats([player, "-D", str(directory)])


def parse_disk_usage(output: str) -> int:
    match = re.search(r"([0-9]+(?:\.[0-9]+)?)\s*([KMGT]?)B?", output,
                      re.IGNORECASE)
    if not match:
        raise RuntimeError(f"cannot parse journal disk usage: {output.strip()}")
    multiplier = {"": 1, "K": 1024, "M": MIB, "G": GIB,
                  "T": 1024**4}[match.group(2).upper()]
    return int(float(match.group(1)) * multiplier)


def journal_usage(namespace: str) -> Usage:
    command = journal_usage_command(namespace)
    result = run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                 text=True, env={**os.environ, "LC_ALL": "C"})
    value = parse_disk_usage(result.stdout)
    return Usage(value, value)


def journal_usage_command(namespace: str) -> list[str]:
    return ["sudo", "journalctl", "--namespace", namespace,
            "--disk-usage", "--no-pager"]


def directory_usage(path: Path) -> Usage:
    logical = int(run(["du", "-B1", "--apparent-size", "-s", str(path)],
                      stdout=subprocess.PIPE, text=True).stdout.split()[0])
    physical = int(run(["du", "-B1", "-s", str(path)],
                       stdout=subprocess.PIPE, text=True).stdout.split()[0])
    return Usage(logical, physical)


def replay_command(args: argparse.Namespace, namespace: str,
                   helper: Path, manifest: Path, unit: str) -> list[str]:
    return [
        "sudo", "systemd-run", "--quiet", "--wait", "--collect",
        f"--unit={unit}",
        f"--property=LogNamespace={namespace}",
        f"--property=User={args.run_as}",
        "--property=LogRateLimitIntervalSec=0",
        "--property=LogRateLimitBurst=0",
        "/usr/bin/python3", str(helper), str(manifest),
    ]


def replay_manifest(args: argparse.Namespace, namespace: str,
                    helper: Path, manifest: Path, unit: str) -> None:
    run(replay_command(args, namespace, helper, manifest, unit))


def run_journald_phase(args: argparse.Namespace, namespace: str,
                       batches: list[Path], machine_id: str,
                       work_dir: Path) -> PhaseResult:
    clear_namespace(namespace, machine_id)
    manifest = work_dir / "batches.manifest"
    helper = work_dir / "replay_manifest.py"
    replay_manifest(args, namespace, helper, manifest,
                    f"{args.namespace}-journal-input-{os.getpid()}")
    sudo_run(["journalctl", "--namespace", namespace, "--sync"])
    generated = len(batches) * args.batch_messages
    usage = journal_usage(namespace)
    stats = journal_stats(namespace)
    if not is_evicted_suffix(stats, generated):
        raise RuntimeError(
            "journald did not evict old generated entries: "
            f"generated={generated}, retained={stats.count}, "
            f"oldest={stats.oldest}, contiguous={stats.contiguous}, "
            f"usage={usage.logical}"
        )
    return PhaseResult(generated, stats, usage)


def journal_tail_cursor(namespace: str) -> str:
    command = journal_tail_cursor_command(namespace)
    result = run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                 text=True, quiet=True)
    match = re.search(r"^-- cursor: (.+)$", result.stdout, re.MULTILINE)
    if not match:
        raise RuntimeError("cannot determine transport journal tail cursor")
    return match.group(1).strip()


def journal_tail_cursor_command(namespace: str) -> list[str]:
    return ["sudo", "journalctl", "--namespace", namespace, "-n", "1",
            "--show-cursor", "--no-pager", "--quiet"]


def read_cursor(path: Path) -> str:
    try:
        return path.read_bytes().split(b"\0", 1)[0].decode("utf-8").strip()
    except FileNotFoundError:
        return ""


def wait_for_recorder(args: argparse.Namespace, namespace: str,
                      cursor_path: Path) -> None:
    target = journal_tail_cursor(namespace)
    deadline = time.monotonic() + args.drain_timeout
    last_cursor = ""
    last_progress = time.monotonic()
    last_report = 0.0
    print("Waiting for recorder to reach the fixed transport-journal tail...")
    while time.monotonic() < deadline:
        cursor = read_cursor(cursor_path)
        if cursor == target:
            print("Recorder reached the transport-journal tail.")
            return
        now = time.monotonic()
        if cursor and cursor != last_cursor:
            last_cursor = cursor
            last_progress = now
        if now - last_report >= 5.0:
            age = now - last_progress
            print(f"  recorder is draining (last cursor progress {age:.1f}s ago)...")
            last_report = now
        if now - last_progress > args.stall_timeout:
            raise RuntimeError(
                f"recorder cursor made no progress for {args.stall_timeout:.0f}s"
            )
        time.sleep(1.0)
    raise RuntimeError(
        f"recorder did not drain within {args.drain_timeout:.0f}s"
    )


def recorder_unit(args: argparse.Namespace) -> str:
    return f"{args.namespace}-recorder-{os.getpid()}"


def recorder_start_command(args: argparse.Namespace, namespace: str,
                           recorder_executable: str, recorder_config: Path,
                           recorder_dir: Path, live_cursor: Path) -> list[str]:
    return [
        "systemd-run", "--quiet", f"--unit={recorder_unit(args)}", "--collect",
        f"--property=User={args.run_as}",
        "--property=SupplementaryGroups=systemd-journal",
        f"--property=Environment=RECORDER_CONFIG={recorder_config}",
        recorder_executable, "--namespace", namespace,
        "--log-dir", str(recorder_dir), "--cursor", str(live_cursor),
    ]


def run_recorder_phase(args: argparse.Namespace, namespace: str,
                       batches: list[Path], machine_id: str,
                       recorder_executable: str, player: str,
                       recorder_config: Path, work_dir: Path) -> PhaseResult:
    clear_namespace(namespace, machine_id)
    manifest = work_dir / "batches.manifest"
    helper = work_dir / "replay_manifest.py"
    replay_manifest(args, namespace, helper, manifest,
                    f"{args.namespace}-recorder-input-{os.getpid()}")
    sudo_run(["journalctl", "--namespace", namespace, "--sync"])

    expected = len(batches) * args.batch_messages
    transport_stats = journal_stats(namespace)
    if not is_complete_range(transport_stats, 0, expected - 1):
        raise RuntimeError(
            "transport journal lost generated input before recorder started: "
            f"expected={expected}, retained={transport_stats.count}, "
            f"oldest={transport_stats.oldest}, newest={transport_stats.newest}, "
            f"contiguous={transport_stats.contiguous}"
        )
    print(f"Transport integrity verified: all {expected} generated entries retained.")

    recorder_dir = work_dir / "recorder"
    recorder_dir.mkdir()
    live_cursor = recorder_dir / "state" / "journal.cursor.live"
    service = recorder_unit(args) + ".service"
    try:
        sudo_run(recorder_start_command(
            args, namespace, recorder_executable, recorder_config,
            recorder_dir, live_cursor))
        sudo_run(["systemctl", "is-active", service])
        wait_for_recorder(args, namespace, live_cursor)
        time.sleep(args.drain_seconds)
    except (OSError, subprocess.CalledProcessError, RuntimeError):
        sudo_run(["journalctl", "-u", service, "--no-pager", "-n", "100"],
                 check=False)
        raise
    finally:
        sudo_run(["systemctl", "stop", service], check=False)

    stats = recorder_stats(player, recorder_dir)
    usage = directory_usage(recorder_dir)
    if stats.count == 0:
        sudo_run(["journalctl", "-u", service,
                  "--no-pager", "-n", "100"], check=False)
        raise RuntimeError("recorder produced no readable generated entries")
    if not is_evicted_suffix(stats, expected):
        raise RuntimeError(
            "recorder retention did not evict old generated entries: "
            f"generated={expected}, retained={stats.count}, "
            f"oldest={stats.oldest}, newest={stats.newest}, "
            f"contiguous={stats.contiguous}"
        )
    return PhaseResult(expected, stats, usage)


def print_sudo_plan(args: argparse.Namespace, states: list[ConfigState],
                    machine_id: str, recorder_executable: str,
                    recorder_config: Path, work_dir: Path) -> None:
    manifest = work_dir / "batches.manifest"
    helper = work_dir / "replay_manifest.py"
    journal_namespace = states[0].namespace
    input_namespace = states[1].namespace
    journal_unit = f"{args.namespace}-journal-input-{os.getpid()}"
    input_unit = f"{args.namespace}-recorder-input-{os.getpid()}"
    recorder_dir = work_dir / "recorder"
    live_cursor = recorder_dir / "state" / "journal.cursor.live"
    recorder_service = recorder_unit(args) + ".service"

    def show(command: list[str]) -> None:
        print("  $ " + command_text(command))

    print("\nPrivileged operations planned:")
    for state in states:
        if state.original != state.generated_path.read_bytes():
            show(["sudo", "install", "-m", "0644",
                  str(state.generated_path), str(state.system_path)])
    show(["sudo", "systemctl", "daemon-reload"])

    print("  # journald phase")
    for command in namespace_stop_commands(journal_namespace):
        show(["sudo", *command])
    for path in namespace_paths(journal_namespace, machine_id):
        show(["sudo", "rm", "-rf", "--", str(path)])
    show(replay_command(args, journal_namespace, helper, manifest,
                        journal_unit))
    show(["sudo", "journalctl", "--namespace", journal_namespace, "--sync"])
    show(journal_usage_command(journal_namespace))
    show(journal_stats_command(journal_namespace))

    print("  # recorder phase")
    for command in namespace_stop_commands(input_namespace):
        show(["sudo", *command])
    for path in namespace_paths(input_namespace, machine_id):
        show(["sudo", "rm", "-rf", "--", str(path)])
    show(replay_command(args, input_namespace, helper, manifest, input_unit))
    show(["sudo", "journalctl", "--namespace", input_namespace, "--sync"])
    show(journal_stats_command(input_namespace))
    show(["sudo", *recorder_start_command(
        args, input_namespace, recorder_executable, recorder_config,
        recorder_dir, live_cursor)])
    show(["sudo", "systemctl", "is-active", recorder_service])
    show(journal_tail_cursor_command(input_namespace))
    show(["sudo", "systemctl", "stop", recorder_service])

    print("  # conditional diagnostics, interruption handling, and cleanup")
    show(["sudo", "journalctl", "-u", recorder_service,
          "--no-pager", "-n", "100"])
    for unit in (
        recorder_service,
        journal_unit + ".service",
        input_unit + ".service",
    ):
        show(["sudo", "systemctl", "stop", unit])
    for state in states:
        for command in namespace_stop_commands(state.namespace):
            show(["sudo", *command])
        for path in namespace_paths(state.namespace, machine_id):
            show(["sudo", "rm", "-rf", "--", str(path)])
        if state.original is None:
            show(["sudo", "rm", "-f", "--", str(state.system_path)])
        elif state.restore_path is not None:
            show(["sudo", "install", "-m", "0644",
                  str(state.restore_path), str(state.system_path)])
    show(["sudo", "systemctl", "daemon-reload"])


def restore_all(states: list[ConfigState]) -> None:
    for state in states:
        stop_namespace(state.namespace)
        restore_config(state)
    sudo_run(["systemctl", "daemon-reload"], check=False)


def stop_benchmark_units(args: argparse.Namespace) -> None:
    for unit in (
        recorder_unit(args) + ".service",
        f"{args.namespace}-journal-input-{os.getpid()}.service",
        f"{args.namespace}-recorder-input-{os.getpid()}.service",
    ):
        sudo_run(["systemctl", "stop", unit], check=False)


def write_replay_helper(path: Path) -> None:
    path.write_text(
        "import pathlib, shutil, sys\n"
        "for name in pathlib.Path(sys.argv[1]).read_text().splitlines():\n"
        "    with pathlib.Path(name).open(encoding='ascii') as source:\n"
        "        shutil.copyfileobj(source, sys.stdout)\n"
        "sys.stdout.flush()\n",
        encoding="ascii",
    )


def check_free_space(requirements: list[tuple[Path, int]]) -> None:
    by_device: dict[int, tuple[Path, int]] = {}
    for path, required in requirements:
        device = path.stat().st_dev
        representative, current = by_device.get(device, (path, 0))
        by_device[device] = (representative, current + required)
    for representative, required in by_device.values():
        available = shutil.disk_usage(representative).free
        if available < required:
            raise RuntimeError(
                f"insufficient free space on filesystem containing "
                f"{representative}: required={required}, available={available}"
            )


def execute(args: argparse.Namespace) -> int:
    recorder_executable = shutil.which(args.recorder)
    player = shutil.which(args.player)
    if not recorder_executable or not player:
        print("error: recorder and player executables must be available",
              file=sys.stderr)
        return 2
    recorder_executable = str(Path(recorder_executable).resolve())
    player = str(Path(player).resolve())

    executing_user = pwd.getpwuid(os.getuid()).pw_name
    if args.run_as != executing_user:
        print(f"error: --run-as must be the executing user ({executing_user})",
              file=sys.stderr)
        return 2

    journal_namespace = args.namespace
    input_namespace = args.input_namespace or f"{args.namespace}-input"
    if input_namespace == journal_namespace:
        print("error: baseline and input namespaces must be different",
              file=sys.stderr)
        return 2

    machine_id = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    work_dir = Path(tempfile.mkdtemp(prefix="recorder-capacity-"))
    recorder_config = work_dir / "recorder.json"
    write_recorder_config(recorder_config, args.budget, args.segment_bytes,
                          args.capture_all_fields)
    write_replay_helper(work_dir / "replay_manifest.py")
    transport_budget = max(GIB, args.budget * 64)
    states = [
        make_config_state(
            journal_namespace, work_dir,
            generated_journald_config("persistent", args.budget),
        ),
        make_config_state(
            input_namespace, work_dir,
            generated_journald_config("persistent", transport_budget),
        ),
    ]
    privileged_started = False

    try:
        batch_count = planned_batch_count(args)
        generated = batch_count * args.batch_messages
        workload_bytes = generated * (args.message_bytes + 1)
        check_free_space([
            (work_dir, workload_bytes + args.budget),
            (Path("/var/log"), transport_budget + args.budget),
        ])
        batches = prepare_batches(args, work_dir)
        print(f"Benchmark files: {work_dir}")
        print(f"Prepared {len(batches)} batches ({generated} messages)")
        print(f"Generated workload size: {workload_bytes / MIB:.2f} MiB")
        print(f"Baseline namespace: {journal_namespace} ({args.budget} bytes)")
        print(f"Recorder input namespace: {input_namespace} ({transport_budget} bytes)")

        existing = [
            path for state in states
            for path in namespace_paths(state.namespace, machine_id)
            if path.exists()
        ]
        if existing:
            answer = input(
                "Benchmark namespaces contain journal data that must be deleted. "
                "Continue? [y/N] "
            )
            if answer.strip().lower() not in ("y", "yes"):
                print(f"Keeping temporary files in {work_dir}")
                return 1

        print_sudo_plan(args, states, machine_id, recorder_executable,
                        recorder_config, work_dir)
        if input("Continue with the benchmark? [y/N] ").strip().lower() not in (
                "y", "yes"):
            print(f"Keeping temporary files in {work_dir}")
            return 1

        privileged_started = True
        for state in states:
            install_config(state)
        sudo_run(["systemctl", "daemon-reload"])

        print("\n=== journald capacity run ===")
        journal_result = run_journald_phase(
            args, journal_namespace, batches, machine_id, work_dir)

        print("\n=== recorder capacity run ===")
        recorder_result = run_recorder_phase(
            args, input_namespace, batches, machine_id, recorder_executable,
            player, recorder_config, work_dir)

        print("\nCapacity benchmark result:")
        print(f"  budget: {args.budget / MIB:.2f} MiB")
        print(f"  message size: {args.message_bytes} bytes")
        print("  recorder capture mode: "
              f"{'all supported fields' if args.capture_all_fields else 'default fields'}")
        print(f"  journald generated: {journal_result.generated}")
        print(f"  journald retained: {journal_result.retained.count}")
        print(f"  journald oldest retained sequence: {journal_result.retained.oldest}")
        print(f"  journald usage: {journal_result.usage.logical / MIB:.2f} MiB")
        print(f"  journald budget utilization: "
              f"{journal_result.usage.logical / args.budget * 100:.2f}%")
        print(f"  recorder generated: {recorder_result.generated}")
        print(f"  recorder retained: {recorder_result.retained.count}")
        print(f"  recorder oldest retained sequence: {recorder_result.retained.oldest}")
        print(f"  recorder logical usage: {recorder_result.usage.logical / MIB:.2f} MiB")
        print(f"  recorder physical usage: {recorder_result.usage.physical / MIB:.2f} MiB")
        print(f"  recorder logical budget utilization: "
              f"{recorder_result.usage.logical / args.budget * 100:.2f}%")
        if journal_result.retained.count:
            advantage = recorder_result.retained.count / journal_result.retained.count
            print(f"  recorder retention advantage: {advantage:.2f}x")
        print("  saturation verified by actual eviction in both stores")

        if input("Remove namespace data, configs, and temporary files? [y/N] ").strip().lower() in (
                "y", "yes"):
            for state in states:
                clear_namespace(state.namespace, machine_id)
            restore_all(states)
            shutil.rmtree(work_dir)
        else:
            restore_all(states)
            print(f"Keeping benchmark data and temporary files in {work_dir}")
        return 0
    except (OSError, subprocess.CalledProcessError, RuntimeError,
            KeyboardInterrupt) as error:
        if privileged_started:
            try:
                stop_benchmark_units(args)
                restore_all(states)
            except (OSError, subprocess.CalledProcessError):
                print("warning: failed to restore benchmark configuration",
                      file=sys.stderr)
        print(f"error: capacity benchmark failed: {error}", file=sys.stderr)
        print(f"Temporary files kept in {work_dir}", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 2


def parser() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--namespace", default="recorder-capacity")
    parser.add_argument("--input-namespace",
                        help="separate recorder transport namespace")
    parser.add_argument("--budget", type=parse_size, default=20 * MIB)
    parser.add_argument("--message-bytes", type=int, default=64)
    parser.add_argument("--batch-messages", type=int, default=4096)
    parser.add_argument("--max-batches", type=int, default=1024)
    parser.add_argument("--oversubscribe", type=int, default=4)
    parser.add_argument("--segment-bytes", type=parse_size, default=MIB)
    parser.add_argument("--drain-seconds", type=float, default=0.3)
    parser.add_argument("--drain-timeout", type=float, default=600.0)
    parser.add_argument("--stall-timeout", type=float, default=30.0)
    parser.add_argument("--run-as", default=pwd.getpwuid(os.getuid()).pw_name)
    parser.add_argument("--recorder", default="./recorder")
    parser.add_argument("--player", default="./player")
    parser.add_argument(
        "--capture-all-fields", action="store_true",
        help="store all optional journald metadata fields supported by recorder",
    )
    args = parser.parse_args()
    if not args.run_as:
        parser.error("--run-as must not be empty")
    if args.message_bytes < len(f"{MESSAGE_PREFIX}{0:012d}-"):
        parser.error("--message-bytes is too small for the sequence prefix")
    if (args.batch_messages <= 0 or args.max_batches <= 0 or
            args.oversubscribe <= 1 or
            args.drain_seconds < 0 or args.drain_timeout <= 0 or
            args.stall_timeout <= 0):
        parser.error("invalid benchmark limits")
    if args.segment_bytes >= args.budget:
        parser.error("--segment-bytes must be smaller than --budget")
    namespace_re = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    for option, namespace in (("--namespace", args.namespace),
                              ("--input-namespace", args.input_namespace)):
        if namespace is not None:
            if not namespace_re.fullmatch(namespace):
                parser.error(f"{option} contains unsafe characters")
            if len(namespace) > 120:
                parser.error(f"{option} is too long")
    return args


if __name__ == "__main__":
    raise SystemExit(execute(parser()))
