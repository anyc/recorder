#!/usr/bin/env python3
"""Prepare and run controlled journald/recorder storage benchmarks."""

import argparse
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


MIB = 1024**2
NAMESPACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


@dataclass
class Usage:
    logical: int = 0
    physical: int = 0


@dataclass
class ConfigState:
    system_path: Path
    persistent_path: Path
    original: bytes | None
    backup_path: Path | None
    changed: bool = False


def parse_size(value: str) -> int:
    units = {"K": 1024, "M": MIB, "G": 1024**3, "T": 1024**4}
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
             **kwargs: object) -> subprocess.CompletedProcess:
    return run(["sudo", *command], check=check, **kwargs)


def usage(path: Path, sudo: bool = False) -> Usage:
    prefix = ["sudo"] if sudo else []
    logical = run(
        [*prefix, "du", "-B1", "--apparent-size", "-s", str(path)],
        stdout=subprocess.PIPE, text=True,
    )
    physical = run(
        [*prefix, "du", "-B1", "-s", str(path)],
        stdout=subprocess.PIPE, text=True,
    )
    return Usage(int(logical.stdout.split()[0]),
                 int(physical.stdout.split()[0]))


def file_bytes(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def stream_count(command: list[str]) -> int:
    print("$ " + command_text(command))
    with tempfile.TemporaryFile() as error_output:
        process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=error_output)
        count = 0
        assert process.stdout is not None
        for line in process.stdout:
            if line.strip():
                count += 1
        returncode = process.wait()
        error_output.seek(0)
        stderr = error_output.read()
    if returncode != 0:
        raise RuntimeError(
            f"command failed with status {returncode}: {command_text(command)}\n"
            f"{stderr.decode(errors='replace').strip()}"
        )
    return count


def journal_count_command(namespace: str, unit: str | None = None) -> list[str]:
    command = ["sudo", "journalctl", "--namespace", namespace]
    if unit:
        command.extend(["--unit", unit])
    command.extend(["--output=json", "--no-pager", "--quiet"])
    return command


def journal_entry_count(namespace: str, unit: str | None = None) -> int:
    return stream_count(journal_count_command(namespace, unit))


def parse_header_usage(output: str) -> int:
    total = 0
    pattern = re.compile(
        r"^Disk usage: ([0-9]+(?:\.[0-9]+)?)\s*([KMGTEP]?)B?$"
    )
    for line in output.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        exponent = " KMGTEP".find(match.group(2))
        total += int(float(match.group(1)) * 1024**max(exponent, 0))
    if total == 0:
        raise RuntimeError("journalctl reported no journal data usage")
    return total


def journal_header_command(namespace: str) -> list[str]:
    return ["sudo", "journalctl", "--namespace", namespace, "--header"]


def extent_scan_command(helper: Path, journal_path: Path) -> list[str]:
    return ["sudo", "/usr/bin/python3", str(helper), str(journal_path)]


def journal_usage_details(namespace: str, journal_path: Path,
                          extent_helper: Path) -> tuple[int, int]:
    header = run(journal_header_command(namespace), stdout=subprocess.PIPE,
                 text=True, env={**os.environ, "LC_ALL": "C"})
    header_usage = parse_header_usage(header.stdout)
    extent = run(extent_scan_command(extent_helper, journal_path),
                 stdout=subprocess.PIPE, text=True)
    try:
        nonzero_extent = int(extent.stdout.strip())
    except ValueError as error:
        raise RuntimeError("cannot parse journal nonzero extent") from error
    return header_usage, nonzero_extent


def journal_export_command(namespace: str, unit: str) -> list[str]:
    return ["sudo", "journalctl", "--namespace", namespace, "--unit", unit,
            "--output=export", "--no-pager", "--quiet"]


def journal_export_size(namespace: str, unit: str) -> int:
    command = journal_export_command(namespace, unit)
    print("$ " + command_text(command))
    with tempfile.TemporaryFile() as error_output:
        process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                   stderr=error_output)
        total = 0
        assert process.stdout is not None
        while True:
            chunk = process.stdout.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
        returncode = process.wait()
        error_output.seek(0)
        stderr = error_output.read()
    if returncode != 0:
        raise RuntimeError(
            f"journal export failed with status {returncode}: "
            f"{stderr.decode(errors='replace').strip()}"
        )
    return total


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
    for command in namespace_stop_commands(namespace):
        sudo_run(command, check=False, stdout=subprocess.DEVNULL,
                 stderr=subprocess.DEVNULL)


def clear_namespace(namespace: str, machine_id: str) -> None:
    stop_namespace(namespace)
    for path in namespace_paths(namespace, machine_id):
        sudo_run(["rm", "-rf", "--", str(path)])


def replay_command(input_path: Path, helper: Path, namespace: str, unit: str,
                   run_as: str | None, use_sudo: bool) -> list[str]:
    command = (["sudo"] if use_sudo else []) + [
        "systemd-run", "--quiet", "--wait", "--collect", f"--unit={unit}",
        f"--property=LogNamespace={namespace}",
        "--property=LogRateLimitIntervalSec=0",
        "--property=LogRateLimitBurst=0",
    ]
    if run_as:
        command.append(f"--property=User={run_as}")
    command.extend(["/usr/bin/python3", str(helper),
                    str(input_path.resolve())])
    return command


def run_replay(input_path: Path, helper: Path, namespace: str, unit: str,
               run_as: str | None = None, use_sudo: bool = True) -> None:
    run(replay_command(input_path, helper, namespace, unit, run_as, use_sudo))


def generated_journald_config(storage: str, max_use: int) -> str:
    return (
        "[Journal]\n"
        f"Storage={storage}\n"
        "Compress=yes\n"
        "Seal=no\n"
        "RateLimitIntervalSec=0\n"
        "LineMax=8M\n"
        "SystemKeepFree=0\n"
        "RuntimeKeepFree=0\n"
        f"SystemMaxUse={max_use}\n"
        f"RuntimeMaxUse={max_use}\n"
        "MaxRetentionSec=0\n"
    )


def write_recorder_config(path: Path,
                          capture_all_fields: bool = False) -> None:
    capture = "true" if capture_all_fields else "false"
    path.write_text(
        "{\n"
        '  "log_max_bytes": 0,\n'
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


def make_config_state(system_path: Path, persistent_path: Path,
                      work_dir: Path) -> ConfigState:
    original = system_path.read_bytes() if system_path.exists() else None
    backup = None
    if original is not None and original != persistent_path.read_bytes():
        backup = work_dir / f"{system_path.name}.original"
        backup.write_bytes(original)
    return ConfigState(system_path, persistent_path, original, backup)


def install_config(state: ConfigState, desired_path: Path) -> None:
    desired = desired_path.read_bytes()
    if not state.changed and state.original == desired:
        print(f"Namespace configuration already matches: {state.system_path}")
        return
    sudo_run(["install", "-m", "0644", str(desired_path),
              str(state.system_path)])
    state.changed = True


def restore_config(state: ConfigState) -> None:
    if not state.changed:
        return
    if state.original is None:
        sudo_run(["rm", "-f", "--", str(state.system_path)], check=False)
        return
    source = state.backup_path or state.persistent_path
    if source.read_bytes() != state.original:
        raise RuntimeError(f"missing valid backup for {state.system_path}")
    sudo_run(["install", "-m", "0644", str(source),
              str(state.system_path)], check=False)


def write_helpers(work_dir: Path) -> tuple[Path, Path]:
    replay_helper = work_dir / "replay.py"
    replay_helper.write_text(
        "import pathlib, sys\n"
        "with pathlib.Path(sys.argv[1]).open(encoding='utf-8', "
        "errors='replace') as source:\n"
        "    for line in source:\n"
        "        sys.stdout.write(line if line.endswith('\\n') else line + '\\n')\n"
        "sys.stdout.flush()\n",
        encoding="utf-8",
    )
    extent_helper = work_dir / "journal_extent.py"
    extent_helper.write_text(
        "import pathlib, sys\n"
        "total = 0\n"
        "for path in pathlib.Path(sys.argv[1]).rglob('*.journal*'):\n"
        "    if not path.is_file():\n"
        "        continue\n"
        "    end = path.stat().st_size\n"
        "    used = 0\n"
        "    with path.open('rb') as source:\n"
        "        while end:\n"
        "            size = min(1024 * 1024, end)\n"
        "            end -= size\n"
        "            source.seek(end)\n"
        "            block = source.read(size)\n"
        "            index = len(block) - 1\n"
        "            while index >= 0 and block[index] == 0:\n"
        "                index -= 1\n"
        "            if index >= 0:\n"
        "                used = end + index + 1\n"
        "                break\n"
        "    total += used\n"
        "print(total)\n",
        encoding="utf-8",
    )
    return replay_helper, extent_helper


def journal_tail_cursor_command(namespace: str) -> list[str]:
    return ["sudo", "journalctl", "--namespace", namespace, "-n", "1",
            "--show-cursor", "--no-pager", "--quiet"]


def journal_tail_cursor(namespace: str) -> str:
    result = run(journal_tail_cursor_command(namespace),
                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                 text=True, quiet=True)
    match = re.search(r"^-- cursor: (.+)$", result.stdout, re.MULTILINE)
    if not match:
        raise RuntimeError("cannot determine namespace journal tail cursor")
    return match.group(1).strip()


def journal_cursor_after(namespace: str, cursor: str) -> str:
    command = ["sudo", "journalctl", "--namespace", namespace,
               "--after-cursor", cursor, "-n", "1", "--show-cursor",
               "--no-pager", "--quiet"]
    result = run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                 text=True, quiet=True)
    match = re.search(r"^-- cursor: (.+)$", result.stdout, re.MULTILINE)
    return match.group(1).strip() if match else ""


def journal_has_entries_after_cursor(namespace: str, cursor: str) -> bool:
    next_cursor = journal_cursor_after(namespace, cursor)
    return bool(next_cursor and next_cursor != cursor)


def read_cursor(path: Path) -> str:
    try:
        return path.read_bytes().split(b"\0", 1)[0].decode().strip()
    except FileNotFoundError:
        return ""


def wait_for_cursor(args: argparse.Namespace, namespace: str,
                    cursor_path: Path) -> None:
    deadline = time.monotonic() + args.drain_timeout
    last_cursor = ""
    last_progress = time.monotonic()
    last_report = 0.0
    print("Waiting for recorder to reach the namespace-journal tail...")
    while time.monotonic() < deadline:
        cursor = read_cursor(cursor_path)
        now = time.monotonic()
        if cursor and cursor != last_cursor:
            last_cursor = cursor
            last_progress = now
        if cursor and not journal_has_entries_after_cursor(namespace, cursor):
            print("Recorder reached the namespace-journal tail.")
            return
        if now - last_report >= 5:
            print(f"  recorder is draining (last progress "
                  f"{now - last_progress:.1f}s ago)...")
            last_report = now
        if now - last_progress > args.stall_timeout:
            raise RuntimeError(
                f"recorder cursor made no progress for "
                f"{args.stall_timeout:.0f}s"
            )
        time.sleep(1)
    raise RuntimeError(
        f"recorder did not drain within {args.drain_timeout:.0f}s"
    )


def player_count(player: str, recorder_dir: Path, unit: str) -> int:
    return stream_count([player, "-D", str(recorder_dir), "-u", unit])


def percentage(difference: int, baseline: int) -> float:
    return difference / baseline * 100 if baseline else 0.0


def print_sudo_plan(
        args: argparse.Namespace, state: ConfigState, persistent_path: Path,
        volatile_path: Path, replay_helper: Path, extent_helper: Path,
        input_path: Path, recorder_config: Path, recorder_executable: str,
        recorder_dir: Path, machine_id: str, executing_user: str,
        journal_unit: str, recorder_unit: str, recorder_service: str,
        replay_a: str, replay_b: str) -> None:
    journal_path = namespace_paths(args.namespace, machine_id)[0]

    def show(command: list[str]) -> None:
        print("  $ " + command_text(command))

    print("\nThe following privileged commands may be executed:")
    if state.original != persistent_path.read_bytes():
        show(["sudo", "install", "-m", "0644", str(persistent_path),
              str(state.system_path)])
    show(["sudo", "systemctl", "daemon-reload"])

    print("  # persistent journald phase")
    for command in namespace_stop_commands(args.namespace):
        show(["sudo", *command])
    for path in namespace_paths(args.namespace, machine_id):
        show(["sudo", "rm", "-rf", "--", str(path)])
    show(replay_command(input_path, replay_helper, args.namespace, replay_a,
                        executing_user, True))
    show(["sudo", "journalctl", "--namespace", args.namespace, "--sync"])
    show(journal_count_command(args.namespace))
    show(journal_count_command(args.namespace, journal_unit))
    show(journal_header_command(args.namespace))
    show(extent_scan_command(extent_helper, journal_path))
    show(journal_export_command(args.namespace, journal_unit))
    show(["sudo", "du", "-B1", "--apparent-size", "-s", str(journal_path)])
    show(["sudo", "du", "-B1", "-s", str(journal_path)])

    print("  # volatile recorder-input phase")
    show(["sudo", "install", "-m", "0644", str(volatile_path),
          str(state.system_path)])
    for command in namespace_stop_commands(args.namespace):
        show(["sudo", *command])
    for path in namespace_paths(args.namespace, machine_id):
        show(["sudo", "rm", "-rf", "--", str(path)])
    show(replay_command(input_path, replay_helper, args.namespace, replay_b,
                        executing_user, True))
    show(["sudo", "journalctl", "--namespace", args.namespace, "--sync"])
    show(journal_count_command(args.namespace, recorder_unit))
    show(["sudo", "systemd-run", "--quiet",
          f"--unit={recorder_service.removesuffix('.service')}", "--collect",
          f"--property=User={executing_user}",
          "--property=SupplementaryGroups=systemd-journal",
          f"--property=Environment=RECORDER_CONFIG={recorder_config}",
          recorder_executable, "--namespace", args.namespace,
          "--log-dir", str(recorder_dir), "--cursor",
          str(recorder_dir / "state" / "journal.cursor.live")])
    show(["sudo", "systemctl", "is-active", recorder_service])
    show(journal_tail_cursor_command(args.namespace))
    show(["sudo", "systemctl", "stop", recorder_service])

    print("  # conditional diagnostics, interruption handling, and cleanup")
    show(["sudo", "journalctl", "-u", recorder_service,
          "--no-pager", "-n", "100"])
    for unit in (recorder_service, replay_a + ".service",
                 replay_b + ".service"):
        show(["sudo", "systemctl", "stop", unit])
    for command in namespace_stop_commands(args.namespace):
        show(["sudo", *command])
    for path in namespace_paths(args.namespace, machine_id):
        show(["sudo", "rm", "-rf", "--", str(path)])
    if state.original is None:
        show(["sudo", "rm", "-f", "--", str(state.system_path)])
    else:
        source = state.backup_path or state.persistent_path
        show(["sudo", "install", "-m", "0644", str(source),
              str(state.system_path)])
    show(["sudo", "systemctl", "daemon-reload"])


def restore_all(state: ConfigState, namespace: str) -> None:
    stop_namespace(namespace)
    restore_config(state)
    sudo_run(["systemctl", "daemon-reload"], check=False)


def stop_benchmark_units(recorder_service: str,
                         replay_units: tuple[str, str]) -> None:
    for unit in (recorder_service, *(name + ".service" for name in replay_units)):
        sudo_run(["systemctl", "stop", unit], check=False)


def interactive(args: argparse.Namespace) -> int:
    recorder_executable = shutil.which(args.recorder)
    player = shutil.which(args.player)
    if not recorder_executable or not player:
        print("error: recorder and player executables must be available",
              file=sys.stderr)
        return 2
    recorder_executable = str(Path(recorder_executable).resolve())
    player = str(Path(player).resolve())

    executing_user = pwd.getpwuid(os.getuid()).pw_name
    machine_id = Path("/etc/machine-id").read_text(encoding="ascii").strip()
    work_dir = Path(tempfile.mkdtemp(prefix="recorder-benchmark-"))
    input_path = work_dir / "input.log"
    recorder_dir = work_dir / "recorder"
    recorder_config = work_dir / "recorder.json"
    persistent_path = work_dir / f"journald@{args.namespace}.persistent.conf"
    volatile_path = work_dir / f"journald@{args.namespace}.volatile.conf"
    system_path = Path(f"/etc/systemd/journald@{args.namespace}.conf")
    replay_helper, extent_helper = write_helpers(work_dir)
    persistent_path.write_text(
        generated_journald_config("persistent", args.max_use),
        encoding="utf-8",
    )
    volatile_path.write_text(
        generated_journald_config("volatile", args.max_use),
        encoding="utf-8",
    )
    write_recorder_config(recorder_config, args.capture_all_fields)
    state = make_config_state(system_path, persistent_path, work_dir)
    pid = os.getpid()
    replay_a = f"{args.namespace}-replay-a-{pid}"
    replay_b = f"{args.namespace}-replay-b-{pid}"
    journal_unit = replay_a + ".service"
    recorder_unit = replay_b + ".service"
    recorder_service = f"{args.namespace}-recorder-{pid}.service"
    privileged_started = False

    try:
        print(f"Benchmark files: {work_dir}")
        existing_data = any(
            path.exists() for path in namespace_paths(args.namespace, machine_id)
        )
        if existing_data:
            answer = input(
                f"Namespace {args.namespace} already has journal data. "
                "Delete it for a fresh benchmark? [y/N] "
            )
            if answer.strip().lower() not in ("y", "yes"):
                shutil.rmtree(work_dir)
                print("Benchmark cancelled; namespace data was preserved.")
                return 1

        capture_args = argparse.Namespace(
            output=str(input_path), since=args.since, until=args.until,
            namespace=args.source_namespace,
        )
        if capture(capture_args) != 0:
            raise RuntimeError("log capture failed")
        input_messages = count_file_lines(input_path)
        if input_messages == 0:
            raise RuntimeError("captured workload contains no messages")

        print_sudo_plan(
            args, state, persistent_path, volatile_path, replay_helper,
            extent_helper, input_path, recorder_config, recorder_executable,
            recorder_dir, machine_id, executing_user, journal_unit,
            recorder_unit, recorder_service, replay_a, replay_b,
        )
        answer = input(
            "This benchmark will execute the commands above. Continue? [y/N] "
        )
        if answer.strip().lower() not in ("y", "yes"):
            shutil.rmtree(work_dir)
            print("Benchmark cancelled.")
            return 1

        privileged_started = True
        install_config(state, persistent_path)
        sudo_run(["systemctl", "daemon-reload"])

        print("\n=== persistent journald phase ===")
        clear_namespace(args.namespace, machine_id)
        run_replay(input_path, replay_helper, args.namespace, replay_a,
                   executing_user)
        sudo_run(["journalctl", "--namespace", args.namespace, "--sync"])
        journal_entries = journal_entry_count(args.namespace)
        journal_replayed = journal_entry_count(args.namespace, journal_unit)
        if journal_replayed != input_messages:
            raise RuntimeError(
                "journald replay was incomplete: "
                f"input={input_messages}, retained={journal_replayed}"
            )
        journal_path = namespace_paths(args.namespace, machine_id)[0]
        header_bytes, nonzero_bytes = journal_usage_details(
            args.namespace, journal_path, extent_helper)
        export_bytes = journal_export_size(args.namespace, journal_unit)
        journal_disk = usage(journal_path, sudo=True)

        print("\n=== volatile recorder-input phase ===")
        install_config(state, volatile_path)
        clear_namespace(args.namespace, machine_id)
        run_replay(input_path, replay_helper, args.namespace, replay_b,
                   executing_user)
        sudo_run(["journalctl", "--namespace", args.namespace, "--sync"])
        recorder_input = journal_entry_count(args.namespace, recorder_unit)
        if recorder_input != input_messages:
            raise RuntimeError(
                "recorder input journal was incomplete: "
                f"input={input_messages}, retained={recorder_input}"
            )

        recorder_dir.mkdir()
        live_cursor = recorder_dir / "state" / "journal.cursor.live"
        start_command = [
            "systemd-run", "--quiet",
            f"--unit={recorder_service.removesuffix('.service')}", "--collect",
            f"--property=User={executing_user}",
            "--property=SupplementaryGroups=systemd-journal",
            f"--property=Environment=RECORDER_CONFIG={recorder_config}",
            recorder_executable, "--namespace", args.namespace,
            "--log-dir", str(recorder_dir), "--cursor", str(live_cursor),
        ]
        try:
            sudo_run(start_command)
            sudo_run(["systemctl", "is-active", recorder_service])
            wait_for_cursor(args, args.namespace, live_cursor)
            time.sleep(args.drain_seconds)
        except (OSError, subprocess.CalledProcessError, RuntimeError):
            sudo_run(["journalctl", "-u", recorder_service,
                      "--no-pager", "-n", "100"], check=False)
            raise
        finally:
            sudo_run(["systemctl", "stop", recorder_service], check=False)

        segment_files = list(recorder_dir.rglob("*.seg"))
        if not segment_files:
            sudo_run(["journalctl", "-u", recorder_service,
                      "--no-pager", "-n", "100"], check=False)
            raise RuntimeError("recorder produced no segment files")
        recorder_replayed = player_count(player, recorder_dir, recorder_unit)
        if recorder_replayed != input_messages:
            sudo_run(["journalctl", "-u", recorder_service,
                      "--no-pager", "-n", "100"], check=False)
            raise RuntimeError(
                "recorder output was incomplete: "
                f"input={input_messages}, readable={recorder_replayed}"
            )
        recorder_disk = usage(recorder_dir)
        recorder_file_bytes = file_bytes(recorder_dir)

        print("\nBenchmark result:")
        print(f"  input bytes: {input_path.stat().st_size}")
        print(f"  input messages: {input_messages}")
        print(f"  journald replayed messages: {journal_replayed}")
        print(f"  recorder replayed messages: {recorder_replayed}")
        print(f"  journald namespace entries: {journal_entries}")
        print(f"  journald export size: {export_bytes / 1024:.2f} KiB")
        print(f"  journald apparent size: {journal_disk.logical / 1024:.2f} KiB")
        print(f"  journald physical allocation: "
              f"{journal_disk.physical / 1024:.2f} KiB")
        print(f"  journald header-reported usage: {header_bytes / 1024:.2f} KiB")
        print(f"  journald nonzero-data extent upper bound: "
              f"{nonzero_bytes / 1024:.2f} KiB")
        print(f"  recorder apparent size: {recorder_disk.logical / 1024:.2f} KiB")
        print(f"  recorder stored-file bytes: {recorder_file_bytes / 1024:.2f} KiB")
        print("  recorder capture mode: "
              f"{'all supported fields' if args.capture_all_fields else 'default fields'}")
        print(f"  recorder physical allocation: "
              f"{recorder_disk.physical / 1024:.2f} KiB")

        physical_saved = journal_disk.physical - recorder_disk.physical
        if physical_saved >= 0:
            print(f"  physical space saved by recorder: "
                  f"{physical_saved / 1024:.2f} KiB "
                  f"({percentage(physical_saved, journal_disk.physical):.2f}%)")
        else:
            print(f"  extra physical space used by recorder: "
                  f"{-physical_saved / 1024:.2f} KiB")

        extent_saved = nonzero_bytes - recorder_file_bytes
        if extent_saved >= 0:
            print(f"  nonzero-extent upper-bound reduction: "
                  f"{extent_saved / 1024:.2f} KiB "
                  f"({percentage(extent_saved, nonzero_bytes):.2f}%)")
        else:
            print(f"  recorder stored-file excess versus nonzero extent: "
                  f"{-extent_saved / 1024:.2f} KiB")

        remove = input(
            "Remove namespace data and temporary files? [y/N] "
        ).strip().lower() in ("y", "yes")
        if remove:
            clear_namespace(args.namespace, machine_id)
        restore_all(state, args.namespace)
        if remove:
            shutil.rmtree(work_dir)
        else:
            print(f"Keeping benchmark files in {work_dir}")
        return 0
    except (EOFError, OSError, subprocess.CalledProcessError, RuntimeError,
            KeyboardInterrupt) as error:
        if privileged_started:
            try:
                stop_benchmark_units(recorder_service, (replay_a, replay_b))
                restore_all(state, args.namespace)
            except (OSError, subprocess.CalledProcessError, RuntimeError):
                print("warning: failed to restore namespace configuration",
                      file=sys.stderr)
        print(f"error: benchmark failed: {error}", file=sys.stderr)
        print(f"Temporary files kept in {work_dir}", file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 2


def count_file_lines(path: Path) -> int:
    with path.open(encoding="utf-8", errors="replace") as source:
        return sum(1 for _ in source)


def write_config(args: argparse.Namespace) -> int:
    output = Path(args.output)
    output.write_text(
        generated_journald_config(args.storage, args.max_use),
        encoding="utf-8",
    )
    print(f"Wrote {output}")
    print("\nCopy it to the namespace configuration location:")
    print("  " + command_text([
        "sudo", "install", "-m", "0644", str(output),
        f"/etc/systemd/journald@{args.namespace}.conf",
    ]))
    print("Then reload the manager and restart the namespace before measuring:")
    print("  sudo systemctl daemon-reload")
    print(f"  sudo systemctl restart "
          f"systemd-journald@{args.namespace}.service")
    return 0


def capture(args: argparse.Namespace) -> int:
    command = [
        "journalctl", "--no-pager", "--quiet", "--output=cat",
        "--truncate-newline", "--since", args.since,
    ]
    if args.until:
        command.extend(["--until", args.until])
    if args.namespace:
        command.extend(["--namespace", args.namespace])
    print(f"Capturing logs to {args.output}")
    with Path(args.output).open("w", encoding="utf-8") as output:
        result = subprocess.run(command, stdout=output, check=False)
    if result.returncode != 0:
        return result.returncode
    count = count_file_lines(Path(args.output))
    print(f"Captured {count} log messages")
    return 0


def replay(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    helper_dir = Path(tempfile.mkdtemp(prefix="recorder-replay-"))
    try:
        helper_dir.chmod(0o755)
        helper, _ = write_helpers(helper_dir)
        command = replay_command(
            input_path, helper, args.namespace, args.unit, args.run_as,
            not args.no_sudo,
        )
        return run(command, check=False).returncode
    finally:
        shutil.rmtree(helper_dir)


def validate_name(parser: argparse.ArgumentParser, option: str,
                  value: str | None) -> None:
    if value is None:
        return
    if not NAMESPACE_RE.fullmatch(value):
        parser.error(f"{option} contains unsafe characters")
    if len(value) > 120:
        parser.error(f"{option} is too long")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)

    config = subparsers.add_parser("config", help="write a namespace config")
    config.add_argument("--namespace", default="recorder-bench")
    config.add_argument("--output", default="journald@recorder-bench.conf")
    config.add_argument("--storage", choices=("persistent", "volatile"),
                        default="persistent")
    config.add_argument("--max-use", type=parse_size, default=4 * 1024**3)
    config.set_defaults(function=write_config)

    capture_parser = subparsers.add_parser(
        "capture", help="save real logs as a replayable workload")
    capture_parser.add_argument("--output", required=True)
    capture_parser.add_argument("--since", default="1 day ago")
    capture_parser.add_argument("--until")
    capture_parser.add_argument("--namespace")
    capture_parser.set_defaults(function=capture)

    replay_parser = subparsers.add_parser(
        "replay", help="replay a saved workload into a namespace")
    replay_parser.add_argument("--input", required=True)
    replay_parser.add_argument("--namespace", default="recorder-bench")
    replay_parser.add_argument("--unit", default="recorder-benchmark-replay")
    replay_parser.add_argument(
        "--run-as", help="run replay as this unprivileged user")
    replay_parser.add_argument("--no-sudo", action="store_true")
    replay_parser.set_defaults(function=replay)

    interactive_parser = subparsers.add_parser(
        "interactive", help="run both benchmark phases interactively")
    interactive_parser.add_argument("--namespace", default="recorder-bench")
    interactive_parser.add_argument("--since", default="1 day ago")
    interactive_parser.add_argument("--until")
    interactive_parser.add_argument("--source-namespace")
    interactive_parser.add_argument("--max-use", type=parse_size,
                                    default=4 * 1024**3)
    interactive_parser.add_argument("--recorder", default="./recorder")
    interactive_parser.add_argument("--player", default="./player")
    interactive_parser.add_argument(
        "--capture-all-fields", action="store_true",
        help="store all optional journald metadata fields supported by recorder",
    )
    interactive_parser.add_argument("--drain-seconds", type=float, default=0.3)
    interactive_parser.add_argument("--drain-timeout", type=float,
                                    default=600.0)
    interactive_parser.add_argument("--stall-timeout", type=float,
                                    default=30.0)
    interactive_parser.set_defaults(function=interactive)
    return result


def main() -> int:
    argument_parser = parser()
    args = argument_parser.parse_args()
    for option, value in (
        ("--namespace", getattr(args, "namespace", None)),
        ("--source-namespace", getattr(args, "source_namespace", None)),
        ("--unit", getattr(args, "unit", None)),
    ):
        validate_name(argument_parser, option, value)
    if getattr(args, "drain_seconds", 0) < 0:
        argument_parser.error("--drain-seconds must not be negative")
    if getattr(args, "drain_timeout", 1) <= 0:
        argument_parser.error("--drain-timeout must be greater than zero")
    if getattr(args, "stall_timeout", 1) <= 0:
        argument_parser.error("--stall-timeout must be greater than zero")
    try:
        return args.function(args)
    except (OSError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
