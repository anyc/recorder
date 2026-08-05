#!/usr/bin/env python3
"""End-to-end test for recorder's direct syslog fallback source."""

import argparse
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def wait_for_socket(path: Path, process: subprocess.Popen[bytes]) -> None:
    for _ in range(100):
        if path.exists():
            return
        if process.poll() is not None:
            raise RuntimeError(f"recorder exited early with status {process.returncode}")
        time.sleep(0.02)
    raise RuntimeError(f"recorder did not create {path}")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recorder", type=Path, default=root / "recorder")
    parser.add_argument("--player", type=Path, default=root / "player")
    args = parser.parse_args()
    recorder = args.recorder.resolve()
    player = args.player.resolve()

    message = "recorder fallback integration message"
    with tempfile.TemporaryDirectory(prefix="recorder-fallback-") as tmp:
        base = Path(tmp)
        socket_path = base / "dev-log"
        log_dir = base / "store"
        process = subprocess.Popen(
            [
                str(recorder),
                "--fallback",
                "--syslog-socket",
                str(socket_path),
                "--no-kmsg",
                "--log-dir",
                str(log_dir),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            wait_for_socket(socket_path, process)
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
                client.sendto(f"<11>fallback-test: {message}".encode(), str(socket_path))
            time.sleep(0.2)
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=10)
        except Exception:
            process.kill()
            process.wait()
            raise

        if process.returncode != 0:
            raise RuntimeError(stderr.decode(errors="replace"))
        if socket_path.exists():
            raise RuntimeError("recorder did not remove its syslog socket")
        segments = list(log_dir.rglob("*.seg"))
        if len(segments) != 1:
            raise RuntimeError(f"expected one stored segment, found {len(segments)}")
        output = subprocess.check_output([str(player), "-i", str(segments[0])], text=True)
        if message not in output:
            raise RuntimeError(f"fallback entry is missing from player output: {output!r}")
    print("fallback integration ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
