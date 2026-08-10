#!/usr/bin/env python3
"""Test simulated low-space reclamation for higher-priority writes."""

import json
import os
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def run_one(recorder: Path, config: Path, socket_path: Path, log_dir: Path,
            priority: int, message: str) -> str:
    process = subprocess.Popen(
        [str(recorder), "-v", "--fallback", "--syslog-socket", str(socket_path),
         "--no-kmsg", "--log-dir", str(log_dir)],
        env={**os.environ, "RECORDER_CONFIG": str(config)},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(100):
            if socket_path.exists():
                break
            if process.poll() is not None:
                _, stderr = process.communicate()
                raise RuntimeError(
                    f"recorder exited early: {process.returncode}: "
                    f"{stderr.decode(errors='replace')}"
                )
            time.sleep(0.02)
        else:
            raise RuntimeError("recorder did not create the syslog socket")
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
            client.sendto(f"<{priority}>storage-test: {message}".encode(),
                          str(socket_path))
        time.sleep(0.2)
        process.send_signal(signal.SIGTERM)
        _, stderr = process.communicate(timeout=10)
    except Exception:
        process.kill()
        process.wait()
        raise
    if process.returncode != 0:
        raise RuntimeError(stderr.decode(errors="replace"))
    return stderr.decode(errors="replace")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    recorder = (root / "recorder").resolve()
    with tempfile.TemporaryDirectory(prefix="recorder-storage-policy-") as tmp:
        base = Path(tmp)
        config = base / "recorder.json"
        socket_path = base / "dev-log"
        log_dir = base / "store"
        config.write_text(json.dumps({
            "log_max_bytes": 0,
            "min_free_bytes": 1,
            "segment_max_bytes": 1024 * 1024,
            "priority_groups": [
                {"name": "high", "priorities": [0]},
                {"name": "low", "priorities": [1, 2, 3, 4, 5, 6, 7]},
            ],
        }), encoding="utf-8")

        run_one(recorder, config, socket_path, log_dir, 15, "low")
        low_segments = list((log_dir / "low").glob("*.seg"))
        if len(low_segments) != 1:
            raise RuntimeError(f"expected one low-priority segment, found {low_segments}")

        stderr = run_one(recorder, config, socket_path, log_dir, 0, "high")
        if list((log_dir / "low").glob("*.seg")):
            raise RuntimeError("low-priority segment was not reclaimed")
        if len(list((log_dir / "high").glob("*.seg"))) != 1:
            raise RuntimeError("high-priority segment was not written")
        if "retention removed segment" not in stderr:
            raise RuntimeError(f"reclamation diagnostic missing: {stderr!r}")
    print("storage policy integration ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
