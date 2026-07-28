"""Trusted synthetic process tree used only by Windows Job Object tests."""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path


def main() -> int:
    if len(sys.argv) < 2:
        return 2
    mode = sys.argv[1]
    if mode == "child" and len(sys.argv) == 2:
        time.sleep(30)
        return 0
    if mode != "parent" or len(sys.argv) != 4:
        return 2
    marker = Path(sys.argv[2])
    child_pid = Path(sys.argv[3])
    deadline = time.monotonic() + 10
    while not marker.exists():
        if time.monotonic() >= deadline:
            return 3
        time.sleep(0.02)
    child = subprocess.Popen(
        [
            getattr(sys, "_base_executable", sys.executable),
            str(Path(__file__)),
            "child",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    child_pid.write_text(str(child.pid), encoding="ascii")
    time.sleep(30)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
