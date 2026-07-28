"""Single-request trusted UIA worker entered before normal app imports."""

from __future__ import annotations

import os
import sys

from automation.action_protocol import (
    MAX_WORKER_FRAME_BYTES,
    decode_worker_command,
    encode_worker_receipt,
)
from automation.uia_actions import execute_windows_uia_action


def run_worker() -> int:
    if (
        os.name != "nt"
        or os.environ.get("CLICKY_DESKTOP_UIA_WORKER") != "1"
    ):
        return 2
    try:
        frame = sys.stdin.buffer.readline(MAX_WORKER_FRAME_BYTES + 1)
        if (
            not frame
            or len(frame) > MAX_WORKER_FRAME_BYTES
            or sys.stdin.buffer.read(1) != b""
        ):
            return 2
        command = decode_worker_command(frame)
        receipt = execute_windows_uia_action(
            command.target,
            command.request,
        )
        response = encode_worker_receipt(
            nonce=command.nonce,
            authentication_key=command.authentication_key,
            receipt=receipt,
        )
        sys.stdout.buffer.write(response)
        sys.stdout.buffer.flush()
        return 0
    except (BrokenPipeError, OSError, TypeError, ValueError):
        return 2


__all__ = ["run_worker"]
