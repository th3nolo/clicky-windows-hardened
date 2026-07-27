"""Enable process-wide per-monitor-v2 DPI awareness before QApplication."""

from __future__ import annotations

import ctypes
import sys


def enable_per_monitor_v2() -> None:
    if sys.platform != "win32":
        return
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    set_context = getattr(user32, "SetProcessDpiAwarenessContext", None)
    if set_context is not None:
        set_context.argtypes = [ctypes.c_void_p]
        set_context.restype = ctypes.c_bool
        # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 == (HANDLE)-4.
        if set_context(ctypes.c_void_p(-4)):
            return
        error = ctypes.get_last_error()
        # ERROR_ACCESS_DENIED means a manifest or host already fixed awareness.
        if error == 5:
            return
    try:
        shcore = ctypes.WinDLL("shcore", use_last_error=True)
        set_awareness = shcore.SetProcessDpiAwareness
        set_awareness.argtypes = [ctypes.c_int]
        set_awareness.restype = ctypes.c_long
        result = set_awareness(2)  # PROCESS_PER_MONITOR_DPI_AWARE
        if result in (0, -2147024891):  # S_OK or E_ACCESSDENIED/already set
            return
    except (AttributeError, OSError):
        pass
    raise RuntimeError("Windows per-monitor DPI awareness could not be enabled")
