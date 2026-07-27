"""
Hybrid pointer — Clicky pointing accuracy upgrade.

The original grid-locator was inaccurate because it asked the LLM to guess
pixel coordinates from a numbered grid overlay. Vision models trained on
natural images don't have pixel-precise spatial reasoning, so they'd often
pick a neighboring cell or off-by-one row, sending Clicky's blue cursor to
the wrong button.

This module uses a three-tier resolver, each tier much more accurate than the next:

  Tier 1  Windows UI Automation (UIA)     ~5 ms     pixel-perfect
          Walks the OS accessibility tree, finds elements by name/role.
          Works in every standard UI: Chrome/Edge/Firefox, VS Code, IDEs,
          Office, Electron apps, native Win32, WinUI/UWP, Settings, etc.

  Tier 2  Offline OCR (RapidOCR/ONNX)     ~300 ms   text-perfect
          For canvas apps where UIA gives no tree: Figma, Photoshop, games,
          older Java/Swing UIs. Runs entirely on CPU, no API calls.

  Tier 3  Vision LLM grid fallback        ~1-3 s    best effort
          Only used when UIA + OCR both whiff. Delegates to the existing
          element_locator.py — kept as a safety net.

Public API:
    find_target(query: str) -> Optional[Target]

The caller (companion_manager) treats Target as opaque — it has .center_xy
in LOGICAL screen pixels, ready to feed directly into the overlay pointer.
"""

from __future__ import annotations

import asyncio
import base64
import io
import logging
import re
from dataclasses import dataclass
from typing import Any, Coroutine, Optional, List, Tuple

log = logging.getLogger("clicky.pointer")


@dataclass
class Target:
    """A pointing target with exact pixel coordinates in LOGICAL screen space."""
    x: int                # center X
    y: int                # center Y
    bbox: Tuple[int, int, int, int]   # (left, top, right, bottom)
    label: str            # what we matched (button text, control type, etc.)
    source: str           # "uia" | "ocr" | "vision"
    confidence: float     # 0.0–1.0

    @property
    def center_xy(self) -> Tuple[int, int]:
        return (self.x, self.y)


# ──────────────────────────────────────────────────────────────────────────────
#  TIER 1 — Windows UI Automation
# ──────────────────────────────────────────────────────────────────────────────

_INTERACTIVE_TYPES = {
    # Most reliable click targets in UIA
    "Button", "Hyperlink", "MenuItem", "TabItem", "TreeItem", "ListItem",
    "RadioButton", "CheckBox", "ComboBox", "Edit", "Text",
    "Custom",  # often used by Electron / web apps
}


def _normalize(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def _score_match(query: str, element_name: str, element_type: str) -> float:
    """Fuzzy match score 0..1. Boosts:
      - exact substring match in the element name
      - interactive control types
      - whole-word match
    """
    q = _normalize(query)
    name = _normalize(element_name)
    if not q or not name:
        return 0.0
    score = 0.0
    if q == name:
        score = 1.0
    elif q in name:
        score = 0.85
    else:
        # Word overlap
        q_words = set(q.split())
        n_words = set(name.split())
        if q_words and n_words:
            overlap = len(q_words & n_words) / max(len(q_words), 1)
            score = overlap * 0.7
    if element_type in _INTERACTIVE_TYPES:
        score = min(1.0, score + 0.1)
    return score


def _find_via_uia(query: str, min_score: float = 0.5) -> Optional[Target]:
    """Walk the UIA tree for the foreground window + descendants, find best match."""
    try:
        import uiautomation as auto
    except ImportError:
        log.warning("uiautomation not installed — Tier 1 (UIA) disabled")
        return None

    try:
        # Get the focused (foreground) window — pointing is almost always
        # for the active app, and walking the whole desktop is slow.
        root = auto.GetForegroundControl()
        if root is None:
            root = auto.GetRootControl()
    except Exception as e:
        log.debug("UIA root lookup failed: %s", e)
        return None

    best: Optional[Tuple[float, "auto.Control"]] = None
    # Bounded walk — UIA trees can be huge in Chrome/Electron
    queue: List[Tuple["auto.Control", int]] = [(root, 0)]
    visited = 0
    MAX_NODES = 3500
    MAX_DEPTH = 40

    while queue and visited < MAX_NODES:
        node, depth = queue.pop(0)
        visited += 1
        try:
            name = node.Name or ""
            ctrl_type = node.ControlTypeName or ""
            rect = node.BoundingRectangle  # mss/uia returns Rect
        except Exception:
            continue
        # Skip off-screen / zero-size
        if not rect or rect.width() <= 0 or rect.height() <= 0:
            pass
        else:
            score = _score_match(query, name, ctrl_type)
            # Also try AutomationId and HelpText as backup match sources
            if score < 0.85:
                try:
                    aid = getattr(node, "AutomationId", "") or ""
                    if aid:
                        score = max(score, _score_match(query, aid, ctrl_type) * 0.8)
                except Exception:
                    pass
            if score >= min_score and (best is None or score > best[0]):
                best = (score, node)

        if depth < MAX_DEPTH:
            try:
                for child in node.GetChildren():
                    queue.append((child, depth + 1))
            except Exception:
                continue

    if not best:
        log.debug("UIA found no matching target (scanned %d nodes)", visited)
        return None

    score, node = best
    r = node.BoundingRectangle
    cx = int((r.left + r.right) // 2)
    cy = int((r.top + r.bottom) // 2)
    log.info("UIA target accepted (score=%.2f)", score)
    return Target(
        x=cx, y=cy,
        bbox=(int(r.left), int(r.top), int(r.right), int(r.bottom)),
        label=node.Name or node.ControlTypeName,
        source="uia",
        confidence=score,
    )


# ──────────────────────────────────────────────────────────────────────────────
#  TIER 2 — Offline OCR (RapidOCR, ONNX)
# ──────────────────────────────────────────────────────────────────────────────

_ocr_engine = None


def _get_ocr():
    global _ocr_engine
    if _ocr_engine is None:
        try:
            from rapidocr_onnxruntime import RapidOCR
            _ocr_engine = RapidOCR()
        except ImportError:
            log.warning("rapidocr-onnxruntime not installed — Tier 2 (OCR) disabled")
            return None
        except Exception as e:
            log.warning("OCR engine init failed: %s", e)
            return None
    return _ocr_engine


def _find_via_ocr(query: str, screenshot_path: Optional[str] = None,
                  pil_image=None, min_score: float = 0.5) -> Optional[Target]:
    """Run OCR only on an explicitly supplied image."""
    ocr = _get_ocr()
    if ocr is None:
        return None

    try:
        if pil_image is None and screenshot_path is None:
            return None

        import numpy as np
        if pil_image is not None:
            img_arr = np.array(pil_image)
        else:
            img_arr = screenshot_path  # RapidOCR accepts paths directly

        result, _ = ocr(img_arr)
        if not result:
            log.debug("OCR returned no detections")
            return None

        best: Optional[Tuple[float, dict]] = None
        for det in result:
            # RapidOCR format: [bbox(4 corners), text, score]
            try:
                box, text, conf = det
            except Exception:
                continue
            if conf < 0.4:
                continue
            score = _score_match(query, text, "")
            if score >= min_score and (best is None or score > best[0]):
                # Compute bbox from 4 corners
                xs = [int(p[0]) for p in box]
                ys = [int(p[1]) for p in box]
                best = (score, {
                    "text": text,
                    "bbox": (min(xs), min(ys), max(xs), max(ys)),
                    "conf": conf,
                })

        if not best:
            log.debug("OCR found no matching target")
            return None

        score, hit = best
        l, t, r, b = hit["bbox"]
        cx, cy = (l + r) // 2, (t + b) // 2
        log.info("OCR target accepted (score=%.2f)", score)
        return Target(
            x=cx, y=cy, bbox=hit["bbox"],
            label=hit["text"], source="ocr",
            confidence=score * hit["conf"],
        )
    except Exception as e:
        log.warning("OCR tier failed: %s", e)
        return None


# ──────────────────────────────────────────────────────────────────────────────
#  TIER 3 — Vision LLM grid fallback (delegated to existing element_locator)
# ──────────────────────────────────────────────────────────────────────────────


class _ActiveEventLoopError(RuntimeError):
    """Raised when the synchronous Tier 3 API would block an event loop."""


def _run_locator(coroutine: Coroutine[Any, Any, Any]) -> Any:
    """Run the async locator while preserving this module's synchronous API.

    find_target normally runs outside an asyncio loop. A synchronous call from
    a running event loop cannot wait for Tier 3 without freezing that loop, so
    fail immediately instead of hiding the block in a helper thread.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)

    # The coroutine has already been constructed by the caller. Close it
    # before rejecting the unsupported boundary so Python does not later emit
    # an "unawaited coroutine" warning.
    coroutine.close()
    raise _ActiveEventLoopError(
        "Tier 3's synchronous locator cannot run inside an active asyncio "
        "event loop; use a non-loop worker or keep skip_vision=True"
    )


def _find_via_vision(query: str, screenshot, llm_provider) -> Optional[Target]:
    """Last-resort: use the Anthropic Computer Use element locator."""
    try:
        from ai.element_locator import detect_element
    except ImportError:
        log.warning("element_locator not available — Tier 3 (vision) disabled")
        return None

    try:
        detected = _run_locator(detect_element(
            screenshot_jpeg_b64=screenshot.base64_jpeg,
            original_width=screenshot.width,
            original_height=screenshot.height,
            physical_width=screenshot.physical_width,
            physical_height=screenshot.physical_height,
            physical_left=screenshot.physical_left,
            physical_top=screenshot.physical_top,
            dpi_scale=screenshot.dpi_scale,
            screen_index=screenshot.index,
            user_question=query,
        ))
        if not detected:
            return None
        x, y = detected.x, detected.y
        return Target(
            x=x, y=y, bbox=(x - 20, y - 20, x + 20, y + 20),
            label=query, source="vision",
            confidence=0.5,   # vision is least trustworthy
        )
    except _ActiveEventLoopError:
        raise
    except Exception as e:
        log.warning("Vision tier failed: %s", e)
        return None


# ──────────────────────────────────────────────────────────────────────────────
#  PUBLIC API
# ──────────────────────────────────────────────────────────────────────────────

def find_target(
    query: str,
    *,
    screenshot=None,
    pil_image=None,
    llm_provider=None,
    skip_uia: bool = False,
    skip_ocr: bool = False,
    skip_vision: bool = False,
) -> Optional[Target]:
    """Resolve a natural-language pointing query into pixel coordinates.

    Tries UIA → OCR → Vision in order. Returns the first hit with confidence
    >= the tier's threshold. Returns None if all three tiers whiff.

    Args:
        query:        what the user asked Clicky to point at (e.g. "save button",
                      "send icon", "login text field").
        screenshot:   ScreenShot object (from screen.capture) — used by vision tier.
        pil_image:    PIL.Image of the full screen — used by OCR tier. Optional;
                      OCR will capture its own if not provided.
        llm_provider: BaseLLMProvider instance — needed only for vision fallback.
        skip_*:       Force-skip a tier (for testing or perf-sensitive paths).

    Returns:
        Target with .center_xy in logical screen pixels, or None.
    """
    if not query or not query.strip():
        return None

    def uia_to_logical(target):
        if screenshot is None:
            return None
        descriptor = screenshot.descriptor()
        if not descriptor.physical.contains(target.x, target.y):
            return None
        def map_x(value):
            ratio = (
                value - descriptor.physical.left
            ) / max(descriptor.physical.width, 1)
            return descriptor.logical.left + ratio * descriptor.logical.width

        def map_y(value):
            ratio = (
                value - descriptor.physical.top
            ) / max(descriptor.physical.height, 1)
            return descriptor.logical.top + ratio * descriptor.logical.height

        center = descriptor.physical_to_logical(target.x, target.y)
        return Target(
            x=int(round(center[0])),
            y=int(round(center[1])),
            bbox=(
                int(round(map_x(target.bbox[0]))),
                int(round(map_y(target.bbox[1]))),
                int(round(map_x(target.bbox[2]))),
                int(round(map_y(target.bbox[3]))),
            ),
            label=target.label,
            source=target.source,
            confidence=target.confidence,
        )

    def image_to_logical(target, image):
        descriptor = screenshot.descriptor()
        width, height = image.size
        left, top, right, bottom = target.bbox
        map_x = lambda value: (
            descriptor.logical.left
            + value / max(width, 1) * descriptor.logical.width
        )
        map_y = lambda value: (
            descriptor.logical.top
            + value / max(height, 1) * descriptor.logical.height
        )
        return Target(
            x=int(round(map_x(target.x))),
            y=int(round(map_y(target.y))),
            bbox=(
                int(round(map_x(left))),
                int(round(map_y(top))),
                int(round(map_x(right))),
                int(round(map_y(bottom))),
            ),
            label=target.label,
            source=target.source,
            confidence=target.confidence,
        )

    # Tier 1: UIA — fast, free, often perfect
    if not skip_uia and screenshot is not None:
        t = _find_via_uia(query)
        if t is not None and t.confidence >= 0.5:
            converted = uia_to_logical(t)
            if converted is not None:
                return converted

    # Tier 2: OCR — text-based fallback for canvas apps
    if not skip_ocr and screenshot is not None:
        if pil_image is None:
            from PIL import Image

            image_bytes = base64.b64decode(screenshot.base64_jpeg, validate=True)
            pil_image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        t = _find_via_ocr(query, pil_image=pil_image)
        if t is not None and t.confidence >= 0.5:
            return image_to_logical(t, pil_image)

    # Tier 3: vision LLM grid — last resort
    if not skip_vision and screenshot is not None and llm_provider is not None:
        t = _find_via_vision(query, screenshot, llm_provider)
        if t is not None:
            return t

    log.info("All pointer tiers failed to resolve a target")
    return None


__all__ = ["Target", "find_target"]
