"""Reviewed local adapters for exact, transient region image construction."""

from __future__ import annotations

import base64
import hashlib
import io
import secrets
import time
from collections.abc import Callable, Sequence
from typing import Protocol

from handoff.models import (
    MAX_REGION_EDGE_PIXELS,
    HandoffSelectionError,
    PhysicalRegion,
    topology_digest,
)
from handoff.selection import (
    BuiltSelectionImage,
    LassoPoint,
    RegionCaptureBundle,
    TransientMonitorFrame,
)


CAPTURE_LIFETIME_SECONDS = 60.0


class CapturedScreen(Protocol):
    width: int
    height: int
    physical_width: int
    physical_height: int
    base64_jpeg: str

    def descriptor(self): ...


CaptureProvider = Callable[[int], Sequence[CapturedScreen]]


def capture_desktop_bundle(
    *,
    owned_window_regions: tuple[PhysicalRegion, ...] = (),
    clock: Callable[[], float] = time.monotonic,
    generation: str | None = None,
    capture_provider: CaptureProvider | None = None,
) -> RegionCaptureBundle:
    """Capture exact full-resolution frames behind the owned-window guard."""

    if not callable(clock):
        raise TypeError("Capture clock is invalid")
    if capture_provider is None:
        from screen.capture import capture_all_screens

        capture_provider = capture_all_screens
    if not callable(capture_provider):
        raise TypeError("Screen capture provider is invalid")
    captured_at = float(clock())
    capture_generation = (
        generation
        if generation is not None
        else f"capture-{secrets.token_hex(16)}"
    )
    frames: list[TransientMonitorFrame] = []
    try:
        screens = tuple(
            capture_provider(MAX_REGION_EDGE_PIXELS)
        )
        if not screens:
            raise HandoffSelectionError(
                "No screen capture was returned"
            )
        for screen in screens:
            if (
                type(screen.width) is not int
                or type(screen.height) is not int
                or screen.width != screen.physical_width
                or screen.height != screen.physical_height
            ):
                raise HandoffSelectionError(
                    "Screen capture was resized before selection"
                )
            try:
                encoded = screen.base64_jpeg.encode("ascii")
                jpeg = bytearray(
                    base64.b64decode(encoded, validate=True)
                )
            except Exception as exc:
                raise HandoffSelectionError(
                    "Screen capture payload is invalid"
                ) from exc
            try:
                frame = TransientMonitorFrame(
                    monitor=screen.descriptor(),
                    jpeg_bytes=jpeg,
                )
            except Exception:
                jpeg[:] = b"\x00" * len(jpeg)
                raise
            frames.append(frame)
        descriptors = tuple(frame.monitor for frame in frames)
        return RegionCaptureBundle(
            generation=capture_generation,
            captured_at=captured_at,
            expires_at=captured_at + CAPTURE_LIFETIME_SECONDS,
            topology_sha256=topology_digest(descriptors),
            frames=tuple(frames),
            owned_window_regions=owned_window_regions,
        )
    except Exception:
        for frame in frames:
            frame.wipe()
        raise


def build_selected_image(
    frame: TransientMonitorFrame,
    region: PhysicalRegion,
    lasso_points: tuple[LassoPoint, ...] | None,
) -> BuiltSelectionImage:
    """Crop exact pixels and optionally apply one reviewed freehand mask."""

    if not isinstance(frame, TransientMonitorFrame):
        raise TypeError("Monitor frame is invalid")
    if not isinstance(region, PhysicalRegion):
        raise TypeError("Selected region is invalid")
    if not region.inside(frame.monitor.physical):
        raise HandoffSelectionError(
            "Selected region is outside the captured monitor"
        )
    from PIL import Image, ImageDraw

    try:
        with Image.open(io.BytesIO(frame.jpeg_bytes)) as source:
            source.load()
            if source.size != (
                frame.monitor.physical.width,
                frame.monitor.physical.height,
            ):
                raise HandoffSelectionError(
                    "Captured pixels no longer match the monitor"
                )
            relative_left = (
                region.left - frame.monitor.physical.left
            )
            relative_top = (
                region.top - frame.monitor.physical.top
            )
            image = source.crop(
                (
                    relative_left,
                    relative_top,
                    relative_left + region.width,
                    relative_top + region.height,
                )
            ).convert("RGB")
    except HandoffSelectionError:
        raise
    except Exception as exc:
        raise HandoffSelectionError(
            "Selected image could not be decoded"
        ) from exc

    mask_sha256: str | None = None
    if lasso_points is not None:
        if (
            not isinstance(lasso_points, tuple)
            or len(lasso_points) < 4
            or any(
                not isinstance(point, LassoPoint)
                for point in lasso_points
            )
        ):
            raise HandoffSelectionError(
                "Freehand mask points are invalid"
            )
        polygon = [
            (
                point.x - region.left,
                point.y - region.top,
            )
            for point in lasso_points
        ]
        if any(
            x < 0
            or y < 0
            or x > region.width
            or y > region.height
            for x, y in polygon
        ):
            raise HandoffSelectionError(
                "Freehand mask leaves the selected region"
            )
        mask = Image.new("L", image.size, 0)
        ImageDraw.Draw(mask).polygon(polygon, fill=255)
        mask_bytes = mask.tobytes()
        mask_sha256 = hashlib.sha256(mask_bytes).hexdigest()
        background = Image.new("RGB", image.size, (16, 24, 39))
        image = Image.composite(image, background, mask)

    output = io.BytesIO()
    image.save(
        output,
        format="JPEG",
        quality=90,
        optimize=True,
    )
    return BuiltSelectionImage(
        content=bytearray(output.getvalue()),
        media_type="image/jpeg",
        mask_sha256=mask_sha256,
    )


__all__ = [
    "CAPTURE_LIFETIME_SECONDS",
    "build_selected_image",
    "capture_desktop_bundle",
]
