"""Small, provider-neutral selection of visual context for one Tutor turn.

This module deliberately decides *which already-captured bytes* belong on a
request.  It neither captures the desktop nor serializes a provider payload.
Keeping that decision separate lets request telemetry report the selected media
without retaining the images themselves.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Literal, Sequence


MAX_TEMPORAL_FRAMES = 4
MediaMode = Literal["static", "temporal", "motion"]


@dataclass(frozen=True, slots=True)
class MediaContext:
    """The non-overlapping visual context selected for a Tutor request.

    ``screenshots_b64`` may contain the focused screen or a caller supplied
    relevant crop.  ``timeline_frames`` are timestamped history images.  A
    motion request uses video and omits extracted timeline frames, preventing
    the same recorded interval from being attached twice.
    """

    mode: MediaMode
    screenshots_b64: tuple[str, ...]
    timeline_frames: tuple[tuple[float, str], ...]
    include_video: bool

    def __post_init__(self) -> None:
        if self.mode not in {"static", "temporal", "motion"}:
            raise ValueError("Unknown media context mode")
        if self.include_video != (self.mode == "motion"):
            raise ValueError("Media mode and video selection disagree")
        if self.mode == "temporal" and self.screenshots_b64:
            raise ValueError("Temporal context must not duplicate current screenshots")
        if self.include_video and self.timeline_frames:
            raise ValueError("Video context must not also attach extracted frames")
        if len(self.timeline_frames) > MAX_TEMPORAL_FRAMES:
            raise ValueError("Too many selected temporal frames")


_MOTION_RE = re.compile(
    r"\b(?:animation|animated|cursor\s+(?:movement|moving|path)|"
    r"drag(?:ging)?|motion|mov(?:ement|ing)|playback|scroll(?:ing|ed)?|"
    r"movimiento|movi[eé]ndose|arrastr(?:ar|ando)|desplaz(?:ar|ando))\b",
    re.IGNORECASE,
)
_TEMPORAL_RE = re.compile(
    r"\b(?:before|after|again|changed?|earlier|first|happened|"
    r"later|previous|sequence|then|timeline|where did|"
    r"what\s+did\s+i\s+do|what\s+was\s+i\s+doing|"
    r"walk\s+me\s+through\s+what\s+i\s+did|how\s+did\s+i\s+get\s+here|"
    r"antes|despu[eé]s|cambi[oó]|primero|luego|qu[eé]\s+hice|"
    r"qu[eé]\s+estaba\s+haciendo)\b",
    re.IGNORECASE,
)
_VIDEO_WITH_ACTION_RE = re.compile(
    r"\bvideo\b.*\b(?:do(?:es|esn't| did)?|happen(?:ed|s)?|"
    r"show(?:s|ed)?|move(?:d|s)?|play(?:ed|s)?)\b",
    re.IGNORECASE,
)
_VIDEO_METADATA_RE = re.compile(
    r"\b(?:title|name|caption|author|channel|duration|length)\b",
    re.IGNORECASE,
)


def build_media_context(
    transcript: str,
    *,
    current_screenshots_b64: Sequence[str] = (),
    active_screenshot_b64: str | None = None,
    relevant_crop_b64: str | None = None,
    timeline_frames: Sequence[tuple[float, str]] = (),
    video_available: bool,
) -> MediaContext:
    """Select static, temporal, or explicit-motion visual evidence.

    Ambiguous sequence language retains a bounded, ordered set of frames.  A
    bare reference to a video's title or other metadata is static; it does not
    justify uploading the complete recording.  The active screen is the
    relevant desktop crop unless a page/crop source is explicitly available.
    This is an intentionally bounded lexical heuristic, rather than a claim
    that every teaching or recall request can be inferred from transcript text.
    """

    if not isinstance(transcript, str):
        raise TypeError("Transcript must be text")
    current = _clean_images(current_screenshots_b64)
    focused = _single_image(relevant_crop_b64) or _single_image(active_screenshot_b64)
    static_image = focused or (current[0] if current else None)
    temporal = _bounded_ordered_frames(timeline_frames)
    text = transcript.strip()

    explicit_motion = bool(_MOTION_RE.search(text)) or bool(
        _VIDEO_WITH_ACTION_RE.search(text) and not _VIDEO_METADATA_RE.search(text)
    )
    temporal_request = bool(_TEMPORAL_RE.search(text))

    if explicit_motion and video_available:
        # A current focused screen remains useful for coordinate-aware answers;
        # the extracted frame samples are deliberately omitted.
        return MediaContext("motion", (static_image,) if static_image else (), (), True)
    if (temporal_request or explicit_motion) and temporal:
        return MediaContext("temporal", (), temporal, False)
    return MediaContext("static", (static_image,) if static_image else (), (), False)


def _clean_images(images: Sequence[str]) -> tuple[str, ...]:
    return tuple(image for image in images if isinstance(image, str) and image)


def _single_image(image: str | None) -> str | None:
    return image if isinstance(image, str) and image else None


def _bounded_ordered_frames(
    frames: Sequence[tuple[float, str]],
) -> tuple[tuple[float, str], ...]:
    valid: list[tuple[float, str]] = []
    previous = -1.0
    for frame in frames:
        if not isinstance(frame, tuple) or len(frame) != 2:
            continue
        seconds, image = frame
        if (
            type(seconds) not in (int, float)
            or not math.isfinite(float(seconds))
            or not 0 <= float(seconds)
            or float(seconds) < previous
            or not isinstance(image, str)
            or not image
        ):
            continue
        previous = float(seconds)
        valid.append((float(seconds), image))
    if len(valid) <= MAX_TEMPORAL_FRAMES:
        return tuple(valid)
    return tuple(
        valid[round(index * (len(valid) - 1) / (MAX_TEMPORAL_FRAMES - 1))]
        for index in range(MAX_TEMPORAL_FRAMES)
    )


__all__ = ["MAX_TEMPORAL_FRAMES", "MediaContext", "build_media_context"]
