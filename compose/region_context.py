"""One-use adapter from a reviewed region route to Compose screenshots."""

from __future__ import annotations

import base64
import hashlib
import math
import threading
import time
from collections.abc import Callable, Sequence

from compose.models import ComposeScreenshot
from handoff.models import HandoffDestination
from handoff.routing import HandoffRouteContext


class ComposeRegionContextError(RuntimeError):
    """Reviewed region context could not enter a Compose request safely."""


class ReviewedRegionCaptureGateway:
    """Consume one exact reviewed JPEG without recapturing the desktop."""

    def __init__(
        self,
        context: HandoffRouteContext,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            not isinstance(context, HandoffRouteContext)
            or context.destination
            is not HandoffDestination.COMPOSE_PREVIEW
        ):
            if isinstance(context, HandoffRouteContext):
                context.wipe()
            raise TypeError("Compose region context is invalid")
        if not callable(clock):
            context.wipe()
            raise TypeError("Compose region clock is invalid")
        self._context = context
        self._clock = clock
        self._lock = threading.Lock()
        self._consumed = False

    def capture(
        self,
        authorized_screenshot_ids: tuple[str, ...],
    ) -> Sequence[ComposeScreenshot]:
        context = self._context
        with self._lock:
            if self._consumed:
                raise ComposeRegionContextError(
                    "Reviewed region context was already consumed"
                )
            self._consumed = True
        try:
            if authorized_screenshot_ids != (context.selection_id,):
                raise ComposeRegionContextError(
                    "Compose requested a different region"
                )
            now = float(self._clock())
            if (
                not math.isfinite(now)
                or now < 0
                or now >= context.expires_at
            ):
                raise ComposeRegionContextError(
                    "Reviewed region context expired"
                )
            if (
                context.media_type != "image/jpeg"
                or hashlib.sha256(context.image_content).hexdigest()
                != context.image_sha256
            ):
                raise ComposeRegionContextError(
                    "Reviewed region context changed"
                )
            screenshot = ComposeScreenshot(
                screenshot_id=context.selection_id,
                label="Reviewed screen region",
                width=context.width,
                height=context.height,
                base64_jpeg=base64.b64encode(
                    context.image_content
                ).decode("ascii"),
            )
            return (screenshot,)
        except ComposeRegionContextError:
            raise
        except Exception:
            raise ComposeRegionContextError(
                "Reviewed region context is not valid Compose input"
            ) from None
        finally:
            context.wipe()


__all__ = [
    "ComposeRegionContextError",
    "ReviewedRegionCaptureGateway",
]
