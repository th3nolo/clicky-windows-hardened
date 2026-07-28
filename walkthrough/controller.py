"""Manual-advance controller for display-only visual walkthroughs."""

from __future__ import annotations

import asyncio
import math
import threading
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Protocol, Sequence

from screen.topology import MonitorDescriptor
from walkthrough.models import (
    ShapeKind,
    StepKind,
    VisualShape,
    VisualTarget,
    Walkthrough,
    WalkthroughStep,
)
from walkthrough.protocol import WalkthroughTargetGuard


class WalkthroughControllerError(RuntimeError):
    pass


class _Timer(Protocol):
    daemon: bool

    def start(self) -> None: ...

    def cancel(self) -> None: ...


@dataclass(frozen=True, slots=True)
class RenderPoint:
    x: float
    y: float
    label: str


@dataclass(frozen=True, slots=True)
class RenderShape:
    kind: ShapeKind
    points: tuple[tuple[float, float], ...]
    color: str
    radius: float | None = None


@dataclass(frozen=True, slots=True)
class RenderPlan:
    point: RenderPoint | None = None
    shapes: tuple[RenderShape, ...] = ()


@dataclass(frozen=True, slots=True)
class WalkthroughProgress:
    walkthrough_id: str
    step_id: str
    current: int
    total: int
    remaining: int
    narration: str
    paused_for_voice: bool
    advancing: bool


@dataclass(frozen=True, slots=True)
class AdvanceResult:
    step: WalkthroughStep | None
    completed: bool
    reason: str


class RejectingTargetGuard:
    """Coordinate-only production default until trusted UIA refs are supplied."""

    def resolve(self, _opaque_reference: str) -> None:
        return None

    def revalidate(self, _target: VisualTarget) -> bool:
        return False


class WalkthroughController:
    """Own exactly one visual session without input or action authority."""

    def __init__(
        self,
        *,
        target_guard: WalkthroughTargetGuard,
        screen_allowed: Callable[[], bool],
        capture_displays: Callable[[], Sequence[MonitorDescriptor]],
        on_render: Callable[[RenderPlan], None],
        on_clear: Callable[[], None],
        on_progress: Callable[[WalkthroughProgress], None],
        on_end: Callable[[str], None],
        capture_runner: Callable[
            [Callable[[], Sequence[MonitorDescriptor]]],
            Awaitable[Sequence[MonitorDescriptor]],
        ] | None = None,
        clock=time.monotonic,
        timer_factory=threading.Timer,
    ) -> None:
        for callback, name in (
            (screen_allowed, "screen permission"),
            (capture_displays, "display capture"),
            (on_render, "render callback"),
            (on_clear, "clear callback"),
            (on_progress, "progress callback"),
            (on_end, "end callback"),
            (
                capture_runner or _capture_in_worker,
                "walkthrough capture runner",
            ),
            (clock, "walkthrough clock"),
            (timer_factory, "walkthrough timer"),
        ):
            if not callable(callback):
                raise TypeError(f"{name} is required")
        if not callable(getattr(target_guard, "revalidate", None)):
            raise TypeError("walkthrough target revalidator is required")
        self._targets = target_guard
        self._screen_allowed = screen_allowed
        self._capture_displays = capture_displays
        self._on_render = on_render
        self._on_clear = on_clear
        self._on_progress = on_progress
        self._on_end = on_end
        self._capture_runner = capture_runner or _capture_in_worker
        self._clock = clock
        self._timer_factory = timer_factory
        self._lock = threading.RLock()
        self._generation = 0
        self._walkthrough: Walkthrough | None = None
        self._topology: tuple[tuple[object, ...], ...] = ()
        self._displays: dict[str, MonitorDescriptor] = {}
        self._index = 0
        self._deadline = 0.0
        self._paused_for_voice = False
        self._advancing = False
        self._timer: _Timer | None = None

    @property
    def active(self) -> bool:
        with self._lock:
            return self._walkthrough is not None

    @property
    def paused_for_voice(self) -> bool:
        with self._lock:
            return self._paused_for_voice

    def start(
        self,
        walkthrough: Walkthrough,
        displays: Sequence[MonitorDescriptor],
    ) -> WalkthroughStep:
        if not isinstance(walkthrough, Walkthrough):
            raise TypeError("validated walkthrough is required")
        topology = _display_map(displays)
        if not self._screen_allowed():
            self.cancel("permission_revoked")
            raise WalkthroughControllerError(
                "screen capture permission is unavailable"
            )
        self.cancel("replaced", notify=False)
        with self._lock:
            self._generation += 1
            self._walkthrough = walkthrough
            self._topology = _topology_signature(topology)
            self._displays = topology
            self._index = 0
            self._paused_for_voice = False
            self._advancing = False
            token = self._generation
        try:
            return self._activate(token)
        except Exception:
            self._end_exact(token, "invalid_first_step")
            raise

    def pause_for_voice(self) -> bool:
        with self._lock:
            if self._walkthrough is None or self._advancing:
                return False
            self._paused_for_voice = True
            progress = self._progress_locked()
        _safe_call(self._on_progress, progress)
        return True

    async def advance(self, *, from_voice: bool = False) -> AdvanceResult:
        with self._lock:
            walkthrough = self._walkthrough
            if walkthrough is None:
                return AdvanceResult(None, False, "inactive")
            if self._advancing:
                return AdvanceResult(None, False, "already_advancing")
            if self._paused_for_voice and not from_voice:
                return AdvanceResult(None, False, "voice_capture_active")
            if self._expired_locked():
                token = self._generation
                should_expire = True
                is_last = False
            else:
                should_expire = False
                token = self._generation
            if should_expire:
                pass
            elif self._index + 1 >= len(walkthrough.steps):
                is_last = True
            else:
                is_last = False
                self._advancing = True
                self._paused_for_voice = False
                self._cancel_timer_locked()
                progress = self._progress_locked()
                next_index = self._index + 1
        if should_expire:
            self._end_exact(token, "expired")
            return AdvanceResult(None, False, "expired")
        if is_last:
            self._end_exact(token, "completed")
            return AdvanceResult(None, True, "completed")

        _safe_call(self._on_progress, progress)
        _safe_call(self._on_clear)
        with self._lock:
            if (
                self._walkthrough is not walkthrough
                or self._generation != token
                or not self._advancing
            ):
                return AdvanceResult(None, False, "stale")
        if not self._screen_allowed():
            self._end_exact(token, "capture_denied")
            return AdvanceResult(None, False, "capture_denied")
        try:
            captured = await self._capture_runner(
                self._capture_displays
            )
            topology = _display_map(captured)
        except Exception:
            self._end_exact(token, "capture_failed")
            return AdvanceResult(None, False, "capture_failed")
        if not self._screen_allowed():
            self._end_exact(token, "permission_revoked")
            return AdvanceResult(None, False, "permission_revoked")

        with self._lock:
            if (
                self._walkthrough is not walkthrough
                or self._generation != token
                or not self._advancing
            ):
                return AdvanceResult(None, False, "stale")
            if _topology_signature(topology) != self._topology:
                hotplugged = True
            else:
                hotplugged = False
                self._displays = topology
                self._index = next_index
                self._advancing = False
        if hotplugged:
            self._end_exact(token, "display_topology_changed")
            return AdvanceResult(None, False, "display_topology_changed")
        try:
            step = self._activate(token)
        except Exception:
            self._end_exact(token, "step_revalidation_failed")
            return AdvanceResult(None, False, "step_revalidation_failed")
        return AdvanceResult(step, False, "advanced")

    def cancel(self, reason: str = "cancelled", *, notify: bool = True) -> bool:
        with self._lock:
            if self._walkthrough is None:
                return False
            self._generation += 1
            self._clear_locked()
        _safe_call(self._on_clear)
        if notify:
            _safe_call(self._on_end, str(reason))
        return True

    def _activate(self, token: int) -> WalkthroughStep:
        with self._lock:
            if (
                self._walkthrough is None
                or self._generation != token
                or self._advancing
            ):
                raise WalkthroughControllerError(
                    "walkthrough activation is stale"
                )
            step = self._walkthrough.steps[self._index]
            plan = self._render_plan_locked(step)
            now = float(self._clock())
            if not math.isfinite(now) or now <= 0:
                raise WalkthroughControllerError(
                    "walkthrough clock is invalid"
                )
            self._deadline = now + step.ttl_seconds
            self._paused_for_voice = False
            self._start_timer_locked(
                token,
                self._index,
                step.ttl_seconds,
            )
            progress = self._progress_locked()
        _safe_call(self._on_clear)
        _safe_call(self._on_render, plan)
        _safe_call(self._on_progress, progress)
        return step

    def _render_plan_locked(self, step: WalkthroughStep) -> RenderPlan:
        target = step.target
        if target is not None:
            display = self._displays.get(target.display_id)
            if display is None or not _target_inside_display(target, display):
                raise WalkthroughControllerError(
                    "walkthrough target display changed"
                )
            if (
                target.expires_at <= float(self._clock())
                or self._targets.revalidate(target) is not True
            ):
                raise WalkthroughControllerError(
                    "walkthrough target is stale"
                )
            center_x = target.logical_left + target.logical_width / 2.0
            center_y = target.logical_top + target.logical_height / 2.0
            point = None
            shapes = ()
            if step.kind in (StepKind.HOVER, StepKind.POINT):
                point = RenderPoint(center_x, center_y, step.label)
            else:
                color = (
                    "yellow"
                    if step.kind is StepKind.HIGHLIGHT
                    else "blue"
                )
                shapes = (
                    RenderShape(
                        ShapeKind.RECTANGLE,
                        (
                            (target.logical_left, target.logical_top),
                            (
                                target.logical_left + target.logical_width,
                                target.logical_top + target.logical_height,
                            ),
                        ),
                        color,
                    ),
                )
            return RenderPlan(point, shapes)

        if step.point is not None:
            display = self._displays.get(step.point.display_id)
            if display is None:
                raise WalkthroughControllerError(
                    "walkthrough display is unavailable"
                )
            x, y = _logical_point(display, step.point.x, step.point.y)
            return RenderPlan(RenderPoint(x, y, step.label))

        display = self._displays.get(step.display_id or "")
        if display is None:
            raise WalkthroughControllerError(
                "walkthrough shape display is unavailable"
            )
        return RenderPlan(
            shapes=tuple(
                _render_shape(shape, display) for shape in step.shapes
            )
        )

    def _start_timer_locked(
        self,
        token: int,
        index: int,
        ttl_seconds: float,
    ) -> None:
        self._cancel_timer_locked()
        timer = self._timer_factory(
            ttl_seconds,
            lambda: self._expire(token, index),
        )
        timer.daemon = True
        self._timer = timer
        timer.start()

    def _cancel_timer_locked(self) -> None:
        timer = self._timer
        self._timer = None
        if timer is not None:
            try:
                timer.cancel()
            except Exception:
                pass

    def _expire(self, token: int, index: int) -> None:
        with self._lock:
            if (
                self._walkthrough is None
                or self._generation != token
                or self._index != index
            ):
                return
        self._end_exact(token, "expired")

    def _end_exact(self, token: int, reason: str) -> bool:
        with self._lock:
            if self._walkthrough is None or self._generation != token:
                return False
            self._generation += 1
            self._clear_locked()
        _safe_call(self._on_clear)
        _safe_call(self._on_end, reason)
        return True

    def _clear_locked(self) -> None:
        self._cancel_timer_locked()
        self._walkthrough = None
        self._topology = ()
        self._displays = {}
        self._index = 0
        self._deadline = 0.0
        self._paused_for_voice = False
        self._advancing = False

    def _expired_locked(self) -> bool:
        now = float(self._clock())
        return (
            not math.isfinite(now)
            or now <= 0
            or now >= self._deadline
        )

    def _progress_locked(self) -> WalkthroughProgress:
        walkthrough = self._walkthrough
        if walkthrough is None:
            raise WalkthroughControllerError("walkthrough is inactive")
        step = walkthrough.steps[self._index]
        current = self._index + 1
        total = len(walkthrough.steps)
        return WalkthroughProgress(
            walkthrough_id=walkthrough.walkthrough_id,
            step_id=step.step_id,
            current=current,
            total=total,
            remaining=total - current,
            narration=step.narration,
            paused_for_voice=self._paused_for_voice,
            advancing=self._advancing,
        )


def _display_map(
    displays: Sequence[MonitorDescriptor],
) -> dict[str, MonitorDescriptor]:
    if not isinstance(displays, (tuple, list)) or not displays:
        raise WalkthroughControllerError("display topology is unavailable")
    result = {}
    for display in displays:
        if not isinstance(display, MonitorDescriptor):
            raise WalkthroughControllerError("display descriptor is invalid")
        if not display.stable_id or display.stable_id in result:
            raise WalkthroughControllerError("display identity is ambiguous")
        result[display.stable_id] = display
    return result


def _topology_signature(
    displays: dict[str, MonitorDescriptor],
) -> tuple[tuple[object, ...], ...]:
    """Capture routing-relevant identity while allowing focus to change."""

    return tuple(
        (
            display.stable_id,
            display.index,
            display.capture_index,
            display.device_name,
            display.physical,
            display.logical,
            display.dpi_x,
            display.dpi_y,
            display.primary,
        )
        for display in sorted(
            displays.values(),
            key=lambda item: item.stable_id,
        )
    )


def _target_inside_display(
    target: VisualTarget,
    display: MonitorDescriptor,
) -> bool:
    bounds = display.logical
    return (
        bounds.contains(target.logical_left, target.logical_top)
        and target.logical_left + target.logical_width <= bounds.right
        and target.logical_top + target.logical_height <= bounds.bottom
    )


def _logical_point(
    display: MonitorDescriptor,
    normalized_x: float,
    normalized_y: float,
) -> tuple[float, float]:
    bounds = display.logical
    x = bounds.left + normalized_x / 1_000.0 * bounds.width
    y = bounds.top + normalized_y / 1_000.0 * bounds.height
    return (
        min(float(bounds.right - 1), max(float(bounds.left), x)),
        min(float(bounds.bottom - 1), max(float(bounds.top), y)),
    )


def _render_shape(
    shape: VisualShape,
    display: MonitorDescriptor,
) -> RenderShape:
    points = tuple(
        _logical_point(display, point[0], point[1])
        for point in shape.points
    )
    radius = None
    if shape.radius is not None:
        radius = (
            shape.radius
            / 1_000.0
            * min(display.logical.width, display.logical.height)
        )
    return RenderShape(
        shape.kind,
        points,
        shape.color.value,
        radius,
    )


def _safe_call(callback, *args) -> None:
    try:
        callback(*args)
    except Exception:
        pass


async def _capture_in_worker(
    callback: Callable[[], Sequence[MonitorDescriptor]],
) -> Sequence[MonitorDescriptor]:
    return await asyncio.to_thread(callback)


__all__ = [
    "AdvanceResult",
    "RejectingTargetGuard",
    "RenderPlan",
    "RenderPoint",
    "RenderShape",
    "WalkthroughController",
    "WalkthroughControllerError",
    "WalkthroughProgress",
]
