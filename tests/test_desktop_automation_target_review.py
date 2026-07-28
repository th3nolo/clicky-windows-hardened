from __future__ import annotations

import hashlib
import inspect
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from automation.models import (
    AutomationPattern,
    DesktopActionKind,
    DesktopBounds,
    DesktopTarget,
)
from automation.policy import DesktopPolicyReason
from automation.review import (
    DesktopReviewStatus,
    DesktopTargetReviewController,
)
from automation.stop import (
    AutomationStopController,
    GlobalAutomationStopHotkey,
)
from automation.targeting import (
    DesktopObservation,
    DesktopTargetGuard,
    WindowsDesktopTargetInspector,
)


ROOT = Path(__file__).resolve().parents[1]
APP_IDENTITY = hashlib.sha256(b"synthetic-app").hexdigest()


def target(**overrides: object) -> DesktopTarget:
    values: dict[str, object] = {
        "process_id": 42,
        "process_start_time_ns": 123_456_789,
        "application_name": "Synthetic editor",
        "application_identity": APP_IDENTITY,
        "top_level_hwnd": 100,
        "foreground_hwnd": 100,
        "runtime_id": (42, 7, 3),
        "control_type": "ButtonControl",
        "framework_id": "Win32",
        "automation_id": "save-button",
        "control_name": "Save",
        "bounds": DesktopBounds(-1800, 100, 160, 40),
        "supported_patterns": frozenset({AutomationPattern.INVOKE}),
        "enabled": True,
        "offscreen": False,
        "control_element": True,
        "password": False,
        "protected": False,
        "clicky_process_id": 99,
        "clicky_integrity": 0x2000,
        "target_integrity": 0x2000,
        "desktop_name": "Default",
    }
    values.update(overrides)
    return DesktopTarget(**values)  # type: ignore[arg-type]


def observation(
    current: DesktopTarget | None = None,
    *,
    hints: tuple[str, ...] = ("Save", "Synthetic editor"),
) -> DesktopObservation:
    return DesktopObservation(current or target(), hints)


class FakeInspector:
    def __init__(self, current: DesktopObservation | Exception) -> None:
        self.current = current
        self.calls = 0

    def observe(self) -> DesktopObservation:
        self.calls += 1
        if isinstance(self.current, Exception):
            raise self.current
        return self.current


class FakeHighlighter:
    def __init__(self) -> None:
        self.requests = []
        self.cleared = []
        self.failure: Exception | None = None
        self.on_show = None

    def show(self, request) -> None:
        self.requests.append(request)
        if self.on_show is not None:
            self.on_show()
        if self.failure is not None:
            raise self.failure

    def clear(self, review_id: str) -> None:
        self.cleared.append(review_id)

    def is_active(self, review_id: str) -> bool:
        return bool(
            self.requests
            and self.requests[-1].review_id == review_id
            and review_id not in self.cleared
        )


class MutableClock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


class DesktopTargetGuardTests(unittest.TestCase):
    def test_capture_and_exact_revalidation_are_read_only(self):
        inspector = FakeInspector(observation())
        guard = DesktopTargetGuard(inspector)

        captured = guard.capture(DesktopActionKind.INVOKE)
        self.assertTrue(captured.allowed)
        assert captured.lease is not None
        current = guard.revalidate(
            captured.lease,
            action=DesktopActionKind.INVOKE,
        )

        self.assertTrue(current.allowed)
        self.assertEqual(inspector.calls, 2)

    def test_inspector_error_or_wrong_return_is_unavailable(self):
        for current in (RuntimeError("synthetic"), object()):
            with self.subTest(current_type=type(current).__name__):
                inspector = FakeInspector(current)  # type: ignore[arg-type]
                decision = DesktopTargetGuard(inspector).capture(
                    DesktopActionKind.INVOKE
                )
                self.assertFalse(decision.allowed)
                self.assertEqual(
                    decision.reason,
                    DesktopPolicyReason.INSPECTOR_ERROR,
                )

    def test_changed_target_and_sensitive_label_fail_revalidation(self):
        inspector = FakeInspector(observation())
        guard = DesktopTargetGuard(inspector)
        first = guard.capture(DesktopActionKind.INVOKE)
        assert first.lease is not None

        inspector.current = observation(
            target(runtime_id=(42, 7, 4)),
        )
        self.assertEqual(
            guard.revalidate(
                first.lease,
                action=DesktopActionKind.INVOKE,
            ).reason,
            DesktopPolicyReason.IDENTITY_CHANGED,
        )
        inspector.current = observation(hints=("Place order",))
        self.assertEqual(
            guard.revalidate(
                first.lease,
                action=DesktopActionKind.INVOKE,
            ).reason,
            DesktopPolicyReason.PAYMENT_OR_PURCHASE,
        )

    def test_observation_repr_never_contains_raw_hints(self):
        current = observation(hints=("Synthetic private label",))
        self.assertNotIn("Synthetic private label", repr(current))

    def test_windows_inspector_source_has_no_action_or_value_read(self):
        source = inspect.getsource(WindowsDesktopTargetInspector)

        self.assertNotIn(".Value", source)
        self.assertNotIn("CurrentValue", source)
        self.assertNotIn("Invoke()", source)
        self.assertNotIn("Select()", source)
        self.assertNotIn("Toggle()", source)
        self.assertNotIn("SetFocus()", source)
        self.assertNotIn("SetValue", source)
        self.assertIn("GetValuePattern", source)


class AutomationStopControllerTests(unittest.TestCase):
    def test_stop_invalidates_before_all_cancellations(self):
        controller = AutomationStopController()
        lease = controller.begin("run-one")
        observations = []

        controller.bind_cancel(
            lease,
            "a",
            lambda: observations.append(controller.active),
        )
        controller.bind_cancel(
            lease,
            "b",
            lambda: observations.append(controller.active),
        )

        self.assertTrue(controller.stop())
        self.assertEqual(observations, [None, None])
        self.assertFalse(controller.stop())
        self.assertFalse(controller.is_active(lease))

    def test_replacement_and_stale_binding_cancel_without_queue_execution(self):
        controller = AutomationStopController()
        first = controller.begin("run-one")
        cancelled = []
        controller.bind_cancel(first, "worker", lambda: cancelled.append("old"))

        second = controller.begin("run-two")
        self.assertEqual(cancelled, ["old"])
        self.assertFalse(controller.is_active(first))
        self.assertTrue(controller.is_active(second))

        late = []
        self.assertFalse(
            controller.bind_cancel(
                first,
                "late",
                lambda: late.append("cancelled"),
            )
        )
        executed, value = controller.run_if_active(
            first,
            lambda: "must-not-run",
        )
        self.assertFalse(executed)
        self.assertIsNone(value)
        self.assertEqual(late, ["cancelled"])

    def test_guarded_step_and_stop_are_serialized(self):
        controller = AutomationStopController()
        lease = controller.begin("run-one")
        entered = threading.Event()
        release = threading.Event()
        events = []

        def step():
            entered.set()
            release.wait(timeout=2)
            events.append("step")

        worker = threading.Thread(
            target=lambda: controller.run_if_active(lease, step)
        )
        worker.start()
        self.assertTrue(entered.wait(timeout=2))
        stopper = threading.Thread(
            target=lambda: events.append(
                "stopped" if controller.stop() else "idle"
            )
        )
        stopper.start()
        self.assertNotIn("stopped", events)
        release.set()
        worker.join(timeout=2)
        stopper.join(timeout=2)

        self.assertEqual(events, ["step", "stopped"])
        self.assertFalse(controller.is_active(lease))

    def test_callback_failure_does_not_skip_later_cancellation(self):
        controller = AutomationStopController()
        lease = controller.begin("run-one")
        called = []

        def fail():
            raise RuntimeError("synthetic")

        controller.bind_cancel(lease, "a", fail)
        controller.bind_cancel(lease, "b", lambda: called.append("b"))
        controller.stop()
        self.assertEqual(called, ["b"])

    def test_hotkey_is_non_suppressing_and_removes_only_its_handle(self):
        controller = AutomationStopController()
        lease = controller.begin("run-one")
        fake_keyboard = SimpleNamespace()
        registrations = []
        removals = []

        def add_hotkey(key, callback, **options):
            registrations.append((key, callback, options))
            return "automation-hotkey-handle"

        fake_keyboard.add_hotkey = add_hotkey
        fake_keyboard.remove_hotkey = removals.append
        with mock.patch.dict(sys.modules, {"keyboard": fake_keyboard}):
            hotkey = GlobalAutomationStopHotkey(controller)
            self.assertTrue(hotkey.start())
            self.assertFalse(hotkey.start())
            self.assertEqual(registrations[0][0], "esc")
            self.assertFalse(registrations[0][2]["suppress"])
            registrations[0][1]()
            self.assertFalse(controller.is_active(lease))
            self.assertTrue(hotkey.close())
            self.assertFalse(hotkey.close())

        self.assertEqual(removals, ["automation-hotkey-handle"])


class DesktopTargetReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inspector = FakeInspector(observation())
        self.guard = DesktopTargetGuard(self.inspector)
        self.highlighter = FakeHighlighter()
        self.stops = AutomationStopController()
        self.clock = MutableClock()
        self.controller = DesktopTargetReviewController(
            self.guard,
            self.highlighter,
            self.stops,
            clock=self.clock,
        )
        self.run = self.stops.begin("desktop-run-one")

    def preview(self):
        return self.controller.preview(
            self.run,
            action=DesktopActionKind.INVOKE,
            ttl_seconds=10,
        )

    def test_preview_highlights_exact_target_but_grants_no_action(self):
        result = self.preview()

        self.assertTrue(result.ready)
        assert result.lease is not None
        request = result.lease.request
        self.assertEqual(request.run_id, self.run.run_id)
        self.assertEqual(request.application_name, "Synthetic editor")
        self.assertEqual(request.control_name, "Save")
        self.assertEqual(request.bounds, target().bounds)
        self.assertEqual(
            request.target_identity_digest,
            target().identity_digest,
        )
        self.assertEqual(request.target_review_digest, target().review_digest)
        self.assertEqual(self.highlighter.requests, [request])
        self.assertFalse(hasattr(result.lease, "execute"))
        self.assertFalse(hasattr(request, "invoke"))

    def test_revalidation_accepts_only_the_exact_reviewed_target(self):
        result = self.preview()
        assert result.lease is not None

        current = self.controller.revalidate(result.lease)
        self.assertTrue(current.ready)

        self.inspector.current = observation(
            target(control_name="Delete permanently"),
            hints=("Delete permanently",),
        )
        changed = self.controller.revalidate(result.lease)
        self.assertEqual(changed.status, DesktopReviewStatus.BLOCKED)
        self.assertIn(
            result.lease.request.review_id,
            self.highlighter.cleared,
        )

    def test_stop_clears_highlight_and_suppresses_stale_review(self):
        result = self.preview()
        assert result.lease is not None

        self.assertTrue(self.stops.stop())
        self.assertIn(
            result.lease.request.review_id,
            self.highlighter.cleared,
        )
        stale = self.controller.revalidate(result.lease)
        self.assertEqual(stale.status, DesktopReviewStatus.CANCELLED)

    def test_missing_visible_highlight_blocks_revalidation(self):
        result = self.preview()
        assert result.lease is not None
        self.highlighter.clear(result.lease.request.review_id)

        hidden = self.controller.revalidate(result.lease)

        self.assertEqual(hidden.status, DesktopReviewStatus.UNAVAILABLE)
        self.assertIsNone(hidden.lease)

    def test_stop_during_show_clears_and_returns_cancelled(self):
        self.highlighter.on_show = self.stops.stop

        result = self.preview()

        self.assertEqual(result.status, DesktopReviewStatus.CANCELLED)
        self.assertEqual(len(self.highlighter.requests), 1)
        self.assertIn(
            self.highlighter.requests[0].review_id,
            self.highlighter.cleared,
        )

    def test_expiry_or_highlighter_failure_exposes_no_lease(self):
        result = self.preview()
        assert result.lease is not None
        self.clock.value = result.lease.request.expires_at + 0.001

        expired = self.controller.revalidate(result.lease)
        self.assertEqual(expired.status, DesktopReviewStatus.EXPIRED)
        self.assertIsNone(expired.lease)

        self.run = self.stops.begin("desktop-run-two")
        self.highlighter.failure = RuntimeError("synthetic")
        unavailable = self.preview()
        self.assertEqual(
            unavailable.status,
            DesktopReviewStatus.UNAVAILABLE,
        )
        self.assertIsNone(unavailable.lease)

    def test_blocked_or_cancelled_target_is_never_highlighted(self):
        self.inspector.current = observation(hints=("Checkout",))
        blocked = self.preview()
        self.assertEqual(blocked.status, DesktopReviewStatus.BLOCKED)
        self.assertEqual(self.highlighter.requests, [])

        self.stops.stop()
        cancelled = self.preview()
        self.assertEqual(cancelled.status, DesktopReviewStatus.CANCELLED)
        self.assertEqual(self.highlighter.requests, [])

    def test_invalid_ttl_fails_before_inspection(self):
        for ttl in (0, 31, float("nan")):
            with self.subTest(ttl=ttl):
                calls = self.inspector.calls
                with self.assertRaises(ValueError):
                    self.controller.preview(
                        self.run,
                        action=DesktopActionKind.INVOKE,
                        ttl_seconds=ttl,
                    )
                self.assertEqual(self.inspector.calls, calls)


if __name__ == "__main__":
    unittest.main()
