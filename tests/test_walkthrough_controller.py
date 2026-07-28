"""Manual advance, recapture, TTL, and no-action walkthrough tests."""

from __future__ import annotations

import ast
import asyncio
import json
import os
import unittest
from pathlib import Path

from screen.topology import MonitorDescriptor, Rect
from walkthrough.controller import (
    RejectingTargetGuard,
    WalkthroughController,
)
from walkthrough.models import (
    ShapeColor,
    ShapeKind,
    StepKind,
    VisualTarget,
    VisualShape,
    Walkthrough,
    WalkthroughStep,
)
from walkthrough.protocol import WalkthroughProtocolParser


ROOT = Path(__file__).resolve().parents[1]
DISPLAY = "monitor-primary"
WALKTHROUGH_ID = "walkthrough_123456"


class _Timer:
    instances = []

    def __init__(self, seconds, callback):
        self.seconds = seconds
        self.callback = callback
        self.daemon = False
        self.started = False
        self.cancelled = False
        type(self).instances.append(self)

    def start(self):
        self.started = True

    def cancel(self):
        self.cancelled = True

    def fire(self):
        self.callback()


class _TargetGuard:
    def __init__(self):
        self.current = True
        self.calls = []

    def resolve(self, _reference):
        return None

    def revalidate(self, target):
        self.calls.append(target)
        return self.current


def _display(
    *,
    stable_id: str = DISPLAY,
    left: int = 0,
    top: int = 0,
    width: int = 1600,
    height: int = 900,
) -> MonitorDescriptor:
    return MonitorDescriptor(
        stable_id=stable_id,
        index=1,
        capture_index=1,
        device_name=r"\\.\DISPLAY1",
        label="Screen 1",
        physical=Rect(left, top, width * 2, height * 2),
        logical=Rect(left, top, width, height),
        dpi_x=192.0,
        dpi_y=192.0,
        primary=True,
        focused=True,
    )


def _coordinate_walkthrough(step_count=2) -> Walkthrough:
    rows = []
    for index in range(step_count):
        rows.append(
            {
                "step_id": f"step_point_{index}_12345678",
                "type": "POINT",
                "narration": f"Manual instruction {index + 1}.",
                "ttl_seconds": 10,
                "display_ref": DISPLAY,
                "point": [100 + index * 200, 300 + index * 100],
                "label": f"Point {index + 1}",
                "coordinate_display_only": True,
            }
        )
    payload = json.dumps(
        {
            "schema": "clicky.visual_walkthrough",
            "version": 1,
            "walkthrough_id": WALKTHROUGH_ID,
            "steps": rows,
        }
    )
    return WalkthroughProtocolParser(
        RejectingTargetGuard(),
        clock=lambda: 100.0,
    ).parse(payload, known_displays=frozenset({DISPLAY}))


def _target_walkthrough(target: VisualTarget) -> Walkthrough:
    steps = (
        WalkthroughStep(
            step_id="step_target_12345678",
            kind=StepKind.TARGET,
            narration="Review the target.",
            ttl_seconds=10.0,
            target=target,
        ),
        WalkthroughStep(
            step_id="step_hover_123456789",
            kind=StepKind.HOVER,
            narration="Review it again.",
            ttl_seconds=10.0,
            target=target,
        ),
    )
    return Walkthrough(1, WALKTHROUGH_ID, 100.0, steps)


class _Harness:
    def __init__(
        self,
        *,
        allowed=True,
        displays=None,
        target_guard=None,
        capture=None,
        capture_runner=None,
    ):
        _Timer.instances.clear()
        self.allowed = allowed
        self.displays = list(displays or [_display()])
        self.renders = []
        self.clears = 0
        self.progress = []
        self.ends = []
        self.capture_calls = 0
        self.target_guard = target_guard or _TargetGuard()

        def capture_displays():
            self.capture_calls += 1
            if capture is not None:
                return capture()
            return tuple(self.displays)

        self.controller = WalkthroughController(
            target_guard=self.target_guard,
            screen_allowed=lambda: self.allowed,
            capture_displays=capture_displays,
            on_render=self.renders.append,
            on_clear=self._clear,
            on_progress=self.progress.append,
            on_end=self.ends.append,
            capture_runner=(
                capture_runner or self._run_capture_inline
            ),
            clock=lambda: 100.0,
            timer_factory=_Timer,
        )

    @staticmethod
    async def _run_capture_inline(callback):
        return callback()

    def _clear(self):
        self.clears += 1


class WalkthroughControllerTests(unittest.TestCase):
    def test_start_renders_first_step_and_waits_for_explicit_continue(self):
        harness = _Harness()
        first = harness.controller.start(
            _coordinate_walkthrough(),
            [_display()],
        )

        self.assertEqual(first.narration, "Manual instruction 1.")
        self.assertEqual(len(harness.renders), 1)
        self.assertEqual(harness.capture_calls, 0)
        self.assertEqual(harness.progress[-1].current, 1)
        self.assertEqual(harness.progress[-1].remaining, 1)
        self.assertEqual(harness.renders[-1].point.x, 160.0)
        self.assertEqual(harness.renders[-1].point.y, 270.0)
        self.assertEqual(len(_Timer.instances), 1)
        self.assertTrue(_Timer.instances[0].started)

    def test_continue_recaptures_once_then_renders_next_step(self):
        harness = _Harness()
        harness.controller.start(_coordinate_walkthrough(), [_display()])
        result = asyncio.run(harness.controller.advance())

        self.assertEqual(result.reason, "advanced")
        self.assertEqual(result.step.narration, "Manual instruction 2.")
        self.assertEqual(harness.capture_calls, 1)
        self.assertEqual(len(harness.renders), 2)
        self.assertEqual(harness.progress[-1].current, 2)
        self.assertEqual(harness.progress[-1].remaining, 0)
        self.assertTrue(_Timer.instances[0].cancelled)

    def test_finish_never_recaptures_or_activates_an_external_control(self):
        harness = _Harness()
        harness.controller.start(
            _coordinate_walkthrough(step_count=1),
            [_display()],
        )
        result = asyncio.run(harness.controller.advance())

        self.assertTrue(result.completed)
        self.assertEqual(harness.capture_calls, 0)
        self.assertEqual(harness.ends, ["completed"])
        self.assertFalse(harness.controller.active)

    def test_permission_denial_and_revocation_fail_without_late_render(self):
        denied = _Harness(allowed=False)
        with self.assertRaisesRegex(RuntimeError, "permission"):
            denied.controller.start(
                _coordinate_walkthrough(),
                [_display()],
            )
        self.assertEqual(denied.renders, [])

        replacement = _Harness()
        replacement.controller.start(
            _coordinate_walkthrough(),
            [_display()],
        )
        replacement.allowed = False
        with self.assertRaisesRegex(RuntimeError, "permission"):
            replacement.controller.start(
                _coordinate_walkthrough(),
                [_display()],
            )
        self.assertFalse(replacement.controller.active)
        self.assertEqual(
            replacement.ends,
            ["permission_revoked"],
        )

        revoked = _Harness()
        revoked.controller.start(_coordinate_walkthrough(), [_display()])

        def revoke_during_capture():
            revoked.allowed = False
            return (_display(),)

        revoked.controller._capture_displays = revoke_during_capture
        result = asyncio.run(revoked.controller.advance())
        self.assertEqual(result.reason, "permission_revoked")
        self.assertEqual(len(revoked.renders), 1)
        self.assertEqual(revoked.ends, ["permission_revoked"])

    def test_hotplug_ends_session_before_next_annotation(self):
        harness = _Harness(
            displays=[_display(stable_id="different-monitor")]
        )
        harness.controller.start(_coordinate_walkthrough(), [_display()])
        result = asyncio.run(harness.controller.advance())

        self.assertEqual(result.reason, "display_topology_changed")
        self.assertEqual(len(harness.renders), 1)
        self.assertEqual(harness.ends, ["display_topology_changed"])

    def test_geometry_or_dpi_change_ends_before_next_annotation(self):
        changed = _display(width=1280, height=720)
        harness = _Harness(displays=[changed])
        harness.controller.start(_coordinate_walkthrough(), [_display()])
        result = asyncio.run(harness.controller.advance())

        self.assertEqual(result.reason, "display_topology_changed")
        self.assertEqual(len(harness.renders), 1)
        self.assertEqual(harness.ends, ["display_topology_changed"])

    def test_cancel_during_inflight_capture_suppresses_late_output(self):
        started = asyncio.Event()
        release = asyncio.Event()

        def capture():
            return (_display(),)

        async def delayed_capture(callback):
            started.set()
            await release.wait()
            return callback()

        harness = _Harness(
            capture=capture,
            capture_runner=delayed_capture,
        )
        harness.controller.start(_coordinate_walkthrough(), [_display()])

        async def scenario():
            task = asyncio.create_task(harness.controller.advance())
            await asyncio.wait_for(started.wait(), timeout=2)
            self.assertTrue(harness.controller.cancel("cancelled"))
            release.set()
            return await task

        result = asyncio.run(scenario())
        self.assertEqual(result.reason, "stale")
        self.assertEqual(len(harness.renders), 1)
        self.assertEqual(harness.ends, ["cancelled"])

    def test_reentrant_cancel_before_capture_prevents_recapture(self):
        harness = _Harness()

        def cancel_on_advancing(progress):
            harness.progress.append(progress)
            if progress.advancing:
                harness.controller.cancel("cancelled")

        harness.controller._on_progress = cancel_on_advancing
        harness.controller.start(_coordinate_walkthrough(), [_display()])
        result = asyncio.run(harness.controller.advance())
        self.assertEqual(result.reason, "stale")
        self.assertEqual(harness.capture_calls, 0)
        self.assertEqual(len(harness.renders), 1)

    def test_stale_target_fails_revalidation_after_recapture(self):
        guard = _TargetGuard()
        target = VisualTarget(
            opaque_id="target_ref_1234567890",
            display_id=DISPLAY,
            identity_digest="b" * 64,
            logical_left=100.0,
            logical_top=100.0,
            logical_width=200.0,
            logical_height=80.0,
            expires_at=200.0,
        )
        harness = _Harness(target_guard=guard)
        harness.controller.start(_target_walkthrough(target), [_display()])
        guard.current = False
        result = asyncio.run(harness.controller.advance())

        self.assertEqual(result.reason, "step_revalidation_failed")
        self.assertEqual(len(harness.renders), 1)
        self.assertEqual(harness.ends, ["step_revalidation_failed"])

    def test_ttl_expiry_clears_and_stale_timer_cannot_end_replacement(self):
        harness = _Harness()
        harness.controller.start(_coordinate_walkthrough(), [_display()])
        stale_timer = _Timer.instances[-1]
        harness.controller.start(_coordinate_walkthrough(), [_display()])
        active_timer = _Timer.instances[-1]
        stale_timer.fire()
        self.assertTrue(harness.controller.active)
        active_timer.fire()
        self.assertFalse(harness.controller.active)
        self.assertEqual(harness.ends, ["expired"])

    def test_voice_pause_blocks_click_but_explicit_voice_continue_advances(self):
        harness = _Harness()
        harness.controller.start(_coordinate_walkthrough(), [_display()])
        self.assertTrue(harness.controller.pause_for_voice())
        blocked = asyncio.run(harness.controller.advance())
        advanced = asyncio.run(
            harness.controller.advance(from_voice=True)
        )

        self.assertEqual(blocked.reason, "voice_capture_active")
        self.assertEqual(advanced.reason, "advanced")
        self.assertEqual(harness.capture_calls, 1)

    def test_mixed_dpi_negative_origin_shape_mapping_is_display_local(self):
        secondary = _display(
            stable_id="monitor-secondary",
            left=-1200,
            top=-100,
            width=1200,
            height=800,
        )
        step = WalkthroughStep(
            step_id="step_shape_123456789",
            kind=StepKind.SHAPE,
            narration="Show the local rectangle.",
            ttl_seconds=10.0,
            display_id=secondary.stable_id,
            shapes=(
                VisualShape(
                    ShapeKind.RECTANGLE,
                    ((0.0, 0.0), (1_000.0, 1_000.0)),
                    ShapeColor.BLUE,
                ),
            ),
            coordinate_display_only=True,
        )
        walkthrough = Walkthrough(
            1,
            WALKTHROUGH_ID,
            100.0,
            (step,),
        )
        harness = _Harness(displays=[secondary])
        harness.controller.start(walkthrough, [secondary])
        points = harness.renders[-1].shapes[0].points
        self.assertEqual(points[0], (-1200.0, -100.0))
        self.assertEqual(points[1], (-1.0, 699.0))

    def test_controller_has_no_desktop_action_or_input_import(self):
        path = ROOT / "walkthrough" / "controller.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        forbidden = (
            "automation",
            "capability_registry",
            "dictation.insertion",
            "connectors",
            "workspace_coding",
        )
        self.assertFalse(
            tuple(
                name
                for name in imported
                if name.startswith(forbidden)
            )
        )
        for token in ("SendInput", "mouse_event", "DesktopActionCall"):
            self.assertNotIn(token, source)


class WalkthroughUiAndWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

    def test_progress_ui_requires_click_and_names_no_action_boundary(self):
        source = (ROOT / "ui" / "walkthrough.py").read_text(encoding="utf-8")
        self.assertIn('continue_requested = pyqtSignal()', source)
        self.assertIn('"Continue"', source)
        self.assertIn('"Finish"', source)
        self.assertIn("remaining", source)
        self.assertIn("will not click or change", source)
        self.assertNotIn("QTest.mouseClick", source)

    def test_manager_uses_strict_private_buffer_and_existing_capture_path(self):
        source = (ROOT / "companion_manager.py").read_text(encoding="utf-8")
        self.assertIn("walkthrough_response_contract(", source)
        self.assertIn("self._walkthrough_parser.parse(", source)
        self.assertIn("if walkthrough_requested:", source)
        self.assertIn("full_response += chunk", source)
        self.assertIn(
            "screenshots = capture_all_screens()",
            source,
        )
        self.assertIn("and not walkthrough_requested", source)
        self.assertIn("steps = _split_steps(full_response)", source)
        self.assertIn(
            "if self._walkthrough.active:",
            source,
        )
        self.assertIn(
            "await self._advance_walkthrough(\n"
            "                        session,\n"
            "                        from_voice=True,",
            source,
        )
        self.assertGreaterEqual(
            source.count(
                'self._walkthrough.cancel("voice_input_failed")'
            ),
            4,
        )

    def test_prompt_json_escapes_and_rejects_ambiguous_display_ids(self):
        from walkthrough.prompt import walkthrough_response_contract

        escaped = walkthrough_response_contract(
            (_display(stable_id='monitor-"quoted'),)
        )
        self.assertIn('"monitor-\\"quoted"', escaped)
        with self.assertRaisesRegex(ValueError, "identity"):
            walkthrough_response_contract((_display(), _display()))

    def test_manager_bounds_private_provider_buffer_before_parsing(self):
        source = (ROOT / "companion_manager.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("walkthrough_bytes + chunk_size", source)
        self.assertIn("> MAX_PAYLOAD_BYTES", source)
        self.assertIn("if walkthrough_overflow:", source)

    def test_main_and_package_wire_progress_continue_cancel_and_stop(self):
        main = (ROOT / "main.py").read_text(encoding="utf-8")
        spec = (ROOT / "clicky.spec").read_text(encoding="utf-8")
        self.assertIn("walkthrough_panel = WalkthroughPanel()", main)
        self.assertIn(
            "walkthrough_panel.continue_requested.connect(\n"
            "        manager.continue_walkthrough",
            main,
        )
        self.assertIn(
            "walkthrough_panel.cancel_requested.connect(\n"
            "        manager.cancel_walkthrough",
            main,
        )
        for module in (
            '"walkthrough.controller"',
            '"walkthrough.prompt"',
            '"ui.walkthrough"',
        ):
            self.assertIn(module, spec)


if __name__ == "__main__":
    unittest.main()
