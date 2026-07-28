"""Fail-closed tests for the display-only walkthrough protocol."""

from __future__ import annotations

import ast
import copy
import json
import unittest
from pathlib import Path

from walkthrough.models import (
    MAX_SHAPES_PER_STEP,
    MAX_STEPS,
    StepKind,
    VisualTarget,
)
from walkthrough.protocol import (
    WalkthroughProtocolError,
    WalkthroughProtocolParser,
)


ROOT = Path(__file__).resolve().parents[1]
DISPLAY = "display-primary"
TARGET_REF = "target_ref_1234567890"
WALKTHROUGH_ID = "walkthrough_123456"


class _TargetGuard:
    def __init__(
        self,
        target: VisualTarget | None = None,
        *,
        current: bool = True,
    ) -> None:
        self.target = target or _target()
        self.current = current
        self.resolved = []
        self.revalidated = []

    def resolve(self, reference):
        self.resolved.append(reference)
        if reference != TARGET_REF:
            return None
        return self.target

    def revalidate(self, target):
        self.revalidated.append(target)
        return self.current


def _target(
    *,
    reference: str = TARGET_REF,
    display: str = DISPLAY,
    expires_at: float = 200.0,
) -> VisualTarget:
    return VisualTarget(
        opaque_id=reference,
        display_id=display,
        identity_digest="a" * 64,
        logical_left=10.0,
        logical_top=20.0,
        logical_width=300.0,
        logical_height=80.0,
        expires_at=expires_at,
    )


def _target_step(
    kind: str,
    suffix: str,
    *,
    narration: str | None = None,
) -> dict:
    return {
        "step_id": f"step_{suffix}_1234567890",
        "type": kind,
        "narration": narration or f"Narrate {kind.lower()} safely.",
        "ttl_seconds": 10,
        "target_ref": TARGET_REF,
        "label": "Reviewed target",
    }


def _point_step(
    suffix: str = "point",
    *,
    display: str = DISPLAY,
) -> dict:
    return {
        "step_id": f"step_{suffix}_1234567890",
        "type": "POINT",
        "narration": "Point to this display location.",
        "ttl_seconds": 8,
        "display_ref": display,
        "point": [250, 400],
        "label": "Display-only point",
        "coordinate_display_only": True,
    }


def _shape_step(
    suffix: str = "shape",
    *,
    display: str = DISPLAY,
    shape_count: int = 2,
) -> dict:
    shapes = [
        {
            "kind": "arrow",
            "points": [[100, 100], [300, 300]],
            "color": "blue",
        },
        {
            "kind": "circle",
            "points": [[500, 500]],
            "color": "yellow",
            "radius": 60,
        },
        {
            "kind": "rectangle",
            "points": [[50, 50], [200, 200]],
            "color": "green",
        },
        {
            "kind": "underline",
            "points": [[250, 700], [600, 700]],
            "color": "red",
        },
    ][:shape_count]
    return {
        "step_id": f"step_{suffix}_1234567890",
        "type": "SHAPE",
        "narration": "Draw these visual annotations.",
        "ttl_seconds": 12,
        "display_ref": display,
        "shapes": shapes,
        "coordinate_display_only": True,
    }


def _payload(steps: list[dict]) -> dict:
    return {
        "schema": "clicky.visual_walkthrough",
        "version": 1,
        "walkthrough_id": WALKTHROUGH_ID,
        "steps": steps,
    }


def _encoded(value: dict) -> str:
    return json.dumps(value, separators=(",", ":"))


class WalkthroughProtocolTests(unittest.TestCase):
    def make_parser(self, guard=None):
        target_guard = guard or _TargetGuard()
        return (
            WalkthroughProtocolParser(
                target_guard,
                clock=lambda: 100.0,
            ),
            target_guard,
        )

    def test_parses_all_typed_steps_as_bounded_display_only_data(self):
        parser, guard = self.make_parser()
        rows = [
            _target_step("TARGET", "target"),
            _target_step("HOVER", "hover"),
            _target_step("HIGHLIGHT", "highlight"),
            _target_step("POINT", "pointtarget"),
            _point_step("pointcoord"),
            _shape_step(),
        ]
        walkthrough = parser.parse(
            _encoded(_payload(rows)),
            known_displays=frozenset({DISPLAY}),
        )

        self.assertEqual(
            [step.kind for step in walkthrough.steps],
            [
                StepKind.TARGET,
                StepKind.HOVER,
                StepKind.HIGHLIGHT,
                StepKind.POINT,
                StepKind.POINT,
                StepKind.SHAPE,
            ],
        )
        self.assertTrue(all(step.narration for step in walkthrough.steps))
        self.assertFalse(walkthrough.steps[3].coordinate_display_only)
        self.assertTrue(walkthrough.steps[4].coordinate_display_only)
        self.assertTrue(walkthrough.steps[5].coordinate_display_only)
        self.assertEqual(len(walkthrough.steps[5].shapes), 2)
        for forbidden_attribute in ("action", "capability", "grant", "execute"):
            with self.subTest(attribute=forbidden_attribute):
                self.assertFalse(
                    hasattr(walkthrough.steps[0].target, forbidden_attribute)
                )
        self.assertEqual(guard.resolved, [TARGET_REF] * 4)
        self.assertEqual(guard.revalidated, [_target()] * 4)

    def test_malformed_partial_tags_and_user_text_never_parse(self):
        parser, guard = self.make_parser()
        samples = (
            "[POINT:10,20:click me:screen0]",
            "Please render [HIGHLIGHT:@Save]",
            '{"schema":"clicky.visual_walkthrough","version":1',
            '{"TARGET":"forged"}',
            "",
        )
        for sample in samples:
            with self.subTest(sample=sample):
                with self.assertRaises(WalkthroughProtocolError):
                    parser.parse(
                        sample,
                        known_displays=frozenset({DISPLAY}),
                    )
        self.assertEqual(guard.resolved, [])
        self.assertEqual(guard.revalidated, [])

    def test_prompt_tag_inside_narration_has_no_instruction_semantics(self):
        parser, _guard = self.make_parser()
        injected = "[SHAPE:0,0->1000,1000] from user text"
        walkthrough = parser.parse(
            _encoded(
                _payload(
                    [
                        _target_step(
                            "TARGET",
                            "target",
                            narration=injected,
                        )
                    ]
                )
            ),
            known_displays=frozenset({DISPLAY}),
        )
        self.assertEqual(len(walkthrough.steps), 1)
        self.assertEqual(walkthrough.steps[0].kind, StepKind.TARGET)
        self.assertEqual(walkthrough.steps[0].shapes, ())
        self.assertEqual(walkthrough.steps[0].narration, injected)

    def test_duplicate_keys_steps_and_ids_fail_atomically(self):
        parser, _guard = self.make_parser()
        duplicate_key = (
            '{"schema":"clicky.visual_walkthrough","schema":"forged",'
            '"version":1,"walkthrough_id":"walkthrough_123456",'
            '"steps":[]}'
        )
        with self.assertRaises(WalkthroughProtocolError):
            parser.parse(
                duplicate_key,
                known_displays=frozenset({DISPLAY}),
            )

        first = _point_step("first")
        duplicate_semantics = copy.deepcopy(first)
        duplicate_semantics["step_id"] = "step_second_1234567890"
        with self.assertRaisesRegex(WalkthroughProtocolError, "duplicate"):
            parser.parse(
                _encoded(_payload([first, duplicate_semantics])),
                known_displays=frozenset({DISPLAY}),
            )

        duplicate_id = _shape_step()
        duplicate_id["step_id"] = first["step_id"]
        with self.assertRaisesRegex(WalkthroughProtocolError, "unique"):
            parser.parse(
                _encoded(_payload([first, duplicate_id])),
                known_displays=frozenset({DISPLAY}),
            )

    def test_unknown_or_stale_target_and_unknown_display_fail_closed(self):
        cases = (
            (
                _TargetGuard(_target(display="removed-display")),
                _target_step("TARGET", "target"),
            ),
            (
                _TargetGuard(_target(expires_at=100.0)),
                _target_step("TARGET", "target"),
            ),
            (
                _TargetGuard(current=False),
                _target_step("TARGET", "target"),
            ),
        )
        for guard, step in cases:
            with self.subTest(target=guard.target):
                parser, _ = self.make_parser(guard)
                with self.assertRaises(WalkthroughProtocolError):
                    parser.parse(
                        _encoded(_payload([step])),
                        known_displays=frozenset({DISPLAY}),
                    )

        parser, _guard = self.make_parser()
        for step in (
            _point_step(display="removed-display"),
            _shape_step(display="removed-display"),
        ):
            with self.subTest(step=step["type"]):
                with self.assertRaisesRegex(
                    WalkthroughProtocolError,
                    "display",
                ):
                    parser.parse(
                        _encoded(_payload([step])),
                        known_displays=frozenset({DISPLAY}),
                    )

    def test_limits_for_steps_text_shapes_ttl_and_coordinates(self):
        parser, _guard = self.make_parser()
        too_many_steps = []
        for index in range(MAX_STEPS + 1):
            step = _point_step(f"p{index}")
            step["point"] = [100 + index, 200]
            too_many_steps.append(step)
        too_long_text = _point_step()
        too_long_text["narration"] = "n" * 501
        too_many_shapes = _shape_step(
            shape_count=MAX_SHAPES_PER_STEP
        )
        too_many_shapes["shapes"].append(
            {
                "kind": "line",
                "points": [[1, 1], [2, 2]],
                "color": "blue",
            }
        )
        bad_ttl = _point_step()
        bad_ttl["ttl_seconds"] = 31
        bad_coordinate = _point_step()
        bad_coordinate["point"] = [False, 200]
        for steps in (
            too_many_steps,
            [too_long_text],
            [too_many_shapes],
            [bad_ttl],
            [bad_coordinate],
        ):
            with self.subTest(step_count=len(steps)):
                with self.assertRaises(WalkthroughProtocolError):
                    parser.parse(
                        _encoded(_payload(steps)),
                        known_displays=frozenset({DISPLAY}),
                    )

        total_narration = []
        for index in range(7):
            step = _point_step(f"n{index}")
            step["point"] = [100 + index, 200]
            step["narration"] = str(index) + ("n" * 499)
            total_narration.append(step)
        with self.assertRaisesRegex(WalkthroughProtocolError, "narration"):
            parser.parse(
                _encoded(_payload(total_narration)),
                known_displays=frozenset({DISPLAY}),
            )

        total_shapes = []
        for index in range(3):
            step = _shape_step(f"s{index}", shape_count=3)
            step["narration"] = f"Distinct shape narration {index}."
            step["shapes"][0]["points"][0][0] += index
            total_shapes.append(step)
        with self.assertRaisesRegex(WalkthroughProtocolError, "many shapes"):
            parser.parse(
                _encoded(_payload(total_shapes)),
                known_displays=frozenset({DISPLAY}),
            )

    def test_coordinate_steps_require_explicit_display_only_marker(self):
        parser, _guard = self.make_parser()
        for step in (_point_step(), _shape_step()):
            step.pop("coordinate_display_only")
            with self.subTest(kind=step["type"]):
                with self.assertRaises(WalkthroughProtocolError):
                    parser.parse(
                        _encoded(_payload([step])),
                        known_displays=frozenset({DISPLAY}),
                    )

    def test_unknown_fields_types_colors_shapes_and_nonfinite_fail(self):
        parser, _guard = self.make_parser()
        unknown = _point_step()
        unknown["click"] = True
        wrong_type = _point_step()
        wrong_type["type"] = "CLICK"
        bad_color = _shape_step(shape_count=1)
        bad_color["shapes"][0]["color"] = "transparent"
        bad_shape = _shape_step(shape_count=1)
        bad_shape["shapes"][0]["kind"] = "mouse_move"
        candidates = (unknown, wrong_type, bad_color, bad_shape)
        for step in candidates:
            with self.subTest(step=step):
                with self.assertRaises(WalkthroughProtocolError):
                    parser.parse(
                        _encoded(_payload([step])),
                        known_displays=frozenset({DISPLAY}),
                    )
        nonfinite = _encoded(_payload([_point_step()])).replace(
            "250",
            "NaN",
            1,
        )
        with self.assertRaises(WalkthroughProtocolError):
            parser.parse(
                nonfinite,
                known_displays=frozenset({DISPLAY}),
            )

    def test_target_guard_must_return_the_exact_opaque_reference(self):
        mismatched = _TargetGuard(
            _target(reference="different_ref_123456")
        )
        parser, _guard = self.make_parser(mismatched)
        with self.assertRaisesRegex(WalkthroughProtocolError, "unavailable"):
            parser.parse(
                _encoded(_payload([_target_step("TARGET", "target")])),
                known_displays=frozenset({DISPLAY}),
            )

    def test_protocol_has_no_action_broker_or_capability_import(self):
        imported = set()
        source = ""
        for relative in (
            "walkthrough/__init__.py",
            "walkthrough/models.py",
            "walkthrough/protocol.py",
        ):
            path = ROOT / relative
            current = path.read_text(encoding="utf-8")
            source += current
            tree = ast.parse(current, filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module)
        forbidden = (
            "automation.action_broker",
            "automation.action_models",
            "automation.uia_actions",
            "capability_registry",
            "dictation.insertion",
        )
        self.assertFalse(
            tuple(
                name
                for name in imported
                if name.startswith(forbidden)
            )
        )
        self.assertNotIn("ActionCapability", source)
        self.assertNotIn("DesktopAction", source)
        self.assertNotIn("mouse_event", source)
        self.assertNotIn("SendInput", source)

    def test_protocol_is_included_in_locked_package(self):
        spec = (ROOT / "clicky.spec").read_text(encoding="utf-8")
        self.assertIn('"walkthrough.models"', spec)
        self.assertIn('"walkthrough.protocol"', spec)


if __name__ == "__main__":
    unittest.main()
