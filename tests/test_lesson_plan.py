"""Strict planning-manifest regression coverage before notebook mutation."""
from __future__ import annotations

import json
import unittest

from automation.lesson_plan import (
    LessonComponent,
    LessonPlan,
    LessonPlanMode,
    PageGeometry,
    PageRegion,
    PLANNER_CONSTRAINTS,
    PLANNER_SYSTEM,
    SCHEMA,
    SCHEMA_VERSION,
    parse_lesson_plan,
    request_lesson_plan,
)


def component(component_id="row", *, region=None, labels=("Rows",), symbols=("alpha", "alpha", "times"),
              objects=("row_vector",), symbol_count=3, sequence=("alpha", "alpha", "times"),
              dimension_label=None, exact_text=None):
    return {
        "component_id": component_id,
        "region": region or {"x": 10, "y": 20, "width": 150, "height": 80},
        "required_labels": list(labels),
        "required_symbols": list(symbols),
        "required_objects": list(objects),
        "symbol_count": symbol_count,
        "symbol_sequence": list(sequence),
        "dimension_label": dimension_label,
        "exact_text": exact_text,
    }


def plan(*components):
    return json.dumps({"schema": SCHEMA, "version": SCHEMA_VERSION, "components": list(components)})


GEOMETRY = PageGeometry(
    page_width=1200, page_height=1600, source_image_width=960, source_image_height=1280,
    source_page_region=PageRegion(0, 0, 1200, 1600),
)


def parse_plan(payload, *, mode=LessonPlanMode.TEACHING):
    return parse_lesson_plan(
        payload, mode=mode, page_geometry=GEOMETRY, target_is_new_page=False,
    )


class Provider:
    def __init__(self, response):
        self.response = response
        self.responses = iter(response) if isinstance(response, list) else None
        self.calls = []

    async def stream_response(self, prompt, images, history, system, model=None):
        self.calls.append((prompt, images, history, system, model))
        yield next(self.responses) if self.responses is not None else self.response


class LessonPlanTests(unittest.IsolatedAsyncioTestCase):
    async def test_request_uses_one_source_image_and_freezes_valid_manifest(self):
        provider = Provider(plan(
            component("row"),
            component("column", region={"x": 200, "y": 20, "width": 150, "height": 80},
                      labels=("Columns",), symbols=("alpha", "times"), symbol_count=2,
                      sequence=("alpha", "times")),
        ))
        result = await request_lesson_plan(
            provider, "planner-model", "Explain the page", "source-image",
            page_geometry=GEOMETRY, target_is_new_page=True,
        )

        self.assertEqual([item.component_id for item in result.components], ["row", "column"])
        self.assertEqual(result.components[0].required_symbols, ("alpha", "alpha", "times"))
        prompt, images, history, system, model = provider.calls[0]
        self.assertEqual(images, ["source-image"])
        self.assertEqual(history, [])
        self.assertEqual(system, PLANNER_SYSTEM)
        self.assertEqual(model, "planner-model")
        self.assertIn("Explain the page", prompt)
        self.assertIn('"mode":"teaching"', prompt)
        self.assertIn('"page_width":1200', prompt)
        self.assertIn('"target_is_new_page":true', prompt)
        prompt_payload = json.loads(prompt)
        contract = prompt_payload["manifest"]["constraints"]
        self.assertEqual(contract, list(PLANNER_CONSTRAINTS))
        example = prompt_payload["manifest"]["response"]["components"][0]
        self.assertEqual(example, {
            "component_id": "row-example",
            "region": {"x": 100, "y": 100, "width": 800, "height": 240},
            "required_labels": ["row", "1x3"],
            "required_symbols": ["1", "2", "3"],
            "required_objects": ["row_vector"],
            "symbol_count": 3,
            "symbol_sequence": ["1", "2", "3"],
            "dimension_label": "1x3",
            "exact_text": None,
        })
        self.assertTrue(any("symbol_count null" in rule for rule in contract))
        self.assertTrue(any("exact_text is null" in rule for rule in contract))
        self.assertTrue(any("Prefer two coherent components" in rule for rule in contract))
        with self.assertRaisesRegex(Exception, "cannot assign"):
            result.components = ()
        manifest = result.writer_manifest()
        self.assertNotIn("source-image", json.dumps(manifest))
        self.assertNotIn("Explain the page", json.dumps(manifest))

    async def test_one_strict_schema_repair_retries_with_bounded_rejected_answer(self):
        invalid = json.loads(plan(component(dimension_label="1 x 3", labels=("Rows", "1 x 3"))))
        invalid.update({
            "target_is_new_page": True,
            "preserve_existing_pages": True,
            "teaching_note": "Use blue ink",
            "ink_colors": ["blue"],
        })
        invalid["components"][0]["exact_text"] = "Rows alpha alpha times"
        provider = Provider([
            json.dumps(invalid),
            plan(component(dimension_label="1x3", labels=("Rows", "1x3"))),
        ])

        result = await request_lesson_plan(
            provider, "planner-model", "Explain the page", "source-image",
            page_geometry=GEOMETRY, target_is_new_page=False,
        )

        self.assertEqual(result.components[0].dimension_label, "1x3")
        self.assertEqual(len(provider.calls), 2)
        self.assertEqual([call[1] for call in provider.calls], [["source-image"], ["source-image"]])
        self.assertEqual([call[2] for call in provider.calls], [[], []])
        repair = provider.calls[1][0]
        self.assertIn('"validation_error":"Lesson planner response has an unsupported schema"', repair)
        self.assertIn('"rejected_response"', repair)
        self.assertIn('"target_is_new_page": true', json.loads(repair)["repair"]["rejected_response"])

    async def test_schema_repair_occurs_once_and_keeps_strict_validator(self):
        invalid = json.dumps({"schema": SCHEMA, "version": SCHEMA_VERSION, "components": []})
        provider = Provider([invalid, invalid])
        with self.assertRaisesRegex(ValueError, "components are invalid"):
            await request_lesson_plan(
                provider, "planner-model", "Explain the page", "source-image",
                page_geometry=GEOMETRY, target_is_new_page=False,
            )
        self.assertEqual(len(provider.calls), 2)

    async def test_generic_vector_is_not_accepted_as_coverage(self):
        generic = component(labels=(), symbols=(), objects=("vector",), symbol_count=None, sequence=())
        with self.assertRaisesRegex(ValueError, "unsupported visible object"):
            parse_plan(plan(generic))

        generic_row = component(labels=(), symbols=(), objects=("row_vector",), symbol_count=None, sequence=())
        with self.assertRaisesRegex(ValueError, "generic vector-only"):
            parse_plan(plan(generic_row))

    async def test_empty_requirements_are_rejected_before_writer_can_see_them(self):
        empty = component(labels=(), symbols=(), objects=(), symbol_count=None, sequence=())
        with self.assertRaisesRegex(ValueError, "meaningful visible"):
            parse_plan(plan(empty))

    async def test_region_overlap_and_bad_symbol_contract_are_rejected(self):
        overlapping = component("column", region={"x": 100, "y": 20, "width": 150, "height": 80})
        with self.assertRaisesRegex(ValueError, "must not overlap"):
            parse_plan(plan(component("row"), overlapping))

        bad_count = component(symbols=("alpha", "alpha", "times", "times"),
                              symbol_count=4, sequence=("alpha", "alpha", "times"))
        with self.assertRaisesRegex(ValueError, "must match symbol count"):
            parse_plan(plan(bad_count))

        hidden_symbols = component(symbols=(), symbol_count=3, sequence=())
        with self.assertRaisesRegex(ValueError, "must match required symbols"):
            parse_plan(plan(hidden_symbols))

        reordered = component(sequence=("times", "alpha", "alpha"))
        with self.assertRaisesRegex(ValueError, "must preserve required symbol order"):
            parse_plan(plan(reordered))

    async def test_regions_outside_explicit_page_dip_bounds_are_rejected(self):
        outside = component(region={"x": 1100, "y": 20, "width": 150, "height": 80})
        with self.assertRaisesRegex(ValueError, "exceeds page dimensions"):
            parse_plan(plan(outside))

    async def test_dimension_must_be_explicitly_visible_label(self):
        hidden_dimension = component(dimension_label="3x1")
        with self.assertRaisesRegex(ValueError, "required visible label"):
            parse_plan(plan(hidden_dimension))

        explicit_dimension = component(labels=("Rows", "3x1"), dimension_label="3x1")
        parsed = parse_plan(plan(explicit_dimension))
        self.assertEqual(parsed.components[0].dimension_label, "3x1")

    async def test_exact_text_is_only_valid_in_explicit_exact_copy_mode(self):
        copied = component(exact_text="Rows alpha times alpha")
        with self.assertRaisesRegex(ValueError, "only in explicit exact-copy"):
            parse_plan(plan(copied))
        exact = parse_plan(plan(copied), mode=LessonPlanMode.EXACT_COPY)
        self.assertEqual(exact.mode, LessonPlanMode.EXACT_COPY)

        without_exact = component(exact_text=None)
        with self.assertRaisesRegex(ValueError, "requires exact text"):
            parse_plan(plan(without_exact), mode=LessonPlanMode.EXACT_COPY)

    async def test_per_component_verifier_contract_keeps_duplicate_symbols(self):
        parsed = parse_plan(plan(component()))
        verification = parsed.verification_components()[0]
        self.assertEqual(verification.required_symbols, ("alpha", "alpha", "times"))
        self.assertEqual(verification.component_id, "row")


if __name__ == "__main__":
    unittest.main()
