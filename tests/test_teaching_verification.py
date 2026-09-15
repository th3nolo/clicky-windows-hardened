"""Regression coverage for fresh, output-only teaching verification."""
from __future__ import annotations

import json
import unittest

from automation.teaching_verification import (
    OUTPUT_READER_SYSTEM,
    SCHEMA,
    SCHEMA_VERSION,
    TeachingComponent,
    TeachingExpectation,
    VerificationMode,
    compare_teaching_output,
    parse_output_observation,
    verify_teaching_output,
)


def response(*, text="Rows α × α", labels=("Rows",), symbols=("alpha", "times"),
             entry_symbol_sequence=None, objects=("row_vector",), uncertainties=()):
    return json.dumps({
        "schema": SCHEMA,
        "version": SCHEMA_VERSION,
        "visible_text": text,
        "labels": list(labels),
        "symbols": list(symbols),
        "entry_symbol_sequence": list(symbols if entry_symbol_sequence is None else entry_symbol_sequence),
        "objects": list(objects),
        "uncertainties": list(uncertainties),
    })


EXPECTATION = TeachingExpectation((
    TeachingComponent("row-vector", required_labels=("Rows",),
                      required_symbols=("alpha", "times"), required_objects=("row_vector",)),
))


class Provider:
    def __init__(self, output):
        self.output = output
        self.outputs = iter(output) if isinstance(output, list) else None
        self.calls = []

    async def stream_response(self, prompt, images, history, system, model=None):
        self.calls.append((prompt, images, history, system, model))
        yield next(self.outputs) if self.outputs is not None else self.output


class PendingProvider:
    """Models provider usage that is aborted when its stream is closed early."""

    def __init__(self, first_chunk):
        self.first_chunk = first_chunk
        self.aborted = False
        self.finished = False

    async def stream_response(self, prompt, images, history, system, model=None):
        try:
            yield self.first_chunk
            self.finished = True
            yield response()
        finally:
            self.aborted = not self.finished


class TeachingVerificationTests(unittest.IsolatedAsyncioTestCase):
    async def test_fresh_reader_receives_only_crop_fixed_prompt_and_empty_history(self):
        provider = Provider(response())
        private_expectation = TeachingExpectation((
            TeachingComponent("private-component", required_labels=("Private Heading",),
                              required_symbols=("integral",)),
        ))
        result = await verify_teaching_output(provider, "reader-model", "output-crop", private_expectation)

        self.assertFalse(result.accepted)
        prompt, images, history, system, model = provider.calls[0]
        self.assertEqual(images, ["output-crop"])
        self.assertEqual(history, [])
        self.assertEqual(system, OUTPUT_READER_SYSTEM)
        self.assertEqual(model, "reader-model")
        self.assertNotIn("Private Heading", prompt)
        self.assertNotIn("integral", prompt)
        self.assertNotIn("private-component", prompt)
        self.assertNotIn("expected", prompt.casefold())

    async def test_garbled_reader_report_cannot_false_complete_from_writer_done(self):
        provider = Provider(response(text="R0ws a x a", labels=("R0ws",), symbols=("alpha",), objects=("row_vector",)))
        result = await verify_teaching_output(provider, "reader-model", "output-crop", EXPECTATION)

        self.assertFalse(result.accepted)
        self.assertEqual(result.outcome, "needs_review")
        self.assertEqual(result.missing_component_ids, ("row-vector",))
        component = result.components[0]
        self.assertEqual(component.missing_labels, ("Rows",))
        self.assertEqual(component.missing_symbols, ("times",))

    async def test_malformed_reader_response_is_unresolved_not_accepted(self):
        provider = Provider('{"schema":"clicky.teaching_output_observation"')
        result = await verify_teaching_output(provider, "reader-model", "output-crop", EXPECTATION)

        self.assertFalse(result.accepted)
        self.assertIsNone(result.observation)
        self.assertIn("complete JSON", result.parse_error or "")
        self.assertEqual(result.unresolved, ("independent output observation was unavailable",))

    async def test_reader_uncertainty_remains_unresolved_even_when_tokens_match(self):
        provider = Provider(response(uncertainties=("the second mark may be times or x",)))
        result = await verify_teaching_output(provider, "reader-model", "output-crop", EXPECTATION)

        self.assertFalse(result.accepted)
        self.assertEqual(result.unresolved, ("the second mark may be times or x",))
        self.assertEqual(result.missing_component_ids, ())

    async def test_exact_copy_requires_exact_visible_text_but_teaching_allows_paraphrase(self):
        expectation = TeachingExpectation((
            TeachingComponent("sentence", required_labels=("Rows",), exact_text="Rows are multiplied."),
        ))
        observation = parse_output_observation(response(text="Rows multiply.", labels=("Rows",), symbols=(), objects=("sentence",)))

        teaching = compare_teaching_output(observation, expectation)
        exact = compare_teaching_output(observation, expectation, mode=VerificationMode.EXACT_COPY)

        self.assertTrue(teaching.accepted)
        self.assertFalse(exact.accepted)
        self.assertFalse(exact.components[0].exact_text_matches)

    async def test_exact_copy_requires_text_contract_for_every_component(self):
        observation = parse_output_observation(response())
        with self.assertRaisesRegex(ValueError, "requires exact text"):
            compare_teaching_output(observation, EXPECTATION, mode=VerificationMode.EXACT_COPY)

    async def test_schema_rejects_extra_writer_claim_fields(self):
        payload = json.loads(response())
        payload["done"] = True
        with self.assertRaisesRegex(ValueError, "unsupported schema"):
            parse_output_observation(json.dumps(payload))

    async def test_oversized_reader_response_closes_pending_provider_stream(self):
        provider = PendingProvider("x" * (16 * 1024 + 1))
        result = await verify_teaching_output(provider, "reader-model", "output-crop", EXPECTATION)

        self.assertFalse(result.accepted)
        self.assertIn("exceeded", result.parse_error or "")
        self.assertTrue(provider.aborted)
        self.assertFalse(provider.finished)

    async def test_non_text_reader_chunk_closes_pending_provider_stream(self):
        provider = PendingProvider(object())
        with self.assertRaisesRegex(ValueError, "non-text"):
            await verify_teaching_output(provider, "reader-model", "output-crop", EXPECTATION)

        self.assertTrue(provider.aborted)
        self.assertFalse(provider.finished)

    async def test_empty_component_has_no_evidence_contract_and_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "visual evidence"):
            TeachingComponent("empty")

    async def test_repeated_symbols_and_objects_require_matching_multiplicity(self):
        expectation = TeachingExpectation((
            TeachingComponent("vertical-vector", required_symbols=("alpha",) * 6,
                              required_objects=("row_vector", "row_vector")),
        ))
        observation = parse_output_observation(response(symbols=("alpha",), objects=("row_vector",)))
        result = compare_teaching_output(observation, expectation)

        self.assertFalse(result.accepted)
        self.assertEqual(result.components[0].missing_symbols, ("alpha",) * 5)
        self.assertEqual(result.components[0].missing_objects, ("row_vector",))

    async def test_ordered_symbol_group_and_normalized_dimension_must_match(self):
        expectation = TeachingExpectation((
            TeachingComponent("column", required_labels=("1x3",),
                              required_symbols=("alpha", "times", "alpha"),
                              required_symbol_sequence=("alpha", "times", "alpha")),
        ))
        observation = parse_output_observation(response(
            labels=("1 × 3",), symbols=("alpha", "times", "alpha"),
            entry_symbol_sequence=("alpha", "alpha", "times"), objects=("row_vector",),
        ))
        result = compare_teaching_output(observation, expectation)

        self.assertFalse(result.accepted)
        self.assertEqual(result.components[0].missing_labels, ())
        self.assertFalse(result.components[0].symbol_sequence_matches)

    async def test_realistic_vector_readback_excludes_brackets_and_dimension_from_entry_order(self):
        expectation = TeachingExpectation((
            TeachingComponent(
                "row-example", required_labels=("row", "1x3"),
                required_symbols=("1", "2", "3"),
                required_symbol_sequence=("1", "2", "3"),
                required_objects=("row_vector",),
            ),
        ))
        observation = parse_output_observation(response(
            text="row [1 2 3] 1x3", labels=("row", "1x3"),
            symbols=("left_bracket", "1", "2", "3", "right_bracket"),
            entry_symbol_sequence=("1", "2", "3"), objects=("row_vector",),
        ))
        result = compare_teaching_output(observation, expectation)

        self.assertTrue(result.accepted)
        self.assertTrue(result.components[0].symbol_sequence_matches)

    async def test_components_need_distinct_crops_so_one_label_cannot_satisfy_both(self):
        with self.assertRaisesRegex(ValueError, "distinct output crop"):
            TeachingExpectation((
                TeachingComponent("first", required_labels=("Rows",)),
                TeachingComponent("second", required_labels=("Rows",)),
            ))

        expectation = TeachingExpectation((
            TeachingComponent("first", required_labels=("Rows",), crop_index=0),
            TeachingComponent("second", required_labels=("Rows",), crop_index=1),
        ))
        provider = Provider([
            response(text="Rows", labels=("Rows",), symbols=(), objects=("sentence",)),
            response(text="Rows", labels=("Rows",), symbols=(), objects=("sentence",)),
        ])
        result = await verify_teaching_output(provider, "reader-model", ("crop-one", "crop-two"), expectation)

        self.assertTrue(result.accepted)
        self.assertEqual([call[1] for call in provider.calls], [["crop-one"], ["crop-two"]])
        self.assertIsNone(result.observation)
        self.assertEqual(len(result.observations), 2)

    async def test_exact_copy_uses_each_components_own_crop(self):
        expectation = TeachingExpectation((
            TeachingComponent("first", required_labels=("Rows",), exact_text="Rows", crop_index=0),
            TeachingComponent("second", required_labels=("Columns",), exact_text="Columns", crop_index=1),
        ))
        provider = Provider([
            response(text="Rows", labels=("Rows",), symbols=(), objects=("sentence",)),
            response(text="Columns", labels=("Columns",), symbols=(), objects=("sentence",)),
        ])
        result = await verify_teaching_output(
            provider, "reader-model", ("crop-one", "crop-two"), expectation,
            mode=VerificationMode.EXACT_COPY,
        )

        self.assertTrue(result.accepted)
        self.assertTrue(all(item.exact_text_matches for item in result.components))


if __name__ == "__main__":
    unittest.main()
