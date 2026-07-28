"""Deterministic source-backed Markdown research report tests."""

from __future__ import annotations

import hashlib
import json
import unittest
from datetime import datetime, timezone

from research.markdown_artifact import (
    ResearchMarkdownError,
    ResearchMarkdownSchema,
    inspect_research_markdown,
    render_research_json_to_markdown,
    render_research_markdown,
)
from tests.test_research_csv import batch, record


NOW = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
SOURCE = "https://creator.example/one"


def records_json(source: str = SOURCE) -> str:
    return json.dumps(
        {
            "records": [
                {
                    "entity": {
                        "value": "Creator #1 <reviewed>",
                        "source_urls": [source],
                    },
                    "public_url": {
                        "value": source,
                        "source_urls": [source],
                    },
                    "rationale": {
                        "value": "Matches the public request.",
                        "source_urls": [source],
                    },
                    "requested_fields": {
                        "audience": {
                            "value": "Software developers",
                            "source_urls": [source],
                        }
                    },
                }
            ]
        },
        separators=(",", ":"),
    )


class ResearchMarkdownArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = ResearchMarkdownSchema(
            "Creator research: Q3",
            ("audience",),
        )

    def test_strict_json_renders_only_observed_source_cited_markdown(self):
        artifact = render_research_json_to_markdown(
            records_json(),
            self.schema,
            requested_sections=1,
            maximum_output_bytes=64 * 1024,
            allowed_source_urls=(SOURCE,),
            retrieved_at=NOW,
        )

        self.assertTrue(artifact.complete)
        self.assertEqual(artifact.section_count, 1)
        self.assertEqual(
            artifact.sha256,
            hashlib.sha256(artifact.content).hexdigest(),
        )
        text = artifact.content.decode("utf-8")
        self.assertIn("# Creator research\\: Q3", text)
        self.assertIn("## 1. Creator \\#1 \\<reviewed\\>", text)
        self.assertIn(
            "- **audience:** Software developers — "
            "[S001] <https://creator.example/one>",
            text,
        )
        self.assertNotIn("<reviewed>", text)

        inspected = inspect_research_markdown(
            artifact.content,
            self.schema,
            requested_sections=1,
            maximum_bytes=64 * 1024,
        )
        self.assertTrue(inspected.structurally_valid)
        self.assertTrue(inspected.complete)
        self.assertEqual(inspected.section_count, 1)
        self.assertEqual(inspected.citation_count, 4)
        self.assertEqual(
            inspected.source_digest,
            artifact.source_digest,
        )

    def test_renderer_is_deterministic_and_section_headings_are_unique(self):
        records = batch(
            record("one", entity="Same name"),
            record("two", entity="Same name"),
        )
        first = render_research_markdown(
            records,
            self.schema,
            requested_sections=2,
        )
        second = render_research_markdown(
            records,
            self.schema,
            requested_sections=2,
        )
        self.assertEqual(first.content, second.content)
        self.assertIn(b"## 1. Same name", first.content)
        self.assertIn(b"## 2. Same name", first.content)

    def test_row_shortfall_is_explicit_and_never_padded(self):
        artifact = render_research_markdown(
            batch(record("one")),
            self.schema,
            requested_sections=2,
        )
        self.assertFalse(artifact.complete)
        self.assertEqual(
            artifact.partial_reason,
            "requested_sections_not_reached:1/2",
        )
        inspected = inspect_research_markdown(
            artifact.content,
            self.schema,
            requested_sections=2,
            maximum_bytes=64 * 1024,
        )
        self.assertTrue(inspected.structurally_valid)
        self.assertTrue(inspected.partial)
        self.assertEqual(
            inspected.result_code,
            "research_markdown_section_shortfall",
        )

    def test_unobserved_sources_and_unsafe_multiline_text_are_rejected(self):
        with self.assertRaisesRegex(
            ResearchMarkdownError,
            "invalid sourced values",
        ):
            render_research_json_to_markdown(
                records_json("https://invented.example/one"),
                self.schema,
                requested_sections=1,
                maximum_output_bytes=64 * 1024,
                allowed_source_urls=(SOURCE,),
                retrieved_at=NOW,
            )
        payload = json.loads(records_json())
        payload["records"][0]["rationale"]["value"] = "Line one\n## Injected"
        with self.assertRaisesRegex(
            ResearchMarkdownError,
            "text is invalid",
        ):
            render_research_json_to_markdown(
                json.dumps(payload),
                self.schema,
                requested_sections=1,
                maximum_output_bytes=64 * 1024,
                allowed_source_urls=(SOURCE,),
                retrieved_at=NOW,
            )
        unsafe_url = "https://creator.example/a`b"
        with self.assertRaisesRegex(
            ResearchMarkdownError,
            "not safe to embed",
        ):
            render_research_json_to_markdown(
                records_json(unsafe_url),
                self.schema,
                requested_sections=1,
                maximum_output_bytes=64 * 1024,
                allowed_source_urls=(unsafe_url,),
                retrieved_at=NOW,
            )

    def test_inspector_rejects_missing_unknown_or_uncovered_citations(self):
        valid = render_research_json_to_markdown(
            records_json(),
            self.schema,
            requested_sections=1,
            maximum_output_bytes=64 * 1024,
            allowed_source_urls=(SOURCE,),
            retrieved_at=NOW,
        ).content
        cases = (
            valid.replace(
                " — [S001] <https://creator.example/one>".encode(),
                b"",
                1,
            ),
            valid.replace(b"[S001]", b"[S002]", 1),
            valid.replace(
                b"- [S001] <https://creator.example/one>",
                b"- [S001] <https://other.example/one>",
            ),
        )
        for content in cases:
            with self.subTest(content=content[:80]):
                inspected = inspect_research_markdown(
                    content,
                    self.schema,
                    requested_sections=1,
                    maximum_bytes=64 * 1024,
                )
                self.assertFalse(inspected.structurally_valid)
                self.assertFalse(inspected.partial)

    def test_inspector_rejects_heading_title_encoding_and_size_drift(self):
        valid = render_research_json_to_markdown(
            records_json(),
            self.schema,
            requested_sections=1,
            maximum_output_bytes=64 * 1024,
            allowed_source_urls=(SOURCE,),
            retrieved_at=NOW,
        ).content
        cases = (
            valid.replace(b"## 1. Creator", b"## 1. # Creator"),
            valid.replace(b"# Creator research", b"# Other research"),
            valid.replace(b"\n", b"\r\n"),
        )
        for content in cases:
            with self.subTest(content=content[:80]):
                self.assertFalse(
                    inspect_research_markdown(
                        content,
                        self.schema,
                        requested_sections=1,
                        maximum_bytes=64 * 1024,
                    ).structurally_valid
                )
        self.assertFalse(
            inspect_research_markdown(
                valid,
                self.schema,
                requested_sections=1,
                maximum_bytes=len(valid) - 1,
            ).structurally_valid
        )


if __name__ == "__main__":
    unittest.main()
