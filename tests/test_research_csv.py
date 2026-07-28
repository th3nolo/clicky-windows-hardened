"""Deterministic source-backed research CSV rendering and inspection tests."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import unittest
from datetime import datetime, timezone

from research.csv_artifact import (
    ResearchCsvError,
    ResearchCsvSchema,
    inspect_research_csv,
    render_research_csv,
)
from research.models import (
    ResearchBatch,
    ResearchField,
    ResearchLimits,
    ResearchRecord,
    ResearchValue,
)


NOW = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)


def sourced(value: str, source: str) -> ResearchValue:
    return ResearchValue(value, (source,))


def record(
    slug: str,
    *,
    entity: str | None = None,
) -> ResearchRecord:
    source = f"https://evidence.example/{slug}"
    public_url = f"https://creator.example/{slug}"
    return ResearchRecord(
        entity=sourced(entity or f"Creator {slug}", source),
        public_url=sourced(public_url, public_url),
        requested_fields=(
            ResearchField(
                "audience",
                sourced("Software developers", source),
            ),
        ),
        rationale=sourced(
            "Relevant to the requested public campaign.",
            source,
        ),
        retrieved_at=NOW,
    )


def batch(*records: ResearchRecord) -> ResearchBatch:
    return ResearchBatch(
        tuple(records),
        ResearchLimits(
            max_rows=10,
            max_fields_per_record=4,
            max_sources_per_record=8,
            max_total_sources=20,
            max_output_bytes=64 * 1024,
        ),
    )


def rewrite(content: bytes, mutate) -> bytes:
    rows = list(
        csv.reader(io.StringIO(content.decode("utf-8"), newline=""))
    )
    mutate(rows)
    stream = io.StringIO(newline="")
    csv.writer(stream, lineterminator="\r\n").writerows(rows)
    return stream.getvalue().encode("utf-8")


class ResearchCsvArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = ResearchCsvSchema(("audience",))

    def test_renderer_is_deterministic_source_complete_and_excel_safe(self):
        records = batch(
            record("one", entity="=WEBSERVICE(\"unsafe\")"),
            record("two"),
        )
        first = render_research_csv(
            records,
            self.schema,
            requested_rows=2,
        )
        second = render_research_csv(
            records,
            self.schema,
            requested_rows=2,
        )
        self.assertEqual(first.content, second.content)
        self.assertEqual(
            first.sha256,
            hashlib.sha256(first.content).hexdigest(),
        )
        self.assertEqual(first.schema_digest, self.schema.schema_digest)
        self.assertTrue(first.complete)
        self.assertIsNone(first.partial_reason)

        rows = list(
            csv.reader(
                io.StringIO(first.content.decode("utf-8"), newline="")
            )
        )
        self.assertEqual(rows[0], list(self.schema.columns))
        self.assertTrue(rows[1][0].startswith("'="))
        for source_index in (1, 3, 5, 7):
            sources = json.loads(rows[1][source_index])
            self.assertTrue(sources)
            self.assertTrue(
                all(url.startswith("https://") for url in sources)
            )

        inspected = inspect_research_csv(
            first.content,
            self.schema,
            requested_rows=2,
            maximum_bytes=64 * 1024,
        )
        self.assertTrue(inspected.structurally_valid)
        self.assertTrue(inspected.complete)
        self.assertFalse(inspected.partial)
        self.assertEqual(inspected.row_count, 2)

    def test_shortfall_is_explicit_partial_and_never_padded(self):
        artifact = render_research_csv(
            batch(record("one")),
            self.schema,
            requested_rows=3,
        )
        self.assertEqual(artifact.row_count, 1)
        self.assertFalse(artifact.complete)
        self.assertEqual(
            artifact.partial_reason,
            "requested_rows_not_reached:1/3",
        )
        rows = list(
            csv.reader(
                io.StringIO(artifact.content.decode("utf-8"), newline="")
            )
        )
        self.assertEqual(len(rows) - 1, 1)

        inspected = inspect_research_csv(
            artifact.content,
            self.schema,
            requested_rows=3,
            maximum_bytes=64 * 1024,
        )
        self.assertTrue(inspected.structurally_valid)
        self.assertFalse(inspected.complete)
        self.assertTrue(inspected.partial)
        self.assertEqual(
            inspected.result_code,
            "research_csv_row_shortfall",
        )

    def test_schema_requires_exact_requested_fields_and_order(self):
        with self.assertRaisesRegex(ResearchCsvError, "match CSV schema"):
            render_research_csv(
                batch(record("one")),
                ResearchCsvSchema(("topic",)),
                requested_rows=1,
            )
        with self.assertRaisesRegex(ResearchCsvError, "must be unique"):
            ResearchCsvSchema(("audience", "audience"))
        with self.assertRaisesRegex(ResearchCsvError, "field ID"):
            ResearchCsvSchema(("entity_sources",))

    def test_inspector_rejects_duplicate_urls_and_missing_sources(self):
        valid = render_research_csv(
            batch(record("one"), record("two")),
            self.schema,
            requested_rows=2,
        ).content

        duplicated = rewrite(
            valid,
            lambda rows: rows[2].__setitem__(2, rows[1][2]),
        )
        inspection = inspect_research_csv(
            duplicated,
            self.schema,
            requested_rows=2,
            maximum_bytes=64 * 1024,
        )
        self.assertFalse(inspection.structurally_valid)
        self.assertFalse(inspection.partial)

        missing_sources = rewrite(
            valid,
            lambda rows: rows[1].__setitem__(5, "[]"),
        )
        inspection = inspect_research_csv(
            missing_sources,
            self.schema,
            requested_rows=2,
            maximum_bytes=64 * 1024,
        )
        self.assertFalse(inspection.structurally_valid)

    def test_inspector_rejects_unsafe_sources_schema_and_noncanonical_bytes(self):
        valid = render_research_csv(
            batch(record("one")),
            self.schema,
            requested_rows=1,
        ).content
        private_source = rewrite(
            valid,
            lambda rows: rows[1].__setitem__(
                1,
                '["http://127.0.0.1/private"]',
            ),
        )
        wrong_schema = rewrite(
            valid,
            lambda rows: rows[0].__setitem__(0, "name"),
        )
        formula = rewrite(
            valid,
            lambda rows: rows[1].__setitem__(0, "=CMD()"),
        )
        noncanonical = valid.replace(b"\r\n", b"\n")
        for content in (
            private_source,
            wrong_schema,
            formula,
            noncanonical,
        ):
            with self.subTest(content=content[:32]):
                inspection = inspect_research_csv(
                    content,
                    self.schema,
                    requested_rows=1,
                    maximum_bytes=64 * 1024,
                )
                self.assertFalse(inspection.structurally_valid)
                self.assertFalse(inspection.complete)

    def test_inspector_enforces_output_size_and_requested_count(self):
        valid = render_research_csv(
            batch(record("one")),
            self.schema,
            requested_rows=1,
        ).content
        oversized = inspect_research_csv(
            valid,
            self.schema,
            requested_rows=1,
            maximum_bytes=len(valid) - 1,
        )
        self.assertFalse(oversized.structurally_valid)

        extra_row = rewrite(
            valid,
            lambda rows: rows.append(list(rows[1])),
        )
        extra = inspect_research_csv(
            extra_row,
            self.schema,
            requested_rows=1,
            maximum_bytes=64 * 1024,
        )
        self.assertFalse(extra.structurally_valid)


if __name__ == "__main__":
    unittest.main()
