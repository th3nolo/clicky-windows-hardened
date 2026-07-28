"""Source-evidence, URL canonicalization, and research-record limit tests."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from research.models import (
    DuplicateResearchRecordError,
    ResearchBatch,
    ResearchField,
    ResearchLimits,
    ResearchRecord,
    ResearchValidationError,
    ResearchValue,
    canonicalize_public_url,
)


NOW = datetime(2026, 7, 27, 12, 0, tzinfo=timezone.utc)
SOURCE = "https://Evidence.Example:443/source?b=2&a=1#section"


def value(text: str, source: str = SOURCE) -> ResearchValue:
    return ResearchValue(text, (source,))


def record(
    public_url: str = "https://Example.com/creator/#profile",
    *,
    field_count: int = 1,
) -> ResearchRecord:
    return ResearchRecord(
        entity=value("Example Creator"),
        public_url=value(public_url, public_url),
        requested_fields=tuple(
            ResearchField(
                f"attribute_{index}",
                value(f"Value {index}"),
            )
            for index in range(field_count)
        ),
        rationale=value("Relevant to the requested public topic."),
        retrieved_at=NOW,
    )


def limits(**overrides: int) -> ResearchLimits:
    values = {
        "max_rows": 10,
        "max_fields_per_record": 4,
        "max_sources_per_record": 8,
        "max_total_sources": 20,
        "max_output_bytes": 64 * 1024,
    }
    values.update(overrides)
    return ResearchLimits(**values)


class PublicUrlCanonicalizationTests(unittest.TestCase):
    def test_normalizes_identity_without_hiding_unsupported_authority(self):
        self.assertEqual(
            canonicalize_public_url(
                "HTTPS://Example.COM:443/a/../creator/"
                "?z=2&a=hello%20world#profile"
            ),
            "https://example.com/creator/?a=hello+world&z=2",
        )
        self.assertEqual(
            canonicalize_public_url("http://example.com:80"),
            "http://example.com/",
        )

    def test_rejects_credentials_local_targets_and_unsupported_schemes(self):
        rejected = (
            "file:///etc/passwd",
            "ftp://example.com/file",
            "https://user:secret@example.com/",
            "https://localhost/",
            "https://service.internal/",
            "https://127.0.0.1/",
            "https://10.0.0.1/",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/",
            "https://example.com/%zz",
            "https://example.com/\nnext",
        )
        for url in rejected:
            with self.subTest(url=url), self.assertRaises(
                ResearchValidationError
            ):
                canonicalize_public_url(url)

    def test_network_tool_mode_requires_https(self):
        with self.assertRaisesRegex(
            ResearchValidationError,
            "scheme",
        ):
            canonicalize_public_url(
                "http://example.com/source",
                require_https=True,
            )


class ResearchRecordTests(unittest.TestCase):
    def test_every_factual_value_requires_inspectable_source_evidence(self):
        item = record()
        self.assertEqual(
            item.canonical_public_url,
            "https://example.com/creator/",
        )
        self.assertEqual(
            item.entity.source_urls,
            ("https://evidence.example/source?a=1&b=2",),
        )
        self.assertTrue(item.all_source_urls)
        self.assertEqual(
            item.canonical_payload()["requested_fields"][0]["field_id"],
            "attribute_0",
        )

        with self.assertRaisesRegex(
            ResearchValidationError,
            "source evidence",
        ):
            ResearchValue("Unsupported fact", ())

    def test_fields_are_typed_unique_and_retrieval_time_is_aware(self):
        duplicate = ResearchField("audience", value("Developers"))
        with self.assertRaisesRegex(
            ResearchValidationError,
            "unique",
        ):
            ResearchRecord(
                entity=value("Creator"),
                public_url=value(
                    "https://example.com/creator",
                    "https://example.com/creator",
                ),
                requested_fields=(duplicate, duplicate),
                rationale=value("Relevant."),
                retrieved_at=NOW,
            )
        with self.assertRaisesRegex(
            ResearchValidationError,
            "timezone-aware",
        ):
            ResearchRecord(
                entity=value("Creator"),
                public_url=value(
                    "https://example.com/creator",
                    "https://example.com/creator",
                ),
                requested_fields=(),
                rationale=value("Relevant."),
                retrieved_at=datetime(2026, 7, 27, 12, 0),
            )

    def test_batch_rejects_canonical_duplicates_instead_of_counting_them(
        self,
    ):
        first = record("https://EXAMPLE.com:443/creator#one")
        duplicate = record("https://example.com/creator#two")
        with self.assertRaisesRegex(
            DuplicateResearchRecordError,
            "Duplicate canonical",
        ):
            ResearchBatch((first, duplicate), limits())

    def test_batch_enforces_rows_fields_sources_and_total_bytes(self):
        with self.assertRaisesRegex(
            ResearchValidationError,
            "row limit",
        ):
            ResearchBatch(
                (
                    record("https://example.com/a"),
                    record("https://example.com/b"),
                ),
                limits(max_rows=1),
            )
        with self.assertRaisesRegex(
            ResearchValidationError,
            "field limit",
        ):
            ResearchBatch(
                (record(field_count=2),),
                limits(max_fields_per_record=1),
            )
        with self.assertRaisesRegex(
            ResearchValidationError,
            "output limit",
        ):
            ResearchBatch(
                (record(),),
                limits(max_output_bytes=1),
            )


if __name__ == "__main__":
    unittest.main()
