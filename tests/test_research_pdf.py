"""Deterministic inert PDF rendering and visible-text inspection tests."""

from __future__ import annotations

import hashlib
import io
import unittest

from research.docx_artifact import ResearchDocxParagraph
from research.markdown_artifact import (
    ResearchMarkdownSchema,
    render_research_markdown,
)
from research.pdf_artifact import (
    ResearchPdfError,
    _layout_paragraphs,
    _serialize_pdf,
    inspect_research_pdf,
    render_research_markdown_to_pdf,
    safe_pdf_text_preview,
    validate_safe_pdf_document,
)
from tests.test_research_csv import batch, record


class ResearchPdfArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema = ResearchMarkdownSchema(
            "Creator research",
            ("audience",),
        )
        self.report = render_research_markdown(
            batch(record("one")),
            self.schema,
            requested_sections=1,
        )
        self.artifact = render_research_markdown_to_pdf(
            self.report.content,
            self.schema,
            requested_sections=1,
            maximum_output_bytes=1024 * 1024,
        )

    def test_renderer_is_deterministic_and_exactly_self_verified(self):
        second = render_research_markdown_to_pdf(
            self.report.content,
            self.schema,
            requested_sections=1,
            maximum_output_bytes=1024 * 1024,
        )
        self.assertEqual(self.artifact.content, second.content)
        self.assertEqual(self.artifact.report_sha256, self.report.sha256)
        self.assertEqual(
            self.artifact.sha256,
            hashlib.sha256(self.artifact.content).hexdigest(),
        )
        self.assertTrue(self.artifact.content.startswith(b"%PDF-1.7"))
        for token in (
            b"/OpenAction",
            b"/JavaScript",
            b"/JS",
            b"/EmbeddedFile",
            b"/Annots",
            b"/AcroForm",
            b"/URI",
            b"/Encrypt",
        ):
            self.assertNotIn(token, self.artifact.content)

    def test_canonical_document_extracts_only_visible_report_paragraphs(self):
        document = validate_safe_pdf_document(self.artifact.content)
        self.assertEqual(document.page_count, self.artifact.page_count)
        self.assertGreater(document.text_line_count, len(document.paragraphs))
        self.assertEqual(document.paragraphs[0].style, "Title")
        self.assertEqual(document.paragraphs[0].text, "Creator research")
        self.assertEqual(document.paragraphs[-3].text, "Sources")
        preview = safe_pdf_text_preview(self.artifact.content)
        self.assertIn("1. Creator one", preview)
        self.assertIn("S001: https://creator.example/one", preview)

        inspection = inspect_research_pdf(
            self.artifact.content,
            self.schema,
            requested_sections=1,
            maximum_bytes=1024 * 1024,
        )
        self.assertTrue(inspection.structurally_valid)
        self.assertEqual(inspection.section_count, 1)
        self.assertEqual(
            inspection.document_digest,
            self.artifact.document_digest,
        )
        self.assertEqual(
            inspection.source_digest,
            self.artifact.source_digest,
        )

    def test_active_features_xref_changes_and_text_tampering_are_rejected(self):
        active = self.artifact.content.replace(
            b"/Type /Catalog",
            b"/OpenAction 1 0 R",
            1,
        )
        changed_xref = self.artifact.content.replace(
            b"0000000015 00000 n ",
            b"0000000016 00000 n ",
            1,
        )
        title_hex = "Creator research".encode("cp1252").hex().upper().encode()
        changed_hex = "Creator researck".encode("cp1252").hex().upper().encode()
        changed_text = self.artifact.content.replace(
            title_hex,
            changed_hex,
            1,
        )
        with self.assertRaises(ResearchPdfError):
            validate_safe_pdf_document(active)
        with self.assertRaises(ResearchPdfError):
            validate_safe_pdf_document(changed_xref)
        self.assertFalse(
            inspect_research_pdf(
                changed_text,
                self.schema,
                requested_sections=1,
                maximum_bytes=1024 * 1024,
            ).structurally_valid
        )

    def test_layout_pages_are_bounded_and_reconstruct_exact_paragraph_text(self):
        paragraphs = (
            ResearchDocxParagraph("Title", "Long report"),
            ResearchDocxParagraph("Body", "word " * 3_000),
        )
        content = _serialize_pdf(_layout_paragraphs(paragraphs))
        document = validate_safe_pdf_document(content)
        self.assertGreater(document.page_count, 1)
        self.assertEqual(document.paragraphs, paragraphs)

    def test_incomplete_markdown_and_unsupported_glyphs_fail_before_output(self):
        short = render_research_markdown(
            batch(record("one")),
            self.schema,
            requested_sections=2,
        )
        with self.assertRaisesRegex(ResearchPdfError, "not complete"):
            render_research_markdown_to_pdf(
                short.content,
                self.schema,
                requested_sections=2,
                maximum_output_bytes=1024 * 1024,
            )

        emoji_schema = ResearchMarkdownSchema(
            "Creator research \U0001f680",
            ("audience",),
        )
        emoji_report = render_research_markdown(
            batch(record("one")),
            emoji_schema,
            requested_sections=1,
        )
        with self.assertRaisesRegex(
            ResearchPdfError,
            "unsupported character",
        ):
            render_research_markdown_to_pdf(
                emoji_report.content,
                emoji_schema,
                requested_sections=1,
                maximum_output_bytes=1024 * 1024,
            )

    def test_pinned_pypdf_extracts_visible_text_when_available(self):
        try:
            from pypdf import PdfReader
        except ImportError:
            self.skipTest("pypdf is Windows-runtime-only in this lane")
        reader = PdfReader(io.BytesIO(self.artifact.content), strict=True)
        self.assertEqual(len(reader.pages), self.artifact.page_count)
        extracted = "\n".join(
            page.extract_text() or ""
            for page in reader.pages
        )
        self.assertIn("Creator research", extracted)
        self.assertIn("1. Creator one", extracted)
        self.assertIn("https://creator.example/one", extracted)


if __name__ == "__main__":
    unittest.main()
