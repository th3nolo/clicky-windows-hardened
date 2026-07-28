"""Bounded task-tool research adapter tests."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from research.models import ResearchValidationError
from research.tools import (
    BoundedResearchToolAdapter,
    ResearchToolError,
    ResearchToolLimitError,
    ResearchToolLimits,
)


ROOT = Path(__file__).resolve().parents[1]


class BoundedResearchToolAdapterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.search_calls: list[tuple[str, int]] = []
        self.fetch_calls: list[tuple[str, int]] = []
        self.search_text = (
            "[1] First Source — "
            "https://EXAMPLE.com:443/creator?b=2&a=1#profile\n"
            "First bounded excerpt.\n\n"
            "[2] Duplicate Source — "
            "https://example.com/creator?a=1&b=2#other\n"
            "Duplicate excerpt.\n\n"
            "[3] Unsafe Source — https://127.0.0.1/admin\n"
            "Must be discarded.\n\n"
            "[4] Second Source — https://other.example/page\n"
            "Second bounded excerpt."
        )
        self.fetch_text = "bounded public evidence"

        async def search(query: str, max_results: int) -> str:
            self.search_calls.append((query, max_results))
            return self.search_text

        async def fetch(url: str, max_chars: int) -> str:
            self.fetch_calls.append((url, max_chars))
            return self.fetch_text

        self.fetch_adapter = fetch
        self.adapter = BoundedResearchToolAdapter(
            ResearchToolLimits(
                max_requests=12,
                max_response_bytes=4_096,
                max_sources=4,
            ),
            search_adapter=search,
            fetch_adapter=fetch,
        )

    async def test_search_keeps_only_unique_public_https_sources(self):
        result = await self.adapter.search("public creator research", 4)
        self.assertIn(
            "[1] First Source — https://example.com/creator?a=1&b=2",
            result,
        )
        self.assertIn(
            "[2] Second Source — https://other.example/page",
            result,
        )
        self.assertNotIn("Duplicate Source", result)
        self.assertNotIn("127.0.0.1", result)
        self.assertEqual(
            self.adapter.snapshot.physical_requests_charged,
            6,
        )
        self.assertEqual(
            self.adapter.snapshot.unique_sources_observed,
            2,
        )

    async def test_fetch_canonicalizes_before_existing_hardened_path(self):
        fetched = await self.adapter.fetch(
            "HTTPS://Evidence.Example:443/a/../page#fragment",
            100,
        )
        self.assertEqual(fetched, self.fetch_text)
        self.assertEqual(
            self.fetch_calls,
            [("https://evidence.example/page", 100)],
        )

    async def test_private_and_unsupported_fetches_fail_before_adapter(self):
        for url in (
            "http://example.com/page",
            "https://127.0.0.1/admin",
            "file:///etc/passwd",
        ):
            with self.subTest(url=url), self.assertRaises(
                ResearchValidationError
            ):
                await self.adapter.fetch(url, 100)
        self.assertEqual(self.fetch_calls, [])

    async def test_physical_request_limit_is_charged_before_side_effect(self):
        calls = 0

        async def search(_query: str, _max_results: int) -> str:
            nonlocal calls
            calls += 1
            return ""

        adapter = BoundedResearchToolAdapter(
            ResearchToolLimits(
                max_requests=4,
                max_response_bytes=100,
            ),
            search_adapter=search,
            fetch_adapter=self.fetch_adapter,
        )
        with self.assertRaisesRegex(
            ResearchToolLimitError,
            "request limit",
        ):
            await adapter.search("query", 3)
        self.assertEqual(calls, 0)
        self.assertEqual(
            adapter.snapshot.physical_requests_charged,
            0,
        )

    async def test_response_bytes_and_fetch_chars_fail_closed(self):
        async def oversized_search(_query: str, _maximum: int) -> str:
            return "x" * 101

        adapter = BoundedResearchToolAdapter(
            ResearchToolLimits(
                max_requests=8,
                max_response_bytes=100,
            ),
            search_adapter=oversized_search,
            fetch_adapter=self.fetch_adapter,
        )
        with self.assertRaisesRegex(
            ResearchToolLimitError,
            "response-byte",
        ):
            await adapter.search("query", 1)

        self.fetch_text = "x" * 101
        with self.assertRaisesRegex(
            ResearchToolError,
            "invalid bounded response",
        ):
            await self.adapter.fetch(
                "https://example.com/oversized",
                100,
            )

    async def test_malformed_non_text_responses_are_not_exposed(self):
        async def malformed(_query: str, _maximum: int):
            return {"url": "https://example.com/"}

        adapter = BoundedResearchToolAdapter(
            ResearchToolLimits(
                max_requests=8,
                max_response_bytes=100,
            ),
            search_adapter=malformed,
            fetch_adapter=self.fetch_adapter,
        )
        with self.assertRaisesRegex(ResearchToolError, "must be text"):
            await adapter.search("query", 1)

    def test_research_layer_has_no_browser_connector_shell_or_filesystem(self):
        forbidden_modules = {
            "connectors",
            "os",
            "pathlib",
            "selenium",
            "subprocess",
            "uiautomation",
            "webbrowser",
        }
        for relative in (
            "research/models.py",
            "research/tools.py",
        ):
            tree = ast.parse(
                (ROOT / relative).read_text(encoding="utf-8"),
                filename=relative,
            )
            imported = {
                alias.name.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, (ast.Import, ast.ImportFrom))
                for alias in (
                    node.names
                    if isinstance(node, ast.Import)
                    else (ast.alias(node.module or ""),)
                )
            }
            self.assertFalse(
                imported & forbidden_modules,
                f"{relative} imports forbidden authority",
            )


if __name__ == "__main__":
    unittest.main()
