import unittest
from tools.check_advisories import advisory_matches, locked_packages, NoRedirects


class AdvisoryTests(unittest.TestCase):
    def test_clean_complete_result(self):
        self.assertEqual(advisory_matches([("example", "1.0")], {"results": [{}]}), [])

    def test_match_blocks_instead_of_ignoring_advisory(self):
        self.assertEqual(advisory_matches([("example", "1.0")], {"results": [{"vulns": [{"id": "GHSA-1234"}]}]}), ["example==1.0: GHSA-1234"])

    def test_incomplete_or_malformed_results_fail_closed(self):
        for payload in [None, {"results": []}, {"results": [{"next_page_token": "more"}]}, {"results": [{"error": "unavailable"}]}, {"results": [{"vulns": None}]}, {"results": [{"vulns": [{"id": "bad\ncontent"}]}]}]:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                advisory_matches([("example", "1.0")], payload)

    def test_local_sources_and_credentials_cannot_enter_query(self):
        with self.assertRaises(ValueError):
            locked_packages({"package": [{"name": "example", "version": "1", "source": {"git": "https://private.invalid"}}]})

    def test_redirects_rejected_before_following(self):
        with self.assertRaises(ValueError):
            NoRedirects().redirect_request(None, None, 307, "", {}, "https://other.invalid")


if __name__ == "__main__":
    unittest.main()
