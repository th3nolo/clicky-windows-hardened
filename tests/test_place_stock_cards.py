"""Fail-closed place and end-of-day stock result cards."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from connectors.base import SecretValue
from data_providers.places import (
    NominatimPlaceProvider,
    PlaceHttpResponse,
    PlaceProviderDisabledError,
    PlaceProviderError,
    PlaceProviderRateLimitError,
    PlaceSearchRequest,
    ReviewedNominatimEndpoint,
)
from data_providers.stocks import (
    ALPHA_VANTAGE_ENDPOINT,
    AlphaVantageEndOfDayProvider,
    MarketDataDisabledError,
    MarketDataError,
    MarketHttpResponse,
    StockQuoteRequest,
)
from widgets.result_cards import place_result_card, stock_result_card


NOW = datetime(2026, 7, 28, 12, 0, tzinfo=timezone.utc)
PRIVATE_NOMINATIM = "https://maps.example.test/nominatim/search"


class FakeClock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value


class PlaceTransport:
    def __init__(self, values: list[dict]) -> None:
        self.values = values
        self.calls: list[tuple[str, dict[str, str], int]] = []

    def search(self, *, endpoint, query, maximum_response_bytes):
        self.calls.append(
            (endpoint.search_url, dict(query), maximum_response_bytes)
        )
        return PlaceHttpResponse(
            status=200,
            content_type="application/json; charset=utf-8",
            body=json.dumps(self.values).encode("utf-8"),
        )


class StockTransport:
    def __init__(self, *, trading_day: str = "2026-07-27") -> None:
        self.trading_day = trading_day
        self.calls: list[tuple[str, dict[str, str], int]] = []

    def quote(self, *, endpoint, query, maximum_response_bytes):
        self.calls.append((endpoint, dict(query), maximum_response_bytes))
        return MarketHttpResponse(
            status=200,
            content_type="application/json",
            body=json.dumps(
                {
                    "Global Quote": {
                        "01. symbol": query["symbol"],
                        "05. price": "237.1250",
                        "07. latest trading day": self.trading_day,
                        "09. change": "-1.2500",
                        "10. change percent": "-0.5245%",
                    }
                }
            ).encode("utf-8"),
        )


def place_payload() -> list[dict]:
    return [
        {
            "display_name": "Caracas, Distrito Capital, Venezuela",
            "lat": "10.4806",
            "lon": "-66.9036",
            "category": "place",
            "type": "city",
        }
    ]


class PlaceCardTests(unittest.TestCase):
    def test_public_or_unreviewed_nominatim_is_rejected(self):
        with self.assertRaises(ValueError):
            ReviewedNominatimEndpoint(
                "public",
                "https://nominatim.openstreetmap.org/search",
            )
        with self.assertRaises(PlaceProviderDisabledError):
            NominatimPlaceProvider(
                "missing",
                feature_enabled=True,
                external_search_consent=True,
            )

    def test_place_search_is_explicit_consent_gated_and_fixed(self):
        with self.assertRaises(ValueError):
            PlaceSearchRequest(query="Caracas")

        transport = PlaceTransport(place_payload())
        provider = NominatimPlaceProvider(
            "private",
            feature_enabled=False,
            external_search_consent=True,
            endpoints={"private": PRIVATE_NOMINATIM},
            transport=transport,
        )
        with self.assertRaises(PlaceProviderDisabledError):
            provider.search(
                PlaceSearchRequest(query="Caracas", user_initiated=True),
                now=NOW,
            )
        self.assertEqual(transport.calls, [])

    def test_place_result_has_source_freshness_no_actions_and_cache(self):
        clock = FakeClock()
        transport = PlaceTransport(place_payload())
        provider = NominatimPlaceProvider(
            "private",
            feature_enabled=True,
            external_search_consent=True,
            endpoints={"private": PRIVATE_NOMINATIM},
            transport=transport,
            monotonic=clock,
        )
        request = PlaceSearchRequest(query="Caracas", user_initiated=True)
        first = provider.search(request, now=NOW)
        second = provider.search(request, now=NOW)

        self.assertIs(first, second)
        self.assertEqual(len(transport.calls), 1)
        endpoint, query, _maximum = transport.calls[0]
        self.assertEqual(endpoint, PRIVATE_NOMINATIM)
        self.assertEqual(query["q"], "Caracas")
        self.assertEqual(query["limit"], "5")

        card = place_result_card(first[0], now=NOW)
        self.assertEqual(card.actions, ())
        self.assertEqual(card.freshness_label, "Fresh")
        self.assertIn("OpenStreetMap", card.source_label)
        self.assertIn("ODbL", card.attribution)

    def test_place_provider_rate_limit_and_bad_shape_fail_closed(self):
        clock = FakeClock()
        transport = PlaceTransport(place_payload())
        provider = NominatimPlaceProvider(
            "private",
            feature_enabled=True,
            external_search_consent=True,
            endpoints={"private": PRIVATE_NOMINATIM},
            transport=transport,
            monotonic=clock,
        )
        provider.search(
            PlaceSearchRequest(query="Caracas", user_initiated=True),
            now=NOW,
        )
        with self.assertRaises(PlaceProviderRateLimitError):
            provider.search(
                PlaceSearchRequest(query="Valencia", user_initiated=True),
                now=NOW,
            )

        invalid = PlaceTransport([{"display_name": "Unknown"}])
        invalid_provider = NominatimPlaceProvider(
            "private",
            feature_enabled=True,
            external_search_consent=True,
            endpoints={"private": PRIVATE_NOMINATIM},
            transport=invalid,
        )
        with self.assertRaises(PlaceProviderError):
            invalid_provider.search(
                PlaceSearchRequest(query="Unknown", user_initiated=True),
                now=NOW,
            )


class StockCardTests(unittest.TestCase):
    def test_stock_quote_requires_explicit_action_consent_and_license(self):
        with self.assertRaises(ValueError):
            StockQuoteRequest(symbol="MSFT")

        for enabled, consent, license_confirmed in (
            (False, True, True),
            (True, False, True),
            (True, True, False),
        ):
            transport = StockTransport()
            provider = AlphaVantageEndOfDayProvider(
                api_key=SecretValue(b"redacted-test-key"),
                feature_enabled=enabled,
                market_data_consent=consent,
                license_confirmed=license_confirmed,
                transport=transport,
            )
            with self.assertRaises(MarketDataDisabledError):
                provider.quote(
                    StockQuoteRequest(symbol="MSFT", user_initiated=True),
                    now=NOW,
                )
            self.assertEqual(transport.calls, [])

    def test_stock_quote_is_fixed_read_only_and_labeled(self):
        transport = StockTransport()
        secret = SecretValue(b"redacted-test-key")
        provider = AlphaVantageEndOfDayProvider(
            api_key=secret,
            feature_enabled=True,
            market_data_consent=True,
            license_confirmed=True,
            transport=transport,
        )
        quote = provider.quote(
            StockQuoteRequest(symbol="MSFT", user_initiated=True),
            now=NOW,
        )
        endpoint, query, _maximum = transport.calls[0]
        self.assertEqual(endpoint, ALPHA_VANTAGE_ENDPOINT)
        self.assertEqual(query["function"], "GLOBAL_QUOTE")
        self.assertEqual(query["apikey"], "redacted-test-key")
        self.assertNotIn("redacted-test-key", repr(secret))
        self.assertEqual(quote.freshness, "end_of_day")
        self.assertIsNone(quote.currency)

        card = stock_result_card(quote, now=NOW)
        self.assertEqual(card.actions, ())
        self.assertIn("End-of-day", card.freshness_label)
        self.assertIn("not investment advice", card.informational_notice)
        self.assertIn("Alpha Vantage", card.source_label)

    def test_old_market_data_is_not_refreshed_by_retrieval(self):
        provider = AlphaVantageEndOfDayProvider(
            api_key=SecretValue(b"redacted-test-key"),
            feature_enabled=True,
            market_data_consent=True,
            license_confirmed=True,
            transport=StockTransport(trading_day="2026-07-01"),
        )
        quote = provider.quote(
            StockQuoteRequest(symbol="MSFT", user_initiated=True),
            now=NOW,
        )
        self.assertTrue(quote.is_stale(NOW))
        self.assertIn(
            "Stale",
            stock_result_card(quote, now=NOW).freshness_label,
        )

    def test_future_market_date_fails_closed(self):
        provider = AlphaVantageEndOfDayProvider(
            api_key=SecretValue(b"redacted-test-key"),
            feature_enabled=True,
            market_data_consent=True,
            license_confirmed=True,
            transport=StockTransport(trading_day="2026-07-29"),
        )
        with self.assertRaises(MarketDataError):
            provider.quote(
                StockQuoteRequest(symbol="MSFT", user_initiated=True),
                now=NOW,
            )


if __name__ == "__main__":
    unittest.main()
