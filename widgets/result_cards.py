"""Read-only, source-and-freshness-labeled place and stock card models."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from data_providers.places import PlaceResult
from data_providers.stocks import MARKET_DATA_NOTICE, StockQuote


@dataclass(frozen=True, slots=True)
class PlaceResultCard:
    title: str
    subtitle: str
    coordinates: str
    source_label: str
    attribution: str
    retrieved_at_label: str
    freshness_label: str
    actions: tuple[()] = ()


@dataclass(frozen=True, slots=True)
class StockResultCard:
    title: str
    price_label: str
    change_label: str
    as_of_label: str
    source_label: str
    freshness_label: str
    informational_notice: str
    currency_label: str = "Currency not provided by source"
    actions: tuple[()] = ()


def place_result_card(result: PlaceResult, *, now: datetime) -> PlaceResultCard:
    if not isinstance(result, PlaceResult):
        raise TypeError("A typed place result is required")
    if now.tzinfo is None:
        raise TypeError("Place card time must be timezone-aware")
    current = now.astimezone(timezone.utc)
    freshness = "Fresh" if current <= result.fresh_until else "Stale — refresh"
    return PlaceResultCard(
        title=result.display_name,
        subtitle=f"{result.category} · {result.place_type}",
        coordinates=f"{result.latitude}, {result.longitude}",
        source_label=f"Source: {result.source}",
        attribution=result.attribution,
        retrieved_at_label=(
            "Retrieved: " + result.retrieved_at.isoformat(timespec="seconds")
        ),
        freshness_label=freshness,
    )


def stock_result_card(quote: StockQuote, *, now: datetime) -> StockResultCard:
    if not isinstance(quote, StockQuote):
        raise TypeError("A typed stock quote is required")
    if now.tzinfo is None:
        raise TypeError("Stock card time must be timezone-aware")
    freshness = (
        "Stale end-of-day quote — refresh"
        if quote.is_stale(now)
        else "End-of-day quote"
    )
    sign = "+" if quote.change >= 0 else ""
    return StockResultCard(
        title=quote.symbol,
        price_label=f"Provider-reported price: {quote.price}",
        change_label=f"Change: {sign}{quote.change} ({sign}{quote.change_percent}%)",
        as_of_label=f"As of trading date: {quote.as_of_date.isoformat()}",
        source_label=f"Source: {quote.source}",
        freshness_label=freshness,
        informational_notice=MARKET_DATA_NOTICE,
    )


__all__ = [
    "PlaceResultCard",
    "StockResultCard",
    "place_result_card",
    "stock_result_card",
]
