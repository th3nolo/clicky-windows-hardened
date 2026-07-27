"""Bounded transcription terms that the user explicitly approved."""

from __future__ import annotations

import unicodedata
from collections.abc import Sequence


SHIPPED_TERMS = ("Clicky",)
MAX_VOCABULARY_TERMS = 64
MAX_USER_TERMS = MAX_VOCABULARY_TERMS - len(SHIPPED_TERMS)
MAX_TERM_CHARACTERS = 64


class VocabularyError(ValueError):
    """A proposed user vocabulary exceeds the reviewed boundary."""


def _clean_term(value: object) -> str:
    if not isinstance(value, str):
        return ""
    normalized = unicodedata.normalize("NFKC", value)
    if any(unicodedata.category(char).startswith("C") for char in normalized):
        return ""
    term = " ".join(normalized.split()).strip()
    if not term or len(term) > MAX_TERM_CHARACTERS:
        return ""
    return term


def sanitize_user_terms(terms: Sequence[object]) -> tuple[str, ...]:
    """Safely load an untrusted preference without expanding its boundary."""

    clean = []
    seen = {term.casefold() for term in SHIPPED_TERMS}
    for value in terms:
        if len(clean) >= MAX_USER_TERMS:
            break
        term = _clean_term(value)
        if not term or term.casefold() in seen:
            continue
        seen.add(term.casefold())
        clean.append(term)
    return tuple(clean)


def validate_user_terms(terms: Sequence[object]) -> tuple[str, ...]:
    """Validate terms submitted by the explicit vocabulary editor."""

    if not isinstance(terms, (list, tuple)):
        raise VocabularyError("Vocabulary must be a list of terms")
    clean = []
    seen = {term.casefold() for term in SHIPPED_TERMS}
    for value in terms:
        if not isinstance(value, str) or not value.strip():
            continue
        term = _clean_term(value)
        if not term:
            raise VocabularyError(
                f"Each term must be printable and at most "
                f"{MAX_TERM_CHARACTERS} characters"
            )
        folded = term.casefold()
        if folded in seen:
            continue
        seen.add(folded)
        clean.append(term)
        if len(clean) > MAX_USER_TERMS:
            raise VocabularyError(
                f"At most {MAX_USER_TERMS} user-approved terms are allowed"
            )
    return tuple(clean)


def approved_vocabulary(user_terms: Sequence[object]) -> tuple[str, ...]:
    """Shipped product terms plus the bounded user-approved preference."""

    return SHIPPED_TERMS + sanitize_user_terms(user_terms)
