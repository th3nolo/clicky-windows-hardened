"""Independent, output-only checks for notebook teaching batches.

The teaching writer is allowed to propose notebook mutations, but it is not an
oracle for what was visibly rendered.  This module therefore sends one fresh
reader request with only a result crop and a fixed observation schema.  The
local caller compares that observation with its retained requirements *after*
the request.  Expected text, writer prompts, tool history, and source imagery
are intentionally absent from the reader request.

This is a visual readback boundary, not a mathematical proof engine.  It can
compare explicitly required labels, symbols, and visible objects; uncertain
readings remain unresolved.  In teaching mode prose can be paraphrased.  In
exact-copy mode a separate exact visible-text comparison is required.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable, Sequence
from contextlib import aclosing
from dataclasses import dataclass
from enum import Enum


MAX_OUTPUT_CROPS = 2
MAX_CROP_CHARS = 12 * 1024 * 1024
MAX_READER_RESPONSE_CHARS = 16 * 1024
MAX_VISIBLE_TEXT_CHARS = 4_000
MAX_OBSERVED_ITEMS = 48
MAX_ITEM_CHARS = 160
SCHEMA = "clicky.teaching_output_observation"
SCHEMA_VERSION = 1
VISIBLE_OBJECT_KINDS = frozenset({
    "row_vector", "column_vector", "matrix", "arrow", "enclosure", "sentence", "heading", "label",
})


class VerificationMode(str, Enum):
    """How strictly a requested component's prose is compared."""

    TEACHING = "teaching"
    EXACT_COPY = "exact_copy"


@dataclass(frozen=True, slots=True)
class TeachingComponent:
    """Local requirements for one visible teaching component.

    ``exact_text`` is used only in :attr:`VerificationMode.EXACT_COPY`.
    ``crop_index`` binds this component to one immutable output crop.  An
    expectation cannot aggregate multiple components into one crop because a
    single observed label would otherwise be able to satisfy each component.
    Required labels, symbols, and objects are atomic visual requirements;
    they deliberately do not encode a claim that string matching proves a
    mathematical statement is semantically correct.
    """

    component_id: str
    required_labels: tuple[str, ...] = ()
    required_symbols: tuple[str, ...] = ()
    required_symbol_sequence: tuple[str, ...] = ()
    required_objects: tuple[str, ...] = ()
    exact_text: str | None = None
    crop_index: int = 0

    def __post_init__(self) -> None:
        if not _valid_identifier(self.component_id):
            raise ValueError("Teaching component ID is invalid")
        _validate_items(self.required_labels, "required labels")
        _validate_items(self.required_symbols, "required symbols")
        _validate_items(self.required_symbol_sequence, "required symbol sequence")
        _validate_objects(self.required_objects, "required objects")
        if self.required_symbol_sequence and self.required_symbol_sequence != self.required_symbols:
            raise ValueError("Teaching component symbol sequence must preserve required symbols")
        if not (self.required_labels or self.required_symbols or self.required_objects):
            raise ValueError("Teaching component needs at least one visual evidence requirement")
        if self.exact_text is not None:
            if not isinstance(self.exact_text, str) or len(self.exact_text) > MAX_VISIBLE_TEXT_CHARS:
                raise ValueError("Exact text is invalid or too long")
        if type(self.crop_index) is not int or self.crop_index < 0:
            raise ValueError("Teaching component crop index is invalid")


@dataclass(frozen=True, slots=True)
class TeachingExpectation:
    """A local contract never passed to the independent output reader.

    At most two components are supported because every component must have a
    distinct, indexed crop and causes one bounded fresh reader request.
    """

    components: tuple[TeachingComponent, ...]

    def __post_init__(self) -> None:
        if not self.components or len(self.components) > MAX_OUTPUT_CROPS:
            raise ValueError("Teaching expectations need between one and two components")
        if len({component.component_id for component in self.components}) != len(self.components):
            raise ValueError("Teaching component IDs must be unique")
        indexes = {component.crop_index for component in self.components}
        if len(indexes) != len(self.components):
            raise ValueError("Every teaching component must use one distinct output crop")


@dataclass(frozen=True, slots=True)
class OutputObservation:
    """A bounded, schema-validated visual transcription from a fresh reader."""

    visible_text: str
    labels: tuple[str, ...]
    symbols: tuple[str, ...]
    entry_symbol_sequence: tuple[str, ...]
    objects: tuple[str, ...]
    uncertainties: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ComponentComparison:
    component_id: str
    crop_index: int
    missing_labels: tuple[str, ...]
    missing_symbols: tuple[str, ...]
    symbol_sequence_matches: bool | None
    missing_objects: tuple[str, ...]
    exact_text_matches: bool | None

    @property
    def satisfied(self) -> bool:
        return not (
            self.missing_labels
            or self.missing_symbols
            or self.symbol_sequence_matches is False
            or self.missing_objects
            or self.exact_text_matches is False
        )


@dataclass(frozen=True, slots=True)
class TeachingVerification:
    """Comparison evidence suitable for a controller's completion decision."""

    accepted: bool
    outcome: str
    observations: tuple[OutputObservation, ...]
    components: tuple[ComponentComparison, ...]
    unresolved: tuple[str, ...]
    parse_error: str | None = None

    @property
    def observation(self) -> OutputObservation | None:
        """Compatibility accessor for a single-component verification only."""
        return self.observations[0] if len(self.observations) == 1 else None

    @property
    def missing_component_ids(self) -> tuple[str, ...]:
        return tuple(component.component_id for component in self.components if not component.satisfied)


OUTPUT_READER_SYSTEM = (
    "You are an independent visual reader for a notebook output crop. "
    "Report only what is visibly readable in the attached output crop. "
    "You have no source page, expected answer, writer plan, tool history, or authority to approve completion. "
    "Do not infer missing mathematics or repair garbled ink. Do not claim semantic mathematical correctness. "
    "If a mark, label, symbol, order, or shape is ambiguous, record it in uncertainties. "
    "Return one JSON object only, with no Markdown."
)

_READER_PROMPT = json.dumps(
    {
        "schema": SCHEMA,
        "version": SCHEMA_VERSION,
        "instruction": (
            "Transcribe the supplied output crop only. labels are readable word or short-label strings; "
            "symbols use canonical visual names such as alpha, times, plus, minus, equals, left_bracket, "
            "or right_bracket; objects use only row_vector, column_vector, matrix, arrow, enclosure, sentence, heading, or label. "
            "symbols lists every standalone mathematical mark in the crop. entry_symbol_sequence lists only the entries inside "
            "one clear vector or matrix group in reading order; exclude enclosing brackets, labels, and dimension labels from that sequence. "
            "Never deduplicate symbols. If a numeric mark cannot be assigned clearly, record it in uncertainties. "
            "Put every uncertain or unreadable matter in uncertainties."
        ),
        "response": {
            "schema": SCHEMA,
            "version": SCHEMA_VERSION,
            "visible_text": "visible text in reading order, or empty string",
            "labels": ["readable short label"],
            "symbols": ["canonical symbol"],
            "entry_symbol_sequence": ["vector or matrix entry in visible order"],
            "objects": ["visible object kind"],
            "uncertainties": ["specific uncertain visible item"],
        },
    },
    separators=(",", ":"),
)


async def verify_teaching_output(
    provider: object,
    model: str,
    output_crops: str | Sequence[str],
    expectation: TeachingExpectation,
    *,
    mode: VerificationMode = VerificationMode.TEACHING,
) -> TeachingVerification:
    """Read one fresh crop for each component and compare locally.

    The provider must implement Clicky's ordinary ``stream_response`` method.
    Each reader request receives exactly one output crop and an empty history;
    it cannot receive writer context through this API. Provider failures
    propagate so callers cannot convert an unperformed inspection into
    completion.
    """
    if not isinstance(mode, VerificationMode):
        raise ValueError("Unknown teaching verification mode")
    crops = _validated_crops(output_crops)
    stream_response = getattr(provider, "stream_response", None)
    if not callable(stream_response):
        raise TypeError("Provider does not support a fresh output-reader request")
    if len(crops) != len(expectation.components):
        raise ValueError("Every teaching component needs its own output crop")
    if {component.crop_index for component in expectation.components} != set(range(len(crops))):
        raise ValueError("Teaching component crop indexes must match the supplied output crops")
    observations: list[OutputObservation] = []
    comparisons: list[ComponentComparison] = []
    unresolved: list[str] = []
    for component in sorted(expectation.components, key=lambda item: item.crop_index):
        response = ""
        # This intentionally contains one immutable crop.  A component cannot
        # borrow a repeated label or symbol observed in another component.
        stream = stream_response(
            _READER_PROMPT, [crops[component.crop_index]], [], OUTPUT_READER_SYSTEM, model=model,
        )
        # Reader streams can continue producing billed output after a local
        # bound rejects their first oversized chunk. Explicitly close the
        # provider generator on every return or exception from this loop.
        async with aclosing(stream):
            async for chunk in stream:
                if not isinstance(chunk, str):
                    raise ValueError("Output reader returned a non-text chunk")
                response += chunk
                if len(response) > MAX_READER_RESPONSE_CHARS:
                    return _failed_verification(expectation, "Output reader response exceeded its limit")
        try:
            observation = parse_output_observation(response)
        except ValueError as error:
            return _failed_verification(expectation, str(error))
        observations.append(observation)
        component_result = compare_teaching_output(
            observation, TeachingExpectation((component,)), mode=mode,
        )
        comparisons.extend(component_result.components)
        unresolved.extend(component_result.unresolved)
    accepted = not unresolved and all(comparison.satisfied for comparison in comparisons)
    return TeachingVerification(
        accepted=accepted,
        outcome="verified" if accepted else "needs_review",
        observations=tuple(observations),
        components=tuple(comparisons),
        unresolved=tuple(unresolved),
    )


def parse_output_observation(response: str) -> OutputObservation:
    """Parse the exact bounded reader schema; malformed output is unresolved."""
    if not isinstance(response, str) or not response or len(response) > MAX_READER_RESPONSE_CHARS:
        raise ValueError("Output reader response is empty or exceeds its limit")
    try:
        payload = json.loads(response)
    except json.JSONDecodeError as error:
        raise ValueError("Output reader did not return complete JSON") from error
    if not isinstance(payload, dict) or set(payload) != {
        "schema", "version", "visible_text", "labels", "symbols", "entry_symbol_sequence", "objects", "uncertainties"
    }:
        raise ValueError("Output reader response has an unsupported schema")
    if payload["schema"] != SCHEMA or payload["version"] != SCHEMA_VERSION:
        raise ValueError("Output reader response has the wrong schema version")
    visible_text = payload["visible_text"]
    if not isinstance(visible_text, str) or len(visible_text) > MAX_VISIBLE_TEXT_CHARS:
        raise ValueError("Output reader visible text is invalid or too long")
    return OutputObservation(
        visible_text=visible_text,
        labels=_parse_items(payload["labels"], "labels"),
        symbols=_parse_items(payload["symbols"], "symbols"),
        entry_symbol_sequence=_parse_items(payload["entry_symbol_sequence"], "entry symbol sequence"),
        objects=_parse_objects(payload["objects"], "objects"),
        uncertainties=_parse_items(payload["uncertainties"], "uncertainties"),
    )


def compare_teaching_output(
    observation: OutputObservation,
    expectation: TeachingExpectation,
    *,
    mode: VerificationMode = VerificationMode.TEACHING,
) -> TeachingVerification:
    """Compare local requirements without treating a reader as a math oracle."""
    if not isinstance(mode, VerificationMode):
        raise ValueError("Unknown teaching verification mode")
    if len(expectation.components) != 1:
        raise ValueError("One observation can verify exactly one teaching component")
    observed_labels = Counter(_canonical_label(item) for item in observation.labels)
    observed_symbols = Counter(_canonical_symbol(item) for item in observation.symbols)
    observed_objects = Counter(_canonical(item) for item in observation.objects)
    comparisons: list[ComponentComparison] = []
    for component in expectation.components:
        missing_labels = _missing(component.required_labels, observed_labels, _canonical_label)
        missing_symbols = _missing(component.required_symbols, observed_symbols, _canonical_symbol)
        missing_objects = _missing(component.required_objects, observed_objects, _canonical)
        exact_match: bool | None = None
        sequence_match: bool | None = None
        if component.required_symbol_sequence:
            sequence_match = (
                tuple(_canonical_symbol(item) for item in observation.entry_symbol_sequence)
                == tuple(_canonical_symbol(item) for item in component.required_symbol_sequence)
            )
        if mode is VerificationMode.EXACT_COPY:
            if component.exact_text is None:
                raise ValueError("Exact-copy verification requires exact text for every component")
            exact_match = _normalize_exact_text(observation.visible_text) == _normalize_exact_text(component.exact_text)
        comparisons.append(ComponentComparison(
            component_id=component.component_id,
            crop_index=component.crop_index,
            missing_labels=missing_labels,
            missing_symbols=missing_symbols,
            symbol_sequence_matches=sequence_match,
            missing_objects=missing_objects,
            exact_text_matches=exact_match,
        ))
    unresolved = tuple(observation.uncertainties)
    accepted = not unresolved and all(item.satisfied for item in comparisons)
    return TeachingVerification(
        accepted=accepted,
        outcome="verified" if accepted else "needs_review",
        observations=(observation,),
        components=tuple(comparisons),
        unresolved=unresolved,
    )


def _failed_verification(expectation: TeachingExpectation, error: str) -> TeachingVerification:
    return TeachingVerification(
        accepted=False,
        outcome="needs_review",
        observations=(),
        components=tuple(
            ComponentComparison(
                component_id=component.component_id,
                crop_index=component.crop_index,
                missing_labels=component.required_labels,
                missing_symbols=component.required_symbols,
                symbol_sequence_matches=False if component.required_symbol_sequence else None,
                missing_objects=component.required_objects,
                exact_text_matches=False if component.exact_text is not None else None,
            )
            for component in expectation.components
        ),
        unresolved=("independent output observation was unavailable",),
        parse_error=error,
    )


def _validated_crops(output_crops: str | Sequence[str]) -> list[str]:
    crops = [output_crops] if isinstance(output_crops, str) else list(output_crops)
    if not 1 <= len(crops) <= MAX_OUTPUT_CROPS:
        raise ValueError("Output verification needs one or two output crops")
    if any(not isinstance(crop, str) or not crop or len(crop) > MAX_CROP_CHARS for crop in crops):
        raise ValueError("Output crop is invalid or exceeds its limit")
    return crops


def _parse_items(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > MAX_OBSERVED_ITEMS:
        raise ValueError(f"Output reader {name} are invalid or too numerous")
    if any(not isinstance(item, str) or not item.strip() or len(item) > MAX_ITEM_CHARS for item in value):
        raise ValueError(f"Output reader {name} contain an invalid item")
    return tuple(value)


def _parse_objects(value: object, name: str) -> tuple[str, ...]:
    values = _parse_items(value, name)
    _validate_objects(values, name)
    return values


def _validate_items(items: Iterable[str], name: str) -> None:
    values = tuple(items)
    if len(values) > MAX_OBSERVED_ITEMS or any(
        not isinstance(value, str) or not value.strip() or len(value) > MAX_ITEM_CHARS for value in values
    ):
        raise ValueError(f"Teaching component {name} are invalid")


def _validate_objects(items: Iterable[str], name: str) -> None:
    _validate_items(items, name)
    if any(_canonical(item) not in VISIBLE_OBJECT_KINDS for item in items):
        raise ValueError(f"Teaching component {name} use unsupported visible object kinds")


def _missing(required: Iterable[str], observed: Counter[str], canonicalizer: object) -> tuple[str, ...]:
    remaining = observed.copy()
    missing = []
    for item in required:
        canonical = canonicalizer(item)  # type: ignore[operator]
        if remaining[canonical] > 0:
            remaining[canonical] -= 1
        else:
            missing.append(item)
    return tuple(missing)


def _canonical(value: str) -> str:
    return " ".join(value.casefold().split())


def _canonical_label(value: str) -> str:
    canonical = _canonical(value)
    compact = canonical.replace(" ", "").replace("×", "x")
    if re.fullmatch(r"[1-9][0-9]*x[1-9][0-9]*", compact):
        return compact
    return canonical


def _canonical_symbol(value: str) -> str:
    normalized = _canonical(value)
    return {
        "α": "alpha",
        "x": "times",
        "×": "times",
        "multiplication": "times",
    }.get(normalized, normalized)


def _normalize_exact_text(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _valid_identifier(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value))


__all__ = [
    "ComponentComparison",
    "MAX_CROP_CHARS",
    "MAX_OUTPUT_CROPS",
    "OUTPUT_READER_SYSTEM",
    "OutputObservation",
    "SCHEMA",
    "SCHEMA_VERSION",
    "TeachingComponent",
    "TeachingExpectation",
    "TeachingVerification",
    "VISIBLE_OBJECT_KINDS",
    "VerificationMode",
    "compare_teaching_output",
    "parse_output_observation",
    "verify_teaching_output",
]
