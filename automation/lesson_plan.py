"""Bounded source-aware lesson manifests for native notebook teaching.

The writer receives a frozen manifest, never a free-form completion checklist.
One planner request may inspect the learner question and source screenshot, but
the returned plan is parsed and validated before any mutation is considered.
In particular, a generic ``vector`` object is not evidence that distinct row
and column vector components have been planned or will be verified.
"""
from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable
from contextlib import aclosing
from dataclasses import dataclass
from enum import Enum


MAX_COMPONENTS = 8
MAX_PLAN_RESPONSE_CHARS = 24 * 1024
MAX_CORRECTIVE_RESPONSE_CHARS = 8 * 1024
MAX_SOURCE_SCREENSHOT_CHARS = 12 * 1024 * 1024
MAX_QUESTION_CHARS = 4_000
MAX_ITEMS = 32
MAX_ITEM_CHARS = 160
SCHEMA = "clicky.lesson_plan"
SCHEMA_VERSION = 1
VISIBLE_OBJECT_KINDS = frozenset({
    "row_vector", "column_vector", "matrix", "arrow", "enclosure", "sentence", "heading", "label",
})

PLANNER_CONSTRAINTS = (
    "Return exactly one JSON object with only top-level keys schema, version, components.",
    "components contains one to eight non-overlapping page-DIP rectangles inside the supplied page dimensions.",
    "Each component has exactly component_id, region, required_labels, required_symbols, required_objects, symbol_count, symbol_sequence, dimension_label, exact_text.",
    "component_id is a stable identifier using letters, digits, dot, underscore, or dash; every label, symbol, and object is a nonempty short string.",
    "Every component needs visible labels, symbols, or objects; use only row_vector, column_vector, matrix, arrow, enclosure, sentence, heading, or label objects. A generic vector object is forbidden.",
    "When required_symbols is empty, use symbol_count null and symbol_sequence []. When symbols are present, symbol_count equals their list length and symbol_sequence repeats that exact list in reading order.",
    "dimension_label is null unless that dimension is visibly drawn; when present it uses compact form like 1x3 and appears exactly in required_labels.",
    "In teaching mode exact_text is null. In exact-copy mode exact_text is a nonempty visible string for every component.",
    "Prefer two coherent components such as one row example and one column example; do not split one example into repeated label, vector, and dimension components.",
    "Never emit target_is_new_page, preserve_existing_pages, teaching_note, ink_colors, commentary, or any other field.",
)


class LessonPlanMode(str, Enum):
    """Whether prose must be reproduced exactly or may teach by paraphrase."""

    TEACHING = "teaching"
    EXACT_COPY = "exact_copy"


@dataclass(frozen=True, slots=True)
class PageRegion:
    """A positive rectangle in InkNotes page DIP coordinates."""

    x: float
    y: float
    width: float
    height: float

    def __post_init__(self) -> None:
        values = (self.x, self.y, self.width, self.height)
        if any(type(value) not in (int, float) or not math.isfinite(value) for value in values):
            raise ValueError("Lesson component region must contain finite page DIP numbers")
        if self.x < 0 or self.y < 0 or self.width <= 0 or self.height <= 0:
            raise ValueError("Lesson component region must be a positive page DIP rectangle")

    def to_dict(self) -> dict[str, float]:
        return {"x": self.x, "y": self.y, "width": self.width, "height": self.height}


@dataclass(frozen=True, slots=True)
class PageGeometry:
    """Explicit mapping from source pixels to InkNotes page DIP coordinates."""

    page_width: float
    page_height: float
    source_image_width: int
    source_image_height: int
    source_page_region: PageRegion

    def __post_init__(self) -> None:
        if any(type(value) not in (int, float) or not math.isfinite(value) or value <= 0
               for value in (self.page_width, self.page_height)):
            raise ValueError("Lesson page dimensions are invalid")
        if any(type(value) is not int or not 1 <= value <= 32_768
               for value in (self.source_image_width, self.source_image_height)):
            raise ValueError("Lesson source image dimensions are invalid")
        source = self.source_page_region
        if source.x + source.width > self.page_width or source.y + source.height > self.page_height:
            raise ValueError("Lesson source image mapping exceeds the page")

    def to_dict(self) -> dict[str, object]:
        return {
            "page_width": self.page_width,
            "page_height": self.page_height,
            "source_image_width": self.source_image_width,
            "source_image_height": self.source_image_height,
            "source_page_region": self.source_page_region.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class LessonComponent:
    """One independently cropped and verified visible teaching component.

    ``required_symbols`` preserves repeated symbol requirements. An optional
    ``symbol_sequence`` records visible order, while ``symbol_count`` makes
    the count explicit. ``dimension_label`` must itself be a required visible
    label, so it cannot be a hidden semantic claim.
    """

    component_id: str
    region: PageRegion
    required_labels: tuple[str, ...] = ()
    required_symbols: tuple[str, ...] = ()
    required_objects: tuple[str, ...] = ()
    symbol_count: int | None = None
    symbol_sequence: tuple[str, ...] = ()
    dimension_label: str | None = None
    exact_text: str | None = None

    def __post_init__(self) -> None:
        if not _valid_identifier(self.component_id):
            raise ValueError("Lesson component ID is invalid")
        _validate_items(self.required_labels, "required labels")
        _validate_items(self.required_symbols, "required symbols")
        _validate_objects(self.required_objects, "required objects")
        _validate_items(self.symbol_sequence, "symbol sequence")
        if self.symbol_count is not None:
            if type(self.symbol_count) is not int or not 1 <= self.symbol_count <= MAX_ITEMS:
                raise ValueError("Lesson component symbol count is invalid")
            if not self.required_symbols or len(self.required_symbols) != self.symbol_count:
                raise ValueError("Lesson component symbol count must match required symbols")
            if self.symbol_sequence and len(self.symbol_sequence) != self.symbol_count:
                raise ValueError("Lesson component symbol sequence must match symbol count")
        if self.symbol_sequence and not self.required_symbols:
            raise ValueError("Lesson component symbol sequence needs required symbols")
        if self.symbol_sequence and self.symbol_sequence != self.required_symbols:
            raise ValueError("Lesson component symbol sequence must preserve required symbol order")
        if self.dimension_label is not None:
            if not isinstance(self.dimension_label, str) or not re.fullmatch(r"[1-9][0-9]*x[1-9][0-9]*", self.dimension_label):
                raise ValueError("Lesson component dimension label is invalid")
            if self.dimension_label not in self.required_labels:
                raise ValueError("Lesson component dimension label must be a required visible label")
        if self.exact_text is not None:
            if not isinstance(self.exact_text, str) or not self.exact_text.strip() or len(self.exact_text) > 4_000:
                raise ValueError("Lesson component exact text is invalid")
        if not self.has_meaningful_requirement:
            raise ValueError("Lesson component needs meaningful visible requirements")
        if _is_generic_vector_only(self):
            raise ValueError("A generic vector-only component cannot prove lesson coverage")

    @property
    def has_meaningful_requirement(self) -> bool:
        return bool(
            self.required_labels
            or self.required_symbols
            or self.required_objects
            or self.symbol_sequence
            or self.dimension_label
        )

    def writer_manifest(self) -> dict[str, object]:
        """Return compact frozen intent for the native writer, with no source data."""
        return {
            "component_id": self.component_id,
            "region": self.region.to_dict(),
            "required_labels": list(self.required_labels),
            "required_symbols": list(self.required_symbols),
            "required_objects": list(self.required_objects),
            "symbol_count": self.symbol_count,
            "symbol_sequence": list(self.symbol_sequence),
            "dimension_label": self.dimension_label,
            "exact_text": self.exact_text,
        }

    def verification_component(self):
        """Create one output-reader contract; callers verify components singly."""
        from automation.teaching_verification import TeachingComponent

        labels = self.required_labels
        return TeachingComponent(
            component_id=self.component_id,
            required_labels=labels,
            required_symbols=self.required_symbols,
            required_symbol_sequence=self.symbol_sequence,
            required_objects=self.required_objects,
            exact_text=self.exact_text,
        )


@dataclass(frozen=True, slots=True)
class LessonPlan:
    """A validated, immutable manifest that must exist before notebook mutation."""

    mode: LessonPlanMode
    page_geometry: PageGeometry
    target_is_new_page: bool
    components: tuple[LessonComponent, ...]

    def __post_init__(self) -> None:
        if not self.components or len(self.components) > MAX_COMPONENTS:
            raise ValueError("Lesson plan needs between one and eight components")
        if len({component.component_id for component in self.components}) != len(self.components):
            raise ValueError("Lesson component IDs must be unique")
        if type(self.target_is_new_page) is not bool:
            raise ValueError("Lesson target-page flag is invalid")
        if self.mode is LessonPlanMode.EXACT_COPY:
            if any(component.exact_text is None for component in self.components):
                raise ValueError("Exact-copy lesson plan requires exact text for every component")
        elif any(component.exact_text is not None for component in self.components):
            raise ValueError("Exact text is permitted only in explicit exact-copy mode")
        for index, first in enumerate(self.components):
            if not _in_page(first.region, self.page_geometry):
                raise ValueError("Lesson component region exceeds page dimensions")
            for second in self.components[index + 1:]:
                if _overlaps(first.region, second.region):
                    raise ValueError("Lesson component regions must not overlap")

    def writer_manifest(self) -> tuple[dict[str, object], ...]:
        return tuple(component.writer_manifest() for component in self.components)

    def verification_components(self):
        """Return per-component contracts; do not aggregate them into one crop."""
        return tuple(component.verification_component() for component in self.components)


PLANNER_SYSTEM = (
    "Plan a notebook teaching lesson from the attached source screenshot and learner question. "
    "Return JSON only using the requested schema. Make one component for every independently visible item "
    "that must later be cropped and verified. Preserve ambiguities rather than inventing a reading. "
    "Do not use a generic vector object as a substitute for separate required row or column components. "
    "Regions are non-overlapping InkNotes page DIP rectangles. Use the supplied source-pixel to page-DIP mapping; "
    "never infer page DIP coordinates from source-image pixels. This plan cannot mutate a notebook. "
    "Follow every constraint in the supplied manifest contract exactly."
)

_PLAN_PROMPT = json.dumps(
    {
        "schema": SCHEMA,
        "version": SCHEMA_VERSION,
        "constraints": list(PLANNER_CONSTRAINTS),
        "response": {
            "schema": SCHEMA,
            "version": SCHEMA_VERSION,
            "components": [{
                "component_id": "row-example",
                "region": {"x": 100, "y": 100, "width": 800, "height": 240},
                "required_labels": ["row", "1x3"],
                "required_symbols": ["1", "2", "3"],
                "required_objects": ["row_vector"],
                "symbol_count": 3,
                "symbol_sequence": ["1", "2", "3"],
                "dimension_label": "1x3",
                "exact_text": None,
            }],
        },
    },
    separators=(",", ":"),
)


async def request_lesson_plan(
    provider: object,
    model: str,
    question: str,
    source_screenshot: str,
    *,
    page_geometry: PageGeometry,
    target_is_new_page: bool,
    mode: LessonPlanMode = LessonPlanMode.TEACHING,
) -> LessonPlan:
    """Make one bounded source-aware planning request and freeze its manifest."""
    if not isinstance(mode, LessonPlanMode):
        raise ValueError("Unknown lesson plan mode")
    if not isinstance(question, str) or not question.strip() or len(question) > MAX_QUESTION_CHARS:
        raise ValueError("Lesson planning question is invalid")
    if not isinstance(source_screenshot, str) or not source_screenshot or len(source_screenshot) > MAX_SOURCE_SCREENSHOT_CHARS:
        raise ValueError("Lesson planning screenshot is invalid")
    if not isinstance(page_geometry, PageGeometry):
        raise ValueError("Lesson planning page geometry is invalid")
    if type(target_is_new_page) is not bool:
        raise ValueError("Lesson planning target-page flag is invalid")
    stream_response = getattr(provider, "stream_response", None)
    if not callable(stream_response):
        raise TypeError("Provider does not support lesson planning")
    request = {
        "question": question,
        "mode": mode.value,
        "mode_instruction": (
            "Every component must provide exact_text because exact-copy mode is active."
            if mode is LessonPlanMode.EXACT_COPY else
            "Teaching mode permits paraphrase; leave exact_text null."
        ),
        "page_geometry": page_geometry.to_dict(),
        "target_is_new_page": target_is_new_page,
        "manifest": json.loads(_PLAN_PROMPT),
    }
    response = await _read_plan_response(
        stream_response, json.dumps(request, separators=(",", ":")), source_screenshot, model,
    )
    try:
        return parse_lesson_plan(
            response, mode=mode, page_geometry=page_geometry, target_is_new_page=target_is_new_page,
        )
    except ValueError as error:
        # One repair attempt is enough to correct a schema-shaped answer. The
        # strict parser remains the only acceptance authority; no field is
        # silently discarded or inferred from the rejected response.
        repair = dict(request)
        repair["repair"] = {
            "validation_error": str(error)[:512],
            "rejected_response": response[:MAX_CORRECTIVE_RESPONSE_CHARS],
            "instruction": (
                "Return a replacement JSON object only. Preserve no extra fields. "
                "Use exact top-level and component keys from manifest."
            ),
        }
        repaired = await _read_plan_response(
            stream_response, json.dumps(repair, separators=(",", ":")), source_screenshot, model,
        )
        return parse_lesson_plan(
            repaired, mode=mode, page_geometry=page_geometry, target_is_new_page=target_is_new_page,
        )


async def _read_plan_response(stream_response, prompt: str, source_screenshot: str, model: str) -> str:
    """Read one capped planner stream and close it on every failure path."""
    response = ""
    stream = stream_response(prompt, [source_screenshot], [], PLANNER_SYSTEM, model=model)
    async with aclosing(stream):
        async for chunk in stream:
            if not isinstance(chunk, str):
                raise ValueError("Lesson planner returned a non-text chunk")
            response += chunk
            if len(response) > MAX_PLAN_RESPONSE_CHARS:
                raise ValueError("Lesson planner response exceeded its limit")
    return response


def parse_lesson_plan(
    response: str,
    *,
    mode: LessonPlanMode = LessonPlanMode.TEACHING,
    page_geometry: PageGeometry,
    target_is_new_page: bool,
) -> LessonPlan:
    """Strictly validate model JSON before any native writer receives it."""
    if not isinstance(mode, LessonPlanMode):
        raise ValueError("Unknown lesson plan mode")
    if not isinstance(page_geometry, PageGeometry):
        raise ValueError("Lesson planning page geometry is invalid")
    if type(target_is_new_page) is not bool:
        raise ValueError("Lesson planning target-page flag is invalid")
    if not isinstance(response, str) or not response or len(response) > MAX_PLAN_RESPONSE_CHARS:
        raise ValueError("Lesson planner response is empty or exceeds its limit")
    try:
        payload = json.loads(response)
    except json.JSONDecodeError as error:
        raise ValueError("Lesson planner did not return complete JSON") from error
    if not isinstance(payload, dict) or set(payload) != {"schema", "version", "components"}:
        raise ValueError("Lesson planner response has an unsupported schema")
    if payload["schema"] != SCHEMA or payload["version"] != SCHEMA_VERSION:
        raise ValueError("Lesson planner response has the wrong schema version")
    raw_components = payload["components"]
    if not isinstance(raw_components, list) or not 1 <= len(raw_components) <= MAX_COMPONENTS:
        raise ValueError("Lesson planner components are invalid")
    return LessonPlan(
        mode=mode,
        page_geometry=page_geometry,
        target_is_new_page=target_is_new_page,
        components=tuple(_parse_component(raw) for raw in raw_components),
    )


def _parse_component(raw: object) -> LessonComponent:
    required_keys = {
        "component_id", "region", "required_labels", "required_symbols", "required_objects",
        "symbol_count", "symbol_sequence", "dimension_label", "exact_text",
    }
    if not isinstance(raw, dict) or set(raw) != required_keys:
        raise ValueError("Lesson planner component has an unsupported schema")
    region = raw["region"]
    if not isinstance(region, dict) or set(region) != {"x", "y", "width", "height"}:
        raise ValueError("Lesson planner component region has an unsupported schema")
    return LessonComponent(
        component_id=raw["component_id"],
        region=PageRegion(**region),
        required_labels=_items(raw["required_labels"], "required labels"),
        required_symbols=_items(raw["required_symbols"], "required symbols"),
        required_objects=_items(raw["required_objects"], "required objects"),
        symbol_count=raw["symbol_count"],
        symbol_sequence=_items(raw["symbol_sequence"], "symbol sequence"),
        dimension_label=raw["dimension_label"],
        exact_text=raw["exact_text"],
    )


def _items(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"Lesson planner {name} are invalid")
    return tuple(value)


def _validate_items(items: Iterable[str], name: str) -> None:
    values = tuple(items)
    if len(values) > MAX_ITEMS or any(
        not isinstance(value, str) or not value.strip() or len(value) > MAX_ITEM_CHARS for value in values
    ):
        raise ValueError(f"Lesson component {name} are invalid")


def _validate_objects(items: Iterable[str], name: str) -> None:
    _validate_items(items, name)
    if any(item not in VISIBLE_OBJECT_KINDS for item in items):
        raise ValueError(f"Lesson component {name} use unsupported visible object kinds")


def _is_generic_vector_only(component: LessonComponent) -> bool:
    return (
        not component.required_labels
        and not component.required_symbols
        and not component.symbol_sequence
        and component.dimension_label is None
        and component.exact_text is None
        and {item.casefold() for item in component.required_objects} <= {"row_vector", "column_vector"}
    )


def _overlaps(first: PageRegion, second: PageRegion) -> bool:
    return not (
        first.x + first.width <= second.x
        or second.x + second.width <= first.x
        or first.y + first.height <= second.y
        or second.y + second.height <= first.y
    )


def _in_page(region: PageRegion, geometry: PageGeometry) -> bool:
    return region.x + region.width <= geometry.page_width and region.y + region.height <= geometry.page_height


def _valid_identifier(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", value))


__all__ = [
    "LessonComponent",
    "LessonPlan",
    "LessonPlanMode",
    "MAX_COMPONENTS",
    "PageGeometry",
    "PageRegion",
    "PLANNER_CONSTRAINTS",
    "PLANNER_SYSTEM",
    "SCHEMA",
    "SCHEMA_VERSION",
    "VISIBLE_OBJECT_KINDS",
    "parse_lesson_plan",
    "request_lesson_plan",
]
