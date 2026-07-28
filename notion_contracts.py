"""Provider-neutral contracts for bounded Notion reads and local drafts."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field


MAX_NOTION_PROVIDER_REQUESTS = 16
MAX_NOTION_TITLE_CHARS = 2_000
MAX_NOTION_BLOCK_TEXT_CHARS = 16 * 1024
MAX_NOTION_DRAFT_BLOCKS = 100
MAX_NOTION_DRAFT_TEXT_CHARS = 64 * 1024
_DRAFT_BLOCK_TYPES = frozenset(
    {
        "bulleted_list_item",
        "code",
        "divider",
        "heading_1",
        "heading_2",
        "heading_3",
        "numbered_list_item",
        "paragraph",
        "quote",
        "to_do",
    }
)


def canonical_notion_id(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 64
        or value.strip() != value
    ):
        raise ValueError(f"{label} is invalid")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    return str(parsed)


def bounded_notion_text(
    value: object,
    maximum: int,
    label: str,
    *,
    allow_empty: bool = True,
) -> str:
    if (
        not isinstance(value, str)
        or (not allow_empty and not value)
        or len(value) > maximum
        or "\x00" in value
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("Notion value is not canonical JSON") from exc


@dataclass(frozen=True, slots=True)
class NotionDraftBlock:
    block_type: str
    text: str = field(default="", repr=False)
    checked: bool | None = None
    language: str | None = None

    def __post_init__(self) -> None:
        if self.block_type not in _DRAFT_BLOCK_TYPES:
            raise ValueError("Notion draft block type is unsupported")
        bounded_notion_text(
            self.text,
            MAX_NOTION_BLOCK_TEXT_CHARS,
            "Notion draft block text",
        )
        if self.block_type == "divider" and self.text:
            raise ValueError("Notion divider draft cannot contain text")
        if self.block_type != "divider" and not self.text:
            raise ValueError("Notion draft text block cannot be empty")
        if self.checked is not None and (
            type(self.checked) is not bool or self.block_type != "to_do"
        ):
            raise ValueError("Notion draft checked state is invalid")
        if self.language is not None:
            bounded_notion_text(
                self.language,
                128,
                "Notion draft code language",
                allow_empty=False,
            )
            if self.block_type != "code":
                raise ValueError(
                    "Notion draft code language is invalid"
                )

    @classmethod
    def from_json_value(cls, value: object) -> "NotionDraftBlock":
        if not isinstance(value, dict) or not set(value).issubset(
            {"checked", "language", "text", "type"}
        ):
            raise ValueError("Notion draft block shape is invalid")
        if "type" not in value:
            raise ValueError("Notion draft block type is missing")
        return cls(
            block_type=value["type"],
            text=value.get("text", ""),
            checked=value.get("checked"),
            language=value.get("language"),
        )

    def json_value(self) -> dict[str, object]:
        value: dict[str, object] = {
            "text": self.text,
            "type": self.block_type,
        }
        if self.checked is not None:
            value["checked"] = self.checked
        if self.language is not None:
            value["language"] = self.language
        return value


@dataclass(frozen=True, slots=True)
class NotionLocalDraft:
    title: str = field(repr=False)
    blocks: tuple[NotionDraftBlock, ...] = field(repr=False)
    intended_parent_page_id: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        bounded_notion_text(
            self.title,
            MAX_NOTION_TITLE_CHARS,
            "Notion draft title",
            allow_empty=False,
        )
        if (
            not isinstance(self.blocks, tuple)
            or not self.blocks
            or len(self.blocks) > MAX_NOTION_DRAFT_BLOCKS
            or any(not isinstance(item, NotionDraftBlock) for item in self.blocks)
        ):
            raise ValueError("Notion draft blocks are invalid")
        if sum(len(item.text) for item in self.blocks) > (
            MAX_NOTION_DRAFT_TEXT_CHARS
        ):
            raise ValueError("Notion draft text exceeds its limit")
        if self.intended_parent_page_id is not None:
            object.__setattr__(
                self,
                "intended_parent_page_id",
                canonical_notion_id(
                    self.intended_parent_page_id,
                    "Intended Notion parent page ID",
                ),
            )

    def to_json_bytes(self) -> bytes:
        return _canonical_json(
            {
                "blocks": [item.json_value() for item in self.blocks],
                "intended_parent_page_id": self.intended_parent_page_id,
                "publication_authorized": False,
                "schema": "clicky.notion.local_draft.v1",
                "state": "local_unpublished",
                "title": self.title,
            }
        )


def render_notion_local_draft(
    *,
    title: str,
    blocks_json: str,
    intended_parent_page_id: str | None = None,
) -> NotionLocalDraft:
    """Validate model/user block JSON and return an inert local draft."""

    bounded_notion_text(
        blocks_json,
        MAX_NOTION_DRAFT_TEXT_CHARS * 2,
        "Notion draft block JSON",
        allow_empty=False,
    )
    try:
        raw = json.loads(blocks_json)
    except json.JSONDecodeError as exc:
        raise ValueError("Notion draft block JSON is invalid") from exc
    if (
        not isinstance(raw, list)
        or not raw
        or len(raw) > MAX_NOTION_DRAFT_BLOCKS
    ):
        raise ValueError("Notion draft block list is invalid")
    return NotionLocalDraft(
        title=title,
        blocks=tuple(NotionDraftBlock.from_json_value(item) for item in raw),
        intended_parent_page_id=intended_parent_page_id,
    )


__all__ = [
    "MAX_NOTION_PROVIDER_REQUESTS",
    "MAX_NOTION_TITLE_CHARS",
    "NotionDraftBlock",
    "NotionLocalDraft",
    "bounded_notion_text",
    "canonical_notion_id",
    "render_notion_local_draft",
]
