"""Exact provider instruction for coordinate-only visual walkthrough output."""

from __future__ import annotations

import json

from screen.topology import MonitorDescriptor


def walkthrough_response_contract(
    displays: tuple[MonitorDescriptor, ...],
) -> str:
    """Return a bounded JSON-only contract; never grant target/action IDs."""

    if (
        not isinstance(displays, tuple)
        or not displays
        or any(not isinstance(display, MonitorDescriptor) for display in displays)
    ):
        raise ValueError("walkthrough display context is invalid")
    stable_ids = tuple(display.stable_id for display in displays)
    if (
        len(frozenset(stable_ids)) != len(stable_ids)
        or any(
            not isinstance(stable_id, str)
            or not 1 <= len(stable_id) <= 128
            or not stable_id.isprintable()
            or stable_id.strip() != stable_id
            for stable_id in stable_ids
        )
    ):
        raise ValueError("walkthrough display identity is invalid")
    display_ids = ", ".join(
        json.dumps(stable_id, ensure_ascii=True)
        for stable_id in stable_ids
    )
    return f"""

VISUAL WALKTHROUGH RESPONSE MODE:
Return ONLY one JSON object. Do not use Markdown fences or explanatory text.
The exact root is:
{{"schema":"clicky.visual_walkthrough","version":1,
"walkthrough_id":"<16-128 chars using letters digits underscore hyphen>",
"steps":[...]}}

Create 2-6 short, manually advanced steps. Every step must include:
- "step_id": a unique 16-128 character opaque identifier;
- "type": only "POINT" or "SHAPE";
- "narration": one plain-text instruction describing what the user should do;
- "ttl_seconds": an integer from 5 through 30.

Allowed display_ref values: {display_ids}.

POINT exact shape:
{{"step_id":"...","type":"POINT","narration":"...","ttl_seconds":15,
"display_ref":"<allowed id>","point":[x,y],"label":"...",
"coordinate_display_only":true}}

SHAPE exact shape:
{{"step_id":"...","type":"SHAPE","narration":"...","ttl_seconds":15,
"display_ref":"<allowed id>","shapes":[...],
"coordinate_display_only":true}}

Coordinates are normalized integers from 0 through 1000. A SHAPE step has 1-4
shapes and at most 8 shapes total. Each shape is one of:
- {{"kind":"arrow","points":[[x1,y1],[x2,y2]],"color":"blue"}}
- {{"kind":"line","points":[[x1,y1],[x2,y2]],"color":"blue"}}
- {{"kind":"rectangle","points":[[x1,y1],[x2,y2]],"color":"yellow"}}
- {{"kind":"underline","points":[[x1,y1],[x2,y2]],"color":"green"}}
- {{"kind":"circle","points":[[x,y]],"color":"yellow","radius":50}}
Colors: blue, red, green, yellow, orange, purple, white, cyan.

These are display-only annotations. Never emit TARGET, HOVER, or HIGHLIGHT
without a trusted target_ref; none are available in this request. Never emit a
click, key, URL, tool call, action, script, or desktop-automation instruction.
Do not claim any control was activated. The user advances each step explicitly.
"""


__all__ = ["walkthrough_response_contract"]
