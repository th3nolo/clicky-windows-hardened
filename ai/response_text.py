"""Incrementally hide drawing markup from visible response text."""

import re
from dataclasses import dataclass

ANY_TAG_RE = re.compile(
    r'\[(?:POINT|ARROW|CIRCLE|UNDERLINE|LABEL|LINE|RECT|POLY|TEXT|ANGLE|CLEAR)'
    r'(?::[^\]]*)?\]'
)
ANY_PARTIAL_RE = re.compile(r'\[[A-Z]{0,9}(?::[^\]]*)?$')


@dataclass(slots=True)
class ResponseText:
    pending: str = ""

    def feed(self, chunk: str) -> str:
        text = ANY_TAG_RE.sub("", self.pending + chunk)
        partial = ANY_PARTIAL_RE.search(text)
        boundary = partial.start() if partial else len(text)
        self.pending = text[boundary:]
        return text[:boundary]

    def finish(self) -> str:
        text, self.pending = self.pending, ""
        return ANY_TAG_RE.sub("", text)
