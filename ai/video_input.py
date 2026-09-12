"""Bounded MP4 input and explicitly supported audiovisual model identities."""

import base64
import binascii
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_VIDEO_BYTES = 16 * 1024 * 1024
MAX_VIDEO_B64 = 4 * ((MAX_VIDEO_BYTES + 2) // 3)


class VideoInput(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    mime_type: Literal["video/mp4"] = "video/mp4"
    data: Annotated[str, Field(min_length=16, max_length=MAX_VIDEO_B64)]

    @field_validator("data")
    @classmethod
    def validate_mp4(cls, value: str) -> str:
        try:
            raw = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("Video must be base64 MP4 data") from exc
        if len(raw) > MAX_VIDEO_BYTES or raw[4:8] != b"ftyp":
            raise ValueError("Video must be an MP4 no larger than 16 MiB")
        return value

    @property
    def data_url(self) -> str:
        return f"data:{self.mime_type};base64,{self.data}"

    @classmethod
    def from_bytes(cls, raw: bytes) -> "VideoInput":
        if len(raw) > MAX_VIDEO_BYTES:
            raise ValueError("Video exceeds 16 MiB")
        return cls(data=base64.b64encode(raw).decode("ascii"))
