"""Immutable command schemas at the JSON boundary."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

Identifier = Annotated[str, Field(max_length=128, pattern=r"\S")]
Text = Annotated[str, Field(max_length=8000, pattern=r"\S")]


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class NotebookContext(StrictModel):
    scope: Literal["notebook"]
    notebook_id: Identifier
    page_id: Identifier
    revision: Annotated[int, Field(ge=0)]


class DesktopContext(StrictModel):
    scope: Literal["desktop"]


Context = Annotated[NotebookContext | DesktopContext, Field(discriminator="scope")]


class CommandBase(StrictModel):
    # A strict bounded integer also rejects True and 1.0; Literal[1] alone does not.
    protocol_version: Annotated[int, Field(ge=1, le=1)]
    request_id: Identifier


class Capabilities(CommandBase):
    type: Literal["capabilities"]


class Shutdown(CommandBase):
    type: Literal["shutdown"]


class Cancel(CommandBase):
    type: Literal["cancel"]
    turn_id: Identifier


class Submit(CommandBase):
    type: Literal["submit"]
    turn_id: Identifier
    text: Text
    context: Context


Command = Annotated[
    Capabilities | Shutdown | Cancel | Submit, Field(discriminator="type")
]
COMMANDS: TypeAdapter[Command] = TypeAdapter(Command)
IDENTIFIERS: TypeAdapter[str] = TypeAdapter(Identifier)
