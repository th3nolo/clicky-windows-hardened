"""Immutable response selection values; no configuration or provider I/O."""

from dataclasses import dataclass
from typing import Generic, TypeVar

BackendT = TypeVar("BackendT")


@dataclass(frozen=True, slots=True)
class ProviderIdentity:
    provider_id: str
    endpoint: str


@dataclass(frozen=True, slots=True)
class ResponseSelection:
    identity: ProviderIdentity
    model_id: str | None
    revision: int


@dataclass(frozen=True, slots=True)
class ResponseDispatch(Generic[BackendT]):
    selection: ResponseSelection
    backend: BackendT


class SelectionChangedError(RuntimeError):
    """The accepted destination no longer matches the published selection."""


def require_unchanged_selection(
    accepted: ResponseSelection, current: ResponseSelection,
) -> None:
    if accepted != current:
        raise SelectionChangedError("The response selection changed. Submit the request again.")


def require_selected_model(selection: ResponseSelection) -> str:
    if not selection.model_id:
        raise SelectionChangedError("Choose a validated model before asking Clicky.")
    return selection.model_id
