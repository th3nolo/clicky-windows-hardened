"""Consent-gated, local-only suggestions based on installed app names.

The scanner reads only Windows uninstall DisplayName values. It never reads
application paths, icons, publishers, versions, files, or user content, and it
never persists the resulting inventory.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Protocol


MAX_REGISTRY_SUBKEYS = 512
MAX_APP_NAME_CHARACTERS = 120
MAX_SUGGESTIONS = 5

_UNINSTALL_KEYS = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
)

_BLOCKED_NAME_PARTS = (
    " redistributable",
    " runtime",
    " update",
    " updater",
    " driver",
    " language pack",
    " sdk",
    " webview2",
)

_USE_CASES = (
    (
        ("visual studio code", "cursor", "pycharm", "intellij"),
        "Ask for visible-code explanations or prepare a reviewed workspace change.",
    ),
    (
        ("excel", "libreoffice calc"),
        "Turn selected information into a reviewed spreadsheet artifact.",
    ),
    (
        ("powerpoint", "libreoffice impress"),
        "Prepare and review a presentation artifact before adopting it.",
    ),
    (
        ("word", "libreoffice writer"),
        "Draft and review a document without sending or publishing it.",
    ),
    (
        ("outlook", "thunderbird"),
        "Draft a message for review; sending remains a separate user action.",
    ),
    (
        ("teams", "slack", "discord", "zoom"),
        "Ask for guidance about the visible interface without granting click authority.",
    ),
    (
        ("chrome", "firefox", "edge", "brave"),
        "Use screen-aware guidance for the visible page with no background browsing.",
    ),
    (
        ("notion", "obsidian"),
        "Create a reviewed local draft before any connected-account write.",
    ),
)


@dataclass(frozen=True, slots=True)
class AppSuggestion:
    app_name: str
    use_case: str

    def __post_init__(self) -> None:
        if _clean_name(self.app_name) != self.app_name:
            raise ValueError("App suggestion name is not display-safe")
        if not isinstance(self.use_case, str) or not self.use_case.strip():
            raise ValueError("App suggestion use case is required")


class AppNameSource(Protocol):
    def list_app_names(self) -> tuple[str, ...]:
        """Return bounded app display names without persisting them."""


class WindowsRegistryAppNameSource:
    """Read bounded DisplayName values from fixed Windows uninstall keys."""

    def list_app_names(self) -> tuple[str, ...]:
        if sys.platform != "win32":
            return ()
        import winreg

        names: list[str] = []
        remaining = MAX_REGISTRY_SUBKEYS
        access_views = tuple(
            dict.fromkeys(
                (
                    getattr(winreg, "KEY_WOW64_64KEY", 0),
                    getattr(winreg, "KEY_WOW64_32KEY", 0),
                )
            )
        )
        for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            for key_path in _UNINSTALL_KEYS:
                for view in access_views:
                    if remaining <= 0:
                        return tuple(names)
                    try:
                        root = winreg.OpenKey(
                            hive,
                            key_path,
                            0,
                            winreg.KEY_READ | view,
                        )
                    except OSError:
                        continue
                    with root:
                        try:
                            count = min(
                                winreg.QueryInfoKey(root)[0],
                                remaining,
                            )
                        except OSError:
                            continue
                        for index in range(count):
                            remaining -= 1
                            try:
                                subkey_name = winreg.EnumKey(root, index)
                                child = winreg.OpenKey(root, subkey_name)
                            except OSError:
                                continue
                            with child:
                                if _registry_entry_hidden(winreg, child):
                                    continue
                                try:
                                    value, _kind = winreg.QueryValueEx(
                                        child,
                                        "DisplayName",
                                    )
                                except OSError:
                                    continue
                                if isinstance(value, str):
                                    names.append(value)
        return tuple(names)


def _registry_entry_hidden(winreg, key) -> bool:
    try:
        system_component, _kind = winreg.QueryValueEx(
            key,
            "SystemComponent",
        )
    except OSError:
        system_component = 0
    if system_component == 1:
        return True
    try:
        release_type, _kind = winreg.QueryValueEx(key, "ReleaseType")
    except OSError:
        return False
    return (
        isinstance(release_type, str)
        and release_type.strip() != ""
    )


def _clean_name(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    if any(not character.isprintable() for character in value):
        return None
    candidate = " ".join(value.strip().split())
    if (
        not candidate
        or len(candidate) > MAX_APP_NAME_CHARACTERS
    ):
        return None
    folded = candidate.casefold()
    if any(part in folded for part in _BLOCKED_NAME_PARTS):
        return None
    return candidate


def _use_case_for(name: str) -> str:
    folded = name.casefold()
    for keywords, use_case in _USE_CASES:
        if any(keyword in folded for keyword in keywords):
            return use_case
    return (
        "Ask for guidance about this app only when its interface is visible; "
        "no app-control permission is implied."
    )


def discover_local_app_suggestions(
    *,
    consent: bool,
    disabled: bool,
    source: AppNameSource | None = None,
) -> tuple[AppSuggestion, ...]:
    """Enumerate only after explicit consent and return an ephemeral result."""

    if type(consent) is not bool or type(disabled) is not bool:
        raise TypeError("App suggestion privacy flags must be booleans")
    if disabled:
        raise PermissionError("Local app suggestions are disabled")
    if not consent:
        raise PermissionError(
            "Consent is required before installed app names are enumerated"
        )

    app_source = source or WindowsRegistryAppNameSource()
    unique: dict[str, str] = {}
    for raw_name in app_source.list_app_names()[:MAX_REGISTRY_SUBKEYS]:
        name = _clean_name(raw_name)
        if name is None:
            continue
        unique.setdefault(name.casefold(), name)

    known_keywords = tuple(
        keyword
        for keywords, _use_case in _USE_CASES
        for keyword in keywords
    )
    names = sorted(
        unique.values(),
        key=lambda candidate: (
            not any(
                keyword in candidate.casefold()
                for keyword in known_keywords
            ),
            candidate.casefold(),
        ),
    )[:MAX_SUGGESTIONS]
    return tuple(
        AppSuggestion(app_name=name, use_case=_use_case_for(name))
        for name in names
    )
