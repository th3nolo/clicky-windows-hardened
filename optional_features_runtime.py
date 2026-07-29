"""Product caller services for the default-off restored parity features."""

from __future__ import annotations

import os
import secrets
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Mapping

from capability_registry import CapabilityId, ConnectorId
from connectors.accounts import ConnectedAccountService
from connectors.base import ConnectorCall
from connectors.google_calendar_upcoming import (
    MAX_UPCOMING_RESPONSE_BYTES,
    CalendarUpcomingRequest,
    GoogleCalendarUpcomingAdapter,
)
from skills.signed_import import (
    APPROVED_SIGNING_ROOTS,
    MAX_SIGNED_PACKAGE_BYTES,
    MAX_TRUST_POLICY_BYTES,
    SignedSkillPreview,
    SignedSkillStore,
    VerifiedTrustPolicy,
    preview_signed_skill,
    verify_trust_policy,
)
from widgets.meeting_countdown import (
    MeetingCountdown,
    MeetingCountdownPrivacy,
    MeetingDismissalStore,
    build_meeting_countdowns,
)


_UTC = timezone.utc


class OptionalFeatureUnavailableError(RuntimeError):
    pass


def local_feature_data_dir() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA") or Path.home())
    return base / "Clicky"


def windows_session_locked() -> bool:
    """Return locked on uncertainty; non-Windows test hosts fail closed."""

    if os.name != "nt":
        return True
    try:
        import ctypes

        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.OpenInputDesktop.argtypes = [
            ctypes.c_uint,
            ctypes.c_bool,
            ctypes.c_uint,
        ]
        user32.OpenInputDesktop.restype = ctypes.c_void_p
        user32.SwitchDesktop.argtypes = [ctypes.c_void_p]
        user32.SwitchDesktop.restype = ctypes.c_bool
        user32.CloseDesktop.argtypes = [ctypes.c_void_p]
        user32.CloseDesktop.restype = ctypes.c_bool
        desktop = user32.OpenInputDesktop(0, False, 0x0100)
        if not desktop:
            return True
        try:
            return not bool(user32.SwitchDesktop(desktop))
        finally:
            user32.CloseDesktop(desktop)
    except Exception:
        return True


class MeetingCountdownRuntime:
    """One selected primary calendar, minimal metadata, generic output."""

    def __init__(
        self,
        account_service: ConnectedAccountService | None = None,
        *,
        dismissals: MeetingDismissalStore | None = None,
        adapter_factory=GoogleCalendarUpcomingAdapter,
    ) -> None:
        self._accounts = account_service or ConnectedAccountService()
        self._dismissals = dismissals or MeetingDismissalStore(
            local_feature_data_dir() / "meeting_dismissals.json"
        )
        self._adapter_factory = adapter_factory

    async def refresh(
        self,
        *,
        enabled: bool,
        connector_read_allowed: bool,
        screen_shared: bool,
        now: datetime | None = None,
        selected_calendar_ids: tuple[str, ...] = ("primary",),
    ) -> tuple[MeetingCountdown, ...]:
        if not enabled:
            raise OptionalFeatureUnavailableError(
                "Meeting countdowns are disabled"
            )
        if not connector_read_allowed:
            raise OptionalFeatureUnavailableError(
                "Calendar read permission is disabled"
            )
        current = now or datetime.now(_UTC)
        if current.tzinfo is None:
            raise TypeError("Meeting countdown time must be timezone-aware")
        current = current.astimezone(_UTC)
        if windows_session_locked():
            return ()
        privacy = MeetingCountdownPrivacy(
            session_locked=False,
            screen_shared=screen_shared,
        )
        if not privacy.may_display:
            return ()

        calendar_accounts = tuple(
            account
            for account in self._accounts.list_accounts()
            if account.connector is ConnectorId.GOOGLE_CALENDAR
            and account.allows(CapabilityId.CALENDAR_EVENT_READ)
        )
        if not calendar_accounts:
            raise OptionalFeatureUnavailableError(
                "Connect one Google Calendar account first"
            )
        if len(calendar_accounts) != 1:
            raise OptionalFeatureUnavailableError(
                "Select one Google Calendar account before showing countdowns"
            )
        account = calendar_accounts[0]
        request = CalendarUpcomingRequest(
            selected_calendar_ids=selected_calendar_ids,
            time_min=_utc_text(current),
            time_max=_utc_text(current + timedelta(hours=24)),
        )
        call = ConnectorCall(
            call_id="meeting-" + secrets.token_hex(12),
            run_id="meeting-" + secrets.token_hex(12),
            authorization_id=account.authorization_id,
            connector=request.connector,
            capability=request.capability,
            operation_id=request.operation_id,
            request_digest=request.request_digest,
            maximum_response_bytes=MAX_UPCOMING_RESPONSE_BYTES,
        )
        with self._accounts.lease_access_token(
            account.authorization_id,
            CapabilityId.CALENDAR_EVENT_READ,
        ) as lease:
            result = await self._adapter_factory(account).execute(
                call,
                request,
                lease.token,
                fetched_at=current,
            )
        return build_meeting_countdowns(
            result,
            enabled=True,
            privacy=privacy,
            now=current,
            dismissals=self._dismissals,
        )

    def dismiss(self, countdown: MeetingCountdown) -> None:
        if not isinstance(countdown, MeetingCountdown):
            raise TypeError("A typed meeting countdown is required")
        self._dismissals.dismiss(
            countdown.opaque_event_id,
            until=countdown.ends_at,
        )


class SignedSkillImportRuntime:
    """Offline preview followed by exact-digest activation."""

    def __init__(
        self,
        *,
        feature_enabled: bool,
        approved_roots: Mapping[str, bytes] = APPROVED_SIGNING_ROOTS,
        store: SignedSkillStore | None = None,
    ) -> None:
        self._enabled = feature_enabled is True
        self._roots = approved_roots
        self._store = store or SignedSkillStore(
            local_feature_data_dir() / "signed_skills",
            feature_enabled=self._enabled,
        )
        self._pending_policy_payload: bytes | None = None
        self._pending_policy_digest: str | None = None

    def preview(
        self,
        *,
        trust_policy_path: Path,
        package_path: Path,
        now: datetime | None = None,
    ) -> tuple[VerifiedTrustPolicy, SignedSkillPreview]:
        if not self._enabled:
            raise OptionalFeatureUnavailableError(
                "Signed skill import is disabled"
            )
        if not self._roots:
            raise OptionalFeatureUnavailableError(
                "No production signing trust root is approved"
            )
        policy_payload = _read_regular_bounded(
            trust_policy_path,
            MAX_TRUST_POLICY_BYTES,
            "Trust policy",
        )
        policy = verify_trust_policy(
            policy_payload,
            approved_roots=self._roots,
            now=now,
        )
        package = _read_regular_bounded(
            package_path,
            MAX_SIGNED_PACKAGE_BYTES,
            "Signed skill package",
        )
        preview = preview_signed_skill(
            package,
            trust_policy=policy,
            now=now,
        )
        self._pending_policy_payload = policy_payload
        self._pending_policy_digest = policy.digest
        return policy, preview

    def activate(
        self,
        preview: SignedSkillPreview,
        *,
        reviewed_approval_digest: str,
        now: datetime | None = None,
    ) -> None:
        payload = self._pending_policy_payload
        expected_policy_digest = self._pending_policy_digest
        if payload is None or expected_policy_digest is None:
            raise OptionalFeatureUnavailableError(
                "Preview the exact trust policy before activation"
            )
        policy = self._store.install_trust_policy(
            payload,
            approved_roots=self._roots,
            now=now,
        )
        if policy.digest != expected_policy_digest:
            raise OptionalFeatureUnavailableError(
                "Trust policy changed after preview"
            )
        verified = preview_signed_skill(
            preview.package_bytes,
            trust_policy=policy,
            now=now,
        )
        if (
            verified.package_digest != preview.package_digest
            or verified.approval_digest != preview.approval_digest
        ):
            raise OptionalFeatureUnavailableError(
                "Signed skill changed after preview"
            )
        self._store.stage(verified)
        self._store.activate(
            verified,
            reviewed_approval_digest=reviewed_approval_digest,
        )
        self._pending_policy_payload = None
        self._pending_policy_digest = None

    def active_entries(
        self,
        *,
        now: datetime | None = None,
    ):
        policy = self._store.load_trust_policy(
            approved_roots=self._roots,
            now=now,
        )
        self._store.reconcile(policy, now=now)
        return self._store.active_entries(policy, now=now)


def _read_regular_bounded(path: Path, maximum: int, label: str) -> bytes:
    if not isinstance(path, Path):
        raise TypeError(f"{label} path must be a Path")
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise OptionalFeatureUnavailableError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise OptionalFeatureUnavailableError(
            f"{label} must be a local regular file"
        )
    if path.stat().st_size > maximum:
        raise OptionalFeatureUnavailableError(
            f"{label} exceeds its reviewed size bound"
        )
    with path.open("rb") as handle:
        payload = handle.read(maximum + 1)
    if len(payload) > maximum:
        raise OptionalFeatureUnavailableError(
            f"{label} exceeds its reviewed size bound"
        )
    return payload


def _utc_text(value: datetime) -> str:
    normalized = value.astimezone(_UTC).replace(microsecond=0)
    return normalized.isoformat().replace("+00:00", "Z")


__all__ = [
    "MeetingCountdownRuntime",
    "OptionalFeatureUnavailableError",
    "SignedSkillImportRuntime",
    "local_feature_data_dir",
    "windows_session_locked",
]
