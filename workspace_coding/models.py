"""Immutable, content-minimized contracts for one isolated coding task."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from enum import Enum

from capability_registry import CapabilityId


MAX_WORKSPACE_PATH_CHARS = 1_024
MAX_WORKSPACE_FILES = 10_000
MAX_WORKSPACE_BYTES = 1024 * 1024 * 1024
MAX_WORKSPACE_FILE_BYTES = 64 * 1024 * 1024
MAX_COMMAND_ARGUMENTS = 32
MAX_COMMAND_ARGUMENT_CHARS = 512
MAX_COMMAND_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_COMMAND_SECONDS = 5 * 60
MAX_CHANGESET_FILES = MAX_WORKSPACE_FILES
MAX_DIFF_BYTES = 16 * 1024 * 1024
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_PROFILE_ARGUMENT = re.compile(r"^[A-Za-z0-9_./:=+@,-]+$")
_SELECTOR_ARGUMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*$")


class WorkspaceChangeKind(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"


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
        raise ValueError("Workspace value is not canonical JSON") from exc


def _token(value: object, label: str, *, maximum: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or _OPAQUE_ID.fullmatch(value) is None
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _identifier(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or _IDENTIFIER.fullmatch(value) is None
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be SHA-256")
    return value


def _commit(value: object) -> str:
    if not isinstance(value, str) or _COMMIT.fullmatch(value) is None:
        raise ValueError("Workspace HEAD commit is invalid")
    return value


def _bounded_int(
    value: object,
    minimum: int,
    maximum: int,
    label: str,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class GitWorkspaceIdentity:
    """Content-free identity established by the trusted host selector."""

    repository_id: str
    final_path_sha256: str
    head_commit: str
    branch: str | None
    status_sha256: str
    git_executable_sha256: str
    dirty: bool

    def __post_init__(self) -> None:
        _token(self.repository_id, "Workspace repository ID")
        _sha256(self.final_path_sha256, "Workspace final-path digest")
        _commit(self.head_commit)
        if self.branch is not None and (
            not isinstance(self.branch, str)
            or not self.branch
            or len(self.branch) > 255
            or "\x00" in self.branch
            or not self.branch.isprintable()
        ):
            raise ValueError("Workspace branch is invalid")
        _sha256(self.status_sha256, "Workspace status digest")
        _sha256(self.git_executable_sha256, "Git executable digest")
        if type(self.dirty) is not bool:
            raise TypeError("Workspace dirty state must be explicit")

    @property
    def identity_digest(self) -> str:
        return hashlib.sha256(
            _canonical_json(
                {
                    "branch": self.branch,
                    "dirty": self.dirty,
                    "final_path_sha256": self.final_path_sha256,
                    "git_executable_sha256": self.git_executable_sha256,
                    "head_commit": self.head_commit,
                    "repository_id": self.repository_id,
                    "status_sha256": self.status_sha256,
                }
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class WorkspaceFileRecord:
    relative_path: str
    byte_count: int
    sha256: str

    def __post_init__(self) -> None:
        from workspace_coding.paths import validate_relative_workspace_path

        validate_relative_workspace_path(self.relative_path)
        _bounded_int(
            self.byte_count,
            0,
            MAX_WORKSPACE_FILE_BYTES,
            "Workspace file size",
        )
        _sha256(self.sha256, "Workspace file digest")

    def canonical_value(self) -> dict[str, object]:
        return {
            "byte_count": self.byte_count,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class WorkspaceManifest:
    run_id: str
    repository_identity_digest: str
    files: tuple[WorkspaceFileRecord, ...]
    total_bytes: int

    def __post_init__(self) -> None:
        _token(self.run_id, "Workspace run ID")
        _sha256(
            self.repository_identity_digest,
            "Workspace repository identity digest",
        )
        if (
            not isinstance(self.files, tuple)
            or len(self.files) > MAX_WORKSPACE_FILES
            or any(
                not isinstance(item, WorkspaceFileRecord)
                for item in self.files
            )
        ):
            raise ValueError("Workspace manifest files are invalid")
        paths = [item.relative_path for item in self.files]
        if paths != sorted(paths, key=str.casefold):
            raise ValueError("Workspace manifest must be canonically ordered")
        if len({path.casefold() for path in paths}) != len(paths):
            raise ValueError("Workspace manifest path identity is ambiguous")
        _bounded_int(
            self.total_bytes,
            0,
            MAX_WORKSPACE_BYTES,
            "Workspace manifest size",
        )
        if self.total_bytes != sum(item.byte_count for item in self.files):
            raise ValueError("Workspace manifest size does not match files")

    @property
    def manifest_digest(self) -> str:
        return hashlib.sha256(self.to_json_bytes()).hexdigest()

    def to_json_bytes(self) -> bytes:
        return _canonical_json(
            {
                "files": [item.canonical_value() for item in self.files],
                "repository_identity_digest": (
                    self.repository_identity_digest
                ),
                "run_id": self.run_id,
                "schema_version": 1,
                "total_bytes": self.total_bytes,
            }
        )


@dataclass(frozen=True, slots=True)
class WorkspaceReadRequest:
    relative_path: str
    expected_sha256: str
    maximum_bytes: int = MAX_WORKSPACE_FILE_BYTES

    def __post_init__(self) -> None:
        from workspace_coding.paths import validate_relative_workspace_path

        validate_relative_workspace_path(self.relative_path)
        _sha256(self.expected_sha256, "Workspace read digest")
        _bounded_int(
            self.maximum_bytes,
            1,
            MAX_WORKSPACE_FILE_BYTES,
            "Workspace read limit",
        )

    @property
    def arguments_digest(self) -> str:
        return _request_digest(
            "workspace.read",
            {
                "expected_sha256": self.expected_sha256,
                "maximum_bytes": self.maximum_bytes,
                "relative_path": self.relative_path,
            },
        )


@dataclass(frozen=True, slots=True)
class WorkspaceWriteRequest:
    relative_path: str
    content: bytes = field(repr=False)
    expected_prior_sha256: str | None
    maximum_bytes: int = MAX_WORKSPACE_FILE_BYTES

    def __post_init__(self) -> None:
        from workspace_coding.paths import validate_relative_workspace_path

        validate_relative_workspace_path(self.relative_path)
        if (
            not isinstance(self.content, bytes)
            or len(self.content) > self.maximum_bytes
        ):
            raise ValueError("Workspace write content is invalid")
        if self.expected_prior_sha256 is not None:
            _sha256(
                self.expected_prior_sha256,
                "Workspace prior file digest",
            )
        _bounded_int(
            self.maximum_bytes,
            1,
            MAX_WORKSPACE_FILE_BYTES,
            "Workspace write limit",
        )

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()

    @property
    def arguments_digest(self) -> str:
        return _request_digest(
            "workspace.write",
            {
                "content_bytes": len(self.content),
                "content_sha256": self.content_sha256,
                "expected_prior_sha256": self.expected_prior_sha256,
                "maximum_bytes": self.maximum_bytes,
                "relative_path": self.relative_path,
            },
        )


@dataclass(frozen=True, slots=True)
class WorkspaceDeleteRequest:
    relative_path: str
    expected_sha256: str

    def __post_init__(self) -> None:
        from workspace_coding.paths import validate_relative_workspace_path

        validate_relative_workspace_path(self.relative_path)
        _sha256(self.expected_sha256, "Workspace delete digest")

    @property
    def arguments_digest(self) -> str:
        return _request_digest(
            "workspace.delete",
            {
                "expected_sha256": self.expected_sha256,
                "relative_path": self.relative_path,
            },
        )


@dataclass(frozen=True, slots=True)
class WorkspaceMkdirRequest:
    relative_path: str

    def __post_init__(self) -> None:
        from workspace_coding.paths import validate_relative_workspace_path

        validate_relative_workspace_path(self.relative_path)

    @property
    def arguments_digest(self) -> str:
        return _request_digest(
            "workspace.mkdir",
            {"relative_path": self.relative_path},
        )


@dataclass(frozen=True, slots=True)
class CommandProfile:
    profile_id: str
    executable_relative_path: str
    executable_sha256: str
    fixed_arguments: tuple[str, ...]
    allow_selectors: bool
    runs_candidate_code: bool
    timeout_seconds: int = MAX_COMMAND_SECONDS
    maximum_output_bytes: int = MAX_COMMAND_OUTPUT_BYTES

    def __post_init__(self) -> None:
        from workspace_coding.paths import validate_relative_workspace_path

        _identifier(self.profile_id, "Command profile ID")
        validate_relative_workspace_path(self.executable_relative_path)
        if self.executable_relative_path.rsplit("/", 1)[-1].casefold() in {
            "bash",
            "bash.exe",
            "bun",
            "bun.exe",
            "cmd",
            "cmd.exe",
            "cscript",
            "cscript.exe",
            "npx",
            "npx.cmd",
            "powershell",
            "powershell.exe",
            "pwsh",
            "pwsh.exe",
            "sh",
            "sh.exe",
            "wscript",
            "wscript.exe",
            "yarn",
            "yarn.cmd",
        }:
            raise ValueError("Command profile executable is not allowlisted")
        _sha256(self.executable_sha256, "Command executable digest")
        _arguments(self.fixed_arguments, "Command fixed arguments")
        if type(self.allow_selectors) is not bool:
            raise TypeError("Command selector policy must be explicit")
        if type(self.runs_candidate_code) is not bool:
            raise TypeError("Command execution policy must be explicit")
        _bounded_int(
            self.timeout_seconds,
            1,
            MAX_COMMAND_SECONDS,
            "Command timeout",
        )
        _bounded_int(
            self.maximum_output_bytes,
            1,
            MAX_COMMAND_OUTPUT_BYTES,
            "Command output limit",
        )
        _reject_dependency_or_shell_tokens(self.fixed_arguments)

    @property
    def profile_digest(self) -> str:
        return hashlib.sha256(
            _canonical_json(
                {
                    "allow_selectors": self.allow_selectors,
                    "executable_relative_path": (
                        self.executable_relative_path
                    ),
                    "executable_sha256": self.executable_sha256,
                    "fixed_arguments": list(self.fixed_arguments),
                    "maximum_output_bytes": self.maximum_output_bytes,
                    "profile_id": self.profile_id,
                    "runs_candidate_code": self.runs_candidate_code,
                    "timeout_seconds": self.timeout_seconds,
                }
            )
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class WorkspaceCommandRequest:
    profile_id: str
    profile_digest: str
    staging_manifest_digest: str
    selectors: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.profile_id, "Command profile ID")
        _sha256(self.profile_digest, "Command profile digest")
        _sha256(
            self.staging_manifest_digest,
            "Command staging digest",
        )
        _arguments(self.selectors, "Command selectors")
        for selector in self.selectors:
            if (
                _SELECTOR_ARGUMENT.fullmatch(selector) is None
                or any(
                    not component
                    for component in selector.split(".")
                )
            ):
                raise ValueError("Command selectors are not canonical")
        _reject_dependency_or_shell_tokens(self.selectors)

    @property
    def arguments_digest(self) -> str:
        return _request_digest(
            "workspace.command",
            {
                "profile_digest": self.profile_digest,
                "profile_id": self.profile_id,
                "selectors": list(self.selectors),
                "staging_manifest_digest": self.staging_manifest_digest,
            },
        )


@dataclass(frozen=True, slots=True)
class VerificationReceipt:
    profile_id: str
    profile_digest: str
    staging_manifest_digest: str
    arguments_digest: str
    exit_code: int
    output_sha256: str
    output_bytes: int
    duration_seconds: float
    succeeded: bool

    def __post_init__(self) -> None:
        _identifier(self.profile_id, "Verification profile ID")
        _sha256(self.profile_digest, "Verification profile digest")
        _sha256(
            self.staging_manifest_digest,
            "Verification staging digest",
        )
        _sha256(self.arguments_digest, "Verification arguments digest")
        if type(self.exit_code) is not int or not -2**31 <= self.exit_code < 2**31:
            raise ValueError("Verification exit code is invalid")
        _sha256(self.output_sha256, "Verification output digest")
        _bounded_int(
            self.output_bytes,
            0,
            MAX_COMMAND_OUTPUT_BYTES,
            "Verification output size",
        )
        if (
            not isinstance(self.duration_seconds, (int, float))
            or isinstance(self.duration_seconds, bool)
            or not math.isfinite(float(self.duration_seconds))
            or not 0 <= float(self.duration_seconds) <= MAX_COMMAND_SECONDS
        ):
            raise ValueError("Verification duration is invalid")
        if type(self.succeeded) is not bool:
            raise TypeError("Verification status must be explicit")
        if self.succeeded != (self.exit_code == 0):
            raise ValueError("Verification status does not match exit code")


@dataclass(frozen=True, slots=True)
class WorkspaceChange:
    relative_path: str
    kind: WorkspaceChangeKind
    prior_sha256: str | None
    current_sha256: str | None
    prior_bytes: int | None
    current_bytes: int | None

    def __post_init__(self) -> None:
        from workspace_coding.paths import validate_relative_workspace_path

        validate_relative_workspace_path(self.relative_path)
        if not isinstance(self.kind, WorkspaceChangeKind):
            raise TypeError("Workspace change kind is invalid")
        for digest in (self.prior_sha256, self.current_sha256):
            if digest is not None:
                _sha256(digest, "Workspace change digest")
        for count in (self.prior_bytes, self.current_bytes):
            if count is not None:
                _bounded_int(
                    count,
                    0,
                    MAX_WORKSPACE_FILE_BYTES,
                    "Workspace change size",
                )
        if self.kind is WorkspaceChangeKind.ADDED and (
            self.prior_sha256 is not None
            or self.prior_bytes is not None
            or self.current_sha256 is None
            or self.current_bytes is None
        ):
            raise ValueError("Added workspace change is inconsistent")
        if self.kind is WorkspaceChangeKind.DELETED and (
            self.current_sha256 is not None
            or self.current_bytes is not None
            or self.prior_sha256 is None
            or self.prior_bytes is None
        ):
            raise ValueError("Deleted workspace change is inconsistent")
        if self.kind is WorkspaceChangeKind.MODIFIED and (
            self.prior_sha256 is None
            or self.current_sha256 is None
            or self.prior_bytes is None
            or self.current_bytes is None
            or self.prior_sha256 == self.current_sha256
        ):
            raise ValueError("Modified workspace change is inconsistent")


@dataclass(frozen=True, slots=True)
class IsolatedWorkspaceResult:
    baseline_manifest_digest: str
    final_manifest: WorkspaceManifest
    changes: tuple[WorkspaceChange, ...]
    verifications: tuple[VerificationReceipt, ...]
    state: str

    def __post_init__(self) -> None:
        _sha256(
            self.baseline_manifest_digest,
            "Baseline manifest digest",
        )
        if not isinstance(self.final_manifest, WorkspaceManifest):
            raise TypeError("Final workspace manifest is invalid")
        if (
            not isinstance(self.changes, tuple)
            or len(self.changes) > MAX_CHANGESET_FILES
            or any(not isinstance(item, WorkspaceChange) for item in self.changes)
        ):
            raise ValueError("Workspace changes are invalid")
        paths = [item.relative_path for item in self.changes]
        if paths != sorted(paths, key=str.casefold):
            raise ValueError("Workspace changes must be ordered")
        if (
            not isinstance(self.verifications, tuple)
            or len(self.verifications) > 16
            or any(
                not isinstance(item, VerificationReceipt)
                for item in self.verifications
            )
        ):
            raise ValueError("Workspace verification evidence is invalid")
        if self.state not in {
            "awaiting_review",
            "failed",
            "partial",
            "cancelled",
        }:
            raise ValueError("Isolated workspace result state is invalid")
        all_succeeded = bool(self.verifications) and all(
            item.succeeded
            and item.staging_manifest_digest
            == self.final_manifest.manifest_digest
            for item in self.verifications
        )
        if self.state == "awaiting_review" and not all_succeeded:
            raise ValueError(
                "Reviewable workspace results require exact successful "
                "verification"
            )
        if self.state in {"failed", "partial"} and all_succeeded:
            raise ValueError(
                "Successful verification evidence cannot use failure state"
            )

    @property
    def result_digest(self) -> str:
        return hashlib.sha256(
            _canonical_json(
                {
                    "baseline_manifest_digest": (
                        self.baseline_manifest_digest
                    ),
                    "changes": [
                        {
                            "current_bytes": item.current_bytes,
                            "current_sha256": item.current_sha256,
                            "kind": item.kind.value,
                            "prior_bytes": item.prior_bytes,
                            "prior_sha256": item.prior_sha256,
                            "relative_path": item.relative_path,
                        }
                        for item in self.changes
                    ],
                    "final_manifest_digest": (
                        self.final_manifest.manifest_digest
                    ),
                    "state": self.state,
                    "verifications": [
                        {
                            "arguments_digest": item.arguments_digest,
                            "exit_code": item.exit_code,
                            "output_bytes": item.output_bytes,
                            "output_sha256": item.output_sha256,
                            "profile_digest": item.profile_digest,
                            "profile_id": item.profile_id,
                            "staging_manifest_digest": (
                                item.staging_manifest_digest
                            ),
                            "succeeded": item.succeeded,
                        }
                        for item in self.verifications
                    ],
                }
            )
        ).hexdigest()


def workspace_action_digest(
    *,
    run_id: str,
    call_id: str,
    capability: CapabilityId,
    arguments_digest: str,
) -> str:
    _token(run_id, "Workspace action run ID")
    _token(call_id, "Workspace action call ID")
    if capability not in {
        CapabilityId.WORKSPACE_WRITE,
        CapabilityId.WORKSPACE_COMMAND,
    }:
        raise ValueError("Workspace action capability is invalid")
    _sha256(arguments_digest, "Workspace action arguments digest")
    return hashlib.sha256(
        _canonical_json(
            {
                "arguments_digest": arguments_digest,
                "call_id": call_id,
                "capability": capability.value,
                "run_id": run_id,
                "schema_version": 1,
            }
        )
    ).hexdigest()


def _request_digest(operation: str, value: dict[str, object]) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "operation": operation,
                "schema_version": 1,
                **value,
            }
        )
    ).hexdigest()


def _arguments(value: object, label: str) -> tuple[str, ...]:
    if (
        not isinstance(value, tuple)
        or len(value) > MAX_COMMAND_ARGUMENTS
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > MAX_COMMAND_ARGUMENT_CHARS
            or _PROFILE_ARGUMENT.fullmatch(item) is None
            for item in value
        )
    ):
        raise ValueError(f"{label} are invalid")
    return value


def _reject_dependency_or_shell_tokens(arguments: tuple[str, ...]) -> None:
    forbidden = {
        "add",
        "ci",
        "dlx",
        "eval",
        "exec",
        "fetch",
        "i",
        "install",
        "publish",
        "rm",
        "remove",
        "sync",
        "un",
        "uninstall",
        "up",
        "update",
        "upgrade",
    }
    shell_tokens = {"|", "||", "&", "&&", ">", ">>", "<", ";", "`"}
    for argument in arguments:
        folded = argument.casefold()
        normalized = (
            folded[2:].split("=", 1)[0]
            if folded.startswith("--")
            else folded[1:].split("=", 1)[0]
            if folded.startswith("/") and len(folded) > 2
            else folded
        )
        if (
            normalized in forbidden
            or folded in shell_tokens
            or "$(" in argument
            or "%comspec%" in folded
            or argument.startswith("@")
        ):
            raise ValueError(
                "Command profiles cannot install dependencies or use a shell"
            )


__all__ = [
    "CommandProfile",
    "GitWorkspaceIdentity",
    "IsolatedWorkspaceResult",
    "MAX_COMMAND_OUTPUT_BYTES",
    "MAX_COMMAND_SECONDS",
    "MAX_DIFF_BYTES",
    "MAX_WORKSPACE_BYTES",
    "MAX_WORKSPACE_FILES",
    "MAX_WORKSPACE_FILE_BYTES",
    "VerificationReceipt",
    "WorkspaceChange",
    "WorkspaceChangeKind",
    "WorkspaceCommandRequest",
    "WorkspaceDeleteRequest",
    "WorkspaceFileRecord",
    "WorkspaceManifest",
    "WorkspaceMkdirRequest",
    "WorkspaceReadRequest",
    "WorkspaceWriteRequest",
    "workspace_action_digest",
]
