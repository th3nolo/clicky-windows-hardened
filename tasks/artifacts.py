"""Pending-output staging and post-verification artifact adoption."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from tasks.coordinator import (
    TaskWorkspace,
    TaskWorkspaceError,
    _is_link_or_reparse,
    _protect_directory,
    _remove_tree_without_following_links,
)
from tasks.models import Artifact, TaskRun, ToolCall, ToolResult
from tasks.verifiers import (
    FileSnapshot,
    VerificationEvidence,
    VerificationSubjectKind,
)


MAX_PARTIAL_REASON_CHARS = 512
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ArtifactAdoptionError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class PendingArtifact:
    """Metadata for task-temp bytes that are not yet an Artifact."""

    artifact_id: str
    run_id: str
    source_call_id: str
    name: str
    media_type: str
    byte_count: int
    sha256: str
    provenance_digest: str
    complete: bool
    partial_reason: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        _identifier(self.artifact_id, "Pending artifact ID")
        _opaque_id(self.run_id, "Pending artifact run ID")
        _opaque_id(self.source_call_id, "Pending artifact call ID")
        _artifact_name(self.name)
        _media_type(self.media_type)
        if (
            type(self.byte_count) is not int
            or not 1 <= self.byte_count <= 64 * 1024 * 1024
        ):
            raise ValueError("Pending artifact size is invalid")
        _sha256(self.sha256, "Pending artifact digest")
        _sha256(
            self.provenance_digest,
            "Pending artifact provenance digest",
        )
        if type(self.complete) is not bool:
            raise TypeError("Pending artifact completeness must be explicit")
        if self.complete:
            if self.partial_reason is not None:
                raise ValueError(
                    "Complete pending artifacts cannot have a partial reason"
                )
        elif (
            not isinstance(self.partial_reason, str)
            or not self.partial_reason.strip()
            or len(self.partial_reason) > MAX_PARTIAL_REASON_CHARS
            or "\x00" in self.partial_reason
        ):
            raise ValueError(
                "Partial pending artifacts require a bounded reason"
            )

    def file_snapshot(self) -> FileSnapshot:
        return FileSnapshot(
            artifact_id=self.artifact_id,
            name=self.name,
            media_type=self.media_type,
            byte_count=self.byte_count,
            sha256=self.sha256,
            provenance_digest=self.provenance_digest,
            complete=self.complete,
        )


class ArtifactAdoptionManager:
    """Move only verified complete bytes from task temp to host storage."""

    def __init__(
        self,
        run: TaskRun,
        workspace: TaskWorkspace,
        *,
        adoption_root: Path | None = None,
    ) -> None:
        if not isinstance(run, TaskRun):
            raise TypeError("Artifact adoption requires a TaskRun")
        if not isinstance(workspace, TaskWorkspace):
            raise TypeError("Artifact adoption requires a TaskWorkspace")
        root = adoption_root or _default_adoption_root()
        if not isinstance(root, Path) or not root.is_absolute():
            raise ValueError("Artifact adoption root must be absolute")
        _reject_linked_existing_ancestors(root)
        self._run = run
        self._workspace = workspace
        self._root = root
        self._pending: dict[str, tuple[PendingArtifact, Path]] = {}
        self._adopted: dict[str, tuple[Artifact, Path]] = {}
        workspace.verify()
        if root.exists() and (
            _is_link_or_reparse(root) or not root.is_dir()
        ):
            raise ArtifactAdoptionError(
                "Artifact storage directory is linked or invalid"
            )

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    @property
    def adopted_count(self) -> int:
        return len(self._adopted)

    def stage(
        self,
        call: ToolCall,
        *,
        artifact_id: str,
        name: str,
        media_type: str,
        content: bytes,
        complete: bool,
        partial_reason: str | None,
    ) -> PendingArtifact:
        if not isinstance(call, ToolCall) or call.run_id != self._run.run_id:
            raise ArtifactAdoptionError("Pending artifact call is invalid")
        if artifact_id in self._pending or artifact_id in self._adopted:
            raise ArtifactAdoptionError("Artifact ID already exists")
        if not isinstance(content, bytes) or not content:
            raise ArtifactAdoptionError("Pending artifact content is invalid")
        digest = hashlib.sha256(content).hexdigest()
        pending = PendingArtifact(
            artifact_id=artifact_id,
            run_id=call.run_id,
            source_call_id=call.call_id,
            name=name,
            media_type=media_type,
            byte_count=len(content),
            sha256=digest,
            provenance_digest=_provenance_digest(
                call,
                artifact_id=artifact_id,
                name=name,
                media_type=media_type,
                byte_count=len(content),
                sha256=digest,
            ),
            complete=complete,
            partial_reason=partial_reason,
        )
        self._workspace.verify()
        directory = self._workspace.path / "pending-artifacts"
        path = directory / _artifact_filename(artifact_id)
        try:
            directory.mkdir(mode=0o700, exist_ok=True)
            self._workspace.verify()
            _write_exclusive(path, content)
            self._workspace.verify()
        except Exception as exc:
            _unlink_regular(path)
            raise ArtifactAdoptionError(
                "Could not stage pending artifact"
            ) from exc
        self._pending[artifact_id] = (pending, path)
        return pending

    def load_pending(
        self,
        artifact_id: str,
    ) -> tuple[PendingArtifact, bytes]:
        record = self._pending.get(artifact_id)
        if record is None:
            raise ArtifactAdoptionError("Pending artifact was not found")
        pending, path = record
        content = self._read_verified(
            path,
            byte_count=pending.byte_count,
            sha256=pending.sha256,
            temporary=True,
        )
        return pending, content

    def adopt(
        self,
        artifact_id: str,
        *,
        evidence: VerificationEvidence,
        result: ToolResult,
    ) -> Artifact:
        pending, content = self.load_pending(artifact_id)
        if not pending.complete:
            raise ArtifactAdoptionError("Partial output cannot be adopted")
        if (
            not isinstance(evidence, VerificationEvidence)
            or evidence.subject_kind is not VerificationSubjectKind.FILE
            or evidence.subject_reference != pending.artifact_id
            or evidence.subject_digest != pending.sha256
            or not evidence.postcondition_met
        ):
            raise ArtifactAdoptionError(
                "Artifact verifier evidence does not match pending bytes"
            )
        if (
            not isinstance(result, ToolResult)
            or result.run_id != pending.run_id
            or result.verifier_id != self._run.spec.verifier_id
            or result.evidence_digest != evidence.evidence_digest
            or not result.is_successful_verification
        ):
            raise ArtifactAdoptionError(
                "Artifact ToolResult is not successful verifier evidence"
            )
        run_directory = self._root / _run_directory_name(pending.run_id)
        _prepare_private_directory(run_directory)
        destination = run_directory / _artifact_filename(artifact_id)
        try:
            _write_exclusive(destination, content)
        except Exception as exc:
            _unlink_regular(destination)
            raise ArtifactAdoptionError(
                "Could not adopt verified artifact"
            ) from exc
        artifact = Artifact(
            artifact_id=pending.artifact_id,
            run_id=pending.run_id,
            source_call_id=pending.source_call_id,
            name=pending.name,
            media_type=pending.media_type,
            byte_count=pending.byte_count,
            sha256=pending.sha256,
            verification_result_id=result.result_id,
            verification_evidence_digest=evidence.evidence_digest,
        )
        pending_path = self._pending[artifact_id][1]
        try:
            pending_path.unlink()
        except OSError as exc:
            _unlink_regular(destination)
            raise ArtifactAdoptionError(
                "Could not remove verified task-temp output"
            ) from exc
        del self._pending[artifact_id]
        self._adopted[artifact_id] = (artifact, destination)
        return artifact

    def read_adopted(self, artifact_id: str) -> tuple[Artifact, bytes]:
        record = self._adopted.get(artifact_id)
        if record is None:
            raise ArtifactAdoptionError("Adopted artifact was not found")
        artifact, path = record
        content = self._read_verified(
            path,
            byte_count=artifact.byte_count,
            sha256=artifact.sha256,
            temporary=False,
        )
        return artifact, content

    def discard_incomplete(self) -> None:
        """Delete pending bytes without touching adopted artifacts."""

        directory = self._workspace.path / "pending-artifacts"
        if not directory.exists() and not directory.is_symlink():
            self._pending.clear()
            return
        try:
            _remove_tree_without_following_links(directory)
        except OSError as exc:
            raise ArtifactAdoptionError(
                "Could not discard incomplete task output"
            ) from exc
        self._pending.clear()
        self._workspace.verify()

    def _read_verified(
        self,
        path: Path,
        *,
        byte_count: int,
        sha256: str,
        temporary: bool,
    ) -> bytes:
        if temporary:
            self._workspace.verify()
        elif _is_link_or_reparse(path.parent):
            raise ArtifactAdoptionError(
                "Adopted artifact directory identity changed"
            )
        try:
            metadata = path.stat(follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_size != byte_count
            ):
                raise OSError("artifact identity changed")
            with path.open("rb") as stream:
                content = stream.read(byte_count + 1)
            if (
                len(content) != byte_count
                or hashlib.sha256(content).hexdigest() != sha256
            ):
                raise OSError("artifact integrity changed")
        except Exception as exc:
            raise ArtifactAdoptionError(
                "Artifact bytes failed integrity validation"
            ) from exc
        return content


def _default_adoption_root() -> Path:
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise TaskWorkspaceError(
                "LOCALAPPDATA is required for task artifact adoption"
            )
        root = Path(local_app_data)
        if not root.is_absolute():
            raise TaskWorkspaceError("LOCALAPPDATA must be absolute")
        return root / "Clicky" / "TaskArtifacts"
    return Path.home() / ".clicky" / "task-artifacts"


def _prepare_private_directory(path: Path) -> None:
    try:
        _reject_linked_existing_ancestors(path)
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        _reject_linked_existing_ancestors(path)
        if not path.is_dir():
            raise ArtifactAdoptionError(
                "Artifact storage directory is linked or invalid"
            )
        _protect_directory(path)
    except ArtifactAdoptionError:
        raise
    except OSError as exc:
        raise ArtifactAdoptionError(
            "Could not prepare private artifact storage"
        ) from exc


def _reject_linked_existing_ancestors(path: Path) -> None:
    current = path
    while not current.exists():
        parent = current.parent
        if parent == current:
            raise ArtifactAdoptionError(
                "Artifact storage has no existing absolute ancestor"
            )
        current = parent
    for candidate in (current, *current.parents):
        if _is_link_or_reparse(candidate):
            raise ArtifactAdoptionError(
                "Artifact storage ancestors cannot be linked"
            )


def _write_exclusive(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        _unlink_regular(path)
        raise


def _unlink_regular(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        return
    except OSError:
        return


def _artifact_filename(artifact_id: str) -> str:
    return hashlib.sha256(artifact_id.encode("utf-8")).hexdigest() + ".artifact"


def _run_directory_name(run_id: str) -> str:
    return "task-" + hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:32]


def _provenance_digest(
    call: ToolCall,
    *,
    artifact_id: str,
    name: str,
    media_type: str,
    byte_count: int,
    sha256: str,
) -> str:
    encoded = json.dumps(
        {
            "artifact_id": artifact_id,
            "arguments_digest": call.arguments_digest,
            "byte_count": byte_count,
            "call_id": call.call_id,
            "capability": call.capability.value,
            "media_type": media_type,
            "name": name,
            "run_id": call.run_id,
            "sha256": sha256,
            "step_id": call.step_id,
            "tool_name": call.tool_name,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _identifier(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or _IDENTIFIER.fullmatch(value) is None
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _opaque_id(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or not value.isprintable()
        or any(character in "/\\" for character in value)
    ):
        raise ValueError(f"{label} is invalid")
    return value


def _artifact_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or Path(value).name != value
        or any(character in "/\\\x00" for character in value)
    ):
        raise ValueError("Pending artifact name is invalid")
    return value


def _media_type(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 3 <= len(value) <= 127
        or "/" not in value
        or not value.isprintable()
    ):
        raise ValueError("Pending artifact media type is invalid")
    return value


def _sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{label} must be SHA-256")
    return value


__all__ = [
    "ArtifactAdoptionError",
    "ArtifactAdoptionManager",
    "PendingArtifact",
]
