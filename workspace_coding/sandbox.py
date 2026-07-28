"""Exact Windows Sandbox configuration and untrusted-result verification."""

from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import PureWindowsPath, Path

from workspace_coding.models import (
    IsolatedWorkspaceResult,
    VerificationReceipt,
    WorkspaceChange,
    WorkspaceChangeKind,
    WorkspaceManifest,
)
from workspace_coding.paths import ensure_plain_directory
from workspace_coding.snapshot import WorkspaceSnapshot, scan_workspace


SANDBOX_INPUT_PATH = r"C:\ClickyInput"
SANDBOX_TASK_PATH = r"C:\ClickyTask"
SANDBOX_LOGON_COMMAND = (
    r"C:\ClickyInput\python\python.exe -I -S "
    r"C:\ClickyInput\workspace-worker.py "
    r"--envelope C:\ClickyInput\task-envelope.json "
    r"--workspace C:\ClickyTask\workspace "
    r"--results C:\ClickyTask\results"
)
_DRIVE_ROOTED = re.compile(r"^[A-Za-z]:\\")


class SandboxConfigurationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class SandboxConfiguration:
    input_host_path: str
    task_host_path: str
    xml_bytes: bytes

    def __post_init__(self) -> None:
        _host_path(self.input_host_path)
        _host_path(self.task_host_path)
        if (
            not isinstance(self.xml_bytes, bytes)
            or not 256 <= len(self.xml_bytes) <= 32 * 1024
        ):
            raise ValueError("Windows Sandbox configuration is invalid")


def generate_sandbox_configuration(
    *,
    input_host_path: str,
    task_host_path: str,
) -> SandboxConfiguration:
    """Generate the only allowed two-mapping, network-disabled V1 config."""

    input_path = _host_path(input_host_path)
    task_path = _host_path(task_host_path)
    input_folded = input_path.rstrip("\\").casefold() + "\\"
    task_folded = task_path.rstrip("\\").casefold() + "\\"
    if (
        input_folded.startswith(task_folded)
        or task_folded.startswith(input_folded)
    ):
        raise SandboxConfigurationError(
            "Windows Sandbox mappings cannot overlap"
        )
    root = ET.Element("Configuration")
    for name, value in (
        ("vGPU", "Disable"),
        ("Networking", "Disable"),
        ("AudioInput", "Disable"),
        ("VideoInput", "Disable"),
        ("PrinterRedirection", "Disable"),
        ("ClipboardRedirection", "Disable"),
        ("ProtectedClient", "Enable"),
    ):
        ET.SubElement(root, name).text = value
    mappings = ET.SubElement(root, "MappedFolders")
    _mapping(
        mappings,
        host=input_path,
        sandbox=SANDBOX_INPUT_PATH,
        read_only=True,
    )
    _mapping(
        mappings,
        host=task_path,
        sandbox=SANDBOX_TASK_PATH,
        read_only=False,
    )
    logon = ET.SubElement(root, "LogonCommand")
    ET.SubElement(logon, "Command").text = SANDBOX_LOGON_COMMAND
    xml_bytes = ET.tostring(
        root,
        encoding="utf-8",
        xml_declaration=True,
        short_empty_elements=False,
    )
    _verify_generated_configuration(
        xml_bytes,
        input_path=input_path,
        task_path=task_path,
    )
    return SandboxConfiguration(
        input_host_path=input_path,
        task_host_path=task_path,
        xml_bytes=xml_bytes,
    )


def verify_isolated_result(
    *,
    snapshot: WorkspaceSnapshot,
    verifications: tuple[VerificationReceipt, ...],
    cancelled: bool = False,
) -> IsolatedWorkspaceResult:
    """Inspect Sandbox output without executing it and derive truthful state."""

    if not isinstance(snapshot, WorkspaceSnapshot):
        raise TypeError("Workspace snapshot is invalid")
    baseline = snapshot.baseline_manifest
    final_workspace_root = snapshot.workspace_root
    ensure_plain_directory(final_workspace_root)
    if (
        not isinstance(verifications, tuple)
        or any(
            not isinstance(item, VerificationReceipt)
            for item in verifications
        )
    ):
        raise TypeError("Workspace verification receipts are invalid")
    final_manifest, _directories = scan_workspace(
        final_workspace_root,
        run_id=baseline.run_id,
        repository_identity_digest=(
            baseline.repository_identity_digest
        ),
    )
    changes = _changes(baseline, final_manifest)
    all_succeeded = bool(verifications) and all(
        receipt.succeeded
        and receipt.staging_manifest_digest
        == final_manifest.manifest_digest
        for receipt in verifications
    )
    if cancelled:
        state = "cancelled"
    elif all_succeeded:
        state = "awaiting_review"
    elif verifications:
        state = "failed"
    else:
        state = "partial"
    return IsolatedWorkspaceResult(
        baseline_manifest_digest=baseline.manifest_digest,
        final_manifest=final_manifest,
        changes=changes,
        verifications=verifications,
        state=state,
    )


def _changes(
    baseline: WorkspaceManifest,
    final: WorkspaceManifest,
) -> tuple[WorkspaceChange, ...]:
    before = {item.relative_path.casefold(): item for item in baseline.files}
    after = {item.relative_path.casefold(): item for item in final.files}
    output: list[WorkspaceChange] = []
    for key in sorted(set(before) | set(after)):
        prior = before.get(key)
        current = after.get(key)
        if prior is None:
            assert current is not None
            output.append(
                WorkspaceChange(
                    relative_path=current.relative_path,
                    kind=WorkspaceChangeKind.ADDED,
                    prior_sha256=None,
                    current_sha256=current.sha256,
                    prior_bytes=None,
                    current_bytes=current.byte_count,
                )
            )
        elif current is None:
            output.append(
                WorkspaceChange(
                    relative_path=prior.relative_path,
                    kind=WorkspaceChangeKind.DELETED,
                    prior_sha256=prior.sha256,
                    current_sha256=None,
                    prior_bytes=prior.byte_count,
                    current_bytes=None,
                )
            )
        elif prior.sha256 != current.sha256:
            if prior.relative_path != current.relative_path:
                raise SandboxConfigurationError(
                    "Workspace output changed path casing"
                )
            output.append(
                WorkspaceChange(
                    relative_path=current.relative_path,
                    kind=WorkspaceChangeKind.MODIFIED,
                    prior_sha256=prior.sha256,
                    current_sha256=current.sha256,
                    prior_bytes=prior.byte_count,
                    current_bytes=current.byte_count,
                )
            )
    return tuple(sorted(output, key=lambda item: item.relative_path.casefold()))


def _host_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 3 <= len(value) <= 1024
        or _DRIVE_ROOTED.match(value) is None
        or "/" in value
        or "\x00" in value
    ):
        raise SandboxConfigurationError(
            "Windows Sandbox host mapping must be a drive-rooted path"
        )
    path = PureWindowsPath(value)
    if any(part in {".", ".."} for part in path.parts):
        raise SandboxConfigurationError(
            "Windows Sandbox host mapping is not canonical"
        )
    return str(path)


def _mapping(
    parent: ET.Element,
    *,
    host: str,
    sandbox: str,
    read_only: bool,
) -> None:
    mapping = ET.SubElement(parent, "MappedFolder")
    ET.SubElement(mapping, "HostFolder").text = host
    ET.SubElement(mapping, "SandboxFolder").text = sandbox
    ET.SubElement(mapping, "ReadOnly").text = (
        "true" if read_only else "false"
    )


def _verify_generated_configuration(
    xml_bytes: bytes,
    *,
    input_path: str,
    task_path: str,
) -> None:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise SandboxConfigurationError(
            "Generated Windows Sandbox configuration is malformed"
        ) from exc
    expected = {
        "vGPU": "Disable",
        "Networking": "Disable",
        "AudioInput": "Disable",
        "VideoInput": "Disable",
        "PrinterRedirection": "Disable",
        "ClipboardRedirection": "Disable",
        "ProtectedClient": "Enable",
    }
    if root.tag != "Configuration":
        raise SandboxConfigurationError(
            "Windows Sandbox configuration root is invalid"
        )
    for name, value in expected.items():
        if root.findtext(name) != value:
            raise SandboxConfigurationError(
                "Windows Sandbox security setting is invalid"
            )
    mappings = root.findall("./MappedFolders/MappedFolder")
    actual = [
        (
            item.findtext("HostFolder"),
            item.findtext("SandboxFolder"),
            item.findtext("ReadOnly"),
        )
        for item in mappings
    ]
    if actual != [
        (input_path, SANDBOX_INPUT_PATH, "true"),
        (task_path, SANDBOX_TASK_PATH, "false"),
    ]:
        raise SandboxConfigurationError(
            "Windows Sandbox mappings are invalid"
        )
    if root.findtext("./LogonCommand/Command") != SANDBOX_LOGON_COMMAND:
        raise SandboxConfigurationError(
            "Windows Sandbox worker command is invalid"
        )


__all__ = [
    "SANDBOX_INPUT_PATH",
    "SANDBOX_LOGON_COMMAND",
    "SANDBOX_TASK_PATH",
    "SandboxConfiguration",
    "SandboxConfigurationError",
    "generate_sandbox_configuration",
    "verify_isolated_result",
]
