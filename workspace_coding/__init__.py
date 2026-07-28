"""Default-off contracts for isolated workspace-coding tasks."""

from workspace_coding.broker import (
    WorkspaceBroker,
    WorkspaceBrokerError,
    WorkspaceCommandLauncher,
)
from workspace_coding.models import (
    CommandProfile,
    GitWorkspaceIdentity,
    IsolatedWorkspaceResult,
    VerificationReceipt,
    WorkspaceChange,
    WorkspaceChangeKind,
    WorkspaceCommandRequest,
    WorkspaceDeleteRequest,
    WorkspaceFileRecord,
    WorkspaceManifest,
    WorkspaceMkdirRequest,
    WorkspaceReadRequest,
    WorkspaceWriteRequest,
    workspace_action_digest,
)
from workspace_coding.sandbox import (
    SandboxConfiguration,
    SandboxConfigurationError,
    generate_sandbox_configuration,
    verify_isolated_result,
)
from workspace_coding.snapshot import (
    WorkspaceSnapshot,
    WorkspaceSnapshotError,
    create_isolated_snapshot,
    inspect_selected_git_workspace,
)

__all__ = [
    "CommandProfile",
    "GitWorkspaceIdentity",
    "IsolatedWorkspaceResult",
    "SandboxConfiguration",
    "SandboxConfigurationError",
    "VerificationReceipt",
    "WorkspaceBroker",
    "WorkspaceBrokerError",
    "WorkspaceChange",
    "WorkspaceChangeKind",
    "WorkspaceCommandLauncher",
    "WorkspaceCommandRequest",
    "WorkspaceDeleteRequest",
    "WorkspaceFileRecord",
    "WorkspaceManifest",
    "WorkspaceMkdirRequest",
    "WorkspaceReadRequest",
    "WorkspaceSnapshot",
    "WorkspaceSnapshotError",
    "WorkspaceWriteRequest",
    "create_isolated_snapshot",
    "generate_sandbox_configuration",
    "inspect_selected_git_workspace",
    "verify_isolated_result",
    "workspace_action_digest",
]
