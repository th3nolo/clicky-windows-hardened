"""Closed vocabulary shared by declarative skills and the trusted task broker."""

from __future__ import annotations

from enum import Enum
from types import MappingProxyType
from typing import Mapping

from capability_registry import CapabilityId


class DeclarativeTool(str, Enum):
    """Reviewed broker operations; deliberately excludes shell and Python."""

    MODEL_GENERATE = "model.generate"
    WEB_SEARCH = "web.search"
    WEB_FETCH = "web.fetch"
    RESEARCH_CSV_RENDER = "research.csv.render"
    ARTIFACT_READ = "artifact.read"
    ARTIFACT_WRITE = "artifact.write"
    CONNECTOR_READ = "connector.read"
    CONNECTOR_WRITE = "connector.write"
    VERIFY_OUTPUT = "verify.output"


TOOL_CAPABILITIES: Mapping[
    DeclarativeTool, CapabilityId
] = MappingProxyType(
    {
        DeclarativeTool.MODEL_GENERATE: CapabilityId.TASK_AGENT_RUN,
        DeclarativeTool.WEB_SEARCH: CapabilityId.WEB_SEARCH_BOUNDED,
        DeclarativeTool.WEB_FETCH: CapabilityId.WEB_FETCH_BOUNDED,
        DeclarativeTool.RESEARCH_CSV_RENDER: CapabilityId.TASK_AGENT_RUN,
        DeclarativeTool.ARTIFACT_READ: CapabilityId.LOCAL_ARTIFACT_READ,
        DeclarativeTool.ARTIFACT_WRITE: CapabilityId.LOCAL_ARTIFACT_WRITE,
        DeclarativeTool.VERIFY_OUTPUT: CapabilityId.TASK_AGENT_RUN,
    }
)


INITIAL_TASK_BROKER_TOOLS = frozenset(TOOL_CAPABILITIES)


__all__ = [
    "DeclarativeTool",
    "INITIAL_TASK_BROKER_TOOLS",
    "TOOL_CAPABILITIES",
]
