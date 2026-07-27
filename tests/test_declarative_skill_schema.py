"""Strict Declarative Skill schema tests from the locked environment."""

from __future__ import annotations

import copy
import json
import unittest

from pydantic import ValidationError

from capability_registry import CapabilityId, ConnectorId
from skills.schema import (
    MAX_DEFINITION_BYTES,
    MAX_NETWORK_REQUESTS,
    MAX_OUTPUT_BYTES,
    MAX_RUNTIME_SECONDS,
    MAX_TOOL_CALLS,
    DeclarativeSkillCompatibilityError,
    DeclarativeSkillSizeError,
    DeclarativeTool,
    InvocationMode,
    OAuthScopeId,
    parse_declarative_skill,
)


def _definition() -> dict:
    return {
        "schema_version": 1,
        "skill_id": "clicky.research_to_csv",
        "version": "1.0.0",
        "name": "Research to CSV",
        "description": "Research public sources and create a local CSV.",
        "invocation": {
            "mode": InvocationMode.DETERMINISTIC_PHRASES.value,
            "phrases": ["research public accounts"],
        },
        "inputs": [
            {
                "input_id": "query",
                "input_type": "text",
                "description": "The bounded public research request.",
                "required": True,
                "sensitive": False,
                "max_chars": 2_000,
                "max_bytes": None,
                "minimum": None,
                "maximum": None,
            },
            {
                "input_id": "destination",
                "input_type": "file_reference",
                "description": "An approved local output destination.",
                "required": True,
                "sensitive": False,
                "max_chars": None,
                "max_bytes": 4 * 1024 * 1024,
                "minimum": None,
                "maximum": None,
            },
        ],
        "output": {
            "output_type": "table",
            "media_type": "text/csv",
            "fields": [
                {
                    "field_id": "name",
                    "value_type": "text",
                    "description": "Public entity name.",
                    "required": True,
                },
                {
                    "field_id": "source",
                    "value_type": "url",
                    "description": "Public source URL.",
                    "required": True,
                },
            ],
        },
        "prompt_template": (
            "Research only public sources for {{input.query}}. "
            "Do not invent missing records."
        ),
        "steps": [
            {
                "step_id": "search",
                "tool": DeclarativeTool.WEB_SEARCH.value,
                "capability": CapabilityId.WEB_SEARCH_BOUNDED.value,
                "depends_on": [],
                "arguments": [
                    {
                        "argument_id": "query",
                        "source": "input",
                        "reference": "query",
                        "value": None,
                    }
                ],
                "output_id": "search_results",
                "connector": None,
                "approval_id": None,
            },
            {
                "step_id": "write_csv",
                "tool": DeclarativeTool.ARTIFACT_WRITE.value,
                "capability": CapabilityId.LOCAL_ARTIFACT_WRITE.value,
                "depends_on": ["search"],
                "arguments": [
                    {
                        "argument_id": "records",
                        "source": "step_output",
                        "reference": "search_results",
                        "value": None,
                    },
                    {
                        "argument_id": "destination",
                        "source": "input",
                        "reference": "destination",
                        "value": None,
                    },
                ],
                "output_id": "csv_artifact",
                "connector": None,
                "approval_id": "approve_local_csv",
            },
            {
                "step_id": "verify",
                "tool": DeclarativeTool.VERIFY_OUTPUT.value,
                "capability": CapabilityId.TASK_AGENT_RUN.value,
                "depends_on": ["write_csv"],
                "arguments": [
                    {
                        "argument_id": "artifact",
                        "source": "step_output",
                        "reference": "csv_artifact",
                        "value": None,
                    }
                ],
                "output_id": "verified_csv",
                "connector": None,
                "approval_id": None,
            },
        ],
        "capabilities": [
            CapabilityId.TASK_AGENT_RUN.value,
            CapabilityId.WEB_SEARCH_BOUNDED.value,
            CapabilityId.LOCAL_ARTIFACT_WRITE.value,
        ],
        "connectors": [],
        "approvals": [
            {
                "approval_id": "approve_local_csv",
                "capability": CapabilityId.LOCAL_ARTIFACT_WRITE.value,
                "reason": "Review the destination and content before writing.",
                "preview_references": [
                    "input.destination",
                    "step.search_results",
                ],
            }
        ],
        "limits": {
            "runtime_seconds": 300,
            "max_tool_calls": 8,
            "max_network_requests": 4,
            "max_output_bytes": 4 * 1024 * 1024,
        },
        "publisher": {
            "publisher_id": "clicky.official",
            "display_name": "Clicky",
        },
        "source_digest": "a" * 64,
        "minimum_clicky_version": "1.2.0",
    }


def _parse(definition: dict):
    return parse_declarative_skill(
        json.dumps(definition).encode("utf-8")
    )


class DeclarativeSkillSchemaTests(unittest.TestCase):
    def test_valid_definition_is_typed_bounded_and_compatible(self):
        definition = _parse(_definition())

        self.assertEqual(definition.skill_id, "clicky.research_to_csv")
        self.assertEqual(
            definition.capabilities,
            frozenset(
                {
                    CapabilityId.TASK_AGENT_RUN,
                    CapabilityId.WEB_SEARCH_BOUNDED,
                    CapabilityId.LOCAL_ARTIFACT_WRITE,
                }
            ),
        )
        self.assertEqual(
            definition.steps[0].tool,
            DeclarativeTool.WEB_SEARCH,
        )
        with self.assertRaises(ValidationError):
            definition.limits.runtime_seconds = 1

    def test_unknown_fields_and_python_entry_points_fail_before_registration(self):
        cases = []
        top_level = _definition()
        top_level["entrypoint"] = "package.module:handler"
        cases.append(top_level)

        nested = _definition()
        nested["steps"][0]["module"] = "unsafe.module"
        cases.append(nested)

        python_tool = _definition()
        python_tool["steps"][0]["tool"] = "python"
        cases.append(python_tool)

        shell_tool = _definition()
        shell_tool["steps"][0]["tool"] = "command"
        cases.append(shell_tool)

        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(
                ValidationError
            ):
                _parse(candidate)

    def test_malformed_incompatible_and_oversized_definitions_fail_closed(self):
        with self.assertRaises(ValidationError):
            parse_declarative_skill(b"{not-json")

        invalid_version = _definition()
        invalid_version["version"] = "1"
        with self.assertRaises(ValidationError):
            _parse(invalid_version)

        future = _definition()
        future["minimum_clicky_version"] = "2.0.0"
        with self.assertRaises(DeclarativeSkillCompatibilityError):
            _parse(future)

        with self.assertRaises(DeclarativeSkillSizeError):
            parse_declarative_skill(b"x" * (MAX_DEFINITION_BYTES + 1))
        with self.assertRaises(TypeError):
            parse_declarative_skill("{}")

    def test_each_resource_limit_has_a_fixed_hard_ceiling(self):
        cases = (
            ("runtime_seconds", MAX_RUNTIME_SECONDS),
            ("max_tool_calls", MAX_TOOL_CALLS),
            ("max_network_requests", MAX_NETWORK_REQUESTS),
            ("max_output_bytes", MAX_OUTPUT_BYTES),
        )
        for field, maximum in cases:
            candidate = _definition()
            candidate["limits"][field] = maximum + 1
            with self.subTest(field=field), self.assertRaises(
                ValidationError
            ):
                _parse(candidate)

    def test_capabilities_must_exactly_match_steps(self):
        extra = _definition()
        extra["capabilities"].append(CapabilityId.WORKSPACE_READ.value)
        with self.assertRaisesRegex(
            ValidationError,
            "exactly match workflow needs",
        ):
            _parse(extra)

        missing = _definition()
        missing["capabilities"].remove(
            CapabilityId.LOCAL_ARTIFACT_WRITE.value
        )
        with self.assertRaisesRegex(
            ValidationError,
            "exactly match workflow needs",
        ):
            _parse(missing)

        broad = _definition()
        broad["capabilities"][0] = "filesystem"
        with self.assertRaises(ValidationError):
            _parse(broad)

    def test_workflow_order_bindings_and_approvals_are_fail_closed(self):
        future_output = _definition()
        future_output["steps"][0]["arguments"][0] = {
            "argument_id": "query",
            "source": "step_output",
            "reference": "csv_artifact",
            "value": None,
        }
        with self.assertRaisesRegex(
            ValidationError,
            "future or unknown output",
        ):
            _parse(future_output)

        missing_approval = _definition()
        missing_approval["steps"][1]["approval_id"] = None
        with self.assertRaisesRegex(
            ValidationError,
            "approval must match",
        ):
            _parse(missing_approval)

        too_few_calls = _definition()
        too_few_calls["limits"]["max_tool_calls"] = 2
        with self.assertRaisesRegex(
            ValidationError,
            "lower than the declared workflow",
        ):
            _parse(too_few_calls)

    def test_connector_scopes_and_capabilities_are_exact(self):
        candidate = _definition()
        candidate["steps"].insert(
            1,
            {
                "step_id": "read_mail",
                "tool": DeclarativeTool.CONNECTOR_READ.value,
                "capability": CapabilityId.GMAIL_MESSAGE_READ.value,
                "depends_on": ["search"],
                "arguments": [],
                "output_id": "messages",
                "connector": ConnectorId.GMAIL.value,
                "approval_id": None,
            },
        )
        candidate["capabilities"].append(
            CapabilityId.GMAIL_MESSAGE_READ.value
        )
        candidate["connectors"] = [
            {
                "connector": ConnectorId.GMAIL.value,
                "capabilities": [
                    CapabilityId.GMAIL_MESSAGE_READ.value
                ],
                "oauth_scopes": [
                    OAuthScopeId.GMAIL_MESSAGES_READ.value
                ],
            }
        ]
        parsed = _parse(candidate)
        self.assertEqual(parsed.connectors[0].connector, ConnectorId.GMAIL)

        wrong_scope = copy.deepcopy(candidate)
        wrong_scope["connectors"][0]["oauth_scopes"] = [
            OAuthScopeId.GMAIL_DRAFTS_WRITE.value
        ]
        with self.assertRaisesRegex(
            ValidationError,
            "exactly match connector capabilities",
        ):
            _parse(wrong_scope)

        extra_connector_capability = copy.deepcopy(candidate)
        extra_connector_capability["connectors"][0][
            "capabilities"
        ].append(CapabilityId.GMAIL_DRAFT_WRITE.value)
        extra_connector_capability["connectors"][0][
            "oauth_scopes"
        ].append(OAuthScopeId.GMAIL_DRAFTS_WRITE.value)
        with self.assertRaisesRegex(
            ValidationError,
            "exactly match workflow steps",
        ):
            _parse(extra_connector_capability)

    def test_prompt_tokens_must_reference_declared_inputs_only(self):
        candidate = _definition()
        candidate["prompt_template"] = "Use {{python.entrypoint}}."
        with self.assertRaisesRegex(
            ValidationError,
            "non-declarative expression",
        ):
            _parse(candidate)

        candidate = _definition()
        candidate["prompt_template"] = "Use {{input.unknown}}."
        with self.assertRaisesRegex(
            ValidationError,
            "undeclared input",
        ):
            _parse(candidate)


if __name__ == "__main__":
    unittest.main()
