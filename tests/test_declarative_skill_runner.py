"""Declarative runner authority, approval, schema, and evidence tests."""

from __future__ import annotations

import ast
import copy
import json
import tempfile
import unittest
from pathlib import Path

from capability_registry import (
    CapabilityGrant,
    CapabilityId,
    ConnectorId,
)
from declarative_tools import DeclarativeTool
from skills.declarative_runner import (
    DeclarativeRunnerInputError,
    DeclarativeRunnerPlanningError,
    DeclarativeSkillRunner,
    RunnerDisposition,
    compile_declarative_plan,
    declarative_inputs_digest,
)
from skills.schema import (
    OAuthScopeId,
    declarative_skill_source_digest,
    parse_declarative_skill,
)
from tasks.coordinator import TaskWorkspace
from tasks.models import (
    TaskLimits,
    TaskRun,
    TaskSpec,
    TaskState,
    ToolResultStatus,
)
from tasks.policy import WorkerPolicy


ROOT = Path(__file__).resolve().parents[1]
VERIFIER_ID = "artifact-postcondition-v1"


def definition_payload() -> dict:
    return {
        "schema_version": 1,
        "skill_id": "clicky.research_to_csv",
        "version": "1.0.0",
        "name": "Research to CSV",
        "description": "Create a bounded source-backed CSV.",
        "invocation": {"mode": "explicit", "phrases": []},
        "inputs": [
            {
                "input_id": "query",
                "input_type": "text",
                "description": "The bounded public research query.",
                "required": True,
                "sensitive": False,
                "max_chars": 200,
                "max_bytes": None,
                "minimum": None,
                "maximum": None,
            }
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
        "prompt_template": "Research {{input.query}} using public sources.",
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
                    },
                    {
                        "argument_id": "max_results",
                        "source": "literal",
                        "reference": None,
                        "value": 2,
                    },
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
                        "argument_id": "artifact_id",
                        "source": "literal",
                        "reference": None,
                        "value": "research-csv",
                    },
                    {
                        "argument_id": "name",
                        "source": "literal",
                        "reference": None,
                        "value": "research.csv",
                    },
                    {
                        "argument_id": "media_type",
                        "source": "literal",
                        "reference": None,
                        "value": "text/csv",
                    },
                    {
                        "argument_id": "content",
                        "source": "step_output",
                        "reference": "search_results",
                        "value": None,
                    },
                    {
                        "argument_id": "complete",
                        "source": "literal",
                        "reference": None,
                        "value": True,
                    },
                ],
                "output_id": "csv_artifact",
                "connector": None,
                "approval_id": "approve_csv",
            },
            {
                "step_id": "verify",
                "tool": DeclarativeTool.VERIFY_OUTPUT.value,
                "capability": CapabilityId.TASK_AGENT_RUN.value,
                "depends_on": ["write_csv"],
                "arguments": [
                    {
                        "argument_id": "artifact_id",
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
                "approval_id": "approve_csv",
                "capability": CapabilityId.LOCAL_ARTIFACT_WRITE.value,
                "reason": "Review this exact CSV before adopting it.",
                "preview_references": [
                    "input.query",
                    "step.search_results",
                ],
            }
        ],
        "limits": {
            "runtime_seconds": 60,
            "max_tool_calls": 8,
            "max_network_requests": 2,
            "max_output_bytes": 64 * 1024,
        },
        "publisher": {
            "publisher_id": "clicky.official",
            "display_name": "Clicky",
        },
        "source_digest": "0" * 64,
        "minimum_clicky_version": "1.2.0",
    }


def parsed_definition(payload: dict | None = None):
    raw = copy.deepcopy(payload or definition_payload())
    provisional = parse_declarative_skill(
        json.dumps(raw).encode("utf-8")
    )
    raw["source_digest"] = declarative_skill_source_digest(provisional)
    return parse_declarative_skill(json.dumps(raw).encode("utf-8"))


def make_run(definition, inputs, *, capabilities=None) -> TaskRun:
    limits = TaskLimits(
        runtime_seconds=definition.limits.runtime_seconds,
        max_tool_calls=definition.limits.max_tool_calls,
        max_network_requests=definition.limits.max_network_requests,
        max_output_bytes=definition.limits.max_output_bytes,
    )
    return TaskRun(
        TaskSpec(
            run_id="runner-task-1",
            skill_id=definition.skill_id,
            skill_version=definition.version,
            goal="Create one verified research artifact.",
            input_digest=declarative_inputs_digest(definition, inputs),
            requested_result="A verified source-backed CSV.",
            verifier_step_id="verify",
            verifier_id=VERIFIER_ID,
            limits=limits,
        ),
        CapabilityGrant(
            run_id="runner-task-1",
            capabilities=(
                capabilities
                if capabilities is not None
                else definition.capabilities
            ),
        ),
    )


class DeclarativeSkillRunnerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

    def create_runner(
        self,
        definition,
        inputs,
        *,
        search_text=(
            "name,source\r\n"
            "Example,https://example.com/profile\r\n"
        ),
    ):
        run = make_run(definition, inputs)
        workspace = TaskWorkspace.create(
            run.run_id,
            WorkerPolicy.from_task_limits(run.spec.limits),
            root=Path(self.temporary.name).absolute() / "workspaces",
        )
        self.addCleanup(workspace.cleanup)
        calls = {"search": 0, "model": 0}

        async def search(query, max_results):
            calls["search"] += 1
            self.assertEqual(max_results, 2)
            return search_text

        async def model(arguments):
            calls["model"] += 1
            yield "I completed the task and wrote the file."

        async def fetch(url, max_chars):
            return "bounded page"

        runner = DeclarativeSkillRunner.create(
            definition,
            run,
            workspace,
            model_stream=model,
            web_search=search,
            web_fetch=fetch,
            artifact_root=(
                Path(self.temporary.name).absolute() / "adopted"
            ),
        )
        return runner, run, workspace, calls

    async def test_declared_workflow_pauses_then_completes_from_verifier_evidence(self):
        definition = parsed_definition()
        inputs = {"query": "public creators"}
        runner, run, workspace, calls = self.create_runner(
            definition,
            inputs,
        )

        started = runner.start(inputs)
        self.assertEqual(started.disposition, RunnerDisposition.RUNNING)

        searched = await runner.advance(now=10.0)
        self.assertEqual(searched.task_state, TaskState.RUNNING)
        self.assertEqual(calls["search"], 1)
        self.assertEqual(len(searched.results), 1)

        waiting = await runner.advance(now=11.0)
        self.assertEqual(
            waiting.disposition,
            RunnerDisposition.WAITING_FOR_APPROVAL,
        )
        payload = waiting.pending_approval
        self.assertIsNotNone(payload)
        self.assertEqual(payload.target.reference, "research-csv")
        self.assertEqual(payload.preview.media_type, "text/csv")
        self.assertEqual(workspace.verify(), (0, 0))

        request = payload.request
        run.approve(
            request.approval_id,
            request.action_digest,
            now=12.0,
        )
        written = await runner.advance(now=12.0)
        self.assertEqual(written.task_state, TaskState.RUNNING)
        self.assertEqual(len(written.results), 2)

        completed = await runner.advance(now=13.0)
        self.assertEqual(completed.disposition, RunnerDisposition.COMPLETED)
        self.assertEqual(run.state, TaskState.COMPLETED)
        self.assertEqual(len(completed.results), 3)
        self.assertTrue(
            completed.results[-1].is_successful_verification
        )
        self.assertEqual(len(completed.artifacts), 1)
        artifact = completed.artifacts[0]
        self.assertTrue(artifact.adopted)
        self.assertEqual(artifact.media_type, "text/csv")
        self.assertEqual(
            artifact.verification_result_id,
            completed.results[-1].result_id,
        )

    async def test_model_completion_prose_is_only_inert_step_output(self):
        payload = definition_payload()
        payload["steps"][0] = {
            "step_id": "search",
            "tool": DeclarativeTool.MODEL_GENERATE.value,
            "capability": CapabilityId.TASK_AGENT_RUN.value,
            "depends_on": [],
            "arguments": [
                {
                    "argument_id": "system_prompt",
                    "source": "literal",
                    "reference": None,
                    "value": "Return only CSV data.",
                }
            ],
            "output_id": "search_results",
            "connector": None,
            "approval_id": None,
        }
        payload["capabilities"] = [
            CapabilityId.TASK_AGENT_RUN.value,
            CapabilityId.LOCAL_ARTIFACT_WRITE.value,
        ]
        payload["limits"]["max_network_requests"] = 0
        definition = parsed_definition(payload)
        inputs = {"query": "public creators"}
        runner, run, _, calls = self.create_runner(definition, inputs)
        runner.start(inputs)

        snapshot = await runner.advance(now=10.0)

        self.assertEqual(calls["model"], 1)
        self.assertEqual(snapshot.task_state, TaskState.RUNNING)
        self.assertEqual(snapshot.artifacts, ())
        self.assertIsNone(run.verifier_result)

    def test_plan_rejects_dynamic_capability_growth_and_unknown_arguments(self):
        definition = parsed_definition()
        inputs = {"query": "public creators"}
        run = make_run(
            definition,
            inputs,
            capabilities=frozenset(
                {
                    *definition.capabilities,
                    CapabilityId.WEB_FETCH_BOUNDED,
                }
            ),
        )
        with self.assertRaisesRegex(
            DeclarativeRunnerPlanningError,
            "exactly match",
        ):
            compile_declarative_plan(definition, run)

        payload = definition_payload()
        payload["steps"][0]["arguments"].append(
            {
                "argument_id": "undeclared_host_option",
                "source": "literal",
                "reference": None,
                "value": "shell",
            }
        )
        definition_with_unknown_argument = parsed_definition(payload)
        run = make_run(definition_with_unknown_argument, inputs)
        with self.assertRaisesRegex(
            DeclarativeRunnerPlanningError,
            "arguments do not match",
        ):
            compile_declarative_plan(
                definition_with_unknown_argument,
                run,
            )

    def test_gmail_read_without_exact_selected_thread_fails_closed(self):
        payload = definition_payload()
        payload["steps"][0] = {
            "step_id": "search",
            "tool": DeclarativeTool.CONNECTOR_READ.value,
            "capability": CapabilityId.GMAIL_MESSAGE_READ.value,
            "depends_on": [],
            "arguments": [],
            "output_id": "search_results",
            "connector": ConnectorId.GMAIL.value,
            "approval_id": None,
        }
        payload["capabilities"] = [
            CapabilityId.TASK_AGENT_RUN.value,
            CapabilityId.GMAIL_MESSAGE_READ.value,
            CapabilityId.LOCAL_ARTIFACT_WRITE.value,
        ]
        payload["connectors"] = [
            {
                "connector": ConnectorId.GMAIL.value,
                "capabilities": [CapabilityId.GMAIL_MESSAGE_READ.value],
                "oauth_scopes": [OAuthScopeId.GMAIL_MESSAGES_READ.value],
            }
        ]
        payload["limits"]["max_network_requests"] = 1
        definition = parsed_definition(payload)
        run = make_run(definition, {"query": "public creators"})

        with self.assertRaisesRegex(
            DeclarativeRunnerPlanningError,
            "arguments do not match",
        ):
            compile_declarative_plan(definition, run)

    def test_calendar_availability_compiles_with_exact_connector_authority(self):
        payload = definition_payload()
        payload["steps"][0] = {
            "step_id": "search",
            "tool": DeclarativeTool.CONNECTOR_READ.value,
            "capability": CapabilityId.CALENDAR_EVENT_READ.value,
            "depends_on": [],
            "arguments": [
                {
                    "argument_id": "authorization_id",
                    "source": "literal",
                    "reference": None,
                    "value": "oauth.calendar-one",
                },
                {
                    "argument_id": "selected_calendar_ids_json",
                    "source": "literal",
                    "reference": None,
                    "value": '["primary","team@example.com"]',
                },
                {
                    "argument_id": "time_min",
                    "source": "literal",
                    "reference": None,
                    "value": "2026-07-27T12:00:00Z",
                },
                {
                    "argument_id": "time_max",
                    "source": "literal",
                    "reference": None,
                    "value": "2026-07-28T12:00:00Z",
                },
            ],
            "output_id": "search_results",
            "connector": ConnectorId.GOOGLE_CALENDAR.value,
            "approval_id": None,
        }
        payload["capabilities"] = [
            CapabilityId.TASK_AGENT_RUN.value,
            CapabilityId.CALENDAR_EVENT_READ.value,
            CapabilityId.LOCAL_ARTIFACT_WRITE.value,
        ]
        payload["connectors"] = [
            {
                "connector": ConnectorId.GOOGLE_CALENDAR.value,
                "capabilities": [CapabilityId.CALENDAR_EVENT_READ.value],
                "oauth_scopes": [
                    OAuthScopeId.CALENDAR_EVENTS_READ.value
                ],
            }
        ]
        definition = parsed_definition(payload)
        run = make_run(definition, {"query": "availability"})

        plan = compile_declarative_plan(definition, run)

        self.assertEqual(
            plan.declared_steps[0].tool,
            DeclarativeTool.CONNECTOR_READ,
        )
        self.assertEqual(
            plan.declared_steps[0].connector,
            ConnectorId.GOOGLE_CALENDAR,
        )
        self.assertEqual(
            plan.declared_steps[0].capability,
            CapabilityId.CALENDAR_EVENT_READ,
        )

    def test_gmail_selected_thread_compiles_with_exact_read_authority(self):
        payload = definition_payload()
        payload["steps"][0] = {
            "step_id": "search",
            "tool": DeclarativeTool.CONNECTOR_READ.value,
            "capability": CapabilityId.GMAIL_MESSAGE_READ.value,
            "depends_on": [],
            "arguments": [
                {
                    "argument_id": "authorization_id",
                    "source": "literal",
                    "reference": None,
                    "value": "oauth.gmail-one",
                },
                {
                    "argument_id": "selected_thread_id",
                    "source": "literal",
                    "reference": None,
                    "value": "thread-123",
                },
            ],
            "output_id": "search_results",
            "connector": ConnectorId.GMAIL.value,
            "approval_id": None,
        }
        payload["capabilities"] = [
            CapabilityId.TASK_AGENT_RUN.value,
            CapabilityId.GMAIL_MESSAGE_READ.value,
            CapabilityId.LOCAL_ARTIFACT_WRITE.value,
        ]
        payload["connectors"] = [
            {
                "connector": ConnectorId.GMAIL.value,
                "capabilities": [CapabilityId.GMAIL_MESSAGE_READ.value],
                "oauth_scopes": [OAuthScopeId.GMAIL_MESSAGES_READ.value],
            }
        ]
        definition = parsed_definition(payload)
        run = make_run(definition, {"query": "selected Gmail thread"})

        plan = compile_declarative_plan(definition, run)

        self.assertEqual(
            plan.declared_steps[0].capability,
            CapabilityId.GMAIL_MESSAGE_READ,
        )
        self.assertEqual(
            plan.declared_steps[0].connector,
            ConnectorId.GMAIL,
        )

    def test_drive_selected_file_compiles_with_exact_read_authority(self):
        payload = definition_payload()
        payload["steps"][0] = {
            "step_id": "search",
            "tool": DeclarativeTool.CONNECTOR_READ.value,
            "capability": CapabilityId.DRIVE_SELECTED_FILE_READ.value,
            "depends_on": [],
            "arguments": [
                {
                    "argument_id": "authorization_id",
                    "source": "literal",
                    "reference": None,
                    "value": "oauth.drive-one",
                },
                {
                    "argument_id": "selected_file_id",
                    "source": "literal",
                    "reference": None,
                    "value": "1AbCdEfGhIjKlMnOpQrStUvWxYz",
                },
            ],
            "output_id": "search_results",
            "connector": ConnectorId.GOOGLE_DRIVE.value,
            "approval_id": None,
        }
        payload["capabilities"] = [
            CapabilityId.TASK_AGENT_RUN.value,
            CapabilityId.DRIVE_SELECTED_FILE_READ.value,
            CapabilityId.LOCAL_ARTIFACT_WRITE.value,
        ]
        payload["connectors"] = [
            {
                "connector": ConnectorId.GOOGLE_DRIVE.value,
                "capabilities": [
                    CapabilityId.DRIVE_SELECTED_FILE_READ.value
                ],
                "oauth_scopes": [
                    OAuthScopeId.DRIVE_SELECTED_FILE_READ.value
                ],
            }
        ]
        payload["limits"]["max_network_requests"] = 2
        definition = parsed_definition(payload)
        run = make_run(definition, {"query": "selected Drive file"})

        plan = compile_declarative_plan(definition, run)

        self.assertEqual(
            plan.declared_steps[0].capability,
            CapabilityId.DRIVE_SELECTED_FILE_READ,
        )
        self.assertEqual(
            plan.declared_steps[0].connector,
            ConnectorId.GOOGLE_DRIVE,
        )

        payload["steps"][0]["arguments"].pop()
        definition_without_file = parsed_definition(payload)
        run_without_file = make_run(
            definition_without_file,
            {"query": "selected Drive file"},
        )
        with self.assertRaisesRegex(
            DeclarativeRunnerPlanningError,
            "arguments do not match",
        ):
            compile_declarative_plan(
                definition_without_file,
                run_without_file,
            )

    def test_gmail_draft_compiles_only_with_exact_approved_write(self):
        payload = definition_payload()
        payload["steps"][0] = {
            "step_id": "search",
            "tool": DeclarativeTool.CONNECTOR_WRITE.value,
            "capability": CapabilityId.GMAIL_DRAFT_WRITE.value,
            "depends_on": [],
            "arguments": [
                {
                    "argument_id": "authorization_id",
                    "source": "literal",
                    "reference": None,
                    "value": "oauth.gmail-one",
                },
                {
                    "argument_id": "to_addresses_json",
                    "source": "literal",
                    "reference": None,
                    "value": '["recipient@example.com"]',
                },
                {
                    "argument_id": "cc_addresses_json",
                    "source": "literal",
                    "reference": None,
                    "value": "[]",
                },
                {
                    "argument_id": "bcc_addresses_json",
                    "source": "literal",
                    "reference": None,
                    "value": "[]",
                },
                {
                    "argument_id": "subject",
                    "source": "literal",
                    "reference": None,
                    "value": "Reviewed subject",
                },
                {
                    "argument_id": "body_text",
                    "source": "literal",
                    "reference": None,
                    "value": "Reviewed body",
                },
            ],
            "output_id": "search_results",
            "connector": ConnectorId.GMAIL.value,
            "approval_id": "approve_gmail_draft",
        }
        payload["capabilities"] = [
            CapabilityId.TASK_AGENT_RUN.value,
            CapabilityId.GMAIL_DRAFT_WRITE.value,
            CapabilityId.LOCAL_ARTIFACT_WRITE.value,
        ]
        payload["connectors"] = [
            {
                "connector": ConnectorId.GMAIL.value,
                "capabilities": [CapabilityId.GMAIL_DRAFT_WRITE.value],
                "oauth_scopes": [OAuthScopeId.GMAIL_DRAFTS_WRITE.value],
            }
        ]
        payload["approvals"].append(
            {
                "approval_id": "approve_gmail_draft",
                "capability": CapabilityId.GMAIL_DRAFT_WRITE.value,
                "reason": "Review exact Gmail draft content.",
                "preview_references": ["input.query"],
            }
        )
        definition = parsed_definition(payload)
        run = make_run(definition, {"query": "reviewed Gmail draft"})

        plan = compile_declarative_plan(definition, run)

        self.assertEqual(
            plan.declared_steps[0].tool,
            DeclarativeTool.CONNECTOR_WRITE,
        )
        self.assertEqual(
            plan.declared_steps[0].approval_id,
            "approve_gmail_draft",
        )
        self.assertNotIn("gmail.send", {item.value for item in CapabilityId})

    def test_google_docs_compiles_exact_selected_read_and_reviewed_create(self):
        read_payload = definition_payload()
        read_payload["steps"][0] = {
            "step_id": "search",
            "tool": DeclarativeTool.CONNECTOR_READ.value,
            "capability": CapabilityId.DOCS_DOCUMENT_READ.value,
            "depends_on": [],
            "arguments": [
                {
                    "argument_id": "authorization_id",
                    "source": "literal",
                    "reference": None,
                    "value": "oauth.docs-one",
                },
                {
                    "argument_id": "selected_document_id",
                    "source": "literal",
                    "reference": None,
                    "value": "document_123",
                },
            ],
            "output_id": "search_results",
            "connector": ConnectorId.GOOGLE_DOCS.value,
            "approval_id": None,
        }
        read_payload["capabilities"] = [
            CapabilityId.TASK_AGENT_RUN.value,
            CapabilityId.DOCS_DOCUMENT_READ.value,
            CapabilityId.LOCAL_ARTIFACT_WRITE.value,
        ]
        read_payload["connectors"] = [
            {
                "connector": ConnectorId.GOOGLE_DOCS.value,
                "capabilities": [CapabilityId.DOCS_DOCUMENT_READ.value],
                "oauth_scopes": [
                    OAuthScopeId.DOCS_SELECTED_DOCUMENT_READ.value
                ],
            }
        ]
        read_definition = parsed_definition(read_payload)
        read_run = make_run(
            read_definition,
            {"query": "selected Google document"},
        )
        read_plan = compile_declarative_plan(
            read_definition,
            read_run,
        )
        self.assertEqual(
            read_plan.declared_steps[0].capability,
            CapabilityId.DOCS_DOCUMENT_READ,
        )

        create_payload = definition_payload()
        create_payload["steps"][0] = {
            "step_id": "search",
            "tool": DeclarativeTool.CONNECTOR_WRITE.value,
            "capability": CapabilityId.DOCS_DOCUMENT_CREATE.value,
            "depends_on": [],
            "arguments": [
                {
                    "argument_id": "authorization_id",
                    "source": "literal",
                    "reference": None,
                    "value": "oauth.docs-one",
                },
                {
                    "argument_id": "title",
                    "source": "literal",
                    "reference": None,
                    "value": "Reviewed memo",
                },
                {
                    "argument_id": "body_text",
                    "source": "literal",
                    "reference": None,
                    "value": "Exact reviewed body",
                },
                {
                    "argument_id": "idempotency_key",
                    "source": "literal",
                    "reference": None,
                    "value": "run.docs-create-1",
                },
            ],
            "output_id": "search_results",
            "connector": ConnectorId.GOOGLE_DOCS.value,
            "approval_id": "approve_docs_create",
        }
        create_payload["capabilities"] = [
            CapabilityId.TASK_AGENT_RUN.value,
            CapabilityId.DOCS_DOCUMENT_CREATE.value,
            CapabilityId.LOCAL_ARTIFACT_WRITE.value,
        ]
        create_payload["connectors"] = [
            {
                "connector": ConnectorId.GOOGLE_DOCS.value,
                "capabilities": [
                    CapabilityId.DOCS_DOCUMENT_CREATE.value
                ],
                "oauth_scopes": [
                    OAuthScopeId.DOCS_DOCUMENT_CREATE.value
                ],
            }
        ]
        create_payload["approvals"].append(
            {
                "approval_id": "approve_docs_create",
                "capability": CapabilityId.DOCS_DOCUMENT_CREATE.value,
                "reason": "Review the exact Google document content.",
                "preview_references": ["input.query"],
            }
        )
        create_payload["limits"]["max_network_requests"] = 6
        create_definition = parsed_definition(create_payload)
        create_run = make_run(
            create_definition,
            {"query": "create reviewed Google document"},
        )
        create_plan = compile_declarative_plan(
            create_definition,
            create_run,
        )
        self.assertEqual(
            create_plan.declared_steps[0].approval_id,
            "approve_docs_create",
        )

        create_payload["limits"]["max_network_requests"] = 5
        too_small = parsed_definition(create_payload)
        with self.assertRaisesRegex(
            DeclarativeRunnerPlanningError,
            "network limit",
        ):
            compile_declarative_plan(
                too_small,
                make_run(
                    too_small,
                    {"query": "create reviewed Google document"},
                ),
            )

    def test_sheets_export_compiles_only_with_exact_source_and_six_calls(self):
        payload = definition_payload()
        payload["steps"][0] = {
            "step_id": "search",
            "tool": DeclarativeTool.CONNECTOR_WRITE.value,
            "capability": CapabilityId.SHEETS_VALUES_WRITE.value,
            "depends_on": ["read_source"],
            "arguments": [
                {
                    "argument_id": "authorization_id",
                    "source": "literal",
                    "reference": None,
                    "value": "oauth.sheets-one",
                },
                {
                    "argument_id": "source_artifact_id",
                    "source": "step_output",
                    "reference": "source_artifact",
                    "value": None,
                },
                {
                    "argument_id": "source_sha256",
                    "source": "literal",
                    "reference": None,
                    "value": "a" * 64,
                },
                {
                    "argument_id": "title",
                    "source": "literal",
                    "reference": None,
                    "value": "Reviewed research",
                },
                {
                    "argument_id": "idempotency_key",
                    "source": "literal",
                    "reference": None,
                    "value": "run.export-1",
                },
            ],
            "output_id": "search_results",
            "connector": ConnectorId.GOOGLE_SHEETS.value,
            "approval_id": "approve_sheets_export",
        }
        payload["steps"].insert(
            0,
            {
                "step_id": "read_source",
                "tool": DeclarativeTool.ARTIFACT_READ.value,
                "capability": CapabilityId.LOCAL_ARTIFACT_READ.value,
                "depends_on": [],
                "arguments": [
                    {
                        "argument_id": "artifact_id",
                        "source": "literal",
                        "reference": None,
                        "value": "research-csv",
                    }
                ],
                "output_id": "source_artifact",
                "connector": None,
                "approval_id": None,
            },
        )
        payload["capabilities"] = [
            CapabilityId.TASK_AGENT_RUN.value,
            CapabilityId.LOCAL_ARTIFACT_READ.value,
            CapabilityId.SHEETS_VALUES_WRITE.value,
            CapabilityId.LOCAL_ARTIFACT_WRITE.value,
        ]
        payload["connectors"] = [
            {
                "connector": ConnectorId.GOOGLE_SHEETS.value,
                "capabilities": [CapabilityId.SHEETS_VALUES_WRITE.value],
                "oauth_scopes": [OAuthScopeId.SHEETS_VALUES_WRITE.value],
            }
        ]
        payload["approvals"].append(
            {
                "approval_id": "approve_sheets_export",
                "capability": CapabilityId.SHEETS_VALUES_WRITE.value,
                "reason": "Review the exact table export target.",
                "preview_references": ["input.query"],
            }
        )
        payload["limits"]["max_network_requests"] = 6
        definition = parsed_definition(payload)
        run = make_run(definition, {"query": "export verified table"})

        plan = compile_declarative_plan(definition, run)

        self.assertEqual(
            plan.declared_steps[1].capability,
            CapabilityId.SHEETS_VALUES_WRITE,
        )
        self.assertEqual(
            plan.declared_steps[1].connector,
            ConnectorId.GOOGLE_SHEETS,
        )
        payload["limits"]["max_network_requests"] = 5
        too_small = parsed_definition(payload)
        too_small_run = make_run(
            too_small,
            {"query": "export verified table"},
        )
        with self.assertRaisesRegex(
            DeclarativeRunnerPlanningError,
            "network limit",
        ):
            compile_declarative_plan(too_small, too_small_run)

    def test_slides_export_compiles_only_with_exact_source_and_six_calls(self):
        payload = definition_payload()
        payload["steps"][0] = {
            "step_id": "search",
            "tool": DeclarativeTool.CONNECTOR_WRITE.value,
            "capability": CapabilityId.SLIDES_PRESENTATION_WRITE.value,
            "depends_on": ["read_source"],
            "arguments": [
                {
                    "argument_id": "authorization_id",
                    "source": "literal",
                    "reference": None,
                    "value": "oauth.slides-one",
                },
                {
                    "argument_id": "source_artifact_id",
                    "source": "step_output",
                    "reference": "source_artifact",
                    "value": None,
                },
                {
                    "argument_id": "source_sha256",
                    "source": "literal",
                    "reference": None,
                    "value": "a" * 64,
                },
                {
                    "argument_id": "idempotency_key",
                    "source": "literal",
                    "reference": None,
                    "value": "run.slides-export-1",
                },
            ],
            "output_id": "search_results",
            "connector": ConnectorId.GOOGLE_SLIDES.value,
            "approval_id": "approve_slides_export",
        }
        payload["steps"].insert(
            0,
            {
                "step_id": "read_source",
                "tool": DeclarativeTool.ARTIFACT_READ.value,
                "capability": CapabilityId.LOCAL_ARTIFACT_READ.value,
                "depends_on": [],
                "arguments": [
                    {
                        "argument_id": "artifact_id",
                        "source": "literal",
                        "reference": None,
                        "value": "presentation-spec",
                    }
                ],
                "output_id": "source_artifact",
                "connector": None,
                "approval_id": None,
            },
        )
        payload["capabilities"] = [
            CapabilityId.TASK_AGENT_RUN.value,
            CapabilityId.LOCAL_ARTIFACT_READ.value,
            CapabilityId.SLIDES_PRESENTATION_WRITE.value,
            CapabilityId.LOCAL_ARTIFACT_WRITE.value,
        ]
        payload["connectors"] = [
            {
                "connector": ConnectorId.GOOGLE_SLIDES.value,
                "capabilities": [
                    CapabilityId.SLIDES_PRESENTATION_WRITE.value
                ],
                "oauth_scopes": [
                    OAuthScopeId.SLIDES_PRESENTATIONS_WRITE.value
                ],
            }
        ]
        payload["approvals"].append(
            {
                "approval_id": "approve_slides_export",
                "capability": (
                    CapabilityId.SLIDES_PRESENTATION_WRITE.value
                ),
                "reason": "Review the exact presentation export target.",
                "preview_references": ["input.query"],
            }
        )
        payload["limits"]["max_network_requests"] = 6
        definition = parsed_definition(payload)
        run = make_run(definition, {"query": "export verified deck"})

        plan = compile_declarative_plan(definition, run)

        self.assertEqual(
            plan.declared_steps[1].capability,
            CapabilityId.SLIDES_PRESENTATION_WRITE,
        )
        self.assertEqual(
            plan.declared_steps[1].connector,
            ConnectorId.GOOGLE_SLIDES,
        )
        payload["limits"]["max_network_requests"] = 5
        too_small = parsed_definition(payload)
        too_small_run = make_run(
            too_small,
            {"query": "export verified deck"},
        )
        with self.assertRaisesRegex(
            DeclarativeRunnerPlanningError,
            "network limit",
        ):
            compile_declarative_plan(too_small, too_small_run)

    def test_notion_selected_page_reserves_exact_recursive_read_budget(self):
        payload = definition_payload()
        payload["steps"][0] = {
            "step_id": "search",
            "tool": DeclarativeTool.CONNECTOR_READ.value,
            "capability": CapabilityId.NOTION_PAGE_READ.value,
            "depends_on": [],
            "arguments": [
                {
                    "argument_id": "authorization_id",
                    "source": "literal",
                    "reference": None,
                    "value": "oauth.notion-one",
                },
                {
                    "argument_id": "selected_page_id",
                    "source": "literal",
                    "reference": None,
                    "value": (
                        "11111111-1111-4111-8111-111111111111"
                    ),
                },
            ],
            "output_id": "search_results",
            "connector": ConnectorId.NOTION.value,
            "approval_id": None,
        }
        payload["capabilities"] = [
            CapabilityId.TASK_AGENT_RUN.value,
            CapabilityId.NOTION_PAGE_READ.value,
            CapabilityId.LOCAL_ARTIFACT_WRITE.value,
        ]
        payload["connectors"] = [
            {
                "connector": ConnectorId.NOTION.value,
                "capabilities": [CapabilityId.NOTION_PAGE_READ.value],
                "oauth_scopes": [OAuthScopeId.NOTION_PAGES_READ.value],
            }
        ]
        payload["limits"]["max_network_requests"] = 16
        definition = parsed_definition(payload)
        run = make_run(definition, {"query": "selected Notion page"})

        plan = compile_declarative_plan(definition, run)

        self.assertEqual(
            plan.declared_steps[0].capability,
            CapabilityId.NOTION_PAGE_READ,
        )
        self.assertEqual(
            plan.declared_steps[0].connector,
            ConnectorId.NOTION,
        )

        payload["limits"]["max_network_requests"] = 15
        definition = parsed_definition(payload)
        run = make_run(definition, {"query": "selected Notion page"})
        with self.assertRaisesRegex(
            DeclarativeRunnerPlanningError,
            "network limit",
        ):
            compile_declarative_plan(definition, run)

    def test_notion_draft_render_is_local_and_publish_is_not_brokered(self):
        payload = definition_payload()
        payload["steps"][0] = {
            "step_id": "search",
            "tool": DeclarativeTool.NOTION_DRAFT_RENDER.value,
            "capability": CapabilityId.TASK_AGENT_RUN.value,
            "depends_on": [],
            "arguments": [
                {
                    "argument_id": "title",
                    "source": "literal",
                    "reference": None,
                    "value": "Reviewed local draft",
                },
                {
                    "argument_id": "blocks_json",
                    "source": "literal",
                    "reference": None,
                    "value": (
                        '[{"type":"paragraph","text":"Local only"}]'
                    ),
                },
                {
                    "argument_id": "intended_parent_page_id",
                    "source": "literal",
                    "reference": None,
                    "value": (
                        "11111111-1111-4111-8111-111111111111"
                    ),
                },
            ],
            "output_id": "search_results",
            "connector": None,
            "approval_id": None,
        }
        payload["capabilities"] = [
            CapabilityId.TASK_AGENT_RUN.value,
            CapabilityId.LOCAL_ARTIFACT_WRITE.value,
        ]
        payload["limits"]["max_network_requests"] = 0
        definition = parsed_definition(payload)
        run = make_run(definition, {"query": "draft notes"})

        plan = compile_declarative_plan(definition, run)

        self.assertEqual(
            plan.declared_steps[0].tool,
            DeclarativeTool.NOTION_DRAFT_RENDER,
        )
        self.assertIsNone(plan.declared_steps[0].connector)
        self.assertIsNone(plan.declared_steps[0].approval_id)
        self.assertNotIn(
            CapabilityId.NOTION_PAGE_WRITE,
            definition.capabilities,
        )

    async def test_invalid_output_schema_fails_before_approval_or_write(self):
        definition = parsed_definition()
        inputs = {"query": "public creators"}
        runner, run, workspace, _ = self.create_runner(
            definition,
            inputs,
            search_text=(
                "name,unsupported\r\n"
                "Example,missing-source\r\n"
            ),
        )
        runner.start(inputs)
        await runner.advance(now=10.0)

        failed = await runner.advance(now=11.0)

        self.assertEqual(failed.disposition, RunnerDisposition.FAILED)
        self.assertEqual(run.result_code, "runner_validation_failed")
        self.assertIsNone(failed.pending_approval)
        self.assertEqual(failed.artifacts, ())
        self.assertEqual(workspace.verify(), (0, 0))

    async def test_partial_output_is_evidence_but_never_completion(self):
        payload = definition_payload()
        write_arguments = payload["steps"][1]["arguments"]
        next(
            item for item in write_arguments if item["argument_id"] == "complete"
        )["value"] = False
        write_arguments.append(
            {
                "argument_id": "partial_reason",
                "source": "literal",
                "reference": None,
                "value": "Only one verified record was available.",
            }
        )
        definition = parsed_definition(payload)
        inputs = {"query": "public creators"}
        runner, run, workspace, _ = self.create_runner(definition, inputs)
        runner.start(inputs)
        await runner.advance(now=10.0)
        waiting = await runner.advance(now=11.0)
        request = waiting.pending_approval.request
        run.approve(
            request.approval_id,
            request.action_digest,
            now=12.0,
        )

        failed = await runner.advance(now=12.0)

        self.assertEqual(failed.disposition, RunnerDisposition.FAILED)
        self.assertEqual(
            failed.results[-1].status,
            ToolResultStatus.PARTIAL,
        )
        self.assertEqual(run.result_code, "partial_output")
        self.assertEqual(failed.artifacts, ())
        self.assertEqual(workspace.verify(), (0, 0))

    async def test_cancellation_invalidates_pending_approval_without_write(self):
        definition = parsed_definition()
        inputs = {"query": "public creators"}
        runner, run, workspace, _ = self.create_runner(definition, inputs)
        runner.start(inputs)
        await runner.advance(now=10.0)
        waiting = await runner.advance(now=11.0)
        request = waiting.pending_approval.request

        cancelled = runner.cancel()

        self.assertEqual(cancelled.disposition, RunnerDisposition.CANCELLED)
        self.assertEqual(workspace.verify(), (0, 0))
        with self.assertRaisesRegex(ValueError, "Invalid task transition"):
            run.approve(
                request.approval_id,
                request.action_digest,
                now=12.0,
            )

    def test_invocation_values_are_bounded_and_integrity_bound(self):
        definition = parsed_definition()
        with self.assertRaisesRegex(
            DeclarativeRunnerInputError,
            "too long",
        ):
            declarative_inputs_digest(
                definition,
                {"query": "x" * 201},
            )
        with self.assertRaisesRegex(
            DeclarativeRunnerInputError,
            "undeclared",
        ):
            declarative_inputs_digest(
                definition,
                {"query": "ok", "shell": "powershell"},
            )

        inputs = {"query": "public creators"}
        run = make_run(definition, inputs)
        workspace = TaskWorkspace.create(
            run.run_id,
            WorkerPolicy.from_task_limits(run.spec.limits),
            root=Path(self.temporary.name).absolute() / "input-workspaces",
        )
        self.addCleanup(workspace.cleanup)
        runner = DeclarativeSkillRunner.create(
            definition,
            run,
            workspace,
            artifact_root=(
                Path(self.temporary.name).absolute() / "input-artifacts"
            ),
        )
        with self.assertRaisesRegex(
            DeclarativeRunnerInputError,
            "digest does not match",
        ):
            runner.start({"query": "different request"})

    def test_runner_is_package_infrastructure_and_has_no_execution_authority(self):
        init_source = (ROOT / "skills" / "__init__.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('"declarative_runner.py"', init_source)
        spec_source = (ROOT / "clicky.spec").read_text(encoding="utf-8")
        self.assertIn('"skills.declarative_runner"', spec_source)
        source = (ROOT / "skills" / "declarative_runner.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        imported_roots = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            (node.module or "").split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        self.assertTrue(
            {
                "subprocess",
                "socket",
                "ctypes",
                "importlib",
                "requests",
            }.isdisjoint(imported_roots)
        )


if __name__ == "__main__":
    unittest.main()
