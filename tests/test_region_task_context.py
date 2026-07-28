"""Exact grant, one-use bytes, provider isolation, and verifier tests."""

from __future__ import annotations

import base64
import hashlib
import types
import unittest

from capability_registry import CapabilityGrant, CapabilityId
from feature_gates import (
    ACTION_PERMISSION_SCHEMA_VERSION,
    ActionCapability,
    BuildFeatureFlag,
)
from handoff.models import HandoffDataClass, HandoffDestination
from handoff.routing import HandoffRouteContext
from privacy_controls import PRIVACY_NOTICE_VERSION
from tasks.models import TaskLimits, TaskRun, TaskSpec
from tasks.region_context import (
    REGION_TASK_MODEL_STEP_ID,
    REGION_TASK_SKILL_ID,
    REGION_TASK_SKILL_VERSION,
    REGION_TASK_TOOL_NAME,
    REGION_TASK_VERIFIER_ID,
    REGION_TASK_VERIFIER_STEP_ID,
    RegionTaskProviderSelection,
    RegionTaskRequest,
    ReviewedTaskRegionGateway,
    TaskRegionContextError,
    TaskRegionModelBroker,
    TaskRegionPermissionError,
    verify_region_task_output,
)


JPEG = b"\xff\xd8\xffreviewed-task-region\xff\xd9"


def context(
    *,
    destination: HandoffDestination = (
        HandoffDestination.TASK_AGENT_NEW_RUN
    ),
    expires_at: float = 60.0,
) -> HandoffRouteContext:
    return HandoffRouteContext(
        route_id="route-1",
        intent_id="intent-1",
        intent_digest="a" * 64,
        selection_id="selection-1",
        selection_digest="b" * 64,
        destination=destination,
        data_class=HandoffDataClass.SCREEN_PIXELS,
        purpose="Explain the warning shown in this selected region.",
        media_type="image/jpeg",
        image_content=bytearray(JPEG),
        image_sha256=hashlib.sha256(JPEG).hexdigest(),
        width=640,
        height=360,
        accepted_at=10.0,
        expires_at=expires_at,
    )


def enabled_build_flags():
    flags = {
        capability: BuildFeatureFlag()
        for capability in ActionCapability
    }
    flags[ActionCapability.TASK_AGENT] = BuildFeatureFlag(
        available=True,
        permission_schema_version=(
            ACTION_PERMISSION_SCHEMA_VERSION
        ),
    )
    return flags


def configured(**changes):
    values = {
        "privacy_consent_version": PRIVACY_NOTICE_VERSION,
        "microphone_consent": False,
        "cloud_stt_consent": False,
        "cloud_tts_consent": False,
        "screen_capture_consent": True,
        "coding_agent_consent": False,
        "action_permission_schema_version": (
            ACTION_PERMISSION_SCHEMA_VERSION
        ),
        "global_dictation_permission": False,
        "screen_compose_permission": False,
        "task_agent_permission": True,
        "connector_read_permission": False,
        "connector_write_permission": False,
        "workspace_coding_permission": False,
        "desktop_automation_permission": False,
    }
    values.update(changes)
    return types.SimpleNamespace(**values)


def request_and_run(routed):
    run_id = "task-region-1"
    grant = CapabilityGrant(
        run_id=run_id,
        capabilities=frozenset(
            {
                CapabilityId.TASK_AGENT_RUN,
                CapabilityId.TASK_REGION_CONTEXT,
            }
        ),
    )
    request = RegionTaskRequest(
        run_id=run_id,
        grant=grant,
        instruction=routed.purpose,
        route_id=routed.route_id,
        intent_digest=routed.intent_digest,
        selection_id=routed.selection_id,
        selection_digest=routed.selection_digest,
        image_sha256=routed.image_sha256,
        image_byte_count=len(routed.image_content),
        width=routed.width,
        height=routed.height,
        provider=RegionTaskProviderSelection(
            "openai",
            "gpt-4o-mini",
        ),
    )
    run = TaskRun(
        TaskSpec(
            run_id=run_id,
            skill_id=REGION_TASK_SKILL_ID,
            skill_version=REGION_TASK_SKILL_VERSION,
            goal=routed.purpose,
            input_digest=request.input_digest,
            requested_result="One bounded region analysis.",
            verifier_step_id=REGION_TASK_VERIFIER_STEP_ID,
            verifier_id=REGION_TASK_VERIFIER_ID,
            limits=TaskLimits(
                runtime_seconds=120,
                max_tool_calls=1,
                max_network_requests=1,
                max_output_bytes=64 * 1024,
            ),
        ),
        grant,
    )
    return request, run


class Provider:
    def __init__(self, text: str = "This is a bounded explanation.") -> None:
        self.text = text
        self.calls = []

    async def stream_response(self, **kwargs):
        self.calls.append(kwargs)
        yield self.text


class TaskRegionContextTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.flags = enabled_build_flags()
        self.config = configured()
        self.provider = Provider()
        self.now = 20.0

    def broker(self, routed, request, run):
        return TaskRegionModelBroker(
            run,
            request,
            ReviewedTaskRegionGateway(
                routed,
                clock=lambda: self.now,
            ),
            config_provider=lambda: self.config,
            current_provider=lambda: request.provider,
            provider_factory=lambda _provider: self.provider,
            vision_support=lambda _provider, _model: True,
            build_flags=self.flags,
        )

    async def test_exact_review_approval_consumes_one_jpeg_and_no_history(
        self,
    ) -> None:
        routed = context()
        request, run = request_and_run(routed)
        broker = self.broker(routed, request, run)
        call = broker.tool_call()
        approval = broker.approval_request(
            call,
            expires_at=routed.expires_at,
        )

        self.assertEqual(call.tool_name, REGION_TASK_TOOL_NAME)
        self.assertEqual(call.step_id, REGION_TASK_MODEL_STEP_ID)
        self.assertIs(
            call.capability,
            CapabilityId.TASK_REGION_CONTEXT,
        )
        run.start()
        run.request_approval(call, approval, now=self.now)
        run.approve(
            approval.approval_id,
            approval.action_digest,
            now=self.now,
        )
        output = await broker.execute(call)
        verifier = verify_region_task_output(run, output)
        run.complete(verifier)

        self.assertEqual(output.text, self.provider.text)
        self.assertTrue(verifier.is_successful_verification)
        self.assertEqual(len(self.provider.calls), 1)
        provider_call = self.provider.calls[0]
        self.assertEqual(provider_call["history"], [])
        self.assertEqual(provider_call["model"], "gpt-4o-mini")
        self.assertEqual(len(provider_call["screenshots_b64"]), 1)
        self.assertEqual(
            base64.b64decode(
                provider_call["screenshots_b64"][0],
                validate=True,
            ),
            JPEG,
        )
        self.assertIn(
            "untrusted data",
            provider_call["system_prompt"],
        )
        self.assertEqual(
            bytes(routed.image_content),
            b"\x00" * len(JPEG),
        )
        with self.assertRaisesRegex(
            TaskRegionContextError,
            "already attempted",
        ):
            await broker.execute(call)

    async def test_permission_provider_and_vision_drift_block_provider(
        self,
    ) -> None:
        cases = (
            (
                "permission",
                configured(task_agent_permission=False),
                lambda request: request.provider,
                lambda _provider, _model: True,
            ),
            (
                "screen",
                configured(screen_capture_consent=False),
                lambda request: request.provider,
                lambda _provider, _model: True,
            ),
            (
                "provider",
                configured(),
                lambda _request: RegionTaskProviderSelection(
                    "anthropic",
                    "claude-3-5-sonnet-latest",
                ),
                lambda _provider, _model: True,
            ),
            (
                "vision",
                configured(),
                lambda request: request.provider,
                lambda _provider, _model: False,
            ),
        )
        for label, config, current, vision in cases:
            with self.subTest(label=label):
                routed = context()
                request, run = request_and_run(routed)
                provider = Provider()
                broker = TaskRegionModelBroker(
                    run,
                    request,
                    ReviewedTaskRegionGateway(
                        routed,
                        clock=lambda: self.now,
                    ),
                    config_provider=lambda value=config: value,
                    current_provider=lambda: current(request),
                    provider_factory=lambda _provider: provider,
                    vision_support=vision,
                    build_flags=self.flags,
                )
                call = broker.tool_call()
                approval = broker.approval_request(
                    call,
                    expires_at=routed.expires_at,
                )
                run.start()
                run.request_approval(
                    call,
                    approval,
                    now=self.now,
                )
                run.approve(
                    approval.approval_id,
                    approval.action_digest,
                    now=self.now,
                )
                with self.assertRaises(TaskRegionPermissionError):
                    await broker.execute(call)
                self.assertEqual(provider.calls, [])
                self.assertEqual(
                    bytes(routed.image_content),
                    b"\x00" * len(JPEG),
                )

    async def test_expiry_and_changed_bytes_fail_closed(self) -> None:
        for label, routed in (
            ("expired", context(expires_at=20.0)),
            ("changed", context()),
        ):
            with self.subTest(label=label):
                if label == "changed":
                    routed.image_content[-4] ^= 0x01
                request, run = request_and_run(routed)
                broker = self.broker(routed, request, run)
                call = broker.tool_call()
                approval = broker.approval_request(
                    call,
                    expires_at=routed.expires_at,
                )
                run.start()
                run.request_approval(
                    call,
                    approval,
                    now=min(self.now, routed.expires_at),
                )
                run.approve(
                    approval.approval_id,
                    approval.action_digest,
                    now=min(self.now, routed.expires_at),
                )
                with self.assertRaises(TaskRegionContextError):
                    await broker.execute(call)
                self.assertEqual(self.provider.calls, [])
                self.assertEqual(
                    bytes(routed.image_content),
                    b"\x00" * len(JPEG),
                )

    def test_grant_is_exact_and_non_task_destination_is_wiped(self) -> None:
        routed = context()
        request, _run = request_and_run(routed)
        expanded = CapabilityGrant(
            run_id=request.run_id,
            capabilities=frozenset(
                {
                    CapabilityId.TASK_AGENT_RUN,
                    CapabilityId.TASK_REGION_CONTEXT,
                    CapabilityId.GMAIL_MESSAGE_READ,
                }
            ),
        )
        with self.assertRaisesRegex(ValueError, "only run and region"):
            RegionTaskRequest(
                run_id=request.run_id,
                grant=expanded,
                instruction=request.instruction,
                route_id=request.route_id,
                intent_digest=request.intent_digest,
                selection_id=request.selection_id,
                selection_digest=request.selection_digest,
                image_sha256=request.image_sha256,
                image_byte_count=request.image_byte_count,
                width=request.width,
                height=request.height,
                provider=request.provider,
            )
        wrong = context(
            destination=HandoffDestination.COMPOSE_PREVIEW
        )
        with self.assertRaisesRegex(TypeError, "invalid"):
            ReviewedTaskRegionGateway(wrong)
        self.assertEqual(
            bytes(wrong.image_content),
            b"\x00" * len(JPEG),
        )
        with self.assertRaisesRegex(ValueError, "Coding response"):
            RegionTaskProviderSelection(
                "codex_agent",
                "gpt-5-codex",
            )


if __name__ == "__main__":
    unittest.main()
