"""Retained iterators prove task cleanup order without provider or filesystem I/O."""

import asyncio
from pathlib import Path
import types
import unittest
from unittest import mock

from capability_registry import CapabilityGrant, CapabilityId
from declarative_tools import DeclarativeTool
from tasks.coordinator import TaskWorkspace
from tasks.models import TaskLimits, TaskRun, TaskSpec, ToolCall
from tasks.policy import WorkerPolicy
from tasks.stream_lifecycle import owned_stream
from tasks.tool_broker import (
    DeclaredToolStep, ModelGenerateArguments, TaskToolBroker,
    TaskToolBrokerOperationError, _configured_model_stream, broker_arguments_digest,
)


class Iterator:
    def __init__(self, values=(), *, error=None, block=False):
        self.values = iter(values)
        self.error = error
        self.block = block
        self.entered = asyncio.Event()

    def __aiter__(self):
        return self

    async def __anext__(self):
        self.entered.set()
        if self.block:
            await asyncio.Event().wait()
        if self.error:
            raise self.error
        try:
            return next(self.values)
        except StopIteration:
            raise StopAsyncIteration from None


class CloseAware(Iterator):
    def __init__(self, *args, close_error=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.close_calls = 0
        self.closed = False
        self.close_error = close_error

    async def aclose(self):
        self.close_calls += 1
        await asyncio.sleep(0)
        if self.close_error:
            raise self.close_error
        self.closed = True


def make_broker(stream_factory):
    steps = tuple(DeclaredToolStep(
        skill_id="clicky.test", skill_version="1.0.0", step_id=name,
        tool=tool, capability=CapabilityId.TASK_AGENT_RUN, output_id=name + "-output",
        depends_on=("generate",) if name == "verify" else (),
    ) for name, tool in (("generate", DeclarativeTool.MODEL_GENERATE),
                         ("verify", DeclarativeTool.VERIFY_OUTPUT)))
    limits = TaskLimits(runtime_seconds=60, max_tool_calls=8,
                        max_network_requests=8, max_output_bytes=16)
    run = TaskRun(TaskSpec(
        run_id="stream-test", skill_id="clicky.test", skill_version="1.0.0",
        goal="Check iterator ownership", input_digest="a" * 64,
        requested_result="Bounded output", verifier_step_id="verify",
        verifier_id="artifact-postcondition-v1", limits=limits,
    ), CapabilityGrant(run_id="stream-test", capabilities=frozenset({CapabilityId.TASK_AGENT_RUN})))
    run.start()
    root = Path(__file__).resolve().parent / "uncreated-stream-workspace"
    workspace = TaskWorkspace(root, WorkerPolicy.from_task_limits(limits))

    async def unused(*_):
        raise AssertionError("Unrelated adapter executed")

    with mock.patch.object(workspace, "verify", return_value=(0, 0)):
        broker = TaskToolBroker(run, workspace, steps, model_stream=stream_factory,
                                web_search=unused, web_fetch=unused,
                                artifact_root=root / "artifacts")
    args = ModelGenerateArguments(prompt="Synthetic", system_prompt="Return text")
    call = ToolCall(call_id="generate-call", run_id=run.run_id, step_id="generate",
                    tool_name="model.generate", capability=CapabilityId.TASK_AGENT_RUN,
                    arguments_digest=broker_arguments_digest(args))
    return broker, call, args


class TaskStreamLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_broker_closes_before_success_or_failure_is_returned(self):
        cases = (
            (CloseAware(["ok"]), None),
            (CloseAware(["x" * 32]), "broker_limit_exceeded"),
            (CloseAware([123]), "model_output_invalid"),
            (CloseAware(error=OSError("upstream")), "broker_operation_failed"),
            (CloseAware(["ok"], close_error=RuntimeError("close")), "broker_operation_failed"),
            (CloseAware(["x" * 32], close_error=RuntimeError("close")), "broker_limit_exceeded"),
            (CloseAware([123], close_error=RuntimeError("close")), "model_output_invalid"),
            (CloseAware(error=TaskToolBrokerOperationError("model_output_invalid"),
                        close_error=RuntimeError("close")), "model_output_invalid"),
        )
        for stream, error in cases:
            with self.subTest(error=error, values=stream):
                broker, call, args = make_broker(lambda _: stream)
                result = await broker.execute(call, args)
                self.assertEqual(result.result.error_code, error)
                self.assertEqual(stream.close_calls, 1)
                if error is None:
                    self.assertTrue(stream.closed)
                    self.assertEqual(result.text, "ok")
                else:
                    self.assertIsNone(result.text)
                    self.assertEqual(result.result.output_bytes, 0)

    async def test_generic_nullable_and_noncallable_close_remain_compatible(self):
        for close in ("absent", None, 42):
            stream = Iterator(["ok"])
            if close != "absent":
                stream.aclose = close
            broker, call, args = make_broker(lambda _: stream)
            result = await broker.execute(call, args)
            self.assertEqual(result.text, "ok")

    async def test_cancellation_retains_identity_when_close_fails(self):
        stream = CloseAware(block=True, close_error=RuntimeError("secondary"))
        broker, call, args = make_broker(lambda _: stream)
        task = asyncio.create_task(broker.execute(call, args))
        await stream.entered.wait()
        task.cancel("original cancellation")
        with self.assertRaises(asyncio.CancelledError) as caught:
            await task
        self.assertEqual(caught.exception.args, ("original cancellation",))
        self.assertEqual(stream.close_calls, 1)

    async def test_primary_exception_object_survives_secondary_base_exception(self):
        primary = ValueError("original")
        stream = CloseAware(close_error=asyncio.CancelledError("secondary"))
        with self.assertRaises(ValueError) as caught:
            async with owned_stream(stream):
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertEqual(stream.close_calls, 1)

    async def test_cancellation_during_successful_cleanup_is_not_success(self):
        entered = asyncio.Event()
        stream = Iterator()

        async def close():
            entered.set()
            await asyncio.Event().wait()

        stream.aclose = close

        async def consume():
            async with owned_stream(stream):
                pass

        task = asyncio.create_task(consume())
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

    async def test_invalid_close_return_is_cleanup_failure(self):
        stream = Iterator(["ok"])
        stream.aclose = lambda: None
        broker, call, args = make_broker(lambda _: stream)
        result = await broker.execute(call, args)
        self.assertEqual(result.result.error_code, "broker_operation_failed")
        self.assertIsNone(result.text)

    async def test_acquisition_failure_keeps_existing_mapping(self):
        def unavailable(_):
            raise TaskToolBrokerOperationError("model_output_invalid")
        broker, call, args = make_broker(unavailable)
        result = await broker.execute(call, args)
        self.assertEqual(result.result.error_code, "model_output_invalid")

    async def test_default_adapter_closes_inner_without_closing_provider_client(self):
        for mode in ("exhaust", "outer-close", "consumer-error", "cancel", "close-error"):
            with self.subTest(mode=mode):
                source = CloseAware(["first", "second"], block=mode == "cancel",
                                    close_error=RuntimeError("close") if mode == "close-error" else None)
                provider = types.SimpleNamespace(stream_response=lambda **_: source, aclose=mock.AsyncMock())
                cfg = types.ModuleType("config")
                cfg.cfg = types.SimpleNamespace(llm_provider=lambda: "openai", selected_model=lambda _: "synthetic")
                factory = types.ModuleType("ai.provider_factory")
                factory.create_llm_provider = lambda _: provider
                args = ModelGenerateArguments(prompt="Synthetic", system_prompt="Return text")
                with mock.patch.dict("sys.modules", {"config": cfg, "ai.provider_factory": factory}):
                    outer = _configured_model_stream(args)
                    if mode == "cancel":
                        task = asyncio.create_task(anext(outer))
                        await source.entered.wait()
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                    elif mode == "outer-close":
                        self.assertEqual(await anext(outer), "first")
                        await outer.aclose()
                    elif mode == "consumer-error":
                        with self.assertRaisesRegex(ValueError, "consumer"):
                            async with owned_stream(outer):
                                async for _ in outer:
                                    raise ValueError("consumer")
                    elif mode == "close-error":
                        with self.assertRaisesRegex(RuntimeError, "close"):
                            _ = [chunk async for chunk in outer]
                    else:
                        self.assertEqual([chunk async for chunk in outer], ["first", "second"])
                self.assertEqual(source.close_calls, 1)
                provider.aclose.assert_not_called()
