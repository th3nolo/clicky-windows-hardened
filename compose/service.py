"""Permissioned, non-destructive Screen-Aware Compose generation."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Mapping, Sequence
from typing import Protocol

from ai.base_provider import BaseLLMProvider
from ai.provider_catalog import (
    AGENT_PROVIDERS,
    REGISTRY_MODEL_PROVIDERS,
)
from compose.models import (
    ComposeInvocation,
    ComposeRequest,
    ComposeScreenshot,
    Draft,
    DraftProvenance,
)
from compose.prompt import build_compose_prompt, validate_draft_output
from dictation.targeting import SecureTargetGuard
from feature_gates import (
    DEFAULT_BUILD_FEATURE_FLAGS,
    ActionCapability,
    ActionPermissionConfiguration,
    BuildFeatureFlag,
    action_capability_allowed,
)
from privacy_controls import (
    coding_agent_allowed,
    screen_capture_allowed,
)


class ComposeError(RuntimeError):
    """Safe base error for a composition that performed no external action."""


class ComposePermissionError(ComposeError):
    pass


class ComposeTargetError(ComposeError):
    pass


class ComposeCaptureError(ComposeError):
    pass


class ComposeProviderError(ComposeError):
    pass


class ComposeCaptureGateway(Protocol):
    def capture(
        self,
        authorized_screenshot_ids: tuple[str, ...],
    ) -> Sequence[ComposeScreenshot]: ...


class ComposeProviderFactory(Protocol):
    def __call__(self, provider_id: str) -> BaseLLMProvider: ...


VisionSupport = Callable[[str, str], bool]


class ComposeService:
    """Create a draft only; insertion is intentionally outside this service."""

    def __init__(
        self,
        *,
        targets: SecureTargetGuard,
        capture_gateway: ComposeCaptureGateway,
        provider_factory: ComposeProviderFactory | None = None,
        vision_support: VisionSupport | None = None,
        build_flags: Mapping[
            ActionCapability, BuildFeatureFlag
        ] = DEFAULT_BUILD_FEATURE_FLAGS,
    ) -> None:
        self._targets = targets
        self._capture_gateway = capture_gateway
        self._provider_factory = (
            provider_factory or _default_provider_factory
        )
        self._vision_support = (
            vision_support or cached_model_supports_vision
        )
        self._build_flags = build_flags

    def prepare_request(
        self,
        invocation: ComposeInvocation,
        config: ActionPermissionConfiguration,
    ) -> ComposeRequest:
        """Authorize before capturing exactly the explicitly named screens."""

        if not isinstance(invocation, ComposeInvocation):
            raise TypeError("Compose requires an explicit typed invocation")
        self._authorize(invocation, config)
        target = self._targets.revalidate(invocation.target)
        if not target.allowed or target.lease is None:
            raise ComposeTargetError(
                "The compose destination changed or is not permitted."
            )
        try:
            captured = tuple(
                self._capture_gateway.capture(
                    invocation.authorized_screenshot_ids
                )
            )
        except ComposeError:
            raise
        except Exception:
            raise ComposeCaptureError(
                "The authorized screen capture failed."
            ) from None
        if (
            any(
                not isinstance(screenshot, ComposeScreenshot)
                for screenshot in captured
            )
            or len(captured) != len(invocation.authorized_screenshot_ids)
        ):
            raise ComposeCaptureError(
                "Screen capture did not return the authorized set."
            )
        by_id = {screenshot.screenshot_id: screenshot for screenshot in captured}
        if (
            len(by_id) != len(captured)
            or set(by_id) != set(invocation.authorized_screenshot_ids)
        ):
            raise ComposeCaptureError(
                "Screen capture did not return the authorized set."
            )
        ordered = tuple(
            by_id[screenshot_id]
            for screenshot_id in invocation.authorized_screenshot_ids
        )
        try:
            return ComposeRequest(
                run_id=invocation.run_id,
                grant=invocation.grant,
                instruction=invocation.instruction,
                target=target.lease,
                screenshots=ordered,
                provider=invocation.provider,
                response_language=invocation.response_language,
                style_profile_id=invocation.style_profile_id,
                max_output_chars=invocation.max_output_chars,
            )
        except (TypeError, ValueError):
            raise ComposeCaptureError(
                "The authorized screen capture was invalid."
            ) from None

    async def generate_draft(
        self,
        request: ComposeRequest,
        config: ActionPermissionConfiguration,
    ) -> Draft:
        """Call one response provider without history, tools, or side effects."""

        if not isinstance(request, ComposeRequest):
            raise TypeError("Compose generation requires an authorized request")
        self._authorize(request, config)
        target = self._targets.revalidate(request.target)
        if not target.allowed or target.lease is None:
            raise ComposeTargetError(
                "The compose destination changed before generation."
            )
        try:
            provider = self._provider_factory(
                request.provider.provider_id
            )
            stream = provider.stream_response(
                user_text=request.instruction,
                screenshots_b64=[
                    screenshot.base64_jpeg
                    for screenshot in request.screenshots
                ],
                history=[],
                system_prompt=build_compose_prompt(request),
                model=request.provider.model_id,
            )
        except Exception:
            raise ComposeProviderError(
                "The selected compose provider could not start."
            ) from None

        chunks: list[str] = []
        length = 0
        try:
            async for chunk in stream:
                if not isinstance(chunk, str):
                    raise ComposeProviderError(
                        "The selected compose provider returned invalid data."
                    )
                length += len(chunk)
                if length > request.max_output_chars:
                    raise ComposeProviderError(
                        "The selected compose provider exceeded the draft limit."
                    )
                chunks.append(chunk)
        except asyncio.CancelledError:
            await _close_stream(stream)
            raise
        except ComposeProviderError:
            await _close_stream(stream)
            raise
        except Exception:
            await _close_stream(stream)
            raise ComposeProviderError(
                "The selected compose provider failed."
            ) from None
        try:
            text = validate_draft_output(
                "".join(chunks),
                request.max_output_chars,
            )
            provenance = DraftProvenance(
                run_id=request.run_id,
                provider_id=request.provider.provider_id,
                model_id=request.provider.model_id,
                destination_application=(
                    request.destination_application
                ),
                destination_identity=request.destination_identity,
                target_type=request.target_type,
                screenshot_ids=tuple(
                    screenshot.screenshot_id
                    for screenshot in request.screenshots
                ),
                response_language=request.response_language,
                style_profile_id=request.style_profile_id,
                max_output_chars=request.max_output_chars,
            )
            return Draft(text=text, provenance=provenance)
        except (TypeError, ValueError):
            raise ComposeProviderError(
                "The selected compose provider returned an unsafe draft."
            ) from None

    def _authorize(
        self,
        operation: ComposeInvocation | ComposeRequest,
        config: ActionPermissionConfiguration,
    ) -> None:
        capability = ActionCapability.SCREEN_AWARE_COMPOSE
        try:
            allowed = action_capability_allowed(
                config,
                capability,
                grant=operation.grant,
                run_id=operation.run_id,
                build_flags=self._build_flags,
            )
        except Exception:
            allowed = False
        if not allowed:
            raise ComposePermissionError(
                "Screen-Aware Compose is unavailable or not permitted."
            )
        if not screen_capture_allowed(config):
            raise ComposePermissionError(
                "Screen capture permission is required for Screen-Aware Compose."
            )
        provider_id = operation.provider.provider_id
        if (
            provider_id in AGENT_PROVIDERS
            and not coding_agent_allowed(config)
        ):
            raise ComposePermissionError(
                "The selected read-only response provider is not permitted."
            )
        try:
            supports_vision = self._vision_support(
                provider_id,
                operation.provider.model_id,
            )
        except Exception:
            supports_vision = False
        if supports_vision is not True:
            raise ComposePermissionError(
                "The selected model has no validated image-input support."
            )


def cached_model_supports_vision(
    provider_id: str,
    model_id: str,
) -> bool:
    """Conservative capability lookup; unknown/local heuristics fail closed."""

    try:
        from ai.model_selection import model_supports_vision

        if provider_id in REGISTRY_MODEL_PROVIDERS:
            from ai.model_registry import cached_models

            records = cached_models(provider_id)
        elif provider_id == "copilot":
            from ai.github_copilot_provider import cached_models

            records = cached_models()
        else:
            return False
        return model_supports_vision(model_id, records)
    except Exception:
        return False


def _default_provider_factory(provider_id: str) -> BaseLLMProvider:
    from ai.provider_factory import create_llm_provider

    return create_llm_provider(provider_id)


async def _close_stream(stream) -> None:
    close = getattr(stream, "aclose", None)
    if close is None:
        return
    try:
        await close()
    except Exception:
        pass
