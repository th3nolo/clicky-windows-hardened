"""Explicit, permissioned insertion boundary for reviewed compose drafts."""

from __future__ import annotations

import logging
import threading
from collections.abc import Mapping

from compose.models import DraftInsertionApproval
from dictation.insertion import (
    ExplicitInsertionRequest,
    InsertionAdapterKind,
    InsertionBroker,
    InsertionResult,
    InsertionStatus,
)
from feature_gates import (
    DEFAULT_BUILD_FEATURE_FLAGS,
    ActionCapability,
    ActionPermissionConfiguration,
    BuildFeatureFlag,
    action_capability_allowed,
)


_log = logging.getLogger(__name__)


class ComposeInsertionService:
    """Consume one UI approval without adding any auto-insert policy."""

    def __init__(
        self,
        broker: InsertionBroker,
        *,
        build_flags: Mapping[
            ActionCapability, BuildFeatureFlag
        ] = DEFAULT_BUILD_FEATURE_FLAGS,
    ) -> None:
        if not isinstance(broker, InsertionBroker):
            raise TypeError("Compose insertion requires the insertion broker")
        self._broker = broker
        self._build_flags = build_flags
        self._lock = threading.Lock()
        self._claimed_approvals: set[str] = set()

    def insert(
        self,
        approval: DraftInsertionApproval,
        config: ActionPermissionConfiguration,
    ) -> InsertionResult:
        """Attempt one insertion only from an explicit preview approval."""

        if not isinstance(approval, DraftInsertionApproval):
            raise TypeError(
                "Compose insertion requires an explicit preview approval"
            )
        run_id = approval.run_id
        with self._lock:
            if run_id in self._claimed_approvals:
                result = self._blocked(
                    approval,
                    "compose_insertion_duplicate_blocked",
                )
                self._log_result(approval, result)
                return result
            self._claimed_approvals.add(run_id)

        try:
            allowed = action_capability_allowed(
                config,
                ActionCapability.SCREEN_AWARE_COMPOSE,
                grant=approval.grant,
                run_id=run_id,
                build_flags=self._build_flags,
            )
        except Exception:
            allowed = False
        if not allowed:
            result = self._blocked(
                approval,
                "compose_insertion_permission_blocked",
            )
            self._log_result(approval, result)
            return result

        result = self._broker.insert_explicit(
            ExplicitInsertionRequest(
                run_id=run_id,
                target=approval.target,
                text=approval.draft.text,
                clipboard_fallback_approved=False,
            )
        )
        self._log_result(approval, result)
        return result

    @staticmethod
    def _blocked(
        approval: DraftInsertionApproval,
        result_code: str,
    ) -> InsertionResult:
        return InsertionResult(
            status=InsertionStatus.BLOCKED,
            adapter=InsertionAdapterKind.NONE,
            result_code=result_code,
            application_name=(
                approval.draft.provenance.destination_application
            ),
        )

    @staticmethod
    def _log_result(
        approval: DraftInsertionApproval,
        result: InsertionResult,
    ) -> None:
        _log.info(
            "compose insertion run=%s application=%s status=%s "
            "adapter=%s code=%s",
            approval.run_id,
            result.application_name or "unknown",
            result.status.value,
            result.adapter.value,
            result.result_code,
        )
