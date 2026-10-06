"""Parent controls for the joint conditional-control refusal census.

Layer: Tests.
Responsibility: prevent function-level obligations disappearing from a joint
selector/continuation surface, including at retained-view consumption.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
import test_x86_16_scoped_control_obligations as fixture
from angr_platforms.X86_16.ir import entry_domain_call_preservation as edcp
from angr_platforms.X86_16.ir import scoped_control_obligations as joint
from angr_platforms.X86_16.ir import vex_import
from angr_platforms.X86_16.ir.near_return_continuation_view import (
    ScopedNearReturnContinuationViewFailure8616,
)


@pytest.mark.parametrize("at_consumption", [False, True])
def test_orphan_function_selector_refusal_is_retained(
    tmp_path: Path, at_consumption: bool,
) -> None:
    """A function-only selector obligation cannot hide behind clean blocks."""
    project, artifact, boundary, scope, bundle = fixture._fixture(tmp_path)
    try:
        view = vex_import.prove_scoped_control_obligations_view_8616(
            project, bundle, boundary, invocation_scope=scope,
        )
        assert view.complete_for(scope)
        selector = next(
            refusal for block in artifact.blocks for refusal in block.refusals
            if refusal.kind == joint._SELECTOR_WINDOW_PENDING_KIND_8616
        )
        orphan = replace(selector, block_addr=artifact.function_addr + 0x400)
        # Preserve independently held identities, as in the existing scoped
        # refusal controls: source identity alone must not erase new evidence.
        object.__setattr__(artifact, "refusals", (*artifact.refusals, orphan))
        if at_consumption:
            assert view.cfg_projection_for(scope) is None
            # Even a reconciled ledger must not authorize an explicitly
            # unresolved obligation. Replay must audit the surface itself.
            accounted = replace(
                view, raw_fact_count=3, normalized_fact_count=3,
                classified_fact_count=3, materialized_count=2, failure_count=1,
            )
            assert accounted.cfg_projection_for(scope) is None
        else:
            failure, _, _, _ = joint._obligation_surface_failure_8616(
                artifact, boundary,
            )
            assert failure is ScopedNearReturnContinuationViewFailure8616.RESIDUAL_REFUSAL
            refused = joint.prove_scoped_control_obligations_8616(
                artifact, boundary, bundle.terminal_evidence,
                project=project, invocation_scope=scope,
            )
            assert refused.failure is ScopedNearReturnContinuationViewFailure8616.RESIDUAL_REFUSAL
            assert refused.raw_fact_count == 3
            assert refused.normalized_fact_count == 3
            assert refused.classified_fact_count == 3
            assert refused.materialized_count == 0
            assert refused.failure_count > 0
    finally:
        edcp.install_real16_invocation_source_8616(project, None)
