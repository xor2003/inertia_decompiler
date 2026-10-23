"""Real call evidence stays finite while retaining live callee authority."""
from __future__ import annotations

import angr
from angr.analyses.decompiler.structured_codegen.c import CStructuredCodeGenerator

from inertia.cli.project_loading import _build_project_from_bytes
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.ir.function_lifecycle import FunctionStageVerdict8616
from inertia.ir.function_readiness_contracts import (
    FUNCTION_LIFECYCLE_STAGES_8616,
    FunctionLifecycleStage8616,
)
from inertia.pipeline.contracts import assert_pipeline_contracts_8616
from inertia.pipeline.function_readiness import (
    _evidence_fingerprint_8616,
    function_stage_evidence_map_8616,
    function_stage_readiness_8616,
)
from inertia.widening.carry_borrow_pipeline import CarryBorrowWideningPipeline8616

BASE = 0x1000


def _near_call_codegen() -> tuple[angr.Project, CStructuredCodeGenerator]:
    """Run genuine native producers for a caller and a simple returning callee."""
    apply_x86_16_bootstrap()
    # The final padding permits changing the callee's RET to RET 2 in place.
    code = bytes.fromhex('e80100c3b80300c39090')
    project = _build_project_from_bytes(code, base_addr=BASE, entry_point=BASE)
    cfg = project.analyses.CFGFast(normalize=True, fail_fast=True)
    result = project.analyses.Decompiler(cfg.functions[BASE], cfg=cfg, fail_fast=True)
    assert result.codegen is not None
    return project, result.codegen


def test_real_near_call_reaches_completed_native_stages() -> None:
    """An authenticated stack certificate must not serialize its loader handle."""
    project, codegen = _near_call_codegen()
    assert_pipeline_contracts_8616(codegen)
    for stage in FUNCTION_LIFECYCLE_STAGES_8616:
        assert function_stage_readiness_8616(project, BASE, stage).verdict is FunctionStageVerdict8616.CURRENT


def test_callee_stack_source_change_invalidates_live_call_evidence() -> None:
    """Finite call-effect evidence still observes the retained callee proof."""
    project, codegen = _near_call_codegen()
    assert_pipeline_contracts_8616(codegen)
    evidence = function_stage_evidence_map_8616(project, BASE)[FunctionLifecycleStage8616.WIDENING]
    pipeline = next(output for output in evidence.live_outputs
                    if isinstance(output, CarryBorrowWideningPipeline8616))
    aliases = pipeline.source_stack_alias
    assert aliases is not None and aliases.call_effects
    effect = aliases.call_effects[0].effect
    assert effect.current_net_stack_delta is not None
    before = _evidence_fingerprint_8616(effect)
    assert before is not None
    project.loader.memory.store(BASE + 7, bytes.fromhex('c20200'))
    assert effect.current_net_stack_delta is None
    after = _evidence_fingerprint_8616(effect)
    assert after is not None and after != before
    readiness = function_stage_readiness_8616(project, BASE, FunctionLifecycleStage8616.WIDENING)
    assert readiness.verdict is not FunctionStageVerdict8616.CURRENT
    assert readiness.failure is not None
