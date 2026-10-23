"""Readiness shares work within one observation and detects later mutation.

Layer: Pipeline regression tests.
Responsibility: bound repeated stage reads without weakening source currency.
"""

import sys
from collections import Counter
from types import SimpleNamespace

import pytest

from inertia.ir import function_ir_registry as raw_registry
from inertia.ir import function_readiness_contracts as contracts
from inertia.ir import function_ssa_registry as ssa_registry
from inertia.ir.function_lifecycle import FunctionStageFailure8616, FunctionStageVerdict8616
from inertia.ir.function_readiness_contracts import FunctionLifecycleStage8616 as Stage
from inertia.ir.function_ssa_registry import function_ssa_artifact_at_address_8616
from inertia.pipeline import function_readiness as owner
from tests.pipeline.test_function_readiness import BASE, MOV_AX_BX_RET, MOV_AX_DX_RET, _project

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("mutation", ("evidence", "source"))
def test_observation_shares_stage_and_body_reads_but_never_next_observation(mutation: str) -> None:
    """A shared native body is read once; a later edit must still revoke it."""
    project, _ = _project(MOV_AX_BX_RET)
    artifact = function_ssa_artifact_at_address_8616(project, BASE).artifact
    assert artifact is not None
    outputs = [SimpleNamespace(body=artifact, tag=stage) for stage in (Stage.ALIAS, Stage.WIDENING, Stage.TYPES)]
    for index, stage in enumerate((Stage.ALIAS, Stage.WIDENING, Stage.TYPES)):
        owner.record_function_stage_evidence_8616(
            project, BASE, stage, producer="observation_scope_test", outputs=(outputs[index],),
            upstream=tuple((prior, outputs[j]) for j, prior in enumerate((Stage.ALIAS, Stage.WIDENING)[:index])),
        )

    stages: Counter[Stage] = Counter()
    registries: Counter[str] = Counter()
    bodies = 0
    stage_code = owner._live_fingerprints_8616.__code__
    body_code = contracts.function_artifact_body_digest_8616.__code__
    raw_code = raw_registry.registered_function_ir_artifact_8616.__code__
    ssa_code = ssa_registry.registered_function_ssa_artifact_8616.__code__
    codes = (stage_code, body_code, raw_code, ssa_code)

    def observe(code: object, offset: int, result: object) -> None:
        """Count actual producers without replacing identity-bound functions."""
        nonlocal bodies
        frame = sys._getframe(1)
        if code is stage_code:
            stages[frame.f_locals["evidence"].stage] += 1
        elif code is raw_code:
            registries["raw"] += 1
        elif code is ssa_code:
            registries["ssa"] += 1
        elif frame.f_back.f_code is owner._typed_evidence_fingerprint_8616.__code__:
            bodies += 1

    sys.monitoring.use_tool_id(4, "readiness-observation-test")
    try:
        sys.monitoring.register_callback(4, sys.monitoring.events.PY_RETURN, observe)
        for code in codes:
            sys.monitoring.set_local_events(4, code, sys.monitoring.events.PY_RETURN)
        readiness = owner.function_stage_readiness_8616(project, BASE, Stage.TYPES)
    finally:
        for code in codes:
            sys.monitoring.set_local_events(4, code, 0)
        sys.monitoring.register_callback(4, sys.monitoring.events.PY_RETURN, None)
        sys.monitoring.free_tool_id(4)

    assert readiness.verdict is FunctionStageVerdict8616.CURRENT
    assert stages == {Stage.ALIAS: 1, Stage.WIDENING: 1, Stage.TYPES: 1}
    assert bodies == 1
    assert registries == {"raw": 1, "ssa": 1}

    if mutation == "evidence":
        outputs[0].tag = "changed"
        failure = FunctionStageFailure8616.UPSTREAM_EVIDENCE_CHANGED
    else:
        project.loader.memory.store(BASE, MOV_AX_DX_RET)
        failure = FunctionStageFailure8616.SOURCE_REVISION_CHANGED
    readiness = owner.function_stage_readiness_8616(project, BASE, Stage.TYPES)
    assert readiness.verdict is FunctionStageVerdict8616.STALE
    assert readiness.failure is failure
