"""Native service evidence remains consumable in callee-scope memory walks."""

import pytest

from inertia.ir import real16_invocation_domain as owner
from tests.ir import test_x86_16_declared_interrupt_boundary as native
from tools.dosunit.runtime.real16_declared_invocation8616 import declared_int21_version_service_8616


@pytest.mark.parametrize(("declared", "ordinary"), [(True, False), (False, False), (True, True)])
def test_native_declared_interrupt_in_callee_walk(monkeypatch: pytest.MonkeyPatch, declared: bool, ordinary: bool) -> None:
    """Authenticated native interrupt effects survive a callee-scope walk."""
    boot = native._boot()
    project, _boundary, _artifact, coverage = native._world(boot)
    service = declared_int21_version_service_8616(boot.environment, caller_addr=native.MODULE_BASE, callsite_addr=native.INT_ADDR)
    canonical = owner._declared_service_crossing_8616
    seen = []

    def scoped(
        ctx: owner._PathCensusContext8616,
        actual_artifact: owner.IRFunctionArtifact,
        instruction: owner.IRInstr,
        registers: dict[str, int],
        memory: owner.PathMemory8616,
    ) -> owner.Real16InvocationFailure8616 | None:
        if ordinary:
            instruction = next(item for block in actual_artifact.blocks for item in block.instrs if item.op == "CALL" and item.addr == native.CALL_ADDR)
        block = next(block for block in actual_artifact.blocks if instruction in block.instrs)
        saved_site = ctx.callsite_addr
        ctx.callsite_addr = None
        try:
            with monkeypatch.context() as local:
                local.setattr(owner, "_declared_service_crossing_8616", canonical)
                result = owner._cross_call_8616(ctx, actual_artifact, block, instruction, registers, memory)
        finally:
            ctx.callsite_addr = saved_site
        seen.append(result)
        return result

    monkeypatch.setattr(owner, "_declared_service_crossing_8616", scoped)
    domain = native._premise(project, coverage, boot, (service,) if declared else ())
    assert seen
    if ordinary:
        assert seen[0] is owner.Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
        assert not domain.complete
    elif declared:
        assert seen[0] is None
        assert domain.failure is None
        assert domain.complete
    else:
        assert seen[0] is owner.Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
        assert not domain.complete
