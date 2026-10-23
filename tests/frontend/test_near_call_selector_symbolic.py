"""Compare native CALL-window projection against independent x86 IP arithmetic."""

from __future__ import annotations

import capstone
import pytest
import z3

from inertia.frontend.x86_16.near_call_selector_window import (
    NearCallSelectorWindow8616,
    NearCallSelectorWindowFailure8616,
    NearCallSelectorWindowRefusal8616,
    project_near_call_selector_window_8616,
)

pytestmark = pytest.mark.decompiler

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
)
from inertia.frontend.x86_16.frontend_near_return_continuation import (
    prove_near_call_frame_premise_8616,
)


@pytest.mark.parametrize("head", [0x8000, 0xFFFC, 0xFFFD, 0x10000, 0x1FFFE, 0xF7FFD])
@pytest.mark.parametrize("displacement", [-32768, -1, 0, 1, 32767])
def test_projection_matches_symbolic_word_ip(head: int, displacement: int) -> None:
    """Admit exactly the invariant targets, including return-offset wrapping."""
    encoded = b"\xe8" + (displacement & 0xFFFF).to_bytes(2, "little")
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    (decoded,) = tuple(decoder.disasm(encoded, head))
    target = head + len(encoded) + displacement
    row = DecodedDirectCallsite8616(
        caller_start=head, instructions=(decoded,), instruction_index=0,
        callsite_addr=head, target_addr=target,
    )
    index = DecodedDirectCallsiteIndex8616(
        {target & 0xFFFF: (row,)},
        DecodedDirectCallsiteIndexStats8616(1, 1, 1, 1, 0),
    )
    premise = prove_near_call_frame_premise_8616(row, index, target)
    assert premise is not None
    projection = project_near_call_selector_window_8616(premise)

    # Independently execute the architectural word-IP addition. No interval
    # formula or projection predicate participates in this counterexample.
    selector = z3.BitVec("selector", 16)
    segment_base = z3.ZeroExt(16, selector) << 4
    offset = z3.BitVecVal(head, 32) - segment_base
    legal_fetch = z3.And(z3.ULE(offset, 0xFFFF - len(encoded) + 1))
    next_ip = z3.Extract(15, 0, offset) + len(encoded)
    target_ip = next_ip + z3.BitVecVal(displacement, 16)
    linear_target = segment_base + z3.ZeroExt(16, target_ip)
    solver = z3.Solver()
    solver.set(timeout=1000)
    solver.add(legal_fetch, linear_target != target)
    result = solver.check()
    assert result != z3.unknown, solver.reason_unknown()
    if result == z3.sat:
        assert isinstance(projection, NearCallSelectorWindowRefusal8616)
        assert projection.failure is NearCallSelectorWindowFailure8616.TARGET_NOT_WINDOW_INVARIANT
        return

    assert isinstance(projection, NearCallSelectorWindow8616)
    # Also check that no legal selector was silently excluded to manufacture
    # invariance. In particular, a CALL ending at IP=0x10000 remains included.
    solver.reset()
    selected = z3.And(
        z3.UGE(selector, projection.selector_low),
        z3.ULE(selector, projection.selector_high),
    )
    solver.add(selected != legal_fetch)
    assert solver.check() == z3.unsat
