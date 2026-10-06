"""Native path joins and call transport must preserve resize memory evidence."""

import pytest
import test_x86_16_declared_resize_boundary as f
from angr_platforms.X86_16.frontend_direct_callsite_index import build_decoded_direct_callsite_index_8616
from angr_platforms.X86_16.ir.real16_invocation_domain import (
    Real16CallChainLink8616,
    prove_real16_chained_invocation_domain_8616,
)


def test_branch_join_does_not_invent_good_metadata() -> None:
    """Different feasible MCB writes must remain unknown after joining."""
    # Both branches remain possible: unknown memory controls JCXZ.
    # First arm corrupts MCB marker; second restores Z. They never execute together.
    setup = bytes.fromhex("b80000 8ed8 b80001 8ec0 8b0e0005")
    branch = bytes.fromhex("e307 c606f00f00 eb05 c606f00f5a")
    tail = bytes.fromhex("b8004a bb4000 cd21 e80100 c3")
    caller = setup + branch + tail
    int_addr = f.MODULE_BASE + len(setup) + len(branch) + 6
    call_addr = int_addr + 2
    image = caller + b"\xc3"
    mz = bytearray(f._mz(image))
    mz[6:8] = b"\x00\x00"
    boot = f.program_from_mz_bytes(
        bytes(mz),
        f._environment(),
        code_ranges=(f.LinearRange(f.MODULE_BASE, len(caller)), f.LinearRange(f.MODULE_BASE + len(caller), 1)),
    )
    project, _raw, coverage = f._world(boot, len(caller))
    relation = f._resize_relation(boot.environment, int_addr)
    premise = f._resize_premise(project, coverage, call_addr, boot, (relation,))
    assert not premise.complete, "Alternative MCB states must not collapse to last visited block"


def test_resize_feasibility_does_not_prune_reachable_code_write() -> None:
    """Modified MCB bytes keep the error-path code write reachable."""
    setup = bytes.fromhex("b80000 8ed8 b80001 8ec0 c606f00f00 b8004a bb4000")
    # Corrupt MCB must return AX=7; the code write is therefore reachable.
    # Initial-good metadata incorrectly predicts AX=4A00 and prunes it.
    tail = bytes.fromhex("cd21 83f807 7505 c606001190 e80100 c3")
    caller = setup + tail
    int_addr = f.MODULE_BASE + len(setup)
    call_addr = f.MODULE_BASE + len(caller) - 4
    mz = bytearray(f._mz(caller + b"\xc3"))
    mz[6:8] = b"\x00\x00"
    boot = f.program_from_mz_bytes(
        bytes(mz),
        f._environment(),
        code_ranges=(f.LinearRange(f.MODULE_BASE, len(caller)), f.LinearRange(f.MODULE_BASE + len(caller), 1)),
    )
    project, _raw, coverage = f._world(boot, len(caller))
    relation = f._resize_relation(boot.environment, int_addr)
    premise = f._resize_premise(project, coverage, call_addr, boot, (relation,))
    assert not premise.complete, "Corrupt MCB takes code-writing error branch"


def test_parent_mcb_write_reaches_chained_resize_feasibility() -> None:
    """Child feasibility consumes the authenticated parent memory snapshot."""
    head = f.MODULE_BASE
    child = head + 0x40
    prefix = bytes.fromhex("b80000 8ed8 b80001 8ec0 c606f00f00")
    edge = head + len(prefix)
    caller = prefix + b"\xe8" + (child - edge - 3).to_bytes(2, "little") + b"\xc3"
    child_code = bytes.fromhex("b8004a bb4000 cd21 83f807 7505 c606401190 e80100 c3")
    child_call = child + len(child_code) - 4
    image = caller + bytes(child - head - len(caller)) + child_code + b"\xc3"
    mz = bytearray(f._mz(image))
    mz[6:8] = b"\x00\x00"
    boot = f.program_from_mz_bytes(
        bytes(mz),
        f._environment(),
        code_ranges=(
            f.LinearRange(head, len(caller)),
            f.LinearRange(child, len(child_code)),
            f.LinearRange(child + len(child_code), 1),
        ),
    )
    project, parent_ir, parent_cov = f._world(boot, len(caller))
    parent = f._resize_premise(project, parent_cov, edge, boot)
    assert parent.complete
    assert dict(parent.callsite_memory.known)[f.MCB_LINEAR] == 0
    boundary = f.exact_function_range_boundary_8616(project, child, child + len(child_code))
    assert boundary is not None
    raw = f.build_x86_16_ir_function_artifact(project, boundary)
    f.publish_function_ir_artifact_8616(project, raw)
    coverage = f.prove_ir_boundary_coverage_8616(project, boundary, raw)
    assert coverage.complete
    instructions = tuple(i for b in parent_cov.boundary.blocks for i in b.capstone.insns)
    index = build_decoded_direct_callsite_index_8616(
        {(head, head + len(caller)): instructions},
        direct_target_resolver=lambda i: child if i.address == edge else None,
        instruction_address_resolver=lambda i: i.address,
    )
    (row,) = index.for_target(child)
    link = Real16CallChainLink8616(
        parent, index, row, parent_ir, parent_cov.boundary, parent.callsite_call_state, raw, boundary
    )
    relation = f.declared_int21_resize_service_8616(boot.environment, caller_addr=child, callsite_addr=child + 6)
    assert isinstance(relation, f.DeclaredInterruptService8616)
    result = prove_real16_chained_invocation_domain_8616(
        project, coverage, child_call, boot=boot, boot_recompute=f._recompute, chain=link, declared_services=(relation,)
    )
    assert not result.complete
    assert result.failure is f.Real16InvocationFailure8616.CODE_WRITE_VIOLATION


@pytest.mark.parametrize(("marker", "expected_ax", "carry"), [(0x5A, 0x4A00, False), (0, 7, True)])
def test_identical_branch_writes_preserve_resize_response(marker: int, expected_ax: int, carry: bool) -> None:
    """A bytewise must meet retains identical writes on both feasible arms."""
    setup = bytes.fromhex("b80000 8ed8 b80001 8ec0 8b0e0005")
    store = bytes.fromhex("c606f00f") + bytes([marker])
    branch = bytes.fromhex("e307") + store + bytes.fromhex("eb05") + store
    tail = bytes.fromhex("b8004a bb4000 cd21 e80100 c3")
    caller = setup + branch + tail
    interrupt = f.MODULE_BASE + len(setup) + len(branch) + 6
    mz = bytearray(f._mz(caller + b"\xc3"))
    mz[6:8] = b"\0\0"
    boot = f.program_from_mz_bytes(
        bytes(mz),
        f._environment(),
        code_ranges=(
            f.LinearRange(f.MODULE_BASE, len(caller)),
            f.LinearRange(f.MODULE_BASE + len(caller), 1),
        ),
    )
    project, _raw, coverage = f._world(boot, len(caller))
    relation = f._resize_relation(boot.environment, interrupt)
    premise = f._resize_premise(project, coverage, interrupt + 2, boot, (relation,))
    assert premise.complete, premise.failure
    assert not premise.infeasible_edges
    assert dict(premise.callsite_call_state)["ax"] == expected_ax
    assert premise.service_consumptions
    for consumption in premise.service_consumptions:
        assert consumption.answer_ax == expected_ax
        assert consumption.carry is carry
        assert consumption.metadata_before[0] == marker
