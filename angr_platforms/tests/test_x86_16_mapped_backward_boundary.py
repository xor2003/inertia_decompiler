"""Native backward boundaries retain entry identity, census and byte witnesses."""
from __future__ import annotations

from types import ModuleType

import pytest
from angr_platforms.X86_16 import frontend_boundary_transport as transport_owner
from angr_platforms.X86_16 import frontend_direct_callsite_index as index_owner
from angr_platforms.X86_16 import frontend_function_boundary as boundary_owner
from angr_platforms.X86_16 import frontend_invocation_inventory as inventory_owner

from inertia_decompiler.project_loading import _build_project_from_bytes


@pytest.mark.parametrize("tail", ["c3", "ffe0"])
def test_mapped_backward_tail_retains_closed_or_open_result(tail: str) -> None:
    """Only a completely closed backward tail becomes a mapped boundary."""
    # Entry1003 jumps back to1000; only a literal return closes the tail.
    project = _build_project_from_bytes(bytes.fromhex(tail).ljust(3, b"\x90") + bytes.fromhex("ebfb"), base_addr=0x1000, entry_point=0x1003)
    owner = boundary_owner
    boundary = owner.mapped_entry_function_boundary_8616(project, 0x1003)
    if tail == "c3":
        assert boundary is not None
        assert boundary.addr == 0x1003
        assert boundary.block_addrs_set == frozenset({0x1000, 0x1003})
        assert boundary.successor_edges == ((0x1003, 0x1000),)
        assert boundary.reachable_instruction_addrs == frozenset({0x1000, 0x1003})
    else:
        assert boundary is None
    assert owner.exact_function_range_boundary_8616(project, 0x1003, 0x1005) is None


def test_mapped_forward_return_keeps_entry_and_range() -> None:
    """Keep forward-only mapped entry identity and envelope unchanged."""
    project = _build_project_from_bytes(bytes.fromhex("90c3"), base_addr=0x1000, entry_point=0x1000)
    boundary = boundary_owner.mapped_entry_function_boundary_8616(project, 0x1000)
    assert boundary is not None
    assert boundary.addr == 0x1000
    assert boundary.size == 2


def test_backward_call_projections_enclose_census_and_keep_entry() -> None:
    """Both inventory routes retain backward CALLs under the true entry."""
    #1008 jumps backward to CALL1000; its target100b and fallthrough1003 return.
    project = _build_project_from_bytes(bytes.fromhex("e80800c3") + b"\x90" * 4 + bytes.fromhex("ebf6") + b"\x90\xc3", base_addr=0x1000, entry_point=0x1008)
    boundary = boundary_owner.mapped_entry_function_boundary_8616(project, 0x1008)
    assert boundary is not None
    assert boundary.decode_start == 0x1000
    assert boundary.decode_end == 0x100c
    for block in boundary.blocks:
        for insn in block.capstone.insns:
            assert boundary.decode_start <= insn.address
            assert insn.address + insn.size <= boundary.decode_end

    def target(insn: object) -> int | None:
        return 0x100b if insn.mnemonic == "call" else None

    index = index_owner.build_boundary_direct_callsite_index_8616(boundary, direct_target_resolver=target)
    inventory = inventory_owner.build_invocation_inventory_8616(project, 0x1008, direct_target_resolver=target)
    assert inventory.status is inventory_owner.InvocationInventoryStatus8616.READY
    assert inventory.callsite_index is not None
    for result in (index, inventory.callsite_index):
        rows = result.for_target(0x100b)
        assert len(rows) == 1
        assert rows[0].callsite_addr == 0x1000
        assert rows[0].caller_start == 0x1008
        assert rows[0].entry_identity is None
        census = next(item for item in result.caller_censuses if item.entry_addr == 0x1008)
        assert (census.decode_start, census.decode_end) == (0x1000, 0x100c)
        assert all(census.decode_start <= insn.address < insn.address + insn.size <= census.decode_end for insn in census.instructions)


def test_exact_range_projection_retains_supplied_bounds() -> None:
    """Exact-range callers preserve their caller-supplied decoding interval."""
    project = _build_project_from_bytes(bytes.fromhex("90c390"), base_addr=0x1000, entry_point=0x1000)
    boundary = boundary_owner.exact_function_range_boundary_8616(project, 0x1000, 0x1003)
    assert boundary is not None
    assert (boundary.decode_start, boundary.decode_end) == (0x1000, 0x1003)


def _backward_transport_case() -> tuple[object, ModuleType, object]:
    """Create actual native bytes and their staged transport witness."""
    project = _build_project_from_bytes(bytes.fromhex("c39090ebfb"), base_addr=0x1000, entry_point=0x1003)
    boundary = boundary_owner.mapped_entry_function_boundary_8616(project, 0x1003)
    assert boundary is not None
    transport = transport_owner
    witness = transport.capture_function_boundary_8616(project, boundary)
    assert witness is not None
    return project, transport, witness


def test_backward_boundary_roundtrips_into_fresh_project() -> None:
    """Fresh native bytes reconstruct the same backward census and entry."""
    project, transport, witness = _backward_transport_case()
    fresh = _build_project_from_bytes(bytes.fromhex("c39090ebfb"), base_addr=0x1000, entry_point=0x1003)
    restored = transport.restore_function_boundary_8616(fresh, witness)
    assert restored is not None
    assert restored.project is fresh and restored.project is not project
    assert restored.addr == 0x1003
    assert restored.block_addrs_set == frozenset({0x1000, 0x1003})
    assert (restored.decode_start, restored.decode_end) == (0x1000, 0x1005)
    assert restored.near_return_continuations is None
    record = transport.function_boundary_record_8616(project, restored)
    assert record is not None
    rebound = transport.function_boundary_from_record_8616(fresh, record)
    assert rebound is not None and rebound.block_addrs_set == restored.block_addrs_set


def test_backward_transport_refuses_changed_native_bytes() -> None:
    """An altered backward return cannot satisfy the captured digest."""
    _project, transport, witness = _backward_transport_case()
    fresh = _build_project_from_bytes(bytes.fromhex("909090ebfb"), base_addr=0x1000, entry_point=0x1003)
    with pytest.raises(ValueError, match="bytes disagree"):
        transport.restore_function_boundary_8616(fresh, witness)


def test_backward_transport_refuses_missing_entry_head() -> None:
    """A byte-witnessed body cannot invent a callable entry in a gap."""
    _project, transport, witness = _backward_transport_case()
    forged = transport.FunctionBoundaryWitness8616(0x1001, witness.blocks)
    with pytest.raises(ValueError, match="entry"):
        forged.validate()


def test_transport_refuses_unwitnessed_reachable_gap() -> None:
    """Matching witnessed endpoints do not authorize an intervening NOP."""
    from hashlib import sha256
    transport = transport_owner
    project = _build_project_from_bytes(bytes.fromhex("9090c3"), base_addr=0x1000, entry_point=0x1000)
    witness = transport.FunctionBoundaryWitness8616(0x1000, (
        transport.BoundaryBlockWitness8616(0x1000, 1, sha256(b"\x90").hexdigest()),
        transport.BoundaryBlockWitness8616(0x1002, 1, sha256(b"\xc3").hexdigest()),
    ))
    assert transport.restore_function_boundary_8616(project, witness) is None


def test_transport_keeps_open_indirect_tail_refused() -> None:
    """Byte identity alone cannot close an unknown indirect terminal."""
    from hashlib import sha256
    transport = transport_owner
    project = _build_project_from_bytes(bytes.fromhex("ffe090ebfb"), base_addr=0x1000, entry_point=0x1003)
    witness = transport.FunctionBoundaryWitness8616(0x1003, (
        transport.BoundaryBlockWitness8616(0x1000, 2, sha256(bytes.fromhex("ffe0")).hexdigest()),
        transport.BoundaryBlockWitness8616(0x1003, 2, sha256(bytes.fromhex("ebfb")).hexdigest()),
    ))
    assert transport.restore_function_boundary_8616(project, witness) is None
