"""Logical reload replay requires proven ordering and mutation-free paths."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable
from inertia.ir.core import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from inertia.ir.function_ssa_registry import FunctionSSAArtifactVerdict8616
from inertia.ir.ssa import SSABlock
from inertia.ir.ssa_function import SSAFunctionArtifact
import inertia.lowering.ir_segmented_load_carriers as carriers


def _select(monkeypatch, blocks, predecessors, *, same_block=False):
    artifact = SSAFunctionArtifact(0x100, tuple(blocks), predecessor_map=predecessors)
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=SimpleNamespace(registers={"si": (0x18, 2)})),
        cfunc=SimpleNamespace(addr=0x100),
    )
    monkeypatch.setattr(
        carriers, "registered_function_ssa_artifact_8616",
        lambda *_args: SimpleNamespace(verdict=FunctionSSAArtifactVerdict8616.PROVEN, artifact=artifact),
    )
    address = IRAddress(
        MemSpace.DS, base=("di",), offset=4, size=2,
        status=AddressStatus.STABLE, segment_origin=SegmentOrigin.PROVEN,
        base_values=(IRValue(MemSpace.REG, name="di", size=2),),
    )
    fact = carriers._LogicalRegisterWriteFact8616("si", 0x100, 0x104, address)
    selector = carriers._same_block_reload_for_read_8616 if same_block else carriers._nearest_linear_logical_fact_8616
    selected = selector(
        codegen, carriers._RegisterSSAIdentity8616(0x18, 2, 0x100, "return_use"),
        0x110, {("si", 0x104): fact},
    )
    assert selected is None or selected == fact
    assert artifact.blocks == tuple(blocks)
    return selected is not None


def _instruction(op, addr):
    destination = IRValue(MemSpace.REG, name="di", size=2) if op == "MOV" else None
    return IRInstr(op, destination, (), 2, addr)


@pytest.mark.parametrize(
    ("unified_region", "variable_region", "expected"),
    [(0x100, 0x200, 0x100), (None, 0x200, 0x200), (None, None, None), (0, 0x200, 0)],
)
def test_register_identity_prefers_first_complete_variable(unified_region, variable_region, expected):
    variable = SimRegisterVariable(0x18, 2, ident="read", region=variable_region)
    unified = SimRegisterVariable(0x18, 2, ident="joined", region=unified_region)
    node = structured_c.CVariable(
        variable, unified_variable=unified,
        codegen=SimpleNamespace(next_node_idx=lambda: 0, next_ident=lambda _name: "test"),
    )

    identity = carriers._register_ssa_identity_8616(node)

    if expected is None:
        assert identity is None
    else:
        assert identity is not None
        assert (identity.reg, identity.size, identity.region) == (0x18, 2, expected)
        assert identity.ident == ("joined" if unified_region is not None else "read")


@pytest.mark.parametrize("same_block", [True, False])
@pytest.mark.parametrize("addr", [None, 0x108])
@pytest.mark.parametrize("op", ["NOP", "CALL", "STORE", "MOV"])
def test_same_block_reload_requires_ordered_mutation_free_interval(monkeypatch, same_block, addr, op):
    block = SSABlock(0x100, (
        _instruction("LOAD", 0x104), _instruction(op, addr), _instruction("CMP", 0x110),
    ), ())

    assert _select(monkeypatch, (block,), {0x100: ()}, same_block=same_block) is (
        addr is not None and op == "NOP"
    )


@pytest.mark.parametrize("location", ["reload", "intermediate", "use"])
@pytest.mark.parametrize("addr", [None, 0x108])
@pytest.mark.parametrize("op", ["NOP", "CALL", "STORE", "MOV"])
def test_cfg_reload_checks_addressless_intermediate_effects_without_guessing_boundaries(
    monkeypatch, location, addr, op,
):
    extra = (_instruction(op, addr),)
    entry = SSABlock(0x100, (_instruction("LOAD", 0x104),) + (extra if location == "reload" else ()), ())
    middle = SSABlock(0x106, extra if location == "intermediate" else (), ())
    use = SSABlock(0x10C, (extra if location == "use" else ()) + (_instruction("CMP", 0x110),), ())

    assert _select(monkeypatch, (entry, middle, use), {0x100: (), 0x106: (0x100,), 0x10C: (0x106,)}) is (
        op == "NOP" and (addr is not None or location == "intermediate")
    )
