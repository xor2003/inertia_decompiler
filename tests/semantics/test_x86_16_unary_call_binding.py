"""Native-call binding controls for typed active conversion evidence."""
from dataclasses import replace

import pytest
import tests.semantics.test_direct_near_call_target_binding as native
from inertia.ir.core import IRActiveUnary8616, IRValue, MemSpace
import inertia.semantics.direct_near_call_target_binding as binder


@pytest.fixture(scope="module")
def fixture() -> native.Fixture:
    """Build the same genuine native fixture as the permanent binding cohort."""
    return native._fixture(native.near_return._project(), 0x10F1, 0x110D, 0x10F7)


@pytest.mark.parametrize("mutation", ["result_bits", "source_width", "result_width", "operation", "inner_operation", "pin"])
def test_native_call_rejects_corrupted_active_conversion(fixture: native.Fixture, mutation: str) -> None:
    """A complete native CALL loses binding when its actual target DAG is changed."""
    assert native._prove(fixture).complete
    producers = binder._tmp_producers_8616(fixture.block)
    outer = producers[fixture.call.args[0].source_tmp]
    shift = producers[outer.args[0].source_tmp]
    candidate = producers[shift.args[0].source_tmp]
    source = next(arg for arg in candidate.args if isinstance(arg, IRValue) and arg.active_unary is not None)
    active = source.active_unary
    if mutation == "result_bits":
        changed = replace(source, active_unary=replace(active, result_bits=16))
    elif mutation == "source_width":
        changed = replace(source, active_unary=replace(active, operand=replace(active.operand, size=4)))
    elif mutation == "result_width":
        changed = replace(source, size=2)
    elif mutation == "operation":
        changed = replace(source, active_unary=replace(active, op="Iop_16Sto32"))
    elif mutation == "inner_operation":
        inner = replace(active.operand, active_unary=IRActiveUnary8616("Iop_Not16", active.operand, 16))
        changed = replace(source, active_unary=replace(active, operand=inner))
    else:
        changed = replace(source, source_tmp=active.operand.source_tmp)
    row = replace(candidate, args=tuple(changed if arg is source else arg for arg in candidate.args))
    block = replace(fixture.block, instrs=tuple(row if instr is candidate else instr for instr in fixture.block.instrs))
    proof = binder.prove_direct_near_call_target_binding_8616(
        fixture.project, block=block, instruction=fixture.call, summary=fixture.summary)
    assert not proof.complete
    assert proof.failure is binder.DirectNearCallTargetBindingFailure8616.SHAPE_MISMATCH


def test_active_computations_cannot_be_plain_literal_or_register() -> None:
    """An active Not operation never supplies an undecorated literal or register."""
    literal = IRValue(MemSpace.CONST, const=4, size=1)
    changed = replace(literal, active_unary=IRActiveUnary8616("Iop_Not8", literal, 8))
    assert binder._const_int_8616(changed, 1) is None
    leaf = IRValue(MemSpace.REG, name="cs", size=2)
    changed = replace(leaf, active_unary=IRActiveUnary8616("Iop_Not16", leaf, 16))
    assert binder._reg_leaf_name_8616({}, changed) is None
