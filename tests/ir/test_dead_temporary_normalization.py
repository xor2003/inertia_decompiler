"""Dead TMP normalization evidence, retention and malformed boundary controls."""

from dataclasses import replace

import pytest

from inertia.ir import dead_temporary_normalization as normalization_owner
from inertia.ir import scalar_instruction_effects as scalar_owner
from inertia.ir.core import IRAddress, IRBlock, IRCondition, IRInstr, IRValue, MemSpace
from inertia.ir.dead_temporary_normalization import (
    DeadTemporaryDecisionKind8616 as Kind,
)
from inertia.ir.dead_temporary_normalization import (
    DeadTemporaryNormalizationStatus8616 as Status,
)
from inertia.ir.dead_temporary_normalization import (
    normalize_dead_temporaries_8616 as normalize,
)
from inertia.ir.dead_temporary_normalization import (
    read_dead_temporary_dependencies_8616 as read,
)
from inertia.ir.instruction_origin import IRInstructionOrigin8616

pytestmark = pytest.mark.decompiler


def test_foreign_dispatch_mutation_changes_normalization_authority(monkeypatch):
    """Native cache producer identity must observe replaced dictionary handlers."""
    foreign_registry = dict(scalar_owner._CLASSIFIERS_8616)
    monkeypatch.setattr(scalar_owner, "_CLASSIFIERS_8616", foreign_registry)
    before = normalization_owner.dead_temporary_normalization_producers_8616()
    stable = normalization_owner.dead_temporary_normalization_producers_8616()
    assert tuple(map(id, before)) == tuple(map(id, stable))
    foreign_registry["MOV"] = foreign_registry["LOAD"]
    after = normalization_owner.dead_temporary_normalization_producers_8616()
    assert tuple(map(id, before)) != tuple(map(id, after))


def tmp(pin: int, size: int = 2) -> IRValue:
    return IRValue(MemSpace.TMP, name=f"uninterpreted_{pin}", size=size, source_tmp=pin)


def const(value: int = 1, size: int = 2) -> IRValue:
    return IRValue(MemSpace.CONST, const=value, size=size)


def mov(pin: int, source: IRValue | None = None) -> IRInstr:
    return IRInstr("MOV", tmp(pin), (source if source is not None else const(),), size=2, addr=101)


def test_dead_transitive_chain_removed_with_closed_counts() -> None:
    block = IRBlock(100, (mov(1), mov(2, tmp(1))))
    result = normalize(block)
    assert result.status is Status.COMPLETE
    assert result.block.instrs == ()
    assert [decision.kind for decision in result.decisions] == [Kind.REMOVE_DEAD_TOTAL] * 2
    assert (result.evidence.raw_fact_count, result.evidence.normalized_fact_count,
            result.evidence.classified_fact_count, result.evidence.materialized_count,
            result.evidence.failure_count) == (2, 0, 2, 2, 0)


def test_captured_register_external_pin_preserves_chain() -> None:
    rows = (mov(1), mov(2, tmp(1)), mov(3))
    result = normalize(IRBlock(100, rows), (IRValue(MemSpace.REG, name="ax", size=2, source_tmp=2),))
    assert result.block.instrs == rows[:2]
    assert result.block.instrs[0] is rows[0]


def test_store_address_condition_and_architectural_write_keep_dependencies() -> None:
    rows = (mov(1), mov(2), mov(3),
            IRInstr("STORE", None, (IRAddress(MemSpace.DS, base_values=(tmp(1),)), tmp(2))),
            IRInstr("CJMP", None, (IRCondition("eq", (tmp(3), const())), const(200))),
            IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), (const(),), size=2))
    assert normalize(IRBlock(100, rows)).block.instrs == rows


def test_unused_load_and_possible_trap_retained() -> None:
    rows = (IRInstr("LOAD", tmp(1), (IRAddress(MemSpace.DS),), size=2),
            IRInstr("Iop_DivU16", tmp(2), (const(), const(0)), size=2), mov(3))
    result = normalize(IRBlock(100, rows))
    assert result.block.instrs == rows[:2]


@pytest.mark.parametrize("operation,size,operand_size", [("Iop_Add16", 2, 2), ("Iop_CmpEQ16", 1, 2),
                                                         ("Iop_And1", 1, 1), ("Iop_MullU16", 4, 2)])
def test_existing_pure_operation_authorities(operation: str, size: int, operand_size: int) -> None:
    row = IRInstr(operation, tmp(1, size), (const(size=operand_size), const(size=operand_size)), size=size)
    assert normalize(IRBlock(100, (row,))).block.instrs == ()


@pytest.mark.parametrize("rows", [(mov(1), mov(1)), (mov(1, tmp(2)), mov(2)), (mov(1, tmp(999)),)])
def test_duplicate_forward_and_missing_definition_refuse(rows: tuple[IRInstr, ...]) -> None:
    block = IRBlock(100, rows)
    result = normalize(block)
    assert result.status is Status.UNKNOWN_REFUSE
    assert result.block is block
    assert all(decision.kind is Kind.UNKNOWN_REFUSE for decision in result.decisions)


@pytest.mark.parametrize("payload", [object(), [tmp(1)], IRValue(MemSpace.TMP, name="tmp_1"),
                                     IRValue(MemSpace.REG, name="ax", source_tmp=True)])
def test_opaque_external_roots_refuse(payload: object) -> None:
    block = IRBlock(100, (mov(1),))
    assert normalize(block, (payload,)).block is block
    assert normalize(block, (payload,)).status is Status.UNKNOWN_REFUSE


def test_cycle_refuses_without_recursion_failure() -> None:
    value = IRValue(MemSpace.REG, name="ax", size=2)
    object.__setattr__(value, "index", value)
    assert read(value).status is Status.UNKNOWN_REFUSE


def test_source_strings_do_not_create_tmp_dependencies() -> None:
    assert read(("tmp_999", "Iop_Add16", IRValue(MemSpace.REG, name="tmp_999"))).tmp_ids == frozenset()


def test_kept_origin_and_auxiliary_projection_identity_preserved() -> None:
    origin = IRInstructionOrigin8616(100, 9)
    row = replace(mov(1), origin=origin)
    live = IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), (tmp(1),), size=2,
                  origin=IRInstructionOrigin8616(100, 10))
    block = IRBlock(100, (row, live, mov(2)), successor_addrs=(200,))
    result = normalize(block)
    assert result.block.instrs == (row, live)
    assert result.block.instrs[0].origin is origin
    assert result.block.successor_addrs is block.successor_addrs
    assert result.block.refusals is block.refusals


def test_call_destination_tmp_is_input_and_not_a_definition() -> None:
    rows = (mov(1), IRInstr("CALL", tmp(1), (), size=2), mov(2))
    result = normalize(IRBlock(100, rows))
    assert result.status is Status.COMPLETE
    assert result.block.instrs == rows[:2]


@pytest.mark.parametrize("row", [IRInstr("MOV", object(), (const(),), size=2),
                                 IRInstr("LOAD", tmp(1), (IRAddress(MemSpace.DS, base_values=("bx",)),), size=2)])
def test_malformed_owned_dependency_fields_refuse(row: IRInstr) -> None:
    block = IRBlock(100, (row, mov(2)))
    result = normalize(block)
    assert result.status is Status.UNKNOWN_REFUSE
    assert result.block is block


def test_active_unary_and_index_dependencies_are_complete() -> None:
    from inertia.ir.core import IRActiveUnary8616

    value = IRValue(MemSpace.REG, name="ax", size=2, index=tmp(1),
                    active_unary=IRActiveUnary8616("Iop_8Uto16", tmp(2, 1), 16))
    assert read(value).tmp_ids == frozenset({1, 2})
    assert read(value).status is Status.COMPLETE


def test_captured_constant_metadata_pin_is_not_lost() -> None:
    value = replace(const(), source_tmp=1)
    rows = (mov(1), mov(2))
    assert normalize(IRBlock(100, rows), (value,)).block.instrs == rows[:1]


def test_block_next_and_memory_address_origin_pins_keep_producer() -> None:
    rows = (mov(1), mov(2), IRInstr("JMP", None, (const(200),),
                                  origin=IRInstructionOrigin8616(100, 11, address_tmp=1,
                                                                 is_block_next=True, block_next_tmp=2)))
    assert normalize(IRBlock(100, rows)).block.instrs == rows


def test_unknown_external_live_pin_refuses_complete_block() -> None:
    block = IRBlock(100, (mov(1),))
    result = normalize(block, external_live_tmp_ids=frozenset({2}))
    assert result.status is Status.UNKNOWN_REFUSE
    assert result.block is block


def test_foreign_origin_cannot_authorize_deletion() -> None:
    block = IRBlock(100, (replace(mov(1), origin=IRInstructionOrigin8616(200, 0)),))
    assert normalize(block).status is Status.UNKNOWN_REFUSE


def test_malformed_unary_operand_refuses_dependency_read() -> None:
    from inertia.ir.core import IRActiveUnary8616

    value = IRValue(MemSpace.REG, name="ax", size=2, active_unary=IRActiveUnary8616("Iop_8Uto16", "opaque", 16))
    assert read(value).status is Status.UNKNOWN_REFUSE


@pytest.mark.parametrize("operand", ["opaque", 1, object()])
def test_malformed_binary_operand_refuses(operand: object) -> None:
    from inertia.ir.core import IRBinaryValue

    assert read(IRBinaryValue("add", operand, const(), size=2)).status is Status.UNKNOWN_REFUSE


@pytest.mark.parametrize("changes", [{"call_output": object()}, {"memory_access_size": object()},
                                     {"memory_access_insn": True}, {"name": object()}])
def test_foreign_scalar_metadata_cannot_authorize_deletion(changes: dict[str, object]) -> None:
    source = replace(const(), **changes)
    block = IRBlock(100, (mov(1, source),))
    assert normalize(block).status is Status.UNKNOWN_REFUSE
    assert normalize(block).block is block


def test_unpinned_tmp_active_conversion_reads_inner_pinned_producer() -> None:
    from inertia.ir.core import IRActiveUnary8616

    outer = IRValue(MemSpace.TMP, size=4, expr=("Iop_16Uto32",),
                    active_unary=IRActiveUnary8616("Iop_16Uto32", tmp(2), 32))
    row = IRInstr("MOV", IRValue(MemSpace.REG, name="eax", size=4), (outer,), size=4)
    rows = (mov(2), row, mov(3))
    result = normalize(IRBlock(100, rows))
    assert result.status is Status.COMPLETE
    assert result.block.instrs == rows[:2]
    assert read(outer).tmp_ids == frozenset({2})


@pytest.mark.parametrize("op", ["Iop_DivU16", "unsupported"])
def test_unpinned_tmp_unsupported_computation_has_dependencies_without_totality(op: str) -> None:
    from inertia.ir.core import IRActiveUnary8616

    outer = IRValue(MemSpace.TMP, size=4,
                    active_unary=IRActiveUnary8616(op, tmp(2), 32))
    assert read(outer).status is Status.COMPLETE
    computation = IRInstr("MOV", tmp(3, 4), (outer,), size=4)
    rows = (mov(2), computation, mov(4))
    result = normalize(IRBlock(100, rows))
    assert result.block.instrs == rows[:2]


def test_unpinned_tmp_computation_cannot_define_destination() -> None:
    from inertia.ir.core import IRActiveUnary8616

    destination = IRValue(MemSpace.TMP, size=4,
                          active_unary=IRActiveUnary8616("Iop_16Uto32", tmp(2), 32))
    rows = (mov(2), IRInstr("MOV", destination, (const(size=4),), size=4))
    result = normalize(IRBlock(100, rows))
    assert result.status is Status.UNKNOWN_REFUSE
    assert result.block.instrs == rows


@pytest.mark.parametrize("op,result_bits,operand_size", [("Iop_Not8", 8, 1), ("Iop_1Uto16", 16, 1)])
def test_dependency_complete_unproved_unary_keeps_computation_and_closure(
    op: str, result_bits: int, operand_size: int,
) -> None:
    from inertia.ir.core import IRActiveUnary8616

    producer = IRInstr("MOV", tmp(2, operand_size), (const(size=operand_size),), size=operand_size)
    outer = IRValue(MemSpace.TMP, size=(result_bits + 7) // 8, expr=(op,),
                    active_unary=IRActiveUnary8616(op, tmp(2, operand_size), result_bits))
    computation = IRInstr("MOV", tmp(3, outer.size), (outer,), size=outer.size)
    rows = (producer, computation, mov(4))
    assert read(outer).status is Status.COMPLETE
    assert read(outer).tmp_ids == frozenset({2})
    result = normalize(IRBlock(100, rows))
    assert result.status is Status.COMPLETE
    assert result.block.instrs == rows[:2]
    assert result.decisions[2].kind is Kind.REMOVE_DEAD_TOTAL


@pytest.mark.parametrize("changes", [{"result_bits": True}, {"result_bits": 0}, {"result_bits": 32},
                                     {"op": object()}, {"operand": "opaque"}])
def test_unary_dependency_contract_rejects_malformed_fields(changes: dict[str, object]) -> None:
    from inertia.ir.core import IRActiveUnary8616

    unary = replace(IRActiveUnary8616("Iop_1Uto16", tmp(2, 1), 16), **changes)
    outer = IRValue(MemSpace.TMP, size=2, active_unary=unary)
    block = IRBlock(100, (IRInstr("MOV", tmp(2, 1), (const(size=1),), size=1), mov(3, outer)))
    assert normalize(block).status is Status.UNKNOWN_REFUSE
    assert normalize(block).block is block


@pytest.mark.parametrize("producer_op", ["Iop_CmpEQ16", "Iop_And1"])
def test_dead_boolean_conversion_uses_exact_reaching_producer_width(producer_op: str) -> None:
    from inertia.ir.core import IRActiveUnary8616

    operand_size = 2 if producer_op == "Iop_CmpEQ16" else 1
    producer = IRInstr(producer_op, tmp(2, 1), (const(size=operand_size), const(size=operand_size)), size=1)
    conversion = IRValue(MemSpace.TMP, size=2,
                         active_unary=IRActiveUnary8616("Iop_1Uto16", tmp(2, 1), 16))
    rows = (producer, IRInstr("MOV", tmp(3), (conversion,), size=2))
    result = normalize(IRBlock(100, rows))
    assert result.status is Status.COMPLETE
    assert result.block.instrs == ()
    assert result.evidence.materialized_count == 2
    live = normalize(IRBlock(100, rows), external_live_tmp_ids=frozenset({3}))
    assert live.block.instrs == rows


def test_boolean_width_does_not_transfer_to_unrelated_byte_pin() -> None:
    from inertia.ir.core import IRActiveUnary8616

    predicate = IRInstr("Iop_CmpEQ16", tmp(1, 1), (const(), const()), size=1)
    byte = IRInstr("MOV", tmp(2, 1), (const(1, 1),), size=1)
    conversion = IRValue(MemSpace.TMP, size=2,
                         active_unary=IRActiveUnary8616("Iop_1Uto16", tmp(2, 1), 16))
    rows = (predicate, byte, IRInstr("MOV", tmp(3), (conversion,), size=2))
    result = normalize(IRBlock(100, rows))
    assert result.block.instrs == rows[1:]


def test_boolean_width_cannot_redecorate_word_storage_as_one_bit() -> None:
    from inertia.ir.core import IRActiveUnary8616

    predicate = IRInstr("Iop_CmpEQ16", tmp(1, 1), (const(), const()), size=1)
    conversion = IRValue(MemSpace.TMP, size=2,
                         active_unary=IRActiveUnary8616("Iop_1Uto16", tmp(1, 2), 16))
    rows = (predicate, IRInstr("MOV", tmp(3), (conversion,), size=2))
    assert normalize(IRBlock(100, rows)).block.instrs == rows


@pytest.mark.parametrize("source", [const(0, 1), const(128, 1)])
def test_authenticated_truncation_produces_predicate_width(source: IRValue) -> None:
    from inertia.ir.core import IRActiveUnary8616

    narrowed = IRValue(MemSpace.TMP, size=1,
                       active_unary=IRActiveUnary8616("Iop_8to1", source, 1))
    widened = IRValue(MemSpace.TMP, size=2,
                      active_unary=IRActiveUnary8616("Iop_1Uto16", tmp(1, 1), 16))
    rows = (IRInstr("MOV", tmp(1, 1), (narrowed,), size=1),
            IRInstr("MOV", tmp(2), (widened,), size=2))
    result = normalize(IRBlock(100, rows))
    assert result.block.instrs == ()
    assert result.evidence.materialized_count == 2
    assert normalize(IRBlock(100, rows), external_live_tmp_ids=frozenset({2})).block.instrs == rows
