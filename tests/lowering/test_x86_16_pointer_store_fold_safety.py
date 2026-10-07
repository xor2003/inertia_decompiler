"""Pointer-store projection folding must preserve segments and live carriers."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as c
from angr.sim_type import SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.near_pointer_argument import NearPointerArgumentFact8616
from inertia.lowering.pointer_store_consumption import (
    PointerStoreConsumptionFailure8616,
    prove_pointer_store_consumption_8616,
    prove_pointer_store_source_preservation_8616,
)
from inertia.lowering.segmented_memory_lowering import (
    _lower_typed_pointer_register_carrier_stores_8616,
)


def _word_store(*, segment="ds", carrier_value=False, later_use=False, helper_width=1, pointer_slot=6):
    arch = Arch86_16()
    word = SimTypeShort(False).with_arch(arch)
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
        cstyle_null_cmp=False,
    )

    def register(name):
        return c.CVariable(
            SimRegisterVariable(*arch.registers[name], name=name),
            variable_type=word,
            codegen=codegen,
        )

    def constant(value):
        return c.CConstant(value, word, codegen=codegen)

    pointer = c.CVariable(
        SimStackVariable(pointer_slot, 2, base="bp", name=f"output_{pointer_slot}", region=0x4010),
        variable_type=SimTypePointer(word).with_arch(arch),
        codegen=codegen,
    )
    carrier = register("bx")
    value = carrier if carrier_value else register("ax")
    tags = {"inertia_source_instruction_addrs": (0x4018,)}
    helper = f"SEG_U{helper_width * 8}"
    low = c.CAssignment(
        c.CIndexedVariable(pointer, constant(0), codegen=codegen, tags=tags),
        value,
        codegen=codegen,
    )
    high = c.CAssignment(
        c.CFunctionCall(
            helper, None,
            [register(segment), c.CBinaryOp("Add", carrier, constant(1), codegen=codegen)],
            codegen=codegen,
            tags={**tags, "inertia_x86_16_runtime_segment_helper": helper},
        ),
        c.CBinaryOp("Shr", value, constant(8), codegen=codegen),
        codegen=codegen,
    )
    statements = [c.CAssignment(carrier, pointer, codegen=codegen), low, high]
    if later_use:
        statements.append(c.CAssignment(register("cx"), carrier, codegen=codegen))
    root = c.CStatements(statements, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010, statements=root, body=root, arg_list=[pointer],
        functy=SimTypeFunction([pointer.variable_type], word).with_arch(arch),
    )
    codegen._inertia_near_pointer_argument_facts_8616 = (
        NearPointerArgumentFact8616(pointer_slot, 0x4014, 0x4018, 2),
    )
    return codegen, low, value


@pytest.mark.parametrize("helper_width", (1, 2))
def test_word_store_fold_preserves_exact_value(helper_width):
    codegen, low, value = _word_store(helper_width=helper_width)
    assert _lower_typed_pointer_register_carrier_stores_8616(codegen)
    assert codegen.cfunc.statements.statements == [low]
    assert low.rhs is value


@pytest.mark.parametrize("conflict", ("index", "provenance", "source"))
def test_mixed_byte_store_requires_exact_low_projection(conflict):
    codegen, low, value = _word_store()
    root = codegen.cfunc.statements
    high = root.statements[-1]
    if conflict == "index":
        low.lhs.index = c.CConstant(1, value.variable_type, codegen=codegen)
    elif conflict == "provenance":
        low.lhs.tags = {"inertia_source_instruction_addrs": (0x4020,)}
    else:
        high.rhs = c.CConstant(7, value.variable_type, codegen=codegen)
    original = tuple(root.statements)

    assert not _lower_typed_pointer_register_carrier_stores_8616(codegen)
    assert tuple(root.statements) == original
    assert low.rhs is value


@pytest.mark.parametrize("options", [
    {"segment": "es"},
    {"segment": "ss"},
    {"carrier_value": True},
])
def test_word_store_fold_refuses_conflicting_segment_or_live_carrier(options):
    codegen, low, value = _word_store(**options)
    original = tuple(codegen.cfunc.statements.statements)
    assert not _lower_typed_pointer_register_carrier_stores_8616(codegen)
    assert tuple(codegen.cfunc.statements.statements) == original
    assert low.rhs is value


@pytest.mark.parametrize("placement", ["outer", "sibling", "condition", "byte_alias", "shared"])
def test_word_store_fold_preserves_carriers_outside_local_sequence(placement):
    codegen, low, value = _word_store()
    inner = codegen.cfunc.statements
    setup = inner.statements[0]
    carrier = setup.lhs
    if placement == "byte_alias":
        carrier = c.CVariable(
            SimRegisterVariable(*codegen.project.arch.registers["bl"], name="bl"),
            variable_type=value.variable_type,
            codegen=codegen,
        )
    if placement == "shared":
        carrier = inner.statements[-1].lhs
    later = c.CAssignment(value, carrier, codegen=codegen)
    if placement == "sibling":
        later = c.CStatements([later], codegen=codegen)
    elif placement == "condition":
        later = c.CWhileLoop(carrier, c.CStatements([], codegen=codegen), codegen=codegen)
    outer = c.CStatements([inner, later], codegen=codegen)
    codegen.cfunc.body = outer
    codegen.cfunc.statements = outer
    original = tuple(inner.statements)

    assert _lower_typed_pointer_register_carrier_stores_8616(codegen)
    assert inner.statements == [setup, low]
    assert setup is original[0]
    assert outer.statements[-1] is later
    assert low.rhs is value


def test_word_store_fold_retains_setup_for_later_use():
    codegen, low, value = _word_store(later_use=True)
    root = codegen.cfunc.statements
    setup, _low, _high, later = root.statements

    assert _lower_typed_pointer_register_carrier_stores_8616(codegen)
    assert root.statements == [setup, low, later]
    assert later.rhs is setup.lhs
    assert low.rhs is value


def test_word_store_fold_preserves_independent_same_register_setup():
    codegen, low, value = _word_store()
    root = codegen.cfunc.statements
    setup = root.statements[0]
    other, other_low, _ = _word_store(pointer_slot=8)
    other_setup = other.cfunc.statements.statements[0]
    codegen.cfunc.arg_list.append(other_setup.rhs)
    codegen.cfunc.functy.args += (other_setup.rhs.variable_type,)
    codegen._inertia_near_pointer_argument_facts_8616 += other._inertia_near_pointer_argument_facts_8616
    root.statements.extend(other.cfunc.statements.statements)

    assert _lower_typed_pointer_register_carrier_stores_8616(codegen)
    assert root.statements == [setup, low, other_setup, other_low]
    assert low.rhs is value


def test_preserved_source_evidence_never_authorizes_setup_deletion():
    codegen, low, _ = _word_store(later_use=True)
    root = codegen.cfunc.statements
    setup, _, high, _ = root.statements
    source = prove_pointer_store_source_preservation_8616(
        setup.lhs, setup.rhs, (low, high), (low,),
    )
    consumption = prove_pointer_store_consumption_8616(
        (root,), setup, setup.lhs, setup.rhs, (low, high), (low,),
    )

    assert source.source_preserved
    assert not source.complete
    assert source.raw_fact_count == source.normalized_fact_count == 1
    assert source.classified_fact_count == source.materialized_count == 1
    assert source.failure_count == 0
    assert not consumption.complete
    assert consumption.failure is PointerStoreConsumptionFailure8616.UNCONSUMED_REGISTER


@pytest.mark.parametrize("intervening", ["pointer_write", "call", "byte_write"])
def test_word_store_fold_requires_unchanged_pointer_source(intervening):
    codegen, low, value = _word_store()
    root = codegen.cfunc.statements
    setup = root.statements[0]
    if intervening == "pointer_write":
        statement = c.CAssignment(setup.rhs, value, codegen=codegen)
    elif intervening == "call":
        statement = c.CAssignment(
            value, c.CFunctionCall("opaque", None, [], codegen=codegen), codegen=codegen,
        )
    else:
        byte = c.CVariable(
            SimRegisterVariable(*codegen.project.arch.registers["bl"], name="bl"),
            variable_type=value.variable_type, codegen=codegen,
        )
        statement = c.CAssignment(byte, value, codegen=codegen)
    root.statements.insert(1, statement)
    original = tuple(root.statements)

    assert not _lower_typed_pointer_register_carrier_stores_8616(codegen)
    assert tuple(root.statements) == original
    assert low.rhs is value


def test_word_store_consumption_closes_evidence_for_nested_unique_projection():
    codegen, low, _value = _word_store()
    inner = codegen.cfunc.statements
    setup, _low, high = inner.statements
    outer = c.CStatements([inner], codegen=codegen)
    codegen.cfunc.body = outer
    codegen.cfunc.statements = outer

    evidence = prove_pointer_store_consumption_8616(
        (outer, outer), setup, setup.lhs, setup.rhs, (low, high), (low,),
    )
    assert evidence.complete
    assert evidence.raw_fact_count == evidence.normalized_fact_count == 1
    assert evidence.classified_fact_count == evidence.materialized_count == 1
    assert evidence.failure_count == 0
    assert _lower_typed_pointer_register_carrier_stores_8616(codegen)
    assert inner.statements == [low]


@pytest.mark.parametrize("case, failure", [
    ("cycle", PointerStoreConsumptionFailure8616.CYCLIC_AST),
    ("shared_setup", PointerStoreConsumptionFailure8616.INCOMPLETE_PLACEMENT),
    ("opaque", PointerStoreConsumptionFailure8616.OPAQUE_EFFECT),
])
def test_word_store_consumption_refuses_incomplete_function_proof(case, failure):
    codegen, low, value = _word_store()
    root = codegen.cfunc.statements
    setup, _low, high = root.statements
    if case == "cycle":
        root.statements.append(root)
    elif case == "shared_setup":
        root.statements.append(setup)
    else:
        root.statements.append(c.CAssignment(
            value, c.CDirtyExpression(SimpleNamespace(), codegen=codegen), codegen=codegen,
        ))

    evidence = prove_pointer_store_consumption_8616(
        (root,), setup, setup.lhs, setup.rhs, (low, high), (low,),
    )
    assert not evidence.complete
    assert evidence.failure is failure
    assert evidence.classified_fact_count == evidence.materialized_count == 0
    assert evidence.failure_count == 1
