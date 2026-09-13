from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CStatements, CVariable
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from angr_platforms.X86_16.tail_validation import (
    refresh_x86_16_final_semantic_validation_8616,
)
from angr_platforms.X86_16.validation.entry_stack_ranges import (
    entry_stack_ranges_from_codegen_8616,
)
from angr_platforms.X86_16.validation_dataflow import (
    DefUseEntryStackRange8616,
    validate_structured_def_use_8616,
)
from archinfo import ArchX86


def _codegen() -> SimpleNamespace:
    """Return the minimal third-party codegen surface needed by C nodes."""
    return SimpleNamespace(
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
        project=SimpleNamespace(arch=ArchX86()),
    )


def _cvar(
    codegen: SimpleNamespace,
    offset: int,
    width: int = 2,
    name: str = "arg",
) -> CVariable:
    """Build one BP-relative structured variable for focused validation."""
    return CVariable(
        SimStackVariable(offset, width, base="bp", name=name, ident=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def test_explicit_entry_range_accepts_exact_read_and_refuses_overlap() -> None:
    codegen = _codegen()
    entry_range = (DefUseEntryStackRange8616(base_offset=4, width=2),)

    exact = validate_structured_def_use_8616(
        CStatements([_cvar(codegen, 4)], codegen=codegen),
        entry_defined_stack_ranges=entry_range,
    )
    overlapping = validate_structured_def_use_8616(
        CStatements([_cvar(codegen, 5)], codegen=codegen),
        entry_defined_stack_ranges=entry_range,
    )

    assert exact.passed
    assert exact.materialized_count == 1
    assert overlapping.issue_tokens() == (
        "uninitialized-read:stack-local:SS:BP+0x5:size2:root.stmt0",
    )


def test_codegen_collector_projects_entry_sp_argument_to_machine_bp() -> None:
    codegen = _codegen()
    argument = _cvar(codegen, 2)
    codegen.cfunc = SimpleNamespace(arg_list=[argument])
    storage = argument.variable
    assert isinstance(storage, SimStackVariable)
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=storage,
        cvar=argument,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )

    collection = entry_stack_ranges_from_codegen_8616(codegen)

    assert collection.ranges == (
        DefUseEntryStackRange8616(base_offset=4, width=2),
    )
    assert collection.stats.raw_fact_count == 1
    assert collection.stats.normalized_fact_count == 1
    assert collection.stats.classified_fact_count == 1
    assert collection.stats.materialized_count == 1
    assert collection.stats.failure_count == 0
    assert collection.stats.complete is True


def test_codegen_collector_uses_complete_interface_for_coordinate_collision() -> None:
    codegen = _codegen()
    low = _cvar(codegen, 2, name="low")
    high = _cvar(codegen, 4, name="high")
    codegen.cfunc = SimpleNamespace(
        arg_list=[low, high],
        functy=SimTypeFunction(
            [SimTypeShort(False), SimTypeShort(False)],
            SimTypeBottom(label="void"),
        ).with_arch(codegen.project.arch),
    )

    collection = entry_stack_ranges_from_codegen_8616(codegen)

    assert collection.ranges == (
        DefUseEntryStackRange8616(base_offset=4, width=2),
        DefUseEntryStackRange8616(base_offset=6, width=2),
    )
    assert collection.stats.complete is True


def test_final_tail_validation_refuses_read_overlapping_argument_boundary() -> None:
    codegen = _codegen()
    argument = _cvar(codegen, 2)
    storage = argument.variable
    assert isinstance(storage, SimStackVariable)
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=storage,
        cvar=argument,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=[argument],
        # Final C stack variables retain entry-SP coordinates. Entry-SP +3
        # projects to machine BP+5 and overlaps the BP+4..+5 argument.
        statements=CStatements([_cvar(codegen, 3)], codegen=codegen),
    )
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(
        codegen.project,
        codegen,
        persist_failures=False,
    )

    assert report.def_use.issue_tokens() == (
        "uninitialized-read:stack-local:SS:BP+0x5:size2:root.stmt0",
    )


@pytest.mark.parametrize("slot_width", [2, 4])
@pytest.mark.parametrize("unified", [False, True])
def test_byte_argument_cannot_initialize_the_rest_of_its_abi_slot(slot_width, unified):
    codegen = _codegen()
    argument = _cvar(codegen, 2, slot_width)
    argument.variable_type = SimTypeChar().with_arch(codegen.project.arch)
    if unified:
        argument.unified_variable = SimStackVariable(2, slot_width, base="bp", name="arg")
    storage = argument.unified_variable if unified else argument.variable
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=storage, cvar=argument, bp_offset=4,
        entry_sp_offset=2, size=slot_width,
    )
    read = _cvar(codegen, 3, 1, "local_5")
    read.variable_type = SimTypeChar().with_arch(codegen.project.arch)
    codegen.cfunc = SimpleNamespace(
        arg_list=[argument], statements=CStatements([read], codegen=codegen),
    )
    collection = entry_stack_ranges_from_codegen_8616(codegen)
    assert collection.ranges == (DefUseEntryStackRange8616(base_offset=4, width=1),)
    report = refresh_x86_16_final_semantic_validation_8616(codegen.project, codegen, persist_failures=False)
    assert not report.def_use.passed


def test_unknown_argument_value_width_does_not_initialize_a_storage_slot():
    codegen = _codegen()
    argument = _cvar(codegen, 4)
    argument.variable_type = None
    codegen.cfunc = SimpleNamespace(arg_list=[argument])
    collection = entry_stack_ranges_from_codegen_8616(codegen)
    assert not collection.ranges
    assert collection.stats.failure_count == 1
    assert collection.stats.complete


@pytest.mark.parametrize("slot_width", [2, 4])
def test_byte_argument_read_does_not_consume_abi_padding(slot_width):
    codegen = _codegen()
    argument = _cvar(codegen, 2, slot_width)
    argument.variable_type = SimTypeChar().with_arch(codegen.project.arch)
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=argument.variable, cvar=argument, bp_offset=4,
        entry_sp_offset=2, size=slot_width,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=[argument], statements=CStatements([argument], codegen=codegen),
    )
    report = refresh_x86_16_final_semantic_validation_8616(
        codegen.project, codegen, persist_failures=False,
    )
    assert report.def_use.passed, report.def_use.issue_tokens()


@pytest.mark.parametrize("declared_byte", [False, True])
def test_entry_range_uses_the_type_rendered_in_the_function_signature(declared_byte):
    codegen = _codegen()
    argument = _cvar(codegen, 4)
    byte = SimTypeChar().with_arch(codegen.project.arch)
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    argument.variable_type = word if declared_byte else byte
    codegen.cfunc = SimpleNamespace(
        arg_list=[argument],
        functy=SimTypeFunction([byte if declared_byte else word], word).with_arch(codegen.project.arch),
    )
    collection = entry_stack_ranges_from_codegen_8616(codegen)
    assert collection.ranges == (DefUseEntryStackRange8616(base_offset=4, width=1 if declared_byte else 2),)


def test_missing_parameter_declaration_cannot_initialize_a_variable():
    codegen = _codegen()
    codegen.cfunc = SimpleNamespace(
        arg_list=[_cvar(codegen, 4)],
        functy=SimTypeFunction([], SimTypeShort(False)).with_arch(codegen.project.arch),
    )
    collection = entry_stack_ranges_from_codegen_8616(codegen)
    assert not collection.ranges
    assert collection.stats.failure_count == 1
