"""Return-use provenance must survive native conversion of shared C variables."""

from itertools import count
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.codegen_return_origin import (
    apply_codegen_return_origin_8616,
    return_value_origin_8616,
)

_ORIGIN_TAG = "inertia_x86_16_return_value_origin"
_RETURN_ADDR = 0x1200
_FIRST_DEFINITION = 0x1008
_SECOND_DEFINITION = 0x1108
_WORD_BITS = 16


def _fixture():
    indices = count()
    codegen = SimpleNamespace(project=SimpleNamespace(arch=Arch86_16()),
                              next_node_idx=lambda: next(indices), next_ident=lambda name: name)
    local = c.CVariable(SimStackVariable(-2, 2, base="bp", name="saved"),
                        variable_type=SimTypeShort(False), codegen=codegen)
    codegen._handle = lambda _expression: local
    return codegen, local


def _statement(definition, block):
    expression = SimpleNamespace(tags={"ins_addr": definition, "vex_block_addr": block}, bits=_WORD_BITS)
    return SimpleNamespace(ret_exprs=[expression], tags={"ins_addr": _RETURN_ADDR})


def test_shared_variable_retains_distinct_return_use_origins():
    codegen, local = _fixture()
    first = _statement(_FIRST_DEFINITION, 0x1000)
    second = _statement(_SECOND_DEFINITION, 0x1100)

    first_return = c.CStructuredCodeGenerator._handle_Stmt_Return(codegen, first)
    second_return = c.CStructuredCodeGenerator._handle_Stmt_Return(codegen, second)

    assert first_return.retval is second_return.retval is local
    assert local.tags == {}
    assert first.tags == second.tags == {"ins_addr": _RETURN_ADDR}
    first_origin = first_return.tags.get(_ORIGIN_TAG)
    second_origin = second_return.tags.get(_ORIGIN_TAG)
    assert first_origin is not None and second_origin is not None
    assert first_origin.instruction_addr == _FIRST_DEFINITION
    assert second_origin.instruction_addr == _SECOND_DEFINITION
    assert first_origin.block_addr == first.ret_exprs[0].tags["vex_block_addr"]
    assert second_origin.block_addr == second.ret_exprs[0].tags["vex_block_addr"]
    assert first_origin.width_bits == second_origin.width_bits == _WORD_BITS
    assert first_return.tags["ins_addr"] == second_return.tags["ins_addr"] == _RETURN_ADDR


@pytest.mark.parametrize("field,value", [
    ("ins_addr", None), ("ins_addr", True), ("ins_addr", -1), ("ins_addr", "4096"),
    ("vex_block_addr", None), ("vex_block_addr", False), ("vex_block_addr", -1),
    ("bits", None), ("bits", 0), ("bits", True), ("bits", -1), ("bits", "16"),
])
def test_invalid_source_metadata_is_not_guessed(field, value):
    codegen, local = _fixture()
    statement = _statement(_FIRST_DEFINITION, 0x1000)
    if field == "bits":
        statement.ret_exprs[0].bits = value
    else:
        statement.ret_exprs[0].tags[field] = value
    statement.tags[_ORIGIN_TAG] = "stale metadata"

    returned = c.CStructuredCodeGenerator._handle_Stmt_Return(codegen, statement)

    assert returned.retval is local
    assert return_value_origin_8616(returned) is None
    assert _ORIGIN_TAG not in returned.tags
    assert statement.tags[_ORIGIN_TAG] == "stale metadata"


@pytest.mark.parametrize("count_values", [0, 2])
def test_void_or_multiple_values_do_not_claim_a_unique_origin(count_values):
    codegen, local = _fixture()
    statement = _statement(_FIRST_DEFINITION, 0x1000)
    statement.ret_exprs *= count_values

    returned = c.CStructuredCodeGenerator._handle_Stmt_Return(codegen, statement)

    assert returned.retval is (local if count_values else None)
    assert return_value_origin_8616(returned) is None


def test_other_architectures_keep_native_conversion():
    codegen, local = _fixture()
    codegen.project.arch.name = "X86"
    statement = _statement(_FIRST_DEFINITION, 0x1000)

    returned = c.CStructuredCodeGenerator._handle_Stmt_Return(codegen, statement)

    assert returned.retval is local
    assert returned.tags is statement.tags
    assert return_value_origin_8616(returned) is None


def test_origin_installation_is_idempotent():
    installed = c.CStructuredCodeGenerator._handle_Stmt_Return
    apply_codegen_return_origin_8616()
    assert c.CStructuredCodeGenerator._handle_Stmt_Return is installed
