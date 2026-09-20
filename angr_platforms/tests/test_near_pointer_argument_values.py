"""A null argument is not the address of byte zero in the data segment."""

from itertools import count
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CConstant, CFunctionCall, CUnaryOp
from angr.sim_type import SimTypeChar, SimTypeFloat, SimTypePointer, SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_pointer_values import (
    consume_near_pointer_argument_value_8616,
)
from angr_platforms.X86_16.lowering.near_pointer_argument_values import (
    materialize_near_pointer_argument_value_8616,
)
from angr_platforms.X86_16.pipeline.errors import PipelineHardError


@pytest.fixture
def codegen():
    indices = count()
    return SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        next_node_idx=lambda: next(indices),
        next_ident=lambda name: f"{name}_{next(indices)}",
        next_idx=lambda kind: next(indices),
    )


def test_compatibility_consumer_refuses_unbound_lowering(codegen):
    with pytest.raises(PipelineHardError, match="requires a Structuring-bound Lowering service"):
        consume_near_pointer_argument_value_8616(0, 0, codegen=codegen, c_target="portable-flat")


def test_structuring_binds_pointer_value_service(codegen):
    from angr_platforms.X86_16.decompiler_structuring_stage import _bind_structuring_callsite_consumers_8616

    _bind_structuring_callsite_consumers_8616(codegen)
    value = CConstant(0, SimTypeShort(False), codegen=codegen)
    assert consume_near_pointer_argument_value_8616(
        value, 0, codegen=codegen, c_target="portable-flat",
    ) == (value, False)


@pytest.mark.parametrize("target", ["portable-flat", "ms-c-16"])
def test_zero_pointer_argument_preserves_null(target, codegen):
    value = CConstant(0, SimTypeShort(False), codegen=codegen)
    result, wrapped = materialize_near_pointer_argument_value_8616(
        value, CConstant(0x1234, SimTypeShort(False), codegen=codegen), codegen=codegen, c_target=target,
    )
    assert result is value
    assert not wrapped


@pytest.mark.parametrize("target,helper", [("portable-flat", "SEG_PTR"), ("ms-c-16", "MK_FP")])
def test_nonzero_pointer_argument_preserves_segment_and_offset(target, helper, codegen):
    value = CConstant(2, SimTypeShort(False), codegen=codegen)
    segment = CConstant(0x1234, SimTypeShort(False), codegen=codegen)
    result, wrapped = materialize_near_pointer_argument_value_8616(
        value, segment, codegen=codegen, c_target=target,
    )
    assert wrapped
    assert isinstance(result, CFunctionCall)
    assert result.callee_target == helper
    assert result.args[0] is segment
    assert result.args[1].value == 2
    assert result.args[1] is not value


@pytest.mark.parametrize("kind", ["reference", "memory", "float", "float_type"])
def test_address_zero_or_noninteger_zero_is_not_a_null_constant(kind, codegen):
    pointer = SimTypePointer(SimTypeChar())
    if kind == "reference":
        value = CConstant(0, pointer, reference_values={pointer: b"object at offset zero"}, codegen=codegen)
    elif kind == "memory":
        value = CUnaryOp("Dereference", CConstant(0, pointer, codegen=codegen), codegen=codegen)
    elif kind == "float_type":
        value = CConstant(0, SimTypeFloat(), codegen=codegen)
    else:
        value = CConstant(0.0, SimTypeShort(False), codegen=codegen)
    result, wrapped = materialize_near_pointer_argument_value_8616(
        value, CConstant(0x1234, SimTypeShort(False), codegen=codegen), codegen=codegen, c_target="portable-flat",
    )
    assert wrapped
    assert isinstance(result, CFunctionCall)
