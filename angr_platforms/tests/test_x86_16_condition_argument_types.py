from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CFunction, CIndexedVariable, CStatements, CVariable
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.lowering.authoritative_function_prototypes import (
    authoritative_function_prototype_8616,
    capture_authoritative_function_prototype_8616,
)
from angr_platforms.X86_16.lowering.condition_argument_type_facts import (
    proven_recorded_wide_condition_stack_pair_8616,
    record_wide_condition_argument_type_evidence_8616,
)
from angr_platforms.X86_16.lowering.condition_argument_types import (
    _set_argument_surface_type_8616,
    apply_condition_argument_types_8616,
)
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint


class _DummyCodegen:
    def __init__(self, arch: Arch86_16) -> None:
        self._idx = 0
        self.project = SimpleNamespace(arch=arch)

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _FunctionManager:
    def __init__(self, function: SimpleNamespace) -> None:
        self._function = function

    def function(self, *, addr: int, create: bool) -> SimpleNamespace | None:
        assert create is False
        return self._function if addr == self._function.addr else None


@pytest.mark.parametrize("requested_offset,requested_width", [(4, 2), (6, 2), (4, 1)])
def test_argument_refinement_preserves_existing_unsigned_array_index(requested_offset, requested_width) -> None:
    """A signed declaration must not turn an unsigned address index negative."""
    codegen = _DummyCodegen(Arch86_16())
    unsigned = SimTypeShort(False).with_arch(codegen.project.arch)
    signed = SimTypeShort(True).with_arch(codegen.project.arch)
    index = CVariable(SimStackVariable(4, 2, base="bp", name="index"),
                      variable_type=unsigned, codegen=codegen)
    base = CVariable(SimMemoryVariable(0x200, 2, name="items"), variable_type=unsigned, codegen=codegen)
    indexed = CIndexedVariable(base, index, variable_type=unsigned, codegen=codegen)
    root = CStatements([indexed], codegen=codegen)
    cfunc = SimpleNamespace(statements=root, body=root)

    _set_argument_surface_type_8616(codegen, cfunc, requested_offset, requested_width, signed)

    if requested_offset != index.variable.offset or requested_width != index.variable.size:
        assert index.variable_type == unsigned
        assert indexed.index is index
        return

    assert index.variable_type == signed
    assert isinstance(indexed.index, CSemanticCast8616)
    assert indexed.index.src_type == signed and indexed.index.dst_type == unsigned
    assert indexed.index.expr is index
    assert "SemanticCast(" in _expr_fingerprint(indexed, codegen.project)
    bare_indexed = CIndexedVariable(base, index, variable_type=unsigned, codegen=codegen)
    assert _expr_fingerprint(indexed, codegen.project) != _expr_fingerprint(bare_indexed, codegen.project)
    first_view = indexed.index
    _set_argument_surface_type_8616(codegen, cfunc, 4, 2, signed)
    assert indexed.index is first_view


def _fixture(*, signed: bool) -> tuple[SimpleNamespace, _DummyCodegen]:
    arch = Arch86_16()
    function = SimpleNamespace(
        addr=0x1000,
        prototype=None,
        prototype_source=PrototypeSource.CCA_DECOMPILER,
        info={},
    )
    project = SimpleNamespace(arch=arch, kb=SimpleNamespace(functions=_FunctionManager(function)))
    codegen = _DummyCodegen(arch)
    arguments = [
        CVariable(
            SimStackVariable(offset, 4, base="bp", name=name),
            variable_type=SimTypeLong(signed).with_arch(arch),
            codegen=codegen,
        )
        for offset, name in ((4, "a"), (8, "b"))
    ]
    body = CStatements([], addr=0x1000, codegen=codegen)
    prototype = SimTypeFunction(
        [argument.variable_type for argument in arguments],
        SimTypeLong(True),
        arg_names=("a", "b"),
    ).with_arch(arch)
    codegen.cfunc = CFunction(
        0x1000,
        "sub_1000",
        prototype,
        arguments,
        body,
        {},
        SimpleNamespace(),
        codegen=codegen,
    )
    codegen._inertia_typed_conditions = []
    function.prototype = prototype
    return project, codegen


def _wide_condition(op: str) -> ConditionIR:
    return ConditionIR(
        op,
        IRValue(MemSpace.SS, name="bp", offset=4, size=4),
        IRValue(MemSpace.SS, name="bp", offset=8, size=4),
        width_bits=32,
        src_insn=0x1020,
        block_addr=0x1010,
    )


def test_unsigned_wide_condition_materializes_unsigned_long_arguments() -> None:
    project, codegen = _fixture(signed=True)
    assert record_wide_condition_argument_type_evidence_8616(codegen, _wide_condition("ult")) is True

    result = apply_condition_argument_types_8616(project, codegen)

    assert result.changed is True
    assert result.changed_offsets == (4, 8)
    assert result.stats.materialized_count == 2
    assert [argument.signed for argument in codegen.cfunc.functy.args] == [False, False]


def test_signed_wide_condition_overrides_unsigned_low_word_fragments() -> None:
    project, codegen = _fixture(signed=False)
    function = project.kb.functions.function(addr=0x1000, create=False)
    assert function is not None
    capture_authoritative_function_prototype_8616(project, function)
    codegen._inertia_typed_conditions = [
        ConditionIR(
            "ult",
            IRValue(MemSpace.SS, name="bp", offset=4, size=2),
            IRValue(MemSpace.SS, name="bp", offset=8, size=2),
            src_insn=0x1010,
            block_addr=0x1000,
        )
    ]
    record_wide_condition_argument_type_evidence_8616(codegen, _wide_condition("slt"))

    result = apply_condition_argument_types_8616(project, codegen)

    assert result.changed is True
    assert result.stats.failure_count == 0
    assert [argument.signed for argument in codegen.cfunc.functy.args] == [True, True]
    authoritative = authoritative_function_prototype_8616(
        project,
        function,
        argument_count=2,
    )
    assert authoritative is not None
    assert [argument.signed for argument in authoritative.args] == [True, True]


def test_recorded_wide_condition_preserves_exact_stack_pair_proof() -> None:
    """A recovered wide condition remains proof after C declarations rebuild."""
    _project, codegen = _fixture(signed=True)
    record_wide_condition_argument_type_evidence_8616(codegen, _wide_condition("slt"))

    assert proven_recorded_wide_condition_stack_pair_8616(
        codegen,
        IRValue(MemSpace.SS, name="bp", offset=6, size=2),
        IRValue(MemSpace.SS, name="bp", offset=4, size=2),
    )
    assert not proven_recorded_wide_condition_stack_pair_8616(
        codegen,
        IRValue(MemSpace.SS, name="bp", offset=8, size=2),
        IRValue(MemSpace.SS, name="bp", offset=6, size=2),
    )


def test_conflicting_raw_word_facts_refuse_argument_type_change() -> None:
    project, codegen = _fixture(signed=False)
    codegen._inertia_typed_conditions = [
        ConditionIR(
            op,
            IRValue(MemSpace.SS, name="bp", offset=4, size=2),
            IRValue(MemSpace.CONST, const=0, size=2),
            src_insn=0x1010 + index,
            block_addr=0x1000,
        )
        for index, op in enumerate(("slt", "ult"))
    ]

    result = apply_condition_argument_types_8616(project, codegen)

    assert result.changed is False
    assert result.stats.failure_count == 1
    assert [argument.signed for argument in codegen.cfunc.functy.args] == [False, False]
