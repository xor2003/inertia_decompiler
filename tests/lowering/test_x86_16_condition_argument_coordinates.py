from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace
from inertia.lowering.condition_argument_types import (
    apply_condition_argument_types_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)


class _FunctionManager:
    """Empty third-party function manager boundary for the focused pass."""

    def function(self, *, addr: int, create: bool) -> None:
        """Return no external prototype owner for this isolated fixture."""
        assert addr == 0x1000
        assert create is False
        return None


class _Codegen:
    """Minimal codegen boundary supporting CVariable construction."""

    def __init__(self, arch: Arch86_16) -> None:
        self.project = SimpleNamespace(arch=arch)
        self._next_index = 0

    def next_idx(self, _kind: str) -> int:
        """Return one deterministic C-AST index."""
        self._next_index += 1
        return self._next_index

    def next_node_idx(self) -> int:
        """Return one deterministic C-AST node index."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Preserve the requested test identity."""
        return name


def test_signed_condition_types_use_machine_bp_coordinates() -> None:
    """Sign both projected arguments instead of shifting the first fact."""
    arch = Arch86_16()
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(functions=_FunctionManager()),
    )
    codegen = _Codegen(arch)
    unsigned_word = SimTypeShort(False).with_arch(arch)
    variables = (
        SimStackVariable(2, 2, base="bp", name="a", ident="arg_0"),
        SimStackVariable(4, 2, base="bp", name="b", ident="arg_1"),
    )
    arguments = tuple(
        CVariable(variable, variable_type=unsigned_word, codegen=codegen)
        for variable in variables
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=arguments,
        body=arguments,
        statements=arguments,
        functy=SimTypeFunction(
            [unsigned_word, unsigned_word],
            unsigned_word,
        ).with_arch(arch),
    )
    codegen._inertia_typed_conditions = (
        ConditionIR(
            "slt",
            IRValue(MemSpace.SS, name="bp", offset=4, size=2),
            IRValue(MemSpace.SS, name="bp", offset=6, size=2),
            src_insn=0x1010,
            block_addr=0x1000,
        ),
    )
    for variable, argument, bp_offset in zip(
        variables,
        arguments,
        (4, 6),
        strict=True,
    ):
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=argument,
            bp_offset=bp_offset,
            entry_sp_offset=variable.offset,
            size=variable.size,
        )

    result = apply_condition_argument_types_8616(project, codegen)

    assert result.changed
    assert result.changed_offsets == (4, 6)
    assert result.stats.materialized_count == 2
    assert [argument.signed for argument in codegen.cfunc.functy.args] == [True, True]
