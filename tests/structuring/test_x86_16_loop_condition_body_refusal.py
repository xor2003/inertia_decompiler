"""Refusal tests for body-only typed loop-condition candidates."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CStatements,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace

from inertia.structuring.loop_condition_materialization import (
    materialize_typed_loop_continuation_conditions_8616,
)


class _Codegen:
    """Minimal structured-C codegen boundary."""

    def __init__(self) -> None:
        self._next_idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        """Return one deterministic structured-C index."""
        self._next_idx += 1
        return self._next_idx

    def next_node_idx(self) -> int:
        """Return one deterministic structured-C node index."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Return a deterministic identifier for the fixture."""
        return name


def test_body_only_condition_cannot_replace_constant_true_loop_header() -> None:
    """A body condition is not loop-header evidence without owned pretest proof."""
    codegen = _Codegen()
    value_type = SimTypeShort(False).with_arch(codegen.project.arch)
    key = (0x2006, 0x2000)
    current = CConstant(1, value_type, codegen=codegen)
    nested_body = CStatements([], codegen=codegen, tags={"vex_block_addr": 0x2100})
    body = CStatements(
        [nested_body],
        codegen=codegen,
        tags={"ins_addr": key[0], "vex_block_addr": key[1]},
    )
    loop = CWhileLoop(current, body, codegen=codegen)
    root = CStatements([loop], codegen=codegen)
    typed = ConditionIR(
        op="eq",
        lhs=IRValue(MemSpace.REG, name="ax", size=2),
        rhs=IRValue(MemSpace.CONST, const=69, size=2),
        src_insn=key[0],
        block_addr=key[1],
        taken_target=0x2100,
        fallthrough_target=0x2200,
    )

    stats = materialize_typed_loop_continuation_conditions_8616(
        root,
        codegen,
        (typed,),
        {0x2100: (0x2000,), 0x2200: ()},
        lambda _condition: CBinaryOp(
            "CmpEQ",
            CConstant(0, value_type, codegen=codegen),
            CConstant(69, value_type, codegen=codegen),
            codegen=codegen,
        ),
    )

    assert stats.changed is False
    assert stats.classified_fact_count == 0
    assert loop.condition is current
