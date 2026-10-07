from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CIfElse,
    CStatements,
)
from angr.sim_type import SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_ir import ConditionIR
import inertia.structuring.condition_materialization as condition_materialization


class _Codegen:
    def __init__(self) -> None:
        self._next_idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _tagged_body(block_addr: int, codegen: _Codegen) -> CStatements:
    body = CStatements([], codegen=codegen)
    body.tags = {"ins_addr": block_addr, "vex_block_addr": block_addr}
    return body


def test_cfg_arm_orientation_does_not_prune_call_output_carriers(monkeypatch) -> None:
    codegen = _Codegen()
    condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    condition.tags = {"ins_addr": 0x1002, "vex_block_addr": 0x1000}
    true_body = _tagged_body(0x1010, codegen)
    false_body = _tagged_body(0x1020, codegen)
    branch = CIfElse(
        [(condition, true_body)],
        else_node=false_body,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([branch], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root)
    codegen._inertia_typed_conditions = (
        ConditionIR(
            op="ne",
            lhs=0x1002,
            rhs=0,
            src_insn=0x1002,
            block_addr=0x1000,
            taken_target=0x1010,
            fallthrough_target=0x1020,
        ),
    )
    project = SimpleNamespace()
    replacement = CConstant(7, SimTypeShort(False), codegen=codegen)
    monkeypatch.setattr(
        condition_materialization,
        "condition_chain_successors_8616",
        lambda _project, _codegen: {
            0x1000: (0x1010, 0x1020),
            0x1010: (),
            0x1020: (),
        },
    )
    monkeypatch.setattr(
        condition_materialization,
        "materialize_condition_ir_expression_8616",
        lambda _project, _codegen, _fact: replacement,
    )

    def _unexpected_prune(_codegen: object) -> None:
        raise AssertionError("pure CFG arm orientation must not prune call outputs")

    monkeypatch.setattr(
        condition_materialization,
        "prune_materialized_call_output_stack_carriers_8616",
        _unexpected_prune,
    )

    assert condition_materialization.materialize_structuring_condition_chains_8616(project, codegen)
    assert branch.condition_and_nodes == [(replacement, true_body)]
    assert branch.else_node is false_body
