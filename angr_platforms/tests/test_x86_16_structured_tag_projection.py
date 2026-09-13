"""Focused tests for the Structuring-owned subtree tag projection."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CIfElse,
    CStatements,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.structuring import condition_materialization
from angr_platforms.X86_16.structuring.tagged_subtree_projection import (
    StructuredSubtreeEntryTags8616,
    collect_structured_subtree_entry_tags_8616,
)


class _Codegen:
    """Minimal angr structured-codegen boundary for projection fixtures."""

    def __init__(self) -> None:
        self._next_idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        """Return a deterministic fixture node index."""
        self._next_idx += 1
        return self._next_idx

    def next_node_idx(self) -> int:
        """Return a deterministic fixture AST index."""
        return self.next_idx("")

    @staticmethod
    def next_ident(name: str) -> str:
        """Return the fixture's stable identifier."""
        return name


def _tagged_body(codegen: _Codegen, base: int) -> CStatements:
    """Build one body whose lowest instruction and block tags differ."""
    return CStatements(
        [
            CConstant(
                1,
                SimTypeShort(False),
                codegen=codegen,
                tags={"ins_addr": base + 0x12, "vex_block_addr": base + 0x10},
            ),
            CConstant(
                2,
                SimTypeShort(False),
                codegen=codegen,
                tags={"ins_addr": base + 0x08, "vex_block_addr": base},
            ),
        ],
        codegen=codegen,
    )


def test_structured_subtree_entry_tags_collect_both_projections_once() -> None:
    """One read-only walk must publish instruction and block entry tags."""
    codegen = _Codegen()

    lowest_block, lowest_instruction = 0x1000, 0x1008
    result = collect_structured_subtree_entry_tags_8616(_tagged_body(codegen, lowest_block))

    assert result.first_instruction_addr == lowest_instruction
    assert result.block_addrs == (0x1000, 0x1010)
    assert result.first_block_addr == lowest_block


def test_condition_arm_entry_follows_execution_order_not_address_order():
    codegen = _Codegen()
    body = _tagged_body(codegen, 0x1000)
    first_executed_block = 0x1010
    assert condition_materialization._first_tagged_cfg_target_8616(body) == first_executed_block


def test_condition_arm_entry_preserves_explicit_container_identity():
    codegen = _Codegen()
    body = _tagged_body(codegen, 0x1000)
    container_entry = 0x2000
    body.tags = {"vex_block_addr": container_entry}
    assert condition_materialization._first_tagged_cfg_target_8616(body) == container_entry


def test_condition_arm_entry_does_not_use_operand_origin():
    codegen = _Codegen()
    operand = CConstant(1, SimTypeShort(False), codegen=codegen,
                        tags={"ins_addr": 0x1000, "vex_block_addr": 0x1000})
    assignment = CAssignment(operand, operand, codegen=codegen)
    body = CStatements([assignment, *_tagged_body(codegen, 0x2000).statements], codegen=codegen)
    assert condition_materialization._first_tagged_cfg_target_8616(body) is None


def test_condition_surface_collects_each_branch_body_once(monkeypatch) -> None:
    """The condition token must not walk one body once per tag projection."""
    codegen = _Codegen()
    condition = CBinaryOp(
        "CmpEQ",
        CConstant(1, SimTypeShort(False), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    body = _tagged_body(codegen, 0x1000)
    else_body = _tagged_body(codegen, 0x2000)
    branch = CIfElse(
        [(condition, body)],
        else_node=else_body,
        cstyle_ifs=True,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([branch], codegen=codegen)
    )
    roots: list[object] = []
    original = collect_structured_subtree_entry_tags_8616

    def collect_once(root: object) -> StructuredSubtreeEntryTags8616:
        roots.append(root)
        return original(root)

    monkeypatch.setattr(
        condition_materialization,
        "collect_structured_subtree_entry_tags_8616",
        collect_once,
    )

    token = condition_materialization.structuring_condition_surface_token_8616(
        codegen
    )

    assert roots == [body, else_body]
    assert token[0][6:10] == (0x1000, 0x1008, 0x2000, 0x2008)
