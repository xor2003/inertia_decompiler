"""Regression coverage for CFG return-chain condition selection."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIfElse,
    CStatements,
    CUnaryOp,
)
from angr.sim_type import SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.structuring.return_chain_condition_selection import (
    ReturnChainConditionSelectionStats8616,
    ReturnChainConditionSelectionVerdict8616,
)
from inertia.structuring.return_chains import (
    ReturnChainProofCallbacks8616,
    ordered_conditional_return_pairs_from_cfg_8616,
)

JCC_ADDR = 0x1030C
BLOCK_ADDR = 0x10306
RETURN_ADDR = 0x10311
CALL_ADDR = 0x10303


class _Codegen:
    """Minimal dynamic angr codegen surface for return-chain pairing."""

    def __init__(self) -> None:
        self._index = 0
        self.cstyle_null_cmp = True
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc = SimpleNamespace(statements=None)

    def next_idx(self, _name: str) -> int:
        """Return a stable synthetic AST index."""
        self._index += 1
        return self._index

    def next_ident(self, name: str) -> str:
        """Return the requested synthetic identifier."""
        return name

    def next_node_idx(self) -> int:
        """Return a stable synthetic node index."""
        return self.next_idx("")


def _constant(codegen: _Codegen, value: int) -> CConstant:
    """Build one typed short constant."""
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _zero_test(codegen: _Codegen, op: str) -> CBinaryOp:
    """Build one explicit comparison with exact JCC ownership tags."""
    return CBinaryOp(
        op,
        _constant(codegen, 7),
        _constant(codegen, 0),
        codegen=codegen,
        tags={"ins_addr": JCC_ADDR, "vex_block_addr": BLOCK_ADDR},
    )


def _call_zero_test(codegen: _Codegen, op: str) -> CBinaryOp:
    """Build one call-result zero test with exact call and JCC ownership."""
    call = CFunctionCall("in_window_i16", None, [], codegen=codegen, tags={"ins_addr": CALL_ADDR})
    return CBinaryOp(
        op,
        call,
        _constant(codegen, 0),
        codegen=codegen,
        tags={"ins_addr": JCC_ADDR, "vex_block_addr": BLOCK_ADDR},
    )


def _iter_nodes(root: object) -> tuple[object, ...]:
    """Return the small owned AST surface needed by tagged lookup."""
    if isinstance(root, CStatements):
        children = tuple(root.statements or ())
        return (root, *tuple(node for child in children for node in _iter_nodes(child)))
    if isinstance(root, CIfElse):
        pairs = tuple(root.condition_and_nodes or ())
        return (
            root,
            *tuple(node for condition, _body in pairs for node in _iter_nodes(condition)),
            *tuple(node for _condition, body in pairs for node in _iter_nodes(body)),
        )
    if isinstance(root, CUnaryOp):
        return (root, *_iter_nodes(root.operand))
    if isinstance(root, CBinaryOp):
        return (root, *_iter_nodes(root.lhs), *_iter_nodes(root.rhs))
    if isinstance(root, CITE):
        return (
            root,
            *_iter_nodes(root.cond),
            *_iter_nodes(root.iftrue),
            *_iter_nodes(root.iffalse),
        )
    return (root,)


def _paired_condition(
    structured_op: str,
    decoded_op: str,
) -> tuple[object, _Codegen]:
    """Collect one CFG return pair from structured and decoded zero tests."""
    codegen = _Codegen()
    structured = _zero_test(codegen, structured_op)
    codegen.cfunc.statements = CStatements(
        [CIfElse([(structured, CStatements([], codegen=codegen))], codegen=codegen)],
        codegen=codegen,
    )
    jcc = SimpleNamespace(address=JCC_ADDR, target=RETURN_ADDR)
    callbacks = ReturnChainProofCallbacks8616(
        linear_jcc_block_starts=lambda _project, _codegen: ((BLOCK_ADDR, jcc),),
        branch_target_imm=lambda insn: insn.target,
        branch_target_return_value=lambda _project, target: 13 if target == RETURN_ADDR else None,
        decoded_condition_expr=lambda _project, _codegen, _decoded, _tags: _zero_test(codegen, decoded_op),
        translate_cmp_jcc_guard=lambda _project, _codegen, _block, _jcc: object(),
        last_call_addr_before_jcc=lambda _project, _codegen, _jcc: None,
        condition_tags=lambda condition: (
            condition.tags.get("ins_addr"),
            condition.tags.get("vex_block_addr"),
        ),
        iter_c_nodes_deep=_iter_nodes,
    )

    pairs = ordered_conditional_return_pairs_from_cfg_8616(object(), codegen, callbacks)

    assert len(pairs) == 1
    assert pairs[0][1] == 13
    return pairs[0][0], codegen


def test_cfg_return_pair_uses_decoded_jcc_when_zero_test_polarity_conflicts() -> None:
    """A taken JNE return target must not inherit a stale structured EQ test."""
    condition, codegen = _paired_condition("CmpEQ", "CmpNE")

    assert isinstance(condition, CBinaryOp)
    assert condition.op == "CmpNE"
    result = codegen._inertia_return_chain_condition_selection_result_8616
    assert result.verdict is ReturnChainConditionSelectionVerdict8616.DECODED_POLARITY_CONFLICT
    assert codegen._inertia_return_chain_condition_selection_stats_8616 == (
        ReturnChainConditionSelectionStats8616(1, 1, 1, 1, 0)
    )


def test_cfg_return_pair_preserves_structured_condition_when_polarity_matches() -> None:
    """Matching typed polarity keeps the richer exact-tagged structured node."""
    condition, codegen = _paired_condition("CmpNE", "CmpNE")

    assert isinstance(condition, CBinaryOp)
    assert condition.op == "CmpNE"
    result = codegen._inertia_return_chain_condition_selection_result_8616
    assert result.condition is condition
    assert result.verdict is ReturnChainConditionSelectionVerdict8616.STRUCTURED_POLARITY_MATCH


def test_cfg_return_pair_replaces_negated_call_with_decoded_jne_condition() -> None:
    """A structured ``!call`` must not invert a same-JCC taken return edge."""
    codegen = _Codegen()
    structured_call = CFunctionCall(
        "in_window_i16",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": CALL_ADDR},
    )
    structured = CUnaryOp(
        "Not",
        structured_call,
        codegen=codegen,
        tags={"ins_addr": JCC_ADDR, "vex_block_addr": BLOCK_ADDR},
    )
    codegen.cfunc.statements = CStatements(
        [CIfElse([(structured, CStatements([], codegen=codegen))], codegen=codegen)],
        codegen=codegen,
    )
    jcc = SimpleNamespace(address=JCC_ADDR, target=RETURN_ADDR)
    callbacks = ReturnChainProofCallbacks8616(
        linear_jcc_block_starts=lambda _project, _codegen: ((BLOCK_ADDR, jcc),),
        branch_target_imm=lambda insn: insn.target,
        branch_target_return_value=lambda _project, target: 13 if target == RETURN_ADDR else None,
        decoded_condition_expr=lambda _project, _codegen, _decoded, _tags: _call_zero_test(codegen, "CmpNE"),
        translate_cmp_jcc_guard=lambda _project, _codegen, _block, _jcc: object(),
        last_call_addr_before_jcc=lambda _project, _codegen, _jcc: CALL_ADDR,
        condition_tags=lambda condition: (
            condition.tags.get("ins_addr"),
            condition.tags.get("vex_block_addr"),
        ),
        iter_c_nodes_deep=_iter_nodes,
    )

    pairs = ordered_conditional_return_pairs_from_cfg_8616(object(), codegen, callbacks)

    assert len(pairs) == 1
    condition = pairs[0][0]
    assert isinstance(condition, CBinaryOp)
    assert condition.op == "CmpNE"
    result = codegen._inertia_return_chain_condition_selection_result_8616
    assert result.verdict is ReturnChainConditionSelectionVerdict8616.DECODED_POLARITY_CONFLICT


def test_cfg_return_pair_replaces_boolean_ite_call_with_decoded_jne_condition() -> None:
    """The production ``call ? 0 : 1`` form must retain the taken JNE edge."""
    codegen = _Codegen()
    structured_call = CFunctionCall(
        "in_window_i16",
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": CALL_ADDR},
    )
    structured = CITE(
        structured_call,
        _constant(codegen, 0),
        _constant(codegen, 1),
        codegen=codegen,
        tags={"ins_addr": JCC_ADDR, "vex_block_addr": BLOCK_ADDR},
    )
    codegen.cfunc.statements = CStatements(
        [CIfElse([(structured, CStatements([], codegen=codegen))], codegen=codegen)],
        codegen=codegen,
    )
    jcc = SimpleNamespace(address=JCC_ADDR, target=RETURN_ADDR)
    callbacks = ReturnChainProofCallbacks8616(
        linear_jcc_block_starts=lambda _project, _codegen: ((BLOCK_ADDR, jcc),),
        branch_target_imm=lambda insn: insn.target,
        branch_target_return_value=lambda _project, target: 13 if target == RETURN_ADDR else None,
        decoded_condition_expr=lambda _project, _codegen, _decoded, _tags: _call_zero_test(codegen, "CmpNE"),
        translate_cmp_jcc_guard=lambda _project, _codegen, _block, _jcc: object(),
        last_call_addr_before_jcc=lambda _project, _codegen, _jcc: CALL_ADDR,
        condition_tags=lambda condition: (
            condition.tags.get("ins_addr"),
            condition.tags.get("vex_block_addr"),
        ),
        iter_c_nodes_deep=_iter_nodes,
    )

    pairs = ordered_conditional_return_pairs_from_cfg_8616(object(), codegen, callbacks)

    assert len(pairs) == 1
    condition = pairs[0][0]
    assert isinstance(condition, CBinaryOp)
    assert condition.op == "CmpNE"
    result = codegen._inertia_return_chain_condition_selection_result_8616
    assert result.verdict is ReturnChainConditionSelectionVerdict8616.DECODED_POLARITY_CONFLICT
