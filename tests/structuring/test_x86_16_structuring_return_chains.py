from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CIfElse,
    CReturn,
    CStatements,
    CTypeCast,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallerReturnUseVerdict8616

from inertia.frontend.x86_16.frontend_function_instructions import (
    FunctionInstructionInventory8616,
    FunctionInstructionInventoryStatus8616,
)
from inertia.structuring.return_chains import (
    BranchTargetReturnBlockResult8616,
    BranchTargetReturnScanCallbacks8616,
    ComplexDecrementSwitchCallbacks8616,
    ConditionBranchTagCallbacks8616,
    ConditionBranchTagEvidence8616,
    ConditionIdentityCallbacks8616,
    DuplicateEmptyReturnGuardPruneReason8616,
    ExpressionFingerprintCallbacks8616,
    IdenticalAssignmentArmCollapseStatus8616,
    LastAxReturnValueCallbacks8616,
    MaskAccumulatorMaterializationCallbacks8616,
    MaskAccumulatorPairCallbacks8616,
    Return32BitConditionalPairCallbacks8616,
    ReturnChainCountCallbacks8616,
    ReturnChainEmptyIfCallbacks8616,
    ReturnChainFlattenCallbacks8616,
    ReturnChainProofCallbacks8616,
    ReturnConditionalExprPairCallbacks8616,
    ReturnConditionalVoidTailCallCallbacks8616,
    ReturnSelector32BitPairCallbacks8616,
    ReturnSelectorCallbacks8616,
    ReturnSelectorCallsiteProofCallbacks8616,
    SelectorStackExprCallbacks8616,
    SelectorUnsafeEffectsCallbacks8616,
    SequentialDecrementSwitchCallbacks8616,
    SurplusIfGuardKind8616,
    TerminalAxInstructionAction8616,
    TerminalAxReturnEffect8616,
    TerminalAxReturnEffectKind8616,
    TerminalAxScanCallbacks8616,
    TerminalCallResultContract8616,
    TerminalCallResultReturnCallbacks8616,
    TerminalCallResultReturnStatus8616,
    VoidTailCallGuardProof8616,
    VoidTailCallGuardStatus8616,
    VoidTailCallShapeCallbacks8616,
    VoidTailCallSuffixDiamondCallbacks8616,
    VoidTailCallSuffixDiamondStatus8616,
    branch_target_return_expr_8616,
    branch_target_return_value_8616,
    c_node_semantically_empty_8616,
    c_statement_shape_8616,
    call_argument_component_fingerprints_8616,
    call_argument_fingerprints_8616,
    calls_in_nodes_8616,
    collapse_surplus_identical_assignment_arms_8616,
    combine_dx_ax_return_expr_8616,
    condition_branch_return_value_8616,
    condition_branch_tag_evidence_8616,
    condition_has_jcc_evidence_8616,
    condition_identity_keys_8616,
    conditional_branch_count_8616,
    const_return_value_8616,
    duplicate_empty_return_guard_prune_plan_8616,
    else_node_empty_8616,
    ensure_return_chain_codegen_state_8616,
    equality_return_target_from_32bit_jcc_chain_8616,
    first_conditional_jcc_8616,
    flatten_conditional_return_chain_8616,
    flatten_straightline_c_statements_8616,
    inequality_target_from_32bit_jcc_chain_8616,
    is_conditional_branch_insn_8616,
    is_empty_return_statement_8616,
    last_ax_return_value_8616,
    last_call_addr_before_jcc_in_function_8616,
    linear_jcc_block_starts_8616,
    linear_terminal_ax_return_scan_8616,
    materialize_cfg_conditional_return_suffix_8616,
    materialize_cfg_mask_accumulator_8616,
    materialize_cfg_selector_return_branches_8616,
    materialize_complex_decrement_switch_return_chain_8616,
    materialize_empty_if_return_branches_8616,
    materialize_sequential_decrement_switch_return_chain_8616,
    materialize_terminal_call_result_return_8616,
    materialize_void_tail_call_guard_8616,
    materialize_void_tail_call_suffix_diamond_8616,
    next_unconditional_target_after_jcc_8616,
    node_component_fingerprints_8616,
    ordered_32bit_conditional_return_pairs_from_cfg_8616,
    ordered_32bit_mask_update_pairs_from_cfg_8616,
    ordered_32bit_selector_return_expr_pairs_from_cfg_8616,
    ordered_conditional_return_expr_pairs_from_cfg_8616,
    ordered_conditional_return_pairs_from_cfg_8616,
    ordered_conditional_return_values_8616,
    ordered_conditional_void_tail_call_proofs_from_cfg_8616,
    resolve_one_hop_jmp_target_8616,
    return_chain_counts_8616,
    return_chain_expected_counts_8616,
    return_epilogue_block_8616,
    scan_branch_target_return_block_8616,
    selector_condition_call_addrs_8616,
    selector_condition_call_addrs_from_cfg_8616,
    selector_function_has_unsafe_effects_8616,
    selector_stack_expr_from_ax_load_8616,
    selector_targets_from_32bit_jcc_chain_8616,
    single_if_return_8616,
    surplus_empty_guard_condition_8616,
    tail_call_from_statement_8616,
    tail_call_payload_from_statement_8616,
    terminal_ax_fallback_supports_widths_8616,
    terminal_value_block_addrs_8616,
)


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())
        self._inertia_cfg_selector_return_stats_8616 = {"candidates": 0, "materialized": 0, "refused": 0}
        self._inertia_return_selector_materialized_8616 = False
        self._inertia_return_chain_flattened_8616 = False
        self._inertia_return_chain_suffix_materialized_8616 = False
        self._inertia_return_chain_materialized_values_8616 = ()
        self._inertia_return_chain_materialized_condition_fingerprints_8616 = ()
        self._inertia_return_chain_final_value_8616 = 0
        self._inertia_empty_return_branch_stats_8616 = {"candidates": 0, "materialized": 0, "refused": 0}
        self._inertia_empty_return_branch_refused_unsafe_effects_8616 = 0
        self._inertia_empty_return_branch_values_8616 = ()
        self._inertia_return_expr_chain_materialized_8616 = False
        self._inertia_return_expr_chain_materialized_return_fingerprints_8616 = ()
        self._inertia_mask_accumulator_materialized_8616 = False
        self._inertia_mask_accumulator_condition_fingerprints_8616 = ()
        self._inertia_mask_accumulator_return_fingerprint_8616 = ""
        self._inertia_mask_accumulator_update_immediates_8616 = ()
        self._inertia_decrement_switch_return_materialized_8616 = False
        self._inertia_sequential_decrement_switch_return_materialized_8616 = False
        self._inertia_return_selector_raw_stack_slot_aliases_8616 = {}

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_ident(self, name: str) -> str:
        return name

    def next_node_idx(self) -> int:
        return self.next_idx("")


def test_return_chain_codegen_state_initializes_dynamic_codegen_fields():
    codegen = SimpleNamespace()

    ensure_return_chain_codegen_state_8616(codegen)

    assert codegen._inertia_return_selector_materialized_8616 is False
    assert codegen._inertia_cfg_selector_return_stats_8616 == {"candidates": 0, "materialized": 0, "refused": 0}
    assert codegen._inertia_empty_return_branch_stats_8616 == {"candidates": 0, "materialized": 0, "refused": 0}
    assert codegen._inertia_return_chain_materialized_values_8616 == ()
    assert codegen._inertia_mask_accumulator_update_immediates_8616 == ()
    assert codegen._inertia_return_selector_raw_stack_slot_aliases_8616 == {}


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _if_return(cond_value: int, return_value: int, codegen):
    body = CStatements(
        statements=[CReturn(_const(return_value, codegen), codegen=codegen)],
        codegen=codegen,
    )
    return CIfElse([(_const(cond_value, codegen), body)], else_node=None, cstyle_ifs=True, codegen=codegen)


def _if_empty_return(cond_value: int, codegen):
    body = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    return CIfElse([(_const(cond_value, codegen), body)], else_node=None, cstyle_ifs=True, codegen=codegen)


def _iter_nodes(node):
    yield node
    for child in tuple(getattr(node, "statements", ()) or ()):
        yield from _iter_nodes(child)
    for cond, body in tuple(getattr(node, "condition_and_nodes", ()) or ()):
        yield cond
        yield from _iter_nodes(body)
    else_node = getattr(node, "else_node", None)
    if else_node is not None:
        yield from _iter_nodes(else_node)
    retval = getattr(node, "retval", None)
    if retval is not None:
        yield retval
    expr = getattr(node, "expr", None)
    if expr is not None:
        yield expr


def _single_if_return(stmt):
    cond_nodes = getattr(stmt, "condition_and_nodes", ()) or ()
    if len(cond_nodes) != 1:
        return None
    cond, body = cond_nodes[0]
    body_statements = tuple(getattr(body, "statements", ()) or ())
    if len(body_statements) != 1 or not isinstance(body_statements[0], CReturn):
        return None
    return cond, getattr(body_statements[0], "retval", None)


def _const_return_value(expr) -> int | None:
    if isinstance(expr, CConstant):
        return int(expr.value)
    return None


class _Insn:
    def __init__(self, mnemonic: str, operands=()):
        self.mnemonic = mnemonic
        self.operands = tuple(operands)

    def reg_name(self, reg: int) -> str:
        return {1: "ax", 2: "dx", 3: "sp", 4: "bp", 5: "al", 6: "cl", 7: "cx"}.get(reg, "")


def _reg_operand(reg: int):
    return SimpleNamespace(type=1, reg=reg)


def _imm_operand(value: int):
    return SimpleNamespace(type=2, imm=value)


def _mem_operand(base: int, disp: int, size: int = 2):
    return SimpleNamespace(type=3, mem=SimpleNamespace(base=base, disp=disp), size=size)


def _target_insn(mnemonic: str, target: int):
    return SimpleNamespace(mnemonic=mnemonic, operands=(), target=target)


def _block(*insns):
    return SimpleNamespace(capstone=SimpleNamespace(insns=tuple(insns)))


def _insn_at(address: int, insn):
    insn.address = address
    return insn


def _terminal_call_callbacks(
    blocks,
    block_ranges,
    successors,
    call_result_contract=lambda _call: TerminalCallResultContract8616.VALUE,
) -> TerminalCallResultReturnCallbacks8616:
    return TerminalCallResultReturnCallbacks8616(
        iter_c_nodes_deep=_iter_nodes,
        function_block_ranges=lambda: block_ranges,
        load_block=lambda addr, _size: blocks.get(addr),
        successor_addrs=lambda addr: successors.get(addr, ()),
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        call_result_contract=call_result_contract,
    )


def _callbacks(final_value: int) -> ReturnChainFlattenCallbacks8616:
    return ReturnChainFlattenCallbacks8616(
        set_cfunc_statements_root=_set_cfunc_statements_root,
        final_return_value=lambda _project, _codegen: final_value,
        expr_fingerprint=lambda expr, _project: f"const:{expr.value}" if isinstance(expr, CConstant) else repr(expr),
        iter_c_nodes_deep=_iter_nodes,
        single_if_return=_single_if_return,
        const_return_value=_const_return_value,
    )


def _set_cfunc_statements_root(codegen, root):
    codegen.cfunc.statements = root
    codegen.cfunc.body = root


def _count_callbacks() -> ReturnChainCountCallbacks8616:
    return ReturnChainCountCallbacks8616(iter_c_nodes_deep=_iter_nodes)


def _tail_shape_callbacks() -> VoidTailCallShapeCallbacks8616:
    return VoidTailCallShapeCallbacks8616(
        c_node_semantically_empty=lambda node: c_node_semantically_empty_8616(node, _callbacks(0))
    )


def _suffix_diamond_callbacks(
    true_nodes: set[int],
    false_nodes: set[int] | None = None,
) -> VoidTailCallSuffixDiamondCallbacks8616:
    false_node_ids = set(false_nodes or set())

    def _node_fingerprints(node):
        fingerprints = set()
        if id(node) in true_nodes or id(node) in false_node_ids:
            fingerprints.add("true-call")
        for child in _iter_nodes(node):
            if id(child) in true_nodes or id(child) in false_node_ids:
                fingerprints.add("true-call")
        return frozenset(fingerprints)

    return VoidTailCallSuffixDiamondCallbacks8616(
        c_node_semantically_empty=lambda node: c_node_semantically_empty_8616(node, _callbacks(0)),
        calls_in_nodes=lambda nodes: calls_in_nodes_8616(nodes, _callbacks(0)),
        node_component_fingerprints=_node_fingerprints,
        call_argument_component_fingerprints=lambda _call: frozenset(),
    )


def _empty_if_callbacks(
    *,
    ordered_values: list[int] | None = None,
    cfg_pairs: list[tuple[CConstant, int]] | None = None,
    unsafe_effects: bool = False,
    flattened: list[list[tuple[CConstant, int]]] | None = None,
) -> ReturnChainEmptyIfCallbacks8616:
    def _flatten(_project, _codegen, pairs):
        if flattened is not None:
            flattened.append(list(pairs))
        return True

    return ReturnChainEmptyIfCallbacks8616(
        ordered_return_values=lambda _project, _codegen: list(ordered_values or []),
        selector_function_has_unsafe_effects=lambda _project, _codegen, allowed: unsafe_effects and not allowed,
        condition_call_addrs=lambda conditions: frozenset(
            int(condition.tags["condition_call_ins_addr"])
            for condition in conditions
            if isinstance(condition.tags.get("condition_call_ins_addr"), int)
        ),
        condition_branch_return_value=lambda _project, _cond: None,
        condition_branch_is_non_branch=lambda _project, _cond: False,
        condition_tags=lambda cond: getattr(cond, "condition_key", None),
        ordered_return_expr_pairs=lambda _project, _codegen: [],
        ordered_return_pairs=lambda _project, _codegen: list(cfg_pairs or []),
        ordered_32bit_return_pairs=lambda _project, _codegen: [],
        flatten_conditional_return_chain=_flatten,
        materialize_conditional_return_suffix=lambda _project, _codegen, _pairs: False,
        prune_duplicate_empty_return_guard=lambda _project, _codegen: False,
        expr_fingerprint=lambda expr, _project: f"const:{expr.value}" if isinstance(expr, CConstant) else repr(expr),
        iter_c_nodes_deep=_iter_nodes,
    )


def test_return_chain_counts_accounts_structured_if_and_return_nodes():
    codegen = _DummyCodegen()
    root = CStatements(
        statements=[
            _if_return(1, 10, codegen),
            CReturn(_const(20, codegen), codegen=codegen),
        ],
        codegen=codegen,
    )

    assert return_chain_counts_8616(root, _count_callbacks()) == (1, 2)


def test_return_chain_counts_handles_missing_root():
    assert return_chain_counts_8616(None, _count_callbacks()) == (0, 0)


def test_return_chain_expected_counts_requires_materialized_values():
    codegen = SimpleNamespace(
        _inertia_return_chain_flattened_8616=True,
        _inertia_return_chain_suffix_materialized_8616=False,
        _inertia_return_chain_materialized_values_8616=(1, 2, 3),
    )

    assert return_chain_expected_counts_8616(codegen) == (3, 4)


def test_return_chain_expected_counts_refuses_unmaterialized_metadata():
    codegen = SimpleNamespace(
        _inertia_return_chain_flattened_8616=False,
        _inertia_return_chain_suffix_materialized_8616=False,
        _inertia_return_chain_materialized_values_8616=(1,),
    )

    assert return_chain_expected_counts_8616(codegen) is None


def test_condition_identity_keys_collects_jcc_tags_and_expression_fingerprint():
    cond = SimpleNamespace(label="cond")
    project = SimpleNamespace(name="project")
    callbacks = ConditionIdentityCallbacks8616(
        condition_tags=lambda value: (0x1234, 0x1236) if value is cond else None,
        expr_fingerprint=lambda value, owner: f"{owner.name}:{value.label}",
    )

    assert condition_identity_keys_8616(project, cond, callbacks) == frozenset(
        {("tags", (0x1234, 0x1236)), ("fp", "project:cond")}
    )


def test_condition_identity_keys_ignores_invalid_tags_but_keeps_fingerprint():
    cond = SimpleNamespace(label="cond")
    callbacks = ConditionIdentityCallbacks8616(
        condition_tags=lambda _value: ("not", "ints"),
        expr_fingerprint=lambda value, _project: value.label,
    )

    assert condition_identity_keys_8616(object(), cond, callbacks) == frozenset({("fp", "cond")})


def test_condition_identity_keys_refuses_callback_failures_as_empty_identity():
    def _raise(_value):
        raise RuntimeError("missing dynamic metadata")

    callbacks = ConditionIdentityCallbacks8616(
        condition_tags=_raise,
        expr_fingerprint=lambda _value, _project: (_ for _ in ()).throw(RuntimeError("missing fingerprint")),
    )

    assert condition_identity_keys_8616(object(), object(), callbacks) == frozenset()


def test_condition_branch_tag_evidence_accepts_real_conditional_branch():
    cond = SimpleNamespace()
    branch = SimpleNamespace(mnemonic="jne")
    callbacks = ConditionBranchTagCallbacks8616(
        condition_tags=lambda _cond: (0x1200, 0x1202),
        load_block=lambda _addr: _block(branch),
        is_conditional_branch_insn=is_conditional_branch_insn_8616,
    )

    assert condition_branch_tag_evidence_8616(cond, callbacks) is ConditionBranchTagEvidence8616.CONDITIONAL_BRANCH
    assert condition_has_jcc_evidence_8616(cond, callbacks)


def test_condition_branch_tag_evidence_refuses_non_branch_tag():
    cond = SimpleNamespace()
    callbacks = ConditionBranchTagCallbacks8616(
        condition_tags=lambda _cond: (0x1200, 0x1202),
        load_block=lambda _addr: _block(SimpleNamespace(mnemonic="mov")),
        is_conditional_branch_insn=is_conditional_branch_insn_8616,
    )

    assert condition_branch_tag_evidence_8616(cond, callbacks) is ConditionBranchTagEvidence8616.NON_BRANCH
    assert not condition_has_jcc_evidence_8616(cond, callbacks)


def test_condition_branch_tag_evidence_distinguishes_missing_tag_from_unknown_block():
    missing_tag = ConditionBranchTagCallbacks8616(
        condition_tags=lambda _cond: None,
        load_block=lambda _addr: _block(SimpleNamespace(mnemonic="jne")),
        is_conditional_branch_insn=is_conditional_branch_insn_8616,
    )
    missing_block = ConditionBranchTagCallbacks8616(
        condition_tags=lambda _cond: (0x1200, 0x1202),
        load_block=lambda _addr: None,
        is_conditional_branch_insn=is_conditional_branch_insn_8616,
    )

    assert condition_branch_tag_evidence_8616(object(), missing_tag) is ConditionBranchTagEvidence8616.NO_TAG
    assert condition_branch_tag_evidence_8616(object(), missing_block) is ConditionBranchTagEvidence8616.UNKNOWN
    assert condition_has_jcc_evidence_8616(object(), missing_block)


def test_call_argument_fingerprints_collects_direct_argument_fingerprints():
    codegen = _DummyCodegen()
    first = _const(1, codegen)
    second = _const(2, codegen)
    call = CFunctionCall("tail", None, [first, second], codegen=codegen)
    callbacks = ExpressionFingerprintCallbacks8616(
        expr_fingerprint=lambda value, _project: f"const:{value.value}",
        iter_c_nodes_deep=lambda _node: (),
    )

    assert call_argument_fingerprints_8616(object(), call, callbacks) == frozenset({"const:1", "const:2"})


def test_call_argument_component_fingerprints_collects_nested_argument_components():
    codegen = _DummyCodegen()
    nested = _const(7, codegen)
    wrapper = CStatements(statements=[CReturn(nested, codegen=codegen)], codegen=codegen)
    call = CFunctionCall("tail", None, [wrapper], codegen=codegen)
    callbacks = ExpressionFingerprintCallbacks8616(
        expr_fingerprint=lambda value, _project: type(value).__name__
        if not isinstance(value, CConstant)
        else f"const:{value.value}",
        iter_c_nodes_deep=_iter_nodes,
    )

    assert call_argument_component_fingerprints_8616(object(), call, callbacks) == frozenset(
        {"CStatements", "CReturn", "const:7"}
    )


def test_node_component_fingerprints_collects_node_and_nested_components():
    codegen = _DummyCodegen()
    retval = _const(3, codegen)
    node = CStatements(statements=[CReturn(retval, codegen=codegen)], codegen=codegen)
    callbacks = ExpressionFingerprintCallbacks8616(
        expr_fingerprint=lambda value, _project: type(value).__name__
        if not isinstance(value, CConstant)
        else f"const:{value.value}",
        iter_c_nodes_deep=_iter_nodes,
    )

    assert node_component_fingerprints_8616(object(), node, callbacks) == frozenset(
        {"CStatements", "CReturn", "const:3"}
    )


def test_component_fingerprints_ignore_dynamic_callback_failures():
    def _fingerprint(value, _project):
        if isinstance(value, CConstant):
            raise RuntimeError("missing fingerprint")
        return type(value).__name__

    codegen = _DummyCodegen()
    node = CStatements(statements=[CReturn(_const(9, codegen), codegen=codegen)], codegen=codegen)
    callbacks = ExpressionFingerprintCallbacks8616(
        expr_fingerprint=_fingerprint,
        iter_c_nodes_deep=_iter_nodes,
    )

    assert node_component_fingerprints_8616(object(), node, callbacks) == frozenset({"CStatements", "CReturn"})


def test_tail_call_from_statement_accepts_returned_call():
    codegen = _DummyCodegen()
    call = CFunctionCall("sink", None, [], codegen=codegen)
    stmt = CReturn(call, codegen=codegen)

    assert tail_call_from_statement_8616(stmt, _tail_shape_callbacks()) is call


def test_flatten_straightline_c_statements_skips_empty_statement_wrappers():
    codegen = _DummyCodegen()
    call_stmt = CExpressionStatement(CFunctionCall("sink", None, [], codegen=codegen), codegen=codegen)
    root = CStatements(
        statements=[
            CStatements(statements=[], codegen=codegen),
            call_stmt,
            CReturn(None, codegen=codegen),
        ],
        codegen=codegen,
    )

    assert flatten_straightline_c_statements_8616(root, _tail_shape_callbacks()) == (
        call_stmt,
        root.statements[2],
    )


def test_flatten_straightline_c_statements_refuses_control_flow():
    codegen = _DummyCodegen()
    stmt = _if_return(1, 2, codegen)

    assert flatten_straightline_c_statements_8616(stmt, _tail_shape_callbacks()) is None


def test_tail_call_payload_from_statement_extracts_single_call_payload():
    codegen = _DummyCodegen()
    call_stmt = CExpressionStatement(CFunctionCall("sink", None, [], codegen=codegen), codegen=codegen)
    stmt = CStatements(statements=[call_stmt, CReturn(None, codegen=codegen)], codegen=codegen)

    result = tail_call_payload_from_statement_8616(stmt, codegen, _tail_shape_callbacks())

    assert result is not None
    call, payload = result
    assert call is call_stmt.expr
    assert isinstance(payload, CStatements)
    assert tuple(payload.statements) == tuple(stmt.statements)


def test_tail_call_payload_from_returned_call_builds_expression_statement():
    codegen = _DummyCodegen()
    call = CFunctionCall("sink", None, [], codegen=codegen)

    result = tail_call_payload_from_statement_8616(
        CReturn(call, codegen=codegen),
        codegen,
        _tail_shape_callbacks(),
    )

    assert result is not None
    recovered_call, payload = result
    assert recovered_call is call
    assert isinstance(payload, CExpressionStatement)
    assert payload.expr is call


def test_tail_call_payload_from_wrapped_returned_call_builds_expression_statement():
    codegen = _DummyCodegen()
    call = CFunctionCall("sink", None, [], codegen=codegen)
    wrapper = CStatements(
        statements=[CReturn(call, codegen=codegen)],
        codegen=codegen,
    )

    result = tail_call_payload_from_statement_8616(
        wrapper,
        codegen,
        _tail_shape_callbacks(),
    )

    assert result is not None
    recovered_call, payload = result
    assert recovered_call is call
    assert isinstance(payload, CExpressionStatement)
    assert payload.expr is call


def test_else_node_empty_accepts_absent_and_empty_statement_nodes():
    codegen = _DummyCodegen()

    assert else_node_empty_8616(None)
    assert else_node_empty_8616(CStatements(statements=[], codegen=codegen))


def test_else_node_empty_refuses_nonempty_statement_nodes():
    codegen = _DummyCodegen()
    node = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)

    assert not else_node_empty_8616(node)


def test_c_statement_shape_reports_bounded_statement_structure():
    codegen = _DummyCodegen()
    stmt = CStatements(statements=[_if_return(1, 2, codegen)], codegen=codegen)

    assert c_statement_shape_8616(stmt) == (
        "CStatements",
        (("CIfElse", (("CStatements", ("CReturn",)),), "NoneType"),),
    )


def test_c_statement_shape_respects_max_depth():
    codegen = _DummyCodegen()
    stmt = CStatements(statements=[_if_return(1, 2, codegen)], codegen=codegen)

    assert c_statement_shape_8616(stmt, max_depth=1) == ("CStatements", ("CIfElse",))


def test_calls_in_nodes_collects_direct_and_nested_calls():
    codegen = _DummyCodegen()
    direct_call = CFunctionCall("direct", None, [], codegen=codegen)
    nested_call = CFunctionCall("nested", None, [], codegen=codegen)
    nested_stmt = CExpressionStatement(nested_call, codegen=codegen)
    root = CStatements(statements=[nested_stmt], codegen=codegen)

    assert calls_in_nodes_8616((direct_call, root), _callbacks(0)) == (direct_call, nested_call)


def test_calls_in_nodes_returns_empty_tuple_when_no_calls_exist():
    codegen = _DummyCodegen()
    root = CStatements(statements=[CReturn(_const(7, codegen), codegen=codegen)], codegen=codegen)

    assert calls_in_nodes_8616((root,), _callbacks(0)) == ()


def test_materialize_void_tail_call_guard_moves_following_tail_into_true_body():
    codegen = _DummyCodegen()
    stale_cond = _const(0, codegen)
    proven_cond = _const(1, codegen)
    empty_return = CReturn(None, codegen=codegen)
    empty_body = CStatements(statements=[empty_return], codegen=codegen)
    tail_call = CFunctionCall("tail", None, [], codegen=codegen)
    tail_stmt = CExpressionStatement(tail_call, codegen=codegen)
    stmt = CIfElse([(stale_cond, empty_body)], else_node=None, cstyle_ifs=True, codegen=codegen)
    statements = [stmt, tail_stmt]

    result = materialize_void_tail_call_guard_8616(
        stmt=stmt,
        statements=statements,
        index=0,
        proof=VoidTailCallGuardProof8616(
            condition=proven_cond,
            condition_keys=frozenset({("fp", "CmpNE(arg,0)")}),
            true_fingerprint="const:97",
        ),
        tail_from_else=False,
        tail_payload=(tail_call, tail_stmt),
        codegen=codegen,
    )

    assert result.status is VoidTailCallGuardStatus8616.MATERIALIZED
    assert result.removed_following_tail is True
    assert statements == [stmt]
    assert stmt.else_node is None
    materialized_cond, true_body = stmt.condition_and_nodes[0]
    assert materialized_cond is proven_cond
    assert isinstance(true_body, CStatements)
    assert tuple(true_body.statements) == (tail_stmt,)


def test_materialize_void_tail_call_guard_uses_existing_else_tail_payload():
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    empty_body = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    tail_call = CFunctionCall("tail", None, [], codegen=codegen)
    else_node = CStatements(
        statements=[CExpressionStatement(tail_call, codegen=codegen)],
        codegen=codegen,
    )
    stmt = CIfElse([(cond, empty_body)], else_node=else_node, cstyle_ifs=True, codegen=codegen)
    statements = [stmt]

    result = materialize_void_tail_call_guard_8616(
        stmt=stmt,
        statements=statements,
        index=0,
        proof=VoidTailCallGuardProof8616(
            condition=cond,
            condition_keys=frozenset({("tag", 1)}),
            true_fingerprint="tail",
        ),
        tail_from_else=True,
        tail_payload=(tail_call, else_node),
        codegen=codegen,
    )

    assert result.status is VoidTailCallGuardStatus8616.MATERIALIZED
    assert result.removed_following_tail is False
    assert statements == [stmt]
    assert stmt.else_node is None
    assert stmt.condition_and_nodes[0][1] is else_node


def test_materialize_void_tail_call_guard_refuses_missing_following_tail_without_mutation():
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    empty_body = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    tail_call = CFunctionCall("tail", None, [], codegen=codegen)
    tail_stmt = CExpressionStatement(tail_call, codegen=codegen)
    stmt = CIfElse([(cond, empty_body)], else_node=None, cstyle_ifs=True, codegen=codegen)
    statements = [stmt]

    result = materialize_void_tail_call_guard_8616(
        stmt=stmt,
        statements=statements,
        index=0,
        proof=VoidTailCallGuardProof8616(
            condition=cond,
            condition_keys=frozenset({("tag", 1)}),
            true_fingerprint="tail",
        ),
        tail_from_else=False,
        tail_payload=(tail_call, tail_stmt),
        codegen=codegen,
    )

    assert result.status is VoidTailCallGuardStatus8616.MISSING_FOLLOWING_TAIL
    assert statements == [stmt]
    assert stmt.else_node is None
    assert stmt.condition_and_nodes[0][1] is empty_body


def test_materialize_void_tail_call_suffix_diamond_rebuilds_if_else_shape():
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    false_body = CStatements(statements=[CReturn(_const(0, codegen), codegen=codegen)], codegen=codegen)
    suffix_call = CFunctionCall("tail", None, [], codegen=codegen)
    suffix_stmt = CExpressionStatement(suffix_call, codegen=codegen)
    stmt = CIfElse([(cond, false_body)], else_node=None, cstyle_ifs=True, codegen=codegen)
    statements = [stmt, suffix_stmt]

    result = materialize_void_tail_call_suffix_diamond_8616(
        stmt=stmt,
        statements=statements,
        index=0,
        cond=cond,
        false_body=false_body,
        cond_keys=frozenset({("tag", 1)}),
        proofs=[(frozenset({("tag", 1)}), "true-call")],
        codegen=codegen,
        callbacks=_suffix_diamond_callbacks({id(suffix_call)}),
    )

    assert result.status is VoidTailCallSuffixDiamondStatus8616.MATERIALIZED
    assert result.match_fingerprint == "true-call"
    assert statements == [stmt]
    assert stmt.else_node is false_body
    true_body = stmt.condition_and_nodes[0][1]
    assert isinstance(true_body, CStatements)
    assert tuple(true_body.statements) == (suffix_stmt,)


def test_materialize_void_tail_call_suffix_diamond_refuses_false_arm_match():
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    false_return = CReturn(_const(0, codegen), codegen=codegen)
    false_body = CStatements(statements=[false_return], codegen=codegen)
    suffix_call = CFunctionCall("tail", None, [], codegen=codegen)
    suffix_stmt = CExpressionStatement(suffix_call, codegen=codegen)
    stmt = CIfElse([(cond, false_body)], else_node=None, cstyle_ifs=True, codegen=codegen)
    statements = [stmt, suffix_stmt]

    result = materialize_void_tail_call_suffix_diamond_8616(
        stmt=stmt,
        statements=statements,
        index=0,
        cond=cond,
        false_body=false_body,
        cond_keys=frozenset({("tag", 1)}),
        proofs=[(frozenset({("tag", 1)}), "true-call")],
        codegen=codegen,
        callbacks=_suffix_diamond_callbacks({id(suffix_call)}, {id(false_return)}),
    )

    assert result.status is VoidTailCallSuffixDiamondStatus8616.FALSE_ARM_MATCHES_TRUE
    assert statements == [stmt, suffix_stmt]
    assert stmt.else_node is None


def _selector_callbacks(
    *,
    pairs: list[tuple[CConstant, CConstant, CConstant]] | None = None,
    unsafe_effects: bool = False,
    decrement_materialized: bool = False,
    allowed_from_cfg: set[int] | None = None,
) -> ReturnSelectorCallbacks8616:
    return ReturnSelectorCallbacks8616(
        materialize_decrement_switch_return_chain=lambda _project, _codegen: decrement_materialized,
        ordered_32bit_selector_return_expr_pairs=lambda _project, _codegen: [],
        ordered_conditional_return_expr_pairs=lambda _project, _codegen: list(pairs or []),
        selector_condition_call_addrs=lambda _pairs: {0x1234} if _pairs else set(),
        selector_condition_call_addrs_from_cfg=lambda _project, _codegen: set(allowed_from_cfg or set()),
        selector_function_has_unsafe_effects=lambda _project, _codegen, _allowed: unsafe_effects,
        clone_c_value_for_codegen_tree=lambda expr: expr,
        set_cfunc_statements_root=_set_cfunc_statements_root,
        expr_fingerprint=lambda expr, _project: f"const:{expr.value}" if isinstance(expr, CConstant) else repr(expr),
    )


def _proof_callbacks(jcc_entries, return_values, call_addrs=None) -> ReturnChainProofCallbacks8616:
    def _decoded_condition(_project, codegen, decoded, tags):
        expr = _const(int(decoded), codegen)
        expr.tags = dict(tags or {})
        return expr

    def _condition_key(cond):
        key = getattr(cond, "condition_key", None)
        if key is not None:
            return key
        tags = getattr(cond, "tags", None)
        if isinstance(tags, dict):
            return tags.get("ins_addr"), tags.get("vex_block_addr")
        return None

    return ReturnChainProofCallbacks8616(
        linear_jcc_block_starts=lambda _project, _codegen: tuple(jcc_entries),
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        branch_target_return_value=lambda _project, target: return_values.get(int(target)),
        decoded_condition_expr=_decoded_condition,
        translate_cmp_jcc_guard=lambda _project, _codegen, _block_addr, jcc_addr: jcc_addr,
        last_call_addr_before_jcc=lambda _project, _codegen, jcc_addr: (call_addrs or {}).get(jcc_addr),
        condition_tags=_condition_key,
        iter_c_nodes_deep=_iter_nodes,
    )


def _next_target_after_jcc(block, _block_addr: int, jcc_addr: int) -> int | None:
    return next_unconditional_target_after_jcc_8616(
        block,
        jcc_addr,
        lambda _addr: None,
        lambda insn: getattr(insn, "target", None),
    )


def test_structuring_return_chain_flattening_rebuilds_cfg_proven_chain():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    stale_root = CStatements(statements=[], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=stale_root, body=stale_root)
    cond_one = _const(1, codegen)
    cond_two = _const(2, codegen)

    changed = flatten_conditional_return_chain_8616(
        project,
        codegen,
        [(cond_one, 7), (cond_two, 9)],
        _callbacks(11),
    )

    statements = tuple(codegen.cfunc.statements.statements)
    assert changed is True
    assert codegen.cfunc.statements is codegen.cfunc.body
    assert len(statements) == 3
    assert all(isinstance(stmt, CIfElse) for stmt in statements[:2])
    assert isinstance(statements[-1], CReturn)
    assert codegen._inertia_return_chain_flattened_8616 is True
    assert codegen._inertia_return_chain_materialized_values_8616 == (7, 9)
    assert codegen._inertia_return_chain_final_value_8616 == 11


def test_structuring_return_chain_orders_cfg_proven_pairs_and_values():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    structured_first = _const(0x55, codegen)
    structured_first.tags = {"ins_addr": 0x1010, "vex_block_addr": 0x1000}
    branch = CIfElse([(structured_first, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([branch], codegen=codegen))
    first_jcc = SimpleNamespace(address=0x1010, target=0x1200)
    second_jcc = SimpleNamespace(address=0x1020, target=0x1220)
    callbacks = _proof_callbacks(
        ((0x1000, first_jcc), (0x1018, second_jcc)),
        {0x1200: 7, 0x1220: 9},
    )

    pairs = ordered_conditional_return_pairs_from_cfg_8616(project, codegen, callbacks)
    values = ordered_conditional_return_values_8616(project, codegen, callbacks)

    assert values == [7, 9]
    assert [(pair[0].value, pair[1]) for pair in pairs] == [(0x55, 7), (0x1020, 9)]
    assert [pair[0].tags for pair in pairs] == [
        {"ins_addr": 0x1010, "vex_block_addr": 0x1000},
        {"ins_addr": 0x1020, "vex_block_addr": 0x1018},
    ]


def test_structuring_orders_conditional_return_expr_pairs_with_tags_and_callsite():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    jcc = SimpleNamespace(address=0x1010, target=0x1200)
    cond = _const(1, codegen)
    true_expr = _const(7, codegen)
    false_expr = _const(9, codegen)
    callbacks = ReturnConditionalExprPairCallbacks8616(
        linear_jcc_block_starts=lambda _project, _codegen: ((0x1000, jcc),),
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        next_unconditional_target_after_jcc=lambda _project, _block_addr, _jcc_addr: 0x1220,
        branch_target_return_expr=lambda _project, _codegen, target: {0x1200: true_expr, 0x1220: false_expr}.get(target),
        translate_cmp_jcc_guard=lambda _project, _codegen, block_addr, jcc_addr: (block_addr, jcc_addr),
        decoded_condition_expr=lambda _project, _codegen, decoded, tags: cond
        if decoded == (0x1000, 0x1010) and tags == {"ins_addr": 0x1010, "vex_block_addr": 0x1000}
        else None,
        last_call_addr_before_jcc_in_function=lambda _project, _codegen, _jcc_addr: 0x100C,
    )

    pairs = ordered_conditional_return_expr_pairs_from_cfg_8616(project, codegen, callbacks)

    assert pairs == [(cond, true_expr, false_expr)]
    assert cond.tags == {"condition_call_ins_addr": 0x100C}


def test_structuring_orders_conditional_return_expr_pairs_refuses_missing_false_target():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    jcc = SimpleNamespace(address=0x1010, target=0x1200)
    callbacks = ReturnConditionalExprPairCallbacks8616(
        linear_jcc_block_starts=lambda _project, _codegen: ((0x1000, jcc),),
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        next_unconditional_target_after_jcc=lambda _project, _block_addr, _jcc_addr: None,
        branch_target_return_expr=lambda _project, local_codegen, target: _const(int(target), local_codegen),
        translate_cmp_jcc_guard=lambda _project, _codegen, _block_addr, _jcc_addr: object(),
        decoded_condition_expr=lambda _project, local_codegen, _decoded, _tags: _const(1, local_codegen),
        last_call_addr_before_jcc_in_function=lambda _project, _codegen, _jcc_addr: None,
    )

    pairs = ordered_conditional_return_expr_pairs_from_cfg_8616(project, codegen, callbacks)

    assert pairs == []


def test_structuring_orders_conditional_void_tail_call_proofs_requires_true_expr_only():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    jcc = SimpleNamespace(address=0x1010, target=0x1200)
    cond = _const(1, codegen)
    true_expr = _const(7, codegen)
    callbacks = ReturnConditionalVoidTailCallCallbacks8616(
        linear_jcc_block_starts=lambda _project, _codegen: ((0x1000, jcc),),
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        next_unconditional_target_after_jcc=lambda _project, _block_addr, _jcc_addr: 0x1220,
        branch_target_return_expr=lambda _project, _codegen, target: true_expr if target == 0x1200 else None,
        translate_cmp_jcc_guard=lambda _project, _codegen, block_addr, jcc_addr: (block_addr, jcc_addr),
        decoded_condition_expr=lambda _project, _codegen, decoded: cond if decoded == (0x1000, 0x1010) else None,
    )

    proofs = ordered_conditional_void_tail_call_proofs_from_cfg_8616(project, codegen, callbacks)

    assert proofs == [(cond, true_expr)]


def test_structuring_orders_conditional_void_tail_call_proofs_refuses_nonvoid_false_expr():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    jcc = SimpleNamespace(address=0x1010, target=0x1200)
    callbacks = ReturnConditionalVoidTailCallCallbacks8616(
        linear_jcc_block_starts=lambda _project, _codegen: ((0x1000, jcc),),
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        next_unconditional_target_after_jcc=lambda _project, _block_addr, _jcc_addr: 0x1220,
        branch_target_return_expr=lambda _project, local_codegen, target: _const(int(target), local_codegen),
        translate_cmp_jcc_guard=lambda _project, _codegen, _block_addr, _jcc_addr: object(),
        decoded_condition_expr=lambda _project, local_codegen, _decoded: _const(1, local_codegen),
    )

    proofs = ordered_conditional_void_tail_call_proofs_from_cfg_8616(project, codegen, callbacks)

    assert proofs == []


def test_structuring_return_chain_reads_branch_return_value_from_condition_tag():
    branch_insn = SimpleNamespace(address=0x1010, target=0x1200)
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(branch_insn,)))
    project = SimpleNamespace(factory=SimpleNamespace(block=lambda _addr, opt_level=0: block))
    cond = SimpleNamespace(condition_key=(0x1010, 0x1000))
    callbacks = _proof_callbacks((), {0x1200: 7})

    value = condition_branch_return_value_8616(project, cond, callbacks)

    assert value == 7


def test_structuring_return_chain_flattening_is_idempotent_for_existing_chain():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond_one = _const(1, codegen)
    cond_two = _const(2, codegen)
    stale_root = CStatements(statements=[], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=stale_root, body=stale_root)
    flatten_conditional_return_chain_8616(project, codegen, [(cond_one, 7), (cond_two, 9)], _callbacks(11))
    root = codegen.cfunc.statements

    changed = flatten_conditional_return_chain_8616(
        project,
        codegen,
        [(cond_one, 7), (cond_two, 9)],
        _callbacks(11),
    )

    assert changed is False
    assert codegen.cfunc.statements is root
    assert codegen.cfunc.body is root


def test_structuring_return_chain_suffix_rebuilds_after_semantic_prefix():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    setup = CAssignment(_const(90, codegen), _const(91, codegen), codegen=codegen)
    old_guard = _if_return(99, 100, codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=CStatements(statements=[setup, old_guard], codegen=codegen),
    )
    cond_one = _const(1, codegen)
    cond_two = _const(2, codegen)

    changed = materialize_cfg_conditional_return_suffix_8616(
        project,
        codegen,
        [(cond_one, 7), (cond_two, 9)],
        _callbacks(11),
    )

    statements = tuple(codegen.cfunc.statements.statements)
    assert changed is True
    assert codegen.cfunc.statements is codegen.cfunc.body
    assert statements[0] is setup
    assert len(statements) == 4
    assert all(isinstance(stmt, CIfElse) for stmt in statements[1:3])
    assert isinstance(statements[-1], CReturn)
    assert codegen._inertia_return_chain_suffix_materialized_8616 is True
    assert codegen._inertia_return_chain_materialized_values_8616 == (7, 9)
    assert codegen._inertia_return_chain_final_value_8616 == 11


def test_structuring_empty_if_return_chain_uses_cfg_pairs_for_flattening():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond_one = _const(1, codegen)
    cond_two = _const(2, codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=CStatements(
            statements=[
                CIfElse([(cond_one, CStatements(statements=[], codegen=codegen))], else_node=None, codegen=codegen),
                CIfElse([(cond_two, CStatements(statements=[], codegen=codegen))], else_node=None, codegen=codegen),
            ],
            codegen=codegen,
        ),
    )
    cfg_cond_one = _const(11, codegen)
    cfg_cond_two = _const(12, codegen)
    flattened: list[list[tuple[CConstant, int]]] = []

    changed = materialize_empty_if_return_branches_8616(
        project,
        codegen,
        _empty_if_callbacks(
            ordered_values=[7, 9],
            cfg_pairs=[(cfg_cond_one, 7), (cfg_cond_two, 9)],
            flattened=flattened,
        ),
    )

    stats = codegen._inertia_empty_return_branch_stats_8616
    assert changed is True
    assert stats == {"candidates": 2, "materialized": 2, "refused": 0}
    assert codegen._inertia_empty_return_branch_values_8616 == (7, 9)
    assert flattened == [[(cfg_cond_one, 7), (cfg_cond_two, 9)]]


def test_structuring_empty_if_return_chain_refuses_unsafe_effects():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond_one = _const(1, codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=CStatements(
            statements=[
                CIfElse([(cond_one, CStatements(statements=[], codegen=codegen))], else_node=None, codegen=codegen)
            ],
            codegen=codegen,
        ),
    )

    changed = materialize_empty_if_return_branches_8616(
        project,
        codegen,
        _empty_if_callbacks(ordered_values=[7], unsafe_effects=True),
    )

    assert changed is False
    assert codegen._inertia_empty_return_branch_stats_8616 == {"candidates": 1, "materialized": 0, "refused": 2}
    assert codegen._inertia_empty_return_branch_refused_unsafe_effects_8616 == 1


def test_structuring_selector_return_materializes_cfg_expr_chain():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=CStatements(statements=[], codegen=codegen))
    cond_one = _const(1, codegen)
    cond_two = _const(2, codegen)
    true_one = _const(7, codegen)
    true_two = _const(9, codegen)
    final_expr = _const(11, codegen)

    changed = materialize_cfg_selector_return_branches_8616(
        project,
        codegen,
        _selector_callbacks(pairs=[(cond_one, true_one, _const(8, codegen)), (cond_two, true_two, final_expr)]),
    )

    statements = tuple(codegen.cfunc.statements.statements)
    assert changed is True
    assert len(statements) == 3
    assert all(isinstance(stmt, CIfElse) for stmt in statements[:2])
    assert isinstance(statements[-1], CReturn)
    assert codegen._inertia_cfg_selector_return_stats_8616 == {"candidates": 2, "materialized": 2, "refused": 0}
    assert codegen._inertia_return_expr_chain_materialized_8616 is True
    assert codegen._inertia_return_selector_materialized_8616 is True
    assert codegen._inertia_return_chain_materialized_condition_fingerprints_8616 == ("const:1", "const:2")
    assert codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616 == ("const:7", "const:9", "const:11")


def test_structuring_selector_return_refuses_duplicate_conditions():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=CStatements(statements=[], codegen=codegen))
    cond = _const(1, codegen)

    changed = materialize_cfg_selector_return_branches_8616(
        project,
        codegen,
        _selector_callbacks(pairs=[(cond, _const(7, codegen), _const(8, codegen)), (cond, _const(9, codegen), _const(10, codegen))]),
    )

    assert changed is False
    assert codegen._inertia_cfg_selector_return_stats_8616 == {"candidates": 2, "materialized": 0, "refused": 2}
    assert not getattr(codegen, "_inertia_return_selector_materialized_8616", False)


def test_structuring_selector_condition_call_addrs_reads_condition_tags():
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    cond.tags = {"condition_call_ins_addr": 0x1234}

    addrs = selector_condition_call_addrs_8616(
        [(cond, _const(7, codegen), _const(8, codegen))],
        _iter_nodes,
    )

    assert addrs == frozenset({0x1234})


def test_structuring_selector_condition_call_addrs_from_cfg_requires_full_pair_proof():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    jcc = SimpleNamespace(address=0x1010, target=0x1200)
    callbacks = ReturnSelectorCallsiteProofCallbacks8616(
        linear_jcc_block_starts=lambda _project, _codegen: ((0x1000, jcc),),
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        next_unconditional_target_after_jcc=lambda _project, _block_addr, _jcc_addr: 0x1220,
        branch_target_return_expr=lambda _project, local_codegen, target: _const(int(target), local_codegen),
        translate_cmp_jcc_guard=lambda _project, _codegen, _block_addr, _jcc_addr: object(),
        last_call_addr_before_jcc_in_function=lambda _project, _codegen, _jcc_addr: 0x100C,
    )

    addrs = selector_condition_call_addrs_from_cfg_8616(project, codegen, callbacks)

    assert addrs == frozenset({0x100C})


def test_structuring_last_call_before_jcc_uses_nearest_call():
    insns = (
        SimpleNamespace(address=0x1000, mnemonic="call"),
        SimpleNamespace(address=0x1004, mnemonic="mov"),
        SimpleNamespace(address=0x1008, mnemonic="lcall"),
        SimpleNamespace(address=0x1010, mnemonic="jne"),
    )

    assert last_call_addr_before_jcc_in_function_8616(insns, 0x1010) == 0x1008


def test_structuring_last_call_before_jcc_resets_after_branch():
    insns = (
        SimpleNamespace(address=0x1000, mnemonic="call"),
        SimpleNamespace(address=0x1004, mnemonic="je"),
        SimpleNamespace(address=0x1008, mnemonic="mov"),
        SimpleNamespace(address=0x1010, mnemonic="jne"),
    )

    assert last_call_addr_before_jcc_in_function_8616(insns, 0x1010) is None


def test_structuring_linear_jcc_block_starts_uses_linear_block_start():
    insns = (
        SimpleNamespace(address=0x1000, mnemonic="mov"),
        SimpleNamespace(address=0x1002, mnemonic="cmp"),
        SimpleNamespace(address=0x1004, mnemonic="jne"),
        SimpleNamespace(address=0x1006, mnemonic="jmp"),
    )

    assert linear_jcc_block_starts_8616(insns) == ((0x1000, insns[2]),)


def test_structuring_linear_jcc_block_starts_refuses_to_cross_call_or_terminator():
    insns = (
        SimpleNamespace(address=0x1000, mnemonic="mov"),
        SimpleNamespace(address=0x1002, mnemonic="call"),
        SimpleNamespace(address=0x1006, mnemonic="cmp"),
        SimpleNamespace(address=0x1008, mnemonic="jne"),
        SimpleNamespace(address=0x1010, mnemonic="ret"),
        SimpleNamespace(address=0x1012, mnemonic="cmp"),
        SimpleNamespace(address=0x1014, mnemonic="je"),
    )

    assert linear_jcc_block_starts_8616(insns) == ((0x1006, insns[3]), (0x1012, insns[6]))


def test_structuring_single_if_return_accepts_wrapped_return_body():
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    retval = _const(7, codegen)
    stmt = CIfElse(
        [(cond, CStatements(statements=[CReturn(retval, codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )

    assert single_if_return_8616(stmt) == (cond, retval)
    assert const_return_value_8616(retval) == 7


def test_structuring_single_if_return_refuses_multi_statement_body():
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    stmt = CIfElse(
        [
            (
                cond,
                CStatements(
                    statements=[
                        CAssignment(_const(1, codegen), _const(2, codegen), codegen=codegen),
                        CReturn(_const(7, codegen), codegen=codegen),
                    ],
                    codegen=codegen,
                ),
            )
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )

    assert single_if_return_8616(stmt) is None
    assert const_return_value_8616(cond) == 1


def test_structuring_is_empty_return_statement_accepts_direct_and_wrapped_return():
    codegen = _DummyCodegen()
    direct = CReturn(None, codegen=codegen)
    wrapped = CStatements(statements=[direct], codegen=codegen)

    assert is_empty_return_statement_8616(direct) is True
    assert is_empty_return_statement_8616(wrapped) is True


def test_structuring_is_empty_return_statement_refuses_value_return():
    codegen = _DummyCodegen()
    direct = CReturn(_const(7, codegen), codegen=codegen)
    wrapped = CStatements(statements=[direct], codegen=codegen)

    assert is_empty_return_statement_8616(direct) is False
    assert is_empty_return_statement_8616(wrapped) is False


def test_duplicate_empty_return_guard_prune_plan_removes_adjacent_duplicate_guard():
    codegen = _DummyCodegen()
    statements = (_if_empty_return(1, codegen), _if_return(1, 7, codegen), _if_return(2, 9, codegen))

    plan = duplicate_empty_return_guard_prune_plan_8616(object(), statements, (7, 9), _callbacks(0))

    assert plan is not None
    assert plan.index == 0
    assert plan.reason is DuplicateEmptyReturnGuardPruneReason8616.ADJACENT_DUPLICATE_EMPTY_GUARD
    assert plan.value == 7


def test_duplicate_empty_return_guard_prune_plan_removes_empty_prefix_before_chain():
    codegen = _DummyCodegen()
    statements = (
        CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen),
        _if_return(1, 7, codegen),
        _if_return(2, 9, codegen),
    )

    plan = duplicate_empty_return_guard_prune_plan_8616(object(), statements, (7, 9), _callbacks(0))

    assert plan is not None
    assert plan.index == 0
    assert plan.reason is DuplicateEmptyReturnGuardPruneReason8616.EMPTY_PREFIX_BEFORE_CHAIN
    assert plan.value is None


def test_duplicate_empty_return_guard_prune_plan_refuses_condition_mismatch():
    codegen = _DummyCodegen()
    statements = (_if_empty_return(3, codegen), _if_return(1, 7, codegen), _if_return(2, 9, codegen))

    assert duplicate_empty_return_guard_prune_plan_8616(object(), statements, (7, 9), _callbacks(0)) is None


def test_structuring_is_conditional_branch_insn_classifies_jcc_and_loop_family():
    assert is_conditional_branch_insn_8616(SimpleNamespace(mnemonic="jne")) is True
    assert is_conditional_branch_insn_8616(SimpleNamespace(mnemonic="loopne")) is True
    assert is_conditional_branch_insn_8616(SimpleNamespace(mnemonic="jmp")) is False
    assert is_conditional_branch_insn_8616(SimpleNamespace(mnemonic="ljmp")) is False
    assert is_conditional_branch_insn_8616(SimpleNamespace(mnemonic="mov")) is False


def test_structuring_conditional_branch_count_counts_available_linear_instruction_stream():
    insns = (
        SimpleNamespace(mnemonic="mov"),
        SimpleNamespace(mnemonic="jne"),
        SimpleNamespace(mnemonic="jmp"),
        SimpleNamespace(mnemonic="loopne"),
    )

    assert conditional_branch_count_8616(insns) == 2


def test_structuring_conditional_branch_count_reports_missing_instruction_stream():
    assert conditional_branch_count_8616(()) is None


def test_structuring_c_node_semantically_empty_accepts_empty_statements_and_if():
    codegen = _DummyCodegen()
    empty = CStatements(statements=[], codegen=codegen)
    cond = _const(1, codegen)
    empty_if = CIfElse([(cond, empty)], else_node=None, cstyle_ifs=True, codegen=codegen)

    assert c_node_semantically_empty_8616(empty, _callbacks(0)) is True
    assert c_node_semantically_empty_8616(empty_if, _callbacks(0)) is True


def test_structuring_c_node_semantically_empty_refuses_condition_call():
    codegen = _DummyCodegen()
    condition_call = CFunctionCall("cmp_i16", None, [_const(1, codegen), _const(2, codegen)], codegen=codegen)
    empty = CStatements(statements=[], codegen=codegen)
    guarded = CIfElse([(condition_call, empty)], else_node=None, cstyle_ifs=True, codegen=codegen)

    assert c_node_semantically_empty_8616(guarded, _callbacks(0)) is False


def test_structuring_surplus_empty_guard_condition_classifies_empty_return_and_noop():
    codegen = _DummyCodegen()
    cond_return = _const(1, codegen)
    empty_return = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    return_guard = CIfElse([(cond_return, empty_return)], else_node=None, cstyle_ifs=True, codegen=codegen)
    cond_noop = _const(2, codegen)
    noop_body = CStatements(statements=[], codegen=codegen)
    noop_guard = CIfElse([(cond_noop, noop_body)], else_node=None, cstyle_ifs=True, codegen=codegen)

    assert surplus_empty_guard_condition_8616(return_guard, _callbacks(0)) == (
        cond_return,
        SurplusIfGuardKind8616.EMPTY_RETURN,
    )
    assert surplus_empty_guard_condition_8616(noop_guard, _callbacks(0)) == (
        cond_noop,
        SurplusIfGuardKind8616.EMPTY_NOOP,
    )


def test_structuring_surplus_empty_guard_condition_refuses_condition_call():
    codegen = _DummyCodegen()
    condition_call = CFunctionCall("cmp_i16", None, [_const(1, codegen), _const(2, codegen)], codegen=codegen)
    empty_return = CStatements(statements=[CReturn(None, codegen=codegen)], codegen=codegen)
    guarded = CIfElse([(condition_call, empty_return)], else_node=None, cstyle_ifs=True, codegen=codegen)

    assert surplus_empty_guard_condition_8616(guarded, _callbacks(0)) is None


def test_structuring_next_unconditional_target_after_jcc_reads_same_block_jump():
    jcc = SimpleNamespace(address=0x1000, size=2, mnemonic="jne")
    jmp = SimpleNamespace(address=0x1002, mnemonic="jmp", target=0x1200)
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(jcc, jmp)))

    target = next_unconditional_target_after_jcc_8616(
        block,
        0x1000,
        lambda _addr: None,
        lambda insn: getattr(insn, "target", None),
    )

    assert target == 0x1200


def test_structuring_next_unconditional_target_after_jcc_reads_next_block_jump():
    jcc = SimpleNamespace(address=0x1000, size=2, mnemonic="jne")
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(jcc,)))
    next_block = SimpleNamespace(capstone=SimpleNamespace(insns=(SimpleNamespace(address=0x1002, mnemonic="jmp", target=0x1200),)))

    target = next_unconditional_target_after_jcc_8616(
        block,
        0x1000,
        lambda addr: next_block if addr == 0x1002 else None,
        lambda insn: getattr(insn, "target", None),
    )

    assert target == 0x1200


def test_structuring_first_conditional_jcc_ignores_plain_jump():
    plain_jump = SimpleNamespace(address=0x1000, mnemonic="jmp", target=0x1200)
    cond_jump = SimpleNamespace(address=0x1002, mnemonic="jne", target=0x1220)
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(plain_jump, cond_jump)))

    assert first_conditional_jcc_8616(block) is cond_jump


def test_structuring_selector_targets_from_32bit_jcc_chain_reads_three_jcc_shape():
    start_jcc = SimpleNamespace(address=0x1000, size=2, mnemonic="jne", target=0x1100)
    start_jmp = SimpleNamespace(address=0x1002, mnemonic="jmp", target=0x1300)
    mid_jcc = SimpleNamespace(address=0x1100, size=2, mnemonic="jne", target=0x1200)
    mid_jmp = SimpleNamespace(address=0x1102, mnemonic="jmp", target=0x1400)
    low_jcc = SimpleNamespace(address=0x1200, size=2, mnemonic="jne", target=0x1400)
    low_jmp = SimpleNamespace(address=0x1202, mnemonic="jmp", target=0x1300)
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(start_jcc, start_jmp))),
        0x1100: SimpleNamespace(capstone=SimpleNamespace(insns=(mid_jcc, mid_jmp))),
        0x1200: SimpleNamespace(capstone=SimpleNamespace(insns=(low_jcc, low_jmp))),
    }

    targets = selector_targets_from_32bit_jcc_chain_8616(
        0x1000,
        start_jcc,
        lambda addr: blocks.get(addr),
        lambda insn: getattr(insn, "target", None),
        _next_target_after_jcc,
    )

    assert targets == (0x1400, 0x1300)


def test_structuring_selector_targets_from_32bit_jcc_chain_refuses_mismatched_shape():
    start_jcc = SimpleNamespace(address=0x1000, size=2, mnemonic="jne", target=0x1100)
    start_jmp = SimpleNamespace(address=0x1002, mnemonic="jmp", target=0x1300)
    mid_jcc = SimpleNamespace(address=0x1100, size=2, mnemonic="jne", target=0x1200)
    mid_jmp = SimpleNamespace(address=0x1102, mnemonic="jmp", target=0x1400)
    low_jcc = SimpleNamespace(address=0x1200, size=2, mnemonic="jne", target=0x1500)
    low_jmp = SimpleNamespace(address=0x1202, mnemonic="jmp", target=0x1600)
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(start_jcc, start_jmp))),
        0x1100: SimpleNamespace(capstone=SimpleNamespace(insns=(mid_jcc, mid_jmp))),
        0x1200: SimpleNamespace(capstone=SimpleNamespace(insns=(low_jcc, low_jmp))),
    }

    targets = selector_targets_from_32bit_jcc_chain_8616(
        0x1000,
        start_jcc,
        lambda addr: blocks.get(addr),
        lambda insn: getattr(insn, "target", None),
        _next_target_after_jcc,
    )

    assert targets is None


def test_structuring_equality_return_target_from_32bit_jcc_chain_reads_shared_false_target():
    start_jcc = SimpleNamespace(address=0x1000, size=2, mnemonic="je", target=0x1100)
    start_jmp = SimpleNamespace(address=0x1002, mnemonic="jmp", target=0x1300)
    mid_jcc = SimpleNamespace(address=0x1100, size=2, mnemonic="jz", target=0x1200)
    mid_jmp = SimpleNamespace(address=0x1102, mnemonic="jmp", target=0x1300)
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(start_jcc, start_jmp))),
        0x1100: SimpleNamespace(capstone=SimpleNamespace(insns=(mid_jcc, mid_jmp))),
    }

    target = equality_return_target_from_32bit_jcc_chain_8616(
        0x1000,
        start_jcc,
        lambda addr: blocks.get(addr),
        lambda insn: getattr(insn, "target", None),
        _next_target_after_jcc,
    )

    assert target == 0x1200


def test_structuring_inequality_target_from_32bit_jcc_chain_reads_shared_target():
    start_jcc = SimpleNamespace(address=0x1000, size=2, mnemonic="je", target=0x1100)
    start_jmp = SimpleNamespace(address=0x1002, mnemonic="jmp", target=0x1300)
    mid_jcc = SimpleNamespace(address=0x1100, size=2, mnemonic="jne", target=0x1300)
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(start_jcc, start_jmp))),
        0x1100: SimpleNamespace(capstone=SimpleNamespace(insns=(mid_jcc,))),
    }

    target = inequality_target_from_32bit_jcc_chain_8616(
        0x1000,
        start_jcc,
        lambda addr: blocks.get(addr),
        lambda insn: getattr(insn, "target", None),
        _next_target_after_jcc,
    )

    assert target == 0x1300


def test_structuring_ordered_32bit_selector_return_expr_pairs_from_cfg_reads_proven_pair():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    start_jcc = SimpleNamespace(address=0x1000, size=2, mnemonic="jne", target=0x1100)
    start_jmp = SimpleNamespace(address=0x1002, mnemonic="jmp", target=0x1300)
    mid_jcc = SimpleNamespace(address=0x1100, size=2, mnemonic="jne", target=0x1200)
    mid_jmp = SimpleNamespace(address=0x1102, mnemonic="jmp", target=0x1400)
    low_jcc = SimpleNamespace(address=0x1200, size=2, mnemonic="jne", target=0x1400)
    low_jmp = SimpleNamespace(address=0x1202, mnemonic="jmp", target=0x1300)
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(start_jcc, start_jmp))),
        0x1100: SimpleNamespace(capstone=SimpleNamespace(insns=(mid_jcc, mid_jmp))),
        0x1200: SimpleNamespace(capstone=SimpleNamespace(insns=(low_jcc, low_jmp))),
    }
    cond = _const(1, codegen)
    true_expr = _const(7, codegen)
    false_expr = _const(9, codegen)
    callbacks = ReturnSelector32BitPairCallbacks8616(
        function_block_addrs=lambda _project, _codegen: (0x1000,),
        load_block=lambda addr: blocks.get(addr),
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        next_unconditional_target_after_jcc=_next_target_after_jcc,
        translate_cmp_jcc_guard=lambda _project, _codegen, block_addr, jcc_addr: (block_addr, jcc_addr),
        decoded_condition_expr=lambda _project, _codegen, decoded: cond if decoded == (0x1000, 0x1000) else None,
        branch_target_return_expr=lambda _project, _codegen, target: {0x1400: true_expr, 0x1300: false_expr}.get(target),
    )

    pairs = ordered_32bit_selector_return_expr_pairs_from_cfg_8616(project, codegen, callbacks)

    assert pairs == [(cond, true_expr, false_expr)]


def test_structuring_ordered_32bit_selector_return_expr_pairs_from_cfg_refuses_missing_return_expr():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    start_jcc = SimpleNamespace(address=0x1000, size=2, mnemonic="jne", target=0x1100)
    start_jmp = SimpleNamespace(address=0x1002, mnemonic="jmp", target=0x1300)
    mid_jcc = SimpleNamespace(address=0x1100, size=2, mnemonic="jne", target=0x1200)
    mid_jmp = SimpleNamespace(address=0x1102, mnemonic="jmp", target=0x1400)
    low_jcc = SimpleNamespace(address=0x1200, size=2, mnemonic="jne", target=0x1400)
    low_jmp = SimpleNamespace(address=0x1202, mnemonic="jmp", target=0x1300)
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(start_jcc, start_jmp))),
        0x1100: SimpleNamespace(capstone=SimpleNamespace(insns=(mid_jcc, mid_jmp))),
        0x1200: SimpleNamespace(capstone=SimpleNamespace(insns=(low_jcc, low_jmp))),
    }
    callbacks = ReturnSelector32BitPairCallbacks8616(
        function_block_addrs=lambda _project, _codegen: (0x1000,),
        load_block=lambda addr: blocks.get(addr),
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        next_unconditional_target_after_jcc=_next_target_after_jcc,
        translate_cmp_jcc_guard=lambda _project, _codegen, _block_addr, _jcc_addr: object(),
        decoded_condition_expr=lambda _project, local_codegen, _decoded: _const(1, local_codegen),
        branch_target_return_expr=lambda _project, _codegen, _target: None,
    )

    pairs = ordered_32bit_selector_return_expr_pairs_from_cfg_8616(project, codegen, callbacks)

    assert pairs == []


def test_structuring_ordered_32bit_conditional_return_pairs_from_cfg_reads_value_pair():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    start_jcc = SimpleNamespace(address=0x1000, size=2, mnemonic="jne", target=0x1100)
    start_jmp = SimpleNamespace(address=0x1002, mnemonic="jmp", target=0x1300)
    mid_jcc = SimpleNamespace(address=0x1100, size=2, mnemonic="jne", target=0x1200)
    mid_jmp = SimpleNamespace(address=0x1102, mnemonic="jmp", target=0x1400)
    low_jcc = SimpleNamespace(address=0x1200, size=2, mnemonic="jne", target=0x1400)
    low_jmp = SimpleNamespace(address=0x1202, mnemonic="jmp", target=0x1300)
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(start_jcc, start_jmp))),
        0x1100: SimpleNamespace(capstone=SimpleNamespace(insns=(mid_jcc, mid_jmp))),
        0x1200: SimpleNamespace(capstone=SimpleNamespace(insns=(low_jcc, low_jmp))),
    }
    cond = _const(1, codegen)
    callbacks = Return32BitConditionalPairCallbacks8616(
        function_block_addrs=lambda _project, _codegen: (0x1000,),
        load_block=lambda addr: blocks.get(addr),
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        next_unconditional_target_after_jcc=_next_target_after_jcc,
        branch_target_return_value=lambda _project, target: {0x1400: 7}.get(target),
        translate_cmp_jcc_guard=lambda _project, _codegen, block_addr, jcc_addr: (block_addr, jcc_addr),
        decoded_condition_expr=lambda _project, _codegen, decoded: cond if decoded == (0x1000, 0x1000) else None,
        expr_fingerprint=lambda expr, _project: f"const:{expr.value}" if isinstance(expr, CConstant) else repr(expr),
    )

    pairs = ordered_32bit_conditional_return_pairs_from_cfg_8616(project, codegen, callbacks)

    assert pairs == [(cond, 7)]


def test_structuring_ordered_32bit_conditional_return_pairs_from_cfg_skips_duplicate_conditions():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    first_jcc = SimpleNamespace(address=0x1000, size=2, mnemonic="je", target=0x1100)
    first_jmp = SimpleNamespace(address=0x1002, mnemonic="jmp", target=0x1300)
    first_mid_jcc = SimpleNamespace(address=0x1100, size=2, mnemonic="jz", target=0x1200)
    first_mid_jmp = SimpleNamespace(address=0x1102, mnemonic="jmp", target=0x1300)
    second_jcc = SimpleNamespace(address=0x2000, size=2, mnemonic="je", target=0x2100)
    second_jmp = SimpleNamespace(address=0x2002, mnemonic="jmp", target=0x2300)
    second_mid_jcc = SimpleNamespace(address=0x2100, size=2, mnemonic="jz", target=0x2200)
    second_mid_jmp = SimpleNamespace(address=0x2102, mnemonic="jmp", target=0x2300)
    blocks = {
        0x1000: SimpleNamespace(capstone=SimpleNamespace(insns=(first_jcc, first_jmp))),
        0x1100: SimpleNamespace(capstone=SimpleNamespace(insns=(first_mid_jcc, first_mid_jmp))),
        0x2000: SimpleNamespace(capstone=SimpleNamespace(insns=(second_jcc, second_jmp))),
        0x2100: SimpleNamespace(capstone=SimpleNamespace(insns=(second_mid_jcc, second_mid_jmp))),
    }
    cond = _const(1, codegen)
    callbacks = Return32BitConditionalPairCallbacks8616(
        function_block_addrs=lambda _project, _codegen: (0x1000, 0x2000),
        load_block=lambda addr: blocks.get(addr),
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        next_unconditional_target_after_jcc=_next_target_after_jcc,
        branch_target_return_value=lambda _project, target: {0x1200: 7, 0x2200: 9}.get(target),
        translate_cmp_jcc_guard=lambda _project, _codegen, _block_addr, _jcc_addr: object(),
        decoded_condition_expr=lambda _project, _codegen, _decoded: cond,
        expr_fingerprint=lambda _expr, _project: "same-condition",
    )

    pairs = ordered_32bit_conditional_return_pairs_from_cfg_8616(project, codegen, callbacks)

    assert pairs == [(cond, 7)]


def test_structuring_ordered_32bit_mask_update_pairs_from_cfg_reads_direct_branch_update():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    jcc = SimpleNamespace(address=0x1010, mnemonic="jg", target=0x1100)
    callbacks = MaskAccumulatorPairCallbacks8616(
        linear_jcc_block_starts=lambda _project, _codegen: ((0x1000, jcc),),
        selector_targets_from_32bit_jcc_chain=lambda _block_addr, _insn: None,
        equality_return_target_from_32bit_jcc_chain=lambda _block_addr, _insn: None,
        inequality_target_from_32bit_jcc_chain=lambda _block_addr, _insn: None,
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        next_unconditional_target_after_jcc=lambda _project, _block_addr, _jcc_addr: None,
        or_stack_update_imm=lambda _project, target, _slot_offset: {0x1100: 4}.get(target),
        translate_cmp_jcc_guard=lambda _project, _codegen, block_addr, jcc_addr: (block_addr, jcc_addr),
        decoded_condition_expr=lambda _project, _codegen, decoded: cond if decoded == (0x1000, 0x1010) else None,
        expr_fingerprint=lambda expr, _project: f"const:{expr.value}" if isinstance(expr, CConstant) else repr(expr),
    )

    pairs = ordered_32bit_mask_update_pairs_from_cfg_8616(project, codegen, -2, callbacks)

    assert pairs == [(cond, 4)]


def test_structuring_ordered_32bit_mask_update_pairs_from_cfg_skips_duplicate_conditions():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    cond = _const(1, codegen)
    first_jcc = SimpleNamespace(address=0x1010, mnemonic="jg", target=0x1100)
    second_jcc = SimpleNamespace(address=0x1020, mnemonic="jl", target=0x1200)
    callbacks = MaskAccumulatorPairCallbacks8616(
        linear_jcc_block_starts=lambda _project, _codegen: ((0x1000, first_jcc), (0x1020, second_jcc)),
        selector_targets_from_32bit_jcc_chain=lambda _block_addr, _insn: None,
        equality_return_target_from_32bit_jcc_chain=lambda _block_addr, _insn: None,
        inequality_target_from_32bit_jcc_chain=lambda _block_addr, _insn: None,
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        next_unconditional_target_after_jcc=lambda _project, _block_addr, jcc_addr: {0x1020: 0x1300}.get(jcc_addr),
        or_stack_update_imm=lambda _project, target, _slot_offset: {0x1100: 4, 0x1300: 8}.get(target),
        translate_cmp_jcc_guard=lambda _project, _codegen, _block_addr, _jcc_addr: object(),
        decoded_condition_expr=lambda _project, _codegen, _decoded: cond,
        expr_fingerprint=lambda _expr, _project: "same-mask-condition",
    )

    pairs = ordered_32bit_mask_update_pairs_from_cfg_8616(project, codegen, -2, callbacks)

    assert pairs == [(cond, 4)]


def test_structuring_materialize_cfg_mask_accumulator_builds_structured_body():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(statements=None)
    mask_expr = _const(99, codegen)
    first_cond = _const(1, codegen)
    second_cond = _const(2, codegen)
    callbacks = MaskAccumulatorMaterializationCallbacks8616(
        first_stack_zero_init=lambda _project, _codegen: -2,
        ordered_mask_update_pairs=lambda _project, _codegen, slot: [(first_cond, 1), (second_cond, 2)]
        if slot == -2
        else [],
        stack_slot_expr=lambda _codegen, slot, size: mask_expr if (slot, size) == (-2, 2) else None,
        expr_fingerprint=lambda expr, _project: f"const:{expr.value}" if isinstance(expr, CConstant) else repr(expr),
    )

    assert materialize_cfg_mask_accumulator_8616(project, codegen, callbacks)

    statements = tuple(codegen.cfunc.statements.statements)
    assert len(statements) == 4
    assert isinstance(statements[0], CAssignment)
    assert isinstance(statements[1], CIfElse)
    assert isinstance(statements[2], CIfElse)
    assert isinstance(statements[3], CReturn)
    assert codegen._inertia_mask_accumulator_materialized_8616 is True
    assert codegen._inertia_mask_accumulator_condition_fingerprints_8616 == ("const:1", "const:2")
    assert codegen._inertia_mask_accumulator_return_fingerprint_8616 == "const:99"
    assert codegen._inertia_mask_accumulator_update_immediates_8616 == (1, 2)


def test_structuring_materialize_cfg_mask_accumulator_refuses_single_pair():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(statements=None)
    cond = _const(1, codegen)
    callbacks = MaskAccumulatorMaterializationCallbacks8616(
        first_stack_zero_init=lambda _project, _codegen: -2,
        ordered_mask_update_pairs=lambda _project, _codegen, _slot: [(cond, 1)],
        stack_slot_expr=lambda _codegen, _slot, _size: _const(99, codegen),
        expr_fingerprint=lambda expr, _project: f"const:{expr.value}" if isinstance(expr, CConstant) else repr(expr),
    )

    assert not materialize_cfg_mask_accumulator_8616(project, codegen, callbacks)
    assert codegen.cfunc.statements is None


def test_structuring_selector_stack_expr_from_ax_load_uses_bp_stack_slot():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    stack_expr = _const(7, codegen)
    seen_slots: list[tuple[int, int]] = []
    insn = _Insn("mov", (_reg_operand(1), _mem_operand(4, -2, 2)))
    callbacks = SelectorStackExprCallbacks8616(
        linear_function_insns=lambda _project, _codegen: (insn,),
        stack_slot_expr=lambda _codegen, disp, size, _project: seen_slots.append((disp, size)) or stack_expr,
    )

    assert selector_stack_expr_from_ax_load_8616(project, codegen, callbacks) is stack_expr
    assert seen_slots == [(-2, 2)]


def test_structuring_selector_stack_expr_from_ax_load_refuses_non_ax_destination():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    insn = _Insn("mov", (_reg_operand(7), _mem_operand(4, -2, 2)))
    callbacks = SelectorStackExprCallbacks8616(
        linear_function_insns=lambda _project, _codegen: (insn,),
        stack_slot_expr=lambda _codegen, _disp, _size, _project: _const(7, codegen),
    )

    assert selector_stack_expr_from_ax_load_8616(project, codegen, callbacks) is None


def test_structuring_materialize_sequential_decrement_switch_return_chain_builds_cases():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(statements=None)
    selector = _const(9, codegen)
    case0 = _const(10, codegen)
    case1 = _const(11, codegen)
    default = _const(12, codegen)
    insns = (
        _insn_at(0x1000, _Insn("or", (_reg_operand(1), _reg_operand(1)))),
        SimpleNamespace(address=0x1001, mnemonic="jne", target=0x4000),
        SimpleNamespace(address=0x1002, mnemonic="jmp", target=0x2000),
        _insn_at(0x1003, _Insn("dec", (_reg_operand(1),))),
        SimpleNamespace(address=0x1004, mnemonic="jne", target=0x4000),
        SimpleNamespace(address=0x1005, mnemonic="jmp", target=0x3000),
    )

    def _next_linear_jmp_target(local_insns: tuple[object, ...], index: int) -> int | None:
        if index + 1 >= len(local_insns):
            return None
        return getattr(local_insns[index + 1], "target", None)

    callbacks = SequentialDecrementSwitchCallbacks8616(
        set_cfunc_statements_root=_set_cfunc_statements_root,
        selector_stack_expr=lambda _project, _codegen: selector,
        selector_function_has_unsafe_effects=lambda _project, _codegen: False,
        selector_raw_stack_aliases=lambda _project, _selector: {"selector": ("stack:-2:2",)},
        linear_function_insns=lambda _project, _codegen: insns,
        next_linear_jmp_target=_next_linear_jmp_target,
        resolve_one_hop_jmp_target=lambda _project, target: target,
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        branch_target_return_expr=lambda _project, _codegen, target: {0x2000: case0, 0x3000: case1, 0x4000: default}.get(
            target
        ),
        clone_c_value=lambda expr: expr,
        expr_fingerprint=lambda expr, _project: f"const:{expr.value}" if isinstance(expr, CConstant) else repr(expr),
    )

    assert materialize_sequential_decrement_switch_return_chain_8616(project, codegen, callbacks)

    statements = tuple(codegen.cfunc.statements.statements)
    assert codegen.cfunc.statements is codegen.cfunc.body
    assert len(statements) == 3
    assert isinstance(statements[0], CIfElse)
    assert isinstance(statements[1], CIfElse)
    assert isinstance(statements[2], CReturn)
    assert codegen._inertia_decrement_switch_return_materialized_8616 is True
    assert codegen._inertia_sequential_decrement_switch_return_materialized_8616 is True
    assert codegen._inertia_return_selector_materialized_8616 is True
    conditions = tuple(stmt.condition_and_nodes[0][0] for stmt in statements[:2])
    assert tuple((cond.op, cond.rhs.value) for cond in conditions) == (("CmpEQ", 0), ("CmpEQ", 1))
    assert codegen._inertia_return_chain_materialized_condition_fingerprints_8616 == tuple(
        repr(cond) for cond in conditions
    )
    assert codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616 == (
        "const:10",
        "const:11",
        "const:12",
    )
    assert codegen._inertia_return_selector_raw_stack_slot_aliases_8616 == {"selector": ("stack:-2:2",)}


def test_structuring_materialize_sequential_decrement_switch_return_chain_refuses_non_jne_shape():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(statements=None)
    selector = _const(9, codegen)
    insns = (
        _insn_at(0x1000, _Insn("or", (_reg_operand(1), _reg_operand(1)))),
        SimpleNamespace(address=0x1001, mnemonic="je", target=0x4000),
        SimpleNamespace(address=0x1002, mnemonic="jmp", target=0x2000),
        _insn_at(0x1003, _Insn("dec", (_reg_operand(1),))),
        SimpleNamespace(address=0x1004, mnemonic="jne", target=0x4000),
        SimpleNamespace(address=0x1005, mnemonic="jmp", target=0x3000),
    )
    callbacks = SequentialDecrementSwitchCallbacks8616(
        set_cfunc_statements_root=_set_cfunc_statements_root,
        selector_stack_expr=lambda _project, _codegen: selector,
        selector_function_has_unsafe_effects=lambda _project, _codegen: False,
        selector_raw_stack_aliases=lambda _project, _selector: {},
        linear_function_insns=lambda _project, _codegen: insns,
        next_linear_jmp_target=lambda _insns, _index: None,
        resolve_one_hop_jmp_target=lambda _project, target: target,
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        branch_target_return_expr=lambda _project, _codegen, _target: _const(1, codegen),
        clone_c_value=lambda expr: expr,
        expr_fingerprint=lambda expr, _project: f"const:{expr.value}" if isinstance(expr, CConstant) else repr(expr),
    )

    assert not materialize_sequential_decrement_switch_return_chain_8616(project, codegen, callbacks)
    assert codegen.cfunc.statements is None


def test_structuring_materialize_complex_decrement_switch_return_chain_builds_cases():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(statements=None)
    selector = _const(9, codegen)
    case0 = _const(10, codegen)
    default = _const(11, codegen)
    case12 = _const(12, codegen)
    case3 = _const(13, codegen)
    insns = (
        _insn_at(0x1000, _Insn("or", (_reg_operand(1), _reg_operand(1)))),
        SimpleNamespace(address=0x1001, mnemonic="jne", target=0x5000),
        SimpleNamespace(address=0x1002, mnemonic="jmp", target=0x2000),
        _insn_at(0x1003, _Insn("dec", (_reg_operand(1),))),
        SimpleNamespace(address=0x1004, mnemonic="jge", target=0x6000),
        SimpleNamespace(address=0x1005, mnemonic="jmp", target=0x5000),
        _insn_at(0x1006, _Insn("dec", (_reg_operand(1),))),
        SimpleNamespace(address=0x1007, mnemonic="jg", target=0x7000),
        SimpleNamespace(address=0x1008, mnemonic="jmp", target=0x3000),
        _insn_at(0x1009, _Insn("dec", (_reg_operand(1),))),
        SimpleNamespace(address=0x100A, mnemonic="jne", target=0x5000),
        SimpleNamespace(address=0x100B, mnemonic="jmp", target=0x4000),
    )

    def _next_linear_jmp_target(local_insns: tuple[object, ...], index: int) -> int | None:
        if index + 1 >= len(local_insns):
            return None
        return getattr(local_insns[index + 1], "target", None)

    callbacks = ComplexDecrementSwitchCallbacks8616(
        set_cfunc_statements_root=_set_cfunc_statements_root,
        selector_stack_expr=lambda _project, _codegen: selector,
        selector_function_has_unsafe_effects=lambda _project, _codegen: False,
        selector_raw_stack_aliases=lambda _project, _selector: {"selector": ("stack:-2:2",)},
        linear_function_insns=lambda _project, _codegen: insns,
        next_linear_jmp_target=_next_linear_jmp_target,
        resolve_one_hop_jmp_target=lambda _project, target: target,
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        branch_target_return_expr=lambda _project, _codegen, target: {
            0x2000: case0,
            0x3000: case12,
            0x4000: case3,
            0x5000: default,
        }.get(target),
        clone_c_value=lambda expr: expr,
        expr_fingerprint=lambda expr, _project: f"const:{expr.value}" if isinstance(expr, CConstant) else repr(expr),
    )

    assert materialize_complex_decrement_switch_return_chain_8616(project, codegen, callbacks)

    statements = tuple(codegen.cfunc.statements.statements)
    assert codegen.cfunc.statements is codegen.cfunc.body
    assert len(statements) == 5
    assert all(isinstance(stmt, CIfElse) for stmt in statements[:4])
    assert isinstance(statements[4], CReturn)
    assert codegen._inertia_decrement_switch_return_materialized_8616 is True
    assert codegen._inertia_return_selector_materialized_8616 is True
    conditions = tuple(stmt.condition_and_nodes[0][0] for stmt in statements[:4])
    assert tuple((cond.op, cond.rhs.value) for cond in conditions) == (
        ("CmpEQ", 0),
        ("CmpLT", 1),
        ("CmpLE", 2),
        ("CmpEQ", 3),
    )
    assert codegen._inertia_return_chain_materialized_condition_fingerprints_8616 == tuple(
        repr(cond) for cond in conditions
    )
    assert codegen._inertia_return_expr_chain_materialized_return_fingerprints_8616 == (
        "const:10",
        "const:11",
        "const:12",
        "const:13",
        "const:11",
    )
    assert codegen._inertia_return_selector_raw_stack_slot_aliases_8616 == {"selector": ("stack:-2:2",)}


def test_structuring_materialize_complex_decrement_switch_return_chain_refuses_default_mismatch():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    codegen.cfunc = SimpleNamespace(statements=None)
    selector = _const(9, codegen)
    insns = (
        _insn_at(0x1000, _Insn("or", (_reg_operand(1), _reg_operand(1)))),
        SimpleNamespace(address=0x1001, mnemonic="jne", target=0x5000),
        SimpleNamespace(address=0x1002, mnemonic="jmp", target=0x2000),
        _insn_at(0x1003, _Insn("dec", (_reg_operand(1),))),
        SimpleNamespace(address=0x1004, mnemonic="jge", target=0x6000),
        SimpleNamespace(address=0x1005, mnemonic="jmp", target=0x5000),
        _insn_at(0x1006, _Insn("dec", (_reg_operand(1),))),
        SimpleNamespace(address=0x1007, mnemonic="jg", target=0x7000),
        SimpleNamespace(address=0x1008, mnemonic="jmp", target=0x3000),
        _insn_at(0x1009, _Insn("dec", (_reg_operand(1),))),
        SimpleNamespace(address=0x100A, mnemonic="jne", target=0x9999),
        SimpleNamespace(address=0x100B, mnemonic="jmp", target=0x4000),
    )
    callbacks = ComplexDecrementSwitchCallbacks8616(
        set_cfunc_statements_root=_set_cfunc_statements_root,
        selector_stack_expr=lambda _project, _codegen: selector,
        selector_function_has_unsafe_effects=lambda _project, _codegen: False,
        selector_raw_stack_aliases=lambda _project, _selector: {},
        linear_function_insns=lambda _project, _codegen: insns,
        next_linear_jmp_target=lambda local_insns, index: getattr(local_insns[index + 1], "target", None)
        if index + 1 < len(local_insns)
        else None,
        resolve_one_hop_jmp_target=lambda _project, target: target,
        branch_target_imm=lambda insn: getattr(insn, "target", None),
        branch_target_return_expr=lambda _project, _codegen, _target: _const(1, codegen),
        clone_c_value=lambda expr: expr,
        expr_fingerprint=lambda expr, _project: f"const:{expr.value}" if isinstance(expr, CConstant) else repr(expr),
    )

    assert not materialize_complex_decrement_switch_return_chain_8616(project, codegen, callbacks)
    assert codegen.cfunc.statements is None


def test_structuring_selector_function_has_unsafe_effects_flags_memory_write():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    insn = SimpleNamespace(
        address=0x1000,
        mnemonic="mov",
        insn=SimpleNamespace(operands=(_mem_operand(4, -2, 2), _reg_operand(1))),
    )
    callbacks = SelectorUnsafeEffectsCallbacks8616(
        function_inventory=lambda _project, _codegen: _complete_instruction_inventory(insn),
        direct_call_target=lambda _insn: None,
        callee_name_for_target=lambda _project, _target: (None, None),
        target_is_stack_probe_helper=lambda _project, _target, _name: False,
    )

    assert selector_function_has_unsafe_effects_8616(project, codegen, callbacks)


def test_structuring_selector_function_has_unsafe_effects_allows_proven_condition_call():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    insn = SimpleNamespace(address=0x1010, size=3, mnemonic="call", operands=(), target=0x2000)
    callbacks = SelectorUnsafeEffectsCallbacks8616(
        function_inventory=lambda _project, _codegen: _complete_instruction_inventory(insn),
        direct_call_target=lambda local_insn: getattr(local_insn, "target", None),
        callee_name_for_target=lambda _project, _target: ("compare_selector", object()),
        target_is_stack_probe_helper=lambda _project, _target, _name: False,
    )

    assert not selector_function_has_unsafe_effects_8616(project, codegen, callbacks, allowed_call_addrs=frozenset({0x1010}))


def test_structuring_selector_function_has_unsafe_effects_flags_indirect_call():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    insn = SimpleNamespace(address=0x1010, size=3, mnemonic="call", operands=(), target=None)
    callbacks = SelectorUnsafeEffectsCallbacks8616(
        function_inventory=lambda _project, _codegen: _complete_instruction_inventory(insn),
        direct_call_target=lambda _insn: None,
        callee_name_for_target=lambda _project, _target: (None, None),
        target_is_stack_probe_helper=lambda _project, _target, _name: False,
    )

    assert selector_function_has_unsafe_effects_8616(project, codegen, callbacks)


def _complete_instruction_inventory(*insns: object) -> FunctionInstructionInventory8616:
    return FunctionInstructionInventory8616(
        function_entry=0x1000,
        block_addrs=(0x1000,),
        instructions=insns,
        status=FunctionInstructionInventoryStatus8616.COMPLETE,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
    )


def test_structuring_selector_function_refuses_incomplete_instruction_inventory():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen()
    inventory = FunctionInstructionInventory8616(
        function_entry=0x1000,
        block_addrs=(0x1000,),
        instructions=(),
        status=FunctionInstructionInventoryStatus8616.DECODE_REFUSED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=1,
    )
    callbacks = SelectorUnsafeEffectsCallbacks8616(
        function_inventory=lambda _project, _codegen: inventory,
        direct_call_target=lambda _insn: None,
        callee_name_for_target=lambda _project, _target: (None, None),
        target_is_stack_probe_helper=lambda _project, _target, _name: False,
    )

    assert selector_function_has_unsafe_effects_8616(project, codegen, callbacks)


def test_structuring_resolve_one_hop_jmp_target_reads_jump_stub():
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(SimpleNamespace(mnemonic="jmp", target=0x1200),)))

    target = resolve_one_hop_jmp_target_8616(
        0x1000,
        lambda addr: block if addr == 0x1000 else None,
        lambda insn: getattr(insn, "target", None),
    )

    assert target == 0x1200


def test_structuring_resolve_one_hop_jmp_target_keeps_non_jump_target():
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(SimpleNamespace(mnemonic="mov", target=0x1200),)))

    target = resolve_one_hop_jmp_target_8616(
        0x1000,
        lambda _addr: block,
        lambda insn: getattr(insn, "target", None),
    )

    assert target == 0x1000


def test_structuring_resolve_one_hop_jmp_target_keeps_target_when_block_load_fails():
    def _raise(_addr):
        raise RuntimeError("block unavailable")

    assert resolve_one_hop_jmp_target_8616(0x1000, _raise, lambda _insn: None) == 0x1000


def test_structuring_branch_target_return_value_reads_immediate_ax_return():
    block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _Insn("mov", (_reg_operand(1), _imm_operand(0xFFFF))),
                _Insn("ret"),
            )
        )
    )

    value = branch_target_return_value_8616(
        0x1000,
        lambda _addr: block,
        lambda imm: imm - 0x10000 if imm & 0x8000 else imm,
    )

    assert value == -1


def test_structuring_branch_target_return_value_refuses_non_ax_or_control_boundary():
    dx_block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn("mov", (_reg_operand(2), _imm_operand(7))),)))
    branch_block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn("jmp"), _Insn("mov", (_reg_operand(1), _imm_operand(7))))))

    assert branch_target_return_value_8616(0x1000, lambda _addr: dx_block, lambda imm: imm) is None
    assert branch_target_return_value_8616(0x1000, lambda _addr: branch_block, lambda imm: imm) is None


def test_structuring_combine_dx_ax_return_expr_builds_signed_32bit_constant():
    codegen = _DummyCodegen()

    expr = combine_dx_ax_return_expr_8616(
        _const(0xFFFE, codegen),
        _const(0xFFFF, codegen),
        codegen,
        lambda _expr: None,
        lambda _offset, _size: None,
    )

    assert isinstance(expr, CConstant)
    assert expr.value == -2


def test_structuring_combine_dx_ax_return_expr_prefers_adjacent_wide_stack_slot():
    codegen = _DummyCodegen()
    ax_expr = object()
    dx_expr = object()
    wide_expr = object()

    expr = combine_dx_ax_return_expr_8616(
        ax_expr,
        dx_expr,
        codegen,
        lambda value: 4 if value is ax_expr else 6 if value is dx_expr else None,
        lambda offset, size: wide_expr if (offset, size) == (4, 4) else None,
    )

    assert expr is wide_expr


def test_structuring_combine_dx_ax_return_expr_preserves_nonconstant_dx_ax_pair():
    codegen = _DummyCodegen()
    ax_expr = CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    dx_expr = CVariable(
        SimRegisterVariable(6, 2, name="dx"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    expr = combine_dx_ax_return_expr_8616(
        ax_expr,
        dx_expr,
        codegen,
        lambda _expr: None,
        lambda _offset, _size: None,
    )

    assert isinstance(expr, CBinaryOp)
    assert expr.op == "Or"
    assert isinstance(expr.lhs, CBinaryOp)
    assert expr.lhs.op == "Shl"
    assert isinstance(expr.lhs.lhs, CTypeCast)
    assert expr.lhs.lhs.expr is dx_expr
    assert isinstance(expr.rhs, CTypeCast)
    assert expr.rhs.expr is ax_expr


def test_terminal_ax_fallback_accepts_only_known_single_register_widths():
    assert terminal_ax_fallback_supports_widths_8616((8,))
    assert terminal_ax_fallback_supports_widths_8616((16, 16))
    assert not terminal_ax_fallback_supports_widths_8616((16, 32))
    assert not terminal_ax_fallback_supports_widths_8616((None,))
    assert not terminal_ax_fallback_supports_widths_8616(())


def test_structuring_branch_target_return_expr_follows_callback_jump_target():
    terminal_expr = object()
    blocks = {
        0x1000: SimpleNamespace(name="jump"),
        0x1200: SimpleNamespace(name="terminal"),
    }

    expr = branch_target_return_expr_8616(
        0x1000,
        lambda addr: blocks.get(addr),
        lambda block: BranchTargetReturnBlockResult8616(
            next_target=0x1200
        ) if block.name == "jump" else BranchTargetReturnBlockResult8616(expr=terminal_expr),
    )

    assert expr is terminal_expr


def test_structuring_branch_target_return_expr_refuses_seen_target_cycle():
    blocks = {
        0x1000: SimpleNamespace(name="first"),
        0x1200: SimpleNamespace(name="second"),
    }

    expr = branch_target_return_expr_8616(
        0x1000,
        lambda addr: blocks.get(addr),
        lambda block: BranchTargetReturnBlockResult8616(next_target=0x1200 if block.name == "first" else 0x1000),
    )

    assert expr is None


def test_structuring_branch_target_return_expr_refuses_past_max_depth():
    blocks = {addr: SimpleNamespace(addr=addr) for addr in (0x1000, 0x1010, 0x1020)}
    next_by_addr = {0x1000: 0x1010, 0x1010: 0x1020, 0x1020: 0x1030}

    expr = branch_target_return_expr_8616(
        0x1000,
        lambda addr: blocks.get(addr),
        lambda block: BranchTargetReturnBlockResult8616(next_target=next_by_addr[int(block.addr)]),
        max_depth=1,
    )

    assert expr is None


def test_structuring_scan_branch_target_return_block_uses_semantic_effects():
    calls: list[tuple[str, int, int]] = []

    def _combine(ax_value, dx_value):
        calls.append(("combine", int(ax_value or 0), int(dx_value or 0)))
        return ax_value

    result = scan_branch_target_return_block_8616(
        _block(
            _Insn("mov", [_reg_operand(1), _imm_operand(2)]),
            _Insn("add", [_reg_operand(1), _imm_operand(3)]),
            _Insn("ret"),
        ),
        BranchTargetReturnScanCallbacks8616(
            branch_target_imm=lambda _insn: None,
            combine_return_expr=_combine,
            materialize_reg_imm=lambda raw_imm: raw_imm,
            materialize_stack_load=lambda offset, size: ("stack", offset, size),
            materialize_direct_global_load=lambda offset, size: ("global", offset, size),
            materialize_ax_alu_imm=lambda ax_value, op, raw_imm: int(ax_value) + raw_imm if op == "Add" else None,
            materialize_ax_incdec=lambda ax_value, op: int(ax_value) + 1 if op == "Add" else int(ax_value) - 1,
        ),
    )

    assert result == BranchTargetReturnBlockResult8616(expr=5)
    assert calls == [("combine", 5, 0)]


def test_structuring_scan_branch_target_return_block_recovers_register_self_clear():
    result = scan_branch_target_return_block_8616(
        _block(
            _Insn("sub", [_reg_operand(1), _reg_operand(1)]),
            _Insn("ret"),
        ),
        BranchTargetReturnScanCallbacks8616(
            branch_target_imm=lambda _insn: None,
            combine_return_expr=lambda ax_value, _dx_value: ax_value,
            materialize_reg_imm=lambda raw_imm: raw_imm,
            materialize_stack_load=lambda offset, size: ("stack", offset, size),
            materialize_direct_global_load=lambda offset, size: ("global", offset, size),
            materialize_ax_alu_imm=lambda _ax_value, _op, _raw_imm: None,
            materialize_ax_incdec=lambda _ax_value, _op: None,
        ),
    )

    assert result == BranchTargetReturnBlockResult8616(expr=0)


def test_structuring_return_epilogue_block_accepts_frame_teardown_return():
    block = _block(
        _Insn("nop"),
        _Insn("mov", [_reg_operand(3), _reg_operand(4)]),
        _Insn("pop"),
        _Insn("ret"),
    )

    assert return_epilogue_block_8616(block) is True


def test_structuring_return_epilogue_block_rejects_work_before_return():
    block = _block(
        _Insn("mov", [_reg_operand(1), _imm_operand(3)]),
        _Insn("ret"),
    )

    assert return_epilogue_block_8616(block) is False


def test_structuring_terminal_value_block_addrs_filters_epilogue_jumps():
    blocks = {
        0x1000: _block(_Insn("mov", [_reg_operand(1), _imm_operand(7)]), _target_insn("jmp", 0x1200)),
        0x1010: _block(_Insn("mov", [_reg_operand(1), _imm_operand(9)]), _target_insn("jmp", 0x1300)),
        0x1200: _block(_Insn("mov", [_reg_operand(3), _reg_operand(4)]), _Insn("ret")),
        0x1300: _block(_Insn("mov", [_reg_operand(1), _imm_operand(1)]), _Insn("ret")),
    }

    addrs = terminal_value_block_addrs_8616(
        (0x1010, 0x1000),
        lambda addr: blocks.get(addr),
        lambda insn: getattr(insn, "target", None),
    )

    assert addrs == (0x1000,)


def test_structuring_linear_terminal_ax_scan_returns_combined_expr_at_return():
    terminal_expr = object()
    processed: list[str] = []
    block = _block(_Insn("mov", [_reg_operand(1), _imm_operand(7)]), _Insn("ret"))

    def _process(insn, effect: TerminalAxReturnEffect8616) -> TerminalAxInstructionAction8616:
        processed.append(str(insn.mnemonic))
        assert effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_IMM
        assert effect.dst_reg == "ax"
        assert effect.imm == 7
        return TerminalAxInstructionAction8616(classified=True)

    result = linear_terminal_ax_return_scan_8616(
        (0x1000,),
        lambda addr: block if addr == 0x1000 else None,
        lambda insn: getattr(insn, "target", None),
        TerminalAxScanCallbacks8616(
            combined_return_expr=lambda: terminal_expr,
            process_instruction=_process,
        ),
    )

    assert result.expr is terminal_expr
    assert result.raw_insns == 2
    assert result.classified == 1
    assert result.terminal_value_block_count == 1
    assert processed == ["mov"]


def test_structuring_terminal_call_result_materializes_exact_cfg_proven_return():
    codegen = _DummyCodegen()
    call = CFunctionCall("apply_twice", None, [], tags={"ins_addr": 0x104}, codegen=codegen)
    root = CStatements(
        statements=[
            CExpressionStatement(call, tags={"ins_addr": 0x104}, codegen=codegen),
            CReturn(None, tags={"ins_addr": 0x10D}, codegen=codegen),
        ],
        codegen=codegen,
    )
    blocks = {
        0x100: _block(_insn_at(0x104, _Insn("call"))),
        0x106: _block(
            _insn_at(0x106, _Insn("add", [_reg_operand(3), _imm_operand(4)])),
            _insn_at(0x109, _target_insn("jmp", 0x10B)),
        ),
        0x10B: _block(
            _insn_at(0x10B, _Insn("pop", [_reg_operand(4)])),
            _insn_at(0x10C, _Insn("ret")),
        ),
    }

    stats = materialize_terminal_call_result_return_8616(
        root,
        codegen,
        caller_use=CallerReturnUseVerdict8616.USED,
        callbacks=_terminal_call_callbacks(
            blocks,
            ((0x100, 6), (0x106, 5), (0x10B, 2)),
            {0x100: (0x106,), 0x106: (0x10B,), 0x10B: ()},
        ),
    )

    assert stats.status is TerminalCallResultReturnStatus8616.MATERIALIZED
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)
    assert stats.path_block_addrs == (0x100, 0x106, 0x10B)
    assert len(root.statements) == 1
    assert isinstance(root.statements[0], CReturn)
    assert root.statements[0].retval is call
    assert root.statements[0].tags == {"ins_addr": 0x10D}


def test_structuring_terminal_call_result_connects_adjacent_transparent_wrappers():
    codegen = _DummyCodegen()
    call = CFunctionCall("apply_twice", None, [], tags={"ins_addr": 0x104}, codegen=codegen)
    call_wrapper = CStatements(
        statements=[CExpressionStatement(call, codegen=codegen)],
        codegen=codegen,
    )
    return_wrapper = CStatements(
        statements=[CReturn(None, tags={"ins_addr": 0x109}, codegen=codegen)],
        codegen=codegen,
    )
    root = CStatements(statements=[call_wrapper, return_wrapper], codegen=codegen)
    callbacks = _terminal_call_callbacks(
        {
            0x100: _block(_insn_at(0x104, _Insn("call"))),
            0x106: _block(_insn_at(0x106, _Insn("ret"))),
        },
        ((0x100, 6), (0x106, 1)),
        {0x100: (0x106,), 0x106: ()},
    )

    stats = materialize_terminal_call_result_return_8616(
        root,
        codegen,
        caller_use=CallerReturnUseVerdict8616.USED,
        callbacks=callbacks,
    )

    assert stats.status is TerminalCallResultReturnStatus8616.MATERIALIZED
    assert len(root.statements) == 1
    assert isinstance(root.statements[0], CReturn)
    assert root.statements[0].retval is call
    assert root.statements[0].tags == {"ins_addr": 0x109}


def test_structuring_terminal_call_result_folds_exact_carrier_return():
    codegen = _DummyCodegen()
    call = CFunctionCall("apply_twice", None, [], tags={"ins_addr": 0x104}, codegen=codegen)
    carrier = CVariable(
        SimRegisterVariable(0, 2, name="result"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call_container = CStatements(
        statements=[
            CExpressionStatement(_const(1, codegen), codegen=codegen),
            CAssignment(carrier, call, codegen=codegen),
        ],
        codegen=codegen,
    )
    return_container = CStatements(
        statements=[
            CExpressionStatement(_const(2, codegen), codegen=codegen),
            CReturn(carrier, tags={"ins_addr": 0x109}, codegen=codegen),
        ],
        codegen=codegen,
    )
    root = CStatements(
        statements=[call_container, return_container], codegen=codegen
    )

    stats = materialize_terminal_call_result_return_8616(
        root,
        codegen,
        caller_use=CallerReturnUseVerdict8616.USED,
        callbacks=_terminal_call_callbacks(
            {
                0x100: _block(_insn_at(0x104, _Insn("call"))),
                0x106: _block(_insn_at(0x106, _Insn("ret"))),
            },
            ((0x100, 6), (0x106, 1)),
            {0x100: (0x106,), 0x106: ()},
        ),
    )

    assert stats.status is TerminalCallResultReturnStatus8616.MATERIALIZED
    assert len(call_container.statements) == 1
    assert len(return_container.statements) == 2
    assert isinstance(return_container.statements[1], CReturn)
    assert return_container.statements[1].retval is call
    assert return_container.statements[1].tags == {"ins_addr": 0x109}


def test_structuring_terminal_call_result_is_idempotent_after_materialization():
    codegen = _DummyCodegen()
    call = CFunctionCall("apply_twice", None, [], tags={"ins_addr": 0x104}, codegen=codegen)
    root = CStatements(statements=[CReturn(call, codegen=codegen)], codegen=codegen)
    callbacks = _terminal_call_callbacks(
        {
            0x100: _block(_insn_at(0x104, _Insn("call"))),
            0x106: _block(_insn_at(0x106, _Insn("ret"))),
        },
        ((0x100, 6), (0x106, 1)),
        {0x100: (0x106,), 0x106: ()},
    )

    stats = materialize_terminal_call_result_return_8616(
        root,
        codegen,
        caller_use=CallerReturnUseVerdict8616.USED,
        callbacks=callbacks,
    )

    assert stats.status is TerminalCallResultReturnStatus8616.ALREADY_MATERIALIZED
    assert stats.classified_fact_count == stats.materialized_count == 1
    assert tuple(root.statements) == (root.statements[0],)
    assert root.statements[0].retval is call


def test_structuring_terminal_call_result_refuses_unproven_caller_use():
    codegen = _DummyCodegen()
    call = CFunctionCall("apply_twice", None, [], tags={"ins_addr": 0x104}, codegen=codegen)
    call_statement = CExpressionStatement(call, codegen=codegen)
    empty_return = CReturn(None, codegen=codegen)
    root = CStatements(statements=[call_statement, empty_return], codegen=codegen)

    stats = materialize_terminal_call_result_return_8616(
        root,
        codegen,
        caller_use=CallerReturnUseVerdict8616.UNKNOWN,
        callbacks=_terminal_call_callbacks({}, (), {}),
    )

    assert stats.status is TerminalCallResultReturnStatus8616.CALLER_USE_NOT_PROVEN
    assert stats.failure_count == 1
    assert tuple(root.statements) == (call_statement, empty_return)


def test_structuring_terminal_call_result_closed_unused_overrides_local_carrier():
    codegen = _DummyCodegen()
    call = CFunctionCall("outtext", None, [], tags={"ins_addr": 0x104}, codegen=codegen)
    carrier = CVariable(
        SimRegisterVariable(0, 2, name="result"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = CAssignment(carrier, call, codegen=codegen)
    returned_carrier = CReturn(carrier, codegen=codegen)
    root = CStatements([assignment, returned_carrier], codegen=codegen)

    stats = materialize_terminal_call_result_return_8616(
        root,
        codegen,
        caller_use=CallerReturnUseVerdict8616.UNUSED,
        callbacks=_terminal_call_callbacks({}, (), {}),
    )

    assert stats.status is TerminalCallResultReturnStatus8616.CALLER_USE_PROVEN_UNUSED
    assert stats.materialized_count == stats.failure_count == 0
    assert tuple(root.statements) == (assignment, returned_carrier)


@pytest.mark.parametrize(
    ("result_contract", "expected_status"),
    (
        (TerminalCallResultContract8616.VOID, TerminalCallResultReturnStatus8616.CALLEE_RETURNS_VOID),
        (
            TerminalCallResultContract8616.UNKNOWN,
            TerminalCallResultReturnStatus8616.CALLEE_RESULT_CONTRACT_UNKNOWN,
        ),
    ),
)
def test_structuring_terminal_call_result_refuses_nonvalue_callee_contract(result_contract, expected_status):
    codegen = _DummyCodegen()
    call = CFunctionCall("outtext", None, [], tags={"ins_addr": 0x104}, codegen=codegen)
    call_statement = CExpressionStatement(call, codegen=codegen)
    empty_return = CReturn(None, codegen=codegen)
    root = CStatements(statements=[call_statement, empty_return], codegen=codegen)
    callbacks = _terminal_call_callbacks(
        {},
        (),
        {},
        call_result_contract=lambda _call: result_contract,
    )

    stats = materialize_terminal_call_result_return_8616(
        root,
        codegen,
        caller_use=CallerReturnUseVerdict8616.USED,
        callbacks=callbacks,
    )

    assert stats.status is expected_status
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
    assert tuple(root.statements) == (call_statement, empty_return)


def test_structuring_terminal_call_result_refuses_missing_exact_call_tag():
    codegen = _DummyCodegen()
    call = CFunctionCall("apply_twice", None, [], codegen=codegen)
    root = CStatements(
        statements=[CExpressionStatement(call, codegen=codegen), CReturn(None, codegen=codegen)],
        codegen=codegen,
    )

    stats = materialize_terminal_call_result_return_8616(
        root,
        codegen,
        caller_use=CallerReturnUseVerdict8616.USED,
        callbacks=_terminal_call_callbacks({}, (), {}),
    )

    assert stats.status is TerminalCallResultReturnStatus8616.CALL_TAG_MISSING
    assert stats.normalized_fact_count == 0
    assert stats.failure_count == 1
    assert len(root.statements) == 2


def test_structuring_terminal_call_result_refuses_ax_clobber_after_call():
    codegen = _DummyCodegen()
    call = CFunctionCall("apply_twice", None, [], tags={"ins_addr": 0x104}, codegen=codegen)
    root = CStatements(
        statements=[CExpressionStatement(call, codegen=codegen), CReturn(None, codegen=codegen)],
        codegen=codegen,
    )
    blocks = {
        0x100: _block(
            _insn_at(0x104, _Insn("call")),
            _insn_at(0x106, _Insn("mov", [_reg_operand(1), _imm_operand(0)])),
            _insn_at(0x109, _Insn("ret")),
        )
    }

    stats = materialize_terminal_call_result_return_8616(
        root,
        codegen,
        caller_use=CallerReturnUseVerdict8616.USED,
        callbacks=_terminal_call_callbacks(blocks, ((0x100, 10),), {0x100: ()}),
    )

    assert stats.status is TerminalCallResultReturnStatus8616.UNSAFE_POST_CALL_EFFECT
    assert stats.path_block_addrs == (0x100,)
    assert stats.materialized_count == 0
    assert len(root.statements) == 2


def test_structuring_terminal_call_result_refuses_ambiguous_cfg_successors():
    codegen = _DummyCodegen()
    call = CFunctionCall("apply_twice", None, [], tags={"ins_addr": 0x104}, codegen=codegen)
    root = CStatements(
        statements=[CExpressionStatement(call, codegen=codegen), CReturn(None, codegen=codegen)],
        codegen=codegen,
    )
    blocks = {0x100: _block(_insn_at(0x104, _Insn("call")))}

    stats = materialize_terminal_call_result_return_8616(
        root,
        codegen,
        caller_use=CallerReturnUseVerdict8616.USED,
        callbacks=_terminal_call_callbacks(
            blocks,
            ((0x100, 6), (0x106, 1), (0x108, 1)),
            {0x100: (0x106, 0x108)},
        ),
    )

    assert stats.status is TerminalCallResultReturnStatus8616.CFG_PATH_AMBIGUOUS
    assert stats.failure_count == 1
    assert len(root.statements) == 2


def test_structuring_terminal_call_result_refuses_non_adjacent_ast_pair():
    codegen = _DummyCodegen()
    call = CFunctionCall("apply_twice", None, [], tags={"ins_addr": 0x104}, codegen=codegen)
    root = CStatements(
        statements=[
            CExpressionStatement(call, codegen=codegen),
            CAssignment(_const(0, codegen), _const(1, codegen), codegen=codegen),
            CReturn(None, codegen=codegen),
        ],
        codegen=codegen,
    )

    stats = materialize_terminal_call_result_return_8616(
        root,
        codegen,
        caller_use=CallerReturnUseVerdict8616.USED,
        callbacks=_terminal_call_callbacks({}, (), {}),
    )

    assert stats.status is TerminalCallResultReturnStatus8616.NON_ADJACENT_CALL_RETURN
    assert stats.raw_fact_count == stats.failure_count == 1
    assert len(root.statements) == 3


def test_structuring_linear_terminal_ax_scan_refuses_conditional_branch_before_return():
    terminal_expr = object()
    block = _block(_Insn("jne"), _Insn("ret"))

    result = linear_terminal_ax_return_scan_8616(
        (0x1000,),
        lambda addr: block if addr == 0x1000 else None,
        lambda insn: getattr(insn, "target", None),
        TerminalAxScanCallbacks8616(
            combined_return_expr=lambda: terminal_expr,
            process_instruction=lambda _insn, _effect: TerminalAxInstructionAction8616(classified=True),
        ),
    )

    assert result.expr is None
    assert result.raw_insns == 2
    assert result.classified == 0


def test_structuring_linear_terminal_ax_scan_accepts_jump_to_epilogue():
    terminal_expr = object()
    processed: list[str] = []
    blocks = {
        0x1000: _block(_Insn("mov", [_reg_operand(1), _imm_operand(7)]), _target_insn("jmp", 0x1200)),
        0x1200: _block(_Insn("mov", [_reg_operand(3), _reg_operand(4)]), _Insn("ret")),
    }

    def _process(insn, effect: TerminalAxReturnEffect8616) -> TerminalAxInstructionAction8616:
        processed.append(str(insn.mnemonic))
        assert effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_IMM
        assert effect.dst_reg == "ax"
        assert effect.imm == 7
        return TerminalAxInstructionAction8616(classified=True)

    result = linear_terminal_ax_return_scan_8616(
        (0x1000, 0x1200),
        lambda addr: blocks.get(addr),
        lambda insn: getattr(insn, "target", None),
        TerminalAxScanCallbacks8616(
            combined_return_expr=lambda: terminal_expr,
            process_instruction=_process,
        ),
    )

    assert result.expr is terminal_expr
    assert result.raw_insns == 2
    assert result.classified == 1
    assert result.terminal_value_block_count == 1
    assert processed == ["mov"]


def test_structuring_linear_terminal_ax_scan_refuses_materialization_abort():
    block = _block(_Insn("mov", [_reg_operand(1), _imm_operand(7)]), _Insn("ret"))

    result = linear_terminal_ax_return_scan_8616(
        (0x1000,),
        lambda addr: block if addr == 0x1000 else None,
        lambda insn: getattr(insn, "target", None),
        TerminalAxScanCallbacks8616(
            combined_return_expr=object,
            process_instruction=lambda _insn, _effect: TerminalAxInstructionAction8616(abort=True),
        ),
    )

    assert result.expr is None
    assert result.raw_insns == 1
    assert result.classified == 0


def test_structuring_linear_terminal_ax_scan_passes_semantic_effect_to_callback():
    effects: list[TerminalAxReturnEffectKind8616] = []
    block = _block(_Insn("call"), _Insn("ret"))

    result = linear_terminal_ax_return_scan_8616(
        (0x1000,),
        lambda addr: block if addr == 0x1000 else None,
        lambda insn: getattr(insn, "target", None),
        TerminalAxScanCallbacks8616(
            combined_return_expr=lambda: object(),
            process_instruction=lambda _insn, effect: effects.append(effect.kind)
            or TerminalAxInstructionAction8616(classified=True),
        ),
    )

    assert result.expr is not None
    assert effects == [TerminalAxReturnEffectKind8616.CALL_CLOBBER]


def test_structuring_linear_terminal_ax_scan_passes_ax_alu_effect_to_callback():
    effects: list[tuple[TerminalAxReturnEffectKind8616, str | None]] = []
    block = _block(_Insn("mov", [_reg_operand(1), _imm_operand(7)]), _Insn("inc", [_reg_operand(1)]), _Insn("ret"))

    result = linear_terminal_ax_return_scan_8616(
        (0x1000,),
        lambda addr: block if addr == 0x1000 else None,
        lambda insn: getattr(insn, "target", None),
        TerminalAxScanCallbacks8616(
            combined_return_expr=lambda: object(),
            process_instruction=lambda _insn, effect: effects.append((effect.kind, effect.op))
            or TerminalAxInstructionAction8616(classified=True),
        ),
    )

    assert result.expr is not None
    assert effects == [
        (TerminalAxReturnEffectKind8616.MOV_REG_IMM, None),
        (TerminalAxReturnEffectKind8616.AX_INCDEC, "Add"),
    ]


def test_structuring_linear_terminal_ax_scan_passes_shift_combine_effects_to_callback():
    effects: list[tuple[TerminalAxReturnEffectKind8616, str | None, int | None]] = []
    block = _block(
        _Insn("shl", [_reg_operand(5), _imm_operand(1)]),
        _Insn("shr", [_reg_operand(1), _reg_operand(6)]),
        _Insn("shl", [_reg_operand(7), _imm_operand(8)]),
        _Insn("or", [_reg_operand(1), _reg_operand(7)]),
        _Insn("ret"),
    )

    result = linear_terminal_ax_return_scan_8616(
        (0x1000,),
        lambda addr: block if addr == 0x1000 else None,
        lambda insn: getattr(insn, "target", None),
        TerminalAxScanCallbacks8616(
            combined_return_expr=lambda: object(),
            process_instruction=lambda _insn, effect: effects.append((effect.kind, effect.op, effect.imm))
            or TerminalAxInstructionAction8616(classified=True),
        ),
    )

    assert result.expr is not None
    assert effects == [
        (TerminalAxReturnEffectKind8616.AL_SHL_IMM, "Shl", 1),
        (TerminalAxReturnEffectKind8616.AX_SHR_CL, "Shr", None),
        (TerminalAxReturnEffectKind8616.CX_SHL_IMM, "Shl", 8),
        (TerminalAxReturnEffectKind8616.AX_OR_CX, "Or", None),
    ]


def test_last_ax_return_value_uses_last_signed_immediate_ax_move():
    project = SimpleNamespace()
    codegen = SimpleNamespace()
    insns = (
        _Insn("mov", (_reg_operand(1), _imm_operand(1))),
        _Insn("mov", (_reg_operand(2), _imm_operand(2))),
        _Insn("add", (_reg_operand(1), _imm_operand(3))),
        _Insn("mov", (_reg_operand(1), _imm_operand(0xFFFF))),
    )

    value = last_ax_return_value_8616(
        project,
        codegen,
        LastAxReturnValueCallbacks8616(
            function_insns=lambda received_project, received_codegen: (
                insns if received_project is project and received_codegen is codegen else ()
            ),
            signed_i16_immediate=lambda raw: raw - 0x10000 if raw & 0x8000 else raw,
        ),
    )

    assert value == -1


def test_last_ax_return_value_refuses_non_immediate_or_non_ax_moves():
    value = last_ax_return_value_8616(
        SimpleNamespace(),
        SimpleNamespace(),
        LastAxReturnValueCallbacks8616(
            function_insns=lambda _project, _codegen: (
                _Insn("mov", (_reg_operand(2), _imm_operand(9))),
                _Insn("mov", (_reg_operand(1), _reg_operand(2))),
            ),
            signed_i16_immediate=lambda raw: raw,
        ),
    )

    assert value is None
def test_structuring_collapses_surplus_identical_assignment_arms() -> None:
    codegen = _DummyCodegen()
    real_condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    artifact_condition = CConstant(2, SimTypeShort(False), codegen=codegen)
    artifact_condition.tags = {"ins_addr": 0x2000, "vex_block_addr": 0x1FF0}
    real_if = CIfElse(
        [(real_condition, CStatements([], codegen=codegen))],
        codegen=codegen,
    )
    carrier = CConstant(3, SimTypeShort(False), codegen=codegen)
    value = CConstant(4, SimTypeShort(False), codegen=codegen)
    assignment = CAssignment(carrier, value, codegen=codegen)
    artifact_if = CIfElse(
        [
            (
                artifact_condition,
                CStatements([assignment], codegen=codegen),
            )
        ],
        else_node=CStatements(
            [CAssignment(carrier, value, codegen=codegen)],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = CStatements([real_if, artifact_if], codegen=codegen)

    stats = collapse_surplus_identical_assignment_arms_8616(
        root,
        SimpleNamespace(),
        branch_count=1,
        expression_callbacks=ExpressionFingerprintCallbacks8616(
            expr_fingerprint=lambda expr, _project: repr(expr),
            iter_c_nodes_deep=lambda node: tuple(
                child
                for child in (
                    getattr(node, "statements", ())
                    or getattr(node, "condition_and_nodes", ())
                    or ()
                )
                if not isinstance(child, tuple)
            ),
        ),
        branch_callbacks=ConditionBranchTagCallbacks8616(
            condition_tags=lambda condition: (
                condition.tags["ins_addr"],
                condition.tags["vex_block_addr"],
            ),
            load_block=lambda _addr: SimpleNamespace(
                capstone=SimpleNamespace(insns=(SimpleNamespace(mnemonic="imul"),)),
            ),
            is_conditional_branch_insn=lambda insn: insn.mnemonic.startswith("j"),
        ),
    )

    assert stats.status is IdenticalAssignmentArmCollapseStatus8616.MATERIALIZED
    assert stats.raw_fact_count == 2
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert root.statements == [real_if, assignment]
