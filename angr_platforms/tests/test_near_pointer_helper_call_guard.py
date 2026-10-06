"""The owned NEAR_ARG_PTR wrapper is lowered representation, not a call edge.

Layer: Tests.
Responsibility: pin the typed representation-identity predicate exported by
Lowering and the CLI semantic-call counter that consumes it. A genuine
constructor-produced wrapper is excluded from call accounting while its real
argument calls stay counted; forged, bound, subclassed, or merely same-named
CFunctionCall nodes remain ordinary calls.
"""

from itertools import count
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.near_pointer_argument_values import (
    materialize_near_pointer_argument_value_8616,
)
from angr_platforms.X86_16.lowering.near_pointer_value_runtime import (
    NearPointerArgumentHelper8616,
)

_HELPER_TAG = "inertia_near_pointer_argument_helper"
_HELPER_NAME = NearPointerArgumentHelper8616.SINGLE_EVALUATION.value
# Fallback only for red-baseline runs that predate the owned constant.
_FALLBACK_HELPER_NAMES = {
    "Add", "And", "Concat", "Div", "MK_FP", "MEM_U16", "MEM_U32", "MEM_U8",
    "Mul", "Or", "Reference", "SEG_LINEAR", "SEG_PTR", "SEG_U16", "SEG_U32",
    "SEG_U8", "Sub", "Xor", "aNchkstk", "__aNchkstk",
}


def _owned_wrapper_predicate():
    """Import the owned identity predicate; red baselines fail here."""
    from angr_platforms.X86_16.lowering.near_pointer_argument_values import (
        is_near_pointer_argument_helper_call_8616,
    )
    return is_near_pointer_argument_helper_call_8616


@pytest.fixture
def codegen():
    indices = count()
    return SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        const_formats={},
        show_casts=True,
        cstyle_null_cmp=False,
        next_node_idx=lambda: next(indices),
        next_ident=lambda name: f"{name}_{next(indices)}",
        next_idx=lambda kind: next(indices),
    )


def _segment(codegen):
    return CConstant(0x1234, SimTypeShort(False), codegen=codegen)


def _offset(codegen):
    return CConstant(0x40, SimTypeShort(False), codegen=codegen)


def _make_wrapper(codegen, offset=None):
    """Produce a genuine wrapper through the real constructor path."""
    wrapped, changed = materialize_near_pointer_argument_value_8616(
        offset if offset is not None else _offset(codegen),
        _segment(codegen),
        codegen=codegen,
        c_target="portable-flat",
    )
    assert changed
    return wrapped


def _cli_state(codegen, statements):
    """Minimal run state that routes real call counting through the CLI method."""
    from inertia_decompiler import cli_decompilation

    codegen.cfunc = SimpleNamespace(statements=statements)
    state = SimpleNamespace(
        current_func_addr=0x1000,
        function=SimpleNamespace(addr=0x1000, name="probe"),
        pass_name="test",
        call_loss_guard_active=True,
        expected_call_guard_active=False,
        iter_changed=False,
        stack_lowering_dirty=False,
        large_x86_16_function=False,
        block_count=1,
        byte_count=0x10,
        dec=SimpleNamespace(codegen=codegen),
        project=codegen.project,
        semantic_call_helper_names=getattr(
            cli_decompilation, "_SEMANTIC_CODEGEN_HELPER_NAMES_8616", _FALLBACK_HELPER_NAMES
        ),
        _stack_lowering_already_attempted=False,
        _run_stack_lowering_pass=object(),
    )
    run = cli_decompilation._DecompileRun8616
    state._is_semantic_codegen_call = lambda node: run._is_semantic_codegen_call(state, node)
    state._codegen_call_expr_count = lambda: run._codegen_call_expr_count(state)
    state._codegen_call_inventory_8616 = lambda with_names: run._codegen_call_inventory_8616(state, with_names=with_names)
    state._snapshot_codegen_cfunc = lambda: run._snapshot_codegen_cfunc(state)
    state._restore_codegen_cfunc = lambda snapshot: run._restore_codegen_cfunc(state, snapshot)
    state._rewrite_round_guarded_evidence_8616 = lambda index, changed: (
        run._rewrite_round_guarded_evidence_8616(state, index, changed)
    )
    return state


def test_predicate_accepts_only_the_constructor_produced_wrapper(codegen):
    predicate = _owned_wrapper_predicate()
    wrapper = _make_wrapper(codegen)
    assert predicate(wrapper)
    # Idempotence is preserved: the same predicate suppresses re-wrapping.
    again, changed = materialize_near_pointer_argument_value_8616(
        wrapper, _segment(codegen), codegen=codegen, c_target="portable-flat",
    )
    assert again is wrapper
    assert not changed


def test_predicate_rejects_non_call_nodes(codegen):
    predicate = _owned_wrapper_predicate()
    assert not predicate(None)
    assert not predicate(_offset(codegen))
    assert not predicate(CExpressionStatement(_offset(codegen), codegen=codegen))


@pytest.mark.parametrize("mutation", [
    "untagged",
    "string_tag",
    "str_derived_tag",
    "wrong_target",
    "one_arg",
    "three_args",
    "callee_func",
    "subclass",
])
def test_predicate_rejects_impostor_calls(codegen, mutation):
    predicate = _owned_wrapper_predicate()
    segment, offset = _segment(codegen), _offset(codegen)
    tags = {_HELPER_TAG: NearPointerArgumentHelper8616.SINGLE_EVALUATION}
    if mutation == "untagged":
        node = CFunctionCall(_HELPER_NAME, None, [segment, offset], codegen=codegen)
    elif mutation == "string_tag":
        node = CFunctionCall(
            _HELPER_NAME, None, [segment, offset],
            tags={_HELPER_TAG: "NEAR_ARG_PTR"}, codegen=codegen,
        )
    elif mutation == "str_derived_tag":
        node = CFunctionCall(
            _HELPER_NAME, None, [segment, offset],
            tags={_HELPER_TAG: str(NearPointerArgumentHelper8616.SINGLE_EVALUATION)},
            codegen=codegen,
        )
    elif mutation == "wrong_target":
        node = CFunctionCall("NEAR_ARG_PTR_WIDE", None, [segment, offset], tags=dict(tags), codegen=codegen)
    elif mutation == "one_arg":
        node = CFunctionCall(_HELPER_NAME, None, [segment], tags=dict(tags), codegen=codegen)
    elif mutation == "three_args":
        node = CFunctionCall(
            _HELPER_NAME, None, [segment, offset, _offset(codegen)], tags=dict(tags), codegen=codegen,
        )
    elif mutation == "callee_func":
        node = CFunctionCall(
            None, SimpleNamespace(name=_HELPER_NAME), [segment, offset], tags=dict(tags), codegen=codegen,
        )
    else:
        class _ImpostorCall(CFunctionCall):
            pass

        node = _ImpostorCall(_HELPER_NAME, None, [segment, offset], tags=dict(tags), codegen=codegen)
    assert not predicate(node)


def test_cli_counter_excludes_wrapper_but_counts_nested_real_call(codegen):
    inner_call = CFunctionCall("next_offset", None, [], codegen=codegen)
    wrapper = _make_wrapper(codegen, offset=inner_call)
    real_call = CFunctionCall("io_emit", None, [], codegen=codegen)
    root = CStatements(
        [CExpressionStatement(wrapper, codegen=codegen), CExpressionStatement(real_call, codegen=codegen)],
        codegen=codegen,
    )
    state = _cli_state(codegen, root)
    # The wrapper is representation; its cloned call argument is still counted.
    assert not state._is_semantic_codegen_call(wrapper)
    assert state._is_semantic_codegen_call(real_call)
    assert state._codegen_call_expr_count() == 2


@pytest.mark.parametrize("mutation", ["untagged", "string_tag", "callee_func", "subclass"])
def test_cli_counter_still_counts_impostor_calls(codegen, mutation):
    segment, offset = _segment(codegen), _offset(codegen)
    if mutation == "untagged":
        node = CFunctionCall(_HELPER_NAME, None, [segment, offset], codegen=codegen)
    elif mutation == "string_tag":
        node = CFunctionCall(
            _HELPER_NAME, None, [segment, offset],
            tags={_HELPER_TAG: "NEAR_ARG_PTR"}, codegen=codegen,
        )
    elif mutation == "callee_func":
        node = CFunctionCall(
            None, SimpleNamespace(name=_HELPER_NAME), [segment, offset],
            tags={_HELPER_TAG: NearPointerArgumentHelper8616.SINGLE_EVALUATION},
            codegen=codegen,
        )
    else:
        class _ImpostorCall(CFunctionCall):
            pass

        node = _ImpostorCall(_HELPER_NAME, None, [segment, offset], codegen=codegen)
    state = _cli_state(codegen, CStatements([CExpressionStatement(node, codegen=codegen)], codegen=codegen))
    assert state._is_semantic_codegen_call(node)
    assert state._codegen_call_expr_count() == 1


def test_cli_counter_still_excludes_named_render_helpers(codegen):
    node = CFunctionCall("SEG_U8", None, [_segment(codegen)], codegen=codegen)
    state = _cli_state(codegen, CStatements([CExpressionStatement(node, codegen=codegen)], codegen=codegen))
    assert not state._is_semantic_codegen_call(node)


def test_rewrite_guard_allows_retiring_only_the_owned_wrapper(codegen, monkeypatch):
    """Removing the representation wrapper is not semantic call loss."""
    from inertia_decompiler import cli_decompilation

    wrapper = _make_wrapper(codegen)
    real_call = CFunctionCall("io_emit", None, [], codegen=codegen)
    kept = CStatements([CExpressionStatement(real_call, codegen=codegen)], codegen=codegen)
    root = CStatements(
        [CExpressionStatement(wrapper, codegen=codegen), CExpressionStatement(real_call, codegen=codegen)],
        codegen=codegen,
    )
    state = _cli_state(codegen, root)
    monkeypatch.setattr(
        cli_decompilation, "_debug_dump_rewrite_pass_lines_8616", lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        cli_decompilation, "function_original_addr", lambda function: function.addr,
    )

    def rewrite() -> bool:
        codegen.cfunc.statements = kept
        return True

    cli_decompilation._DecompileRun8616._rewrite_round_apply_8616(state, rewrite, 0, 23)
    # Only representation was retired: the guard must not roll back.
    assert state.after_calls == state.before_calls
    assert codegen.cfunc.statements is kept
    assert state.iter_changed is True


def test_rewrite_guard_restores_when_a_real_nested_call_is_removed(codegen, monkeypatch):
    """Removing a real call nested under the wrapper still raises/restores."""
    from inertia_decompiler import cli_decompilation

    inner_call = CFunctionCall("next_offset", None, [], codegen=codegen)
    wrapper = _make_wrapper(codegen, offset=inner_call)
    root = CStatements([CExpressionStatement(wrapper, codegen=codegen)], codegen=codegen)
    state = _cli_state(codegen, root)
    monkeypatch.setattr(
        cli_decompilation, "_debug_dump_rewrite_pass_lines_8616", lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        cli_decompilation, "function_original_addr", lambda function: function.addr,
    )
    stripped = CStatements([], codegen=codegen)

    def rewrite() -> bool:
        codegen.cfunc.statements = stripped
        return True

    cli_decompilation._DecompileRun8616._rewrite_round_apply_8616(state, rewrite, 0, 23)
    # The nested real call loss is rejected and the prior count is restored.
    assert codegen.cfunc.statements is not stripped
    assert state.iter_changed is False
    assert state._codegen_call_expr_count() == state.before_calls


def test_rewrite_guard_raises_when_call_loss_is_not_restorable(codegen, monkeypatch):
    """Without a snapshot, removing a real call fails closed, as before."""
    from angr_platforms.X86_16.pipeline.errors import PipelineHardError

    from inertia_decompiler import cli_decompilation

    real_call = CFunctionCall("io_emit", None, [], codegen=codegen)
    root = CStatements([CExpressionStatement(real_call, codegen=codegen)], codegen=codegen)
    state = _cli_state(codegen, root)
    # Over the snapshot size limit: no restorable snapshot is taken.
    state.block_count = 17
    monkeypatch.setattr(
        cli_decompilation, "_debug_dump_rewrite_pass_lines_8616", lambda *a, **kw: None,
    )
    monkeypatch.setattr(
        cli_decompilation, "function_original_addr", lambda function: function.addr,
    )
    stripped = CStatements([], codegen=codegen)

    def rewrite() -> bool:
        codegen.cfunc.statements = stripped
        return True

    with pytest.raises(PipelineHardError, match="removed call expressions"):
        cli_decompilation._DecompileRun8616._rewrite_round_apply_8616(state, rewrite, 0, 23)


def test_wrapper_identity_survives_snapshot_restore_round_trip(codegen):
    """A restored deepcopy still carries the enum tag, so it stays excluded."""
    predicate = _owned_wrapper_predicate()
    wrapper = _make_wrapper(codegen)
    root = CStatements([CExpressionStatement(wrapper, codegen=codegen)], codegen=codegen)
    state = _cli_state(codegen, root)
    snapshot = state._snapshot_codegen_cfunc()
    assert snapshot is not None
    assert state._restore_codegen_cfunc(snapshot)
    restored_wrapper = codegen.cfunc.statements.statements[0].expr
    assert predicate(restored_wrapper)
    assert state._codegen_call_expr_count() == 0
