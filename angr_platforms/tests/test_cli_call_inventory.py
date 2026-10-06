"""Fresh call observations preserve rewrite guards without duplicate walks."""

from __future__ import annotations

import copy
from types import MethodType, SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CFunctionCall

from inertia_decompiler import cli_decompilation as cli


class _Calls:
    """Minimal third-party-shaped container around real angr call nodes."""

    __module__ = "angr.analyses.decompiler.structured_codegen.c"
    __slots__ = ("calls",)

    def __init__(self, names: tuple[str, ...]) -> None:
        indices = iter(range(10000))
        codegen = SimpleNamespace(
            next_node_idx=lambda: next(indices), next_ident=lambda _kind: "call"
        )
        self.calls = [
            CFunctionCall(callee_target=name, callee_func=None, args=[], codegen=codegen)
            for name in names
        ]


def _state(names=("a", "b"), *, guard=True, expected=("a", "b"), state_type=SimpleNamespace):
    """Bind production guard methods; snapshots always use the live tree."""
    state = state_type(
        dec=SimpleNamespace(codegen=SimpleNamespace(cfunc=SimpleNamespace(statements=_Calls(names)))),
        project=SimpleNamespace(arch=SimpleNamespace(name="86_16")),
        function=SimpleNamespace(addr=0x1000), current_func_addr=0x1000,
        pass_name="test", call_loss_guard_active=guard,
        expected_call_guard_active=bool(expected), expected_non_prologue_calls=expected,
        semantic_call_helper_names=frozenset({"helper_sem"}),
        before_calls=0, after_calls=0, before_missing=(), after_missing=(),
        iter_changed=False, _stack_lowering_already_attempted=False,
        _run_stack_lowering_pass=object(), stack_lowering_dirty=False,
    )
    for name in (
        "_is_semantic_codegen_call", "_codegen_call_inventory_8616",
        "_missing_expected_call_names_8616", "_missing_expected_call_names_from_codegen_counts",
        "_rewrite_round_apply_8616", "_rewrite_round_guarded_evidence_8616",
        "_rewrite_round_prepare_8616", "_rewrite_round_8616",
    ):
        setattr(state, name, MethodType(getattr(cli._DecompileRun8616, name), state))
    state._snapshot_codegen_cfunc = lambda: copy.deepcopy(state.dec.codegen.cfunc.statements)

    def restore(snapshot):
        state.dec.codegen.cfunc.statements = copy.deepcopy(snapshot)
        return True

    state._restore_codegen_cfunc = restore
    return state


@pytest.mark.parametrize("guard", [False, True])
@pytest.mark.parametrize("expected", [(), ("a", "b")])
@pytest.mark.parametrize("changed", [False, True])
def test_one_walk_per_required_observation(monkeypatch, guard, expected, changed):
    """Disabled guards do no work; enabled guards share each fresh walk."""
    state = _state(guard=guard, expected=expected)
    original = cli._iter_c_nodes_deep
    walks = []

    def count(root):
        walks.append(root)
        return original(root)

    monkeypatch.setattr(cli, "_iter_c_nodes_deep", count)
    state._rewrite_round_apply_8616(lambda: changed, 0, 0)
    assert len(walks) == int(guard or bool(expected)) + int(guard and changed)


def test_empty_expected_query_does_not_walk(monkeypatch):
    """An empty expected-name obligation retains its original fast path."""
    state = _state(expected=())

    def forbidden(_root):
        raise AssertionError("no expected calls require no traversal")

    monkeypatch.setattr(cli, "_iter_c_nodes_deep", forbidden)
    assert state._missing_expected_call_names_from_codegen_counts() == ()


def test_walk_shared_node_keeps_last_container_occurrence():
    """Per-field alias suppression preserves the existing observable order."""
    root, first, middle = _Calls(()), _Calls(()), _Calls(())
    root.calls = [first, middle, first]
    assert list(cli._iter_c_nodes_deep(root)) == [root, middle, first]


def test_walk_observes_shared_container_mutation_after_yield():
    """A later parent sees edits made while consuming an earlier child."""
    root, left, right, first, added = (_Calls(()) for _ in range(5))
    shared = [first]
    left.calls = right.calls = shared
    root.calls = [left, right]
    observed = []
    for node in cli._iter_c_nodes_deep(root):
        observed.append(node)
        if node is first:
            shared.append(added)
    assert observed == [root, left, first, right, added]


def test_walk_container_and_node_cycles_terminate():
    """Container cycles and node aliases must neither loop nor hide siblings."""
    root, child = _Calls(()), _Calls(())
    cycle = [child, root]
    cycle.append(cycle)
    root.calls = cycle
    assert list(cli._iter_c_nodes_deep(root)) == [root, child]


def test_histogram_preserves_multiplicity_and_helper_exclusion():
    state = _state(names=("a", "a", "b", "helper_sem"), expected=("a", "a", "a", "b"))
    observed = state._codegen_call_inventory_8616(with_names=True)
    assert observed.total == 3
    assert observed.name_counts == {"a": 2, "b": 1}
    assert state._missing_expected_call_names_8616(observed.name_counts) == ("a(2/3)",)
    unnamed = state._codegen_call_inventory_8616(with_names=False)
    assert unnamed.total == 3
    assert unnamed.name_counts == {}


@pytest.mark.parametrize("named_loss", [False, True])
@pytest.mark.parametrize("restorable", [False, True])
def test_loss_requires_successful_restore(named_loss, restorable):
    """Total-count and equal-count named loss retain independent guards."""
    state = _state()
    if not restorable:
        state._restore_codegen_cfunc = lambda _snapshot: False

    def lose():
        state.dec.codegen.cfunc.statements = _Calls(("a", "c") if named_loss else ("a",))
        return True

    if not restorable:
        with pytest.raises(cli.PipelineHardError):
            state._rewrite_round_apply_8616(lose, 0, 0)
        return
    state._rewrite_round_apply_8616(lose, 0, 0)
    assert state.iter_changed is False
    assert [call.callee_target for call in state.dec.codegen.cfunc.statements.calls] == ["a", "b"]
    state._rewrite_round_apply_8616(lambda: False, 0, 1)
    assert state.before_calls == 2
    assert state.before_missing == ()


def test_silent_change_is_observed_by_next_pass():
    """An incorrect unchanged report cannot make later evidence stale."""
    state = _state()

    def silent_add():
        state.dec.codegen.cfunc.statements = _Calls(("a", "b", "c"))
        return False

    def lose():
        state.dec.codegen.cfunc.statements.calls.pop()
        return True

    state._rewrite_round_apply_8616(silent_add, 0, 0)
    state._rewrite_round_apply_8616(lose, 0, 1)
    assert state.before_calls == 3
    assert state.after_calls == 2
    assert [call.callee_target for call in state.dec.codegen.cfunc.statements.calls] == ["a", "b", "c"]


def test_rewrite_exception_propagates():
    state = _state()

    def broken():
        raise ValueError("rewrite defect")

    with pytest.raises(ValueError, match="rewrite defect"):
        state._rewrite_round_apply_8616(broken, 0, 0)


class _BoundPassState(SimpleNamespace):
    """Exercise real bound-method lookup rather than a stable fake callable."""

    def _run_stack_lowering_pass(self) -> bool:
        """Count one stack pass with an unchanged tree."""
        self.lowering_calls += 1
        return False


def _bound_state():
    state = _state(guard=False, expected=(), state_type=_BoundPassState)
    del state._run_stack_lowering_pass
    state.lowering_calls = 0
    state.rewrite_pass_names = {}
    return state


def test_bound_stack_pass_skips_repeated_clean_attempts():
    """Fresh bound-method objects must still identify the same owned pass."""
    state = _bound_state()
    state.rewrite_passes = (state._run_stack_lowering_pass, state._run_stack_lowering_pass)
    assert not state._rewrite_round_8616(0)
    assert state.lowering_calls == 1
    assert state._stack_lowering_already_attempted
    assert not state._rewrite_round_8616(1)
    assert state.lowering_calls == 1


def test_changed_rewrite_makes_stack_pass_eligible_again():
    """An accepted intervening edit requires one new stack-lowering attempt."""
    state = _bound_state()
    state.rewrite_passes = (state._run_stack_lowering_pass, lambda: True,
                           state._run_stack_lowering_pass, state._run_stack_lowering_pass)
    assert state._rewrite_round_8616(0)
    assert state.lowering_calls == 2
    assert not state.stack_lowering_dirty


def test_stack_pass_identity_includes_its_receiver():
    """The same method bound to another state is a distinct callback."""
    state, other = _bound_state(), _bound_state()
    state._stack_lowering_already_attempted = True
    state.rewrite_passes = (other._run_stack_lowering_pass, state._run_stack_lowering_pass)
    assert not state._rewrite_round_8616(0)
    assert other.lowering_calls == 1
    assert state.lowering_calls == 0
