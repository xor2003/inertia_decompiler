"""Regression tests for identity-safe protected structured call arguments."""

from itertools import count
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
from angr_platforms.X86_16.lowering.call_argument_call_preservation import (
    classify_call_argument_call_preservation_8616,
)
from angr_platforms.X86_16.lowering.call_argument_state import (
    ProtectedCallArgument8616,
    ProtectedCallArgumentStore8616,
)


def test_protected_call_argument_store_refuses_reused_object_id_entry() -> None:
    """A stale entry must not attach to a different regenerated call object."""
    stale_call = object()
    live_call = object()
    stale_expression = object()
    live_expression = object()
    key = (id(live_call), 0)
    store = ProtectedCallArgumentStore8616(
        entries={key: ProtectedCallArgument8616(stale_call, stale_expression, 10)}
    )

    assert store.get(live_call, 0) is None

    store.remember(live_call, 0, live_expression, 1)

    entry = store.get(live_call, 0)
    assert entry is not None
    assert entry.expression is live_expression


def test_argument_replacement_refuses_losing_embedded_machine_call() -> None:
    """A register carrier cannot replace the call whose standalone copy is gone."""
    indices = count()
    codegen = SimpleNamespace(next_node_idx=lambda: next(indices), next_ident=lambda name: name)
    producer = CFunctionCall("sub_1234", None, [], tags={"ins_addr": 0x20}, codegen=codegen)

    result = classify_call_argument_call_preservation_8616([producer], [object()])

    assert not result.preserves_calls
    assert result.raw_fact_count == result.normalized_fact_count == result.classified_fact_count == 1
    assert result.materialized_count == 0
    assert result.failure_count == 1


def test_argument_replacement_counts_shared_call_occurrences() -> None:
    """DAG identity must not hide a lost evaluation of a shared call node."""
    indices = count()
    codegen = SimpleNamespace(next_node_idx=lambda: next(indices), next_ident=lambda name: name)
    producer = CFunctionCall("sub_1234", None, [], tags={"ins_addr": 0x20}, codegen=codegen)
    clone = CFunctionCall("renamed", None, [], tags={"ins_addr": 0x20}, codegen=codegen)

    preserved = classify_call_argument_call_preservation_8616([producer], [clone])
    lost = classify_call_argument_call_preservation_8616([producer, producer], [clone])

    assert preserved.preserves_calls
    assert preserved.materialized_count == 1
    assert not lost.preserves_calls
    assert lost.classified_fact_count == 2
    assert lost.materialized_count == lost.failure_count == 1


def test_argument_replacement_does_not_match_different_machine_calls() -> None:
    """Equal target spelling is not equal instruction provenance."""
    indices = count()
    codegen = SimpleNamespace(next_node_idx=lambda: next(indices), next_ident=lambda name: name)
    producer = CFunctionCall("sub_1234", None, [], tags={"ins_addr": 0x20}, codegen=codegen)
    other = CFunctionCall("sub_1234", None, [], tags={"ins_addr": 0x30}, codegen=codegen)

    assert not classify_call_argument_call_preservation_8616([producer], [other]).preserves_calls
    assert classify_call_argument_call_preservation_8616([object()], [object()]).preserves_calls
