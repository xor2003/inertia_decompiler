"""Shared-DAG resource accounting for ``flat32_call_contracts._term_nodes``.

Layer: tests.
Responsibility: pin the resource-owner counting contract — each distinct
dict node of a shared-subexpression DAG is charged once while outbound
slots, traversal depth and cycles stay bounded — so composed call states
refuse only when the retained DAG itself exceeds ``max_term_nodes``.  The
second half proves both staged ``flat32_region`` adapters delegate to that
owner instead of occurrence-counting shared references, on synthetic terms
and on a real i386 doubled-add function.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane
from tools.dosunit.tests.test_flat32_conditional_boundaries import _scan_region

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import (
    _TERM_DEPTH_LIMIT,
    _TERM_EDGE_FACTOR,
    _term_nodes,
)

LIMIT = 12000  # CallCompositionLimits.max_term_nodes default.


def _const(value: int) -> dict[str, Any]:
    return {"op": "const", "value": hex(value), "width": 32}


def _input(name: str) -> dict[str, Any]:
    return {"op": "input", "name": name, "width": 32}


def _op(op: str, *args: Any) -> dict[str, Any]:
    return {"op": op, "width": 32, "args": list(args)}


def _diamond_chain(depth: int) -> dict[str, Any]:
    """Chain where each level references the previous one twice (a DAG)."""
    node = _input("eax")
    for _ in range(depth):
        node = _op("add", node, node)
    return node


def _unary_chain(depth: int) -> dict[str, Any]:
    """Strictly nested unary chain; each level adds two traversal depths."""
    node = _input("eax")
    for _ in range(depth):
        node = _op("neg", node)
    return node


def test_shared_subexpression_counts_distinct_nodes() -> None:
    """A 14-level diamond reaches ~32k occurrences but retains 15 nodes.

    This is the BC5 false-refusal shape: occurrence counting stopped at
    12001 on a live DAG of 136 distinct dictionaries.
    """
    assert _term_nodes(_diamond_chain(14), LIMIT) == 15


def test_shared_reference_charged_once() -> None:
    """One dict referenced by two parents is a single node."""
    leaf = _const(7)
    assert _term_nodes(_op("add", leaf, leaf), LIMIT) == 2


def test_depth_guard_includes_a_previously_visited_shared_suffix() -> None:
    """Root ordering cannot hide an over-deep path through a shared suffix."""
    shared = _unary_chain(_TERM_DEPTH_LIMIT // 4)
    deep = shared
    for _ in range(_TERM_DEPTH_LIMIT // 4):
        deep = _op("neg", deep)
    for state in ({"shallow": shared, "deep": deep}, {"deep": deep, "shallow": shared}):
        assert _term_nodes(state, LIMIT) > LIMIT


def test_equal_but_distinct_dicts_not_merged() -> None:
    """Dedup is identity-only: structurally equal dicts are two nodes."""
    assert _term_nodes(_op("add", _const(5), _const(5)), LIMIT) == 3


def test_exact_limit_boundary() -> None:
    """Exactly ``max_term_nodes`` distinct dicts passes; one more refuses."""
    root = _op("select", *[_input(f"r{i}") for i in range(LIMIT - 1)])
    assert _term_nodes(root, LIMIT) == LIMIT


def test_distinct_nodes_over_limit_refuse() -> None:
    """A genuinely large unique tree still trips the node budget."""
    root = _op("select", *[_input(f"r{i}") for i in range(LIMIT)])
    assert _term_nodes(root, LIMIT) > LIMIT


def test_deep_chain_refuses_below_recursion_headroom() -> None:
    """A chain deeper than the depth cap refuses before recursive consumers."""
    assert _term_nodes(_unary_chain(_TERM_DEPTH_LIMIT), LIMIT) > LIMIT


def test_deep_chain_under_cap_counts() -> None:
    """A chain inside the depth cap still counts normally."""
    depth = _TERM_DEPTH_LIMIT // 4
    assert _term_nodes(_unary_chain(depth), LIMIT) == depth + 1


def test_dag_with_shared_node_and_deep_path_refuses() -> None:
    """Sharing inside an over-deep region does not hide the depth refusal."""
    inner = _unary_chain(10)
    shallow = _op("neg", inner)
    tail = inner
    for _ in range(_TERM_DEPTH_LIMIT // 2):
        tail = _op("neg", tail)
    root = _op("add", shallow, tail)
    assert _term_nodes(root, LIMIT) > LIMIT


def test_dict_cycle_refuses_boundedly() -> None:
    """A dict reachable from itself is a real cycle, not shared structure."""
    node: dict[str, Any] = {"op": "neg", "width": 32, "args": []}
    node["args"] = [node]
    assert _term_nodes(node, LIMIT) > LIMIT


def test_list_cycle_refuses_boundedly() -> None:
    loop: list[Any] = []
    loop.append(loop)
    assert _term_nodes(_op("add", loop), LIMIT) > LIMIT


def test_tuple_cycle_refuses_boundedly() -> None:
    holder: list[Any] = []
    pair = (holder, _const(0))
    holder.append(pair)
    assert _term_nodes(_op("add", pair), LIMIT) > LIMIT


class _GiantScalarList(list):
    """List whose declared length alone must trip the edge guard.

    ``__len__`` reports an over-budget size; every access path raises, so a
    passing walk proves the guard fires before any child is queued.
    """

    def __len__(self) -> int:
        return _TERM_EDGE_FACTOR * LIMIT + 1

    def __reversed__(self) -> Any:
        raise AssertionError("traversal iterated a container already over budget")

    def __getitem__(self, index: Any) -> Any:
        raise AssertionError("traversal indexed a container already over budget")


def test_giant_scalar_list_refuses_before_iteration() -> None:
    """A scalar-only payload beyond the edge budget refuses without a copy."""
    assert _term_nodes(_op("add", _GiantScalarList()), LIMIT) > LIMIT


def test_giant_dict_metadata_refuses() -> None:
    """Scalar-only dict fan-out beyond the edge budget refuses boundedly."""
    root = {f"k{i}": i for i in range(_TERM_EDGE_FACTOR * LIMIT + 1)}
    assert _term_nodes(root, LIMIT) > LIMIT


def test_materialization_preserves_shared_refs_and_scalar_terms() -> None:
    """The same DAG materializes to compact refs; leaf terms keep semantics."""
    input_term = _input("eax")
    const_term = _const(1)
    shared = {"op": "add", "width": 32, "args": [input_term, const_term]}
    root = _op("mul", shared, shared)
    assert _term_nodes(root, LIMIT) <= LIMIT
    assignments: list[dict[str, Any]] = []
    out = S._materialize_json_term(root, assignments=assignments, memo={}, term_cache={})
    assert out == {"ref": "v1"}
    assert [item["id"] for item in assignments] == ["v0", "v1"]
    # The shared subexpression materializes once; both parents reference it.
    assert assignments[1]["args"] == [{"ref": "v0"}, {"ref": "v0"}]
    # Scalar leaves pass through with identical solver-visible content.
    assert assignments[0]["args"] == [input_term, const_term]
    assert assignments[0]["args"][0] is not input_term


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_adapter_term_counter_is_shared_owner(driver: str) -> None:
    """Each staged region adapter binds the shared counter, not a local copy."""
    with _driver_lane(driver) as lane:
        assert lane.region._term_nodes is _term_nodes


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_adapter_shared_diamond_counts_distinct_nodes(driver: str) -> None:
    """A 14-level diamond keeps 15 nodes under each adapter's budget."""
    with _driver_lane(driver) as lane:
        assert lane.region._term_nodes(_diamond_chain(14), LIMIT) == 15


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_adapter_term_guards_still_refuse(driver: str) -> None:
    """Adapter accounting retains the shared depth, edge and cycle bounds."""
    cyclic: dict[str, Any] = {"op": "neg", "width": 32, "args": []}
    cyclic["args"] = [cyclic]
    with _driver_lane(driver) as lane:
        assert lane.region._term_nodes(_unary_chain(_TERM_DEPTH_LIMIT), LIMIT) > LIMIT
        assert lane.region._term_nodes(_op("add", _GiantScalarList()), LIMIT) > LIMIT
        assert lane.region._term_nodes(cyclic, LIMIT) > LIMIT


# Fourteen `add eax, eax` doublings then ret. Each add's args reference the
# same inlined term twice, so the retained eax DAG has 15 distinct dicts but
# ~32k occurrences: occurrence counting falsely refused expression_limit.
DOUBLED_ADD = "01c0 " * 14 + "c3"
# Same shape with the last add sourcing ecx (`add eax, ecx`): must still fail.
DOUBLED_ADD_CHANGED = "01c0 " * 13 + "01c8 c3"


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_real_doubled_add_region_proves_under_dag_budget(tmp_path: Path, driver: str) -> None:
    """Real i386 doubled adds stay under the node budget and compare honestly.

    Equal bytes must now prove instead of hitting ``region_expression_limit``;
    the changed-arithmetic candidate and a genuinely tiny budget still fail or
    refuse, so the fix cannot mask real divergence or unbounded terms.
    """
    with _driver_lane(driver) as lane, lane.adapter.installed(region=True):
        oracle = _scan_region(DOUBLED_ADD, tmp_path)
        changed = _scan_region(DOUBLED_ADD_CHANGED, tmp_path)
        equal = lane.region.compare_region(oracle, oracle, outputs=("eax", "esp"), timeout_ms=3000)
        unequal = lane.region.compare_region(oracle, changed, outputs=("eax", "esp"), timeout_ms=3000)
        tiny = lane.region.compare_region(
            oracle,
            oracle,
            outputs=("eax", "esp"),
            timeout_ms=3000,
            limits=lane.region.RegionLimits(max_term_nodes=5),
        )
    assert equal["status"] == "passed", equal
    assert unequal["status"] == "failed", unequal
    assert tiny["status"] == "refused" and tiny["reason"] == "region_expression_limit", tiny
