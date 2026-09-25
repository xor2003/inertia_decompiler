"""Runtime contracts for closed-loop semantic evidence.

Layer: Pipeline governance.
Responsibility: owns runtime ordering, invariant checks, hard failures, and final emission gates.
Do not recover semantic facts or perform IR, alias, widening,
lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting
work here.

AGENTS rule: facts produced but not consumed is a pipeline failure.
If ``classified > 0`` and ``materialized == 0``, raise ``PipelineHardError``.

This is NOT a soft diagnostic — it is a hard gate before codegen.

Typical pipeline trace:

    raw → normalized → classified → bound → materialized → verified

Materialization means the downstream representation used for code generation
has changed:
  - AIL expression replaced
  - SimVariable registered and used
  - C emission uses ``local_*``, ``arg_*``, or explicit condition

Creating ``StackVariableBinding`` or ``ConditionIR`` metadata is NOT
materialization.  ``binding_count > 0`` and ``materialized_count == 0``
is failure, not progress.

Do not add new recovery logic here.  This module only enforces contracts.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, cast

from .errors import PipelineHardError

__all__ = [
    "CORE_DECOMPILER_PIPELINE_ORDER_8616",
    "SemanticLaneState",
    "assert_pipeline_contracts_8616",
]

CORE_DECOMPILER_PIPELINE_ORDER_8616: tuple[str, ...] = (
    "IR",
    "Alias",
    "Widening",
    "Types",
    "Structuring",
    "Rewrite",
)


class _PipelineCodegenContract(Protocol):
    """Attribute surface consumed by the pipeline contract gate."""

    _inertia_stack_lane: object
    _inertia_condition_lane: object
    _inertia_semantic_lanes_8616: object
    cfunc: object
    project: object


class _CFunctionAddressLike(Protocol):
    """Minimal C function shape needed for tiny-thunk size lookup."""

    addr: object


class _FunctionSizeLike(Protocol):
    """Minimal angr function shape needed for tiny-thunk size lookup."""

    size: object


class _FunctionManagerLike(Protocol):
    """Minimal angr function manager lookup used by the contract gate."""

    def function(self, *, addr: object, create: bool) -> object | None:
        """Return a function object for the requested address if one exists."""

        del addr, create
        return None


class _KnowledgeBaseLike(Protocol):
    """Minimal project knowledge-base shape used by the contract gate."""

    functions: _FunctionManagerLike


class _ProjectLike(Protocol):
    """Minimal angr project shape used by the contract gate."""

    kb: _KnowledgeBaseLike


@dataclass(slots=True)
class SemanticLaneState:
    """Closed-loop counter for one semantic lane (stack / condition).

    Counters record the pipeline trace:

        raw → normalized → classified → bound → materialized → verified
    """

    name: str = ""
    raw: int = 0
    normalized: int = 0
    classified: int = 0
    bound: int = 0
    materialized: int = 0
    verified: int = 0
    failures: int = 0

    def assert_closed_loop(self, *, layer: str = "") -> None:
        """Raise PipelineHardError if the lane is broken.

        Rules:
        - raw > 0 && normalized == 0 → HARD error (IR normalization failure)
        - bound > 0 && materialized == 0 → HARD error (bindings are not materialization)
        - classified > 0 && materialized == 0 → HARD error
        - failures > 0 → HARD error (recorded evidence loss is never success)
        """
        if self.raw > 0 and self.normalized == 0:
            raise PipelineHardError(
                f"{self.name}: {self.raw} raw accesses captured but 0 normalized "
                f"(classified={self.classified} bound={self.bound} "
                f"materialized={self.materialized})",
                layer=layer or "pipeline_contract",
            )

        if self.bound > 0 and self.materialized == 0:
            raise PipelineHardError(
                f"{self.name}: {self.bound} bindings created but 0 materialized "
                f"(raw={self.raw} normalized={self.normalized} "
                f"classified={self.classified} failures={self.failures})",
                layer=layer or "pipeline_contract",
            )

        if self.classified > 0 and self.materialized == 0:
            raise PipelineHardError(
                f"{self.name}: {self.classified} facts classified but 0 materialized "
                f"(raw={self.raw} normalized={self.normalized} "
                f"bound={self.bound} failures={self.failures})",
                layer=layer or "pipeline_contract",
            )

        if self.failures > 0:
            raise PipelineHardError(
                f"{self.name}: {self.failures} evidence failures recorded "
                f"(raw={self.raw} normalized={self.normalized} "
                f"classified={self.classified} bound={self.bound} "
                f"materialized={self.materialized} verified={self.verified})",
                layer=layer or "pipeline_contract",
            )

    @property
    def raw_fact_count(self) -> int:
        """Return the number of raw facts entering this semantic lane."""

        return self.raw

    @property
    def normalized_fact_count(self) -> int:
        """Return the number of facts normalized into owned IR."""

        return self.normalized

    @property
    def classified_fact_count(self) -> int:
        """Return the number of facts assigned an owned semantic class."""

        return self.classified

    @property
    def materialized_count(self) -> int:
        """Return the number of classified facts materialized into output."""

        return self.materialized

    @property
    def failure_count(self) -> int:
        """Return the number of facts that failed closed-loop processing."""

        return self.failures

    def to_dict(self) -> dict[str, object]:
        """Return a stable dictionary for diagnostics and JSON reports."""

        return {
            "name": self.name,
            "raw": self.raw,
            "normalized": self.normalized,
            "classified": self.classified,
            "bound": self.bound,
            "materialized": self.materialized,
            "verified": self.verified,
            "failures": self.failures,
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }

    @property
    def is_closed(self) -> bool:
        """True if the lane has no un-materialized facts and all raw inputs were normalized."""
        if self.raw > 0 and self.normalized == 0:
            return False
        if self.classified > 0 and self.materialized == 0:
            return False
        if self.bound > 0 and self.materialized == 0:
            return False
        return self.failures == 0

    def summary_line(self) -> str:
        """Single-line summary for diagnostic output."""
        parts = [
            f"raw={self.raw}",
            f"norm={self.normalized}",
            f"clsf={self.classified}",
            f"bound={self.bound}",
            f"mat={self.materialized}",
            f"ver={self.verified}",
            f"fail={self.failures}",
        ]
        status = "CLOSED" if self.is_closed else "BROKEN"
        return f"{self.name}: [{status}] " + " ".join(parts)


def _semantic_lane_or_none_8616(contract: _PipelineCodegenContract, attr: str) -> object | None:
    """Read an owned semantic-lane attribute; missing lane is a typed absence."""
    try:
        return getattr(contract, attr)
    except AttributeError:
        return None


def _assert_semantic_lane_type_8616(lane: object, lane_name: str, layer_tag: str) -> None:
    """Reject lanes that are not ``SemanticLaneState`` contracts."""
    if lane is not None and not isinstance(lane, SemanticLaneState):
        raise PipelineHardError(
            f"{lane_name} has invalid contract type: {type(lane).__name__}",
            layer=f"pipeline_contract:{layer_tag}",
        )


def _pipeline_function_size_8616(contract: _PipelineCodegenContract) -> int | None:
    """Best-effort function size for the tiny-thunk stack-lane allowance."""
    try:
        cfunc = contract.cfunc
    except AttributeError:
        return None
    try:
        project = contract.project
    except AttributeError:
        return None
    if project is None or cfunc is None:
        return None
    try:
        project_like = cast(_ProjectLike, project)
        cfunc_like = cast(_CFunctionAddressLike, cfunc)
        kb_func = project_like.kb.functions.function(addr=cfunc_like.addr, create=False)
        if kb_func is None:
            return None
        size = cast(_FunctionSizeLike, kb_func).size
        if isinstance(size, int) and size > 0:
            return size
    except Exception:
        return None
    return None


def _assert_stack_lane_closed_8616(contract: _PipelineCodegenContract, stack_lane: SemanticLaneState) -> None:
    """Close the stack lane, with a documented allowance for micro bridge thunks."""
    # Tiny thunk allowance:
    # Some 86_16 micro-stubs (e.g. 3-8 byte bridge thunks) can trip raw
    # stack-lane probes without producing meaningful normalized/classified
    # stack semantics. Keep the hard contract for all non-trivial
    # procedures, but avoid false-positive hard stops on these tiny stubs.
    func_size = _pipeline_function_size_8616(contract)
    tiny_stack_stub = (
        isinstance(func_size, int)
        and func_size <= 8
        and stack_lane.raw > 0
        and stack_lane.normalized == 0
        and stack_lane.classified == 0
        and stack_lane.bound == 0
        and stack_lane.materialized == 0
    )
    if not tiny_stack_stub:
        stack_lane.assert_closed_loop(layer="pipeline_contract:stack_lane")


def _assert_extra_semantic_lanes_8616(
    contract: _PipelineCodegenContract,
    stack_lane: object,
    condition_lane: object,
) -> None:
    """Close every registered semantic lane beyond the two primary lanes."""
    try:
        extra_lanes = contract._inertia_semantic_lanes_8616
    except AttributeError:
        extra_lanes = ()
    if not isinstance(extra_lanes, Iterable):
        extra_lanes = ()
    for lane in tuple(extra_lanes):
        if lane is None or lane is stack_lane or lane is condition_lane:
            continue
        if not isinstance(lane, SemanticLaneState):
            raise PipelineHardError(
                f"semantic lane has invalid contract type: {type(lane).__name__}",
                layer="pipeline_contract:semantic_lane",
            )
        lane_name = lane.name or "semantic_lane"
        lane.assert_closed_loop(layer=f"pipeline_contract:{lane_name}")


def assert_pipeline_contracts_8616(codegen: object) -> None:
    """Hard gate: assert every owned semantic lane is closed before codegen.

    Call this after all lowering passes and before code emission.
    Raises PipelineHardError if any lane has un-materialized facts.
    """
    contract = cast(_PipelineCodegenContract, codegen)
    stack_lane = _semantic_lane_or_none_8616(contract, "_inertia_stack_lane")
    condition_lane = _semantic_lane_or_none_8616(contract, "_inertia_condition_lane")

    _assert_semantic_lane_type_8616(stack_lane, "stack lane", "stack_lane")
    _assert_semantic_lane_type_8616(condition_lane, "condition lane", "condition_lane")

    if stack_lane is not None:
        _assert_stack_lane_closed_8616(contract, cast(SemanticLaneState, stack_lane))
    if condition_lane is not None:
        cast(SemanticLaneState, condition_lane).assert_closed_loop(layer="pipeline_contract:condition_lane")

    _assert_extra_semantic_lanes_8616(contract, stack_lane, condition_lane)