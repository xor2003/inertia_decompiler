"""Normalize VEX-only condition transport loads at the IR import boundary.

Layer: IR.
Responsibility: identify exact duplicate loads emitted for an x86-16 JCC and
bind their VEX temporary to the immediately preceding CMP-owned value.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
It never changes frontend VEX or infers alias identity.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, cast

from .core import IRAddress, IRInstr, IRValue

__all__ = [
    "VexConditionTransportLayout8616",
    "VexConditionTransportNormalizer8616",
    "VexConditionTransportStats8616",
    "aggregate_vex_condition_transport_stats_8616",
    "build_vex_condition_transport_layout_8616",
]


class _VexStatementBoundary(Protocol):
    """Minimal pyvex statement fields used to recover instruction layout."""

    tag: object
    addr: object


class _VexWriteTmpBoundary(Protocol):
    """WrTmp fields used to bind expressions to VEX temporaries."""

    tmp: object
    data: object


class _VexExitBoundary(Protocol):
    """Exit field used to prove a temporary reaches the branch guard."""

    guard: object


class _VexExpressionBoundary(Protocol):
    """Expression fields used to trace temporary dependencies."""

    tag: object
    tmp: object
    args: object
    cond: object
    iftrue: object
    iffalse: object


@dataclass(frozen=True, slots=True)
class VexConditionTransportLayout8616:
    """Typed instruction layout needed to prove one transport-only load."""

    exit_instruction_addrs: frozenset[int]
    predecessor_pairs: tuple[tuple[int, int], ...]
    transport_load_tmps: frozenset[tuple[int, int]]

    def predecessor_of(self, instruction_addr: int) -> int | None:
        """Return the immediately preceding IMark address, when present."""
        return next(
            (
                predecessor
                for current, predecessor in self.predecessor_pairs
                if current == instruction_addr
            ),
            None,
        )

    def owns_transport_load(self, instruction_addr: int, tmp_id: int) -> bool:
        """Return whether this exact load temporary reaches the Exit guard."""
        return (instruction_addr, tmp_id) in self.transport_load_tmps


@dataclass(frozen=True, slots=True)
class VexConditionTransportStats8616:
    """Closed evidence counters for removed VEX condition transport loads."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every exact candidate was classified and rebound."""
        return bool(
            self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count
            == self.materialized_count + self.failure_count
        )

    def to_summary(self) -> dict[str, int]:
        """Serialize counters with an owner-specific summary prefix."""
        return {
            "condition_transport_raw_fact_count": self.raw_fact_count,
            "condition_transport_normalized_fact_count": self.normalized_fact_count,
            "condition_transport_classified_fact_count": self.classified_fact_count,
            "condition_transport_materialized_count": self.materialized_count,
            "condition_transport_failure_count": self.failure_count,
        }


def _statement_tag_8616(statement: object) -> str:
    """Read one tag at the dynamic pyvex statement boundary."""
    try:
        return str(cast(_VexStatementBoundary, statement).tag)
    except AttributeError:
        return ""


def _imark_addr_8616(statement: object) -> int | None:
    """Read one IMark address at the dynamic pyvex statement boundary."""
    try:
        return int(cast(Any, cast(_VexStatementBoundary, statement).addr))
    except (AttributeError, TypeError, ValueError):
        return None


def _statement_tmp_8616(statement: object) -> int | None:
    """Read one WrTmp identifier at the dynamic pyvex boundary."""
    try:
        return int(cast(Any, cast(_VexWriteTmpBoundary, statement).tmp))
    except (AttributeError, TypeError, ValueError):
        return None


def _statement_data_8616(statement: object) -> object | None:
    """Read one WrTmp expression at the dynamic pyvex boundary."""
    try:
        return cast(_VexWriteTmpBoundary, statement).data
    except AttributeError:
        return None


def _statement_guard_8616(statement: object) -> object | None:
    """Read one Exit guard at the dynamic pyvex boundary."""
    try:
        return cast(_VexExitBoundary, statement).guard
    except AttributeError:
        return None


def _expression_tag_8616(expression: object | None) -> str:
    """Read one expression tag at the dynamic pyvex boundary."""
    if expression is None:
        return ""
    try:
        return str(cast(_VexExpressionBoundary, expression).tag)
    except AttributeError:
        return ""


def _expression_tmp_8616(expression: object) -> int | None:
    """Read one RdTmp identifier at the dynamic pyvex boundary."""
    try:
        return int(cast(Any, cast(_VexExpressionBoundary, expression).tmp))
    except (AttributeError, TypeError, ValueError):
        return None


def _expression_args_8616(expression: object | None) -> tuple[object, ...]:
    """Read child expressions at the dynamic pyvex boundary."""
    if expression is None:
        return ()
    boundary = cast(_VexExpressionBoundary, expression)
    if _expression_tag_8616(expression) == "Iex_ITE":
        try:
            return boundary.cond, boundary.iftrue, boundary.iffalse
        except AttributeError:
            return ()
    try:
        args = boundary.args
    except AttributeError:
        return ()
    if isinstance(args, tuple):
        return args
    if isinstance(args, list):
        return tuple(args)
    return ()


def _guard_load_tmps_8616(
    expression: object | None,
    tmp_exprs: dict[int, object],
    load_sites: dict[int, int],
    instruction_addr: int,
    seen: set[int] | None = None,
) -> frozenset[int]:
    """Return current-instruction load temporaries reaching one Exit guard."""
    visited = set() if seen is None else seen
    result: set[int] = set()
    if _expression_tag_8616(expression) == "Iex_RdTmp" and expression is not None:
        tmp_id = _expression_tmp_8616(expression)
        if tmp_id is None or tmp_id in visited:
            return frozenset()
        visited.add(tmp_id)
        if load_sites.get(tmp_id) == instruction_addr:
            result.add(tmp_id)
        source = tmp_exprs.get(tmp_id)
        if source is not None:
            result.update(
                _guard_load_tmps_8616(
                    source,
                    tmp_exprs,
                    load_sites,
                    instruction_addr,
                    visited,
                )
            )
    for child in _expression_args_8616(expression):
        result.update(
            _guard_load_tmps_8616(
                child,
                tmp_exprs,
                load_sites,
                instruction_addr,
                visited,
            )
        )
    return frozenset(result)


def build_vex_condition_transport_layout_8616(
    statements: tuple[object, ...],
) -> VexConditionTransportLayout8616:
    """Build exact IMark predecessor and Exit ownership facts."""
    current_addr: int | None = None
    previous_addr: int | None = None
    predecessors: dict[int, int] = {}
    exit_addrs: set[int] = set()
    tmp_exprs: dict[int, object] = {}
    load_sites: dict[int, int] = {}
    transport_load_tmps: set[tuple[int, int]] = set()
    for statement in statements:
        tag = _statement_tag_8616(statement)
        if tag == "Ist_IMark":
            candidate = _imark_addr_8616(statement)
            if candidate is None:
                current_addr = None
                continue
            if current_addr is not None and candidate != current_addr:
                previous_addr = current_addr
            current_addr = candidate
            if previous_addr is not None and previous_addr != current_addr:
                predecessors[current_addr] = previous_addr
            continue
        if tag == "Ist_WrTmp":
            tmp_id = _statement_tmp_8616(statement)
            data = _statement_data_8616(statement)
            if tmp_id is not None and data is not None:
                tmp_exprs[tmp_id] = data
                if current_addr is not None and _expression_tag_8616(data) == "Iex_Load":
                    load_sites[tmp_id] = current_addr
            continue
        if tag == "Ist_Exit" and current_addr is not None:
            exit_addrs.add(current_addr)
            transport_load_tmps.update(
                (current_addr, tmp_id)
                for tmp_id in _guard_load_tmps_8616(
                    _statement_guard_8616(statement),
                    tmp_exprs,
                    load_sites,
                    current_addr,
                )
            )
    return VexConditionTransportLayout8616(
        frozenset(exit_addrs),
        tuple(sorted(predecessors.items())),
        frozenset(transport_load_tmps),
    )


def _load_key_8616(instruction: IRInstr) -> tuple[IRAddress, int] | None:
    """Return exact segmented identity for one imported load."""
    address = instruction.args[0] if instruction.args else None
    if (
        instruction.op != "LOAD"
        or instruction.addr is None
        or not isinstance(address, IRAddress)
    ):
        return None
    return address, instruction.size


@dataclass(slots=True)
class VexConditionTransportNormalizer8616:
    """Track imported loads and rebind only proven JCC transport duplicates."""

    layout: VexConditionTransportLayout8616
    _loads: dict[tuple[int, IRAddress, int], IRValue] = field(default_factory=dict, init=False)
    _materialized_count: int = field(default=0, init=False)

    def observe_load(
        self,
        instruction: IRInstr,
        loaded_value: IRValue,
        tmp_id: int,
    ) -> IRValue | None:
        """Return a prior CMP value when this load is exact JCC transport."""
        key = _load_key_8616(instruction)
        if key is None or instruction.addr is None:
            return None
        address, size = key
        instruction_addr = instruction.addr
        predecessor_addr = self.layout.predecessor_of(instruction_addr)
        replacement = None
        if (
            instruction_addr in self.layout.exit_instruction_addrs
            and self.layout.owns_transport_load(instruction_addr, tmp_id)
            and predecessor_addr is not None
        ):
            replacement = self._loads.get((predecessor_addr, address, size))
        self._loads[(instruction_addr, address, size)] = loaded_value
        if replacement is not None:
            self._materialized_count += 1
        return replacement

    def stats(self) -> VexConditionTransportStats8616:
        """Return closed counters for all exact transport candidates seen."""
        count = self._materialized_count
        return VexConditionTransportStats8616(count, count, count, count, 0)


def aggregate_vex_condition_transport_stats_8616(
    reports: tuple[VexConditionTransportStats8616, ...],
) -> VexConditionTransportStats8616:
    """Aggregate per-block transport counters and enforce closure."""
    result = VexConditionTransportStats8616(
        raw_fact_count=sum(report.raw_fact_count for report in reports),
        normalized_fact_count=sum(report.normalized_fact_count for report in reports),
        classified_fact_count=sum(report.classified_fact_count for report in reports),
        materialized_count=sum(report.materialized_count for report in reports),
        failure_count=sum(report.failure_count for report in reports),
    )
    if not result.closed:
        raise ValueError("VEX condition transport normalization did not close")
    return result
