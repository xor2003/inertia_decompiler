# cython: language_level=3, infer_types=True
"""Publish exact value-producer projections of CALL return-frame stores.

Layer: Semantics. Responsibility: derive store-to-producer relationships from
VEX data dependencies under exact CALL IMarks. Producers remain projections,
never stores. C/AIL shape, values, names, text, and address dependencies are out.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""
from __future__ import annotations
import typing
import cython

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, TypeGuard, cast

from inertia.pipeline.errors import PipelineHardError
import dataclasses
import operator
import builtins

DynamicValue = typing.TypeAliasType("DynamicValue", Any)


@dataclasses.dataclass(frozen=True, order=True)
class CallReturnFrameEffectKey8616:
    """Stable identity of one statement under one exact decoded CALL IMark."""

    callsite_addr: cython.longlong
    vex_block_addr: cython.longlong
    vex_stmt_idx: cython.longlong


class CallReturnFrameProjectionRole8616(StrEnum):
    """Semantic role of one structured projection of a machine frame store."""

    STORE_STATEMENT = "store_statement"
    VALUE_PRODUCER = "value_producer"


class CallReturnFrameProjectionRefusalReason8616(StrEnum):
    """Typed reason that producer ancestry was unsafe to publish."""

    IMARK_NOT_EXACT = "imark_not_exact"
    STORE_NOT_EXACT = "store_not_exact"
    INCOMPLETE_DEPENDENCY = "incomplete_dependency"
    AMBIGUOUS_DEFINITION = "ambiguous_definition"
    CYCLIC_DEPENDENCY = "cyclic_dependency"
    CROSS_CALLSITE_DEPENDENCY = "cross_callsite_dependency"
    SHARED_PRODUCER = "shared_producer"
    NON_FRAME_CONSUMER = "non_frame_consumer"


_Reason8616 = CallReturnFrameProjectionRefusalReason8616
_Role8616 = CallReturnFrameProjectionRole8616


@dataclasses.dataclass(frozen=True, )
class CallReturnFrameProjectionFact8616:
    """Exact relationship from a machine store to one surviving projection."""

    store_key: CallReturnFrameEffectKey8616
    projection_key: CallReturnFrameEffectKey8616
    role: CallReturnFrameProjectionRole8616


@dataclasses.dataclass(frozen=True, )
class CallReturnFrameProjectionRefusal8616:
    """One store ancestry refusal with every implicated producer statement."""

    store_key: CallReturnFrameEffectKey8616
    reason: CallReturnFrameProjectionRefusalReason8616
    producer_keys: object


@dataclasses.dataclass(frozen=True, )
class CallReturnFrameProjectionCollection8616:
    """Closed Semantics census for exact CALL-frame store projections."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    projections: object
    refusals: object

    @property
    def closed(self) -> cython.bint:
        """Return whether all store ancestries and published facts are counted."""
        return (
            0 <= self.normalized_fact_count <= self.raw_fact_count
            and operator.eq(self.normalized_fact_count + self.failure_count, self.raw_fact_count)
            and operator.eq(self.classified_fact_count, len(self.projections))
            and operator.eq(self.materialized_count, self.classified_fact_count)
        )


@dataclasses.dataclass(frozen=True, )
class _DependencyResult8616:
    producers: object
    reason: _Reason8616 | None
    implicated: object


class _DependencyRefusal8616(Exception):
    def __init__(
        self,
        reason: _Reason8616,
        indices: Iterable[cython.longlong] = (),
    ) -> None:
        super().__init__(reason.value)
        self.reason = reason
        self.indices = tuple(sorted(tuple(set(indices))))


@cython.ccall
def _is_int_8616(value: object) -> TypeGuard[cython.longlong]:
    return isinstance(value, int) and not isinstance(value, bool)


@cython.ccall
def _inventory_8616(
    statements: object,
) -> tuple[tuple[int | None, ...], dict[cython.longlong, tuple[cython.longlong, ...]], dict[cython.longlong, cython.longlong]]:
    owner: object
    index: object
    statement: object
    owners: list[int | None] = []
    definitions: dict[cython.longlong, list[cython.longlong]] = {}
    imark_counts: dict[cython.longlong, cython.longlong] = {}
    owner = None
    for index, statement in enumerate(statements):
        try:
            tag = statement.tag
        except AttributeError:
            owners.append(owner)
            continue
        if tag == "Ist_IMark":
            try:
                address = statement.addr
            except AttributeError:
                address = None
            owner = address if _is_int_8616(address) else None
            if owner is not None:
                imark_counts[owner] = imark_counts.get(owner, 0) + 1
        owners.append(owner)
        if tag == "Ist_WrTmp":
            try:
                temporary = statement.tmp
            except AttributeError:
                temporary = None
            if _is_int_8616(temporary):
                definitions.setdefault(temporary, []).append(index)
    return tuple(owners), {tmp: tuple(indices) for tmp, indices in builtins.iter(definitions.items())}, imark_counts


@cython.ccall
def _refuse_dependency_8616(
    reason: _Reason8616,
    indices: Iterable[cython.longlong] = (),
) -> None:
    """Raise one typed dependency refusal with its implicated indices."""
    raise _DependencyRefusal8616(reason, indices)


@cython.dataclasses.dataclass()
class _DependencyWalk8616:
    """Recursive producer walk over one store statement's data expression."""

    statements: object
    owners: object
    definitions: object
    callsite_addr: cython.longlong
    producers: object = field(default_factory=set)
    visiting: object = field(default_factory=list)

    @cython.ccall
    def visit(self, expression_value: object, consumer_index: cython.longlong) -> None:
        """Walk one expression, recording every proven producer."""
        child: object
        expression = cast(DynamicValue, expression_value)
        try:
            tag = expression.tag
        except AttributeError:
            _refuse_dependency_8616(
                _Reason8616.INCOMPLETE_DEPENDENCY, self.visiting
            )
        if tag == "Iex_RdTmp":
            self._visit_rdtmp_8616(expression, consumer_index)
            return
        try:
            children = tuple(expression.child_expressions)
        except (AttributeError, TypeError):
            _refuse_dependency_8616(
                _Reason8616.INCOMPLETE_DEPENDENCY, self.visiting
            )
        for child in children:
            self.visit(child, consumer_index)

    @cython.ccall
    def _visit_rdtmp_8616(
        self,
        expression: DynamicValue,
        consumer_index: cython.longlong,
    ) -> None:
        """Resolve one temporary read to its unique same-callsite producer."""
        indices: object
        try:
            temporary = expression.tmp
        except AttributeError:
            temporary = None
        if not _is_int_8616(temporary):
            _refuse_dependency_8616(
                _Reason8616.INCOMPLETE_DEPENDENCY, self.visiting
            )
        indices = self.definitions.get(temporary, ())
        if not indices:
            _refuse_dependency_8616(
                _Reason8616.INCOMPLETE_DEPENDENCY, self.visiting
            )
        if len(indices) != 1:
            _refuse_dependency_8616(_Reason8616.AMBIGUOUS_DEFINITION, indices)
        producer_index = indices[0]
        if operator.ne(self.owners[producer_index], self.callsite_addr):
            _refuse_dependency_8616(
                _Reason8616.CROSS_CALLSITE_DEPENDENCY, indices
            )
        if producer_index in self.visiting:
            start = self.visiting.index(producer_index)
            _refuse_dependency_8616(
                _Reason8616.CYCLIC_DEPENDENCY,
                tuple(self.visiting[start:]) + (producer_index,),
            )
        try:
            producer_data = self.statements[producer_index].data
        except (AttributeError, IndexError):
            _refuse_dependency_8616(
                _Reason8616.INCOMPLETE_DEPENDENCY, indices
            )
        self.producers.add(producer_index)
        self.visiting.append(producer_index)
        self.visit(producer_data, producer_index)
        self.visiting.pop()
        if producer_index >= consumer_index:
            _refuse_dependency_8616(
                _Reason8616.INCOMPLETE_DEPENDENCY, indices
            )


@cython.ccall
def _dependencies_8616(
    statements: object,
    owners: object,
    definitions: object,
    *,
    callsite_addr: cython.longlong,
    store_index: cython.longlong,
) -> _DependencyResult8616:
    walk = _DependencyWalk8616(statements, owners, definitions, callsite_addr)
    try:
        walk.visit(statements[store_index].data, store_index)
    except (AttributeError, IndexError):
        return _DependencyResult8616((), _Reason8616.INCOMPLETE_DEPENDENCY, (store_index,))
    except _DependencyRefusal8616 as refusal:
        return _DependencyResult8616((), refusal.reason, refusal.indices)
    return _DependencyResult8616(tuple(sorted(walk.producers)), None, ())


@cython.ccall
def _read_temporaries_8616(expression_value: object) -> object:
    """Return all VEX temporaries read by one expression, or refuse an opaque tree."""
    child_reads: object
    child: object
    expression = cast(DynamicValue, expression_value)
    try:
        tag = expression.tag
    except AttributeError:
        return None
    if tag == "Iex_RdTmp":
        try:
            temporary = expression.tmp
        except AttributeError:
            return None
        return frozenset((temporary,)) if _is_int_8616(temporary) else None
    try:
        children = tuple(expression.child_expressions)
    except (AttributeError, TypeError):
        return None
    reads: set[cython.longlong] = set()
    for child in children:
        child_reads = _read_temporaries_8616(child)
        if child_reads is None:
            return None
        reads.update(child_reads)
    return frozenset(reads)


@cython.ccall
def _store_reads_8616(statement: DynamicValue) -> object:
    """Return combined data and address temporaries read by one store."""
    address: object
    address_reads: object
    data_reads: object
    data_reads = _read_temporaries_8616(statement.data)
    # Dynamic pyvex statement boundary: mocked and versioned store
    # nodes do not all expose an address child uniformly.
    try:
        address = statement.addr
    except AttributeError:
        address = None
    address_reads = (
        frozenset()
        if address is None
        else _read_temporaries_8616(address)
    )
    return (
        data_reads | address_reads
        if data_reads is not None and address_reads is not None
        else None
    )


@cython.ccall
def _statement_reads_8616(statement: DynamicValue) -> object:
    """Return the temporaries one statement reads, decoding its tag."""
    reads: object
    reads = _read_temporaries_8616(statement)
    if reads is not None:
        return reads
    try:
        tag = statement.tag
    except AttributeError:
        return None
    if tag == "Ist_IMark":
        return frozenset()
    if tag == "Ist_WrTmp":
        return _read_temporaries_8616(statement.data)
    if tag == "Ist_Store":
        return _store_reads_8616(statement)
    return None


@cython.ccall
def _producer_consumers_8616(
    vex: DynamicValue,
    statements: object,
) -> object:
    """Index every VEX temporary consumer, including the IRSB next expression."""
    next_expression: object
    next_reads: object
    reads: object
    index: object
    statement: object
    temporary: object
    consumers: dict[cython.longlong, set[cython.longlong]] = {}
    for index, statement in enumerate(statements):
        reads = _statement_reads_8616(statement)
        if reads is None:
            return None
        for temporary in reads:
            consumers.setdefault(temporary, set()).add(index)
    try:
        next_expression = vex.next
    except AttributeError:
        next_expression = None
    if next_expression is None:
        return {temporary: frozenset(indices) for temporary, indices in builtins.iter(consumers.items())}
    next_reads = _read_temporaries_8616(next_expression)
    if next_reads is None:
        return None
    for temporary in next_reads:
        consumers.setdefault(temporary, set()).add(len(statements))
    return {temporary: frozenset(indices) for temporary, indices in builtins.iter(consumers.items())}


def _finalize_8616(
    raw_count: cython.longlong,
    normalized_count: cython.longlong,
    projections: Iterable[CallReturnFrameProjectionFact8616],
    refusals: Iterable[CallReturnFrameProjectionRefusal8616],
) -> CallReturnFrameProjectionCollection8616:
    facts = tuple(
        sorted(
            projections,
            key=lambda fact: (
                fact.store_key,
                fact.role is _Role8616.VALUE_PRODUCER,
                fact.projection_key,
            ),
        )
    )
    refused = tuple(sorted(refusals, key=lambda item: (item.store_key, item.reason.value, item.producer_keys)))
    result = CallReturnFrameProjectionCollection8616(
        raw_count,
        normalized_count,
        len(facts),
        len(facts),
        max(raw_count - normalized_count, 0),
        facts,
        refused,
    )
    if not result.closed or (result.classified_fact_count > 0 and result.materialized_count == 0):
        raise PipelineHardError("CALL-frame Semantics projection evidence did not close")
    return result


@cython.ccall
def _store_reason_8616(
    statements: object,
    owners: object,
    imark_counts: object,
    callsite_addr: cython.longlong,
    store_index: cython.longlong,
) -> _Reason8616 | None:
    """Return the typed refusal for one store index, or None when exact."""
    if imark_counts.get(callsite_addr, 0) != 1:
        return _Reason8616.IMARK_NOT_EXACT
    if not 0 <= store_index < len(statements):
        return _Reason8616.STORE_NOT_EXACT
    try:
        exact_store = statements[store_index].tag == "Ist_Store" and operator.eq(owners[store_index], callsite_addr)
    except AttributeError:
        exact_store = False
    return None if exact_store else _Reason8616.STORE_NOT_EXACT


@cython.ccall
def _non_frame_producers_8616(
    statements: object,
    producer_indices: object,
    consumers: object,
    allowed_consumer_indices: object,
) -> object:
    """Return producers whose temporary escapes the allowed consumer set."""
    producer_index: object
    non_frame_producers: set[cython.longlong] = set()
    for producer_index in producer_indices:
        try:
            temporary = statements[producer_index].tmp
        except (AttributeError, IndexError):
            non_frame_producers.add(producer_index)
            continue
        if (
            consumers is None
            or not _is_int_8616(temporary)
            or not consumers.get(temporary, frozenset()).issubset(allowed_consumer_indices)
        ):
            non_frame_producers.add(producer_index)
    return non_frame_producers


def collect_call_return_frame_store_projections_8616(
    vex: object,
    *,
    callsite_addr: cython.longlong,
    vex_block_addr: cython.longlong,
    store_statement_indices: Iterable[cython.longlong],
) -> CallReturnFrameProjectionCollection8616:
    """Publish exact data-producer projections for stores under one CALL IMark."""
    reason: object
    dependency: object
    store_index: object
    try:
        statements = tuple(cast(DynamicValue, vex).statements or ())
    except (AttributeError, TypeError):
        statements = ()
    store_indices = tuple(sorted({index for index in iter(store_statement_indices) if _is_int_8616(index)}))
    owners, definitions, imark_counts = _inventory_8616(statements)
    self_facts: list[CallReturnFrameProjectionFact8616] = []
    dependencies: dict[cython.longlong, _DependencyResult8616] = {}
    refusals: list[CallReturnFrameProjectionRefusal8616] = []
    for store_index in store_indices:
        store_key = CallReturnFrameEffectKey8616(callsite_addr, vex_block_addr, store_index)
        reason = _store_reason_8616(
            statements, owners, imark_counts, callsite_addr, store_index,
        )
        if reason is not None:
            refusals.append(CallReturnFrameProjectionRefusal8616(store_key, reason, ()))
            continue
        self_facts.append(
            CallReturnFrameProjectionFact8616(
                store_key,
                store_key,
                _Role8616.STORE_STATEMENT,
            )
        )
        dependencies[store_index] = _dependencies_8616(
            statements,
            owners,
            definitions,
            callsite_addr=callsite_addr,
            store_index=store_index,
        )

    producer_indices = {
        producer_index
        for dependency in builtins.iter(dependencies.values())
        if dependency.reason is None
        for producer_index in iter(dependency.producers)
    }
    allowed_consumer_indices = producer_indices | set(dependencies)
    consumers = _producer_consumers_8616(cast(DynamicValue, vex), statements)
    non_frame_producers = _non_frame_producers_8616(
        statements, producer_indices, consumers, allowed_consumer_indices,
    )

    producer_facts: list[CallReturnFrameProjectionFact8616] = []
    normalized_count = 0
    for store_index, dependency in sorted(tuple(dependencies.items())):
        store_key = CallReturnFrameEffectKey8616(callsite_addr, vex_block_addr, store_index)
        reason = dependency.reason
        implicated = dependency.implicated
        unsafe_producers = tuple(
            producer_index
            for producer_index in iter(dependency.producers)
            if producer_index in non_frame_producers
        )
        if reason is None and unsafe_producers:
            reason = _Reason8616.NON_FRAME_CONSUMER
            implicated = unsafe_producers
        if reason is not None:
            refusals.append(
                CallReturnFrameProjectionRefusal8616(
                    store_key,
                    reason,
                    tuple(
                        CallReturnFrameEffectKey8616(
                            cast(int, owners[index]) if owners[index] is not None else callsite_addr,
                            vex_block_addr,
                            index,
                        )
                        for index in iter(implicated)
                    ),
                )
            )
            continue
        normalized_count += 1
        producer_facts.extend(
            CallReturnFrameProjectionFact8616(
                store_key,
                CallReturnFrameEffectKey8616(callsite_addr, vex_block_addr, producer_index),
                _Role8616.VALUE_PRODUCER,
            )
            for producer_index in iter(dependency.producers)
        )
    return _finalize_8616(
        len(store_indices),
        normalized_count,
        tuple(self_facts) + tuple(producer_facts),
        refusals,
    )
