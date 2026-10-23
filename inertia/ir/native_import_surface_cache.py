"""Layer: IR.
Responsibility: reuse isolated native facts inside one import request, never proofs.

Records own private copies. A consumer receives another copy, so condition
captures, terminal maps and frozen IR nodes cannot poison a later consumer.
Copiers must detach owned graph objects; opaque payloads are not admitted. Source
authorities are checked before every reuse; unsupported backends simply relift.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, cast

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616

from .core import IRBlock, IRInstr
from .direct_evidence_deadline import direct_evidence_deadline_expired_8616
from .native_copy_memo import seed_native_copy_memo_8616
from .raw_boot_native_surface_cache import _native_surface_key_8616
from .source_graph_binding import ImmutableSourceGraphFacts8616

_MAX_RECORDS = 4
_MAX_BLOCKS = 256


@dataclass(frozen=True, slots=True)
class NativeCensusSourceBinding8616:
    """Retained source identity only, never proof or callback-reuse authority."""

    project: object = field(compare=False, repr=False)
    boundary: ExactFunctionRangeBoundary8616 = field(compare=False, repr=False)
    key: tuple[object, ...]
    pinned: tuple[object, ...] = field(compare=False, repr=False)


def native_census_source_current_8616(
    binding: NativeCensusSourceBinding8616, *, producers: tuple[object, ...],
    allow_conditional_source: bool = False,
) -> bool:
    """Check the original import key against current source/configuration inputs.

    Supply the current fetch/import producers, never the retained old objects.
    Consumers must charge this check and separately authenticate native rows,
    admission, seeds and callbacks. Fresh bytes alone grant no semantic reuse.
    Conditional input checks require explicit opt-in; that opt-in authenticates
    only raw lift inputs, never the retained return premise or call effects.
    """
    if direct_evidence_deadline_expired_8616(binding.project):
        return False
    conditional = (binding.boundary.near_return_continuations is not None
                   or bool(binding.boundary.conditional_edges))
    if conditional and not allow_conditional_source:
        return False
    current = _source_key_8616(binding.project, binding.boundary, producers)
    unchanged = current is not None and current[0] == binding.key
    return unchanged and not direct_evidence_deadline_expired_8616(binding.project)


@dataclass(frozen=True, slots=True)
class NativeCensusBlockSelection8616:
    """Raw native blocks and the indexing work actually performed this time."""

    blocks: dict[int, IRBlock]
    work_units: int
    source_binding: NativeCensusSourceBinding8616 | None = field(default=None, repr=False)
    #: ``(block_addr, stop_after)`` for each returned block whose detached
    #: copy carries only the consumed row prefix. Empty for ordinary full
    #: selections; a listed block can never satisfy a whole-block binding.
    prefix_rows: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True, slots=True)
class _CensusProjection:
    """One private index of raw rows, owned by the existing raw record.

    ``prefix_rows`` names stored blocks truncated to a consumed row prefix.
    A marked block can never satisfy a later full or wider request for that
    address; same-key growth replaces it with a fresh detached copy.
    """

    key: tuple[object, ...]
    pinned: tuple[object, ...]
    blocks: dict[int, IRBlock]
    complete_inventory: bool
    prefix_rows: tuple[tuple[int, int], ...]


def _projection_covers_8616(
    projection: _CensusProjection,
    selected_blocks: frozenset[int] | None,
    terminal: tuple[int, int] | None,
) -> bool:
    """Require every requested block and every requested row to be retained."""
    if selected_blocks is None:
        if not projection.complete_inventory:
            return False
    elif not selected_blocks.issubset(projection.blocks):
        return False
    return all(
        (selected_blocks is not None and addr not in selected_blocks)
        or terminal == (addr, stop)
        for addr, stop in projection.prefix_rows
    )


def _select_census_rows_8616(
    blocks: dict[int, IRBlock], selected_blocks: frozenset[int] | None,
    terminal: tuple[int, int] | None,
) -> tuple[dict[int, IRBlock], tuple[tuple[int, int], ...]]:
    """Choose raw row references before allocating any detached graph."""
    selected = blocks if selected_blocks is None else {
        addr: block for addr, block in blocks.items() if addr in selected_blocks
    }
    return _census_terminal_prefix_8616(selected, terminal)


def _retained_projection_source_8616(
    projection: _CensusProjection | None,
    current: tuple[tuple[object, ...], tuple[object, ...]],
) -> tuple[tuple[object, ...], tuple[object, ...]]:
    """Keep source identity across inventory growth only after fresh equality."""
    if projection is not None and projection.key == current[0]:
        return projection.key, projection.pinned
    return current


def _copy_census_blocks_8616(blocks: dict[int, IRBlock]) -> dict[int, IRBlock]:
    """Detach selected graphs with the canonical typed deepcopy memo.

    The memo owns fresh clones, never shared frozen source nodes. One memo
    preserves aliases across blocks; unsupported fields retain deepcopy's
    ordinary reconstruction. Selection and row-work accounting stay unchanged.
    """
    return deepcopy(blocks, seed_native_copy_memo_8616(tuple(blocks.values())))


def _grow_census_projection_8616(
    retained: _CensusProjection | None,
    key: tuple[object, ...],
    available: dict[int, IRBlock],
    selected: dict[int, IRBlock],
    prefix_rows: tuple[tuple[int, int], ...],
) -> tuple[dict[int, IRBlock], tuple[tuple[int, int], ...], int]:
    """Extend one same-source projection without re-copying private blocks.

    Only a projection authenticated against the freshly checked ``key``
    donates rows: a foreign or absent source forces a full copy, and every
    donated block is already a detached private object, never a raw row
    loan. A retained block named in the retained ``prefix_rows`` is a stored
    truncation: a selected one can never satisfy the fresh full or wider
    request and is copied again, while an unselected one stays private with
    its marker. A donated full block satisfies even a narrowed fresh
    selection — the consumed-prefix cut is applied to the detached consumer
    copy — so the private store keeps the whole block and drops the marker.
    Unaffected retained blocks stay private so a moving partial selection
    never discards work already performed. Returns the merged private
    inventory, the markers describing blocks actually stored truncated, and
    work charged for retained-header visits and newly copied blocks/rows.
    Only addresses in the fresh raw inventory may be retained, so growth
    cannot accumulate stale addresses or exceed that inventory's bound.
    """
    donated: dict[int, IRBlock] = {}
    markers: list[tuple[int, int]] = []
    if retained is None or retained.key != key:
        copied = _copy_census_blocks_8616(selected)
        return copied, prefix_rows, len(copied) + sum(len(block.instrs) for block in copied.values())
    work = len(selected) + len(retained.prefix_rows)
    truncated = dict(retained.prefix_rows)
    for addr, block in retained.blocks.items():
        work += 1
        if addr not in available:
            continue
        if addr in truncated:
            if addr in selected:
                continue
            markers.append((addr, truncated[addr]))
        donated[addr] = block
    missing = {addr: block for addr, block in selected.items() if addr not in donated}
    copied = _copy_census_blocks_8616(missing)
    work += len(copied) + sum(len(block.instrs) for block in copied.values())
    markers.extend(row for row in prefix_rows if row[0] in missing)
    donated.update(copied)
    return donated, tuple(markers), work


def _census_prefix_count_8616(block: IRBlock, stop_after: int) -> int | None:
    """Select exactly the ordered native prefix an exact cutoff consumes.

    ``None`` on a non-int stop or row address or a stop before the block
    head; otherwise the index of the first row past the cutoff. Rows after
    the returned index are never copied or authorized for the caller.
    """
    if type(stop_after) is not int or type(block.addr) is not int or stop_after < block.addr:
        return None
    for index, instruction in enumerate(block.instrs):
        if type(instruction) is not IRInstr or type(instruction.addr) is not int:
            return None
        if instruction.addr > stop_after:
            return index
    return len(block.instrs)


def _census_terminal_prefix_8616(
    selected: dict[int, IRBlock], terminal: tuple[int, int] | None,
) -> tuple[dict[int, IRBlock], tuple[tuple[int, int], ...]]:
    """Apply one caller-declared consumed-row cutoff to the detached set.

    Returns the original selection unchanged with empty ``prefix_rows``
    unless the terminal is an exact ``(block_addr, stop_after)`` pair on a
    selected block with a real ordered suffix; then that one block's copy
    template carries only the consumed prefix rows. Invalid, missing or
    degenerate cutoffs authorize nothing and are silently full.
    """
    if not (
        type(terminal) is tuple
        and len(terminal) == 2
        and type(terminal[0]) is int
        and type(terminal[1]) is int
        and type(selected.get(terminal[0])) is IRBlock
    ):
        return selected, ()
    target = selected[terminal[0]]
    count = _census_prefix_count_8616(target, terminal[1])
    if count is None or count >= len(target.instrs):
        return selected, ()
    narrowed = dict(selected)
    narrowed[terminal[0]] = replace(target, instrs=target.instrs[:count])
    return narrowed, ((terminal[0], terminal[1]),)


def _request_native_census_blocks_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    fetch: Callable[[object, object], tuple[IRBlock, ...] | None],
    *,
    selected_blocks: frozenset[int] | None = None,
    producers: tuple[object, ...],
    terminal: tuple[int, int] | None = None,
    allow_conditional_source: bool = False,
) -> NativeCensusBlockSelection8616 | None:
    """Select detached raw rows from the existing bounded native-fact session.

    A missing source/configuration authority falls back to the caller's normal
    authoritative import. One projection per raw record retains no proof,
    path state, manifest, or store verdict. All returned rows are detached;
    deliberate mutation of a returned frozen node cannot poison later reuse.

    Inventory growth under an unchanged freshly checked source key reuses the
    retained projection's already-private full blocks; only new, missing or
    widened rows are freshly detached, and ``work_units`` charges the copying
    actually performed. A retained truncated prefix never satisfies a later
    full or wider request.

    ``terminal`` is an optional explicit ``(block_addr, stop_after)`` for one
    caller-declared consumed-row cutoff. When exactly valid — a real suffix
    exists and every consumed row is an ordered int-addressed IR row — the
    detached copy of that one block carries only the consumed prefix, so
    only the traversal/copy actually performed is charged. Any invalid or
    degenerate terminal falls back to an ordinary full copy: a truncated
    block is never authorized and never an error. ``prefix_rows`` on the
    result names each truncation actually applied so whole-block consumers
    can re-derive or conservatively decline.

    ``allow_conditional_source`` supplies raw source identity for a consumer
    that independently reauthenticates conditional call effects. It does not
    authorize path reuse; default consumers receive no conditional binding.
    """
    session = _ACTIVE.get()
    if session is None or direct_evidence_deadline_expired_8616(project):
        return None
    authorities = (fetch, *producers)
    before = _source_key_8616(project, boundary, authorities)
    if before is None:
        return None
    # Census producer identities differ from the raw import's; select the
    # variant by its raw source key, then authenticate the projection with
    # this call's own fetch/producer key as before.
    slot = _variant_slot_8616(project, boundary.addr, before[0][0])
    record = session.records.get(slot)
    projection = None if record is None else record.census
    work_units = 0
    if (projection is None or projection.key != before[0]
            or not _projection_covers_8616(projection, selected_blocks, terminal)):
        rows = fetch(project, boundary)
        if rows is None or direct_evidence_deadline_expired_8616(project):
            return None
        after = _source_key_8616(project, boundary, authorities)
        record = session.records.get(slot)
        if after is None or before[0] != after[0] or record is None:
            return None
        if len(rows) > _MAX_BLOCKS or any(type(row.addr) is not int for row in rows):
            return None
        blocks = {row.addr: row for row in rows}
        if len(blocks) != len(rows):
            return None
        selected, prefix_rows = _select_census_rows_8616(blocks, selected_blocks, terminal)
        private_rows, stored_prefixes, growth_work = _grow_census_projection_8616(
            projection, after[0], blocks, selected, prefix_rows)
        if direct_evidence_deadline_expired_8616(project):
            return None
        key, pinned = _retained_projection_source_8616(projection, after)
        projection = _CensusProjection(
            key, pinned, private_rows, len(private_rows) == len(blocks), stored_prefixes,
        )
        _retain_8616(session, slot, replace(record, census=projection))
        # Index every raw block header, but copy only the rows not already private.
        work_units = len(rows) + growth_work
    selected, narrowed_prefixes = _select_census_rows_8616(projection.blocks, selected_blocks, terminal)
    inherited_prefixes = tuple(row for row in projection.prefix_rows if row[0] in selected)
    prefix_rows = inherited_prefixes + tuple(row for row in narrowed_prefixes if row not in inherited_prefixes)
    detached = _copy_census_blocks_8616(selected)
    if direct_evidence_deadline_expired_8616(project):
        return None
    work_units += len(detached) + sum(len(block.instrs) for block in detached.values())
    binding = None if (boundary.near_return_continuations is not None and not allow_conditional_source) else NativeCensusSourceBinding8616(
        project, boundary, projection.key, projection.pinned,
    )
    return NativeCensusBlockSelection8616(detached, work_units, binding, prefix_rows)


@dataclass(frozen=True, slots=True)
class _Record:
    """Private facts and the live identities that authenticate their source."""

    project: object
    key: tuple[object, ...]
    pinned: tuple[object, ...]
    surface: object
    blocks: int
    census: _CensusProjection | None = None
    #: Canonical facts detached from ``surface`` on first rebind demand. The
    #: retained graph itself is never re-encoded once this is populated.
    facts: ImmutableSourceGraphFacts8616 | None = None
    #: Pin the canonical projection producer independently of raw lift identity.
    facts_producer: object = None


@dataclass(slots=True)
class _Session:
    """Bounded storage owned by exactly one outer import operation.

    ``records`` retains one private record per exact authenticated raw
    surface variant: ``(id(project), boundary address, raw source key)``.
    Distinct continuation/raw lift inputs of one address are separate
    variants; the global record and block caps bound all variants together.
    """

    records: dict[tuple[int, int, object], _Record] = field(default_factory=dict)
    #: Opaque terminal-fact records pinned by owning consumers. Released with
    #: the session on outer request exit; no global or cross-request store.
    terminal_facts: dict[tuple[int, int, int, int | None], object] = field(default_factory=dict)


_ACTIVE: ContextVar[_Session | None] = ContextVar("native_import_surface", default=None)


def native_terminal_fact_store_8616() -> dict[tuple[int, int, int, int | None], object] | None:
    """Return the active request's bounded terminal-fact map, or ``None``.

    Owning consumers may pin typed detached-fact records keyed by their own
    source binding plus current project/range/view identities. The map dies
    with the session on outer ``native_import_request_8616`` exit, so records
    can never outlive the request that produced them.
    """
    session = _ACTIVE.get()
    return None if session is None else session.terminal_facts


@contextmanager
def native_import_request_8616() -> Iterator[None]:
    """Share facts with nested imports and release all records on outer exit."""
    if _ACTIVE.get() is not None:
        yield
        return
    session = _Session()
    token = _ACTIVE.set(session)
    try:
        yield
    finally:
        session.terminal_facts.clear()
        _ACTIVE.reset(token)


def _configuration_8616(project: object) -> tuple[tuple[object, ...], tuple[object, ...]] | None:
    """Bind canonical angr byte sources, stop points and native lift producers."""
    from angr import Project
    from angr.engines import UberEngine
    from angr.factory import AngrObjectFactory
    from pyvex.lifting import lifters

    from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY, Lifter86_16

    from .canonical_patterns import canonical_pattern_config_8616
    from .logical_memory_capture import record_access

    if type(project) is not Project:
        return None
    external = cast(Any, project)  # angr factory/engine configuration is a third-party boundary.
    factory = external.factory
    engine = factory.default_engine
    if type(factory) is not AngrObjectFactory or type(engine) is not UberEngine:
        return None
    if external.selfmodifying_code or engine.selfmodifying_code or external.kb.patches.items():
        return None
    if "block" in vars(factory) or "lift_vex" in vars(engine):
        return None
    registered = tuple(lifters[external.arch.name])
    if registered != (Lifter86_16,):
        return None
    producers = (
        factory, engine, AngrObjectFactory.block, UberEngine.lift_vex,
        Lifter86_16, Lifter86_16.lift, Lifter86_16.decode,
        Instruction_ANY, Instruction_ANY.parse, Instruction_ANY.lift,
        Instruction_ANY._record_typed_condition_8616,
        record_access, *registered, *Lifter86_16.instrs,
    )
    key = (
        tuple(id(producer) for producer in producers),
        engine._single_step, engine.default_strict_block_end,
        tuple(sorted(external._sim_procedures)),
        os.environ.get("INERTIA_ENABLE_AFFINE_SWITCH_CONDITIONS") == "1",
        tuple(sorted(canonical_pattern_config_8616().disabled)),
    )
    return key, producers


def _source_key_8616(
    project: object, boundary: ExactFunctionRangeBoundary8616,
    producers: tuple[object, ...],
) -> tuple[tuple[object, ...], tuple[object, ...]] | None:
    """Authenticate the exact native source and retain every identity authority."""
    from .vex_import import build_x86_16_ir_function_artifact

    configuration = _configuration_8616(project)
    if configuration is None:
        return None
    source = _native_surface_key_8616(
        project, boundary, build_x86_16_ir_function_artifact, raw_lift_only=True,
    )
    if source is None:
        return None
    producers = (*producers, _copy_census_blocks_8616, seed_native_copy_memo_8616)
    key = source[0], configuration[0], tuple(id(producer) for producer in producers)
    return key, (*source[1], *configuration[1], *producers)


def _variant_slot_8616(
    project: object, addr: int, source: object,
) -> tuple[int, int, object]:
    """Name the bounded slot of one exact authenticated raw surface variant.

    ``source`` is the raw surface key (``before[0][0]``): bytes, boundary
    extents, return-lift inputs and import producer identity. Configuration
    and consumer producer drift still refuse through full key comparison;
    only the raw source distinguishes variants of one address.
    """
    return id(project), addr, source


def _drop_address_variants_8616(session: _Session, project: object, addr: int) -> None:
    """Release every retained raw variant of one address deterministically."""
    owner = id(project)
    for slot in [slot for slot in session.records if slot[0] == owner and slot[1] == addr]:
        del session.records[slot]


def _retain_8616(
    session: _Session, slot: tuple[int, int, object], record: _Record,
) -> None:
    """Evict oldest variant facts deterministically before exceeding the caps.

    ``_MAX_RECORDS`` counts every retained variant, not distinct addresses;
    ``_MAX_BLOCKS`` sums blocks across all variants together. The same slot
    is released before counting so replacement never double-counts, and every
    insertion — including reinsertion after a reentrant copy/projection
    callback — passes through this bound-aware path.
    """
    session.records.pop(slot, None)
    while session.records and (
        len(session.records) >= _MAX_RECORDS
        or sum(item.blocks for item in session.records.values()) + record.blocks > _MAX_BLOCKS
    ):
        del session.records[next(iter(session.records))]
    session.records[slot] = record


def request_native_surface_8616[T](
    project: object,
    function: object,
    importer: Callable[[object, object], T],
    *,
    producers: tuple[object, ...],
    admit: Callable[[T, ExactFunctionRangeBoundary8616], bool],
    clone: Callable[[T], T] = deepcopy,
) -> T:
    """Reuse private fact copies only; the caller always reruns proof and finishing.

    Each exact authenticated raw surface variant of one address retains its
    own bounded record, so alternating unconditional and conditional-return
    lift inputs reuse their own facts instead of evicting each other.

    Expired requests bypass retention, letting the importer's existing deadline
    path return its typed incomplete surface. No proof verdict or transient
    import failure is memoized; unresolved native facts retain their reasons.
    """
    session = _ACTIVE.get()
    if session is None or type(function) is not ExactFunctionRangeBoundary8616:
        return importer(project, function)
    boundary = function
    if len(boundary.blocks) > _MAX_BLOCKS or direct_evidence_deadline_expired_8616(project):
        _drop_address_variants_8616(session, project, boundary.addr)
        return importer(project, function)
    authorities = (*producers, importer, admit, clone)
    before = _source_key_8616(project, boundary, authorities)
    if before is None:
        _drop_address_variants_8616(session, project, boundary.addr)
    else:
        slot = _variant_slot_8616(project, boundary.addr, before[0][0])
        record = session.records.pop(slot, None)
        if record is not None:
            # Raw facts contain no boundary identity; finishing consumes the
            # current boundary. Equivalent reconstructed boundaries may share
            # only lifting. Other raw variants of this address stay retained;
            # a mismatched key is never authenticated as current.
            unchanged = record.project is project and record.key == before[0]
            if unchanged and not direct_evidence_deadline_expired_8616(project):
                result = clone(cast(T, record.surface))
                if not direct_evidence_deadline_expired_8616(project):
                    _retain_8616(session, slot, record)
                    return result
    result = importer(project, function)
    if before is None or direct_evidence_deadline_expired_8616(project) or not admit(result, boundary):
        return result
    after = _source_key_8616(project, boundary, authorities)
    if after is not None and before[0] == after[0]:
        private = clone(result)
        if not direct_evidence_deadline_expired_8616(project):
            _retain_8616(session, _variant_slot_8616(
                project, boundary.addr, after[0][0],
            ), _Record(
                project, before[0], before[1], private, len(boundary.blocks),
            ))
    return result


class NativeFactRebindState8616(Enum):
    """Terminal state of one bounded native-fact comparison."""

    #: The record's retained canonical facts proved the fresh caller facts equal.
    AUTHENTICATED = "authenticated"
    #: The validated record proved the caller foreign, or the budget expired.
    REFUSED = "refused"
    #: No validated record applies; the caller runs its ordinary import path.
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class NativeFactRebind8616:
    """One rebind outcome; ``evidence`` is a detached, caller-owned value."""

    state: NativeFactRebindState8616
    evidence: object = None


_REBIND_UNRESOLVED_8616 = NativeFactRebind8616(NativeFactRebindState8616.UNRESOLVED)
_REBIND_REFUSED_8616 = NativeFactRebind8616(NativeFactRebindState8616.REFUSED)


def _immutable_facts_equal_8616(
    caller: ImmutableSourceGraphFacts8616, native: ImmutableSourceGraphFacts8616,
) -> bool:
    """Replay the sealed graph/refusal comparison over frozen canonical facts.

    Dataclass ``==`` covers ``function_addr``, ``roots`` and ``records`` — the
    complete interned canonical surface the shared encoder would compare. The
    ``compare=False`` refusal evidence fields are orthogonal sealed census
    data and are compared explicitly, matching the owner's documented
    contract.
    """
    return bool(
        caller == native
        and caller.function_refusals == native.function_refusals
        and caller.block_refusals == native.block_refusals
    )


def request_native_fact_rebind_8616[T](
    project: object,
    function: object,
    importer: Callable[[object, object], T],
    *,
    producers: tuple[object, ...],
    admit: Callable[[T, ExactFunctionRangeBoundary8616], bool],
    clone: Callable[[T], T] = deepcopy,
    native_facts: Callable[[T], ImmutableSourceGraphFacts8616 | None],
    caller_facts: Callable[[], ImmutableSourceGraphFacts8616 | None],
    detached_evidence: Callable[[T], object],
) -> NativeFactRebind8616:
    """Authenticate fresh caller facts against the record's retained facts.

    Only the record's PRIVATE canonical facts are reused: the retained native
    graph is neither cloned nor re-encoded, and the caller surface is freshly
    canonicalized on every invocation. ``importer``, ``admit`` and ``clone``
    are never invoked here — their identities authenticate the record's key,
    identical to ``request_native_surface_8616``.

    UNRESOLVED reports that no validated record applies (no live request, no
    matching key, expired budget before authentication); the caller then runs
    its ordinary import-and-compare path unchanged. REFUSED reports that the
    validated record proved the caller foreign, that canonicalization refused,
    or that the deadline expired mid-comparison; the caller must not bind.
    Malformed caller or native graphs propagate the canonical owner's typed
    ``SourceGraphSerializationError8616`` exactly like the shared encoder.
    """
    session = _ACTIVE.get()
    if session is None or type(function) is not ExactFunctionRangeBoundary8616:
        return _REBIND_UNRESOLVED_8616
    boundary = function
    if len(boundary.blocks) > _MAX_BLOCKS or direct_evidence_deadline_expired_8616(project):
        _drop_address_variants_8616(session, project, boundary.addr)
        return _REBIND_UNRESOLVED_8616
    authorities = (*producers, importer, admit, clone)
    before = _source_key_8616(project, boundary, authorities)
    if before is None:
        _drop_address_variants_8616(session, project, boundary.addr)
        return _REBIND_UNRESOLVED_8616
    slot = _variant_slot_8616(project, boundary.addr, before[0][0])
    record = session.records.pop(slot, None)
    if (
        record is None
        or record.project is not project
        or record.key != before[0]
        or direct_evidence_deadline_expired_8616(project)
    ):
        return _REBIND_UNRESOLVED_8616
    # The record now re-enters the session before any terminal return so the
    # validated private facts keep serving unrelated consumers of this key.
    facts = record.facts if record.facts_producer is native_facts else None
    if facts is None:
        facts = native_facts(cast(T, record.surface))
        _retain_8616(session, slot, record)
        if (
            type(facts) is not ImmutableSourceGraphFacts8616
            or direct_evidence_deadline_expired_8616(project)
        ):
            return _REBIND_REFUSED_8616
        record = replace(record, facts=facts, facts_producer=native_facts)
    _retain_8616(session, slot, record)
    # Detach evidence before observing caller facts: a copy callback cannot
    # invalidate a caller graph that has already passed comparison.
    evidence = detached_evidence(cast(T, record.surface))
    if direct_evidence_deadline_expired_8616(project):
        return _REBIND_REFUSED_8616
    caller = caller_facts()
    if (
        type(caller) is not ImmutableSourceGraphFacts8616
        or not _immutable_facts_equal_8616(caller, facts)
        or direct_evidence_deadline_expired_8616(project)
    ):
        return _REBIND_REFUSED_8616
    # Recheck bytes and configuration after every projection/copy callback.
    # A record authenticated before a callback is not evidence about its edits.
    after = _source_key_8616(project, boundary, authorities)
    if (after is None or after[0] != before[0]
            or direct_evidence_deadline_expired_8616(project)):
        session.records.pop(slot, None)
        return _REBIND_REFUSED_8616
    return NativeFactRebind8616(NativeFactRebindState8616.AUTHENTICATED, evidence)
