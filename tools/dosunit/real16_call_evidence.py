"""Layer: tools/dosunit real-mode comparator evidence.

Responsibility: document admission and identity for bounded real16 call
composition — grouping lowered parts by function id, requiring complete
ranges/full-state outputs, scanning structured IR for external effects and
trap exits, computing whole-body/semantic dependency hashes, and proposing
unique catalog owners for solver-admitted indirect call targets.  Nothing
here composes or proves state; see ``real16_call_execution``.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

import tools.dosunit.straightline_ssa as S
from tools.dosunit.binary_environment import external_effects, part_io_events
from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.proof_contracts import Architecture
from tools.dosunit.real16_call_contracts import (
    ComposeSession,
    FunctionCtx,
    Real16CallRefusal,
)

if TYPE_CHECKING:
    from tools.dosunit.ordered_io_environment import OrderedIoContract


def part_delta(part: dict[str, Any]) -> int | None:
    """Entry delta of a lowered part, or ``None`` when unrecorded."""
    value = part.get("part")
    part_info = value if isinstance(value, dict) else {}
    parsed: int | None = S._optional_int(part_info.get("entry_delta"))
    return parsed


def part_entry_linear(part: dict[str, Any]) -> int | None:
    """Function-entry linear address recorded on a lowered part."""
    value = part.get("function_entry")
    entry = value if isinstance(value, dict) else {}
    parsed: int | None = S._optional_int(entry.get("linear"))
    return parsed


def block_source(part: dict[str, Any]) -> dict[str, Any]:
    """Source record of a lowered part (empty mapping when malformed)."""
    source = part.get("source")
    return source if isinstance(source, dict) else {}


def block_transfer(part: dict[str, Any]) -> dict[str, Any]:
    """Binary-derived transfer record of a lowered part."""
    transfer = block_source(part).get("transfer")
    return transfer if isinstance(transfer, dict) else {}


def _required_state_names() -> set[str]:
    """Internal names every reached block must publish for safe composition."""
    return set(S._ssa_register_widths())


def _check_part_state(part: dict[str, Any], function_id: str) -> None:
    """Refuse reached blocks lacking full-state outputs or trap exits."""
    outputs = part.get("outputs")
    names = set(outputs) if isinstance(outputs, dict) else set()
    missing = sorted(_required_state_names() - names)
    if missing:
        raise Real16CallRefusal(
            "full_state_outputs_missing",
            {"function": function_id, "delta": part_delta(part), "missing": missing},
        )
    trap_exits = part.get("trap_exits")
    if isinstance(trap_exits, list) and trap_exits:
        raise Real16CallRefusal(
            "unsupported_return_control",
            {"function": function_id, "delta": part_delta(part), "trap_exits": trap_exits},
        )


def _check_part_effects(
    part: dict[str, Any], function_id: str, io_model: OrderedIoContract | None = None
) -> None:
    """Refuse external environment effects recorded in structured IR terms.

    Under a declared ``io_model``, only events the modeled ordered-I/O
    relation covers may pass: a covered effect kind whose scalar width is
    outside the declared width domain, or a malformed event shape, still
    refuses.  With no model the environment-free gate is unchanged.
    """
    effects = external_effects(
        {"assignments": part.get("assignments"), "outputs": part.get("outputs")}
    )
    if not effects:
        return
    events = part_io_events(part) if io_model is not None else None
    covered = (
        io_model is not None
        and events is not None
        and effects <= io_model.effects
        and all(width in io_model.widths for _, _, width in events)
    )
    if not covered:
        raise Real16CallRefusal(
            "unsupported_io_effect",
            {
                "function": function_id,
                "delta": part_delta(part),
                "effects": sorted(effect.value for effect in effects),
            },
        )


def _body_identity(part: dict[str, Any], function_id: str) -> tuple[int, str]:
    """Require a positive declared whole-body size and a complete SHA256."""
    source = block_source(part)
    size = S._optional_int(source.get("function_machine_code_size"))
    digest = source.get("function_machine_code_sha256")
    if size is None or size <= 0 or not isinstance(digest, str) or len(digest) != 64:
        raise Real16CallRefusal("function_range_incomplete", {"function": function_id})
    try:
        bytes.fromhex(digest)
    except ValueError as error:
        raise Real16CallRefusal("function_range_incomplete", {"function": function_id}) from error
    return size, digest


def _check_part_range(part: dict[str, Any], delta: int, size: int, function_id: str) -> None:
    """Require every composed block to lie completely inside the binary body."""
    source = block_source(part)
    block_size = S._optional_int(source.get("machine_code_size"))
    digest = source.get("machine_code_sha256")
    valid_digest = isinstance(digest, str) and len(digest) == 64
    if block_size is None or block_size <= 0 or delta < 0 or delta + block_size > size or not valid_digest:
        raise Real16CallRefusal("function_range_incomplete", {"function": function_id, "delta": delta})


def _validate_group_part(
    part: dict[str, Any],
    function_id: str,
    entry: int,
    body: tuple[int, str],
    blocks: dict[int, dict[str, Any]],
    *,
    io_model: OrderedIoContract | None = None,
) -> int:
    """Check one part's entry, unique cutpoint, range, state and effects."""
    delta = part_delta(part)
    if delta is None or delta in blocks or part_entry_linear(part) != entry:
        raise Real16CallRefusal("function_range_incomplete", {"function": function_id, "delta": delta})
    if _body_identity(part, function_id) != body:
        raise Real16CallRefusal("function_range_incomplete", {"function": function_id})
    _check_part_range(part, delta, body[0], function_id)
    _check_part_state(part, function_id)
    _check_part_effects(part, function_id, io_model)
    return delta


def _group_context(
    function_id: str,
    parts: list[dict[str, Any]],
    *,
    io_model: OrderedIoContract | None = None,
) -> FunctionCtx:
    """Build one closed binary-function context with a consistent body identity.

    ``io_model`` is the declared ordered-I/O environment contract under
    which covered scalar port events may be admitted; uncovered events,
    dirty helpers or machine state still refuse.
    """
    body = _body_identity(parts[0], function_id)
    entry = part_entry_linear(parts[0])
    if entry is None:
        raise Real16CallRefusal("function_range_incomplete", {"function": function_id})
    function = parts[0].get("function")
    name = str(function.get("name") or function_id) if isinstance(function, dict) else function_id
    blocks: dict[int, dict[str, Any]] = {}
    for part in parts:
        delta = _validate_group_part(part, function_id, entry, body, blocks, io_model=io_model)
        blocks[delta] = part
    if 0 not in blocks:
        raise Real16CallRefusal("function_range_incomplete", {"function": function_id})
    for part in parts:
        for successor in S._direct_successor_delta_set(part):
            if successor not in blocks:
                raise Real16CallRefusal("successor_outside_region", {"function": function_id, "delta": successor})
    return FunctionCtx(function_id, name, entry, blocks, body[0], body[1])


def _raw_groups(doc: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Index lowered parts by catalog identity without admitting their bodies."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for part in doc.get("functions", []) or []:
        if not isinstance(part, dict):
            continue
        value = part.get("function")
        function = value if isinstance(value, dict) else {}
        function_id = str(function.get("id") or function.get("name") or "")
        if function_id:
            groups.setdefault(function_id, []).append(part)
    return groups


def group_functions(
    doc: dict[str, Any], *, io_model: OrderedIoContract | None = None
) -> dict[str, FunctionCtx]:
    """Group all full-state parts into closed ranges with unique binary entries."""
    if io_model is not None:
        io_model.validate_for(Architecture.REAL16)
    groups = _raw_groups(doc)
    ctxs: dict[str, FunctionCtx] = {}
    entries: set[int] = set()
    for function_id, parts in groups.items():
        ctx = _group_context(function_id, parts, io_model=io_model)
        if ctx.entry_linear in entries:
            raise Real16CallRefusal("function_range_incomplete", {"function": function_id, "entry": ctx.entry_linear})
        entries.add(ctx.entry_linear)
        ctxs[function_id] = ctx
    return ctxs


def _selected_id(groups: dict[str, list[dict[str, Any]]], function_key: str) -> str:
    """Resolve the requested catalog identity without validating other bodies."""
    selected_id = function_key if function_key in groups else None
    if selected_id is None:
        for function_id, parts in groups.items():
            function = parts[0].get("function")
            if isinstance(function, dict) and function.get("name") == function_key:
                selected_id = function_id
                break
    if selected_id is None:
        raise Real16CallRefusal("function_not_found", {"function": function_key})
    return selected_id


def transfer_call_target(transfer: dict[str, Any]) -> int | None:
    """Literal physical call destination recorded on a transfer, if any."""
    value = transfer.get("target")
    target = value if isinstance(value, dict) else {}
    linear: int | None = S._optional_int(target.get("raw"))
    if linear is None:
        linear = S._optional_int(target.get("linear"))
    return linear


def is_indirect_call_site(block: dict[str, Any]) -> bool:
    """Call blocks whose composed control carries the symbolic target term."""
    transfer = block_transfer(block)
    return (
        str(transfer.get("kind") or "") == "direct_call"
        and transfer_call_target(transfer) is None
    )


def _declared_call_targets(ctx: FunctionCtx) -> set[int]:
    """Read physical direct-call destinations from the admitted binary IR."""
    targets: set[int] = set()
    for part in ctx.blocks.values():
        transfer = block_transfer(part)
        if transfer.get("kind") != "direct_call":
            continue
        linear = transfer_call_target(transfer)
        if linear is not None:
            targets.add(linear)
    return targets


def group_lookup(
    doc: dict[str, Any],
    function_key: str,
    *,
    io_model: OrderedIoContract | None = None,
) -> tuple[dict[str, FunctionCtx], FunctionCtx]:
    """Admit only the selected function and its binary-derived call closure.

    ``io_model`` scopes the ordered-I/O environment contract to every
    admitted context in the transitive call closure — the same declared
    model governs root and nested callees alike.
    """
    if io_model is not None:
        io_model.validate_for(Architecture.REAL16)
    groups = _raw_groups(doc)
    selected_id = _selected_id(groups, function_key)
    by_entry: dict[int, list[str]] = {}
    for function_id, parts in groups.items():
        entry = part_entry_linear(parts[0])
        if entry is not None:
            by_entry.setdefault(entry, []).append(function_id)
    ctxs: dict[str, FunctionCtx] = {}
    pending = [selected_id]
    while pending:
        function_id = pending.pop()
        if function_id in ctxs:
            continue
        ctx = _group_context(function_id, groups[function_id], io_model=io_model)
        owners = by_entry.get(ctx.entry_linear, [])
        if owners != [function_id]:
            raise Real16CallRefusal(
                "function_range_incomplete", {"function": function_id, "entry": ctx.entry_linear}
            )
        ctxs[function_id] = ctx
        for linear in _declared_call_targets(ctx):
            pending.extend(by_entry.get(linear, []))
    return ctxs, ctxs[selected_id]


def check_lowering_refusals(doc: dict[str, Any], reachable_ids: set[str]) -> None:
    """Refuse when a reachable function carries a recorded lowering refusal."""
    for refusal in doc.get("refusals", []) or []:
        if not isinstance(refusal, dict):
            continue
        value = refusal.get("detail")
        detail = value if isinstance(value, dict) else {}
        function_id = str(detail.get("function_id") or "")
        if function_id in reachable_ids or not function_id:
            raise Real16CallRefusal(
                "lowering_refusals_present",
                {"function": function_id, "reason": str(refusal.get("reason") or "")},
            )


def reachable_call_ids(ctxs: dict[str, FunctionCtx], ctx: FunctionCtx) -> set[str]:
    """Statically collect callee function ids by linear call target."""
    by_entry = {c.entry_linear: c for c in ctxs.values()}
    found: set[str] = set()
    pending = [ctx]
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if current.function_id in seen:
            continue
        seen.add(current.function_id)
        for part in current.blocks.values():
            transfer = block_transfer(part)
            if str(transfer.get("kind") or "") != "direct_call":
                continue
            linear = transfer_call_target(transfer)
            callee = by_entry.get(linear) if linear is not None else None
            if callee is not None:
                found.add(callee.function_id)
                pending.append(callee)
    return found


def dependency_identities(
    doc: dict[str, Any], *, contexts: dict[str, FunctionCtx] | None = None
) -> dict[str, dict[str, Any]]:
    """Whole-body SHA and semantic identity per function group."""
    groups = contexts if contexts is not None else group_functions(doc)
    identities: dict[str, dict[str, Any]] = {}
    for function_id, ctx in groups.items():
        semantic = hashlib.sha256()
        parts = [ctx.blocks[delta] for delta in sorted(ctx.blocks)]
        for part in parts:
            source = block_source(part)
            semantic.update(
                canonical_json_bytes(
                    {
                        "outputs": part.get("outputs"),
                        "assignments": part.get("assignments"),
                        "transfer": source.get("transfer"),
                    }
                )
            )
        identities[function_id] = {
            "function": function_id,
            "body_sha256": ctx.body_sha256,
            "semantic_sha256": semantic.hexdigest(),
            "body_size": ctx.body_size,
            "parts": len(parts),
        }
    return identities


class IndirectTargetResolver:
    """Catalog-backed owner for bounded finite indirect call targets.

    ``candidate_entries`` proposes every parseable catalog entry linear under
    the session's ``max_indirect_call_candidates`` bound; the bound is enforced
    while the entry index is being discovered, before sorting, so an oversized
    catalog refuses without materializing or solving anything.  ``resolve``
    lazily validates one callee context on solver admission.  Membership
    itself is proved against the composed ``control_ip`` term by the caller,
    never by this catalog view.
    """

    def __init__(self, doc: dict[str, Any]) -> None:
        """Group lowered parts; the entry index is built lazily and bounded."""
        self._groups = _raw_groups(doc)
        self._by_entry: dict[int, list[str]] | None = None
        self._built: dict[str, FunctionCtx] = {}

    def _entry_index(
        self, limit: int | None, stats: dict[str, Any] | None
    ) -> dict[int, list[str]]:
        """Build the entry→owners index once, bailing early above ``limit``.

        Discovery stops as soon as the index exceeds the bound, so oversized
        catalogs refuse without sorting, term construction, or solver work.
        ``stats`` carries the shared composition deadline into the loop.
        """
        if self._by_entry is not None:
            return self._by_entry
        index: dict[int, list[str]] = {}
        for function_id, parts in self._groups.items():
            S._compose_deadline_check(stats)
            entry = part_entry_linear(parts[0]) if parts else None
            if entry is None:
                continue
            index.setdefault(entry, []).append(function_id)
            if limit is not None and len(index) > limit:
                raise Real16CallRefusal(
                    "compose_budget_exceeded",
                    {"counter": "indirect_call_candidates", "limit": limit},
                )
        self._by_entry = index
        return index

    def candidate_entries(self, session: ComposeSession) -> list[int]:
        """Bounded candidate enumeration; refuses before materializing too many."""
        limit = session.limits.max_indirect_call_candidates
        index = self._entry_index(limit, session.stats)
        if len(index) > limit:
            raise Real16CallRefusal(
                "compose_budget_exceeded",
                {"counter": "indirect_call_candidates", "limit": limit},
            )
        return sorted(index)

    def _matching_owners(self, entry: int, session: ComposeSession) -> list[str]:
        """Find unique ownership without building an unrelated candidate index.

        A literal target needs no candidate enumeration. Scan under the shared
        deadline, retaining at most two matching owners: the second already
        proves ambiguity. Reuse an existing bounded-discovery index when present.
        """
        S._compose_deadline_check(session.stats)
        if self._by_entry is not None:
            return self._by_entry.get(entry, [])[:2]
        owners: list[str] = []
        for function_id, parts in self._groups.items():
            S._compose_deadline_check(session.stats)
            if parts and part_entry_linear(parts[0]) == entry:
                owners.append(function_id)
                if len(owners) == 2:
                    break
        S._compose_deadline_check(session.stats)
        return owners

    def resolve(self, entry: int, session: ComposeSession) -> FunctionCtx:
        """Validate a unique owner with deadline checks, including cache reuse."""
        owners = self._matching_owners(entry, session)
        if len(owners) != 1:
            raise Real16CallRefusal(
                "call_target_unmapped", {"target": entry, "owners": sorted(owners)}
            )
        function_id = owners[0]
        ctx = self._built.get(function_id)
        if ctx is None:
            ctx = _group_context(
                function_id, self._groups[function_id], io_model=session.io_model
            )
            S._compose_deadline_check(session.stats)
            self._built[function_id] = ctx
        return ctx


def dependencies_for(
    doc: dict[str, Any],
    function_key: str,
    *,
    extra_contexts: dict[str, FunctionCtx] | None = None,
    extra_callee_ids: set[str] | frozenset[str] = frozenset(),
    io_model: OrderedIoContract | None = None,
) -> dict[str, Any]:
    """Dependency record: entry identity plus transitively called callees.

    ``extra_contexts``/``extra_callee_ids`` carry solver-admitted indirect
    callees whose reachability was proved during composition rather than
    from declared direct-call transfer metadata. ``io_model`` re-admits the
    closure under the declared ordered-I/O contract so dependency evidence
    matches the admission used during composition.
    """
    ctxs, ctx = group_lookup(doc, function_key, io_model=io_model)
    if extra_contexts:
        ctxs = {**ctxs, **extra_contexts}
    identities = dependency_identities(doc, contexts=ctxs)
    entry = identities.get(ctx.function_id)
    if entry is None:
        raise Real16CallRefusal("dependency_evidence_missing", {"function": ctx.function_id})
    callees = []
    for callee_id in sorted(reachable_call_ids(ctxs, ctx) | set(extra_callee_ids)):
        identity = identities.get(callee_id)
        if identity is None:
            raise Real16CallRefusal(
                "dependency_evidence_missing", {"function": callee_id}
            )
        callees.append(identity)
    return {"entry": entry, "callees": callees}
