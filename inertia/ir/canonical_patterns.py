"""Named canonical IR pattern table with typed proof and verified actions.

Layer: IR.
Responsibility: own the fixed named pattern specs consumed by the SELECT
prefix replay: typed per-candidate match/precondition evidence, a verifying
action that refuses stale or contradictory proof, typed per-pattern
enable/disable configuration, deterministic per-row audited decisions, and
single-flight reentry refusal. Numeric authority stays with the scalar
dispatcher and the known-bits owner; this module only binds their outputs
into auditable proof tokens. No guessing, no deletion, no environment or
entry-state assumptions are introduced here.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from enum import StrEnum

from . import real16_edge_feasibility8616 as kb
from . import scalar_instruction_effects as scalar
from .core import IRActiveUnary8616, IRInstr, IRValue, MemSpace

SELECT_KNOWN_GUARD_PATTERN_8616: str = "select_known_guard"

_CANONICAL_PATTERN_DISABLE_ENV_8616: str = "INERTIA_DISABLE_CANONICAL_PATTERNS"

# (pattern name, row identity) pairs currently inside one attempt. Guarded
# rows stay alive on the replay stack for the whole attempt, so an id key
# cannot be recycled while its entry is present.
_ACTIVE_PATTERN_KEYS_8616: set[tuple[str, int]] = set()


class CanonicalPatternOutcome8616(StrEnum):
    """Typed audited outcome of one pattern attempt on one row.

    These are attempt decisions, never transform counters: only MATCHED rows
    produced a verified replacement and may be counted as materialized.
    """

    MATCHED = "matched"
    UNMATCHED = "unmatched"
    SKIPPED_DISABLED = "skipped_disabled"
    REFUSED_STALE = "refused_stale"
    REFUSED_REENTRY = "refused_reentry"


@dataclass(frozen=True, slots=True)
class CanonicalPatternState8616:
    """Live known-bits replay state viewed by one pattern attempt.

    The mappings are the coordinator's active register/tmp tables, not a
    snapshot: a deferred action re-evaluating through them observes the
    apply-time state, which is exactly what stale-proof refusal requires.
    """

    registers: dict[str, tuple[int, int]]
    tmps: dict[int, tuple[int, int]]


@dataclass(frozen=True, slots=True)
class SelectKnownGuardProof8616:
    """Typed precondition proof bound to one SELECT row at one replay step.

    Binds the exact source row identity, its scalar-registered result width,
    the known-bits guard (mask, value) and the captured arm object chosen by
    the proven guard bit.
    """

    row: IRInstr
    bits: int
    guard_mask: int
    guard_value: int
    chosen: IRValue


@dataclass(frozen=True, slots=True)
class CanonicalPatternMatch8616:
    """One match attempt: admission verdict plus optional applicable proof."""

    admitted: bool
    proof: SelectKnownGuardProof8616 | None = None


@dataclass(frozen=True, slots=True)
class CanonicalPatternSpec8616:
    """One named auditable pattern: cheap gate, typed match, verified action."""

    name: str
    candidate: Callable[[IRInstr], bool]
    match: Callable[[IRInstr, CanonicalPatternState8616], CanonicalPatternMatch8616]
    apply: Callable[[SelectKnownGuardProof8616, IRInstr, CanonicalPatternState8616], IRInstr | None]


@dataclass(frozen=True, slots=True)
class CanonicalPatternStep8616:
    """Audited decision for one pattern attempt on one row.

    ``admitted`` records that scalar shape preconditions held (the admission
    count); ``row`` carries the original or the verified replacement. A
    retained ``proof`` keeps the consumed evidence inspectable; it is never
    itself a transform certificate.
    """

    pattern: str
    outcome: CanonicalPatternOutcome8616
    admitted: bool
    row: IRInstr
    proof: SelectKnownGuardProof8616 | None = None


@dataclass(frozen=True, slots=True)
class CanonicalPatternConfig8616:
    """Typed per-pattern enable/disable policy for canonical IR patterns.

    Construction is total validation: any iterable is normalized to a
    frozenset, and names outside the registered pattern table are refused
    rather than silently ignored.
    """

    disabled: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        """Normalize the disabled set and refuse unregistered pattern names."""
        names = frozenset(self.disabled)
        if type(self.disabled) is not frozenset:
            object.__setattr__(self, "disabled", names)
        unknown = names - canonical_pattern_names_8616()
        if unknown:
            raise ValueError(f"unknown canonical pattern names: {sorted(unknown)}")


def canonical_pattern_names_8616() -> frozenset[str]:
    """Return the registered pattern names accepted by typed config."""
    return frozenset(spec.name for spec in CANONICAL_PATTERN_SPECS_8616)


def canonical_pattern_config_8616(
    disabled: Iterable[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> CanonicalPatternConfig8616:
    """Resolve typed pattern policy; unknown names are refused, never ignored.

    An explicit ``disabled`` iterable is authoritative; otherwise the
    ``INERTIA_DISABLE_CANONICAL_PATTERNS`` comma-separated names apply. The
    typed constructor performs the registry validation, so every policy —
    explicit, resolved, or directly built — obeys the same refusal.
    """
    names: set[str] = set()
    if disabled is not None:
        names.update(disabled)
    else:
        environment = os.environ if env is None else env
        raw = environment.get(_CANONICAL_PATTERN_DISABLE_ENV_8616, "")
        names.update(entry.strip() for entry in raw.split(",") if entry.strip())
    return CanonicalPatternConfig8616(disabled=frozenset(names))


def _select_candidate_8616(row: IRInstr) -> bool:
    """Recognize only operation names registered by the scalar owner."""
    return scalar.frozen_dispatch_lookup(scalar._SELECT_BITS_8616, row.op) is not None


def match_select_known_guard_8616(
    row: IRInstr, state: CanonicalPatternState8616,
) -> CanonicalPatternMatch8616:
    """Bind admitted scalar shape plus a proven guard bit into one token.

    Admission is the scalar owner's registered shape verdict; the proof
    exists only when the guard's least significant bit is *known* (mask bit
    0 set). A known mask with an unknown guard bit admits the row but keeps
    it unchanged.
    """
    bits = scalar.scalar_select_result_bits_8616(row)
    if bits is None:
        return CanonicalPatternMatch8616(admitted=False)
    guard = kb._kb_eval_value_8616(row.args[0], state.registers, state.tmps)
    if guard is None or not guard[0] & 1:
        return CanonicalPatternMatch8616(admitted=True)
    chosen = row.args[1 if guard[1] & 1 else 2]
    if not isinstance(chosen, IRValue):
        return CanonicalPatternMatch8616(admitted=True)
    return CanonicalPatternMatch8616(
        admitted=True,
        proof=SelectKnownGuardProof8616(
            row=row, bits=bits, guard_mask=guard[0], guard_value=guard[1],
            chosen=chosen,
        ),
    )


def _select_known_guard_move_8616(proof: SelectKnownGuardProof8616) -> IRInstr:
    """Preserve exact width and captured value identity of the proven arm."""
    source = proof.chosen
    if proof.bits == 1:
        source = IRValue(
            MemSpace.TMP, size=1, expr=("Iop_8to1",),
            active_unary=IRActiveUnary8616("Iop_8to1", proof.chosen, 1),
        )
    return replace(proof.row, op="MOV", args=(source,))


def apply_select_known_guard_8616(
    proof: SelectKnownGuardProof8616,
    live_row: IRInstr,
    state: CanonicalPatternState8616,
) -> IRInstr | None:
    """Materialize the chosen arm only while the bound proof still holds.

    Refuses stale or contradictory evidence: the live row must be the proof's
    row object, still admit the same registered width, still bind the same
    captured arm, and the guard must still evaluate to the identical
    (mask, value) pair under the apply-time state. Above all, the evaluated
    mask's bit 0 must be set: an unknown selecting bit can never authorize a
    chosen arm, regardless of what the bound pair claims.
    """
    if live_row is not proof.row:
        return None
    row = proof.row
    if scalar.scalar_select_result_bits_8616(row) != proof.bits:
        return None
    if row.args[1 if proof.guard_value & 1 else 2] is not proof.chosen:
        return None
    guard = kb._kb_eval_value_8616(row.args[0], state.registers, state.tmps)
    if guard is None or not guard[0] & 1 or guard != (proof.guard_mask, proof.guard_value):
        return None
    return _select_known_guard_move_8616(proof)


def _run_canonical_pattern_inner_8616(
    spec: CanonicalPatternSpec8616,
    row: IRInstr,
    state: CanonicalPatternState8616,
    config: CanonicalPatternConfig8616,
) -> CanonicalPatternStep8616:
    """Evaluate one pattern's policy, match and verified action once."""
    if spec.name in config.disabled:
        return CanonicalPatternStep8616(
            spec.name, CanonicalPatternOutcome8616.SKIPPED_DISABLED, False, row,
        )
    match = spec.match(row, state)
    if not match.admitted or match.proof is None:
        return CanonicalPatternStep8616(
            spec.name, CanonicalPatternOutcome8616.UNMATCHED, match.admitted, row,
        )
    applied = spec.apply(match.proof, row, state)
    if applied is None:
        return CanonicalPatternStep8616(
            spec.name, CanonicalPatternOutcome8616.REFUSED_STALE, True, row, match.proof,
        )
    return CanonicalPatternStep8616(
        spec.name, CanonicalPatternOutcome8616.MATCHED, True, applied, match.proof,
    )


def run_canonical_pattern_8616(
    spec: CanonicalPatternSpec8616,
    row: IRInstr,
    state: CanonicalPatternState8616,
    config: CanonicalPatternConfig8616,
) -> CanonicalPatternStep8616:
    """Attempt one named pattern once under typed policy and reentry refusal.

    A reentrant attempt on the same (pattern, row) pair is refused without
    executing the match; the guard slot is always released, including when
    the match or action raises, and the original exception propagates
    unchanged.
    """
    key = (spec.name, id(row))
    if key in _ACTIVE_PATTERN_KEYS_8616:
        return CanonicalPatternStep8616(
            spec.name, CanonicalPatternOutcome8616.REFUSED_REENTRY, False, row,
        )
    _ACTIVE_PATTERN_KEYS_8616.add(key)
    try:
        return _run_canonical_pattern_inner_8616(spec, row, state, config)
    finally:
        _ACTIVE_PATTERN_KEYS_8616.discard(key)


CANONICAL_PATTERN_SPECS_8616: tuple[CanonicalPatternSpec8616, ...] = (
    CanonicalPatternSpec8616(
        name=SELECT_KNOWN_GUARD_PATTERN_8616,
        candidate=_select_candidate_8616,
        match=match_select_known_guard_8616,
        apply=apply_select_known_guard_8616,
    ),
)


def canonical_pattern_census_8616(
    steps: tuple[CanonicalPatternStep8616, ...] | list[CanonicalPatternStep8616],
) -> dict[str, int]:
    """Aggregate audited steps into deterministic per-pattern outcome counts."""
    census: dict[str, int] = {}
    for step in steps:
        key = f"{step.pattern}_{step.outcome.value}"
        census[key] = census.get(key, 0) + 1
    return census


def canonical_pattern_producers_8616() -> tuple[object, ...]:
    """Bind the pattern table and every match/action/config authority used."""
    return (
        CANONICAL_PATTERN_SPECS_8616,
        *CANONICAL_PATTERN_SPECS_8616,
        CanonicalPatternSpec8616,
        CanonicalPatternStep8616,
        SelectKnownGuardProof8616,
        CanonicalPatternMatch8616,
        CanonicalPatternState8616,
        CanonicalPatternConfig8616,
        CanonicalPatternConfig8616.__post_init__,
        canonical_pattern_names_8616,
        canonical_pattern_config_8616,
        run_canonical_pattern_8616,
        _run_canonical_pattern_inner_8616,
        canonical_pattern_census_8616,
        _select_candidate_8616,
        match_select_known_guard_8616,
        apply_select_known_guard_8616,
        _select_known_guard_move_8616,
        scalar.scalar_select_result_bits_8616,
        kb._kb_eval_value_8616,
    )
