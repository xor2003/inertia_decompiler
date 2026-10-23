"""Regression for the named canonical IR pattern table.

Layer: IR tests.
Responsibility: prove typed match/precondition evidence, verified actions,
per-pattern policy, reentry refusal and commensurable census counters.
"""

from dataclasses import replace

import pytest
from pytest import MonkeyPatch

from inertia.ir import canonical_patterns
from inertia.ir import select_normalization as select_owner
from inertia.ir.canonical_patterns import (
    CANONICAL_PATTERN_SPECS_8616,
    SELECT_KNOWN_GUARD_PATTERN_8616,
    CanonicalPatternConfig8616,
    CanonicalPatternMatch8616,
    CanonicalPatternOutcome8616,
    CanonicalPatternSpec8616,
    CanonicalPatternState8616,
    SelectKnownGuardProof8616,
    apply_select_known_guard_8616,
    canonical_pattern_census_8616,
    canonical_pattern_config_8616,
    canonical_pattern_producers_8616,
    match_select_known_guard_8616,
    run_canonical_pattern_8616,
)
from inertia.ir.condition_lift_capture import ConditionLiftCaptureSession8616
from inertia.ir.core import IRBlock, IRInstr, IRValue, MemSpace
from inertia.ir.dead_temporary_surface_normalization import normalize_dead_temporary_surface_8616
from inertia.ir.select_normalization import (
    SelectNormalizationStatus8616,
    normalize_selects_8616,
    select_normalization_producers_8616,
)
from tests.ir.test_dead_temporary_surface_normalization import _selection_block
from tests.ir.test_select_normalization import block as select_block

_SPEC = CANONICAL_PATTERN_SPECS_8616[0]
_EMPTY = CanonicalPatternState8616({}, {})


def _state(tmps: dict[int, tuple[int, int]]) -> CanonicalPatternState8616:
    """Build a replay-state view with the given known-bits tmp table."""
    return CanonicalPatternState8616({}, dict(tmps))


def _select_row(bits: int = 8) -> IRInstr:
    """Build one admitted scalar SELECT row over three tmp operands."""
    size = (bits + 7) // 8
    return IRInstr(
        op=f"SELECT{bits}",
        dst=IRValue(MemSpace.TMP, source_tmp=9, size=size),
        args=(
            IRValue(MemSpace.TMP, source_tmp=0, size=1),
            IRValue(MemSpace.TMP, source_tmp=1, size=size),
            IRValue(MemSpace.TMP, source_tmp=2, size=size),
        ),
        size=size, addr=0x100,
    )


def test_match_binds_row_width_guard_and_chosen_arm() -> None:
    """The proof token binds the exact source row, width, guard and arm."""
    row = _select_row(16)
    match = match_select_known_guard_8616(row, _state({0: (0xFF, 0x01)}))
    assert match.admitted and match.proof is not None
    proof = match.proof
    assert proof.row is row and proof.bits == 16
    assert proof.guard_mask == 0xFF and proof.guard_value == 0x01
    assert proof.chosen is row.args[1]


@pytest.mark.parametrize("mask,value,chosen_index", [
    (0xFF, 0x01, 1),
    (0xFF, 0x02, 2),
    (0x01, 0x01, 1),
    (0x02, 0x02, None),
    (0x00, 0x00, None),
])
def test_guard_mask_and_value_ordering(mask: int, value: int, chosen_index: int | None) -> None:
    """The mask's bit 0 proves knowledge; the value's bit 0 picks the arm."""
    row = _select_row(8)
    match = match_select_known_guard_8616(row, _state({0: (mask, value)}))
    assert match.admitted
    if chosen_index is None:
        assert match.proof is None
    else:
        assert match.proof is not None
        assert match.proof.chosen is row.args[chosen_index]
        assert match.proof.guard_mask & 1


def test_shape_refusal_is_admitted_never_guessed() -> None:
    """A malformed SELECT admits nothing and yields no proof."""
    row = replace(_select_row(8), size=2)
    match = match_select_known_guard_8616(row, _state({0: (0xFF, 1)}))
    assert not match.admitted and match.proof is None


def test_apply_materializes_verified_row_replacement() -> None:
    """A bound proof yields the exact captured arm in a MOV row."""
    row = _select_row(8)
    state = _state({0: (0xFF, 0)})
    proof = match_select_known_guard_8616(row, state).proof
    assert proof is not None
    applied = apply_select_known_guard_8616(proof, row, state)
    assert applied is not None and applied.op == "MOV"
    assert applied.dst is row.dst and applied.args[0] is row.args[2]


def test_apply_refuses_stale_and_contradictory_proof() -> None:
    """Forged or drifted proof can never materialize a replacement."""
    row = _select_row(8)
    state = _state({0: (0xFF, 1)})
    proof = match_select_known_guard_8616(row, state).proof
    assert proof is not None
    assert apply_select_known_guard_8616(proof, replace(row, addr=0x200), state) is None
    assert apply_select_known_guard_8616(replace(proof, bits=16), row, state) is None
    assert apply_select_known_guard_8616(replace(proof, chosen=row.args[2]), row, state) is None
    assert apply_select_known_guard_8616(replace(proof, guard_value=0), row, state) is None
    assert apply_select_known_guard_8616(proof, row, _EMPTY) is None
    assert apply_select_known_guard_8616(proof, row, _state({0: (0xFF, 0)})) is None


@pytest.mark.parametrize("bits", [1, 8, 16, 32, 64])
@pytest.mark.parametrize("mask,value", [(0x00, 0x00), (0x02, 0x02), (0x02, 0x00), (0xFE, 0xFE)])
def test_apply_never_authorizes_unknown_guard_bit(bits: int, mask: int, value: int) -> None:
    """A bound pair whose mask lacks the selecting bit never picks an arm."""
    row = _select_row(bits)
    state = _state({0: (mask, value)})
    forged = SelectKnownGuardProof8616(row, bits, mask, value, row.args[2])
    assert apply_select_known_guard_8616(forged, row, state) is None


def test_runner_refuses_forged_match_evidence() -> None:
    """Forged match output reaches the verified action and is refused."""
    row = _select_row(8)
    forged = SelectKnownGuardProof8616(row, 8, 0, 0, row.args[2])
    spec = replace(_SPEC, match=lambda r, s: CanonicalPatternMatch8616(True, forged))
    step = run_canonical_pattern_8616(spec, row, _state({0: (0, 0)}), CanonicalPatternConfig8616())
    assert step.outcome is CanonicalPatternOutcome8616.REFUSED_STALE
    assert step.row is row and step.proof is forged
    assert not canonical_patterns._ACTIVE_PATTERN_KEYS_8616


def test_forged_match_under_unknown_eval_keeps_exact_row() -> None:
    """Replay refuses a forged proof whose bound pair lacks a known bit."""
    original = select_block(0, 8)
    guard = IRInstr(
        op="Iop_Or8",
        dst=IRValue(MemSpace.TMP, source_tmp=0, size=1),
        args=(IRValue(MemSpace.REG, name="al", size=1), IRValue(MemSpace.CONST, const=2, size=1)),
        size=1,
    )
    original = replace(original, instrs=(guard, *original.instrs[1:]))
    select_row = original.instrs[-1]
    forged = SelectKnownGuardProof8616(select_row, 8, 2, 2, select_row.args[2])
    spec = replace(_SPEC, match=lambda r, s: CanonicalPatternMatch8616(True, forged))
    block, admitted, rewritten, steps = select_owner._rewrite_prefix_8616(
        original, (spec,), CanonicalPatternConfig8616(),
    )
    assert block is original and admitted == 1 and rewritten == 0
    (step,) = steps
    assert step.outcome is CanonicalPatternOutcome8616.REFUSED_STALE
    assert block.instrs[-1].op == "SELECT8"


@pytest.mark.parametrize("bits", [1, 8, 16, 32, 64])
def test_normalize_records_matched_step_per_width(bits: int) -> None:
    """Every registered width records one MATCHED step and materializes once."""
    result = normalize_selects_8616(select_block(0, bits))
    (step,) = result.pattern_steps
    assert step.pattern == SELECT_KNOWN_GUARD_PATTERN_8616
    assert step.outcome is CanonicalPatternOutcome8616.MATCHED
    assert step.admitted and step.proof is not None and step.proof.bits == bits
    assert result.block.instrs[-1] is step.row and step.row.op == "MOV"
    assert result.evidence.classified_fact_count == result.evidence.materialized_count == 1


def test_unknown_guard_records_unmatched_not_materialized() -> None:
    """Scanning without proof keeps the row and never counts a transform."""
    original = select_block(None, 8)
    result = normalize_selects_8616(original)
    (step,) = result.pattern_steps
    assert step.outcome is CanonicalPatternOutcome8616.UNMATCHED
    assert step.admitted and step.proof is None and step.row is original.instrs[-1]
    assert result.block is original
    assert result.evidence.normalized_fact_count == 1
    assert result.evidence.classified_fact_count == result.evidence.materialized_count == 0


def test_partial_mask_without_guard_bit_keeps_exact_row() -> None:
    """A guard whose mask lacks bit 0 is admitted yet never rewritten."""
    original = select_block(0, 8)
    guard = IRInstr(
        op="Iop_Or8",
        dst=IRValue(MemSpace.TMP, source_tmp=0, size=1),
        args=(IRValue(MemSpace.REG, name="al", size=1), IRValue(MemSpace.CONST, const=2, size=1)),
        size=1,
    )
    original = replace(original, instrs=(guard, *original.instrs[1:]))
    result = normalize_selects_8616(original)
    (step,) = result.pattern_steps
    assert step.outcome is CanonicalPatternOutcome8616.UNMATCHED
    assert result.block.instrs[-1] is original.instrs[-1]
    assert result.block.instrs[-1].op == "SELECT8"
    assert result.evidence.materialized_count == 0


def test_disabled_pattern_keeps_select_without_replay(monkeypatch: MonkeyPatch) -> None:
    """A disabled pattern records SKIPPED and skips dependency replay."""

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("disabled patterns must not replay dependencies")

    monkeypatch.setattr(select_owner, "_collect_block_facts", forbidden)
    monkeypatch.setattr(select_owner, "_rewrite_prefix_8616", forbidden)
    original = select_block(0, 8)
    config = canonical_pattern_config_8616(disabled={SELECT_KNOWN_GUARD_PATTERN_8616})
    result = normalize_selects_8616(original, config=config)
    assert result.block is original
    assert result.status is SelectNormalizationStatus8616.COMPLETE
    assert result.evidence.raw_fact_count == 1
    assert result.evidence.normalized_fact_count == result.evidence.materialized_count == 0
    assert result.evidence.failure_count == 0
    (step,) = result.pattern_steps
    assert step.outcome is CanonicalPatternOutcome8616.SKIPPED_DISABLED


def test_env_disables_pattern_in_real_surface_path(monkeypatch: MonkeyPatch) -> None:
    """Environment policy reaches the import path and retains the SELECT."""
    monkeypatch.setenv("INERTIA_DISABLE_CANONICAL_PATTERNS", SELECT_KNOWN_GUARD_PATTERN_8616)
    block = _selection_block()
    result = normalize_dead_temporary_surface_8616(
        (block,), ConditionLiftCaptureSession8616({}, {}), (), {},
    )
    assert any(row.op == "SELECT8" for row in result.blocks[0].instrs)
    summary = result.to_summary()
    assert summary["canonical_pattern_select_known_guard_skipped_disabled_count"] == 1
    assert summary["select_materialized_count"] == 0
    assert summary["select_failure_count"] == 0


def test_explicit_config_disables_only_this_pattern() -> None:
    """Selective disable keeps SELECT; the default path still materializes."""
    block = _selection_block()
    enabled = normalize_dead_temporary_surface_8616(
        (block,), ConditionLiftCaptureSession8616({}, {}), (), {},
    )
    assert not any(row.op == "SELECT8" for row in enabled.blocks[0].instrs)
    summary = enabled.to_summary()
    assert summary["canonical_pattern_select_known_guard_matched_count"] == 1
    disabled = normalize_dead_temporary_surface_8616(
        (block,), ConditionLiftCaptureSession8616({}, {}), (), {},
        pattern_config=canonical_pattern_config_8616(disabled={SELECT_KNOWN_GUARD_PATTERN_8616}),
    )
    kept = disabled.blocks[0]
    assert any(row.op == "SELECT8" for row in kept.instrs)
    assert {row.addr for row in kept.instrs} == {row.addr for row in block.instrs}


def test_unknown_pattern_name_is_refused(monkeypatch: MonkeyPatch) -> None:
    """Unknown names in typed or environment policy are never ignored."""
    with pytest.raises(ValueError, match="unknown canonical pattern"):
        canonical_pattern_config_8616(disabled={"not_a_pattern"})
    monkeypatch.setenv("INERTIA_DISABLE_CANONICAL_PATTERNS", "not_a_pattern")
    with pytest.raises(ValueError, match="unknown canonical pattern"):
        canonical_pattern_config_8616()


def test_direct_config_construction_validates_names() -> None:
    """The typed policy itself refuses unknown names and normalizes input."""
    with pytest.raises(ValueError, match="unknown canonical pattern"):
        CanonicalPatternConfig8616(disabled={"not_a_pattern"})
    config = CanonicalPatternConfig8616(disabled=[SELECT_KNOWN_GUARD_PATTERN_8616])
    assert config.disabled == frozenset({SELECT_KNOWN_GUARD_PATTERN_8616})
    assert CanonicalPatternConfig8616().disabled == frozenset()


def test_reentry_is_refused_and_guard_released() -> None:
    """A reentrant attempt on the same row is refused, never nested."""
    row = _select_row(8)
    state = _state({0: (0xFF, 1)})
    config = CanonicalPatternConfig8616()
    inner_steps: list[canonical_patterns.CanonicalPatternStep8616] = []

    def reentrant_match(r: IRInstr, s: CanonicalPatternState8616) -> CanonicalPatternMatch8616:
        inner_steps.append(run_canonical_pattern_8616(spec, r, s, config))
        return match_select_known_guard_8616(r, s)

    spec = CanonicalPatternSpec8616(
        name=SELECT_KNOWN_GUARD_PATTERN_8616,
        candidate=_SPEC.candidate,
        match=reentrant_match,
        apply=_SPEC.apply,
    )
    step = run_canonical_pattern_8616(spec, row, state, config)
    assert step.outcome is CanonicalPatternOutcome8616.MATCHED
    (inner,) = inner_steps
    assert inner.outcome is CanonicalPatternOutcome8616.REFUSED_REENTRY
    assert not inner.admitted
    assert not canonical_patterns._ACTIVE_PATTERN_KEYS_8616


def test_match_error_keeps_cause_and_releases_guard() -> None:
    """An unexpected match error propagates its cause and cleans up."""

    def raising_match(row: IRInstr, state: CanonicalPatternState8616) -> CanonicalPatternMatch8616:
        raise RuntimeError("synthetic match failure")

    spec = replace(_SPEC, match=raising_match)
    with pytest.raises(RuntimeError, match="synthetic match failure"):
        run_canonical_pattern_8616(spec, _select_row(8), _EMPTY, CanonicalPatternConfig8616())
    assert not canonical_patterns._ACTIVE_PATTERN_KEYS_8616


def test_stale_action_refusal_is_not_materialized() -> None:
    """A refused verified action stays admitted but never materializes."""
    original = select_block(0, 8)
    refusing = replace(_SPEC, apply=lambda proof, live, state: None)
    block, admitted, rewritten, steps = select_owner._rewrite_prefix_8616(
        original, (refusing,), CanonicalPatternConfig8616(),
    )
    assert block is original and admitted == 1 and rewritten == 0
    (step,) = steps
    assert step.outcome is CanonicalPatternOutcome8616.REFUSED_STALE and step.admitted


def test_candidate_free_block_skips_policy_resolution(monkeypatch: MonkeyPatch) -> None:
    """No candidate means no policy resolution, dependency or numeric work."""

    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("candidate-free blocks must not resolve policy")

    monkeypatch.setattr(canonical_patterns, "canonical_pattern_config_8616", forbidden)
    original = IRBlock(addr=0x100, instrs=(IRInstr(op="opaque", dst=None, args=()),))
    result = normalize_selects_8616(original)
    assert result.block is original
    assert result.evidence.raw_fact_count == 0 and result.pattern_steps == ()


def test_decisions_and_counters_are_deterministic() -> None:
    """Repeated runs over one block yield identical decisions and counters."""
    original = select_block(1, 16)
    first = normalize_selects_8616(original)
    second = normalize_selects_8616(original)
    assert first.block == second.block and first.evidence == second.evidence
    assert [(s.pattern, s.outcome, s.admitted) for s in first.pattern_steps] == [
        (s.pattern, s.outcome, s.admitted) for s in second.pattern_steps
    ]


def test_census_aggregates_per_pattern_outcomes() -> None:
    """The ledger census counts outcomes per named pattern, not transforms."""
    matched = normalize_selects_8616(select_block(0, 8))
    assert canonical_pattern_census_8616(list(matched.pattern_steps)) == {
        "select_known_guard_matched": 1,
    }
    disabled = normalize_selects_8616(
        select_block(0, 8),
        config=canonical_pattern_config_8616(disabled={SELECT_KNOWN_GUARD_PATTERN_8616}),
    )
    assert canonical_pattern_census_8616(list(disabled.pattern_steps)) == {
        "select_known_guard_skipped_disabled": 1,
    }


def test_producer_closure_binds_pattern_table_and_actions() -> None:
    """The sealed registry binds the table, specs, match, action and policy."""
    producers = select_normalization_producers_8616()
    assert canonical_pattern_producers_8616 in producers
    assert CANONICAL_PATTERN_SPECS_8616 in producers
    assert _SPEC in producers
    for authority in (
        run_canonical_pattern_8616,
        match_select_known_guard_8616,
        apply_select_known_guard_8616,
        canonical_pattern_config_8616,
    ):
        assert authority in producers
    assert tuple(map(id, producers)) == tuple(map(id, select_normalization_producers_8616()))
    assert tuple(map(id, canonical_pattern_producers_8616())) == tuple(
        map(id, canonical_pattern_producers_8616())
    )


@pytest.mark.decompiler
@pytest.mark.parametrize("authority", ["match", "apply", "config", "table"])
def test_native_cache_rejects_replaced_pattern_authority(
    monkeypatch: MonkeyPatch, authority: str,
) -> None:
    """A replaced sealed producer is re-derived, never served from staleness.

    Each case swaps one canonical authority for a wrapper or rebound table;
    the import cache must detect the changed producer identity and re-run
    normalization (observed through the dependency visitor), returning an
    identical surface rather than the stale cached one.
    """
    from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
    from inertia.ir import dead_temporary_normalization as normalization
    from inertia.ir import native_import_surface_cache as cache
    from inertia.ir import vex_import as vex
    from tests.ir.test_native_import_surface_cache import _world

    apply_x86_16_bootstrap()
    project, boundary, _calls, _request = _world(bytes.fromhex("b83412eb02909089d0c3"))
    observer = normalization._value_children
    visits: list[IRValue] = []

    def observed(value: IRValue) -> tuple[object, ...] | None:
        visits.append(value)
        return observer(value)

    original_match = match_select_known_guard_8616
    original_apply = apply_select_known_guard_8616
    original_config = canonical_pattern_config_8616
    with cache.native_import_request_8616():
        monkeypatch.setattr(normalization, "_value_children", observed)
        first = vex._import_x86_16_function_surface_8616(project, boundary)
        assert first.dead_temporary_normalization is not None
        visits.clear()
        if authority == "match":
            monkeypatch.setattr(
                canonical_patterns, "match_select_known_guard_8616",
                lambda row, state: original_match(row, state),
            )
        elif authority == "apply":
            monkeypatch.setattr(
                canonical_patterns, "apply_select_known_guard_8616",
                lambda proof, row, state: original_apply(proof, row, state),
            )
        elif authority == "config":
            monkeypatch.setattr(
                canonical_patterns, "canonical_pattern_config_8616",
                lambda disabled=None, *, env=None: original_config(disabled, env=env),
            )
        else:
            monkeypatch.setattr(
                canonical_patterns, "CANONICAL_PATTERN_SPECS_8616",
                (*CANONICAL_PATTERN_SPECS_8616,),
            )
        second = vex._import_x86_16_function_surface_8616(project, boundary)
        assert visits
        assert second.dead_temporary_normalization is not None
        assert second.dead_temporary_normalization.to_summary() == (
            first.dead_temporary_normalization.to_summary()
        )


_POLICY_ENV_8616 = "INERTIA_DISABLE_CANONICAL_PATTERNS"


def _policy_request_world_8616(
    monkeypatch: MonkeyPatch,
) -> tuple[object, list[int], object]:
    """Build the real native cache-request world over a typed SELECT input.

    The importer feeds the real surface normalizer a synthetic captured
    block; this is a cache lifecycle fixture, not a claim that the SELECT
    came from the boundary's machine bytes.
    """
    from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
    from inertia.ir import native_import_surface_cache as cache
    from inertia.ir import vex_import
    from tests.ir.test_native_import_surface_cache import _world

    apply_x86_16_bootstrap()
    monkeypatch.delenv(_POLICY_ENV_8616, raising=False)
    project, boundary, _calls, _request = _world()
    imports: list[int] = []

    def importer(_project: object, _boundary: object) -> object:
        imports.append(1)
        return normalize_dead_temporary_surface_8616(
            (_selection_block(),), ConditionLiftCaptureSession8616({}, {}), (), {},
        )

    def admit(_surface: object, _function: object) -> bool:
        return True

    def request() -> object:
        return cache.request_native_surface_8616(
            project, boundary, importer,
            producers=vex_import._native_import_producers_8616(),
            admit=admit,
        )

    return request, imports, cache


def _has_select_8616(result: object) -> bool:
    """Report whether the surface retains any SELECT8 row."""
    return any(row.op == "SELECT8" for row in result.blocks[0].instrs)


@pytest.mark.decompiler
def test_cache_reuse_honors_pattern_policy_transitions(monkeypatch: MonkeyPatch) -> None:
    """enabled -> disabled -> enabled re-derives; identical policy hits."""
    request, imports, cache = _policy_request_world_8616(monkeypatch)
    with cache.native_import_request_8616():
        enabled = request()
        assert len(imports) == 1 and not _has_select_8616(enabled)
        assert not _has_select_8616(request()) and len(imports) == 1
        monkeypatch.setenv(_POLICY_ENV_8616, SELECT_KNOWN_GUARD_PATTERN_8616)
        disabled = request()
        assert _has_select_8616(disabled) and len(imports) == 2
        assert _has_select_8616(request()) and len(imports) == 2
        monkeypatch.delenv(_POLICY_ENV_8616)
        reenabled = request()
        assert not _has_select_8616(reenabled) and len(imports) == 3
        assert not _has_select_8616(request()) and len(imports) == 3


@pytest.mark.decompiler
def test_cache_refuses_unknown_policy_before_reuse(monkeypatch: MonkeyPatch) -> None:
    """An unknown disable name refuses even with an enabled result cached."""
    request, imports, cache = _policy_request_world_8616(monkeypatch)
    with cache.native_import_request_8616():
        request()
        monkeypatch.setenv(_POLICY_ENV_8616, "bogus_name")
        with pytest.raises(ValueError, match="unknown canonical pattern"):
            request()
    assert len(imports) == 1


@pytest.mark.decompiler
def test_mid_import_policy_change_is_never_published_under_old_key(
    monkeypatch: MonkeyPatch,
) -> None:
    """A policy flip inside the importer is not retained under the entry key."""
    from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
    from inertia.ir import native_import_surface_cache as cache
    from inertia.ir import vex_import
    from tests.ir.test_native_import_surface_cache import _world

    apply_x86_16_bootstrap()
    monkeypatch.delenv(_POLICY_ENV_8616, raising=False)
    project, boundary, _calls, _request = _world()
    imports: list[int] = []

    def flipping_importer(_project: object, _boundary: object) -> object:
        imports.append(1)
        monkeypatch.setenv(_POLICY_ENV_8616, SELECT_KNOWN_GUARD_PATTERN_8616)
        return normalize_dead_temporary_surface_8616(
            (_selection_block(),), ConditionLiftCaptureSession8616({}, {}), (), {},
        )

    def admit(_surface: object, _function: object) -> bool:
        return True

    def request() -> object:
        return cache.request_native_surface_8616(
            project, boundary, flipping_importer,
            producers=vex_import._native_import_producers_8616(),
            admit=admit,
        )

    with cache.native_import_request_8616():
        first = request()
        assert _has_select_8616(first) and len(imports) == 1
        second = request()
        assert _has_select_8616(second) and len(imports) == 2
        assert _has_select_8616(request()) and len(imports) == 2
