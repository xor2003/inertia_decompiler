"""Derivation receipts record whether a census consulted the entry-call pool.

The receipt is observational only: ``UNKNOWN`` means no canonical census
ran, ``UNUSED`` means a completed canonical census never reached the pool
lookup, and ``READ`` means at least one CALL row — real or feasibility
scratch — consulted the pool, including failed or empty lookups.
"""
import time

import pytest

from inertia.ir import real16_invocation_domain as owner
from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from tests.ir.test_declared_function_entry_domain import _recompute
from tests.ir.test_raw_callee_scoped_call_chain import _collect
from tests.ir.test_raw_callee_scoped_call_chain import calls_with_pending_helper as calls_with_pending_helper

pytestmark = pytest.mark.decompiler


def _derive(world: tuple, callsite_addr: int, records: tuple) -> tuple:
    """Run the canonical declared-entry derivation and expose the receipt."""
    project, boot, artifact, boundary, _resolver, admission = world
    link = owner.DeclaredFunctionEntryLink8616(admission, artifact, boundary)
    with direct_evidence_deadline_scope_8616(project, time.monotonic() + 20), native_import_request_8616():
        return owner._derive_declared_function_entry_domain_8616(
            project, link, callsite_addr, boot=boot, boot_recompute=_recompute,
            entry_call_preservations=records,
        )


def test_first_call_prefix_reports_entry_pool_unused(calls_with_pending_helper: tuple) -> None:
    """A prefix ending at the first CALL never consults a nonempty pool."""
    records = tuple(_collect(calls_with_pending_helper))
    assert len(records) == 2
    _domain, derived = _derive(calls_with_pending_helper, 0x1043, records)
    assert derived.failure is None and derived.domain is not None
    assert derived.entry_call_pool_consultation is owner._EntryCallPoolConsultation8616.UNUSED


def test_interior_call_prefix_reports_entry_pool_read(calls_with_pending_helper: tuple) -> None:
    """Crossing the first CALL to reach the second consults the pool."""
    records = tuple(_collect(calls_with_pending_helper))
    _domain, derived = _derive(calls_with_pending_helper, 0x1046, records)
    assert derived.failure is None and derived.domain is not None
    assert derived.entry_call_pool_consultation is owner._EntryCallPoolConsultation8616.READ


def test_post_census_refusal_reports_read_on_empty_pool(calls_with_pending_helper: tuple) -> None:
    """A failed lookup on an empty pool is still a consultation, and the
    post-census refusal exit surfaces it."""
    _domain, derived = _derive(calls_with_pending_helper, 0x1046, ())
    assert derived.failure is not None and derived.domain is None
    assert derived.entry_call_pool_consultation is owner._EntryCallPoolConsultation8616.READ


def test_rejected_scratch_consultation_propagates(
    calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A scratch pool lookup that binds no record still marks the real ctx."""
    records = tuple(_collect(calls_with_pending_helper))
    captured = []
    census = owner._census_invocation_8616

    def capture(
        ctx: owner._PathCensusContext8616, *args: object, **kwargs: object,
    ) -> object:
        result = census(ctx, *args, **kwargs)
        if ctx.callsite_addr == 0x1043:
            captured.append(ctx)
        return result

    monkeypatch.setattr(owner, "_census_invocation_8616", capture)
    _domain, derived = _derive(calls_with_pending_helper, 0x1043, records)
    assert derived.failure is None and captured
    ctx = captured[-1]
    assert ctx.entry_call_pool_consulted is False

    _project, _boot, artifact, _boundary, _resolver, _admission = calls_with_pending_helper
    block, instruction = next(
        (blk, row) for blk in artifact.blocks for row in blk.instrs if row.addr == 0x1046
    )
    # The pool is consulted, but no retained record binds this CALL row.
    ctx.entry_call_preservations = tuple(
        record for record in records if record.callsite_addr != 0x1046
    )
    result = owner._feasibility_call_scratch_8616(
        ctx, artifact, block, instruction,
        {"sp": 0xFFFE, "ss": 0x2000, "cs": 0x1000},
        owner.path_memory_initial_8616(), (),
    )
    assert result is False
    assert ctx.entry_call_pool_consulted is True


def test_pre_census_refusal_reports_unknown(calls_with_pending_helper: tuple) -> None:
    """A refusal before any census keeps the receipt unknown, not unused."""
    project, boot, _artifact, _boundary, _resolver, _admission = calls_with_pending_helper
    _domain, derived = owner._derive_declared_function_entry_domain_8616(
        project, None, 0x1043, boot=boot, boot_recompute=_recompute,
        entry_call_preservations=(),
    )
    assert derived.failure is owner.Real16InvocationFailure8616.DECLARED_ENTRY_UNPROVEN
    assert derived.entry_call_pool_consultation is owner._EntryCallPoolConsultation8616.UNKNOWN


@pytest.mark.parametrize('scratch_kind', ['call', 'service'])
@pytest.mark.parametrize('raises', [False, True])
def test_scratch_consultation_survives_every_exit(
    calls_with_pending_helper: tuple, monkeypatch: pytest.MonkeyPatch,
    scratch_kind: str, raises: bool,
) -> None:
    """Both scratch consumers preserve consultation on rejection and loud errors."""
    captured = []
    census = owner._census_invocation_8616

    def capture(ctx: owner._PathCensusContext8616, *args: object, **kwargs: object) -> object:
        result = census(ctx, *args, **kwargs)
        captured.append(ctx)
        return result

    monkeypatch.setattr(owner, '_census_invocation_8616', capture)
    _domain, derived = _derive(calls_with_pending_helper, 0x1043, ())
    assert derived.failure is None and captured
    ctx = captured[-1]
    assert not ctx.entry_call_pool_consulted
    artifact = calls_with_pending_helper[2]
    block, instruction = next(
        (blk, row) for blk in artifact.blocks for row in blk.instrs if row.addr == 0x1046
    )

    def consult(scratch: owner._PathCensusContext8616, *args: object) -> object:
        assert scratch is not ctx
        scratch.entry_call_pool_consulted = True
        if raises:
            raise ValueError('scratch boundary failed after consultation')
        return False if scratch_kind == 'call' else owner.Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN

    name = '_feasibility_call_effect_8616' if scratch_kind == 'call' else '_declared_service_crossing_8616'
    monkeypatch.setattr(owner, name, consult)

    def run() -> bool:
        registers = {'sp': 0xFFFE, 'ss': 0x2000, 'cs': 0x1000}
        memory = owner.path_memory_initial_8616()
        if scratch_kind == 'call':
            return owner._feasibility_call_scratch_8616(ctx, artifact, block, instruction, registers, memory, ())
        return owner._feasibility_apply_service_8616(ctx, artifact, instruction, registers, memory)

    if raises:
        with pytest.raises(ValueError, match='scratch boundary failed after consultation'):
            run()
    else:
        assert not run()
    assert ctx.entry_call_pool_consulted
