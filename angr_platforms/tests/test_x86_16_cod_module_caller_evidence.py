from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from angr_platforms.X86_16.callsite_summary import CallerReturnUseVerdict8616
from angr_platforms.X86_16.cod_extract import extract_cod_proc_metadata
from angr_platforms.X86_16.lowering.callee_argument_count_evidence import (
    CalleeArgumentCountVerdict8616,
    collect_callee_argument_count_evidence_8616,
)
from angr_platforms.X86_16.lowering.callee_argument_width_evidence import (
    CalleeArgumentWidthVerdict8616,
    collect_callee_argument_width_evidence_8616,
)

from inertia_decompiler.cod_module_caller_evidence import record_cod_module_caller_return_use_evidence_8616

REPO_ROOT = Path(__file__).resolve().parents[2]


def _unavailable_isolated_body(_address: int, **_kwargs: object) -> SimpleNamespace:
    """Expose no decoded body at the synthetic isolated target address."""
    return SimpleNamespace(capstone=SimpleNamespace(insns=()))


def test_carr_cod_module_proves_setgear_result_is_unused() -> None:
    metadata = extract_cod_proc_metadata(REPO_ROOT / "cod" / "f14" / "CARR.COD", "_SetGear")
    evidence_owner = SimpleNamespace(
        factory=SimpleNamespace(block=_unavailable_isolated_body),
    )

    evidence = record_cod_module_caller_return_use_evidence_8616(metadata, 0x1000, evidence_owner)

    assert evidence.verdict is CallerReturnUseVerdict8616.UNUSED
    assert evidence.raw_fact_count == 1
    assert evidence.normalized_fact_count == 1
    assert evidence.classified_fact_count == 1
    assert evidence.materialized_count == 1
    assert evidence.failure_count == 0
    assert evidence.used_callsite_count == 0
    assert evidence.unused_callsite_count == 1
    assert evidence.callsite_addrs == (0x24AD,)

    count_evidence = collect_callee_argument_count_evidence_8616(evidence_owner, 0x1000)
    width_evidence = collect_callee_argument_width_evidence_8616(evidence_owner, 0x1000)
    assert count_evidence.verdict is CalleeArgumentCountVerdict8616.CONSISTENT
    assert count_evidence.argument_count == 1
    assert count_evidence.failure_count == 0
    assert width_evidence.verdict is CalleeArgumentWidthVerdict8616.CONSISTENT
    assert width_evidence.widths_by_offset == ((4, 2),)
    assert width_evidence.raw_fact_count == 1
    assert width_evidence.materialized_count == 1
    assert width_evidence.failure_count == 0


def test_cockpit_cod_module_proves_tidshowrange_result_is_unused() -> None:
    metadata = extract_cod_proc_metadata(
        REPO_ROOT / "cod" / "f14" / "COCKPIT.COD",
        "_TIDShowRange",
    )
    evidence_owner = SimpleNamespace()

    evidence = record_cod_module_caller_return_use_evidence_8616(
        metadata,
        0x1000,
        evidence_owner,
    )

    assert evidence.verdict is CallerReturnUseVerdict8616.UNUSED
    assert evidence.raw_fact_count == 1
    assert evidence.normalized_fact_count == 1
    assert evidence.classified_fact_count == 1
    assert evidence.materialized_count == 1
    assert evidence.failure_count == 0
    assert evidence.used_callsite_count == 0
    assert evidence.unused_callsite_count == 1
    assert evidence.callsite_addrs == (0x729,)
    assert evidence.fact_census_complete
