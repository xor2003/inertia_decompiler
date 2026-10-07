"""Regression evidence for the opt-in flat32 block-lift retry cap.

The default ``max_blocks_per_function`` cap stays at 64 blocks per closure.
An explicit ``retry_max_blocks_per_function`` opt-in — a strict integer
greater than the initial cap and at most ``RETRY_BLOCK_CAP_MAXIMUM`` —
lets one worklist that demonstrably reached the original cap continue the
same pending queue and already-lifted blocks once up to the retry cap.

All cases lift real i386 byte chains through pyvex/angr and compare with
real Z3.  The chain fixture is a linear run of ``add eax,1; jmp +0``
units ending in ``ret``: ``jmp +0`` is a real ``Ijk_Boring`` block
boundary whose constant ``next`` names the following unit, so a chain of
N units exercises exactly N lifted blocks with no conditional exits and
no calls.
"""

import sys
import time
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest
from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane
from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "artifacts" / "msc8-z3cmp32"))
sys.path.insert(0, str(ROOT))

from flat32_adapter import installed
from tools.dosunit.tests.test_flat32_compose_total_budget import (
    BASE,
    OUTPUTS,
    _Clock,
    _compare,
    _project,
)

import tools.dosunit.compare.flat32_call_lowering as _lowering
from tools.dosunit.compare.flat32_call_composition import (
    CallCompositionLimits,
    CallCompositionRefusal,
    summarize_with_calls,
)
from tools.dosunit.compare.flat32_call_contracts import (
    RETRY_BLOCK_CAP_MAXIMUM,
    _ComposeSession,
    _normalize_function_map,
    _register_widths,
)
from tools.dosunit.compare.flat32_call_lowering import _lift_function

_CHAIN_UNIT = "83c001eb00"
"""One chain unit: ``add eax,1`` then ``jmp +0`` into the next unit (5 bytes)."""

_CHAIN_BLOCKS = 80
"""Closure size above the default 64 cap and below the 128 retry bound."""


def _chain(blocks: int = _CHAIN_BLOCKS, units: dict[int, str] | None = None) -> str:
    """Build one acyclic chain of ``blocks`` real VEX blocks ending in ``ret``.

    ``units`` overrides individual unit encodings; each override must keep
    the trailing ``eb00`` jump so the chain stays a one-block-per-unit
    closure with identical layout on both sides.
    """
    parts = [_CHAIN_UNIT] * (blocks - 1) + ["c3"]
    for index, encoding in (units or {}).items():
        parts[index] = encoding
    return " ".join(parts)


def _functions(code: str) -> dict[int, int]:
    """Declare the whole chain image as one function byte range."""
    return {BASE: len(bytes.fromhex(code.replace(" ", "")))}


def _summarize(code: str, **kwargs: Any) -> dict[str, Any]:
    """Run standalone composition over the chain under the flat32 seams."""
    with installed(region=True):
        return summarize_with_calls(
            _project(code),
            entry=BASE,
            functions=_functions(code),
            outputs=OUTPUTS,
            **kwargs,
        )


def test_default_cap_still_refuses_over_64_blocks() -> None:
    """The opt-in is off by default: an 80-block closure keeps refusing."""
    code = _chain()
    result = _compare(
        code,
        code,
        oracle_functions=_functions(code),
        candidate_functions=_functions(code),
    )
    assert result["status"] == "refused"
    assert result["reason"] == "block_limit"
    

def test_opt_in_retry_proves_equal_and_records_typed_evidence() -> None:
    """An 80-block identical pair proves equal and reports the engaged retry."""
    code = _chain()
    result = _compare(
        code,
        code,
        oracle_functions=_functions(code),
        candidate_functions=_functions(code),
        limits=CallCompositionLimits(retry_max_blocks_per_function=RETRY_BLOCK_CAP_MAXIMUM),
    )
    assert result["status"] == "passed"
    expected = [
        {
            "entry": hex(BASE),
            "initial_cap": 64,
            "retry_cap": RETRY_BLOCK_CAP_MAXIMUM,
            "blocks_lifted": _CHAIN_BLOCKS,
        }
    ]
    assert result["block_lift_retries"] == {"oracle": expected, "candidate": expected}
    assert result["oracle_blocks_composed"] == _CHAIN_BLOCKS
    assert result["candidate_blocks_composed"] == _CHAIN_BLOCKS


def test_below_cap_closure_never_engages_retry() -> None:
    """A function completing under the initial cap records no retry."""
    result = _compare(
        limits=CallCompositionLimits(retry_max_blocks_per_function=RETRY_BLOCK_CAP_MAXIMUM),
    )
    assert result["status"] == "passed"
    assert result["block_lift_retries"] == {"oracle": [], "candidate": []}


def test_retry_lifts_each_block_once_and_caches_complete_closure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The continuation never relifts; a closed map is cached and reused."""
    code = _chain()
    real_lift_block = _lowering._lift_block
    lifted: list[int] = []

    def counting(session: _ComposeSession, function_entry: int, address: int, end: int) -> Any:
        lifted.append(address)
        return real_lift_block(session, function_entry, address, end)

    monkeypatch.setattr(_lowering, "_lift_block", counting)
    with installed(region=True):
        session = _ComposeSession(
            project=_project(code),
            functions=_normalize_function_map(_functions(code)),
            labels={},
            limits=CallCompositionLimits(
                retry_max_blocks_per_function=RETRY_BLOCK_CAP_MAXIMUM
            ),
            reg_widths=_register_widths(),
        )
        first = _lift_function(session, BASE)
        second = _lift_function(session, BASE)
    assert second is first
    assert len(lifted) == _CHAIN_BLOCKS
    assert len(set(lifted)) == _CHAIN_BLOCKS
    assert session.blocks_lifted == _CHAIN_BLOCKS
    retries = session.block_lift_retries
    assert len(retries) == 1
    retry = retries[0]
    assert retry.entry == BASE
    assert retry.initial_cap == 64
    assert retry.retry_cap == RETRY_BLOCK_CAP_MAXIMUM
    assert retry.blocks_lifted == _CHAIN_BLOCKS


def test_retry_exhaustion_remains_refused() -> None:
    """A closure larger than the retry cap still refuses with block_limit."""
    code = _chain(blocks=RETRY_BLOCK_CAP_MAXIMUM + 2)
    result = _compare(
        code,
        code,
        oracle_functions=_functions(code),
        candidate_functions=_functions(code),
        limits=CallCompositionLimits(retry_max_blocks_per_function=RETRY_BLOCK_CAP_MAXIMUM),
    )
    assert result["status"] == "refused"
    assert result["reason"] == "block_limit"


def test_exhausted_retry_publishes_no_partial_closure() -> None:
    """A refused continuation caches nothing and records no retry evidence."""
    code = _chain(blocks=RETRY_BLOCK_CAP_MAXIMUM + 2)
    with installed(region=True):
        session = _ComposeSession(
            project=_project(code),
            functions=_normalize_function_map(_functions(code)),
            labels={},
            limits=CallCompositionLimits(
                retry_max_blocks_per_function=RETRY_BLOCK_CAP_MAXIMUM
            ),
            reg_widths=_register_widths(),
        )
        with pytest.raises(CallCompositionRefusal, match="block_limit"):
            _lift_function(session, BASE)
    assert session.blocks == {}
    assert session.block_lift_retries == []
    assert session.blocks_lifted == 0


@pytest.mark.parametrize(
    ("oracle_unit", "candidate_unit"),
    [
        ("83c001eb00", "83c002eb00"),
        ("a300200000eb00", "a304200000eb00"),
    ],
    ids=["arithmetic", "store"],
)
def test_changed_block_semantics_still_fail_under_retry(
    oracle_unit: str, candidate_unit: str
) -> None:
    """Opt-in retry changes reachability, not verdicts: deltas still fail.

    ``arithmetic`` replaces one ``add eax,1`` with ``add eax,2``;
    ``store`` replaces ``mov [0x2000],eax`` with ``mov [0x2004],eax``.
    """
    oracle_code = _chain(units={40: oracle_unit})
    candidate_code = _chain(units={40: candidate_unit})
    result = _compare(
        oracle_code,
        candidate_code,
        oracle_functions=_functions(oracle_code),
        candidate_functions=_functions(candidate_code),
        limits=CallCompositionLimits(retry_max_blocks_per_function=RETRY_BLOCK_CAP_MAXIMUM),
    )
    assert result["status"] == "failed"


def test_shared_deadline_refuses_mid_continuation(monkeypatch: pytest.MonkeyPatch) -> None:
    """A deadline expiring during the retry extension refuses; no reset happens."""
    code = _chain()
    clock = _Clock()
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    real_lift_block = _lowering._lift_block
    lifted: list[int] = []

    def advancing(session: _ComposeSession, function_entry: int, address: int, end: int) -> Any:
        block = real_lift_block(session, function_entry, address, end)
        lifted.append(address)
        clock.advance(0.05)
        return block

    monkeypatch.setattr(_lowering, "_lift_block", advancing)
    # The 70th lift pushes the fake clock to deadline; the next per-block
    # deadline check refuses — well past the initial 64-block cap.
    with installed(region=True), pytest.raises(
        CallCompositionRefusal, match="compose_budget_exceeded"
    ):
        summarize_with_calls(
            _project(code),
            entry=BASE,
            functions=_functions(code),
            outputs=OUTPUTS,
            limits=CallCompositionLimits(
                retry_max_blocks_per_function=RETRY_BLOCK_CAP_MAXIMUM
            ),
            total_deadline=clock.now + 3.5,
        )
    assert len(lifted) > 64


def test_other_budgets_unchanged_by_retry_opt_in() -> None:
    """A tiny composition budget still refuses even when the lift retry applies."""
    code = _chain()
    with installed(region=True), pytest.raises(
        CallCompositionRefusal, match="region_composition_limit"
    ):
        summarize_with_calls(
            _project(code),
            entry=BASE,
            functions=_functions(code),
            outputs=OUTPUTS,
            limits=CallCompositionLimits(
                max_compositions=8,
                retry_max_blocks_per_function=RETRY_BLOCK_CAP_MAXIMUM,
            ),
        )


@pytest.mark.parametrize(
    "retry_cap",
    [True, False, 0, -1, 32, 64, 129, 256, 65.0, "128", b"96"],
    ids=["bool-true", "bool-false", "zero", "negative", "below-cap", "at-cap",
         "over-bound", "far-over-bound", "float", "str", "bytes"],
)
def test_invalid_retry_cap_policies_refuse(retry_cap: Any) -> None:
    """Malformed retry caps refuse at the contract boundary, never silently clamp."""
    with pytest.raises(CallCompositionRefusal, match="invalid_retry_block_cap"):
        CallCompositionLimits(retry_max_blocks_per_function=retry_cap)


@pytest.mark.parametrize("retry_cap", [65, 96, RETRY_BLOCK_CAP_MAXIMUM])
def test_valid_retry_cap_bounds_accepted(retry_cap: int) -> None:
    """Strict ints strictly between the initial cap and the bound are accepted."""
    limits = CallCompositionLimits(retry_max_blocks_per_function=retry_cap)
    assert limits.retry_max_blocks_per_function == retry_cap


def test_retry_field_appended_preserves_positional_construction() -> None:
    """Existing positional construction keeps its meaning; the field defaults off."""
    legacy = CallCompositionLimits(64, 4, 32, 1, 12000, 4096, 2048, 1000, 64, 128)
    assert legacy.retry_max_blocks_per_function is None
    full = CallCompositionLimits(
        64, 4, 32, 128, 12000, 4096, 2048, 1000, 64, 128, 32, None, 8
    )
    assert full.retry_max_blocks_per_function is None
    extended = CallCompositionLimits(
        64, 4, 32, 128, 12000, 4096, 2048, 1000, 64, 128, 32, None, 8, 96
    )
    assert extended.retry_max_blocks_per_function == 96
    assert extended.max_indirect_call_targets == 8


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_public_adapter_retry_proves_a_complete_large_callee(tmp_path: Path, driver: str) -> None:
    """Both public drivers consume the bounded continuation without assumptions."""
    caller = bytes.fromhex("e801000000c3")
    chain = bytes.fromhex(_chain())
    paths = [tmp_path / f"side{index}.exe" for index in range(3)]
    for path, body in zip(paths, (chain, chain, bytes.fromhex(_chain(units={70: "83c002eb00"}))), strict=True):
        path.write_bytes(pe32_bytes(caller + body))
    listing = tmp_path / "input.lst"
    entry = 0x401000
    callee = entry + len(caller)
    listing.write_text(
        f".text:{entry:08X} f proc\n.text:{callee - 1:08X} f endp\n"
        f".text:{callee:08X} callee proc\n.text:{callee + len(chain) - 1:08X} callee endp\n"
    )
    with _driver_lane(driver) as lane:
        reports = []
        for name, candidate, retry in (("default", paths[1], None), ("retry", paths[1], 128),
                                        ("changed", paths[2], 128)):
            out_dir = tmp_path / name
            out_dir.mkdir()
            args = Namespace(
                oracle_exe=paths[0], oracle_lst=listing, candidate_exe=candidate,
                candidate_lst=listing, candidate_lst_end_kind="last-instruction", candidate_syms=None,
                cache_dir=None, functions="f", mode="region", scan_limit=8192, timeout_ms=10000,
                region_max_blocks=128, normalize_globals=False, assume_paired_calls=False,
                output_regs=",".join(register for register, _ in lane.adapter.REG32.values()),
                retry_block_limit=retry, out_dir=out_dir,
            )
            with lane.adapter.installed(region=True):
                reports.append(lane.z3cmp32.compare(args))
    assert reports[0]["results"][0]["status"] == "refused", reports[0]["results"][0]
    row = reports[1]["results"][0]
    assert row["status"] == "passed" and not row.get("assumptions"), row
    assert row["proof_method"] == "checked_direct_call_composition"
    assert reports[1]["input_domain"]["call_block_retry_policy"]["retry_cap"] == 128
    assert row["block_lift_retries"]["oracle"][0]["blocks_lifted"] == _CHAIN_BLOCKS
    assert reports[2]["results"][0]["status"] == "failed", reports[2]["results"][0]
