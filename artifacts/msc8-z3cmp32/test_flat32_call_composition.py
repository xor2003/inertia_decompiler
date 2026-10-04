"""Regression evidence for bounded flat32 direct-call composition proofs.

Real i386 bytes are lifted through pyvex/angr and compared with real Z3.
The oracle code in every fixture is a caller that loads its first stack
argument, issues a near ``call rel32``, continues in the caller and returns;
the callee body lives at a separate declared range.  Positive controls must
pass and every changed argument, callee store, stack cleanup or return-path
corruption must fail or refuse.
"""

import sys
from pathlib import Path
from typing import Any

import angr
import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import flat32_region
from flat32_adapter import GPRS, REG_NAMES, S, installed

from tools.dosunit.flat32_call_composition import (
    CallCompositionLimits,
    CallCompositionRefusal,
    compare_functions_with_calls,
    summarize_with_calls,
)

BASE = 0x100000
OTHER_BASE = 0x200000
OUTPUTS = GPRS

# caller: mov eax,[esp+4]; call 0x0d; add eax,2; ret   (13 bytes, call ends 0x09)
# callee at 0x0d: add eax,5; ret                       (4 bytes)
CALLER = "8b442404 e804000000 83c002 c3"
CALLEE = "83c005 c3"
CODE = f"{CALLER} {CALLEE}"


def _project(code: str, base: int = BASE) -> angr.Project:
    """Load real i386 bytes as a flat shellcode project."""
    return angr.load_shellcode(bytes.fromhex(code.replace(" ", "")), arch="x86", load_address=base)


def _functions(base: int, callee_offset: int = 0x0D, callee_size: int = 4) -> dict[int, int]:
    """Declared complete byte ranges for the default caller/callee fixture."""
    return {base: 0x0D, base + callee_offset: callee_size}


def _compare(
    oracle_code: str,
    candidate_code: str,
    *,
    oracle_functions: dict[int, int] | None = None,
    candidate_functions: dict[int, int] | None = None,
    oracle_base: int = BASE,
    candidate_base: int = BASE,
    timeout_ms: int = 10000,
    limits: CallCompositionLimits | None = None,
    candidate_normalization: dict[int, int] | None = None,
    outputs: tuple[str, ...] = OUTPUTS,
) -> dict[str, Any]:
    """Compare two composed call regions under the installed flat32 seams."""
    with installed(region=True):
        return compare_functions_with_calls(
            _project(oracle_code, oracle_base),
            _project(candidate_code, candidate_base),
            oracle_entry=oracle_base,
            candidate_entry=candidate_base,
            oracle_functions=oracle_functions or _functions(oracle_base),
            candidate_functions=candidate_functions or _functions(candidate_base),
            outputs=outputs,
            timeout_ms=timeout_ms,
            limits=limits,
            candidate_normalization=candidate_normalization,
        )


def _caller_parts(code: str, base: int, spans: list[tuple[int, int]]) -> list[dict[str, Any]]:
    """Lift caller blocks into flat32_region parts for the refused baseline."""
    project = _project(code, base)
    parts: list[dict[str, Any]] = []
    for offset, size in spans:
        block = project.factory.block(base + offset, size=size, opt_level=0)
        lowered = S._lower_irsb(
            block.vex,
            output_regs=(*REG_NAMES, "ip"),
            max_assignments_per_function=2048,
        )
        assert not isinstance(lowered, S.LowerFailure), lowered
        parts.append(
            {
                "entry": {"linear": hex(base + offset)},
                "function_entry": {"linear": hex(base)},
                "source": {"jumpkind": block.vex.jumpkind},
                **lowered,
            }
        )
    return parts


def test_region_refuses_calls_while_composition_proves_them() -> None:
    """Red: region machinery refuses call blocks; green: composition proves."""
    with installed(region=True):
        parts = _caller_parts(CODE, BASE, [(0, 9), (9, 4)])
        refused = flat32_region.compare_region(parts, parts, outputs=("eax", "esp"), timeout_ms=3000)
    assert refused["status"] == "refused"
    assert refused["reason"] == "call_or_exception_boundary"

    result = _compare(CODE, CODE)
    assert result["status"] == "passed"
    assert result["oracle_inlined_calls"] == 1
    assert result["return_targets_proved"] == 2


def test_equivalent_callee_encoding_passes() -> None:
    """A changed-equivalent callee encoding still proves."""
    lea_callee = "8b442404 e804000000 83c002 c3 8d4005 c3"
    assert _compare(CODE, lea_callee)["status"] == "passed"


def test_callee_stack_writes_stay_observable() -> None:
    """Callee push/pop leaves a real memory difference; strict equality fails it."""
    frame_callee = "8b442404 e804000000 83c002 c3 53 bb05000000 01d8 5b c3"
    result = _compare(
        CODE,
        frame_callee,
        candidate_functions={BASE: 0x0D, BASE + 0x0D: 10},
    )
    assert result["status"] == "failed"


def test_nested_direct_call_chain_passes_and_mutations_fail() -> None:
    """A f->g->h chain composes transitively; a changed leaf invalidates it."""
    chain = "8b442404 e804000000 83c002 c3 e804000000 83c003 c3 83c804 c3"
    changed_leaf = "8b442404 e804000000 83c002 c3 e804000000 83c003 c3 83c805 c3"
    functions = {BASE: 0x0D, BASE + 0x0D: 9, BASE + 0x16: 4}
    passed = _compare(chain, chain, oracle_functions=functions, candidate_functions=functions)
    assert passed["status"] == "passed"
    assert passed["oracle_inlined_calls"] == 2
    assert _compare(
        chain,
        changed_leaf,
        oracle_functions=functions,
        candidate_functions=functions,
    )["status"] == "failed"


@pytest.mark.parametrize(
    "candidate_callee",
    [
        "83c006 c3",  # changed constant: eax +6 instead of +5
        "0344240c c3",  # changed argument slot: [esp+0c] instead of [esp+8]
        "83c005 c20400",  # changed cleanup: ret 4 instead of ret
    ],
)
def test_changed_callee_semantics_fail(candidate_callee: str) -> None:
    """A changed callee result, argument read or cleanup is a real mismatch."""
    oracle_code = "8b442404 e804000000 83c002 c3 03442408 c3"
    candidate_code = f"8b442404 e804000000 83c002 c3 {candidate_callee}"
    oracle_functions = {BASE: 0x0D, BASE + 0x0D: 5}
    candidate_functions = {BASE: 0x0D, BASE + 0x0D: len(bytes.fromhex(candidate_callee))}
    result = _compare(
        oracle_code,
        candidate_code,
        oracle_functions=oracle_functions,
        candidate_functions=candidate_functions,
    )
    assert result["status"] == "failed"


def test_caller_argument_and_callee_store_changes_fail() -> None:
    """A changed caller argument load and a callee frame store are caught."""
    changed_argument = "8b442408 e804000000 83c002 c3 83c005 c3"
    assert _compare(CODE, changed_argument)["status"] == "failed"
    callee_store = "8b442404 e804000000 83c002 c3 c74424082a000000 83c005 c3"
    result = _compare(
        CODE,
        callee_store,
        candidate_functions={BASE: 0x0D, BASE + 0x0D: 12},
    )
    assert result["status"] == "failed"


def test_corrupted_or_unprovable_return_path_refuses() -> None:
    """Checked RET behavior: clobbered or unbalanced return slots refuse."""
    corrupted = "8b442404 e804000000 83c002 c3 c7042478563412 c3"
    result = _compare(
        CODE,
        corrupted,
        candidate_functions={BASE: 0x0D, BASE + 0x0D: 8},
    )
    assert result["status"] == "refused"
    assert result["reason"] == "call_return_target_mismatch"

    # sub esp,4; ret reads a symbolic slot: the solver finds inputs where the
    # return does not reach the fallthrough, so composition refuses.
    unbalanced = "8b442404 e804000000 83c002 c3 83ec04 c3"
    result = _compare(
        CODE,
        unbalanced,
        candidate_functions={BASE: 0x0D, BASE + 0x0D: 4},
    )
    assert result["status"] == "refused"
    assert result["reason"].startswith("call_return_target")


def test_two_call_sites_and_conditional_call_pass() -> None:
    """Repeated sites reuse the proved callee; a call in one branch arm merges."""
    two_sites = "8b442404 e80e000000 83c001 e806000000 83c002 c3 9090 83c005 c3"
    result = _compare(
        two_sites,
        two_sites,
        oracle_functions={BASE: 0x15, BASE + 0x17: 4},
        candidate_functions={BASE: 0x15, BASE + 0x17: 4},
    )
    assert result["status"] == "passed"
    assert result["oracle_inlined_calls"] == 2

    conditional = "85c0 7407 e80a000000 eb00 83c002 c3 90909090 83c005 c3"
    result = _compare(
        conditional,
        conditional,
        oracle_functions={BASE: 0x0F, BASE + 0x13: 4},
        candidate_functions={BASE: 0x0F, BASE + 0x13: 4},
    )
    assert result["status"] == "passed"
    assert result["oracle_inlined_calls"] == 1


def test_branchy_callee_passes_and_changed_arm_fails() -> None:
    """A callee with merged return arms composes; mutating one arm fails."""
    branchy = "8b442404 e804000000 83c002 c3 85c0 7405 83c005 c3 90 83c807 c3"
    functions = {BASE: 0x0D, BASE + 0x0D: 0x0D}
    changed_arm = "8b442404 e804000000 83c002 c3 85c0 7405 83c006 c3 90 83c807 c3"
    assert _compare(
        branchy, branchy, oracle_functions=functions, candidate_functions=functions
    )["status"] == "passed"
    assert _compare(
        branchy, changed_arm, oracle_functions=functions, candidate_functions=functions
    )["status"] == "failed"


def test_indirect_unmapped_and_recursive_calls_refuse() -> None:
    """Indirect, undelcared-target and recursive calls are never inlined."""
    indirect = "8b442404 ffd0 83c002 c3 83c005 c3"
    result = _compare(
        indirect,
        indirect,
        oracle_functions={BASE: 0x0D, BASE + 0x0D: 4},
        candidate_functions={BASE: 0x0D, BASE + 0x0D: 4},
    )
    assert result["status"] == "refused"
    assert result["reason"].startswith("call_indirect_target")

    result = _compare(
        CODE,
        CODE,
        oracle_functions={BASE: 0x0D},
        candidate_functions={BASE: 0x0D},
    )
    assert result["status"] == "refused"
    assert result["reason"].startswith("call_target_unmapped")

    recursive = "8b442404 e804000000 83c002 c3 e8fbffffff c3"
    result = _compare(
        recursive,
        recursive,
        oracle_functions={BASE: 0x0D, BASE + 0x0D: 6},
        candidate_functions={BASE: 0x0D, BASE + 0x0D: 6},
    )
    assert result["status"] == "refused"
    assert result["reason"].startswith("recursive_call")


def test_relocation_needs_explicit_normalization() -> None:
    """Relocated stores fail strictly; a caller-supplied map stays conditional."""
    moved = _compare(CODE, CODE, candidate_base=OTHER_BASE)
    assert moved["status"] == "failed"

    functions = _functions(OTHER_BASE)
    result = _compare(
        CODE,
        CODE,
        candidate_base=OTHER_BASE,
        candidate_functions=functions,
        candidate_normalization={OTHER_BASE + 0x09: BASE + 0x09},
    )
    # The normalization map is an unproved relational assumption: the backend
    # equality holds, but the verdict must remain conditional, never passed.
    assert result["status"] == "conditional"
    assert result["reason"] == "unproved_constant_normalization"
    assumptions = result["assumptions"]
    assert assumptions["kind"] == "caller_supplied_constant_relocation"
    assert assumptions["proved"] is False
    assert assumptions["provenance"] == "caller_supplied_map"
    assert assumptions["constant_map"] == {hex(OTHER_BASE + 0x09): hex(BASE + 0x09)}


def test_preserved_registers_observed_under_narrow_outputs() -> None:
    """A callee clobbering ebx fails even when the caller only asks for eax."""
    clobber = "8b442404 e804000000 83c002 c3 bb07000000 83c005 c3"
    result = _compare(
        CODE,
        clobber,
        candidate_functions={BASE: 0x0D, BASE + 0x0D: 9},
        outputs=("eax",),
    )
    assert result["status"] == "failed"
    # Same binary under the narrow selection still proves.
    assert _compare(CODE, CODE, outputs=("eax",))["status"] == "passed"


def test_budget_and_depth_limits_refuse() -> None:
    """Exhausted composition, block or inline budgets are visible refusals."""
    chain = "8b442404 e804000000 83c002 c3 e804000000 83c003 c3 83c804 c3"
    functions = {BASE: 0x0D, BASE + 0x0D: 9, BASE + 0x16: 4}
    result = _compare(
        chain,
        chain,
        oracle_functions=functions,
        candidate_functions=functions,
        limits=CallCompositionLimits(max_inline_depth=1),
    )
    assert result["status"] == "refused"
    assert result["reason"] == "call_inline_depth_limit"

    result = _compare(CODE, CODE, limits=CallCompositionLimits(max_blocks_per_function=1))
    assert result["status"] == "refused"
    assert result["reason"] == "block_limit"


def test_summarize_reports_call_evidence_and_refusals() -> None:
    """The summary document carries call evidence; unknown entries refuse."""
    with installed(region=True):
        summary = summarize_with_calls(
            _project(CODE),
            entry=BASE,
            functions=_functions(BASE),
            outputs=OUTPUTS,
            labels={BASE + 0x0D: "callee"},
        )
        assert summary["inlined_calls"] == 1
        assert summary["call_sites"][0]["callee"] == "callee"
        with pytest.raises(CallCompositionRefusal):
            summarize_with_calls(
                _project(CODE),
                entry=BASE + 0x40,
                functions=_functions(BASE),
                outputs=OUTPUTS,
            )


# stdcall caller: push 7; call +0x0b; add eax,2; ret   (11 bytes, call ends 0x07)
# Every callee below ends in ``ret 4``, so the caller's pushed argument and
# the callee's stack cleanup are part of the exercised contract.
CALLER_RET4 = "6a07 e804000000 83c002 c3"
RET4_CALLSITE = BASE + 0x02  # exact CALL IMark, after the argument push
RET4_FALLTHROUGH = BASE + 0x07
RET4_CALLEE = BASE + 0x0B


def _ret4_functions(callee_size: int) -> dict[int, int]:
    """Declared ranges for the stdcall caller/callee fixtures."""
    return {BASE: 0x0B, RET4_CALLEE: callee_size}


def test_ret4_callee_disjoint_stack_store_proves() -> None:
    """A callee store to [esp+8] cannot reach the [esp] return slot: proved."""
    clean = "8b442404 c20400"  # mov eax,[esp+4]; ret 4
    stored = "8b442404 c74424082a000000 c20400"  # + mov dword [esp+8],0x2a
    clean_code = f"{CALLER_RET4} {clean}"
    stored_code = f"{CALLER_RET4} {stored}"
    passed = _compare(
        stored_code,
        stored_code,
        oracle_functions=_ret4_functions(15),
        candidate_functions=_ret4_functions(15),
    )
    assert passed["status"] == "passed"
    assert passed["oracle_inlined_calls"] == 1
    assert passed["return_targets_proved"] == 2
    for side in ("oracle", "candidate"):
        call = passed["call_sites"][side][0]
        assert call["callsite"] == hex(RET4_CALLSITE)
        assert call["call_block"] == hex(BASE)
    # The disjoint store stays observable: dropping it is a real mismatch.
    changed = _compare(
        clean_code,
        stored_code,
        oracle_functions=_ret4_functions(7),
        candidate_functions=_ret4_functions(15),
    )
    assert changed["status"] == "failed"


def test_unconstrained_callee_pointer_store_refuses() -> None:
    """A store through a symbolic pointer may alias the return slot: refuse."""
    callee = "c7002a000000 c20400"  # mov dword [eax],0x2a; ret 4
    code = f"{CALLER_RET4} {callee}"
    result = _compare(
        code,
        code,
        oracle_functions=_ret4_functions(9),
        candidate_functions=_ret4_functions(9),
    )
    assert result["status"] == "refused"
    assert result["reason"].startswith("call_return_target")
    failure = result["return_proof_failure"]
    assert failure["callsite"] == hex(RET4_CALLSITE)
    assert failure["call_block"] == hex(BASE)
    assert failure["target"] == hex(RET4_CALLEE)
    assert failure["fallthrough"] == hex(RET4_FALLTHROUGH)
    assert failure["side"] == "oracle"
    assert failure["status"] in ("counterexample", "unknown")


def test_return_slot_corruption_publishes_counterexample_evidence() -> None:
    """A store to [esp] corrupts the return slot; the countermodel is kept."""
    clean = "8b442404 c20400"  # mov eax,[esp+4]; ret 4
    corrupt = "c704242a000000 c20400"  # mov dword [esp],0x2a; ret 4
    clean_code = f"{CALLER_RET4} {clean}"
    corrupt_code = f"{CALLER_RET4} {corrupt}"

    def _assert_corruption_failure(result: dict[str, Any], side: str) -> None:
        assert result["status"] == "refused"
        assert result["reason"] == "call_return_target_mismatch"
        failure = result["return_proof_failure"]
        assert failure["status"] == "counterexample"
        assert failure["side"] == side
        assert failure["callsite"] == hex(RET4_CALLSITE)
        assert failure["call_block"] == hex(BASE)
        assert failure["target"] == hex(RET4_CALLEE)
        assert failure["fallthrough"] == hex(RET4_FALLTHROUGH)
        solver_result = failure["solver_result"]
        assert solver_result["status"] == "failed"
        eip_mismatches = [
            item for item in solver_result["mismatches"] if item.get("reg") == "eip"
        ]
        assert eip_mismatches, solver_result
        mismatch = eip_mismatches[0]
        assert int(mismatch["oracle_value"], 16) == 0x2A
        assert int(mismatch["candidate_value"], 16) == RET4_FALLTHROUGH
        assert isinstance(mismatch["counterexample"], dict) and mismatch["counterexample"]

    same = _compare(
        corrupt_code,
        corrupt_code,
        oracle_functions=_ret4_functions(10),
        candidate_functions=_ret4_functions(10),
    )
    _assert_corruption_failure(same, "oracle")
    candidate_side = _compare(
        clean_code,
        corrupt_code,
        oracle_functions=_ret4_functions(7),
        candidate_functions=_ret4_functions(10),
    )
    _assert_corruption_failure(candidate_side, "candidate")
