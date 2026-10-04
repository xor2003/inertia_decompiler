"""Staged regression evidence for acyclic flat32 tail-transfer composition.

Real i386 bytes are lifted through pyvex/angr and compared with real Z3.
The core fixture mirrors the reviewed oracle.exe chain: a caller near-calls
a one-instruction ``jmp`` thunk declared as its own function, and the thunk
unconditionally transfers to a separately declared callee entry outside its
byte range.  Positive controls must pass (including the constant-folded
register-indirect boundary and a conditional sibling arm), changed callee
semantics must fail, and interior/undeclared/indirect/conditional/
fallthrough-contiguous/cyclic/depth-capped transfers must keep refusing
with their typed reasons.

The routine cohort imports the current repository modules directly.
"""

import sys
from pathlib import Path
from typing import Any

import angr

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "artifacts" / "msc8-z3cmp32"))
sys.path.insert(0, str(ROOT))

from flat32_adapter import GPRS, installed

from tools.dosunit.flat32_call_composition import (
    CallCompositionLimits,
    compare_functions_with_calls,
    summarize_with_calls,
)
from tools.dosunit.flat32_call_contracts import (
    _ComposeSession,
    _normalize_function_map,
    _register_widths,
)
from tools.dosunit.flat32_call_execution import _compose_function

BASE = 0x100000
OUTPUTS = GPRS

# caller: mov eax,[esp+4]; call BASE+0x0d; add eax,2; ret   (0x0d bytes)
# thunk  at BASE+0x0d: jmp BASE+0x16                        (5 bytes, rel +4)
# pad    at BASE+0x12..0x15, callee at BASE+0x16: add eax,5; ret  (4 bytes)
TAIL_CODE = "8b442404 e804000000 83c002 c3 e904000000 90909090 83c005 c3"
TAIL_FUNCTIONS = {BASE: 0x0D, BASE + 0x0D: 5, BASE + 0x16: 4}
TAIL_THUNK = BASE + 0x0D
TAIL_CALLEE = BASE + 0x16


def _project(code: str, base: int = BASE) -> angr.Project:
    """Load real i386 bytes as a flat shellcode project."""
    return angr.load_shellcode(bytes.fromhex(code.replace(" ", "")), arch="x86", load_address=base)


def _compare(
    oracle_code: str,
    candidate_code: str,
    *,
    oracle_functions: dict[int, int] | None = None,
    candidate_functions: dict[int, int] | None = None,
    timeout_ms: int = 10000,
    limits: CallCompositionLimits | None = None,
    outputs: tuple[str, ...] = OUTPUTS,
) -> dict[str, Any]:
    """Compare two composed regions under the installed flat32 seams."""
    with installed(region=True):
        return compare_functions_with_calls(
            _project(oracle_code),
            _project(candidate_code),
            oracle_entry=BASE,
            candidate_entry=BASE,
            oracle_functions=oracle_functions or TAIL_FUNCTIONS,
            candidate_functions=candidate_functions or TAIL_FUNCTIONS,
            outputs=outputs,
            timeout_ms=timeout_ms,
            limits=limits,
        )


def _tail_code(callee: str, thunk: str = "e904000000", pad: str = "90909090") -> str:
    """Rebuild the call-thunk-callee fixture with a swapped body."""
    return f"8b442404 e804000000 83c002 c3 {thunk} {pad} {callee}"


def test_tail_thunk_under_call_passes() -> None:
    """Green: call -> jmp thunk -> callee composes and returns to fallthrough."""
    result = _compare(TAIL_CODE, TAIL_CODE)
    assert result["status"] == "passed"
    assert result["oracle_inlined_calls"] == 1
    assert result["candidate_inlined_calls"] == 1
    assert result["return_targets_proved"] == 2
    assert result["oracle_tail_transfers"] == 1
    assert result["candidate_tail_transfers"] == 1
    for side in ("oracle", "candidate"):
        call = result["call_sites"][side][0]
        assert call["target"] == hex(TAIL_THUNK)
        assert call["fallthrough"] == hex(BASE + 0x09)
        tail = result["tail_sites"][side][0]
        assert tail["site"] == hex(TAIL_THUNK)
        assert tail["block"] == hex(TAIL_THUNK)
        assert tail["target"] == hex(TAIL_CALLEE)
        assert tail["depth"] == 2


def test_root_tail_transfer_passes() -> None:
    """Green: a root function whose terminal is a tail jmp composes cleanly."""
    root_tail = "8b442404 e904000000 90909090 83c005 c3"
    functions = {BASE: 9, BASE + 0x0D: 4}
    result = _compare(root_tail, root_tail, oracle_functions=functions, candidate_functions=functions)
    assert result["status"] == "passed"
    assert result["oracle_tail_transfers"] == 1
    assert result["candidate_tail_transfers"] == 1
    assert result["oracle_inlined_calls"] == 0
    assert result["return_targets_proved"] == 0
    tail = result["tail_sites"]["oracle"][0]
    assert tail["site"] == hex(BASE + 4)
    assert tail["target"] == hex(BASE + 0x0D)
    assert tail["depth"] == 1


def test_tail_session_evidence_counts() -> None:
    """Session counters record the tail transfer separately from the call."""
    with installed(region=True):
        session = _ComposeSession(
            project=_project(TAIL_CODE),
            functions=_normalize_function_map(TAIL_FUNCTIONS),
            labels={TAIL_CALLEE: "tail_callee"},
            limits=CallCompositionLimits(),
            reg_widths=_register_widths(),
        )
        final = _compose_function(session, BASE, frozenset({BASE}), 0)
    assert session.inlined_calls == 1
    assert session.tail_transfers == 1
    assert session.return_targets_proved == 1
    site = session.tail_sites[0]
    assert site["site"] == hex(TAIL_THUNK)
    assert site["block"] == hex(TAIL_THUNK)
    assert site["target"] == hex(TAIL_CALLEE)
    assert site["depth"] == 2
    assert site["callee"] == "tail_callee"
    assert isinstance(final["eip"], dict)


def test_tail_changed_return_value_fails() -> None:
    """A changed tail callee result is a real mismatch, not an assumption."""
    changed = _tail_code("83c006 c3")
    result = _compare(TAIL_CODE, changed)
    assert result["status"] == "failed"


def test_existing_positional_composition_budget_is_preserved() -> None:
    """Adding a tail budget cannot reinterpret an existing caller's work cap."""
    limits = CallCompositionLimits(64, 4, 32, 1, 12000, 4096, 2048, 1000, 64, 128)
    result = _compare(TAIL_CODE, TAIL_CODE, limits=limits)
    assert result["status"] == "refused"
    assert result["reason"] == "region_composition_limit"


def test_tail_callee_clobbers_preserved_register_fails() -> None:
    """A tail callee clobbering ebx fails even under a narrow output set."""
    clobber = _tail_code("bb07000000 83c005 c3")
    functions = {BASE: 0x0D, BASE + 0x0D: 5, BASE + 0x16: 9}
    result = _compare(TAIL_CODE, clobber, candidate_functions=functions, outputs=("eax",))
    assert result["status"] == "failed"


def test_tail_callee_memory_write_observed() -> None:
    """A tail callee stack store stays observable in strict equality."""
    stored = _tail_code("c74424082a000000 83c005 c3")
    functions = {BASE: 0x0D, BASE + 0x0D: 5, BASE + 0x16: 12}
    assert _compare(stored, stored, oracle_functions=functions, candidate_functions=functions)["status"] == "passed"
    changed = _compare(TAIL_CODE, stored, candidate_functions=functions)
    assert changed["status"] == "failed"


def test_tail_callee_ret_cleanup_change_fails() -> None:
    """A tail callee with ret 4 cleanup changes esp and the outer ret target."""
    ret4 = _tail_code("83c005 c20400")
    functions = {BASE: 0x0D, BASE + 0x0D: 5, BASE + 0x16: 6}
    result = _compare(TAIL_CODE, ret4, candidate_functions=functions)
    assert result["status"] == "failed"


def test_tail_saved_return_slot_corruption_refuses() -> None:
    """Corrupting the caller's return slot inside the tail callee refuses.

    The callee ``mov dword [esp],0x2a; ret`` overwrites the return address
    pushed by the enclosing call, proving the tail composition reads the
    caller's real return slot — no return address is pushed by the thunk
    and no +4 stack adjustment is invented.
    """
    corrupt = _tail_code("c704242a000000 c3")
    functions = {BASE: 0x0D, BASE + 0x0D: 5, BASE + 0x16: 8}
    result = _compare(corrupt, corrupt, oracle_functions=functions, candidate_functions=functions)
    assert result["status"] == "refused"
    assert result["reason"] == "call_return_target_mismatch"


def test_tail_stack_adjustment_corrupts_return_refuses() -> None:
    """A thunk that shifts esp before the jmp breaks the callee ret slot."""
    shifted = _tail_code("83c005 c3", thunk="83ec04 e904000000")
    functions = {BASE: 0x0D, BASE + 0x0D: 8, BASE + 0x19: 4}
    result = _compare(shifted, shifted, oracle_functions=functions, candidate_functions=functions)
    assert result["status"] == "refused"
    assert result["reason"].startswith("call_return_target")


def test_tail_interior_target_refuses() -> None:
    """A jmp to a foreign declared range interior is not a tail transfer."""
    interior = _tail_code("83c005 c3", thunk="e906000000")
    result = _compare(interior, interior)
    assert result["status"] == "refused"
    assert result["reason"] == "edge_outside_declared_function:0x100018"


def test_tail_undeclared_target_refuses() -> None:
    """A jmp to an undeclared address keeps the existing refusal."""
    undeclared = _tail_code("83c005 c3", thunk="e91e000000")
    result = _compare(undeclared, undeclared)
    assert result["status"] == "refused"
    assert result["reason"] == "edge_outside_declared_function:0x100030"


def test_tail_indirect_target_refuses() -> None:
    """An indirect terminal jump is never a tail transfer."""
    indirect = "8b442404 e804000000 83c002 c3 ffe0"
    functions = {BASE: 0x0D, BASE + 0x0D: 2}
    result = _compare(indirect, indirect, oracle_functions=functions, candidate_functions=functions)
    assert result["status"] == "refused"
    assert result["reason"] == "indirect_jump"


def test_tail_register_constant_target_admitted() -> None:
    """A register-indirect jmp with a provable constant is still a tail.

    ``mov eax, imm; jmp eax`` resolves through the same ``_static_next``
    constant-copy evidence that admits folded ``call reg`` targets: the
    decoded terminal instruction is an unconditional transfer and its
    destination is a declared foreign entry.  This pins the admission
    boundary at "statically provable unconditional transfer" — no
    stricter direct-encoding binding is applied, matching call admission.
    The callee sits past a NOP pad so the folded target is a real jump,
    not the block's byte-contiguous fallthrough.
    """
    folded = "8b442404 e804000000 83c002 c3 b816001000 ffe0 9090 83c005 c3"
    functions = {BASE: 0x0D, BASE + 0x0D: 7, BASE + 0x16: 4}
    result = _compare(
        folded, folded, oracle_functions=functions, candidate_functions=functions
    )
    assert result["status"] == "passed"
    assert result["oracle_tail_transfers"] == 1
    tail = result["tail_sites"]["oracle"][0]
    assert tail["site"] == hex(BASE + 0x0D + 5)
    assert tail["target"] == hex(BASE + 0x16)


def test_fallthrough_jump_target_is_not_a_tail() -> None:
    """A real jmp whose target is its own fallthrough is not a tail transfer.

    ``jmp $+0`` decodes an unconditional transfer, but its destination is
    byte-contiguous — identical to falling through.  Contiguity beats the
    declared-entry evidence, so the edge keeps the typed
    ``edge_outside_declared_function`` refusal like ordinary fallthrough.
    """
    contiguous_jump = "8b442404 e804000000 83c002 c3 e900000000 83c005 c3"
    functions = {BASE: 0x0D, BASE + 0x0D: 5, BASE + 0x12: 4}
    result = _compare(
        contiguous_jump,
        contiguous_jump,
        oracle_functions=functions,
        candidate_functions=functions,
    )
    assert result["status"] == "refused"
    assert result["reason"] == "edge_outside_declared_function:0x100012"


def test_conditional_sibling_with_tail_transfer_passes() -> None:
    """An in-range conditional sibling composes alongside a tail transfer.

    VEX terminates a block at the ``jz`` exit, so the conditional arm and the
    terminal ``jmp`` live in sibling blocks: the taken arm reaches an
    in-range ``ret`` while the not-taken arm tail-transfers to the foreign
    callee.  The ``noexits`` gate applies to the tail block itself, which
    carries no conditional exits here.
    """
    mixed = "8b442404 e804000000 83c002 c3 85c07405e901000000 c3 83c005 c3"
    functions = {BASE: 0x0D, BASE + 0x0D: 10, BASE + 0x17: 4}
    result = _compare(
        mixed, mixed, oracle_functions=functions, candidate_functions=functions
    )
    assert result["status"] == "passed"
    assert result["oracle_tail_transfers"] == 1
    tail = result["tail_sites"]["oracle"][0]
    assert tail["block"] == hex(BASE + 0x11)
    assert tail["target"] == hex(BASE + 0x17)
    changed = "8b442404 e804000000 83c002 c3 85c07405e901000000 c3 83c006 c3"
    changed_result = _compare(
        mixed, changed, oracle_functions=functions, candidate_functions=functions
    )
    assert changed_result["status"] == "failed"


def test_conditional_outside_transfer_refuses() -> None:
    """A jcc arm to a foreign declared entry keeps refusing (not a tail)."""
    conditional = "85c0 7407 83c002 c3 90909090 83c005 c3"
    functions = {BASE: 7, BASE + 0x0B: 4}
    result = _compare(
        conditional,
        conditional,
        oracle_functions=functions,
        candidate_functions=functions,
    )
    assert result["status"] == "refused"
    assert result["reason"] == "edge_outside_declared_function:0x10000b"


def test_fallthrough_into_declared_entry_is_not_a_tail() -> None:
    """Contiguous fallthrough into the next declared entry is not a jump."""
    contiguous = "9090 c3"
    functions = {BASE: 2, BASE + 2: 1}
    result = _compare(contiguous, contiguous, oracle_functions=functions, candidate_functions=functions)
    assert result["status"] == "refused"
    assert result["reason"] == "edge_outside_declared_function:0x100002"


def test_tail_cycle_refuses() -> None:
    """Mutually tail-jumping thunks refuse through the active-entry guard."""
    cycle = "8b442404 e804000000 83c002 c3 e904000000 90909090 e9f2ffffff"
    functions = {BASE: 0x0D, BASE + 0x0D: 5, BASE + 0x16: 5}
    result = _compare(cycle, cycle, oracle_functions=functions, candidate_functions=functions)
    assert result["status"] == "refused"
    assert result["reason"] == "recursive_tail_transfer:0x10000d"


def test_tail_depth_limit_refuses() -> None:
    """A tail transfer consumes the shared inline-depth budget."""
    result = _compare(
        TAIL_CODE,
        TAIL_CODE,
        limits=CallCompositionLimits(max_inline_depth=1),
    )
    assert result["status"] == "refused"
    assert result["reason"] == "tail_inline_depth_limit"


def test_tail_budget_refuses() -> None:
    """An exhausted tail-transfer budget is a visible typed refusal."""
    result = _compare(
        TAIL_CODE,
        TAIL_CODE,
        limits=CallCompositionLimits(max_tail_transfers=0),
    )
    assert result["status"] == "refused"
    assert result["reason"] == "tail_transfer_budget"


def test_tail_environment_contract_refuses() -> None:
    """A tail callee requiring the environment contract keeps refusing."""
    ported = _tail_code("ec c3")
    functions = {BASE: 0x0D, BASE + 0x0D: 5, BASE + 0x16: 2}
    result = _compare(ported, ported, oracle_functions=functions, candidate_functions=functions)
    assert result["status"] == "refused"
    assert result["reason"] == "external_environment_contract_required"


def test_tail_deterministic_summary() -> None:
    """Identical inputs produce identical summary documents and counters."""
    with installed(region=True):
        first = summarize_with_calls(_project(TAIL_CODE), entry=BASE, functions=TAIL_FUNCTIONS, outputs=OUTPUTS)
        second = summarize_with_calls(_project(TAIL_CODE), entry=BASE, functions=TAIL_FUNCTIONS, outputs=OUTPUTS)
    assert first == second
    assert first["inlined_calls"] == 1
    assert first["return_targets_proved"] == 1
    assert first["tail_transfers"] == 1
    assert first["tail_sites"] == [
        {
            "site": hex(TAIL_THUNK),
            "block": hex(TAIL_THUNK),
            "target": hex(TAIL_CALLEE),
            "depth": 2,
            "callee": "",
        }
    ]


def test_nested_tail_transfers_reserve_budget_before_descent() -> None:
    """Two nested tail transfers cannot pass a one-transfer cap."""
    code = "e905000000 9090909090 e905000000 9090909090 b801000000c3"
    functions = {BASE: 5, BASE + 0x0A: 5, BASE + 0x14: 6}
    row = _compare(code, code, oracle_functions=functions, candidate_functions=functions,
                   limits=CallCompositionLimits(max_tail_transfers=1))
    assert row["status"] == "refused"
    assert row["reason"] == "tail_transfer_budget"


def test_nested_calls_reserve_budget_before_descent() -> None:
    """Two nested direct calls cannot pass a one-call cap."""
    code = "e805000000 c3 90909090 e805000000 c3 90909090 b801000000c3"
    functions = {BASE: 6, BASE + 0x0A: 6, BASE + 0x14: 6}
    row = _compare(code, code, oracle_functions=functions, candidate_functions=functions,
                   limits=CallCompositionLimits(max_inlined_calls=1))
    assert row["status"] == "refused"
    assert row["reason"] == "call_inline_budget"
