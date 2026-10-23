"""Guarded stack-probe identity must never grant an unconditional allocation.

The exact native helper bytes keep their STACK_PROBE pattern identity while
the carry and DS-limit failure exits remain reachable in emulation, so every
collected candidate must resolve as an explicit STACK_ALLOCATION_UNPROVEN
refusal instead of a complete effect or a silent balanced-call fall-through.
"""

from types import SimpleNamespace

import pytest
from unicorn import UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_16, Uc
from unicorn.x86_const import (
    UC_X86_REG_AX,
    UC_X86_REG_BP,
    UC_X86_REG_CS,
    UC_X86_REG_DS,
    UC_X86_REG_SP,
    UC_X86_REG_SS,
)

from inertia.ir import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.semantics.call_stack_allocation import (
    CallStackAllocationCandidate8616,
    collect_call_stack_allocation_candidates_8616,
    resolve_call_stack_allocation_8616,
)
from inertia.semantics.call_stack_effect_contracts import CallStackEffectFailure8616
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.semantics.compiler_helpers import (
    CompilerHelperEvidenceKind8616,
    identify_x86_16_compiler_helper_at_8616,
)

HELPER = 0x206A
SITE = 0x1003
FAILURE_HEAD = HELPER + 0x11
SUCCESS_STORE = HELPER + 0x0D
RETURN_WORD = 0x1234
RETURN_FLAT = 0x1A2 * 0x10 + RETURN_WORD

NATIVE_BYTES = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e ec 00 72 04 8b e3 ff e1 33 c0 e9 45 fe")
RETURNING_TAIL_BYTES = NATIVE_BYTES[:0x11] + bytes.fromhex("bd ef be ff e1")  # mov bp, 0xbeef ; jmp cx
FAR_BYTES = bytes.fromhex("59 5a 8b dc 2b d8 72 0b 3b 1e c6 00 72 05 8b e3 52 51 cb")


def _project(code: bytes) -> SimpleNamespace:
    """Fake only the binary load of the exact helper bytes; no compiler."""

    def load(address: int, size: int) -> bytes:
        if address != HELPER:
            raise KeyError(address)
        return code[:size]

    return SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(
            memory=SimpleNamespace(load=load),
            main_object=SimpleNamespace(linked_base=HELPER, max_addr=len(code) - 1),
        ),
    )


def _artifact(allocation_size: int | None) -> IRFunctionArtifact:
    """Emit an optional AX constant write followed by a direct call to HELPER."""
    instrs = [
        IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2),
                (IRValue(MemSpace.CONST, const=allocation_size, size=2),), size=2, addr=0x1000)
        if allocation_size is not None else
        IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2),
                (IRValue(MemSpace.REG, name="dx", size=2),), size=2, addr=0x1000)
    ]
    instrs.append(IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=HELPER, size=2),), addr=SITE))
    return IRFunctionArtifact(0x1000, (IRBlock(0x1000, tuple(instrs)),))


def _summary(*, marked: bool, allocation_size: int | None, kind: str = "direct_near") -> CallsiteSummary8616:
    """Build a zero-argument callsite summary, optionally marked as a probe."""
    return CallsiteSummary8616(
        callsite_addr=SITE, target_addr=HELPER, return_addr=0x1006,
        kind=kind, arg_count=0, arg_widths=(), stack_cleanup=0,
        return_register=None, return_used=False,
        stack_probe_helper=marked, stack_probe_allocation_size=allocation_size,
    )


def _resolve(summary: CallsiteSummary8616, candidates: dict[int, CallStackAllocationCandidate8616]):
    """Resolve the site candidate and require an explicit outcome."""
    result = resolve_call_stack_allocation_8616(summary, candidates.get(SITE))
    assert result is not None
    return result


def _emulate(code: bytes, allocation_size: int, *, sp: int = 0x10, ds_limit: int = 0x100):
    """Run the helper bytes under Unicorn with a small stack and DS limit."""
    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 0x100000)
    uc.mem_write(HELPER, code)
    for register, value in (
        (UC_X86_REG_CS, 0x1A2), (UC_X86_REG_SS, 0x300), (UC_X86_REG_DS, 0x400),
        (UC_X86_REG_SP, sp), (UC_X86_REG_AX, allocation_size),
    ):
        uc.reg_write(register, value)
    uc.mem_write(0x300 * 0x10 + sp, RETURN_WORD.to_bytes(2, "little"))
    uc.mem_write(0x400 * 0x10 + 0xEC, ds_limit.to_bytes(2, "little"))
    visited: list[int] = []

    def hook(uc_: Uc, address: int, _size: int, _data: object) -> None:
        visited.append(address)
        if address == RETURN_FLAT or (address == FAILURE_HEAD and code == NATIVE_BYTES):
            uc_.emu_stop()

    uc.hook_add(UC_HOOK_CODE, hook)
    uc.emu_start(HELPER, HELPER + len(code) + 8, count=12)
    return uc, visited


def test_native_bytes_keep_stack_probe_identity() -> None:
    evidence = identify_x86_16_compiler_helper_at_8616(_project(NATIVE_BYTES), HELPER)
    assert evidence is not None
    assert evidence.kind is CompilerHelperEvidenceKind8616.STACK_PROBE


@pytest.mark.parametrize("alloc_allocation_size", [0, 18, 32])
def test_guarded_candidate_resolves_unproven_when_summary_marks_probe(alloc_allocation_size: int) -> None:
    project = _project(NATIVE_BYTES)
    candidate = collect_call_stack_allocation_candidates_8616(project, _artifact(alloc_allocation_size)).get(SITE)
    assert candidate is not None
    assert candidate.value_instruction_addr == 0x1000
    assert candidate.allocation_size == alloc_allocation_size

    effect, failure = _resolve(_summary(marked=True, allocation_size=alloc_allocation_size), {SITE: candidate})

    assert not effect.complete
    assert effect.net_stack_delta is None
    assert failure is CallStackEffectFailure8616.STACK_ALLOCATION_UNPROVEN


@pytest.mark.parametrize("marked", [False, True])
@pytest.mark.parametrize("code,kind", [(NATIVE_BYTES, "direct_near"), (FAR_BYTES, "direct_far")])
def test_unmarked_guarded_candidate_cannot_fall_through(code: bytes, kind: str, marked: bool) -> None:
    """Guarded identity candidates refuse even when the summary never says probe."""
    project = _project(code)
    candidates = collect_call_stack_allocation_candidates_8616(project, _artifact(18))
    assert SITE in candidates

    effect, failure = _resolve(_summary(marked=marked, allocation_size=None, kind=kind), candidates)

    assert not effect.complete
    assert failure is CallStackEffectFailure8616.STACK_ALLOCATION_UNPROVEN


@pytest.mark.parametrize("marked", [False, True])
def test_unknown_or_clobbered_allocation_size_still_refuses(marked: bool) -> None:
    """Without a reaching AX constant the candidate keeps None allocation_size fields."""
    project = _project(NATIVE_BYTES)
    candidate = collect_call_stack_allocation_candidates_8616(project, _artifact(None)).get(SITE)
    assert candidate is not None
    assert candidate.value_instruction_addr is None
    assert candidate.allocation_size is None

    effect, failure = _resolve(_summary(marked=marked, allocation_size=None), {SITE: candidate})

    assert not effect.complete
    assert failure is CallStackEffectFailure8616.STACK_ALLOCATION_UNPROVEN


def test_mutated_returning_tail_keeps_identity_without_effect() -> None:
    """A failure head that returns to the caller is still not authority."""
    project = _project(RETURNING_TAIL_BYTES)
    evidence = identify_x86_16_compiler_helper_at_8616(project, HELPER)
    assert evidence is not None
    assert evidence.kind is CompilerHelperEvidenceKind8616.STACK_PROBE
    candidates = collect_call_stack_allocation_candidates_8616(project, _artifact(18))
    assert SITE in candidates

    effect, failure = _resolve(_summary(marked=True, allocation_size=18), candidates)

    assert not effect.complete
    assert failure is CallStackEffectFailure8616.STACK_ALLOCATION_UNPROVEN


@pytest.mark.parametrize("alloc_allocation_size", [0, 18])
def test_ds_limit_guard_failure_is_reachable(alloc_allocation_size: int) -> None:
    """Small DS limit sends modest allocation_sizes through the failure head."""
    _uc, visited = _emulate(NATIVE_BYTES, alloc_allocation_size)
    assert FAILURE_HEAD in visited
    assert SUCCESS_STORE not in visited


def test_carry_guard_failure_is_reachable() -> None:
    """A allocation_size above the post-pop SP trips the carry guard first."""
    _uc, visited = _emulate(NATIVE_BYTES, 32)
    assert FAILURE_HEAD in visited
    assert HELPER + 0x7 not in visited


def test_success_path_applies_the_allocation_size() -> None:
    """With room, the same bytes really allocate — the guards are live either way."""
    uc, visited = _emulate(NATIVE_BYTES, 18, sp=0x1000, ds_limit=0x100)
    assert RETURN_FLAT in visited
    assert FAILURE_HEAD not in visited
    assert uc.reg_read(UC_X86_REG_SP) == 0x1002 - 18


@pytest.mark.parametrize("alloc_allocation_size", [0, 18, 32])
def test_returning_tail_concretely_loses_bp_and_allocation_size(alloc_allocation_size: int) -> None:
    """The returning tail returns with SP moved only by the pop, BP clobbered."""
    uc, visited = _emulate(RETURNING_TAIL_BYTES, alloc_allocation_size)
    assert FAILURE_HEAD in visited
    assert RETURN_FLAT in visited
    assert uc.reg_read(UC_X86_REG_BP) == 0xBEEF
    assert uc.reg_read(UC_X86_REG_SP) == 0x12


def test_ordinary_call_keeps_normal_handling() -> None:
    """No candidate and no probe marking leaves ordinary calls untouched."""
    project = _project(b"\xc3")
    candidates = collect_call_stack_allocation_candidates_8616(project, _artifact(18))
    assert SITE not in candidates
    assert resolve_call_stack_allocation_8616(_summary(marked=False, allocation_size=None), None) is None
