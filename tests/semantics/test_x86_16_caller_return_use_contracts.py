from __future__ import annotations

from types import SimpleNamespace

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.caller_return_use_contracts import (
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from inertia.semantics.callsite_summary import (
    caller_return_use_program_scope_8616,
    collect_caller_return_use_evidence_8616,
)


class _Memory:
    def __init__(self, regions: dict[int, bytes]) -> None:
        self._regions = regions
        self.load_count = 0

    def load(self, addr: int, size: int) -> bytes:
        self.load_count += 1
        for base, data in self._regions.items():
            offset = addr - base
            if offset >= 0 and offset + size <= len(data):
                return data[offset : offset + size]
        raise KeyError(addr)


def _project(regions: dict[int, bytes]) -> SimpleNamespace:
    return SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=_Memory(regions)),
    )


def test_condition_use_retains_exact_caller_callsite_and_witness() -> None:
    # call 0x1020; add sp, 2; test ax, ax
    project = _project({0x1000: bytes.fromhex("e81d0083c40285c0")})

    evidence = collect_caller_return_use_evidence_8616(
        project,
        0x1020,
        ((0x1000, 0x1008),),
    )

    assert evidence.fact_census_complete
    assert len(evidence.facts) == 1
    fact = evidence.facts[0]
    assert fact.caller_addr == 0x1000
    assert fact.callsite_addr == 0x1000
    assert fact.verdict is CallerReturnUseVerdict8616.USED
    assert fact.kind is CallsiteReturnUseKind8616.CONDITION
    assert fact.witness_instruction_addr == 0x1006
    assert fact.classified


def test_clobber_retains_exact_unused_witness() -> None:
    # call 0x1020; mov ax, 0
    project = _project({0x1000: bytes.fromhex("e81d00b80000")})

    evidence = collect_caller_return_use_evidence_8616(
        project,
        0x1020,
        ((0x1000, 0x1006),),
    )

    assert evidence.fact_census_complete
    fact = evidence.facts[0]
    assert fact.verdict is CallerReturnUseVerdict8616.UNUSED
    assert fact.kind is CallsiteReturnUseKind8616.CLOBBERED
    assert fact.witness_instruction_addr == 0x1003


def test_unresolved_jump_retains_unknown_fact_and_failure() -> None:
    # call 0x1020; jmp 0x1100, outside the independently proven caller range.
    project = _project({0x1000: bytes.fromhex("e81d00e9fa00")})

    evidence = collect_caller_return_use_evidence_8616(
        project,
        0x1020,
        ((0x1000, 0x1006),),
    )

    assert evidence.fact_census_complete
    assert evidence.verdict is CallerReturnUseVerdict8616.UNKNOWN
    assert evidence.failure_count == 1
    fact = evidence.facts[0]
    assert fact.verdict is CallerReturnUseVerdict8616.UNKNOWN
    assert fact.witness_instruction_addr == 0x1003
    assert not fact.classified


def test_recursive_passthrough_is_retained_but_excluded() -> None:
    # nop; nop; call self; ret
    project = _project({0x1000: bytes.fromhex("9090e8fbffc3")})

    evidence = collect_caller_return_use_evidence_8616(
        project,
        0x1000,
        ((0x1000, 0x1006),),
    )

    assert evidence.fact_census_complete
    assert evidence.excluded_callsite_count == 1
    fact = evidence.facts[0]
    assert fact.kind is CallsiteReturnUseKind8616.FUNCTION_RETURN
    assert fact.witness_instruction_addr == 0x1005
    assert fact.excluded_recursive_passthrough
    assert not fact.classified


def test_wrapper_passthrough_retains_local_witness_and_transitive_verdict() -> None:
    # wrapper: call 0x1020; ret. observer: call wrapper; test ax, ax.
    project = _project(
        {
            0x1000: bytes.fromhex("e81d00c3"),
            0x1010: bytes.fromhex("e8edff85c0"),
        }
    )

    evidence = collect_caller_return_use_evidence_8616(
        project,
        0x1020,
        ((0x1000, 0x1004), (0x1010, 0x1015)),
    )

    assert evidence.fact_census_complete
    fact = evidence.facts[0]
    assert fact.caller_addr == 0x1000
    assert fact.kind is CallsiteReturnUseKind8616.FUNCTION_RETURN
    assert fact.witness_instruction_addr == 0x1003
    assert fact.verdict is CallerReturnUseVerdict8616.USED
    assert fact.classified


def test_program_scope_decodes_caller_ranges_once_for_multiple_targets() -> None:
    # caller A -> 0x1020; caller B -> 0x1030; both overwrite AX.
    ranges = ((0x1000, 0x1006), (0x1010, 0x1016))
    project = _project(
        {
            0x1000: bytes.fromhex("e81d00b80000"),
            0x1010: bytes.fromhex("e81d00b80000"),
        }
    )
    memory = project.loader.memory

    with caller_return_use_program_scope_8616(project, ranges):
        first = collect_caller_return_use_evidence_8616(project, 0x1020, ranges)
        second = collect_caller_return_use_evidence_8616(project, 0x1030, ranges)

    assert first.verdict is CallerReturnUseVerdict8616.UNUSED
    assert second.verdict is CallerReturnUseVerdict8616.UNUSED
    assert memory.load_count == len(ranges)


def test_program_scope_is_exact_and_request_local() -> None:
    ranges = ((0x1000, 0x1006), (0x1010, 0x1016))
    regions = {
        0x1000: bytes.fromhex("e81d00b80000"),
        0x1010: bytes.fromhex("e81d00b80000"),
    }
    project = _project(regions)
    other_project = _project(regions)
    memory = project.loader.memory
    other_memory = other_project.loader.memory

    with caller_return_use_program_scope_8616(project, ranges):
        collect_caller_return_use_evidence_8616(other_project, 0x1020, ranges)
        collect_caller_return_use_evidence_8616(project, 0x1020, ranges[:1])

    collect_caller_return_use_evidence_8616(project, 0x1020, ranges)

    assert memory.load_count == len(ranges) + 1 + len(ranges)
    assert other_memory.load_count == len(ranges)
