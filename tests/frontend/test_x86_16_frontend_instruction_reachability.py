from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.errors import SimEngineError

from inertia.cli.project_loading import _build_project_from_bytes
from inertia.cli.recovery_instruction_coverage import (
    ExactInstructionCoverageVerdict8616,
    collect_exact_instruction_coverage_8616,
)
from inertia.frontend.x86_16.frontend_capstone_decode import DirectCapstoneBlock8616
from inertia.frontend.x86_16.frontend_function_instructions import (
    FunctionInstructionInventoryStatus8616,
    collect_function_instruction_inventory_8616,
)
from inertia.frontend.x86_16.frontend_instruction_kinds import (
    is_x86_16_call_mnemonic_8616,
)
from inertia.frontend.x86_16.frontend_instruction_reachability import (
    ConditionalIndirectEdge8616,
    collect_decoded_block_evidence_8616,
    collect_instruction_reachability_8616,
    decoded_block_instructions_8616,
)


def test_conditional_indirect_inventory_never_becomes_unconditional() -> None:
    """A target hint closes decoding only and cannot contaminate ordinary cache reads."""
    project = _build_project_from_bytes(bytes.fromhex("ffe3c3"), base_addr=0x1000, entry_point=0x1000)
    kwargs = {"entry": 0x1000, "region_start": 0x1000, "region_end": 0x1003}
    edge = ConditionalIndirectEdge8616(0x1000, 0x1000, 0x1002)
    conditional = collect_instruction_reachability_8616(project, **kwargs, conditional_edges=(edge,))
    assert conditional.inventory_complete
    assert not conditional.complete
    assert conditional.conditional_edges == (edge,)
    assert conditional.successor_edges == ((0x1000, 0x1002),)
    ordinary = collect_instruction_reachability_8616(project, **kwargs)
    assert not ordinary.inventory_complete
    assert ordinary.unresolved_block_addrs == (0x1000,)


@pytest.mark.parametrize("instruction,target", [(0x1001, 0x1002), (0x1000, 0x2000)])
def test_conditional_indirect_inventory_rejects_unusable_hint(instruction: int, target: int) -> None:
    """Unbound instruction coordinates and out-of-image targets remain unresolved."""
    project = _build_project_from_bytes(bytes.fromhex("ffe3c3"), base_addr=0x1000, entry_point=0x1000)
    result = collect_instruction_reachability_8616(
        project, entry=0x1000, region_start=0x1000, region_end=0x1003,
        conditional_edges=(ConditionalIndirectEdge8616(0x1000, instruction, target),),
    )
    assert not result.inventory_complete
    assert not result.complete


@pytest.mark.parametrize("module_base", [0x1000, 0x1A20, 0x11000])
def test_bounded_cs_table_does_not_infer_selector_from_loader(module_base: int) -> None:
    """A guarded table index alone cannot authorize CS-relative destinations.

    This standalone Borland small-model switch has four guarded table entries.
    The image coordinate supplies bytes, not the runtime CS or a stable table
    memory premise. Keep the indirect edge unresolved without those premises.
    """
    body = bytes.fromhex(
        "558bec8b56048bda83fb037719d1e32effa73903"
        "b80a00eb148bc2051400ebf78bc2d1e0ebf1"
        "8bc205fbffebea5dc31e03230323032a03"
    )
    entry = module_base + 0x30A
    image = bytes(0x30A) + body
    project = _build_project_from_bytes(image, base_addr=module_base, entry_point=entry)
    evidence = collect_instruction_reachability_8616(
        project, entry=entry, region_start=module_base, region_end=module_base + len(image),
    )
    assert not evidence.complete
    assert module_base + 0x317 in evidence.unresolved_block_addrs
    assert module_base + 0x319 in evidence.reachable_instruction_addrs
    # The table's first entry is 031eh; interpreting it using the image base
    # would silently assume a CS value that no caller has established.
    assert (module_base + 0x317, module_base + 0x31E) not in evidence.successor_edges


@pytest.mark.parametrize("cached_failure", [False, True])
def test_unmapped_decode_is_an_incomplete_reachability_census(cached_failure: bool) -> None:
    """Foreign image coordinates refuse on both fresh and cached decode failures."""
    project = _build_project_from_bytes(b"\xc3", base_addr=0x1000, entry_point=0x1000)
    address = 0x10010
    if cached_failure:
        with pytest.raises(SimEngineError):
            collect_decoded_block_evidence_8616(project, address, opt_level=0)
    evidence = collect_instruction_reachability_8616(
        project, entry=address, region_start=address, region_end=address + 1,
    )
    assert not evidence.complete
    assert evidence.unresolved_block_addrs == (address,)
    assert evidence.reachable_instruction_addrs == ()
    assert evidence.raw_fact_count == evidence.normalized_fact_count == 1
    assert evidence.classified_fact_count == evidence.failure_count == 1
    assert evidence.materialized_count == 0


@pytest.mark.parametrize("mnemonic", ["call", "lcall", "callq"])
def test_frontend_call_kind_accepts_capstone_near_and_far_spellings(
    mnemonic: str,
) -> None:
    """Near and far backend spellings must project to one call kind."""
    assert is_x86_16_call_mnemonic_8616(mnemonic) is True


def test_frontend_call_kind_refuses_non_call_mnemonic() -> None:
    """Mnemonic classification must not infer calls from unrelated opcodes."""
    assert is_x86_16_call_mnemonic_8616("jmp") is False


def _unreachable_padding_project() -> object:
    return _build_project_from_bytes(
        bytes.fromhex("eb 03 90 90 90 c3"),
        base_addr=0x1000,
        entry_point=0x1000,
    )


def _instruction_shape(instruction: object) -> tuple[int, int, str, str]:
    """Return comparable fields across raw and angr-wrapped Capstone objects."""
    try:
        inner = instruction.insn
    except AttributeError:
        inner = instruction
    return (inner.address, inner.size, inner.mnemonic, inner.op_str)


@pytest.mark.parametrize(
    "code",
    [
        bytes.fromhex("90c3"),
        bytes.fromhex("750190c3"),
        bytes.fromhex("eb0190c3"),
        bytes.fromhex("e8000090c3"),
        bytes.fromhex("e2fe90c3"),
        bytes.fromhex("cd21c3"),
        bytes.fromhex("b90100f3a4c3"),
        bytes.fromhex("f3a4c3"),
        b"\x90" * 100 + b"\xc3",
    ],
    ids=(
        "ret",
        "jcc",
        "jmp",
        "call",
        "loop",
        "int",
        "repeat-after-leading",
        "repeat-at-entry",
        "straight-line",
    ),
)
def test_direct_capstone_block_matches_factory_without_vex(code: bytes) -> None:
    base = 0x3000
    project = _build_project_from_bytes(code, base_addr=base, entry_point=base)
    expected_block = project.factory.block(base, opt_level=0)
    expected = tuple(_instruction_shape(instruction) for instruction in expected_block.capstone.insns)
    project.factory.default_engine.clear_cache()

    decoded = collect_decoded_block_evidence_8616(project, base, opt_level=0)

    assert isinstance(decoded.block, DirectCapstoneBlock8616)
    assert decoded.block.size == expected_block.size
    assert tuple(_instruction_shape(instruction) for instruction in decoded.instructions) == expected
    assert project.factory.default_engine._block_cache == {}


def test_frontend_reachability_excludes_bytes_skipped_by_direct_jump() -> None:
    evidence = collect_instruction_reachability_8616(
        _unreachable_padding_project(),
        entry=0x1000,
        region_start=0x1000,
        region_end=0x1006,
    )

    assert evidence.complete is True
    assert evidence.reachable_block_addrs == (0x1000, 0x1005)
    assert evidence.reachable_instruction_addrs == (0x1000, 0x1005)
    assert evidence.unresolved_block_addrs == ()
    assert evidence.raw_fact_count == 2
    assert evidence.materialized_count == 2
    assert evidence.failure_count == 0


def test_frontend_reachability_refuses_unresolved_indirect_jump() -> None:
    project = _build_project_from_bytes(
        bytes.fromhex("ff e0"),
        base_addr=0x1000,
        entry_point=0x1000,
    )

    evidence = collect_instruction_reachability_8616(
        project,
        entry=0x1000,
        region_start=0x1000,
        region_end=0x1002,
    )

    assert evidence.complete is False
    assert evidence.unresolved_block_addrs == (0x1000,)
    assert evidence.failure_count == 1


def test_frontend_reachability_records_lifter_runtime_refusal(monkeypatch) -> None:
    """An unsupported seed is unresolved evidence, not an audit crash."""
    project = _unreachable_padding_project()

    def refuse_block(_addr: int, *, opt_level: int) -> object:
        raise RuntimeError("unsupported instruction")

    import inertia.frontend.x86_16.frontend_block_inventory as frontend_block_inventory

    refusal = frontend_block_inventory.decode_bounded_capstone_block_8616(
        project,
        0x1000,
        0x1000,
    )
    monkeypatch.setattr(
        frontend_block_inventory,
        "decode_bounded_capstone_block_8616",
        lambda _project, _address, _region_end: refusal,
    )
    monkeypatch.setattr(project.factory, "block", refuse_block)

    evidence = collect_instruction_reachability_8616(
        project,
        entry=0x1000,
        region_start=0x1000,
        region_end=0x1006,
    )

    assert evidence.complete is False
    assert evidence.unresolved_block_addrs == (0x1000,)
    assert evidence.failure_count == 1


def test_frontend_reachability_reuses_exact_immutable_request() -> None:
    calls = 0
    instruction = SimpleNamespace(
        address=0x1000,
        size=1,
        mnemonic="ret",
        insn=SimpleNamespace(operands=()),
    )

    def decode_block(address: int, *, opt_level: int) -> object:
        nonlocal calls
        calls += 1
        assert address == 0x1000
        assert opt_level == 0
        return SimpleNamespace(
            addr=address,
            size=1,
            capstone=SimpleNamespace(insns=(instruction,)),
        )

    project = SimpleNamespace(factory=SimpleNamespace(block=decode_block))

    first = collect_instruction_reachability_8616(
        project,
        entry=0x1000,
        region_start=0x1000,
        region_end=0x1001,
    )
    second = collect_instruction_reachability_8616(
        project,
        entry=0x1000,
        region_start=0x1000,
        region_end=0x1001,
    )

    assert first.complete is True
    assert second is first
    assert calls == 1


def test_frontend_reachability_reuses_shared_tail_block_decode() -> None:
    """Distinct entry censuses must share immutable overlapping block decodes."""
    calls: list[int] = []

    def instruction(address: int, mnemonic: str, target: int | None = None) -> object:
        operands = (
            (SimpleNamespace(type=2, imm=target),)
            if isinstance(target, int)
            else ()
        )
        return SimpleNamespace(
            address=address,
            size=2 if mnemonic == "jmp" else 1,
            mnemonic=mnemonic,
            insn=SimpleNamespace(operands=operands),
        )

    blocks = {
        0x1000: instruction(0x1000, "jmp", 0x1020),
        0x1010: instruction(0x1010, "jmp", 0x1020),
        0x1020: instruction(0x1020, "ret"),
    }

    def decode_block(address: int, *, opt_level: int) -> object:
        calls.append(address)
        assert opt_level == 0
        decoded = blocks[address]
        return SimpleNamespace(
            addr=address,
            size=decoded.size,
            capstone=SimpleNamespace(insns=(decoded,)),
        )

    project = SimpleNamespace(factory=SimpleNamespace(block=decode_block))

    first = collect_instruction_reachability_8616(
        project,
        entry=0x1000,
        region_start=0x1000,
        region_end=0x1030,
    )
    second = collect_instruction_reachability_8616(
        project,
        entry=0x1010,
        region_start=0x1000,
        region_end=0x1030,
    )

    assert first.complete is second.complete is True
    assert first.reachable_block_addrs == (0x1000, 0x1020)
    assert second.reachable_block_addrs == (0x1010, 0x1020)
    assert calls == [0x1000, 0x1020, 0x1010]


def test_frontend_block_inventory_reuses_only_exact_decode_requests() -> None:
    calls: list[tuple[int, int | None, int]] = []
    instruction = SimpleNamespace(address=0x1000, size=1, mnemonic="nop")

    def decode_block(
        address: int,
        *,
        opt_level: int,
        num_inst: int | None = None,
    ) -> object:
        calls.append((address, num_inst, opt_level))
        return SimpleNamespace(capstone=SimpleNamespace(insns=(instruction,)))

    project = SimpleNamespace(factory=SimpleNamespace(block=decode_block))

    first = decoded_block_instructions_8616(project, 0x1000, num_inst=1, opt_level=0)
    second = decoded_block_instructions_8616(project, 0x1000, num_inst=1, opt_level=0)
    whole_block = decoded_block_instructions_8616(project, 0x1000, opt_level=0)

    assert first == second == whole_block == (instruction,)
    assert calls == [(0x1000, 1, 0), (0x1000, None, 0)]


def test_frontend_block_inventory_reuses_deterministic_refusals() -> None:
    calls = 0

    class DeterministicDecodeError(RuntimeError):
        pass

    def refuse_block(
        _address: int,
        *,
        opt_level: int,
        num_inst: int | None = None,
    ) -> object:
        nonlocal calls
        calls += 1
        raise DeterministicDecodeError(f"missing bytes limit={num_inst} opt={opt_level}")

    project = SimpleNamespace(factory=SimpleNamespace(block=refuse_block))

    for _attempt in range(2):
        with pytest.raises(
            DeterministicDecodeError,
            match="missing bytes limit=1 opt=0",
        ):
            decoded_block_instructions_8616(project, 0x200, num_inst=1, opt_level=0)

    assert calls == 1


def test_function_inventory_decodes_only_current_cfg_blocks() -> None:
    current = SimpleNamespace(address=0x2000, size=1, mnemonic="nop")
    stale = SimpleNamespace(address=0x1000, size=1, mnemonic="add")
    decoded_addrs: list[int] = []

    def decode_block(
        address: int,
        *,
        opt_level: int,
        num_inst: int | None = None,
    ) -> object:
        del opt_level, num_inst
        decoded_addrs.append(address)
        instructions = (current,) if address == 0x2000 else (stale,)
        return SimpleNamespace(capstone=SimpleNamespace(insns=instructions))

    function = SimpleNamespace(block_addrs_set={0x2000})
    project = SimpleNamespace(
        factory=SimpleNamespace(block=decode_block),
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda *, addr, create=False: function
                if addr == 0x2000 and create is False
                else None
            )
        ),
    )

    inventory = collect_function_instruction_inventory_8616(
        project,
        function_entry=0x2000,
    )

    assert inventory.status is FunctionInstructionInventoryStatus8616.COMPLETE
    assert inventory.complete is True
    assert inventory.block_addrs == (0x2000,)
    assert inventory.instructions == (current,)
    assert decoded_addrs == [0x2000]
    assert inventory.raw_fact_count == inventory.materialized_count == 1
    assert inventory.failure_count == 0


def test_function_inventory_refuses_incomplete_cfg_decode() -> None:
    function = SimpleNamespace(block_addrs_set={0x2000, 0x2010})

    def decode_block(
        address: int,
        *,
        opt_level: int,
        num_inst: int | None = None,
    ) -> object:
        del opt_level, num_inst
        instructions = (
            (SimpleNamespace(address=address, size=1, mnemonic="nop"),)
            if address == 0x2000
            else ()
        )
        return SimpleNamespace(capstone=SimpleNamespace(insns=instructions))

    project = SimpleNamespace(
        factory=SimpleNamespace(block=decode_block),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda *, addr, create=False: function)
        ),
    )

    inventory = collect_function_instruction_inventory_8616(
        project,
        function_entry=0x2000,
    )

    assert inventory.status is FunctionInstructionInventoryStatus8616.DECODE_REFUSED
    assert inventory.complete is False
    assert inventory.raw_fact_count == 2
    assert inventory.materialized_count == 1
    assert inventory.failure_count == 1


def test_exact_coverage_accepts_only_binary_proven_unreachable_instructions() -> None:
    project = _unreachable_padding_project()
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            project.factory.block(0x1000, opt_level=0),
            project.factory.block(0x1005, opt_level=0),
        ),
    )
    metadata = SimpleNamespace(
        cod_raw_entries=(
            {"offset": 0, "bytes": bytes.fromhex("eb 03")},
            {"offset": 2, "bytes": bytes.fromhex("90")},
            {"offset": 3, "bytes": bytes.fromhex("90")},
            {"offset": 4, "bytes": bytes.fromhex("90")},
            {"offset": 5, "bytes": bytes.fromhex("c3")},
        )
    )

    evidence = collect_exact_instruction_coverage_8616(
        project,
        function,
        metadata,  # type: ignore[arg-type]
    )

    assert evidence.verdict is ExactInstructionCoverageVerdict8616.COMPLETE
    assert evidence.complete is True
    assert evidence.proven_unreachable_instruction_addrs == (0x1002, 0x1003, 0x1004)
    assert evidence.materialized_count == 2
    assert evidence.excluded_unreachable_count == 3
    assert evidence.failure_count == 0
