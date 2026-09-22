from __future__ import annotations

from types import SimpleNamespace

import archinfo
from angr.errors import SimEngineError
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeLong, SimTypeShort
from angr_platforms.X86_16.analysis_helpers import (
    _analysis_function_addr_8616,
    seed_calling_conventions,
    seed_wide_stack_prototype_from_binary_address_8616,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.calling_convention_compat import (
    _promote_wide_return_and_stack_args_8616,
    _set_function_prototype_8616,
    _terminal_byte_return_evidence_8616,
    _terminal_wide_return_evidence_8616,
    _terminal_word_return_evidence_8616,
    _wide_stack_argument_evidence_8616,
    _WideReturnEvidence8616,
    apply_x86_16_wide_stack_prototype_evidence,
    apply_x86_16_wide_stack_prototype_evidence_at_address,
)
from angr_platforms.X86_16.lowering.terminal_call_return_types import (
    TerminalCallReturnTypeEvidence8616,
    TerminalCallReturnTypeResult8616,
)


def test_seed_calling_conventions_preserves_binary_proven_stub_prototype() -> None:
    prototype = object()
    calling_convention = object()
    init_calls: list[None] = []
    function = SimpleNamespace(
        name="sub_1234",
        prototype=prototype,
        calling_convention=calling_convention,
        is_prototype_guessed=False,
        _init_prototype_and_calling_convention=lambda: init_calls.append(None),
    )
    cfg = SimpleNamespace(
        functions={0x1234: function},
        project=SimpleNamespace(arch=SimpleNamespace(name="not-86_16")),
    )

    seed_calling_conventions(cfg)

    assert init_calls == []
    assert function.prototype is prototype
    assert function.calling_convention is calling_convention
    assert function.is_prototype_guessed is False


class _UndecodableFactory:
    """Minimal project factory surface: every block decode request is refused.

    ``seed_calling_conventions`` probes the terminal far-return frame, which
    needs a decodable block surface. This fixture has no binary bytes, so the
    factory declines decode the way a real project does for unmapped bytes.
    """

    def block(self, *_args: object, **_kwargs: object) -> object:
        raise SimEngineError("no decodable block in minimal project")


def test_seed_calling_conventions_caches_progress_per_cfg_function(monkeypatch) -> None:
    init_calls: list[int] = []
    stack_byte_calls: list[int] = []
    wide_stack_calls: list[int] = []
    terminal_calls: list[int] = []
    terminal_register_calls: list[int] = []

    def _track_stack_byte(project: object, function: SimpleNamespace) -> bool:
        stack_byte_calls.append(_analysis_function_addr_8616(function))
        return False

    def _track_wide_stack(project: object, function: SimpleNamespace) -> bool:
        wide_stack_calls.append(_analysis_function_addr_8616(function))
        return False

    def _track_terminal(project: object, function: SimpleNamespace) -> TerminalCallReturnTypeResult8616:
        terminal_calls.append(_analysis_function_addr_8616(function))
        return TerminalCallReturnTypeResult8616(
            evidence=TerminalCallReturnTypeEvidence8616(),
            changed=False,
        )

    def _track_terminal_register(project: object, function: SimpleNamespace) -> object:
        terminal_register_calls.append(_analysis_function_addr_8616(function))
        return SimpleNamespace(
            stats=SimpleNamespace(
                raw_fact_count=0,
                normalized_fact_count=0,
                classified_fact_count=0,
                materialized_count=0,
                failure_count=0,
            ),
            changed=False,
        )

    def _make_function(function_addr: int) -> SimpleNamespace:
        def _init() -> None:
            init_calls.append(function_addr)

        return SimpleNamespace(
            name=f"sub_{function_addr:x}",
            prototype=None,
            calling_convention=None,
            is_prototype_guessed=True,
            _init_prototype_and_calling_convention=_init,
            addr=function_addr,
            block_addrs_set={function_addr},
        )

    monkeypatch.setattr(
        "angr_platforms.X86_16.calling_convention_compat.apply_x86_16_stack_byte_prototype_evidence",
        _track_stack_byte,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.calling_convention_compat.apply_x86_16_wide_stack_prototype_evidence",
        _track_wide_stack,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.lowering.terminal_call_return_types.apply_terminal_call_return_type_evidence_8616",
        _track_terminal,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.lowering.terminal_register_return_types.apply_terminal_register_return_type_evidence_8616",
        _track_terminal_register,
    )

    cfg = SimpleNamespace(
        functions={0x1000: _make_function(0x1000)},
        project=SimpleNamespace(arch=SimpleNamespace(name="86_16"), factory=_UndecodableFactory()),
    )
    seed_calling_conventions(cfg)
    seed_calling_conventions(cfg)

    assert init_calls == [0x1000]
    assert stack_byte_calls == [0x1000]
    assert wide_stack_calls == [0x1000]
    assert terminal_calls == [0x1000]
    assert terminal_register_calls == [0x1000]

    cfg.functions[0x1000].block_addrs_set.add(0x1010)
    seed_calling_conventions(cfg)

    assert init_calls == [0x1000, 0x1000]
    assert terminal_calls == [0x1000, 0x1000]
    assert terminal_register_calls == [0x1000, 0x1000]

    cfg.functions[0x2000] = _make_function(0x2000)
    seed_calling_conventions(cfg)

    assert init_calls == [0x1000, 0x1000, 0x2000]
    assert stack_byte_calls == [0x1000, 0x1000, 0x2000]
    assert wide_stack_calls == [0x1000, 0x1000, 0x2000]
    assert terminal_calls == [0x1000, 0x1000, 0x2000]
    assert terminal_register_calls == [0x1000, 0x1000, 0x2000]
    assert getattr(cfg, "_inertia_seeded_calling_conventions", None) == {0x1000, 0x2000}


def test_wide_stack_seed_copies_an_already_proven_source_prototype(monkeypatch) -> None:
    prototype = object()
    calling_convention = object()
    source = SimpleNamespace(
        prototype=prototype,
        calling_convention=calling_convention,
        is_prototype_guessed=False,
    )
    target = SimpleNamespace(
        prototype=None,
        calling_convention=None,
        is_prototype_guessed=True,
    )

    def reject_reanalysis(*_args: object, **_kwargs: object) -> bool:
        raise AssertionError("already-proven source ABI must not be reanalyzed")

    monkeypatch.setattr(
        "angr_platforms.X86_16.calling_convention_compat.apply_x86_16_wide_stack_prototype_evidence_at_address",
        reject_reanalysis,
    )

    assert seed_wide_stack_prototype_from_binary_address_8616(
        object(),
        source,
        target,
        0x1234,
    )
    assert target.prototype is prototype
    assert target.calling_convention is calling_convention
    assert target.is_prototype_guessed is False


class _FakeRegOperand:
    def __init__(self, reg: int) -> None:
        self.type = 1
        self.reg = reg


class _FakeMemory:
    def __init__(self, base: int, disp: int) -> None:
        self.base = base
        self.disp = disp


class _FakeMemOperand:
    def __init__(self, *, base: int, disp: int, size: int = 2) -> None:
        self.type = 3
        self.size = size
        self.mem = _FakeMemory(base, disp)


class _FakeImmOperand:
    def __init__(self, imm: int) -> None:
        self.type = 2
        self.imm = imm


class _FakeInsn:
    def __init__(
        self,
        mnemonic: str,
        *,
        writes: str | None = None,
        target: int | None = None,
        source_bp_offset: int | None = None,
    ) -> None:
        self.mnemonic = mnemonic
        operands = []
        if writes is not None:
            operands.append(_FakeRegOperand({"ax": 1, "dx": 2, "al": 3, "ah": 4}[writes]))
        if source_bp_offset is not None:
            operands.append(_FakeMemOperand(base=6, disp=source_bp_offset))
        if target is not None:
            operands.append(_FakeImmOperand(target))
        self.operands = tuple(operands)

    def reg_name(self, reg_id: int) -> str:
        return {1: "ax", 2: "dx", 3: "al", 4: "ah", 6: "bp"}.get(reg_id, "")


class _FakeMovSpBpInsn:
    mnemonic = "mov"

    def __init__(self) -> None:
        self.operands = (_FakeRegOperand(47), _FakeRegOperand(6))

    def reg_name(self, reg_id: int) -> str:
        return {47: "sp", 6: "bp"}.get(reg_id, "")


class _FakeBlock:
    def __init__(self, insns: tuple[_FakeInsn | object, ...]) -> None:
        self.capstone = SimpleNamespace(insns=insns)


class _FakeFactory:
    def __init__(self, blocks: dict[int, _FakeBlock]) -> None:
        self._blocks = blocks

    def block(self, addr: int, opt_level: int = 0, size: int | None = None) -> _FakeBlock:
        return self._blocks[addr]


class _FakeProject:
    def __init__(
        self,
        insns: tuple[_FakeInsn | object, ...],
        *,
        extra_blocks: dict[int, tuple[_FakeInsn | object, ...]] | None = None,
    ) -> None:
        blocks = {0x1000: _FakeBlock(insns)}
        blocks.update({addr: _FakeBlock(block_insns) for addr, block_insns in (extra_blocks or {}).items()})
        self.factory = _FakeFactory(blocks)


def test_terminal_wide_return_evidence_requires_terminal_suffix() -> None:
    project = _FakeProject(
        (
            _FakeInsn("mov", writes="ax"),
            _FakeInsn("adc", writes="dx"),
            _FakeInsn("mov"),
            _FakeInsn("ret"),
        )
    )
    function = SimpleNamespace(block_addrs_set={0x1000})

    evidence = _terminal_wide_return_evidence_8616(project, function)

    assert evidence is _WideReturnEvidence8616.NONE


def test_terminal_wide_return_evidence_rejects_stale_dx_before_later_ax_write() -> None:
    project = _FakeProject(
        (
            _FakeInsn("imul", writes="dx"),
            _FakeInsn("sub", writes="ax"),
            _FakeInsn("ret"),
        )
    )
    function = SimpleNamespace(block_addrs_set={0x1000})

    assert _terminal_wide_return_evidence_8616(project, function) is _WideReturnEvidence8616.NONE


def test_terminal_wide_return_evidence_accepts_epilogue_suffix() -> None:
    project = _FakeProject(
        (
            _FakeInsn("mov", writes="ax"),
            _FakeInsn("adc", writes="dx"),
            _FakeInsn("pop"),
            _FakeInsn("ret"),
        )
    )
    function = SimpleNamespace(block_addrs_set={0x1000})

    evidence = _terminal_wide_return_evidence_8616(project, function)

    assert evidence is _WideReturnEvidence8616.DX_AX_TERMINAL_ARITH


def test_terminal_wide_return_evidence_accepts_direct_jump_to_shared_epilogue() -> None:
    project = _FakeProject(
        (
            _FakeInsn("mov", writes="ax"),
            _FakeInsn("sbb", writes="dx"),
            _FakeInsn("jmp", target=0x1010),
        ),
        extra_blocks={0x1010: (_FakeInsn("pop"), _FakeInsn("ret"))},
    )
    function = SimpleNamespace(block_addrs_set={0x1000, 0x1010})

    evidence = _terminal_wide_return_evidence_8616(project, function)

    assert evidence is _WideReturnEvidence8616.DX_AX_TERMINAL_ARITH


def test_terminal_wide_return_evidence_accepts_mov_sp_bp_shared_epilogue() -> None:
    project = _FakeProject(
        (
            _FakeInsn("mov", writes="ax"),
            _FakeInsn("sbb", writes="dx"),
            _FakeInsn("jmp", target=0x1010),
        ),
        extra_blocks={0x1010: (_FakeInsn("pop"), _FakeMovSpBpInsn(), _FakeInsn("pop"), _FakeInsn("ret"))},
    )
    function = SimpleNamespace(block_addrs_set={0x1000, 0x1010})

    evidence = _terminal_wide_return_evidence_8616(project, function)

    assert evidence is _WideReturnEvidence8616.DX_AX_TERMINAL_ARITH


def test_terminal_wide_return_evidence_reads_register_names_from_angr_capstone_wrappers() -> None:
    project = _FakeProject(
        (
            SimpleNamespace(insn=_FakeInsn("mov", writes="ax"), mnemonic="mov"),
            SimpleNamespace(insn=_FakeInsn("sbb", writes="dx"), mnemonic="sbb"),
            _FakeInsn("jmp", target=0x1010),
        ),
        extra_blocks={0x1010: (_FakeInsn("pop"), _FakeInsn("ret"))},
    )
    function = SimpleNamespace(block_addrs_set={0x1000, 0x1010})

    evidence = _terminal_wide_return_evidence_8616(project, function)

    assert evidence is _WideReturnEvidence8616.DX_AX_TERMINAL_ARITH


def test_terminal_word_return_evidence_accepts_ax_before_return() -> None:
    project = _FakeProject((_FakeInsn("mov", writes="ax"), _FakeInsn("ret")))
    function = SimpleNamespace(block_addrs_set={0x1000})

    assert _terminal_word_return_evidence_8616(project, function)


def test_terminal_word_return_evidence_accepts_complete_al_ah_pair() -> None:
    project = _FakeProject(
        (_FakeInsn("mov", writes="al"), _FakeInsn("mov", writes="ah"), _FakeInsn("ret"))
    )
    function = SimpleNamespace(block_addrs_set={0x1000})

    assert _terminal_word_return_evidence_8616(project, function)
    assert not _terminal_byte_return_evidence_8616(project, function)


def test_terminal_word_return_evidence_follows_al_to_ah_epilogue_edge() -> None:
    project = _FakeProject(
        (_FakeInsn("mov", writes="al"), _FakeInsn("jmp", target=0x1010)),
        extra_blocks={0x1010: (_FakeInsn("mov", writes="ah"), _FakeInsn("ret"))},
    )
    function = SimpleNamespace(block_addrs_set={0x1000, 0x1010})

    assert _terminal_word_return_evidence_8616(project, function)
    assert not _terminal_byte_return_evidence_8616(project, function)


def test_terminal_return_evidence_invalidates_register_writes_at_calls() -> None:
    function = SimpleNamespace(block_addrs_set={0x1000})
    direct_byte_project = _FakeProject((_FakeInsn("mov", writes="al"), _FakeInsn("ret")))
    byte_call_project = _FakeProject(
        (_FakeInsn("mov", writes="al"), _FakeInsn("call", target=0x2000), _FakeInsn("ret"))
    )
    word_call_project = _FakeProject(
        (_FakeInsn("mov", writes="ax"), _FakeInsn("call", target=0x2000), _FakeInsn("ret"))
    )

    assert _terminal_byte_return_evidence_8616(direct_byte_project, function)
    assert not _terminal_byte_return_evidence_8616(byte_call_project, function)
    assert not _terminal_word_return_evidence_8616(word_call_project, function)


def test_terminal_wide_return_promotion_accepts_zero_arguments() -> None:
    arch = Arch86_16()
    project = _FakeProject(
        (
            _FakeInsn("mov", writes="ax"),
            _FakeInsn("mov", writes="dx"),
            _FakeInsn("ret"),
        )
    )
    project.arch = arch
    function = SimpleNamespace(block_addrs_set={0x1000})
    analysis = SimpleNamespace(project=project, _function=function)
    prototype = SimTypeFunction([], SimTypeShort(False)).with_arch(arch)

    promoted = _promote_wide_return_and_stack_args_8616(
        analysis,
        prototype,
        promote_return=True,
    )

    assert isinstance(promoted.returnty, SimTypeLong)
    assert promoted.returnty.size == 32
    assert promoted.args == ()


def test_wide_stack_prototype_evidence_preserves_non_guessed_source_prototype():
    arch = archinfo.ArchX86()
    source_proto = SimTypeFunction([SimTypeLong(False)], SimTypeBottom(label="void")).with_arch(arch)
    wide_proto = SimTypeFunction([SimTypeLong(False)], SimTypeLong(False)).with_arch(arch)
    function = SimpleNamespace(
        prototype=source_proto,
        is_prototype_guessed=False,
        project=SimpleNamespace(arch=arch),
    )

    _cc, selected = _set_function_prototype_8616(function, "wide-cc", wide_proto)

    assert selected is source_proto
    assert function.prototype is source_proto
    assert not hasattr(function, "calling_convention")


def test_apply_wide_stack_prototype_evidence_refuses_non_guessed_existing_prototype():
    arch = SimpleNamespace(name="86_16")
    source_proto = SimTypeFunction([SimTypeLong(False)], SimTypeBottom(label="void"))
    function = SimpleNamespace(prototype=source_proto, is_prototype_guessed=False)
    project = SimpleNamespace(arch=arch)

    changed = apply_x86_16_wide_stack_prototype_evidence(project, function)

    assert changed is False
    assert function.prototype is source_proto


def test_wide_stack_argument_evidence_classifies_adjacent_add_adc_bp_words() -> None:
    project = _FakeProject(
        (
            _FakeInsn("add", writes="ax", source_bp_offset=4),
            _FakeInsn("adc", writes="dx", source_bp_offset=6),
            _FakeInsn("ret"),
        )
    )
    function = SimpleNamespace(block_addrs_set={0x1000})

    evidence = _wide_stack_argument_evidence_8616(project, function)

    assert evidence.raw_fact_count == 1
    assert evidence.normalized_fact_count == 1
    assert evidence.classified_offsets == (4,)
    assert evidence.failure_count == 0


def test_wide_stack_argument_evidence_refuses_nonadjacent_carry_source() -> None:
    project = _FakeProject(
        (
            _FakeInsn("add", writes="ax", source_bp_offset=4),
            _FakeInsn("adc", writes="dx", source_bp_offset=8),
            _FakeInsn("ret"),
        )
    )
    function = SimpleNamespace(block_addrs_set={0x1000})

    evidence = _wide_stack_argument_evidence_8616(project, function)

    assert evidence.raw_fact_count == 1
    assert evidence.normalized_fact_count == 1
    assert evidence.classified_offsets == ()
    assert evidence.failure_count == 1


def test_apply_wide_stack_prototype_evidence_merges_physical_words_for_void_callee() -> None:
    arch = Arch86_16()
    project = _FakeProject(
        (
            _FakeInsn("add", writes="ax", source_bp_offset=4),
            _FakeInsn("adc", writes="dx", source_bp_offset=6),
            _FakeInsn("ret"),
        )
    )
    project.arch = arch
    function = SimpleNamespace(
        block_addrs_set={0x1000},
        prototype=SimTypeFunction(
            [SimTypeShort(False), SimTypeShort(False)],
            SimTypeBottom(label="void"),
        ).with_arch(arch),
        is_prototype_guessed=True,
        project=project,
    )

    changed = apply_x86_16_wide_stack_prototype_evidence(project, function)

    assert changed
    assert len(function.prototype.args) == 1
    assert isinstance(function.prototype.args[0], SimTypeLong)
    assert isinstance(function.prototype.returnty, SimTypeLong)


def test_address_wide_stack_evidence_materializes_bodyless_stub_from_bounded_body() -> None:
    arch = Arch86_16()
    project = _FakeProject(
        (
            _FakeInsn("call"),
            _FakeInsn("add", writes="ax", source_bp_offset=4),
            _FakeInsn("adc", writes="dx", source_bp_offset=6),
            _FakeInsn("ret"),
            _FakeInsn("add", writes="ax", source_bp_offset=8),
            _FakeInsn("adc", writes="dx", source_bp_offset=10),
        )
    )
    project.arch = arch
    function = SimpleNamespace(
        prototype=SimTypeFunction(
            [SimTypeShort(False), SimTypeShort(False)],
            SimTypeBottom(label="void"),
        ).with_arch(arch),
        is_prototype_guessed=False,
        project=project,
    )

    changed = apply_x86_16_wide_stack_prototype_evidence_at_address(project, function, 0x1000, scan_size=64)

    assert changed
    assert len(function.prototype.args) == 1
    assert isinstance(function.prototype.args[0], SimTypeLong)
    assert isinstance(function.prototype.returnty, SimTypeLong)


def test_address_wide_stack_evidence_refuses_window_without_return() -> None:
    arch = Arch86_16()
    project = _FakeProject(
        (
            _FakeInsn("add", writes="ax", source_bp_offset=4),
            _FakeInsn("adc", writes="dx", source_bp_offset=6),
        )
    )
    project.arch = arch
    prototype = SimTypeFunction(
        [SimTypeShort(False), SimTypeShort(False)],
        SimTypeBottom(label="void"),
    ).with_arch(arch)
    function = SimpleNamespace(prototype=prototype, is_prototype_guessed=True, project=project)

    changed = apply_x86_16_wide_stack_prototype_evidence_at_address(project, function, 0x1000, scan_size=64)

    assert not changed
    assert function.prototype is prototype
