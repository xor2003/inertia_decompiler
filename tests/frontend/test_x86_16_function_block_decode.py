from __future__ import annotations

from types import SimpleNamespace

from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.frontend.x86_16.frontend_function_block_decode import (
    FunctionBlockDecodeFailureReason8616,
    collect_function_block_decode_artifact_8616,
)
from inertia.semantics.terminal_register_returns import (
    TerminalAxReturnLane8616,
    collect_terminal_ax_return_evidence_8616,
)
from inertia.cli.project_loading import _build_project_from_bytes


class _Memory:
    def __init__(self, blocks: dict[int, bytes]) -> None:
        self.blocks = blocks
        self.loads: list[tuple[int, int]] = []

    def load(self, address: int, size: int) -> bytes:
        self.loads.append((address, size))
        return self.blocks[address][:size]


class _ForbiddenFactory:
    def __init__(self) -> None:
        self.calls = 0

    def block(self, _address: int, **_kwargs: object) -> object:
        self.calls += 1
        raise AssertionError("exact function decode must not enter VEX")


def _function(entry: int, blocks: dict[int, bytes]) -> object:
    nodes = tuple(
        SimpleNamespace(addr=address, size=len(code))
        for address, code in sorted(blocks.items())
    )
    return SimpleNamespace(
        addr=entry,
        size=sum(len(code) for code in blocks.values()),
        block_addrs_set=set(blocks),
        graph=SimpleNamespace(nodes=nodes),
    )


def _instruction_shape(instruction: object) -> tuple[int, int, str, str]:
    inner = getattr(instruction, "insn", instruction)
    return (
        int(inner.address),
        int(inner.size),
        str(inner.mnemonic),
        str(inner.op_str),
    )


def test_exact_function_decode_matches_factory_capstone_without_relifting() -> None:
    code = bytes.fromhex("558bec66b8785634125dc3")
    base = 0x4000
    project = _build_project_from_bytes(code, base_addr=base, entry_point=base)
    function = _function(base, {base: code})

    factory_block = project.factory.block(base, size=len(code), opt_level=0)
    expected = tuple(_instruction_shape(insn) for insn in factory_block.capstone.insns)
    project.factory.default_engine.clear_cache()

    artifact = collect_function_block_decode_artifact_8616(project, function)
    cached = collect_function_block_decode_artifact_8616(project, function)

    assert artifact.complete
    assert cached is artifact
    assert tuple(_instruction_shape(insn) for insn in artifact.blocks[0].instructions) == expected
    assert project.factory.default_engine._block_cache == {}


def test_exact_function_decode_invalidates_when_loaded_bytes_change() -> None:
    base = 0x5000
    memory = _Memory({base: bytes.fromhex("b80100c3")})
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=memory),
    )
    function = _function(base, memory.blocks)

    first = collect_function_block_decode_artifact_8616(project, function)
    memory.blocks[base] = bytes.fromhex("b80200c3")
    second = collect_function_block_decode_artifact_8616(project, function)

    assert first.complete and second.complete
    assert first.content_identity != second.content_identity
    assert first is not second
    assert _instruction_shape(first.blocks[0].instructions[0])[-1] == "ax, 1"
    assert _instruction_shape(second.blocks[0].instructions[0])[-1] == "ax, 2"


def test_exact_function_decode_accepts_caller_owned_hlt_extent() -> None:
    base = 0x5800
    memory = _Memory({base: b"\xf4"})
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=memory),
    )

    artifact = collect_function_block_decode_artifact_8616(
        project,
        _function(base, memory.blocks),
    )

    assert artifact.complete
    assert _instruction_shape(artifact.blocks[0].instructions[0])[2] == "hlt"


def test_exact_function_decode_refuses_incoherent_graph_surface() -> None:
    base = 0x6000
    memory = _Memory({base: b"\xc3"})
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=memory),
    )
    function = SimpleNamespace(
        addr=base,
        block_addrs_set={base, base + 1},
        graph=SimpleNamespace(nodes=(SimpleNamespace(addr=base, size=1),)),
    )

    artifact = collect_function_block_decode_artifact_8616(project, function)

    assert not artifact.complete
    assert artifact.failures[0].reason is FunctionBlockDecodeFailureReason8616.INCOHERENT_GRAPH_EXTENTS
    assert memory.loads == []


def test_terminal_return_semantics_consumes_direct_decode_without_vex(monkeypatch) -> None:
    base = 0x7000
    blocks = {
        base: bytes.fromhex("50b80100eb00"),
        base + 6: bytes.fromhex("58c3"),
    }
    memory = _Memory(blocks)
    factory = _ForbiddenFactory()
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=memory),
        factory=factory,
    )
    function = _function(base, blocks)

    def _effect(instruction: object) -> object:
        mnemonic = str(getattr(instruction, "mnemonic", ""))
        return SimpleNamespace(
            kind=SimpleNamespace(name="OTHER"),
            dst_reg="ax" if mnemonic in {"mov", "pop"} else None,
        )

    import inertia.semantics.terminal_register_returns as terminal_register_returns

    from inertia.semantics.branch_target_return import (
        TerminalAxReturnEffectKind8616,
    )

    monkeypatch.setattr(
        terminal_register_returns,
        "terminal_ax_return_effect_8616",
        lambda instruction: SimpleNamespace(
            kind=TerminalAxReturnEffectKind8616.OTHER,
            dst_reg=_effect(instruction).dst_reg,
        ),
    )

    evidence = collect_terminal_ax_return_evidence_8616(project, function)

    assert evidence.complete
    assert evidence.states == frozenset({TerminalAxReturnLane8616.NONE})
    assert factory.calls == 0


def test_terminal_return_direct_decode_matches_legacy_vex_fallback(monkeypatch) -> None:
    base = 0x8000
    blocks = {
        base: bytes.fromhex("50b80100eb00"),
        base + 6: bytes.fromhex("58c3"),
    }
    project = _build_project_from_bytes(b"".join(blocks.values()), base_addr=base, entry_point=base)
    function = _function(base, blocks)

    direct = collect_terminal_ax_return_evidence_8616(project, function)
    project._inertia_function_evidence_inventories_8616 = {}
    refused = collect_function_block_decode_artifact_8616(
        project,
        SimpleNamespace(
            addr=base,
            block_addrs_set={base, base + 6},
            graph=SimpleNamespace(nodes=(SimpleNamespace(addr=base, size=6),)),
        ),
    )

    import inertia.semantics.terminal_register_returns as terminal_register_returns

    monkeypatch.setattr(
        terminal_register_returns,
        "collect_function_block_decode_artifact_8616",
        lambda _project, _function: refused,
    )
    legacy = collect_terminal_ax_return_evidence_8616(project, function)

    assert not refused.complete
    assert direct == legacy
