"""Layer: Tests.

Responsibility: bind no-effect provenance to native bytes and invocation state.
"""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.ir.core import IRFunctionArtifact, IRInstr
from angr_platforms.X86_16.ir.instruction_origin import IRInstructionOrigin8616
from angr_platforms.X86_16.ir.real16_invocation_domain import _native_origin_equal_8616
from test_nop_census_8616 import _BASE, _built, _mutated_coverage


def test_existing_origin_remains_natively_bound() -> None:
    """Extending origin fields must preserve ordinary native-origin binding."""
    origin = IRInstructionOrigin8616(block_addr=_BASE, statement_index=1)
    assert _native_origin_equal_8616(origin, origin, 0)


def test_mark_origin_difference_is_observable() -> None:
    """Native binding must compare the new field rather than omit it."""
    origin = IRInstructionOrigin8616(block_addr=_BASE, statement_index=1)
    assert not _native_origin_equal_8616(
        origin, replace(origin, is_instruction_mark=True), 0
    )


def test_forged_mark_cannot_hide_native_store() -> None:
    """An address-complete fabricated NOP must not erase an actual store."""
    def forge(artifact: IRFunctionArtifact) -> IRFunctionArtifact:
        return replace(artifact, blocks=tuple(
            replace(block, instrs=(
                IRInstr(op="NOP", dst=None, args=(), size=0, addr=_BASE,
                        origin=IRInstructionOrigin8616(
                            block_addr=_BASE, statement_index=0,
                            is_instruction_mark=True)),
                *(instr for instr in block.instrs if instr.addr != _BASE),
            )) if block.addr == _BASE else block
            for block in artifact.blocks
        ))

    coverage = _mutated_coverage(bytes.fromhex("a3 34 12 c3"), _BASE, _BASE + 4, forge)
    assert coverage is not None
    assert not coverage.complete, "forged mark concealed native STORE"


@pytest.mark.parametrize("changes", [
    {"block_addr": _BASE + 1},
    {"statement_index": 1000000},
    {"is_block_next": True},
    {"address_tmp": 7},
    {"block_next_tmp": 7},
])
def test_nop_origin_coordinates_and_kind_are_bound(changes: dict[str, int | bool]) -> None:
    """A genuine NOP does not authenticate arbitrary retained coordinates."""
    def alter(artifact: IRFunctionArtifact) -> IRFunctionArtifact:
        return replace(artifact, blocks=tuple(
            replace(block, instrs=tuple(
                replace(instr, origin=replace(instr.origin, **changes))
                if instr.op == "NOP" else instr
                for instr in block.instrs
            )) for block in artifact.blocks
        ))

    coverage = _mutated_coverage(bytes.fromhex("90 c3"), _BASE, _BASE + 2, alter)
    assert coverage is not None
    assert not coverage.complete


def test_published_nop_coverage_does_not_survive_native_mutation() -> None:
    """A retained coverage result must not authenticate stale executable bytes."""
    built = _built(bytes.fromhex("90 c3"), _BASE, _BASE + 2)
    assert built is not None
    project, _, _, coverage = built
    assert coverage.complete
    project.loader.memory.store(_BASE, b"\xf4")
    assert not coverage.complete, "cached NOP evidence survived replacement by HLT"


def test_initialized_mz_native_nops_preserve_invocation_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Authenticated native NOPs must be consumed by invocation simulation."""
    import test_x86_16_invocation_domain as native

    # Preserve entry/call coordinates and the real MZ source authority.
    # Two native NOPs replace the original two-byte segment setup before CALL.
    monkeypatch.setattr(native, "STUB_CODE", bytes.fromhex("90 90 e8 cb ff c3"))
    boot = native._boot()
    project, coverage, _, preservation = native._world(boot)
    premise = native.prove_real16_invocation_domain_8616(
        project, coverage, 0x1032, boot=boot, boot_recompute=native._recompute,
        call_preservations=(preservation,),
    )
    assert premise.complete, premise.failure
