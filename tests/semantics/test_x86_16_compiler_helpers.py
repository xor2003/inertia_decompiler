from __future__ import annotations

import io
from types import SimpleNamespace

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.lifter_backend import LifterBackend
from inertia.frontend.x86_16.public_api import VEX_BACKEND
from inertia.postprocess.decompiler_postprocess_stage import _target_is_stack_probe_helper_8616
from inertia.semantics.compiler_helpers import (
    CompilerHelperEvidenceKind8616,
    X86_16MscStackProbeFarSimProcedure8616,
    X86_16MscStackProbeSimProcedure8616,
    hook_x86_16_compiler_helper_at_8616,
    hook_x86_16_known_compiler_helpers_8616,
    identify_x86_16_compiler_helper_at_8616,
    is_x86_16_registered_stack_probe_target_8616,
    is_x86_16_stack_probe_evidence_kind_8616,
    is_x86_16_stack_probe_helper_at_8616,
    is_x86_16_stack_probe_name_8616,
)

MSC_ANCHKSTK_BYTES = bytes.fromhex("59 8b dc 2b d8 72 0a 3b 1e b6 00 72 04 8b e3 ff e1")
MSC_AFCHKSTK_BYTES = bytes.fromhex("59 5a 8b dc 2b d8 72 0b 3b 1e c6 00 72 05 8b e3 52 51 cb")
MSC_ANLDIV_BYTES = bytes.fromhex(
    "55 8b ec 57 56 53 33 ff 8b 46 06 0b c0 7d 11 47 8b 56 04 f7 d8 f7 da 1d 00 00 89 46 06 89 56 04"
)


def _project_with_memory(code: bytes, *, base: int = 0x1000):
    def _load(addr: int, size: int):
        offset = addr - base
        if offset < 0:
            raise KeyError(addr)
        return code[offset : offset + size]

    return SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=_load)),
    )


def test_identify_msc_anchkstk_from_binary_bytes_without_sidecars():
    project = _project_with_memory(MSC_ANCHKSTK_BYTES)

    evidence = identify_x86_16_compiler_helper_at_8616(project, 0x1000)

    assert evidence is not None
    assert evidence.kind is CompilerHelperEvidenceKind8616.STACK_PROBE
    assert evidence.name == "aNchkstk"
    assert evidence.pattern_name == "msc_aNchkstk_popcx_sp_ax"
    assert evidence.matched_bytes == len(MSC_ANCHKSTK_BYTES)
    assert is_x86_16_stack_probe_helper_at_8616(project, 0x1000) is True


def test_identify_msc_afchkstk_far_probe_from_binary_bytes_without_sidecars():
    project = _project_with_memory(MSC_AFCHKSTK_BYTES)

    evidence = identify_x86_16_compiler_helper_at_8616(project, 0x1000)

    assert evidence is not None
    assert evidence.kind is CompilerHelperEvidenceKind8616.STACK_PROBE_FAR
    assert evidence.name == "aFchkstk"
    assert evidence.pattern_name == "msc_aFchkstk_popcx_popdx_sp_ax_retf"
    assert evidence.matched_bytes == len(MSC_AFCHKSTK_BYTES)
    assert is_x86_16_stack_probe_helper_at_8616(project, 0x1000) is True
    assert is_x86_16_stack_probe_evidence_kind_8616(evidence.kind) is True
    assert is_x86_16_stack_probe_evidence_kind_8616(CompilerHelperEvidenceKind8616.SIGNED_LONG_DIVIDE) is False


def test_near_probe_diverted_overflow_branch_has_no_helper_evidence() -> None:
    """Near-probe inlining requires branches to bypass every returning write."""
    for branch_index in (6, 12):
        mutated = bytearray(MSC_ANCHKSTK_BYTES)
        mutated[branch_index] = 0
        project = _project_with_memory(bytes(mutated))

        assert identify_x86_16_compiler_helper_at_8616(project, 0x1000) is None


def test_identify_msc_signed_long_divide_from_binary_bytes_without_sidecars() -> None:
    project = _project_with_memory(MSC_ANLDIV_BYTES)

    evidence = identify_x86_16_compiler_helper_at_8616(project, 0x1000)

    assert evidence is not None
    assert evidence.kind is CompilerHelperEvidenceKind8616.SIGNED_LONG_DIVIDE
    assert evidence.name == "aNldiv"
    assert evidence.pattern_name == "msc_aNldiv_signed_dx_ax"
    assert evidence.matched_bytes == len(MSC_ANLDIV_BYTES)
    assert is_x86_16_stack_probe_helper_at_8616(project, 0x1000) is False


def test_identify_stack_probe_through_rebased_original_project_bytes():
    original = _project_with_memory(MSC_ANCHKSTK_BYTES, base=0x11032)
    sliced = _project_with_memory(b"", base=0x1000)
    sliced._inertia_original_project = original
    sliced._inertia_original_linear_delta = 0xF000

    evidence = identify_x86_16_compiler_helper_at_8616(sliced, 0x2032)

    assert evidence is not None
    assert evidence.addr == 0x2032
    assert evidence.kind is CompilerHelperEvidenceKind8616.STACK_PROBE


def test_identify_stack_probe_through_preserved_linked_original_target():
    original = _project_with_memory(MSC_ANCHKSTK_BYTES, base=0x11222)
    sliced = _project_with_memory(b"", base=0x1000)
    sliced._inertia_original_project = original
    sliced._inertia_original_linear_delta = 0xF560

    evidence = identify_x86_16_compiler_helper_at_8616(sliced, 0x11222)

    assert evidence is not None
    assert evidence.addr == 0x11222
    assert evidence.kind is CompilerHelperEvidenceKind8616.STACK_PROBE
    assert evidence.matched_bytes == len(MSC_ANCHKSTK_BYTES)


def test_stack_probe_name_normalization_covers_msc_and_chkstk_spellings():
    assert is_x86_16_stack_probe_name_8616("__aNchkstk") is True
    assert is_x86_16_stack_probe_name_8616("__aFchkstk") is True
    assert is_x86_16_stack_probe_name_8616("_chkstk") is True
    assert is_x86_16_stack_probe_name_8616("__analloca_probe") is True
    assert is_x86_16_stack_probe_name_8616("clock") is False


def test_hook_msc_afchkstk_installs_far_stack_probe_simprocedure():
    hooks: dict[int, object] = {}
    project = _project_with_memory(MSC_AFCHKSTK_BYTES)
    project.is_hooked = lambda addr: addr in hooks
    project.hook = lambda addr, proc: hooks.setdefault(addr, proc)

    evidence = hook_x86_16_compiler_helper_at_8616(project, 0x1000)

    assert evidence is not None
    assert evidence.kind is CompilerHelperEvidenceKind8616.STACK_PROBE_FAR
    assert isinstance(hooks[0x1000], X86_16MscStackProbeFarSimProcedure8616)
    assert not isinstance(hooks[0x1000], X86_16MscStackProbeSimProcedure8616)


def test_scan_hooks_far_stack_probe_helpers_from_main_object():
    hooks: dict[int, object] = {}
    project = _project_with_memory(b"\x90" + MSC_AFCHKSTK_BYTES, base=0x10000)
    project.loader.main_object = SimpleNamespace(min_addr=0x10000, max_addr=0x10000 + len(MSC_AFCHKSTK_BYTES))
    project.is_hooked = lambda addr: addr in hooks
    project.hook = lambda addr, proc: hooks.setdefault(addr, proc)

    evidence = hook_x86_16_known_compiler_helpers_8616(project)

    assert len(evidence) == 1
    assert evidence[0].addr == 0x10001
    assert evidence[0].kind is CompilerHelperEvidenceKind8616.STACK_PROBE_FAR
    assert isinstance(hooks[0x10001], X86_16MscStackProbeFarSimProcedure8616)
    assert is_x86_16_registered_stack_probe_target_8616(project.arch, 0x10001) is True
    assert is_x86_16_registered_stack_probe_target_8616(project.arch, 0x0001) is True


def test_selector_effect_gate_accepts_far_stack_probe_evidence():
    project = _project_with_memory(MSC_AFCHKSTK_BYTES)

    assert _target_is_stack_probe_helper_8616(project, 0x1000, "sub_1000") is True


def test_selector_effect_gate_uses_binary_stack_probe_evidence_without_sidecar_name():
    project = _project_with_memory(MSC_ANCHKSTK_BYTES)

    assert _target_is_stack_probe_helper_8616(project, 0x1000, "sub_1000") is True


def test_hook_msc_anchkstk_installs_stack_probe_simprocedure():
    hooks: dict[int, object] = {}
    project = _project_with_memory(MSC_ANCHKSTK_BYTES)
    project.is_hooked = lambda addr: addr in hooks
    project.hook = lambda addr, proc: hooks.setdefault(addr, proc)

    evidence = hook_x86_16_compiler_helper_at_8616(project, 0x1000)

    assert evidence is not None
    assert evidence.kind is CompilerHelperEvidenceKind8616.STACK_PROBE
    assert isinstance(hooks[0x1000], X86_16MscStackProbeSimProcedure8616)


def test_scan_hooks_known_stack_probe_helpers_from_main_object():
    hooks: dict[int, object] = {}
    project = _project_with_memory(b"\x90\x90" + MSC_ANCHKSTK_BYTES, base=0x10000)
    project.loader.main_object = SimpleNamespace(min_addr=0x10000, max_addr=0x10000 + len(MSC_ANCHKSTK_BYTES) + 1)
    project.is_hooked = lambda addr: addr in hooks
    project.hook = lambda addr, proc: hooks.setdefault(addr, proc)

    evidence = hook_x86_16_known_compiler_helpers_8616(project)

    assert len(evidence) == 1
    assert evidence[0].addr == 0x10002
    assert isinstance(hooks[0x10002], X86_16MscStackProbeSimProcedure8616)
    assert is_x86_16_registered_stack_probe_target_8616(project.arch, 0x10002) is True
    assert is_x86_16_registered_stack_probe_target_8616(project.arch, 0x0002) is True


def _probe_execution(code: bytes, *, hooked: bool, sp: int, ax: int, limit: int):
    """Execute exact probe bytes to return or the first failure-tail instruction."""
    assert VEX_BACKEND is LifterBackend.CYTHON
    apply_x86_16_bootstrap()
    entry = 0x164A
    project = angr.Project(
        io.BytesIO(code),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": entry, "entry_point": entry},
        auto_load_libs=False,
    )
    if hooked:
        assert hook_x86_16_compiler_helper_at_8616(project, entry) is not None
        assert project.is_hooked(entry)
    state = project.factory.blank_state(
        addr=entry,
        add_options={angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS, angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY},
    )
    state.regs.cs, state.regs.ss, state.regs.ds = 0x100, 0x2000, 0x3000
    state.regs.sp, state.regs.ax, state.regs.flags = sp, ax, 0x602
    far = code == MSC_AFCHKSTK_BYTES
    return_cs = 0x200 if far else 0x100
    frame = b"\x22\x22\x00\x02" if far else b"\x22\x22"
    for offset, value in enumerate(frame):
        state.memory.store(0x20000 + ((sp + offset) & 0xFFFF), value, size=1)
    displacement = 0xC6 if far else 0xB6
    state.memory.store(0x30000 + displacement, limit, size=2, endness="Iend_LE")
    return_linear = (return_cs << 4) + 0x2222
    failure_linear = entry + len(code)
    visited = []
    for _ in range(16):
        result = project.factory.successors(state, opt_level=0)
        successors = result.flat_successors
        assert len(successors) == 1, (state.addr, visited, result, result.all_successors)
        state = successors[0]
        visited.append(state.addr)
        if not entry <= state.addr < failure_linear:
            break
    assert state.addr in {return_linear, failure_linear}, visited
    registers = tuple(
        state.solver.eval(state.registers.load(name))
        for name in ("eip", "ip", "cs", "ss", "ds", "sp", "ax", "bx", "cx", "dx", "flags", "d")
    )
    final_sp = state.solver.eval(state.regs.sp)
    observed_addresses = {
        0x20000 + ((sp + offset) & 0xFFFF) for offset in range(len(frame))
    } | {
        0x20000 + ((final_sp + offset) & 0xFFFF) for offset in range(-4, 4)
    } | {0x30000 + displacement, 0x30001 + displacement}
    memory = tuple(
        (addr, state.solver.eval(state.memory.load(addr, 1)))
        for addr in sorted(observed_addresses)
    )
    return registers, memory, state.addr == failure_linear


@pytest.mark.parametrize("code", [MSC_ANCHKSTK_BYTES, MSC_AFCHKSTK_BYTES], ids=["near", "far"])
@pytest.mark.parametrize(
    ("sp", "ax", "limit", "fails"),
    [(0x8000, 0x20, 0x100, False), (0x100, 0x200, 0, True), (0x8000, 0x20, 0x9000, True), (0xFFFF, 0, 0, False)],
    ids=["return-nonzero-cs", "subtraction-borrow", "below-ds-limit", "wrapped-return-frame"],
)
def test_registered_probe_execution_preserves_native_effects(code, sp, ax, limit, fails):
    """A registered probe must preserve native flags, failure edges and segmented returns."""
    native = _probe_execution(code, hooked=False, sp=sp, ax=ax, limit=limit)
    assert native[2] is fails
    hooked = _probe_execution(code, hooked=True, sp=sp, ax=ax, limit=limit)
    assert hooked == native
