from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.compiler_helpers import (
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
from angr_platforms.X86_16.decompiler_postprocess_stage import _target_is_stack_probe_helper_8616

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
