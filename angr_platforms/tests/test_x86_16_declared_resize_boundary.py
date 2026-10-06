"""Controls for the declared INT21/AH=4A tail-resize census boundary.

Fixture: one genuine MZ whose entry surface runs ``mov ax/es/bx`` setup,
``mov ah,0x4a; int 21h`` then a direct near call — the generic CD21-shaped
boundary the census may cross only under an explicitly declared,
environment-bound resize relation projected through the shared canonical
owner. Every negative keeps refusal typed; positives retain the consumed
relation on the domain with the modeled MCB write evidence. The version
relation controls prove the shared digest and census paths stay intact.
"""

import io
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import cast

import angr
import pytest
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
)
from angr_platforms.X86_16.ir.function_ir_registry import (
    publish_function_ir_artifact_8616,
)
from angr_platforms.X86_16.ir.ir_boundary_cfg import (
    prove_ir_boundary_coverage_8616,
)
from angr_platforms.X86_16.ir.real16_declared_interrupt8616 import (
    VERSION_PRESERVED_LANES_8616,
    DeclaredInterruptRefusal8616,
    DeclaredInterruptService8616,
    DeclaredResizeConsumption8616,
    DeclaredServiceConsumption8616,
)
from angr_platforms.X86_16.ir.real16_invocation_domain import (
    Real16InvocationAssumption8616,
    Real16InvocationDomain8616,
    Real16InvocationFailure8616,
    prove_real16_invocation_domain_8616,
    real16_invocation_discharges_8616,
)
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.mz_static_boot import (
    mz_static_boot_8616,
    recompute_mz_static_boot_8616,
)

from tools.dosunit.real16_declared_invocation8616 import (
    declared_int21_resize_service_8616,
    declared_int21_version_service_8616,
)
from tools.dosunit.real16_program_boot import (
    ProgramBoot,
    ProgramEnvironment,
    program_from_mz_bytes,
)
from tools.dosunit.real16_program_memory import InitialMemoryRegion
from tools.dosunit.real16_program_resize import (
    TailResizePolicy,
)
from tools.dosunit.real16_program_vectors import VectorPolicy, vector_bytes
from tools.dosunit.real16_program_version import VersionPolicy
from tools.dosunit.real16_replay_model import LinearRange, SegOffset

# The declared native profile fixes the loader PSP at 0x100; the module
# loads one paragraph-aligned image above it and the declared tail
# allocation reaches the conventional-memory ceiling (0xA000 paragraphs).
PSP_SEGMENT = 0x100
LOAD_SEGMENT = PSP_SEGMENT + 0x10
MODULE_BASE = LOAD_SEGMENT << 4  # 0x1100
MCB_LINEAR = (PSP_SEGMENT - 1) << 4  # 0x0FF0
MAXIMUM_PARAGRAPHS = 0xA000 - PSP_SEGMENT  # 0x9F00
DOS_ENTRY = SegOffset(0xF000, 0xF100)
NATIVE_SIGNATURE = b"\xb2KV1KPR0G"


def _mcb(size: int = MAXIMUM_PARAGRAPHS, marker: bytes = b"Z") -> bytes:
    """One declared native first/final MCB paragraph."""
    return (
        marker
        + (0x192).to_bytes(2, "little")
        + size.to_bytes(2, "little")
        + b"\0\0"
        + NATIVE_SIGNATURE
    )


def _ivt_bytes() -> bytes:
    """One fully declared 1024-byte IVT with slot 0x21 bound to DOS_ENTRY."""
    table = bytearray(0x400)
    table[0x84:0x88] = vector_bytes(DOS_ENTRY)
    return bytes(table)


_UNSET: object = object()


def _environment(
    *,
    resize: object = _UNSET,
    version: object = _UNSET,
    vector: object = _UNSET,
    ivt: bytes | None = None,
) -> ProgramEnvironment:
    return ProgramEnvironment(
        psp_segment=PSP_SEGMENT,
        allocation=bytes(MAXIMUM_PARAGRAPHS * 16),
        registers=tuple(
            (name, 0)
            for name in (
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
                "esp", "eflags",
            )
        ),
        fs=0,
        gs=0,
        version_policy=(
            VersionPolicy(major=5, minor=0, oem=0, serial=0)
            if version is _UNSET
            else cast(VersionPolicy | None, version)
        ),
        resize_policy=(
            TailResizePolicy(PSP_SEGMENT, _mcb())
            if resize is _UNSET
            else cast(TailResizePolicy | None, resize)
        ),
        vector_policy=(
            VectorPolicy(DOS_ENTRY)
            if vector is _UNSET
            else cast(VectorPolicy | None, vector)
        ),
        extra_memory=(
            InitialMemoryRegion(SegOffset(0, 0), _ivt_bytes() if ivt is None else ivt),
        ),
    )


def _mz(image: bytes, *, ss_field: int = 0x20, sp: int = 0x100) -> bytes:
    header_size = 2 * 16
    exe_size = header_size + len(image)
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = (exe_size % 512).to_bytes(2, "little")
    header[0x04:0x06] = ((exe_size + 511) // 512).to_bytes(2, "little")
    header[0x06:0x08] = (1).to_bytes(2, "little")
    header[0x08:0x0A] = (2).to_bytes(2, "little")
    header[0x0A:0x0C] = (0x10).to_bytes(2, "little")
    # The declared arena reaches the conventional ceiling, so the loader
    # grant bound (maxalloc) must admit the whole tail allocation.
    header[0x0C:0x0E] = (0xFFFF).to_bytes(2, "little")
    header[0x0E:0x10] = (ss_field).to_bytes(2, "little")  # ss = load+ss_field
    header[0x10:0x12] = (sp).to_bytes(2, "little")  # sp
    header[0x14:0x16] = (0).to_bytes(2, "little")  # ip
    header[0x16:0x18] = (0).to_bytes(2, "little")  # cs
    header[0x18:0x1A] = (0x1C).to_bytes(2, "little")
    header[0x1C:0x1E] = (0x20).to_bytes(2, "little")
    header[0x1E:0x20] = (0).to_bytes(2, "little")
    return bytes(header) + image


# mov ax,0x100 ; mov es,ax ; mov ax,0x4A00 ; mov bx,0x40 ; int 21h ;
# call +1 -> +17 ; ret ; callee ret
CALLER_RESIZE = bytes.fromhex("b80001 8ec0 b8004a bb4000 cd21 e80100 c3")
RESIZE_INT_ADDR = MODULE_BASE + 11
RESIZE_CALL_ADDR = MODULE_BASE + 13
CALLEE_CODE = bytes.fromhex("c3")


def _image(caller: bytes) -> bytes:
    image = caller + CALLEE_CODE
    return image + bytes(0x22 - len(image))


def _boot(
    caller: bytes = CALLER_RESIZE, env: ProgramEnvironment | None = None
) -> ProgramBoot:
    ranges = (
        LinearRange(MODULE_BASE, len(caller)),
        LinearRange(MODULE_BASE + len(caller), len(CALLEE_CODE)),
    )
    return program_from_mz_bytes(
        _mz(_image(caller)), _environment() if env is None else env,
        code_ranges=ranges,
    )


def _recompute(boot: object) -> object:
    typed = cast(ProgramBoot, boot)
    return program_from_mz_bytes(
        typed.source, typed.environment, code_ranges=typed.image.code_ranges
    )


def _world(boot: ProgramBoot, caller_len: int) -> tuple:
    """Build the project + registered caller artifact + coverage."""
    project = angr.Project(
        io.BytesIO(boot.image.chunks[0][1]),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": MODULE_BASE,
            "entry_point": MODULE_BASE,
        },
        auto_load_libs=False,
    )
    boundary = exact_function_range_boundary_8616(
        project, MODULE_BASE, MODULE_BASE + caller_len
    )
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, raw)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    assert coverage.complete
    return project, raw, coverage


def _resize_premise(
    project: object,
    coverage: object,
    call_addr: int,
    boot: object,
    services: tuple = (),
) -> Real16InvocationDomain8616:
    return prove_real16_invocation_domain_8616(
        project,
        coverage,
        call_addr,
        boot=boot,
        boot_recompute=_recompute,
        declared_services=services,
    )


def _resize_relation(env: ProgramEnvironment, callsite: int) -> DeclaredInterruptService8616:
    relation = declared_int21_resize_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=callsite
    )
    assert isinstance(relation, DeclaredInterruptService8616)
    return relation


def test_declared_int21_resize_crosses_boundary_and_stays_visible() -> None:
    """Declared env + authenticated relation crosses AH=4A and replays."""
    env = _environment()
    boot = _boot(env=env)
    project, raw, coverage = _world(boot, len(CALLER_RESIZE))
    relation = _resize_relation(env, RESIZE_INT_ADDR)
    premise = _resize_premise(project, coverage, RESIZE_CALL_ADDR, boot, (relation,))
    assert premise.complete
    assert Real16InvocationAssumption8616.DECLARED_INTERRUPT_SERVICE in (
        premise.assumptions
    )
    assert len(premise.service_consumptions) == 1
    consumption = premise.service_consumptions[0]
    assert type(consumption) is DeclaredResizeConsumption8616
    assert consumption.callsite_addr == RESIZE_INT_ADDR
    assert consumption.vector == 0x21
    assert consumption.function == 0x4A
    assert consumption.request_ax == 0x4A00
    assert consumption.answer_ax == 0x4A00
    assert consumption.answer_bx == 0x40
    assert consumption.carry is False
    assert consumption.metadata_linear == MCB_LINEAR
    assert consumption.metadata_before == _mcb()
    assert consumption.metadata_after == _mcb(size=0x40)
    assert consumption.frame_bytes == 6
    call_block = next(b for b in raw.blocks if b.addr == MODULE_BASE)
    assert real16_invocation_discharges_8616(
        premise, project=project, block=call_block,
        callsite_addr=RESIZE_CALL_ADDR, target_addr=MODULE_BASE + 17,
    )
    serialized = premise.to_dict()
    assert serialized["service_consumptions"][0]["kind"] == "resize"
    assert serialized["service_consumptions"][0]["metadata_after_hex"] == _mcb(size=0x40).hex()


def test_resize_admits_any_proven_al() -> None:
    """AH=4A declares no AL selector — a proven nonzero AL still crosses."""
    caller = bytes.fromhex("b80001 8ec0 b8ff4a bb4000 cd21 e80100 c3")
    env = _environment()
    boot = _boot(caller, env)
    project, _, coverage = _world(boot, len(caller))
    relation = _resize_relation(env, MODULE_BASE + 11)
    premise = _resize_premise(
        project, coverage, MODULE_BASE + 13, boot, (relation,)
    )
    assert premise.complete
    consumption = premise.service_consumptions[0]
    assert type(consumption) is DeclaredResizeConsumption8616
    assert consumption.request_ax == 0x4AFF


def test_resize_adapter_refuses_missing_policy() -> None:
    """An environment without a resize policy is incomplete, never default."""
    env = _environment(resize=None)
    verdict = declared_int21_resize_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=RESIZE_INT_ADDR
    )
    assert verdict is DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE


def test_resize_env_without_policy_refuses_consumption() -> None:
    """A relation minted under a resize env cannot bind a policy-free boot."""
    minted_env = _environment()
    bare_env = _environment(resize=None)
    boot = _boot(env=bare_env)
    project, _, coverage = _world(boot, len(CALLER_RESIZE))
    relation = _resize_relation(minted_env, RESIZE_INT_ADDR)
    premise = _resize_premise(project, coverage, RESIZE_CALL_ADDR, boot, (relation,))
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN


def test_resize_env_without_relation_refuses() -> None:
    """A declared resize environment alone is not service evidence."""
    boot = _boot()
    project, _, coverage = _world(boot, len(CALLER_RESIZE))
    premise = _resize_premise(project, coverage, RESIZE_CALL_ADDR, boot)
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN


def test_resize_relation_altered_metadata_refuses() -> None:
    """A forged declared MCB surface fails the re-derived expectation."""
    env = _environment()
    boot = _boot(env=env)
    project, _, coverage = _world(boot, len(CALLER_RESIZE))
    relation = _resize_relation(env, RESIZE_INT_ADDR)
    assert relation.resize is not None
    forged = replace(
        relation,
        resize=replace(relation.resize, metadata=_mcb(size=0x40)),
    )
    premise = _resize_premise(project, coverage, RESIZE_CALL_ADDR, boot, (forged,))
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN


def test_resize_relation_altered_effect_fields_refuse() -> None:
    """Forged preserved-lane or capacity fields cannot keep authority."""
    env = _environment()
    boot = _boot(env=env)
    project, _, coverage = _world(boot, len(CALLER_RESIZE))
    relation = _resize_relation(env, RESIZE_INT_ADDR)
    assert relation.resize is not None
    forged_lanes = replace(relation, preserved=VERSION_PRESERVED_LANES_8616)
    premise = _resize_premise(
        project, coverage, RESIZE_CALL_ADDR, boot, (forged_lanes,)
    )
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    forged_capacity = replace(
        relation, resize=replace(relation.resize, maximum=0x100)
    )
    premise = _resize_premise(
        project, coverage, RESIZE_CALL_ADDR, boot, (forged_capacity,)
    )
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN


def test_resize_adapter_refuses_changed_ivt_bytes() -> None:
    """Declared IVT bytes that differ from dos_entry refuse at the adapter."""
    bad_ivt = bytearray(_ivt_bytes())
    bad_ivt[0x84] ^= 0xFF
    env = _environment(ivt=bytes(bad_ivt))
    verdict = declared_int21_resize_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=RESIZE_INT_ADDR
    )
    assert verdict is DeclaredInterruptRefusal8616.IVT_MISMATCH


def test_resize_relation_for_foreign_callsite_refuses() -> None:
    """A relation bound to a different callsite cannot cross this one."""
    env = _environment()
    boot = _boot(env=env)
    project, _, coverage = _world(boot, len(CALLER_RESIZE))
    foreign = declared_int21_resize_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=RESIZE_INT_ADDR + 0x10
    )
    assert isinstance(foreign, DeclaredInterruptService8616)
    premise = _resize_premise(
        project, coverage, RESIZE_CALL_ADDR, boot, (foreign,)
    )
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN


def test_resize_frame_aliasing_metadata_refuses() -> None:
    """An INT frame landing on the declared MCB revokes the crossing."""
    # mov ax,0x100 ; mov es,ax ; mov ax,0xFF ; mov ss,ax ; mov sp,0x10 puts
    # the 6-byte frame at 0x0FFA..0x1000 — directly on MCB bytes 10..16.
    caller = bytes.fromhex(
        "b80001 8ec0 b8ff00 8ed0 bc1000 b8004a bb4000 cd21 e80100 c3"
    )
    env = _environment()
    boot = _boot(caller, env)
    project, _, coverage = _world(boot, len(caller))
    int_addr = MODULE_BASE + 19
    call_addr = MODULE_BASE + 21
    relation = _resize_relation(env, int_addr)
    premise = _resize_premise(project, coverage, call_addr, boot, (relation,))
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN


def test_resize_other_block_refuses() -> None:
    """Proven ES naming a different block is a typed refusal, not a result."""
    caller = bytes.fromhex("b80002 8ec0 b8004a bb4000 cd21 e80100 c3")
    env = _environment()
    boot = _boot(caller, env)
    project, _, coverage = _world(boot, len(caller))
    relation = _resize_relation(env, MODULE_BASE + 11)
    premise = _resize_premise(
        project, coverage, MODULE_BASE + 13, boot, (relation,)
    )
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN


def test_resize_chain_marker_refuses() -> None:
    """A proven 'M' write to the MCB makes the chain undeclared — refuse."""
    # mov ax,0xFF ; mov ds,ax ; mov byte[ds:0],0x4D ; then resize block.
    caller = bytes.fromhex(
        "b8ff00 8ed8 c6060000 4d"
        " b80001 8ec0 b8004a bb4000 cd21 e80100 c3"
    )
    env = _environment()
    boot = _boot(caller, env)
    project, _, coverage = _world(boot, len(caller))
    int_addr = MODULE_BASE + 21
    call_addr = MODULE_BASE + 23
    relation = _resize_relation(env, int_addr)
    premise = _resize_premise(project, coverage, call_addr, boot, (relation,))
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN


@pytest.mark.parametrize("undeclared", [False, True])
def test_resize_unknown_predecessor_store_refuses(undeclared: bool) -> None:
    """An unproven-byte store into the MCB leaves metadata incomplete."""
    # DS:0100 lies in declared allocation. FS:0500 is genuinely undeclared.
    # mov ax,0xFF ; mov ds,ax ; load AL ;
    # mov [0x0000],al ; then the resize block.
    caller = bytes.fromhex(
        "b8ff00 8ed8 " + ("64a00005" if undeclared else "a00001") + " 88060000"
        " b80001 8ec0 b8004a bb4000 cd21 e80100 c3"
    )
    env = _environment()
    boot = _boot(caller, env)
    project, _, coverage = _world(boot, len(caller))
    int_addr = MODULE_BASE + 23 + int(undeclared)
    call_addr = MODULE_BASE + 25 + int(undeclared)
    relation = _resize_relation(env, int_addr)
    premise = _resize_premise(project, coverage, call_addr, boot, (relation,))
    if undeclared:
        assert not premise.complete
        assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    else:
        assert premise.complete
        assert len(premise.service_consumptions) == 1
        assert premise.service_consumptions[0].carry is True


def test_resize_predecessor_store_changes_current_metadata() -> None:
    """A proven size-field store is the current MCB the crossing reads."""
    # mov ax,0xFF ; mov ds,ax ; mov word[ds:3],0x30 ; then resize to 0x40.
    caller = bytes.fromhex(
        "b8ff00 8ed8 c7060300 3000"
        " b80001 8ec0 b8004a bb4000 cd21 e80100 c3"
    )
    env = _environment()
    boot = _boot(caller, env)
    project, _, coverage = _world(boot, len(caller))
    int_addr = MODULE_BASE + 22
    call_addr = MODULE_BASE + 24
    relation = _resize_relation(env, int_addr)
    premise = _resize_premise(project, coverage, call_addr, boot, (relation,))
    assert premise.complete
    consumption = premise.service_consumptions[0]
    assert type(consumption) is DeclaredResizeConsumption8616
    assert consumption.metadata_before == _mcb(size=0x30)
    assert consumption.metadata_after == _mcb(size=0x40)


def test_repeated_resize_consumes_latest_metadata() -> None:
    """A second AH=4A reads the first response's metadata, not initial."""
    # resize to 0x40 ; mov bx,0x20 ; re-prove ax ; resize again ; call ; ret.
    caller = bytes.fromhex(
        "b80001 8ec0 bb4000 b8004a cd21"
        " bb2000 b8004a cd21 e80100 c3"
    )
    env = _environment()
    boot = _boot(caller, env)
    project, _, coverage = _world(boot, len(caller))
    site1 = MODULE_BASE + 11
    site2 = MODULE_BASE + 19
    call_addr = MODULE_BASE + 21
    relations = (
        _resize_relation(env, site1),
        _resize_relation(env, site2),
    )
    premise = _resize_premise(project, coverage, call_addr, boot, relations)
    assert premise.complete
    assert len(premise.service_consumptions) == 2
    first, second = premise.service_consumptions
    assert type(first) is DeclaredResizeConsumption8616
    assert type(second) is DeclaredResizeConsumption8616
    assert first.metadata_before == _mcb()
    assert first.metadata_after == _mcb(size=0x40)
    # The second crossing reads the first response's MCB bytes.
    assert second.metadata_before == first.metadata_after
    assert second.metadata_after == _mcb(size=0x20)
    assert second.answer_bx == 0x20


def test_mixed_version_and_resize_relations_cross() -> None:
    """Both declared kinds coexist under one environment digest."""
    # mov ax,0x3000 ; int 21h ; then the resize block.
    caller = bytes.fromhex(
        "b80030 cd21 b80001 8ec0 b8004a bb4000 cd21 e80100 c3"
    )
    env = _environment()
    boot = _boot(caller, env)
    project, _, coverage = _world(boot, len(caller))
    version_site = MODULE_BASE + 3
    resize_site = MODULE_BASE + 16
    call_addr = MODULE_BASE + 18
    version_relation = declared_int21_version_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=version_site
    )
    assert isinstance(version_relation, DeclaredInterruptService8616)
    relations = (version_relation, _resize_relation(env, resize_site))
    premise = _resize_premise(project, coverage, call_addr, boot, relations)
    assert premise.complete
    assert len(premise.service_consumptions) == 2
    first, second = premise.service_consumptions
    assert type(first) is DeclaredServiceConsumption8616
    assert first.function == 0x30
    assert type(second) is DeclaredResizeConsumption8616
    assert second.function == 0x4A


def test_version_relation_still_consumes_under_shared_digest() -> None:
    """A version-only environment keeps the version control intact."""
    caller = bytes.fromhex("b80030 cd21 e80100 c3")
    env = _environment(resize=None)
    boot = _boot(caller, env)
    project, _, coverage = _world(boot, len(caller))
    int_addr = MODULE_BASE + 3
    call_addr = MODULE_BASE + 5
    relation = declared_int21_version_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=int_addr
    )
    assert isinstance(relation, DeclaredInterruptService8616)
    premise = _resize_premise(project, coverage, call_addr, boot, (relation,))
    assert premise.complete
    consumption = premise.service_consumptions[0]
    assert type(consumption) is DeclaredServiceConsumption8616
    assert consumption.function == 0x30
    assert consumption.answer_ax == 0x0005
    serialized = premise.to_dict()
    assert serialized["service_consumptions"][0]["kind"] == "version"


def test_static_mz_resize_still_refuses() -> None:
    """The naked static MZ (no declared environment) keeps the refusal."""
    boot = mz_static_boot_8616(_mz(_image(CALLER_RESIZE)), LOAD_SEGMENT)
    env = _environment()
    project, _, coverage = _world(_boot(env=env), len(CALLER_RESIZE))
    premise = prove_real16_invocation_domain_8616(
        project,
        coverage,
        RESIZE_CALL_ADDR,
        boot=boot,
        boot_recompute=recompute_mz_static_boot_8616,
    )
    assert not premise.complete
    # Proven AX reaches relation binding; an absent relation is the same
    # typed boundary verdict the declared-env no-relation control keeps.
    assert premise.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN


def test_shared_resize_contract_imports_lightweight(tmp_path: Path) -> None:
    """The shared resize owner and dosunit module import without angr/X86_16."""
    code = (
        "import sys;"
        "import tools.dosunit.real16_program_resize as resize;"
        "import angr_platforms.real16_resize_response8616 as shared;"
        "assert resize.resize_response_8616 is shared.resize_response_8616;"
        "assert 'angr' not in sys.modules;"
        "assert not any("
        "m == 'angr_platforms.X86_16' or m.startswith('angr_platforms.X86_16.')"
        " for m in sys.modules);"
        "mcb = (b'Z' + (0x192).to_bytes(2, 'little')"
        " + (0x9F00).to_bytes(2, 'little') + b'\\0\\0' + b'\\xb2KV1KPR0G');"
        "policy = resize.TailResizePolicy(0x100, mcb);"
        "result = resize.program_resize_call("
        "policy, segment=0x100, paragraphs=0x40, ax=0x4A00, metadata=mcb);"
        "assert not isinstance(result, resize.ResizeRefused);"
        "assert (result.ax, result.bx, result.carry) == (0x4A00, 0x40, False);"
        "assert result.metadata[3:5] == (0x40).to_bytes(2, 'little')"
    )
    pkgroot = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        (str(pkgroot), str(pkgroot / "angr_platforms"))
    )
    env["PYTHON_JIT"] = "1"
    subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
