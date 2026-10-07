"""Controls for the declared interrupt-service census boundary.

Fixture: one genuine MZ whose entry surface runs ``mov ah,0x30; int 21h``
then a direct near call — the exact CD21-shaped boundary the census must
cross only under an explicitly declared, environment-bound service relation.
Every negative keeps refusal typed; the positive retains the consumed
relation on the domain and replays it.
"""

import io
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import cast

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.function_ir_registry import (
    publish_function_ir_artifact_8616,
)
from inertia.ir.ir_boundary_cfg import (
    prove_ir_boundary_coverage_8616,
)
from inertia.ir.real16_declared_interrupt8616 import (
    DeclaredInterruptRefusal8616,
    DeclaredInterruptService8616,
)
from inertia.ir.real16_invocation_domain import (
    Real16InvocationAssumption8616,
    Real16InvocationDomain8616,
    Real16InvocationFailure8616,
    prove_real16_invocation_domain_8616,
    real16_invocation_discharges_8616,
)
from inertia.ir.vex_import import build_x86_16_ir_function_artifact

from inertia.frontend.x86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
)
from inertia.frontend.x86_16.mz_static_boot import (
    mz_static_boot_8616,
    recompute_mz_static_boot_8616,
)
from tools.dosunit.runtime.real16_declared_invocation8616 import (
    declared_int21_version_service_8616,
)
from tools.dosunit.runtime.real16_program_boot import (
    ProgramBoot,
    ProgramEnvironment,
    program_from_mz_bytes,
)
from tools.dosunit.runtime.real16_program_memory import InitialMemoryRegion
from tools.dosunit.runtime.real16_program_vectors import VectorPolicy, vector_bytes
from tools.dosunit.runtime.real16_program_version import VersionPolicy
from tools.dosunit.runtime.real16_replay_model import LinearRange, SegOffset

PSP_SEGMENT = 0x1F0
LOAD_SEGMENT = PSP_SEGMENT + 0x10
MODULE_BASE = LOAD_SEGMENT << 4  # 0x2000

# mov ah,0x30 ; int 21h ; call +1 -> 0x2008 ; ret
CALLER_CODE = bytes.fromhex("b430 cd21 e80100 c3")
INT_ADDR = MODULE_BASE + 2
CALL_ADDR = MODULE_BASE + 4
CALLEE_ADDR = MODULE_BASE + 8
CALLEE_CODE = bytes.fromhex("c3")
DOS_ENTRY = SegOffset(0xF000, 0xF100)


def _ivt_bytes() -> bytes:
    """One fully declared 1024-byte IVT with slot 0x21 bound to DOS_ENTRY."""
    table = bytearray(0x400)
    table[0x84:0x88] = vector_bytes(DOS_ENTRY)
    return bytes(table)


_UNSET: object = object()


def _environment(
    *,
    eax: int = 0,
    version: object = _UNSET,
    vector: object = _UNSET,
    ivt: bytes | None = None,
) -> ProgramEnvironment:
    return ProgramEnvironment(
        psp_segment=PSP_SEGMENT,
        allocation=bytes(0x410),
        registers=tuple(
            (name, eax if name == "eax" else 0)
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
        vector_policy=(
            VectorPolicy(DOS_ENTRY)
            if vector is _UNSET
            else cast(VectorPolicy | None, vector)
        ),
        extra_memory=(
            InitialMemoryRegion(SegOffset(0, 0), _ivt_bytes() if ivt is None else ivt),
        ),
    )


def _mz(image: bytes) -> bytes:
    header_size = 2 * 16
    exe_size = header_size + len(image)
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = (exe_size % 512).to_bytes(2, "little")
    header[0x04:0x06] = ((exe_size + 511) // 512).to_bytes(2, "little")
    header[0x06:0x08] = (1).to_bytes(2, "little")
    header[0x08:0x0A] = (2).to_bytes(2, "little")
    header[0x0A:0x0C] = (0x10).to_bytes(2, "little")
    header[0x0C:0x0E] = (0x40).to_bytes(2, "little")
    header[0x0E:0x10] = (0x20).to_bytes(2, "little")  # ss = load+0x20
    header[0x10:0x12] = (0x100).to_bytes(2, "little")  # sp
    header[0x14:0x16] = (0).to_bytes(2, "little")  # ip
    header[0x16:0x18] = (0).to_bytes(2, "little")  # cs
    header[0x18:0x1A] = (0x1C).to_bytes(2, "little")
    header[0x1C:0x1E] = (0x20).to_bytes(2, "little")
    header[0x1E:0x20] = (0).to_bytes(2, "little")
    return bytes(header) + image


def _image_bytes() -> bytes:
    image = CALLER_CODE + CALLEE_CODE
    # Pad past the header's relocation target at image offset 0x20.
    return image + bytes(0x22 - len(image))


def _boot(env: ProgramEnvironment | None = None) -> ProgramBoot:
    ranges = (
        LinearRange(MODULE_BASE, len(CALLER_CODE)),
        LinearRange(CALLEE_ADDR, len(CALLEE_CODE)),
    )
    return program_from_mz_bytes(
        _mz(_image_bytes()), _environment() if env is None else env,
        code_ranges=ranges,
    )


def _recompute(boot: object) -> object:
    typed = cast(ProgramBoot, boot)
    return program_from_mz_bytes(
        typed.source, typed.environment, code_ranges=typed.image.code_ranges
    )


def _world(boot: ProgramBoot) -> tuple:
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
        project, MODULE_BASE, MODULE_BASE + len(CALLER_CODE)
    )
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, raw)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    assert coverage.complete
    return project, boundary, raw, coverage


def _premise(
    project: object,
    coverage: object,
    boot: object,
    services: tuple = (),
    boot_recompute: object = _recompute,
) -> Real16InvocationDomain8616:
    return prove_real16_invocation_domain_8616(
        project,
        coverage,
        CALL_ADDR,
        boot=boot,
        boot_recompute=boot_recompute,
        declared_services=services,
    )


def test_declared_int21_crosses_boundary_and_stays_visible() -> None:
    """Declared env + authenticated relation crosses CD21 and replays."""
    env = _environment()
    boot = _boot(env)
    project, _, raw, coverage = _world(boot)
    relation = declared_int21_version_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR
    )
    assert isinstance(relation, DeclaredInterruptService8616)
    premise = _premise(project, coverage, boot, (relation,))
    assert premise.complete
    assert Real16InvocationAssumption8616.DECLARED_INTERRUPT_SERVICE in (
        premise.assumptions
    )
    assert len(premise.service_consumptions) == 1
    consumption = premise.service_consumptions[0]
    assert consumption.callsite_addr == INT_ADDR
    assert consumption.vector == 0x21
    assert consumption.function == 0x30
    assert consumption.selector == 0
    assert consumption.answer_ax == 0x0005
    call_block = next(b for b in raw.blocks if b.addr == MODULE_BASE)
    assert real16_invocation_discharges_8616(
        premise, project=project, block=call_block,
        callsite_addr=CALL_ADDR, target_addr=CALLEE_ADDR,
    )


def test_static_mz_same_opcode_still_refuses() -> None:
    """The naked static MZ (no environment) keeps the typed refusal."""
    boot = mz_static_boot_8616(_mz(_image_bytes()), LOAD_SEGMENT)
    project, _, _, coverage = _world(_boot())
    premise = prove_real16_invocation_domain_8616(
        project,
        coverage,
        CALL_ADDR,
        boot=boot,
        boot_recompute=recompute_mz_static_boot_8616,
    )
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN


def test_declared_env_without_relation_refuses() -> None:
    """A declared environment alone is not service evidence."""
    boot = _boot()
    project, _, _, coverage = _world(boot)
    premise = _premise(project, coverage, boot)
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN


def test_declared_al_nonzero_refuses() -> None:
    """A declared AL=01 selector does not admit the AL=00 contract."""
    env = _environment(eax=1)
    boot = _boot(env)
    project, _, _, coverage = _world(boot)
    relation = declared_int21_version_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR
    )
    assert isinstance(relation, DeclaredInterruptService8616)
    premise = _premise(project, coverage, boot, (relation,))
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN


def test_replaced_policy_relation_refuses() -> None:
    """A relation minted under a different declared response refuses."""
    env = _environment()
    other = _environment(version=VersionPolicy(major=6, minor=0, oem=0, serial=0))
    boot = _boot(env)
    project, _, _, coverage = _world(boot)
    foreign = declared_int21_version_service_8616(
        other, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR
    )
    assert isinstance(foreign, DeclaredInterruptService8616)
    premise = _premise(project, coverage, boot, (foreign,))
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN


def test_malformed_relation_refuses() -> None:
    """A hand-built relation with incoherent IVT evidence refuses."""
    env = _environment()
    boot = _boot(env)
    project, _, _, coverage = _world(boot)
    relation = declared_int21_version_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR
    )
    assert isinstance(relation, DeclaredInterruptService8616)
    forged = replace(relation, ivt_slot_bytes=b"\x00\x00\x00\x00")
    premise = _premise(project, coverage, boot, (forged,))
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN


def test_relation_for_foreign_callsite_refuses() -> None:
    """A relation bound to a different callsite cannot cross this one."""
    env = _environment()
    boot = _boot(env)
    project, _, _, coverage = _world(boot)
    foreign = declared_int21_version_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR + 0x10
    )
    assert isinstance(foreign, DeclaredInterruptService8616)
    premise = _premise(project, coverage, boot, (foreign,))
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN


def test_adapter_refuses_changed_ivt_bytes() -> None:
    """Declared IVT bytes that differ from dos_entry refuse at the adapter."""
    bad_ivt = bytearray(_ivt_bytes())
    bad_ivt[0x84] ^= 0xFF
    env = _environment(ivt=bytes(bad_ivt))
    verdict = declared_int21_version_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR
    )
    assert verdict is DeclaredInterruptRefusal8616.IVT_MISMATCH


def test_adapter_refuses_program_owned_dos_entry() -> None:
    """A DOS vector pointing inside the declared arena refuses."""
    owned = SegOffset(PSP_SEGMENT, 0)
    ivt = bytearray(_ivt_bytes())
    ivt[0x84:0x88] = vector_bytes(owned)
    env = _environment(vector=VectorPolicy(owned), ivt=bytes(ivt))
    verdict = declared_int21_version_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR
    )
    assert verdict is DeclaredInterruptRefusal8616.OWNED_HANDLER


def test_adapter_refuses_incomplete_environment() -> None:
    """Missing declared policies are incomplete, never defaulted."""
    env = _environment(vector=None)
    verdict = declared_int21_version_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR
    )
    assert verdict is DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE
    env2 = _environment(version=None)
    verdict2 = declared_int21_version_service_8616(
        env2, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR
    )
    assert verdict2 is DeclaredInterruptRefusal8616.ENVIRONMENT_INCOMPLETE


def test_retained_premise_refuses_under_stale_source() -> None:
    """Rebinding the retained boot to mutated source revokes completeness."""
    env = _environment()
    boot = _boot(env)
    project, _, _, coverage = _world(boot)
    relation = declared_int21_version_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR
    )
    assert isinstance(relation, DeclaredInterruptService8616)
    premise = _premise(project, coverage, boot, (relation,))
    assert premise.complete
    mutated = bytearray(_image_bytes())
    mutated[6] ^= 0xFF
    foreign = program_from_mz_bytes(
        _mz(bytes(mutated)), env, code_ranges=boot.image.code_ranges
    )
    rebound = replace(premise, boot=foreign)
    assert not rebound.complete


def _ivt_writer_image(*, store_value_known: bool) -> bytes:
    """Caller code that writes IVT slot 0x84 before the interrupt.

    ``xor ax,ax; mov es,ax`` puts a proven zero in ES, then a store into
    ``es:[0084]`` — known (bx, seeded 0) or unknown (a LOAD result) — and
    then the identical ``mov ah,0x30; int 21h; call; ret`` tail.
    """
    head = bytes.fromhex("31c0 8ec0")  # xor ax,ax ; mov es,ax
    if store_value_known:
        store = bytes.fromhex("26 891e8400")  # mov es:[0084],bx
    else:
        store = bytes.fromhex("26 a10000 26 a38400")  # ax=es:[0]; es:[0084]=ax
    tail = bytes.fromhex("b430 cd21 e80100 c3")
    return head + store + tail


def _ivt_writer_world() -> tuple:
    """Build boot/project/coverage for the IVT-writer image."""
    env = _environment()
    image = _ivt_writer_image(store_value_known=True)
    ranges = (
        LinearRange(MODULE_BASE, len(image)),
        LinearRange(CALLEE_ADDR, len(CALLEE_CODE)),
    )
    boot = program_from_mz_bytes(
        _mz(image + CALLEE_CODE + bytes(0x22 - len(image + CALLEE_CODE))),
        env,
        code_ranges=ranges,
    )
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
        project, MODULE_BASE, MODULE_BASE + len(image)
    )
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, raw)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    assert coverage.complete
    return env, boot, project, coverage


def test_store_to_live_ivt_slot_revokes_relation() -> None:
    """A proven store into the 0x21 slot before INT 21h refuses.

    Even a store whose written bytes happen to equal the declared initial
    slot revokes the dispatch evidence — initial layout is not live IVT.
    """
    env, boot, project, coverage = _ivt_writer_world()
    # The writer's CD21 sits after xor/mov-es/store: 4+5=9 bytes of head,
    # then mov ah (2) -> int 21h at +11; the near call is at +13.
    int_addr = MODULE_BASE + 11
    call_addr = MODULE_BASE + 13
    relation = declared_int21_version_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=int_addr
    )
    assert isinstance(relation, DeclaredInterruptService8616)
    premise = prove_real16_invocation_domain_8616(
        project, coverage, call_addr,
        boot=boot, boot_recompute=_recompute, declared_services=(relation,),
    )
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN


def test_unknown_value_store_to_ivt_slot_revokes_relation() -> None:
    """An unknown-value store into the slot likewise revokes the relation."""
    env = _environment()
    image = _ivt_writer_image(store_value_known=False)
    # 4-byte head + 8-byte load/store pair + mov ah (2) -> int at +14,
    # call at +16.
    int_addr = MODULE_BASE + 14
    call_addr = MODULE_BASE + 16
    ranges = (
        LinearRange(MODULE_BASE, len(image)),
        LinearRange(CALLEE_ADDR, len(CALLEE_CODE)),
    )
    boot = program_from_mz_bytes(
        _mz(image + CALLEE_CODE + bytes(0x22 - len(image + CALLEE_CODE))),
        env,
        code_ranges=ranges,
    )
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
        project, MODULE_BASE, MODULE_BASE + len(image)
    )
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, raw)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    assert coverage.complete
    relation = declared_int21_version_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=int_addr
    )
    assert isinstance(relation, DeclaredInterruptService8616)
    premise = prove_real16_invocation_domain_8616(
        project, coverage, call_addr,
        boot=boot, boot_recompute=_recompute, declared_services=(relation,),
    )
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN


def test_forged_effect_fields_cannot_keep_environment_authority() -> None:
    """dataclasses.replace on effect fields must not survive consumption.

    The census re-derives the canonical answer/preserved/IVT surface from
    the declared environment itself; a coherently forged relation field
    under an unchanged environment refuses.
    """
    env = _environment()
    boot = _boot(env)
    project, _, _, coverage = _world(boot)
    relation = declared_int21_version_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR
    )
    assert isinstance(relation, DeclaredInterruptService8616)
    for field, value in (
        ("answer_ax", 0x1234),
        ("answer_bx", 0x4321),
        ("answer_cx", 0xABCD),
        ("preserved", ("ss", "sp", "ds", "es", "flags")),
        ("ivt_entry_offset", relation.ivt_entry_offset + 0x10),
    ):
        forged = replace(relation, **{field: value})
        assert forged.environment_sha256 == relation.environment_sha256
        premise = _premise(project, coverage, boot, (forged,))
        assert not premise.complete, f"forged {field} retained authority"
        assert premise.failure in (
            Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN,
            Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN,
        )


def _frame_loader_world() -> tuple:
    """Boot/project/coverage for the residual-frame selector control.

    Native bytes: ``mov ah,0x30; int 21h`` (site 1, +2), then
    ``mov ax,ss:[0xfa]`` — a load of the word the architectural INT frame
    just wrote at SP-6 — ``mov ss,ax``, reprove AH/AL, and a second
    ``int 21h`` (site 2, +14) before the near call (+16) and ``ret``.
    """
    image = bytes.fromhex(
        "b430 cd21 36a1fa00 8ed0 b430 b000 cd21 e80100 c3"
    ) + CALLEE_CODE
    env = _environment()
    ranges = (
        LinearRange(MODULE_BASE, 20),
        LinearRange(MODULE_BASE + 20, len(CALLEE_CODE)),
    )
    boot = program_from_mz_bytes(
        _mz(image + bytes(0x22 - len(image))), env, code_ranges=ranges
    )
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
        project, MODULE_BASE, MODULE_BASE + 20
    )
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, raw)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    assert coverage.complete
    return env, boot, project, coverage


def test_residual_frame_load_cannot_supply_ss() -> None:
    """A value loaded from the INT frame must not mint a known SS.

    The six frame bytes join the store ledger but their *contents* are
    never modeled: ``_simulate_tmp_write_8616`` must keep a LOAD from
    ``ss:[0xfa]`` unknown, so ``mov ss,ax`` drops SS and site 2's frame
    cannot be proven — even though BOTH callsites carry minted relations
    and AH/AL re-prove cleanly. If a regression let the load reuse the
    (zeroed) initial allocation bytes, SS would become a bogus constant
    and the second interrupt could cross; this control refuses on
    ``DECLARED_SERVICE_UNPROVEN`` either way the frame value would leak.
    """
    env, boot, project, coverage = _frame_loader_world()
    site1 = MODULE_BASE + 2
    site2 = MODULE_BASE + 14
    call_addr = MODULE_BASE + 16
    relations = tuple(
        declared_int21_version_service_8616(
            env, caller_addr=MODULE_BASE, callsite_addr=site
        )
        for site in (site1, site2)
    )
    assert all(
        isinstance(relation, DeclaredInterruptService8616)
        for relation in relations
    )
    premise = prove_real16_invocation_domain_8616(
        project, coverage, call_addr,
        boot=boot, boot_recompute=_recompute, declared_services=relations,
    )
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN


def test_shared_response_contract_imports_lightweight(tmp_path: Path) -> None:
    """The shared contract and version policy import without angr/X86_16.

    Runs a clean interpreter against the repository package: importing
    ``tools.dosunit.runtime.real16_program_version`` must pull in the shared
    ``inertia.frontend.real16_version_response8616`` owner only — the
    platform package shim is stdlib-only, so neither angr nor the
    ``X86_16`` tree may appear in ``sys.modules``.
    """
    code = (
        "import sys;"
        "import tools.dosunit.runtime.real16_program_version as version;"
        "import inertia.frontend.real16_version_response8616 as shared;"
        "assert 'angr' not in sys.modules;"
        "assert not any("
        "m == 'inertia.frontend.x86_16.public_api' or m.startswith('inertia.frontend.x86_16.public_api.')"
        " for m in sys.modules);"
        "assert shared.version_response_words_8616(5, 0, 0, 0) == (5, 0, 0);"
        "answered = version.program_version_query("
        "version.VersionPolicy(major=5, minor=0, oem=0, serial=0),"
        " selector=version.VERSION_SELECTOR);"
        "assert (answered.ax, answered.bx, answered.cx) == (5, 0, 0)"
    )
    pkgroot = Path(__file__).resolve().parents[2]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(pkgroot)
    env["PYTHON_JIT"] = "1"
    subprocess.run(
        [sys.executable, "-c", code],
        check=True,
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )


def test_frame_write_joins_store_ledger() -> None:
    """The consumed INT frame is counted as one proven store."""
    env = _environment()
    boot = _boot(env)
    project, _, _, coverage = _world(boot)
    relation = declared_int21_version_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR
    )
    assert isinstance(relation, DeclaredInterruptService8616)
    premise = _premise(project, coverage, boot, (relation,))
    assert premise.complete
    # No program STOREs in CALLER_CODE; the frame's six bytes are the only
    # store-side evidence the census accounts.
    assert premise.checked_store_count >= 1
    consumption = premise.service_consumptions[0]
    assert consumption.frame_bytes == 6
    assert consumption.frame_linear > 0


def test_frame_overlapping_fetched_code_refuses() -> None:
    """A declared SP landing the INT frame on fetched bytes violates."""
    env = _environment()
    # stack_ss=0 puts the header stack inside the module; sp=0x0c lands the
    # 6-byte frame at 0x2006..0x200c — directly on fetched call bytes.
    ranges = (
        LinearRange(MODULE_BASE, len(CALLER_CODE)),
        LinearRange(CALLEE_ADDR, len(CALLEE_CODE)),
    )
    source = bytearray(_mz(_image_bytes()))
    source[0x0E:0x10] = (0x0).to_bytes(2, "little")  # ss = load+0
    source[0x10:0x12] = (0x0C).to_bytes(2, "little")  # sp
    boot = program_from_mz_bytes(
        bytes(source), env, code_ranges=ranges
    )
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
        project, MODULE_BASE, MODULE_BASE + len(CALLER_CODE)
    )
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, raw)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    assert coverage.complete
    relation = declared_int21_version_service_8616(
        env, caller_addr=MODULE_BASE, callsite_addr=INT_ADDR
    )
    assert isinstance(relation, DeclaredInterruptService8616)
    premise = _premise(project, coverage, boot, (relation,))
    assert not premise.complete
    assert premise.failure in (
        Real16InvocationFailure8616.CODE_WRITE_VIOLATION,
        Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN,
    )
