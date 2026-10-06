"""Native-encoded boundary regressions for production real16 admission.

Layer: tests (production invocation-domain evidence).
Responsibility: pin the reviewed invocation primitive's boundary
obligations with authentic machine encodings only — register-lane
invalidation and recomposition, must-meet predecessor joins, the ``0x67``
address-size-32 store refusal against the genuine 16-bit direct store,
immutable retained source/header/environment binding, and the census work
bound. Every refusal asserts its typed failure at the owning layer and a
closed five-stage ledger (``classified == materialized + failure``);
positives use real lifted bytes only — never injected IR rows.

Encoding notes (verified against the native lifter, not copied from the
exploratory probe): ``89 05`` is ``mov [di], ax`` — mod=00, r/m=101
selects the DI register-indirect form; the trailing ``34 12`` is
``xor al, 0x12``, not a displacement. The genuine 16-bit direct-store
encoding is ``89 06 <disp16>`` (r/m=110). ``67 89 05 <disp32>`` is a real
32-bit direct store under the address-size prefix and must refuse rather
than be truncated into the 16-bit domain.
"""

import io
from collections.abc import Callable
from dataclasses import fields, replace
from types import SimpleNamespace
from typing import cast

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.frontend_function_boundary import exact_function_range_boundary_8616
from angr_platforms.X86_16.ir import real16_invocation_domain as dom
from angr_platforms.X86_16.ir.core import (
    IRBinaryValue,
    IRBlock,
    IRInstr,
    IRValue,
    MemSpace,
)
from angr_platforms.X86_16.ir.function_ir_registry import publish_function_ir_artifact_8616
from angr_platforms.X86_16.ir.ir_boundary_cfg import (
    prove_ir_boundary_coverage_8616,
)
from angr_platforms.X86_16.ir.real16_invocation_domain import (
    Real16InvocationDomain8616,
    Real16InvocationFailure8616,
    prove_real16_invocation_domain_8616,
    real16_invocation_discharges_8616,
)
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact

from tools.dosunit.real16_program_boot import (
    ProgramBoot,
    ProgramEnvironment,
    program_from_mz_bytes,
)
from tools.dosunit.real16_replay_model import LinearRange, SegOffset

LOAD_SEGMENT = 0x100
PSP_SEGMENT = LOAD_SEGMENT - 0x10
CALLER_CODE = bytes.fromhex("e81000 89c3 36 8b0f c3")
CALLEE_CODE = bytes.fromhex("c3")
STUB_CODE = bytes.fromhex("161f e8cbff c3")


def _build_image(stub: bytes = STUB_CODE) -> bytes:
    image = CALLER_CODE + bytes(0x13 - len(CALLER_CODE)) + CALLEE_CODE
    return image + bytes(0x30 - len(image)) + stub


def _build_mz(image: bytes, *, stack_ss: int, stack_sp: int) -> bytes:
    header = bytearray(32)
    exe_size = 32 + len(image)
    header[0:2] = b"MZ"
    header[0x02:0x04] = (exe_size % 512).to_bytes(2, "little")
    header[0x04:0x06] = ((exe_size + 511) // 512).to_bytes(2, "little")
    header[0x06:0x08] = (1).to_bytes(2, "little")
    header[0x08:0x0A] = (2).to_bytes(2, "little")
    header[0x0A:0x0C] = (0x10).to_bytes(2, "little")
    header[0x0C:0x0E] = (0x20).to_bytes(2, "little")
    header[0x0E:0x10] = stack_ss.to_bytes(2, "little")
    header[0x10:0x12] = stack_sp.to_bytes(2, "little")
    header[0x14:0x16] = (0x30).to_bytes(2, "little")  # entry_ip -> stub head
    header[0x16:0x18] = (0).to_bytes(2, "little")    # entry_cs
    header[0x18:0x1A] = (0x1C).to_bytes(2, "little")
    # The single reloc entry targets image padding (module offset 0x20),
    # never a fetched opcode byte.
    header[0x1C:0x1E] = (0x20).to_bytes(2, "little")
    header[0x1E:0x20] = (0).to_bytes(2, "little")
    return bytes(header) + image


def _environment(**registers: int) -> ProgramEnvironment:
    declared = {
        name: registers.get(name, 0)
        for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
                     "esp", "eflags")
    }
    return ProgramEnvironment(
        psp_segment=PSP_SEGMENT,
        allocation=bytes(0x300),
        registers=tuple(declared.items()),
        fs=0,
        gs=0,
    )


def _boot(code: bytes = STUB_CODE, env: ProgramEnvironment | None = None,
          *, stack_ss: int = 0x10, stack_sp: int = 0x100) -> ProgramBoot:
    return program_from_mz_bytes(
        _build_mz(_build_image(code), stack_ss=stack_ss, stack_sp=stack_sp),
        env if env is not None else _environment(),
        code_ranges=(LinearRange(0x1030, len(code)),),
    )


def _recompute(boot: object) -> object:
    """Replay the deterministic boot authority for one boot-shaped value."""
    typed = cast(ProgramBoot, boot)
    return program_from_mz_bytes(
        typed.source, typed.environment, code_ranges=typed.image.code_ranges
    )


def _stub_world(
    boot: ProgramBoot,
    code: bytes,
    mutate: Callable[[IRBlock], IRBlock] | None = None,
) -> tuple:
    """Build project/artifact/coverage for one stub byte string.

    ``mutate`` runs on each imported block before the single publish: the
    registry binds first-wins, so a mutation applied after publishing can
    never reach the proof.
    """
    project = angr.Project(
        io.BytesIO(boot.image.chunks[0][1]),
        main_opts={"backend": "blob", "arch": Arch86_16(),
                   "base_addr": 0x1000, "entry_point": 0x1000},
        auto_load_libs=False,
    )
    boundary = exact_function_range_boundary_8616(
        project, 0x1030, 0x1030 + len(code)
    )
    assert boundary is not None
    raw = build_x86_16_ir_function_artifact(project, boundary)
    if mutate is not None:
        raw = replace(raw, blocks=tuple(mutate(b) for b in raw.blocks))
    publish_function_ir_artifact_8616(project, raw)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    return project, raw, coverage


def _prove_stub(
    boot: ProgramBoot,
    code: bytes,
    callsite: int,
    *,
    mutate: Callable[[IRBlock], IRBlock] | None = None,
    boot_override: object | None = None,
    boot_recompute: Callable[[object], object] | None = _recompute,
) -> tuple:
    """Prove the stub premise; return (premise, project, raw)."""
    project, raw, coverage = _stub_world(boot, code, mutate)
    premise = prove_real16_invocation_domain_8616(
        project,
        coverage,
        callsite,
        boot=boot if boot_override is None else boot_override,
        boot_recompute=boot_recompute,
    )
    return premise, project, raw


def _assert_ledger_closed(premise: Real16InvocationDomain8616) -> None:
    """The five-stage ledger: classified == materialized + failure."""
    assert premise.classified_fact_count == (
        premise.materialized_count + premise.failure_count
    )
    assert premise.raw_fact_count >= premise.normalized_fact_count
    assert premise.normalized_fact_count >= premise.classified_fact_count


def _assert_row_refusal(
    premise: Real16InvocationDomain8616,
    failure: Real16InvocationFailure8616,
    *,
    simulated: bool = True,
) -> None:
    """A refusal at row stage: rows were classified, exactly some refused.

    ``simulated`` asserts at least one earlier row materialized — proof
    the census reached the simulation layer before this row refused, not
    an earlier gate.
    """
    assert not premise.complete
    assert premise.failure is failure
    assert premise.failure_count >= 1
    assert premise.materialized_count < premise.classified_fact_count
    if simulated:
        assert premise.materialized_count > 0
    _assert_ledger_closed(premise)


def _assert_proven(premise: Real16InvocationDomain8616) -> None:
    """A complete premise: all classified rows materialized, none refused."""
    assert premise.complete
    assert premise.failure is None
    assert premise.failure_count == 0
    assert premise.materialized_count == premise.classified_fact_count > 0
    _assert_ledger_closed(premise)


def _assert_boot_refusal(
    premise: Real16InvocationDomain8616,
    failure: Real16InvocationFailure8616,
    recompute_calls: list[object],
) -> None:
    """A pre-census boot-evidence refusal: the recompute callback idles.

    The typed failure owns the report and zero rows entered the census —
    proving the refusal came from boot evidence, not a later layer.
    """
    assert not premise.complete
    assert premise.failure is failure
    assert not recompute_calls
    assert premise.classified_fact_count == 0
    _assert_ledger_closed(premise)


def _forged_boot(boot: ProgramBoot, **substitutions: object) -> object:
    """Clone boot fields into a structurally identical foreign surface."""
    data = {member.name: getattr(boot, member.name) for member in fields(boot)}
    data.update(substitutions)
    return SimpleNamespace(**data)


def _recording_recompute(calls: list[object]) -> Callable[[object], object]:
    """A recompute authority that records whether it was ever invoked."""
    def replay(boot: object) -> object:
        calls.append(boot)
        return _recompute(boot)
    return replay


def test_register_lanes_recompose_wide_base_for_store() -> None:
    """``mov bl,0x20; mov bh,0x11; mov [bx],ax`` recomposes bx=0x1120.

    Each byte lane write keeps its own lane and invalidates the
    overlapping parent view; the store's base read tiles ``bx`` back from
    the two proven sibling lanes. ds:0x1120 -> 0x2020 is disjoint from
    every fetched byte, so the whole premise proves.
    """
    code = bytes.fromhex("b3 20 b7 11 89 07 e8 0000 c3")
    boot = _boot(code)
    premise, project, raw = _prove_stub(boot, code, 0x1036)
    _assert_proven(premise)
    call_block = next(
        b for b in raw.blocks if any(i.addr == 0x1036 for i in b.instrs)
    )
    assert real16_invocation_discharges_8616(
        premise, project=project, block=call_block,
        callsite_addr=0x1036, target_addr=0x1039,
    )


def test_low_lane_load_revokes_wide_base_for_store() -> None:
    """``mov bx,0x1120; mov bl,[bx]; mov [bx],ax`` must not reuse stale bx.

    The byte load into ``bl`` invalidates every overlapping view — the
    earlier ``bx`` constant cannot survive a partial write. The store's
    base then evaluates to unknown and refuses at the store-address
    layer, not as a guessed constant.
    """
    code = bytes.fromhex("bb 20 11 8a 1f 89 07 e8 0000 c3")
    boot = _boot(code)
    premise, _, _ = _prove_stub(boot, code, 0x1037)
    _assert_row_refusal(
        premise, Real16InvocationFailure8616.STORE_ADDRESS_UNPROVEN
    )


def test_load_into_sp_revokes_callsite_push_store() -> None:
    """``mov sp,[bx]`` leaves sp unknown; the CALL push store refuses.

    The callsite's own frame push is a censused STORE whose SS:SP-2
    address must evaluate exactly; a memory clobber of sp revokes the
    header-derived constant, so the store is unproven.
    """
    code = bytes.fromhex("8b 27 e8 0000 c3")
    boot = _boot(code)
    premise, _, _ = _prove_stub(boot, code, 0x1032)
    _assert_row_refusal(
        premise, Real16InvocationFailure8616.STORE_ADDRESS_UNPROVEN
    )


def test_disagreeing_predecessor_join_drops_register() -> None:
    """Must-meet join: ``bx=0x20`` vs ``bx=0x40`` predecessors drop bx.

    ``jne`` admits both arms (flags are unseeded); the join block's
    ``mov [bx],ax`` sees no proven bx and the store refuses. The refusal
    itself proves the must-meet ran over both predecessor exits: had only
    one arm's exit state reached the join, ``bx`` would still be a proven
    constant (0x20 or 0x40) and the disjoint store would have passed.
    """
    code = bytes.fromhex(
        "75 05 bb 2000 eb07 bb 4000 eb02 9090 89 07 e8 0000 c3"
    )
    boot = _boot(code)
    premise, _, _ = _prove_stub(boot, code, 0x1040)
    _assert_row_refusal(
        premise, Real16InvocationFailure8616.STORE_ADDRESS_UNPROVEN
    )


def test_agreeing_predecessor_join_keeps_register() -> None:
    """Must-meet join: identical ``bx=0x20`` predecessors keep bx.

    The store at ds:0x0020 -> 0xF20 is disjoint from every fetched byte;
    the premise proves and the whole path — both predecessor arms — is
    retained in the block census.
    """
    code = bytes.fromhex(
        "75 05 bb 2000 eb07 bb 2000 eb02 9090 89 07 e8 0000 c3"
    )
    boot = _boot(code)
    premise, project, raw = _prove_stub(boot, code, 0x1040)
    _assert_proven(premise)
    assert set(premise.path_block_addrs) == {0x1030, 0x1032, 0x1037, 0x103E}
    call_block = next(
        b for b in raw.blocks if any(i.addr == 0x1040 for i in b.instrs)
    )
    assert real16_invocation_discharges_8616(
        premise, project=project, block=call_block,
        callsite_addr=0x1040, target_addr=0x1043,
    )


def test_address_size32_store_refuses_effective_address_domain() -> None:
    """``67 89 05 <disp32>`` is a real 32-bit store; it must refuse.

    The fetched byte run begins with the ``0x67`` address-size override,
    so the truncated 16-bit IR offset cannot be trusted — the store
    census refuses ``store_address_unproven`` after earlier rows already
    materialized (the obligation reached the owning layer; decode and
    native binding both passed first).
    """
    code = bytes.fromhex("67 89 05 34 12 00 00 e8 0000 c3")
    boot = _boot(code)
    premise, _, _ = _prove_stub(boot, code, 0x1037)
    _assert_row_refusal(
        premise, Real16InvocationFailure8616.STORE_ADDRESS_UNPROVEN
    )


def test_genuine_disp16_direct_store_proves() -> None:
    """``89 06 34 12`` is ``mov [0x1234], ax`` — the real disp16 form.

    r/m=110 under mod=00 is the direct 16-bit absolute: ds:0x1234 ->
    0x2134, disjoint from every fetched byte, so the premise proves.
    """
    code = bytes.fromhex("89 06 34 12 e8 0000 c3")
    boot = _boot(code)
    premise, project, raw = _prove_stub(boot, code, 0x1034)
    _assert_proven(premise)
    call_block = next(
        b for b in raw.blocks if any(i.addr == 0x1034 for i in b.instrs)
    )
    assert real16_invocation_discharges_8616(
        premise, project=project, block=call_block,
        callsite_addr=0x1034, target_addr=0x1037,
    )


def test_rm101_store_binds_declared_di_not_displacement() -> None:
    """``89 05 34 12`` is ``mov [di], ax; xor al, 0x12`` — never disp16.

    The same bytes prove under the default declared ``edi=0`` (di=0 ->
    ds:0 -> 0xF00, disjoint) and refuse under a declared ``edi=0x130``
    (di=0x130 -> ds:0x130 -> 0x1030, the store's own fetched bytes ->
    ``code_write_violation``). Only a live register base can move with
    the declared environment — this pins both the correct r/m decode and
    the environment-to-seed binding at the store-span layer.
    """
    code = bytes.fromhex("89 05 34 12 e8 0000 c3")
    boot_lo = _boot(code, _environment())
    premise_lo, _, _ = _prove_stub(boot_lo, code, 0x1034)
    _assert_proven(premise_lo)
    boot_hi = _boot(code, _environment(edi=0x130))
    premise_hi, _, _ = _prove_stub(boot_hi, code, 0x1034)
    _assert_row_refusal(
        premise_hi, Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    )


def test_mutated_retained_source_refuses_before_recompute() -> None:
    """Image- and header-byte mutations of ``boot.source`` refuse early.

    The retained source is re-derived through the MZ authority before any
    caller callback runs: a flipped code byte (stale module), a flipped
    ``stack_sp`` header byte, and a flipped ``entry_ip`` header byte all
    diverge from the declared fields and refuse ``boot_not_reproduced``
    with the recompute authority never invoked.
    """
    boot = _boot()
    calls: list[object] = []
    recompute = _recording_recompute(calls)
    for offset in (0x20 + 0x05, 0x10, 0x14):
        mutated = bytearray(boot.source)
        mutated[offset] ^= 0xFF
        premise, _, _ = _prove_stub(
            boot, STUB_CODE, 0x1032,
            boot_override=_forged_boot(boot, source=bytes(mutated)),
            boot_recompute=recompute,
        )
        _assert_boot_refusal(
            premise, Real16InvocationFailure8616.BOOT_NOT_REPRODUCED, calls
        )


def test_forged_header_coordinates_refuse_before_recompute() -> None:
    """Declared entry/stack that diverge from the source refuse early."""
    boot = _boot()
    calls: list[object] = []
    recompute = _recording_recompute(calls)
    for field_name, forged in (
        ("entry", SegOffset(0x100, 0x31)),
        ("stack", SegOffset(0x110, 0x104)),
    ):
        premise, _, _ = _prove_stub(
            boot, STUB_CODE, 0x1032,
            boot_override=_forged_boot(boot, **{field_name: forged}),
            boot_recompute=recompute,
        )
        _assert_boot_refusal(
            premise, Real16InvocationFailure8616.BOOT_NOT_REPRODUCED, calls
        )


def test_malformed_environment_refuses_boot_malformed() -> None:
    """An untyped or out-of-domain environment surface refuses malformed.

    ``registers`` must be the exact tuple of typed pairs and
    ``psp_segment``/``fs``/``gs`` must be 16-bit words; both violations
    refuse ``boot_malformed`` before the recompute authority runs.
    """
    boot = _boot()
    calls: list[object] = []
    recompute = _recording_recompute(calls)
    environments = (
        SimpleNamespace(
            psp_segment=PSP_SEGMENT, registers="nope", fs=0, gs=0
        ),
        SimpleNamespace(
            psp_segment=0x1_0000,
            registers=boot.environment.registers, fs=0, gs=0,
        ),
    )
    for environment in environments:
        premise, _, _ = _prove_stub(
            boot, STUB_CODE, 0x1032,
            boot_override=_forged_boot(boot, environment=environment),
            boot_recompute=recompute,
        )
        _assert_boot_refusal(
            premise, Real16InvocationFailure8616.BOOT_MALFORMED, calls
        )


def test_census_work_bound_refuses_with_closed_ledger() -> None:
    """The shared census work bound refuses at every stage, ledger closed.

    A zero bound refuses before any row is classified (empty closed
    ledger). A mid-census bound — the first limit under which rows were
    classified but the census still exhausts — refuses
    ``census_work_exceeded`` with ``classified == materialized`` and
    ``raw >= normalized >= classified``. Restoring the bound reproves the
    authentic stub: no state survives the refusal.
    """
    boot = _boot()
    project, _, coverage = _stub_world(boot, STUB_CODE)

    def prove_with_limit(limit: int) -> Real16InvocationDomain8616:
        saved = dom._CENSUS_WORK_LIMIT_8616
        dom._CENSUS_WORK_LIMIT_8616 = limit
        try:
            return prove_real16_invocation_domain_8616(
                project, coverage, 0x1032,
                boot=boot, boot_recompute=_recompute,
            )
        finally:
            dom._CENSUS_WORK_LIMIT_8616 = saved

    pre = prove_with_limit(0)
    assert not pre.complete
    assert pre.failure is Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
    assert pre.classified_fact_count == 0
    assert pre.refusal_site is None
    _assert_ledger_closed(pre)

    # Classification advances monotonically with the work cap on this
    # authentic positive fixture. Find its first classified row with
    # logarithmic probes rather than hundreds of complete native re-lifts.
    lower = 0
    upper = dom._CENSUS_WORK_LIMIT_8616
    while upper - lower > 1:
        limit = (lower + upper) // 2
        probe = prove_with_limit(limit)
        assert probe.failure in (None, Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED)
        if probe.classified_fact_count > 0:
            upper = limit
        else:
            lower = limit
    mid_census = prove_with_limit(upper)
    assert mid_census.failure is Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
    assert mid_census.classified_fact_count > 0
    assert mid_census.classified_fact_count == (
        mid_census.materialized_count + mid_census.failure_count
    )
    assert mid_census.materialized_count > 0
    assert mid_census.refusal_site is None
    _assert_ledger_closed(mid_census)

    restored = prove_real16_invocation_domain_8616(
        project, coverage, 0x1032, boot=boot, boot_recompute=_recompute
    )
    _assert_proven(restored)


def test_native_binding_depth_bound_fails_closed() -> None:
    """Identical deep-nested blocks still refuse — the bound is a refusal.

    ``_native_block_bound_8616`` compares packed terms under
    ``_NATIVE_BINDING_DEPTH_LIMIT_8616``: two field-identical blocks whose
    operand nesting exceeds the bound cannot be proven equal and refuse
    instead of overflowing. The same row injected into the authentic
    artifact refuses ``native_effect_unproven`` with every in-scope row a
    classified refusal — a closed ledger with zero materializations.
    """
    const = IRValue(MemSpace.CONST, const=1, size=2)
    deep: IRBinaryValue = IRBinaryValue("Iop_Add16", const, const, size=2)
    for _ in range(dom._NATIVE_BINDING_DEPTH_LIMIT_8616 + 8):
        deep = IRBinaryValue("Iop_Add16", deep, const, size=2)
    deep_row = IRInstr(
        "MOV", IRValue(MemSpace.REG, name="bx", size=2), (deep,),
        size=2, addr=0x1030,
    )
    deep_block = IRBlock(
        addr=0x1030, instrs=(deep_row,), refusals=(), successor_addrs=()
    )
    assert dom._native_block_bound_8616(deep_block, deep_block) is False

    boot = _boot()

    def inject(block: IRBlock) -> IRBlock:
        return (
            replace(block, instrs=(deep_row, *block.instrs))
            if block.addr == 0x1030
            else block
        )

    premise, _, _ = _prove_stub(boot, STUB_CODE, 0x1032, mutate=inject)
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    assert premise.materialized_count == 0
    assert premise.failure_count == premise.classified_fact_count > 0
    _assert_ledger_closed(premise)


def test_tampered_premise_fields_replay_to_incomplete() -> None:
    """A retained-field mutation on the proof object cannot discharge.

    ``complete`` re-derives the whole derivation and compares every
    retained field; a tampered selector interval or census count fails
    the replay, and ``real16_invocation_discharges_8616`` follows.
    """
    boot = _boot()
    premise, project, raw = _prove_stub(boot, STUB_CODE, 0x1032)
    _assert_proven(premise)
    call_block = next(
        b for b in raw.blocks if any(i.addr == 0x1032 for i in b.instrs)
    )
    assert real16_invocation_discharges_8616(
        premise, project=project, block=call_block,
        callsite_addr=0x1032, target_addr=0x1000,
    )
    for tampered in (
        replace(premise, minimum_selector=0),
        replace(premise, checked_store_count=0),
    ):
        assert not tampered.complete
        assert not real16_invocation_discharges_8616(
            tampered, project=project, block=call_block,
            callsite_addr=0x1032, target_addr=0x1000,
        )


def test_authentic_unknown_effect_refuses_at_classifier() -> None:
    """``f6 e3`` (``mul bx``) lifts rows the scalar classifier refuses.

    The authentic Iop_Mul16 rows are byte-exact under native binding, so
    the refusal comes from the authoritative scalar-effect classifier —
    ``path_effect_unproven`` with the row classified then refused — the
    UNKNOWN gate at its real layer, preserved.
    """
    code = bytes.fromhex("f6 e3 e8 0000 c3")
    boot = _boot(code)
    premise, _, _ = _prove_stub(boot, code, 0x1032)
    _assert_row_refusal(
        premise, Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
    )
