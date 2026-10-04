"""Concrete real16 replay controls execute actual MZ bytes in fresh guests.

These tests exercise the production loader, guest, execution and report owners.
"""

from __future__ import annotations

import pytest

from tools.dosunit import real16_mz_load as mz_load
from tools.dosunit import real16_replay as replay_mod
from tools.dosunit import real16_replay_model as model
from tools.dosunit import real16_replay_report as report_mod

CallerFrame = model.CallerFrame
A20Policy = model.A20Policy
FrameKind = model.FrameKind
LinearRange = model.LinearRange
Real16ReplayPolicy = model.Real16ReplayPolicy
Real16ReplayStatus = model.Real16ReplayStatus
Real16Vector = model.Real16Vector
SegOffset = model.SegOffset

LOAD = 0x1000  # default load paragraph for fixture images
STACK_SEG = 0x7000
STACK_SP = 0x0100
TRAP_OFF = 0x8000  # near-frame return offset inside the entry CS, outside image bytes


def _mz(image: bytes, *, relocs: tuple[tuple[int, int], ...] = (), minalloc: int = 0) -> bytes:
    """Build a real MZ executable around load-module bytes and relocations."""
    reloc_pos = 0x1C
    header_size = ((reloc_pos + len(relocs) * 4 + 15) // 16) * 16
    file_size = header_size + len(image)
    blocks, lastsize = divmod(file_size, 512)
    if lastsize:
        blocks += 1
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = lastsize.to_bytes(2, "little")
    header[0x04:0x06] = blocks.to_bytes(2, "little")
    header[0x06:0x08] = len(relocs).to_bytes(2, "little")
    header[0x08:0x0A] = (header_size // 16).to_bytes(2, "little")
    header[0x0A:0x0C] = (minalloc & 0xFFFF).to_bytes(2, "little")
    header[0x0C:0x0E] = (0xFFFF).to_bytes(2, "little")
    header[0x0E:0x10] = (0x0080).to_bytes(2, "little")
    header[0x10:0x12] = (0xFFFE).to_bytes(2, "little")
    header[0x14:0x16] = (0).to_bytes(2, "little")
    header[0x16:0x18] = (0).to_bytes(2, "little")
    header[0x18:0x1A] = reloc_pos.to_bytes(2, "little")
    for index, (offset, segment) in enumerate(relocs):
        at = reloc_pos + index * 4
        header[at:at + 2] = (offset & 0xFFFF).to_bytes(2, "little")
        header[at + 2:at + 4] = (segment & 0xFFFF).to_bytes(2, "little")
    return bytes(header) + image


def _image(
    image: bytes,
    *,
    relocs: tuple[tuple[int, int], ...] = (),
    code_size: int | None = None,
    minalloc: int = 0,
    load_segment: int = LOAD,
):
    """Load fixture MZ bytes; ``code_size`` scopes declared instruction bytes."""
    base = load_segment * 16
    ranges = ()
    if code_size is not None:
        ranges = (LinearRange(base, code_size),)
    return mz_load.image_from_mz_bytes(
        _mz(image, relocs=relocs, minalloc=minalloc),
        load_segment=load_segment,
        code_ranges=ranges,
    )


def _entry() -> SegOffset:
    """Entry contract for fixture functions at the image start."""
    return SegOffset(LOAD, 0)


def _vector(
    *,
    regs: dict[str, int] | None = None,
    sregs: dict[str, int] | None = None,
    frame: CallerFrame | None = None,
    high: dict[str, int] | None = None,
    memory: tuple[tuple[SegOffset, bytes], ...] = (),
    observations: tuple[tuple[SegOffset, int], ...] = (),
    flags_mask: int = 0,
) -> Real16Vector:
    """Concrete near-frame vector over explicit segments and registers."""
    base_regs = {"ax": 0, "bx": 0, "cx": 0, "dx": 0, "si": 0, "di": 0,
                 "bp": 0, "sp": STACK_SP, "flags": 0x0002}
    base_regs.update(regs or {})
    base_segs = {"ds": LOAD, "es": LOAD, "ss": STACK_SEG, "fs": 0, "gs": 0}
    base_segs.update(sregs or {})
    return Real16Vector(
        registers=tuple(sorted(base_regs.items())),
        segments=tuple(sorted(base_segs.items())),
        frame=frame or CallerFrame(FrameKind.NEAR16, SegOffset(LOAD, TRAP_OFF)),
        high_halves=tuple(sorted((high or {}).items())),
        memory=memory,
        observations=observations,
        flags_mask=flags_mask,
    )


def _run(image, vector=None, **kwargs):
    """Replay one fixture image/vector under the default explicit policy."""
    return replay_mod.replay(image, _entry(), vector or _vector(), **kwargs)


def test_identical_images_agree_and_return():
    image = _image(bytes.fromhex("b8 34 12 c3"))  # mov ax,1234h; ret
    first = _run(image)
    second = _run(image)
    assert first.status is Real16ReplayStatus.RETURNED
    assert first == second
    assert dict(first.registers)["ax"] == 0x1234
    assert replay_mod.compare_replays(first, second).value == "agreed"


def test_nop_equivalent_edit_agrees():
    plain = _image(bytes.fromhex("b8 34 12 c3"))
    padded = _image(bytes.fromhex("90 b8 34 12 c3"))  # leading nop
    left = _run(plain)
    right = _run(padded)
    assert left.status is Real16ReplayStatus.RETURNED
    assert right.status is Real16ReplayStatus.RETURNED
    assert replay_mod.compare_replays(left, right).value == "agreed"


def test_changed_return_cleanup_and_store_mismatch():
    plain = _image(bytes.fromhex("c3"))                    # ret
    cleanup = _image(bytes.fromhex("c2 04 00"))            # ret 4
    ordinary = _run(plain)
    cleaned = _run(cleanup)
    assert ordinary.status is Real16ReplayStatus.RETURNED
    assert cleaned.status is Real16ReplayStatus.RETURNED
    assert replay_mod.compare_replays(ordinary, cleaned).value == "mismatched"

    # Identical code writing different values into a declared data range.
    code_size = 7
    store_a = _image(bytes.fromhex("b8 01 00 a3 00 02 c3") + bytes(0x200 - 7) + b"\x00\x00",
                     code_size=code_size)
    store_b = _image(bytes.fromhex("b8 02 00 a3 00 02 c3") + bytes(0x200 - 7) + b"\x00\x00",
                     code_size=code_size)
    left = _run(store_a, _vector(observations=((SegOffset(LOAD, 0x200), 2),)))
    right = _run(store_b, _vector(observations=((SegOffset(LOAD, 0x200), 2),)))
    assert left.status is Real16ReplayStatus.RETURNED
    assert left.writes == ((LOAD * 16 + 0x200, bytes.fromhex("0100")),)
    assert left.observations == ((LOAD * 16 + 0x200, bytes.fromhex("0100")),)
    assert replay_mod.compare_replays(left, right).value == "mismatched"


def test_changed_control_flow_mismatch():
    # Conditional that diverges: jz skips ax write only in the changed image.
    always = _image(bytes.fromhex("b8 01 00 c3"))
    guarded = _image(bytes.fromhex("74 01 c3 b8 01 00 c3"))  # jz +1; ret; mov ax,1; ret
    left = _run(always)
    right = _run(guarded)
    assert left.status is Real16ReplayStatus.RETURNED
    assert right.status is Real16ReplayStatus.RETURNED
    assert replay_mod.compare_replays(left, right).value == "mismatched"


def test_near_call_leaf_and_loop_iterations():
    # e8 +2 -> leaf at 5; caller ret at 3; pad 90; leaf: mov ax,7; ret
    caller = _image(bytes.fromhex("e8 02 00 c3 90 b8 07 00 c3"))
    result = _run(caller)
    assert result.status is Real16ReplayStatus.RETURNED
    assert dict(result.registers)["ax"] == 7

    # jcxz +4 -> ret; loop body: add ax,bx; loop back; ret
    loop = _image(bytes.fromhex("e3 04 01 d8 e2 fc c3"))
    for count in (0, 1, 3, 40):
        result = _run(loop, _vector(regs={"bx": 1, "cx": count}))
        assert result.status is Real16ReplayStatus.RETURNED
        assert dict(result.registers)["ax"] == count


def test_far_call_inside_function_returns_through_ret_far():
    # 9a ptr16:16 far-calls the leaf at LOAD:0008; leaf retf returns to the
    # fallthrough ret, which then returns through the near caller frame.
    code = bytes.fromhex(
        "9a 08 00 00 10"  # call far 1000h:0008h
        "c3"              # ret (near caller frame)
        "90 90 90"        # pad to offset 8
        "b8 07 00 cb"     # leaf: mov ax,7; retf
    )
    image = _image(code)
    result = _run(image)
    assert result.status is Real16ReplayStatus.RETURNED
    assert dict(result.registers)["ax"] == 7


def test_far16_frame_return_and_segment_update():
    image = _image(bytes.fromhex("b8 34 12 cb"))  # mov ax,1234h; retf
    far_vector = _vector(frame=CallerFrame(FrameKind.FAR16, SegOffset(0x4000, 0x10)))
    result = _run(image, far_vector)
    assert result.status is Real16ReplayStatus.RETURNED
    regs = dict(result.registers)
    assert regs["ax"] == 0x1234
    assert regs["cs"] == 0x4000
    assert regs["ip"] == 0x10


def test_near_frame_rejects_mismatched_segment():
    image = _image(bytes.fromhex("c3"))
    bad = _vector(frame=CallerFrame(FrameKind.NEAR16, SegOffset(0x4000, TRAP_OFF)))
    with pytest.raises(ValueError, match="near16 frame"):
        _run(image, bad)


def test_segment_alias_preserves_physical_addresses():
    # mov word ptr es:[0100],0BEEFh ; ret ; ES=2FF0h aliases DS=3000h:0000.
    image = _image(bytes.fromhex("26 c7 06 00 01 ef be c3"), code_size=8)
    vector = _vector(
        sregs={"es": 0x2FF0, "ds": 0x3000},
        observations=((SegOffset(0x3000, 0), 2),),
    )
    result = _run(image, vector)
    assert result.status is Real16ReplayStatus.RETURNED
    assert result.observations == ((0x30000, bytes.fromhex("efbe")),)
    assert result.writes == ((0x30000, bytes.fromhex("efbe")),)


def test_changed_initialized_global_mismatches_with_identical_code():
    # mov ax,[0200h]; ret -- identical code, different initialized image data.
    code = bytes.fromhex("a1 00 02 c3")
    pad = bytes(0x200 - len(code))
    image_a = _image(code + pad + bytes.fromhex("11 00"), code_size=len(code))
    image_b = _image(code + pad + bytes.fromhex("22 00"), code_size=len(code))
    left = _run(image_a)
    right = _run(image_b)
    assert left.status is Real16ReplayStatus.RETURNED
    assert right.status is Real16ReplayStatus.RETURNED
    assert dict(left.registers)["ax"] == 0x11
    assert dict(right.registers)["ax"] == 0x22
    assert replay_mod.compare_replays(left, right).value == "mismatched"


def test_fresh_guest_resets_state_between_vectors():
    # inc word ptr [0200h]; ret -- guest mutation must not leak across runs.
    image = _image(bytes.fromhex("ff 06 00 02 c3") + bytes(0x200 - 5) + b"\x05\x00",
                   code_size=5)
    vector = _vector(observations=((SegOffset(LOAD, 0x200), 2),))
    first = _run(image, vector)
    second = _run(image, vector)
    assert first.status is Real16ReplayStatus.RETURNED
    assert first == second
    assert first.observations == ((LOAD * 16 + 0x200, bytes.fromhex("0600")),)


def test_divide_error_and_dos_io_are_typed_outcomes():
    fault = _run(_image(bytes.fromhex("31 d2 31 c0 f6 f1 c3")))  # xor; xor; div cl
    dos = _run(_image(bytes.fromhex("cd 21 c3")))                # int 21h
    out = _run(_image(bytes.fromhex("ee c3")))                   # out dx,al
    hlt = _run(_image(bytes.fromhex("f4 c3")))                   # hlt
    iret = _run(_image(bytes.fromhex("cf")))                     # iret
    assert fault.status is Real16ReplayStatus.FAULTED
    assert fault.detail == "interrupt:0"
    for result in (dos, out, hlt, iret):
        assert result.status is Real16ReplayStatus.UNSUPPORTED
        assert result.events
    # Fault/unsupported executions can never agree, even with themselves.
    for result in (fault, dos, out, hlt, iret):
        assert replay_mod.compare_replays(result, result).value == "incomplete"


def test_budget_exhaustion_is_incomplete_not_mismatch():
    image = _image(bytes.fromhex("eb fe"))  # jmp $
    forever = _run(image, instruction_limit=50)
    assert forever.status is Real16ReplayStatus.BUDGET_EXHAUSTED
    assert replay_mod.compare_replays(forever, forever).value == "incomplete"


def test_self_modifying_code_refused_via_segment_alias():
    # mov [di],al with DS=CS aliases data writes onto instruction bytes.
    image = _image(bytes.fromhex("88 05 c3"))
    vector = _vector(regs={"di": 0})
    result = _run(image, vector)
    assert result.status is Real16ReplayStatus.UNSUPPORTED
    assert result.detail == "instruction_memory_write"


def test_relocation_is_applied_and_fingerprinted():
    # mov ax,[0010h]; ret where image word at 0x10 holds a relocated segment.
    code = bytes.fromhex("a1 10 00 c3")
    pad = bytes(0x10 - len(code))
    image = _image(code + pad + bytes.fromhex("20 00"), relocs=((0x10, 0),),
                   code_size=len(code))
    result = _run(image)
    assert result.status is Real16ReplayStatus.RETURNED
    assert dict(result.registers)["ax"] == LOAD + 0x20
    other = mz_load.image_from_mz_bytes(
        _mz(code + pad + bytes.fromhex("20 00"), relocs=((0x10, 0),)),
        load_segment=0x2000,
    )
    assert image.image_sha256 != other.image_sha256
    assert image.file_sha256 == other.file_sha256


def test_a20_disabled_policy_refuses_boundary_access():
    # mov ax,[bx] with DS:BX at FFFF:1000 -> linear 0x100FF0 above 1 MiB.
    image = _image(bytes.fromhex("8b 07 c3"))
    vector = _vector(regs={"bx": 0x1000}, sregs={"ds": 0xFFFF})
    enabled = _run(image, vector)
    assert enabled.status is Real16ReplayStatus.RETURNED
    refused = _run(image, vector,
                   policy=Real16ReplayPolicy(a20=A20Policy.DISABLED_REFUSE))
    assert refused.status is Real16ReplayStatus.UNSUPPORTED
    assert refused.detail == "a20_wrap_access"


def test_declared_region_above_1mib_refuses_under_disabled_a20():
    image = _image(bytes.fromhex("c3"))
    vector = _vector(memory=((SegOffset(0xF800, 0x9000), b"\x00"),))
    with pytest.raises(ValueError, match="A20"):
        _run(image, vector, policy=Real16ReplayPolicy(a20=A20Policy.DISABLED_REFUSE))


def test_386_high_halves_are_explicit_observables():
    low = _image(bytes.fromhex("66 b8 78 56 34 12 c3"))   # mov eax,12345678h
    high = _image(bytes.fromhex("66 b8 78 56 34 99 c3"))  # mov eax,99345678h
    left = _run(low)
    right = _run(high)
    assert dict(left.registers)["ax"] == 0x5678
    assert dict(left.registers)["eax"] == 0x12345678
    assert replay_mod.compare_replays(left, right).value == "mismatched"
    sixteen_bit = ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "ds", "ss")
    assert replay_mod.compare_replays(left, right, observables=sixteen_bit).value == "agreed"


def test_unavailable_backend_is_typed_not_an_exception(monkeypatch):
    monkeypatch.setattr(replay_mod, "unicorn", None)
    image = _image(bytes.fromhex("c3"))
    result = _run(image)
    assert result.status is Real16ReplayStatus.UNAVAILABLE
    assert replay_mod.compare_replays(result, result).value == "incomplete"


def test_control_escape_is_distinct_from_return():
    # jmp short +8 jumps past the declared 2-byte code range into mapped image.
    image = _image(bytes.fromhex("eb 08") + bytes(0x40), code_size=2)
    result = _run(image)
    assert result.status is Real16ReplayStatus.CONTROL
    assert result.detail == "fetch_outside_declared_code"
    assert replay_mod.compare_replays(result, result).value == "incomplete"


def test_report_document_never_claims_proof(tmp_path):
    image = _image(bytes.fromhex("b8 34 12 c3"))
    result = _run(image)
    row = report_mod.Real16ReplayRow(
        "v1", replay_mod.compare_executions(result, result), result, result,
        _vector(), _entry(), _entry(),
    )
    oracle = tmp_path / "oracle.exe"
    candidate = tmp_path / "candidate.exe"
    oracle.write_bytes(_mz(bytes.fromhex("b8 34 12 c3")))
    candidate.write_bytes(_mz(bytes.fromhex("b8 34 12 c3")))
    document = report_mod.replay16_report_document(
        oracle_path=oracle, candidate_path=candidate,
        oracle_image=image, candidate_image=image,
        rows=[row], policy=Real16ReplayPolicy(), instruction_limit=1000,
    )
    assert document["schema"] == "dosunit.real16_replay.v1"
    assert document["proof_status"] == "not_established_by_execution"
    assert document["summary"] == {"total": 1, "agreed": 1, "mismatched": 0, "incomplete": 0}
    assert document["inputs"]["oracle"]["image"]["image_sha256"] == image.image_sha256


def test_linear_straddle_setup_execution_and_observation_are_coherent():
    """A word at DS:FFFF continues physically instead of wrapping byte two."""
    image = _image(bytes.fromhex("a1 ff ff c3"))
    address = SegOffset(LOAD, 0xFFFF)
    vector = _vector(memory=((address, bytes.fromhex("ab cd")),), observations=((address, 2),))
    result = _run(image, vector)
    assert result.status is Real16ReplayStatus.RETURNED
    assert dict(result.registers)["ax"] == 0xCDAB
    assert result.observations == ((address.linear(), bytes.fromhex("ab cd")),)


def test_mz_relocation_table_must_be_inside_header():
    """Instruction/data bytes cannot be interpreted as relocation metadata."""
    data = bytearray(_mz(bytes.fromhex("b8 34 12 c3")))
    data[6:8] = (1).to_bytes(2, "little")
    data[0x18:0x1A] = (0x20).to_bytes(2, "little")
    with pytest.raises(ValueError, match="relocation table"):
        mz_load.parse_mz(bytes(data))


@pytest.mark.parametrize("field,value", [(0x02, 512), (0x04, 0), (0x08, 1)])
def test_mz_invalid_header_geometry_refuses(field, value):
    """Malformed size fields refuse instead of silently truncating the image."""
    data = bytearray(_mz(bytes.fromhex("c3")))
    data[field:field + 2] = value.to_bytes(2, "little")
    with pytest.raises(ValueError):
        mz_load.parse_mz(bytes(data))


def test_mz_page_count_retains_all_sixteen_bits():
    """The page-count field has no eleven-bit truncation in the DOS format."""
    data = bytearray(_mz(b"\0" * (0x801 * 512 - 0x20)))
    parsed = mz_load.parse_mz(bytes(data))
    assert len(parsed.image) == 0x801 * 512 - 0x20


@pytest.mark.parametrize("code", ["d9 e8 c3", "db e3 c3"])
def test_unobserved_floating_and_vector_state_refuses(code):
    """FLD1/FNINIT effects cannot disappear from integer observations."""
    result = _run(_image(bytes.fromhex(code)))
    assert result.status is Real16ReplayStatus.UNSUPPORTED
    assert result.detail == "unmodeled_register_state"


@pytest.mark.parametrize("code", ["0f31", "0fa2", "0fc7f0", "0fc7f8", "0f01f9", "0f01d0",
                                  "660fc7f0", "660fc7f8"])
def test_undeclared_machine_inputs_refuse_before_function_execution(code: str) -> None:
    """Implicit clock, CPU and entropy state cannot stand in for declared inputs."""
    result = _run(_image(bytes.fromhex(code + "c3")))
    assert result.status is Real16ReplayStatus.UNSUPPORTED
    assert result.detail == "undeclared_machine_input"
