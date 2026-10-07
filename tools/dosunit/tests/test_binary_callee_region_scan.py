"""Deterministic exact-byte controls for the staged callee-region scanner.

Layer: dosunit staged intake test boundary.
Responsibility: exercise ``binary_callee_region_scan`` with hand-built IRSBs
carrying real typed VEX statements (``Ist_Exit``/``Ist_Dirty``) and exact
16-bit encodings; every control asserts the typed status, refusal reason and
retained block/edge evidence.  Runnable under pytest or standalone.
"""

from __future__ import annotations

import archinfo
import pyvex

import tools.dosunit.catalog.binary_callee_region_scan as R
import tools.dosunit.compare.straightline_ssa as S

_ARCH = archinfo.ArchX86()
_BASE = 0x1000
_WINDOW = R.ScanWindow(start=_BASE, end=0x1100)
_BUDGET = R.RegionScanBudget(max_blocks=8, max_instructions=32, max_bytes=64, max_span=0x100)


def _insn(at: int, code_hex: str, mnemonic: str = "", op_str: str = "") -> dict[str, object]:
    """Build one exact instruction record in the owner record shape."""
    data = bytes.fromhex(code_hex)
    return {"linear": at, "size": len(data), "mnemonic": mnemonic, "op_str": op_str, "bytes": data.hex()}


def _exit(target: int, jumpkind: str = "Ijk_Boring") -> pyvex.stmt.Exit:
    """Build a real typed ``Ist_Exit`` with a bare IRConst destination."""
    return pyvex.stmt.Exit(pyvex.expr.Const(pyvex.const.U1(1)), pyvex.const.U16(target), jumpkind, 68)


def _dirty() -> pyvex.stmt.Dirty:
    """Build a real ``Ist_Dirty`` helper statement (environment contract)."""
    cee = pyvex.expr.CCall("Ity_I32", "x86g_dirtyhelper_loadF80", [])
    return pyvex.stmt.Dirty(cee, pyvex.expr.Const(pyvex.const.U1(1)), [], 9, "Ifx_None", None, 0, 0)


def _spec(at: int, insns: tuple[tuple[str, str, str], ...], *,
          exits: tuple[pyvex.stmt.Exit, ...] = (),
          nxt: object = "ret",
          jumpkind: str = "Ijk_Boring",
          extra: tuple = ()) -> tuple[int, dict[str, object]]:
    """Declare one lifted block: instruction encodings plus typed VEX control."""
    return at, {"at": at, "insns": insns, "exits": exits, "nxt": nxt,
                "jumpkind": jumpkind, "extra": extra}


def _irsb_for(spec: dict[str, object]) -> pyvex.IRSB:
    nxt = spec["nxt"]
    if nxt == "ret":
        nxt = pyvex.expr.RdTmp(6)
    elif isinstance(nxt, int):
        nxt = pyvex.expr.Const(pyvex.const.U32(nxt))
    statements = list(spec["extra"]) + list(spec["exits"])
    size = sum(len(bytes.fromhex(code)) for code, _mn, _op in spec["insns"])
    return pyvex.IRSB.empty_block(_ARCH, int(spec["at"]), statements=statements,
                                  nxt=nxt, jumpkind=str(spec["jumpkind"]), size=size)


def _lifter(specs: dict[int, dict[str, object]]) -> R.LiftCallback:
    """Bounded lift callback returning real IRSBs for declared block starts."""
    def lift(start: int, size: int) -> S.LiftedBlock:
        spec = specs[start]
        records = []
        cursor = int(spec["at"])
        for code, mnemonic, op in spec["insns"]:
            records.append(_insn(cursor, code, mnemonic, op))
            cursor += len(bytes.fromhex(code))
        return S.LiftedBlock(irsb=_irsb_for(spec), instructions=records, lifted=True)
    return lift


def _reader(image: bytes, base: int = _BASE) -> R.ReadBytesCallback:
    """Live byte-read callback over an exact loaded image slice."""
    def read(start: int, size: int) -> bytes | None:
        offset = start - base
        if offset < 0 or offset + size > len(image):
            return None
        return bytes(image[offset : offset + size])
    return read


def _image_of(specs: dict[int, dict[str, object]], size: int = 0x200, fill: int = 0x90) -> bytes:
    """Materialize the loaded image bytes declared by the block specs."""
    image = bytearray([fill] * size)
    for spec in specs.values():
        cursor = int(spec["at"]) - _BASE
        for code, _mn, _op in spec["insns"]:
            data = bytes.fromhex(code)
            image[cursor : cursor + len(data)] = data
            cursor += len(data)
    return bytes(image)


def _scan(specs: dict[int, dict[str, object]], *,
          entry: int = _BASE, window: R.ScanWindow = _WINDOW,
          budget: R.RegionScanBudget = _BUDGET,
          image: bytes | None = None) -> R.RegionScanOutcome:
    live = _image_of(specs) if image is None else image
    request = R.RegionScanRequest(
        entry_loader_linear=entry, window=window, budget=budget,
        lift_block=_lifter(specs), read_bytes=_reader(live))
    return R.scan_candidate_region(request)


def _ret_spec(at: int, prefix: tuple[tuple[str, str, str], ...] = ()) -> tuple[int, dict[str, object]]:
    """A block ending in decoded near RET (``c3``)."""
    return _spec(at, (*prefix, ("c3", "ret", "")), jumpkind="Ijk_Ret")


def test_branched_near_ret_completes() -> None:
    """Conditional entry with both arms closing on near RET completes."""
    specs = dict([
        _spec(0x1000, (("3bc3", "cmp", "ax, bx"), ("720a", "jb", "0x100e")),
              exits=(_exit(0x1004),), nxt=0x100E),
        _ret_spec(0x1004, (("33c0", "xor", "ax, ax"),)),
        _ret_spec(0x100E, (("8bd8", "mov", "bx, ax"),)),
    ])
    outcome = _scan(specs)
    assert outcome.status is R.RegionScanStatus.COMPLETED
    assert outcome.refusal is None
    assert outcome.terminals == (0x1004, 0x100E)
    assert outcome.counters.raw_fact_count == 6
    assert outcome.counters.normalized_fact_count == 3
    assert outcome.counters.classified_fact_count == 2
    assert outcome.counters.materialized_count == 3
    assert outcome.counters.failure_count == 0
    entry = outcome.blocks[0]
    assert [edge.kind for edge in entry.edges] == [R.EdgeKind.CONDITIONAL_EXIT, R.EdgeKind.DIRECT_DEFAULT_NEXT]
    assert entry.exits[0].target == 0x1004


def test_diamond_shared_tail_completes() -> None:
    """Two arms sharing one near-RET tail close without a cycle."""
    specs = dict([
        _spec(0x1000, (("3bc3", "cmp", "ax, bx"), ("720a", "jb", "0x1010")),
              exits=(_exit(0x1010),), nxt=0x1020),
        _spec(0x1010, (("eb1e", "jmp", "0x1030"),), nxt=0x1030),
        _spec(0x1020, (("eb0e", "jmp", "0x1030"),), nxt=0x1030),
        _ret_spec(0x1030),
    ])
    outcome = _scan(specs)
    assert outcome.status is R.RegionScanStatus.COMPLETED
    assert outcome.terminals == (0x1030,)
    assert outcome.counters.normalized_fact_count == 4


def test_external_arm_refused() -> None:
    """An arm escaping the declared window refuses; the edge is retained."""
    specs = dict([
        _spec(0x1000, (("3bc3", "cmp", "ax, bx"), ("720a", "jb", "0x1010")),
              exits=(_exit(0x1010),), nxt=0x1020),
        _spec(0x1010, (("e91ef0", "jmp", "0x2000"),), nxt=0x2000),
        _spec(0x1020, (("eb0e", "jmp", "0x1030"),), nxt=0x1030),
        _ret_spec(0x1030),
    ])
    outcome = _scan(specs)
    assert outcome.status is R.RegionScanStatus.REFUSED
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.EXTERNAL_EDGE
    escaped = [edge for block in outcome.blocks for edge in block.edges if edge.external]
    assert len(escaped) == 1 and escaped[0].target == 0x2000
    assert outcome.counters.failure_count == 1 and outcome.counters.closed()


def test_cycle_refused() -> None:
    """A mutual jump pair closes no path; the back-edge refuses as CYCLE."""
    specs = dict([
        _spec(0x1000, (("eb02", "jmp", "0x1004"),), nxt=0x1004),
        _spec(0x1004, (("ebfa", "jmp", "0x1000"),), nxt=0x1000),
    ])
    outcome = _scan(specs)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.CYCLE
    assert outcome.counters.normalized_fact_count == 2


def test_indirect_jump_refused() -> None:
    """``jmp cx`` keeps its retained indirect edge and refuses."""
    specs = dict([
        _spec(0x1000, (("8be3", "mov", "sp, bx"), ("ffe1", "jmp", "cx")), nxt=pyvex.expr.RdTmp(6)),
    ])
    outcome = _scan(specs)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.INDIRECT_CONTROL
    edge = outcome.blocks[0].edges[-1]
    assert edge.kind is R.EdgeKind.INDIRECT_SUCCESSOR and edge.target is None


def test_nested_call_refused() -> None:
    """A nested near CALL inside the region refuses."""
    specs = dict([
        _spec(0x1000, (("e8fd04", "call", "0x1500"),), nxt=0x1500, jumpkind="Ijk_Call"),
    ])
    outcome = _scan(specs)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.NESTED_CALL


def test_far_return_refused() -> None:
    """``retf`` lifts as Ijk_Ret but is not a decoded near RET."""
    specs = dict([
        _spec(0x1000, (("cb", "retf", ""),), jumpkind="Ijk_Ret"),
    ])
    outcome = _scan(specs)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.TERMINAL_NOT_NEAR_RET


def test_trap_exit_refused() -> None:
    """An ``Ijk_Sig`` exit is retained as evidence and refuses as trap."""
    specs = dict([
        _spec(0x1000, (("cc", "int3", ""),), exits=(_exit(0x1004, jumpkind="Ijk_SigSEGV"),), nxt=0x1001),
        _ret_spec(0x1004),
    ])
    outcome = _scan(specs)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.TRAP_EXIT
    assert outcome.blocks[0].exits[0].jumpkind == "Ijk_SigSEGV"


def test_dirty_environment_refused() -> None:
    """A dirty helper in the original IR refuses under the environment rule."""
    specs = dict([
        _spec(0x1000, (("33c0", "xor", "ax, ax"), ("59", "pop", "cx")),
              nxt=0x1003, extra=(_dirty(),)),
    ])
    outcome = _scan(specs)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.ENVIRONMENT_EFFECT


def test_decoded_port_refused() -> None:
    """A port event decoded from exact bytes refuses even without IR effect."""
    specs = dict([
        _spec(0x1000, (("ec", "in", "al, dx"), ("59", "pop", "cx")), nxt=0x1003),
    ])
    outcome = _scan(specs)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.ENVIRONMENT_EFFECT
    assert "summary_io_in" in outcome.refusal.detail.get("effects", [])


def test_missing_bytes_refused() -> None:
    """Unreadable live bytes refuse with the decoded bytes retained."""
    specs = dict([_ret_spec(0x1000)])

    def missing(start: int, size: int) -> bytes | None:
        return None

    request = R.RegionScanRequest(entry_loader_linear=0x1000, window=_WINDOW, budget=_BUDGET,
                                  lift_block=_lifter(specs), read_bytes=missing)
    outcome = R.scan_candidate_region(request)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.ENTRY_UNMAPPED


def test_changed_bytes_refused() -> None:
    """Live bytes differing from or absent for the decoded block refuse."""
    specs = dict([_ret_spec(0x1000)])
    image = bytearray(_image_of(specs))
    image[0] = 0x90
    outcome = _scan(specs, image=bytes(image))
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.BYTES_MISMATCH
    assert outcome.refusal.detail["loaded"] == "90"

    missing_specs = dict([_ret_spec(0x1000, (("90", "nop", ""),))])

    def gone_after_probe(start: int, size: int) -> bytes | None:
        return bytes.fromhex("90") if size == 1 else None

    request = R.RegionScanRequest(entry_loader_linear=0x1000, window=_WINDOW, budget=_BUDGET,
                                  lift_block=_lifter(missing_specs), read_bytes=gone_after_probe)
    outcome = R.scan_candidate_region(request)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.BYTES_MISMATCH
    assert outcome.refusal.detail["loaded"] is None


def test_instruction_head_with_unbounded_lifter_refuses_decode_gap() -> None:
    """A valid retained head cannot split when the fake lift ignores its bound."""
    specs = dict([
        _spec(0x1000, (("9090", "nop", ""), ("9090", "nop", "")),
              exits=(_exit(0x1002),), nxt=0x1004),
        _ret_spec(0x1004),
    ])
    outcome = _scan(specs)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.DECODE_GAP
    assert outcome.blocks[0].exits[0].target == 0x1002


def test_overlapping_blocks_refused() -> None:
    """A lifted block spanning an existing block start refuses as overlap."""
    specs = dict([
        _spec(0x1000, (("3bc3", "cmp", "ax, bx"), ("7204", "jb", "0x1008")),
              exits=(_exit(0x1008),), nxt=0x1004),
        _spec(0x1004, (("90" * 8, "nop", ""),), nxt=0x1030),
        _ret_spec(0x1008),
        _ret_spec(0x1030),
    ])
    outcome = _scan(specs)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.OVERLAPPING_BLOCKS


def test_invalid_budget_refused() -> None:
    """Non-positive bounds refuse closed before any lifting."""
    specs = dict([_ret_spec(0x1000)])
    outcome = _scan(specs, budget=R.RegionScanBudget(0, 32, 64, 0x100))
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.INVALID_BUDGET
    outcome = _scan(specs, budget=R.RegionScanBudget(4, 32, 64, -1))
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.INVALID_BUDGET
    assert outcome.counters.closed()


def test_budget_exceeded_refused() -> None:
    """Block and byte bounds refuse with the verified prefix retained."""
    specs = dict([
        _spec(0x1000, (("3bc3", "cmp", "ax, bx"), ("720a", "jb", "0x1010")),
              exits=(_exit(0x1010),), nxt=0x1004),
        _ret_spec(0x1004),
        _ret_spec(0x1010),
    ])
    outcome = _scan(specs, budget=R.RegionScanBudget(1, 32, 64, 0x100))
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.BUDGET_EXCEEDED
    assert outcome.refusal.detail["counter"] == "blocks"
    outcome = _scan(specs, budget=R.RegionScanBudget(8, 32, 3, 0x100))
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.BUDGET_EXCEEDED
    assert outcome.refusal.detail["counter"] == "bytes"


def test_scope_escape_refused() -> None:
    """A block spanning the window end refuses instead of expanding."""
    specs = dict([_spec(0x1000, (("90909090", "nop", ""),), nxt=0x1004)])
    outcome = _scan(specs, window=R.ScanWindow(0x1000, 0x1003))
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.SCOPE_ESCAPE


def test_entry_outside_window_refused() -> None:
    """An entry outside the declared window refuses before lifting."""
    specs = dict([_ret_spec(0x2000)])
    image = bytearray([0x90] * 0x2000)
    image[0x2000 - _BASE] = 0xC3
    outcome = _scan(specs, entry=0x2000, image=bytes(image))
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.ENTRY_OUTSIDE_WINDOW


def main() -> int:
    """Standalone smoke runner; exits nonzero on the first failure count."""
    tests = sorted(
        (name, fn) for name, fn in globals().items()
        if name.startswith("test_") and callable(fn)
    )
    failures = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as error:
            failures += 1
            print(f"FAIL {name}: {type(error).__name__}: {error}")
        else:
            print(f"PASS {name}")
    print(f"{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())


def test_flat32_absolute_low_target_is_not_rebased() -> None:
    """A flat32 low absolute successor stays outside a high-address window."""
    entry = 0x401000
    specs = dict([_spec(entry, (("eb00", "jmp", ""),), nxt=0x1002),
                  _ret_spec(entry + 2)])
    image = bytes.fromhex("eb00c3")
    request = R.RegionScanRequest(
        entry_loader_linear=entry, window=R.ScanWindow(entry, entry + 3),
        budget=_BUDGET, lift_block=_lifter(specs),
        read_bytes=_reader(image, base=entry), mode_bits=32)
    outcome = R.scan_candidate_region(request)
    assert outcome.status is R.RegionScanStatus.REFUSED
    assert outcome.refusal.reason is R.RegionScanRefusalReason.EXTERNAL_EDGE
    assert outcome.blocks[0].edges[0].target == 0x1002


def test_mid_instruction_target_still_refuses() -> None:
    """A target inside MOV's immediate is not an admissible block leader."""
    specs = dict([
        _spec(0x1000, (("b83412", "mov", "ax, 0x1234"), ("90", "nop", "")),
              exits=(_exit(0x1001),), nxt=0x1004),
        _ret_spec(0x1004),
    ])
    outcome = _scan(specs)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.MID_BLOCK_TARGET
    assert outcome.counters.failure_count == 1
