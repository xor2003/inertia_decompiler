"""Controls for bounded leader-split normalization in the callee-region scanner.

Layer: dosunit staged intake test boundary.
Responsibility: exercise the production implementation of
``binary_callee_region_scan`` with an instruction-table lifter that honors
(or deliberately ignores) the requested byte bound.  Asserts that a reachable
target on a retained instruction head normalizes the owning block instead of
refusing, while mid-instruction targets, byte drift, bound violations,
incompatible overlap and budget expiry still refuse closed.  Runnable under
pytest or standalone.
"""

from __future__ import annotations

from dataclasses import replace

import angr
import archinfo
import pytest
import pyvex
from angr_platforms.X86_16.arch_86_16 import Arch86_16

import tools.dosunit.binary_callee_region_scan as R
import tools.dosunit.straightline_ssa as S
from tools.dosunit.binary_callee_region_split import prefix_edge_verdict

_ARCH = archinfo.ArchX86()
_BASE = 0x1000
_WINDOW = R.ScanWindow(start=_BASE, end=0x1100)
_BUDGET = R.RegionScanBudget(max_blocks=8, max_instructions=32, max_bytes=64, max_span=0x100)


def _exit(target: int, jumpkind: str = "Ijk_Boring", mode_bits: int = 16) -> pyvex.stmt.Exit:
    """Build a real typed ``Ist_Exit`` with a bare IRConst destination."""
    const = pyvex.const.U16(target) if mode_bits == 16 else pyvex.const.U32(target)
    return pyvex.stmt.Exit(pyvex.expr.Const(pyvex.const.U1(1)), const, jumpkind, 68)


def _row(at: int, code_hex: str, *, exit: int | None = None, exit_kind: str = "Ijk_Boring",
         stop: bool = False, jumpkind: str = "Ijk_Boring", nxt: object = None) -> tuple[int, dict[str, object]]:
    """Declare one instruction row in the source table."""
    return at, {"at": at, "bytes": bytes.fromhex(code_hex), "exit": exit, "exit_kind": exit_kind,
                "stop": stop, "jumpkind": jumpkind, "nxt": nxt}


def _table_lifter(table: dict[int, dict[str, object]], *, honor_bound: bool = True,
                  mode_bits: int = 16, hook: object = None) -> R.LiftCallback:
    """Lift contiguous table rows from ``start`` within the requested size.

    A bound-honoring lifter stops before the first row that would exceed the
    requested size and ends with a boring ``next`` at the decode cursor — the
    exact semantics a real bounded lifter has at a forced block boundary.
    """
    def lift(start: int, size: int) -> S.LiftedBlock:
        if hook is not None:
            hook(start, size)
        records: list[dict[str, object]] = []
        statements: list[pyvex.stmt.Stmt] = []
        cursor = start
        used = 0
        stopped = False
        jumpkind = "Ijk_Boring"
        tail: object = None
        while cursor in table:
            row = table[cursor]
            row_size = len(row["bytes"])
            if honor_bound and used + row_size > size:
                break
            records.append({"linear": cursor, "size": row_size, "bytes": row["bytes"].hex(),
                            "mnemonic": "", "op_str": ""})
            if row["exit"] is not None:
                statements.append(_exit(int(row["exit"]), str(row["exit_kind"]), mode_bits))
            cursor += row_size
            used += row_size
            if row["stop"]:
                stopped = True
                jumpkind = str(row["jumpkind"])
                tail = row["nxt"]
                break
        if stopped and tail == "ret":
            nxt: object = pyvex.expr.RdTmp(6)
        elif stopped and isinstance(tail, int):
            nxt = pyvex.expr.Const(pyvex.const.U32(tail))
        else:
            nxt = pyvex.expr.Const(pyvex.const.U32(cursor))
        irsb = pyvex.IRSB.empty_block(_ARCH, start, statements=statements, nxt=nxt,
                                      jumpkind=jumpkind, size=used)
        return S.LiftedBlock(irsb=irsb, instructions=records, lifted=True)
    return lift


def _reader(image: bytes, base: int = _BASE) -> R.ReadBytesCallback:
    """Live byte-read callback over an exact loaded image slice."""
    def read(start: int, size: int) -> bytes | None:
        offset = start - base
        if offset < 0 or offset + size > len(image):
            return None
        return bytes(image[offset : offset + size])
    return read


def _image_of(table: dict[int, dict[str, object]], base: int = _BASE, size: int = 0x200,
              fill: int = 0x90) -> bytes:
    """Materialize the loaded image bytes declared by the table rows."""
    image = bytearray([fill] * size)
    for row in table.values():
        cursor = int(row["at"]) - base
        data = row["bytes"]
        image[cursor : cursor + len(data)] = data
    return bytes(image)


def _scan(table: dict[int, dict[str, object]], *, entry: int = _BASE,
          window: R.ScanWindow = _WINDOW, budget: R.RegionScanBudget = _BUDGET,
          base: int = _BASE, mode_bits: int = 16, image: bytes | None = None,
          honor_bound: bool = True, hook: object = None) -> R.RegionScanOutcome:
    live = _image_of(table, base=base) if image is None else image
    request = R.RegionScanRequest(
        entry_loader_linear=entry, window=window, budget=budget,
        lift_block=_table_lifter(table, honor_bound=honor_bound, mode_bits=mode_bits, hook=hook),
        read_bytes=_reader(live, base=base), mode_bits=mode_bits)
    return R.scan_candidate_region(request)


def _split_table() -> dict[int, dict[str, object]]:
    """Entry chain whose second edge lands on a decoded interior head."""
    return dict([
        _row(0x1000, "721e", exit=0x1020, stop=True, nxt=0x1002),     # jb 0x1020
        _row(0x1002, "7220", exit=0x1024, stop=True, nxt=0x1004),     # jb 0x1024
        _row(0x1004, "eb28", stop=True, nxt=0x1030),                  # jmp 0x1030
        _row(0x1030, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),  # ret
        _row(0x1020, "33c0"),                                          # xor ax, ax
        _row(0x1022, "720c", exit=0x1030),                            # jb 0x1030 (mid-block)
        _row(0x1024, "8bd8"),                                          # mov bx, ax
        _row(0x1026, "eb00", stop=True, nxt=0x1028),                  # jmp 0x1028
        _row(0x1028, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),  # ret
    ])


def test_interior_head_target_splits_and_completes() -> None:
    """A target on a retained instruction head splits the owning block."""
    outcome = _scan(_split_table())
    assert outcome.status is R.RegionScanStatus.COMPLETED, outcome.refusal
    assert outcome.refusal is None
    assert [block.linear for block in outcome.blocks] == [
        0x1000, 0x1002, 0x1004, 0x1020, 0x1024, 0x1028, 0x1030]
    assert outcome.terminals == (0x1028, 0x1030)
    prefix = next(block for block in outcome.blocks if block.linear == 0x1020)
    assert prefix.size == 4
    assert [edge.kind for edge in prefix.edges] == [
        R.EdgeKind.CONDITIONAL_EXIT, R.EdgeKind.DIRECT_DEFAULT_NEXT]
    assert prefix.edges[0].target == 0x1030
    assert prefix.edges[1].target == 0x1024
    assert prefix.exits[0].target == 0x1030
    suffix = next(block for block in outcome.blocks if block.linear == 0x1024)
    assert suffix.size == 4 and suffix.terminal is R.BlockTerminal.OPEN
    assert suffix.edges[-1].target == 0x1028
    spans = outcome.spans
    for index, (start, end) in enumerate(spans):
        assert start < end
        if index:
            assert spans[index - 1][1] <= start


def test_interior_head_split_flat32() -> None:
    """Flat32 mode: the same interior-head split over absolute targets."""
    base = 0x401000
    table = dict([
        _row(base + 0x00, "721e", exit=base + 0x20, stop=True, nxt=base + 0x02),
        _row(base + 0x02, "7220", exit=base + 0x24, stop=True, nxt=base + 0x04),
        _row(base + 0x04, "eb28", stop=True, nxt=base + 0x30),
        _row(base + 0x30, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),
        _row(base + 0x20, "33c0"),
        _row(base + 0x22, "90"),
        _row(base + 0x23, "90"),
        _row(base + 0x24, "8bd8"),
        _row(base + 0x26, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),
    ])
    window = R.ScanWindow(start=base, end=base + 0x100)
    outcome = _scan(table, entry=base, window=window, base=base, mode_bits=32)
    assert outcome.status is R.RegionScanStatus.COMPLETED, outcome.refusal
    prefix = next(block for block in outcome.blocks if block.linear == base + 0x20)
    assert prefix.size == 4
    assert prefix.edges[-1].kind is R.EdgeKind.DIRECT_DEFAULT_NEXT
    assert prefix.edges[-1].target == base + 0x24
    assert outcome.terminals == (base + 0x24, base + 0x30)


def test_mid_instruction_target_still_refused() -> None:
    """A target inside one instruction's byte span refuses MID_BLOCK_TARGET."""
    table = _split_table()
    table[0x1002] = _row(0x1002, "721d", exit=0x1021, stop=True, nxt=0x1004)[1]
    outcome = _scan(table)
    assert outcome.status is R.RegionScanStatus.REFUSED
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.MID_BLOCK_TARGET
    assert outcome.refusal.detail["target"] == "0x01021"


def test_two_interior_leaders_split_deterministically() -> None:
    """Two queued interior targets split the same span in FIFO order."""
    table = dict([
        _row(0x1000, "721e", exit=0x1020, stop=True, nxt=0x1002),
        _row(0x1002, "721e", exit=0x1022, stop=True, nxt=0x1004),
        _row(0x1004, "721e", exit=0x1024, stop=True, nxt=0x1006),
        _row(0x1006, "eb28", stop=True, nxt=0x1030),
        _row(0x1030, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),
        _row(0x1020, "33c0"),
        _row(0x1022, "8bd0"),
        _row(0x1024, "8bd8"),
        _row(0x1026, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),
    ])
    outcome = _scan(table, budget=R.RegionScanBudget(12, 40, 64, 0x100))
    assert outcome.status is R.RegionScanStatus.COMPLETED, outcome.refusal
    assert [block.linear for block in outcome.blocks] == [
        0x1000, 0x1002, 0x1004, 0x1006, 0x1020, 0x1022, 0x1024, 0x1030]
    sizes = {block.linear: block.size for block in outcome.blocks}
    assert sizes[0x1020] == 2 and sizes[0x1022] == 2 and sizes[0x1024] == 3
    middle = next(block for block in outcome.blocks if block.linear == 0x1022)
    assert middle.edges[-1].kind is R.EdgeKind.DIRECT_DEFAULT_NEXT
    assert middle.edges[-1].target == 0x1024


def test_prefix_bytes_changed_between_passes_refused() -> None:
    """Live bytes mutated before the prefix re-verify refuse BYTES_MISMATCH."""
    table = _split_table()
    image = bytearray(_image_of(table))
    mutated = {"on": False}

    def hook(start: int, size: int) -> None:
        if start == 0x1020 and size == 4:
            mutated["on"] = True

    def read(start: int, size: int) -> bytes | None:
        offset = start - _BASE
        if offset < 0 or offset + size > len(image):
            return None
        data = bytes(image[offset : offset + size])
        if mutated["on"] and start == 0x1020:
            data = b"\x90" + data[1:]
        return data

    request = R.RegionScanRequest(
        entry_loader_linear=_BASE, window=_WINDOW, budget=_BUDGET,
        lift_block=_table_lifter(table, hook=hook), read_bytes=read)
    outcome = R.scan_candidate_region(request)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.BYTES_MISMATCH
    assert outcome.refusal.detail["at"] == "0x01020"
    retained = next(block for block in outcome.blocks if block.linear == 0x1020)
    assert retained.size == 8


def test_prefix_lift_ignoring_bound_refused() -> None:
    """A prefix re-lift that overruns the requested bound refuses DECODE_GAP."""
    outcome = _scan(_split_table(), honor_bound=False)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.DECODE_GAP
    assert outcome.refusal.detail["boundary"] == "prefix_length"


def test_forward_leader_bound_completes() -> None:
    """A fresh decode bounded at a forward decoded leader completes."""
    table = dict([
        _row(0x1000, "7206", exit=0x1008, stop=True, nxt=0x1004),
        _row(0x1004, "8bd8"),
        _row(0x1006, "8bc8"),
        _row(0x1008, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),
    ])
    outcome = _scan(table)
    assert outcome.status is R.RegionScanStatus.COMPLETED, outcome.refusal
    assert [block.linear for block in outcome.blocks] == [0x1000, 0x1004, 0x1008]
    bounded = next(block for block in outcome.blocks if block.linear == 0x1004)
    assert bounded.size == 4
    assert bounded.edges[-1].kind is R.EdgeKind.DIRECT_DEFAULT_NEXT
    assert bounded.edges[-1].target == 0x1008
    assert outcome.terminals == (0x1008,)


def test_overlap_bound_ignoring_lifter_refused() -> None:
    """A lifter overrunning the forward bound into a decoded span refuses."""
    table = dict([
        _row(0x1000, "7206", exit=0x1008, stop=True, nxt=0x1004),
        _row(0x1004, "909090909090"),
        _row(0x1008, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),
    ])
    outcome = _scan(table, honor_bound=False)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.OVERLAPPING_BLOCKS


def test_overlap_misaligned_leader_refused() -> None:
    """A forward leader mid-instruction in the fresh decode refuses closed."""
    table = dict([
        _row(0x1000, "7206", exit=0x1008, stop=True, nxt=0x1004),
        _row(0x1004, "909090909090"),
        _row(0x1008, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),
    ])
    outcome = _scan(table)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.LIFT_FAILED


def test_split_repeat_work_hits_byte_budget() -> None:
    """The charged prefix re-lift trips the cumulative byte budget."""
    outcome = _scan(_split_table(), budget=R.RegionScanBudget(8, 32, 15, 0x100))
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.BUDGET_EXCEEDED
    assert outcome.refusal.detail["counter"] == "bytes"


def test_split_repeat_work_hits_block_budget() -> None:
    """The charged prefix re-lift trips the cumulative block budget."""
    outcome = _scan(_split_table(), budget=R.RegionScanBudget(4, 32, 64, 0x100))
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.BUDGET_EXCEEDED
    assert outcome.refusal.detail["counter"] == "blocks"


def test_cycle_through_split_leader_refused() -> None:
    """A back-edge over a normalized split leader still refuses CYCLE."""
    table = dict([
        _row(0x1000, "721e", exit=0x1020, stop=True, nxt=0x1002),
        _row(0x1002, "7220", exit=0x1024, stop=True, nxt=0x1030),
        _row(0x1030, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),
        _row(0x1020, "33c0"),
        _row(0x1022, "8bd8"),
        _row(0x1024, "ebda", stop=True, nxt=0x1000),  # jmp 0x1000 (back-edge)
        _row(0x1026, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),
    ])
    outcome = _scan(table)
    assert outcome.refusal is not None
    assert outcome.refusal.reason is R.RegionScanRefusalReason.CYCLE


def test_entry_span_interior_head_split() -> None:
    """The entry block itself splits when a later edge lands on its head."""
    table = dict([
        _row(0x1000, "33c0"),
        _row(0x1002, "721a", exit=0x1020),                      # jb 0x1020 (mid-block)
        _row(0x1004, "eb00", stop=True, nxt=0x1006),            # jmp 0x1006
        _row(0x1006, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),
        _row(0x1020, "72e2", exit=0x1004, stop=True, nxt=0x1022),  # jb 0x1004 (interior)
        _row(0x1022, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),
    ])
    outcome = _scan(table)
    assert outcome.status is R.RegionScanStatus.COMPLETED, outcome.refusal
    sizes = {block.linear: block.size for block in outcome.blocks}
    assert sizes == {0x1000: 4, 0x1004: 2, 0x1006: 1, 0x1020: 2, 0x1022: 1}
    prefix = next(block for block in outcome.blocks if block.linear == 0x1000)
    assert prefix.edges[-1].target == 0x1004
    assert outcome.terminals == (0x1006, 0x1022)


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


@pytest.mark.parametrize("mode_bits", [16, 32])
def test_native_lift_interior_instruction_head_completes(mode_bits: int) -> None:
    """Real Cython real16 and stock i386 VEX blocks support the same split."""
    code = bytes.fromhex("85c0750275019090c3")
    arch = Arch86_16() if mode_bits == 16 else archinfo.ArchX86()
    project = angr.load_shellcode(code, arch=arch, load_address=0x1000)
    calls = []

    def lift(at: int, size: int) -> S.LiftedBlock:
        calls.append((at, size))
        block = project.factory.block(at, size=size, opt_level=0 if mode_bits == 16 else 1)
        return S.LiftedBlock(block.vex, [S._instruction_record(i.insn) for i in block.capstone.insns], True)

    def read(at: int, size: int) -> bytes | None:
        offset = at - 0x1000
        return code[offset:offset + size] if offset >= 0 and offset + size <= len(code) else None

    request = R.RegionScanRequest(
        entry_loader_linear=0x1000, window=R.ScanWindow(0x1000, 0x1009),
        budget=R.RegionScanBudget(max_blocks=10, max_instructions=40, max_bytes=80, max_span=0x100),
        lift_block=lift, read_bytes=read, mode_bits=mode_bits,
    )
    outcome = R.scan_candidate_region(request)
    assert outcome.status is R.RegionScanStatus.COMPLETED
    assert outcome.refusal is None
    assert [(block.linear, block.size) for block in outcome.blocks] == [
        (0x1000, 4), (0x1004, 2), (0x1006, 1), (0x1007, 2)]
    assert outcome.counters.raw_fact_count == 9
    assert outcome.counters.normalized_fact_count == 4
    assert outcome.counters.classified_fact_count == 5
    assert outcome.counters.materialized_count == 4
    assert outcome.counters.failure_count == 0
    assert len(calls) == 5  # One bounded prefix re-lift, then its reachable suffix.
    assert (0x1006, 1) in calls


def test_prefix_cannot_invent_a_conditional_edge() -> None:
    """Exact prefix bytes alone do not authorize an invented exit target."""
    outcome = _scan(_split_table())
    prefix = next(block for block in outcome.blocks if block.linear == 0x1020)
    leader = prefix.linear + prefix.size
    assert prefix_edge_verdict(prefix, prefix, leader) is None
    forged = replace(prefix, exits=(*prefix.exits,
        R.ScannedExit(jumpkind="Ijk_Boring", target=0x10FE, guard_repr="1", dst_repr="0x10fe")))
    refusal = prefix_edge_verdict(forged, prefix, leader)
    assert refusal is not None
    assert refusal.reason is R.RegionScanRefusalReason.DECODE_GAP
    assert refusal.detail["boundary"] == "prefix_exit"
