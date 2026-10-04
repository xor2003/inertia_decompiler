"""Source-bound REP candidates require discharged summaries before publication."""

from __future__ import annotations

import hashlib
from pathlib import Path

import angr
import archinfo
import pytest
import pyvex
from angr_platforms.X86_16.arch_86_16 import Arch86_16

import tools.dosunit.straightline_ssa as S
from tools.dosunit import binary_callee_region_contracts as C
from tools.dosunit import binary_callee_region_intake as INTAKE
from tools.dosunit import binary_callee_region_lowering as LOWER
from tools.dosunit import binary_callee_region_pending as P
from tools.dosunit import binary_callee_region_scan as R

_ARCH = archinfo.ArchX86()
_BASE = 4096
_WINDOW = C.ScanWindow(start=_BASE, end=4352)
_BUDGET = C.RegionScanBudget(max_blocks=8, max_instructions=32, max_bytes=64, max_span=256)


@pytest.mark.parametrize("mode_bits", [16, 32])
@pytest.mark.parametrize("code", [bytes.fromhex("f3aac3"), bytes.fromhex("f3abc3")])
def test_native_repeat_scan_keeps_self_edge_pending(mode_bits: int, code: bytes) -> None:
    """Native lifters retain REP self-edges on both supported register widths."""
    arch = Arch86_16() if mode_bits == 16 else archinfo.ArchX86()
    project = angr.load_shellcode(code, arch=arch, load_address=_BASE)

    def lift(at: int, size: int) -> S.LiftedBlock:
        block = project.factory.block(at, size=size, opt_level=0 if mode_bits == 16 else 1)
        # Materialize VEX first so angr updates the block's REP boundary before
        # decoding Capstone records, matching the production adapter's order.
        irsb = block.vex
        instructions = [S._instruction_record(row.insn) for row in block.capstone.insns]
        return S.LiftedBlock(irsb, instructions, True)

    scan = R.scan_candidate_region(C.RegionScanRequest(
        _BASE, C.ScanWindow(_BASE, _BASE + len(code)), _BUDGET,
        lift, _reader(code), mode_bits=mode_bits,
    ))
    assert scan.status is C.RegionScanStatus.COMPLETED_PENDING_SUMMARY
    assert scan.refusal is None
    assert scan.pending_summary_edges == (C.PendingSummaryEdge(_BASE, mode_bits),)
    assert any(edge.target == _BASE for edge in scan.blocks[0].edges)


@pytest.mark.parametrize("mutation", ["missing_entry", "missing_base", "duplicate", "dangling"])
def test_pending_discharge_rejects_incomplete_graph(mutation: str) -> None:
    """Missing graph facts cannot turn the residual cycle check into success."""
    outcome = _scan(_rep_table())
    parts = [
        _fake_part(_BASE, successors=(_BASE + 5, _BASE + 12)),
        _fake_part(_BASE + 5, summary="repeat_string", successors=(_BASE + 12,)),
        _fake_part(_BASE + 12),
    ]
    if mutation == "missing_entry":
        parts[-1].pop("entry")
    elif mutation == "missing_base":
        parts[-1].pop("function_entry")
    elif mutation == "duplicate":
        parts.append(dict(parts[-1]))
    else:
        parts[0] = _fake_part(_BASE, successors=(_BASE + 5, _BASE + 99))
    failure = P.verify_pending_summary(parts, outcome)
    assert failure is not None
    assert failure.reason is P.PendingDischargeReason.INCOMPLETE_GRAPH


def _exit(target: int, jumpkind: str = "Ijk_Boring") -> pyvex.stmt.Exit:
    """Build a real typed ``Ist_Exit`` with a bare 16-bit IRConst destination."""
    return pyvex.stmt.Exit(pyvex.expr.Const(pyvex.const.U1(1)), pyvex.const.U16(target), jumpkind, 68)


def _row(
    at: int,
    code_hex: str,
    *,
    exit: int | None = None,
    stop: bool = False,
    jumpkind: str = "Ijk_Boring",
    nxt: object = None,
) -> tuple[int, dict[str, object]]:
    """Declare one instruction row in the source table."""
    return (
        at,
        {"at": at, "bytes": bytes.fromhex(code_hex), "exit": exit, "stop": stop, "jumpkind": jumpkind, "nxt": nxt},
    )


def _table_lifter(table: dict[int, dict[str, object]]) -> C.LiftCallback:
    """Lift contiguous table rows from ``start`` honoring the requested bound."""

    def lift(start: int, size: int) -> S.LiftedBlock:
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
            if used + row_size > size:
                break
            records.append(
                {"linear": cursor, "size": row_size, "bytes": row["bytes"].hex(), "mnemonic": "", "op_str": ""}
            )
            if row["exit"] is not None:
                statements.append(_exit(int(row["exit"])))
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
        irsb = pyvex.IRSB.empty_block(_ARCH, start, statements=statements, nxt=nxt, jumpkind=jumpkind, size=used)
        return S.LiftedBlock(irsb=irsb, instructions=records, lifted=True)

    return lift


def _reader(image: bytes, base: int = _BASE) -> C.ReadBytesCallback:
    """Live byte-read callback over an exact loaded image slice."""

    def read(start: int, size: int) -> bytes | None:
        offset = start - base
        if offset < 0 or offset + size > len(image):
            return None
        return bytes(image[offset : offset + size])

    return read


def _image_of(table: dict[int, dict[str, object]], base: int = _BASE, size: int = 512) -> bytes:
    """Materialize the loaded image bytes declared by the table rows."""
    image = bytearray([144] * size)
    for row in table.values():
        cursor = int(row["at"]) - base
        image[cursor : cursor + len(row["bytes"])] = row["bytes"]
    return bytes(image)


def _scan(
    table: dict[int, dict[str, object]], *, budget: C.RegionScanBudget = _BUDGET, image: bytes | None = None
) -> C.RegionScanOutcome:
    """Scan the table-declared region at ``_BASE`` through the staged scanner."""
    return R.scan_candidate_region(
        C.RegionScanRequest(
            _BASE, _WINDOW, budget, _table_lifter(table), _reader(_image_of(table) if image is None else image)
        )
    )


def _rep_table(code_hex: str = "f3ab") -> dict[int, dict[str, object]]:
    """Entry exits to a RET and defaults to one self-looping repeat block."""
    return dict(
        [
            _row(_BASE, "9090", exit=_BASE + 12, stop=True, nxt=_BASE + 5),
            _row(_BASE + 5, code_hex, exit=_BASE + 12, stop=True, nxt=_BASE + 5),
            _row(_BASE + 12, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),
        ]
    )


def _fake_part(
    linear: int, *, summary: str | None = None, successors: tuple[int, ...] = (), function_entry: int = _BASE
) -> dict[str, object]:
    """Minimal lowered part: entry linear plus direct-successor transfer."""
    transfer: dict[str, object] = {
        "kind": "direct_successors",
        "successors": [{"linear": f"0x{target:05x}"} for target in successors],
    }
    if summary is not None:
        transfer["summary"] = summary
    return {
        "entry": {"linear": f"0x{linear:05x}"},
        "function_entry": {"linear": f"0x{function_entry:05x}"},
        "source": {"transfer": transfer},
    }


def test_rep_self_edge_reports_pending_summary() -> None:
    """A single isolated repeat-shaped self-edge produces pending evidence."""
    outcome = _scan(_rep_table())
    assert outcome.status.value == "completed_pending_summary"
    assert outcome.refusal is None
    assert [edge.linear for edge in outcome.pending_summary_edges] == [_BASE + 5]
    rep_block = next(b for b in outcome.blocks if b.linear == _BASE + 5)
    self_edges = [e for e in rep_block.edges if e.target == _BASE + 5]
    assert [e.kind.value for e in self_edges] == ["direct_default_next"]
    assert outcome.terminals == (_BASE + 12,)
    assert outcome.counters.failure_count == 0


def test_corpus_shape_two_pending_edges() -> None:
    """Two repeat self-edges plus interleaved straight-line blocks stay pending."""
    table = dict(
        [
            _row(_BASE, "9090", exit=_BASE + 32, stop=True, nxt=_BASE + 5),
            _row(_BASE + 5, "f3ab", exit=_BASE + 8, stop=True, nxt=_BASE + 5),
            _row(_BASE + 8, "9090", exit=_BASE + 12, stop=True, nxt=_BASE + 10),
            _row(_BASE + 10, "f3aa", exit=_BASE + 32, stop=True, nxt=_BASE + 10),
            _row(_BASE + 12, "9090", stop=True, nxt=_BASE + 32),
            _row(_BASE + 32, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),
        ]
    )
    outcome = _scan(table)
    assert outcome.status.value == "completed_pending_summary"
    assert [e.linear for e in outcome.pending_summary_edges] == [_BASE + 5, _BASE + 10]


def test_interblock_back_edge_still_refused_cycle() -> None:
    """A back-edge to a different leader remains a CYCLE refusal."""
    table = dict(
        [
            _row(_BASE, "9090", exit=_BASE + 12, stop=True, nxt=_BASE + 5),
            _row(_BASE + 5, "9090", stop=True, nxt=_BASE),
            _row(_BASE + 12, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),
        ]
    )
    outcome = _scan(table)
    assert outcome.status.value == "refused"
    assert outcome.refusal is not None
    assert outcome.refusal.reason.value == "cycle"


def test_conditional_self_exit_still_refused_cycle() -> None:
    """Only default-next self-edges are isolated; a conditional self-exit is not."""
    table = dict(
        [
            _row(_BASE, "9090", exit=_BASE + 12, stop=True, nxt=_BASE + 5),
            _row(_BASE + 5, "9090", exit=_BASE + 5, stop=True, nxt=_BASE + 12),
            _row(_BASE + 12, "c3", stop=True, jumpkind="Ijk_Ret", nxt="ret"),
        ]
    )
    outcome = _scan(table)
    assert outcome.status.value == "refused"
    assert outcome.refusal is not None
    assert outcome.refusal.reason.value == "cycle"


def test_self_loop_without_terminal_refuses() -> None:
    """A pure self-loop lacks a RET; pending classification never excuses that."""
    table = dict([_row(_BASE, "ebfe", stop=True, nxt=_BASE)])
    outcome = _scan(table)
    assert outcome.status.value == "refused"
    assert outcome.refusal is not None
    expected = "cycle" if "after" == "before" else "missing_terminal"
    assert outcome.refusal.reason.value == expected


def test_byte_mismatch_still_refused() -> None:
    """Live-byte drift inside a pending-shaped region stays BYTES_MISMATCH."""
    table = _rep_table()
    image = bytearray(_image_of(table))
    image[5] = 244
    outcome = _scan(table, image=bytes(image))
    assert outcome.status.value == "refused"
    assert outcome.refusal is not None
    assert outcome.refusal.reason.value == "bytes_mismatch"


def test_budget_exhaustion_still_refused() -> None:
    """Cumulative instruction budget still bounds pending-shaped regions."""
    outcome = _scan(_rep_table(), budget=C.RegionScanBudget(8, 2, 64, 256))
    assert outcome.status.value == "refused"
    assert outcome.refusal is not None
    assert outcome.refusal.reason.value == "budget_exceeded"


def test_pending_outcome_contract_rejects_missing_edges() -> None:
    """The outcome validator refuses a pending status without named edges."""
    state_source = b"\x90"
    with pytest.raises(ValueError, match="pending"):
        C.RegionScanOutcome(
            status=C.RegionScanStatus.COMPLETED_PENDING_SUMMARY,
            entry_loader_linear=_BASE,
            window=_WINDOW,
            blocks=(),
            spans=(),
            source_bytes=state_source,
            source_sha256=hashlib.sha256(state_source).hexdigest(),
            counters=C.FactCounters(0, 0, 0, 0, 0),
            refusal=None,
            pending_summary_edges=(),
        )


def test_discharge_rep_edge_accepts_summary_parts() -> None:
    """An admitted repeat summary part discharges the retained self-edge."""
    outcome = _scan(_rep_table())
    assert outcome.status.value == "completed_pending_summary"
    parts = [
        _fake_part(_BASE, successors=(_BASE + 5, _BASE + 12)),
        _fake_part(_BASE + 5, summary="repeat_string", successors=(_BASE + 12,)),
        _fake_part(_BASE + 12),
    ]
    assert P.verify_pending_summary(parts, outcome) is None


def test_discharge_nonrep_self_edge_refused() -> None:
    """A non-repeat self-edge must not discharge even though it isolated."""
    outcome = _scan(_rep_table("ebfe"))
    assert outcome.status.value == "completed_pending_summary"
    parts = [
        _fake_part(_BASE, successors=(_BASE + 5, _BASE + 12)),
        _fake_part(_BASE + 5, summary="repeat_string", successors=(_BASE + 12,)),
        _fake_part(_BASE + 12),
    ]
    failure = P.verify_pending_summary(parts, outcome)
    assert failure is not None
    assert failure.reason.value == "pending_edge_not_repeat_string"


def test_discharge_override_prefix_refused() -> None:
    """Segment-override REP bytes are outside the default-form admission."""
    outcome = _scan(_rep_table("26f3ab"))
    assert outcome.status.value == "completed_pending_summary"
    parts = [
        _fake_part(_BASE, successors=(_BASE + 5, _BASE + 12)),
        _fake_part(_BASE + 5, summary="repeat_string", successors=(_BASE + 12,)),
        _fake_part(_BASE + 12),
    ]
    failure = P.verify_pending_summary(parts, outcome)
    assert failure is not None
    assert failure.reason.value == "pending_edge_not_repeat_string"


def test_discharge_missing_summary_marker_refused() -> None:
    """Repeat bytes without the lowered summary marker cannot discharge."""
    outcome = _scan(_rep_table())
    parts = [
        _fake_part(_BASE, successors=(_BASE + 5, _BASE + 12)),
        _fake_part(_BASE + 5, successors=(_BASE + 12,)),
        _fake_part(_BASE + 12),
    ]
    failure = P.verify_pending_summary(parts, outcome)
    assert failure is not None
    assert failure.reason.value == "repeat_summary_missing_in_part"


def test_discharge_residual_self_cycle_refused() -> None:
    """A surviving self-edge in the lowered graph refuses even with a marker."""
    outcome = _scan(_rep_table())
    parts = [
        _fake_part(_BASE, successors=(_BASE + 5, _BASE + 12)),
        _fake_part(_BASE + 5, summary="repeat_string", successors=(_BASE + 5, _BASE + 12)),
        _fake_part(_BASE + 12),
    ]
    failure = P.verify_pending_summary(parts, outcome)
    assert failure is not None
    assert failure.reason.value == "residual_cycle"


def _mz_case(tmp_path: Path, body: bytes) -> tuple:
    """Lower a real MZ caller/callee image through the production harness."""
    from test_binary_callee_intake import _image, _lower
    from test_dosunit_tool import _edge_function

    return _lower(
        tmp_path, _image(body), [_edge_function("demo.exe:caller", "caller", offset=512, size=7)], f"rep_{'after'}"
    )


def test_real_mz_rep_callee_reaches_consumer(tmp_path: Path) -> None:
    """Real caller CALL + ``rep stosw; ret`` body: intake pending, lowering
    discharges through the byte contract, grouped body composes a post-state."""
    from test_binary_callee_intake import CALLEE_LINEAR, _request

    body = bytes.fromhex("f3abc3")
    project, document = _mz_case(tmp_path, body)
    request = _request(project, document)
    candidate = INTAKE.intake_uncatalogued_region_candidate(
        request, window=C.ScanWindow(CALLEE_LINEAR, CALLEE_LINEAR + len(body)), budget=C.RegionScanBudget(8, 32, 64, 64)
    )
    assert candidate.status.value == "candidate_pending_summary", candidate.to_dict()
    assert candidate.scan is not None
    assert [e.linear for e in candidate.scan.pending_summary_edges] == [CALLEE_LINEAR]
    result = LOWER.lower_region_candidate(request, candidate)
    assert result.status.value == "lowered", result.to_dict()
    assert len(result.parts) == 2
    from tools.dosunit.real16_call_contracts import Real16CallLimits
    from tools.dosunit.real16_call_evidence import group_functions
    from tools.dosunit.real16_call_execution import summarize

    doc = {"functions": list(result.parts), "refusals": []}
    ctxs = group_functions(doc)
    ctx = next(iter(ctxs.values()))
    state, _session = summarize(
        doc, ctx.function_id, limits=Real16CallLimits(ret_check_timeout_ms=2000), timeout_ms=20000
    )
    assert isinstance(state.get("control_ip"), dict)


def test_real_mz_pending_source_mutation_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A span mutated after the pending scan still fails source recheck."""
    from test_binary_callee_intake import CALLEE_LINEAR, _request

    project, document = _mz_case(tmp_path, bytes.fromhex("f3abc3"))
    original = INTAKE.scan_candidate_region

    def mutate_after_scan(request: object) -> object:
        scan = original(request)
        project.loader.memory.store(CALLEE_LINEAR, bytes.fromhex("90"))
        return scan

    monkeypatch.setattr(INTAKE, "scan_candidate_region", mutate_after_scan)
    result = INTAKE.intake_uncatalogued_region_candidate(
        _request(project, document),
        window=C.ScanWindow(CALLEE_LINEAR, CALLEE_LINEAR + 3),
        budget=C.RegionScanBudget(8, 32, 64, 64),
    )
    assert result.status.value == "refused"
    assert result.source_refusal is not None
    assert result.source_refusal.reason.value == "source_changed"


def test_real_mz_fabricated_caller_target_refused(tmp_path: Path) -> None:
    """A caller that never calls the rep body never reaches the pending path."""
    from test_binary_callee_intake import CALLEE_LINEAR, _request

    project, document = _mz_case(tmp_path, bytes.fromhex("f3abc3"))
    result = INTAKE.intake_uncatalogued_region_candidate(
        _request(project, document, target=CALLEE_LINEAR + 1),
        window=C.ScanWindow(CALLEE_LINEAR, CALLEE_LINEAR + 16),
        budget=C.RegionScanBudget(8, 32, 64, 64),
    )
    assert result.status.value == "refused"
    assert result.source_refusal is not None
    assert result.source_refusal.reason.value == "target_not_source_bound"
