"""Source-bound uncatalogued near-RET leaf intake regressions on actual MZ bytes.

Each fixture lowers real machine code to fresh full-state SSA documents whose
catalog deliberately omits the callee.  ``intake_uncatalogued_leaf`` must admit
the leaf only from verified CALL bytes plus a bounded terminal-RET decode, and
must refuse stale, fabricated, colliding, unsupported or over-budget evidence.
"""

from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parent))

from test_dosunit_tool import _edge_function, _mz_exe

from tools.dosunit import straightline_ssa as S
from tools.dosunit.binary_callee_intake import (
    IntakeBudget,
    IntakeRefusalReason,
    IntakeRequest,
    IntakeResult,
    IntakeStatus,
    intake_uncatalogued_leaf,
)
from tools.dosunit.callee_proof_scope import complete_leaf_block
from tools.dosunit.real16_call_evidence import group_functions

CALLER_OFFSET = 0x200
CALLEE_OFFSET = 0x230
CALLEE_LINEAR = 0x1000 + CALLEE_OFFSET
CALLEE_BODY = bytes.fromhex("b83412c3")  # mov ax, 0x1234 ; ret


def _image(callee_body: bytes = CALLEE_BODY, *, size: int = 0x300) -> bytes:
    """Caller @0x200: mov dx,1 ; call 0x0230 (rel 0x002a) ; ret; callee bytes."""
    image = bytearray(size)
    image[CALLER_OFFSET : CALLER_OFFSET + 7] = bytes.fromhex("ba0100e82a00c3")
    image[CALLEE_OFFSET : CALLEE_OFFSET + len(callee_body)] = callee_body
    return bytes(image)


def _lower(
    tmp_path: Path,
    image: bytes,
    functions: list[dict[str, object]],
    tag: str,
) -> tuple:
    exe = tmp_path / f"{tag}.exe"
    exe.write_bytes(_mz_exe(image))
    project = S._load_lifter_project(exe)
    catalog = {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": functions,
        "diagnostics": [],
    }
    document = S.lower_straightline_ssa_document(
        exe_path=exe,
        functions_catalog=catalog,
        output_regs=tuple(S.INTERNAL_STATE_REGS),
        lifter_project=project,
        max_blocks_per_function=32,
        follow_call_fallthrough=True,
    )
    return project, document


def _request(project, document: dict, *, target: int = CALLEE_LINEAR) -> IntakeRequest:
    return IntakeRequest(
        project=project,
        document=document,
        caller_function_key="demo.exe:caller",
        caller_block_delta=0,
        target_linear=target,
    )


def _intake(
    tmp_path: Path,
    callee_body: bytes = CALLEE_BODY,
    *,
    budget: IntakeBudget | None = None,
    **kwargs: object,
) -> IntakeResult:
    project, document = _lower(
        tmp_path,
        _image(callee_body),
        [_edge_function("demo.exe:caller", "caller", offset=CALLER_OFFSET, size=7)],
        str(kwargs.pop("tag", "case")),
    )
    return intake_uncatalogued_leaf(_request(project, document, **kwargs), budget=budget)


def test_intake_admits_uncatalogued_leaf(tmp_path: Path) -> None:
    result = _intake(tmp_path)
    assert result.status is IntakeStatus.ADMITTED, result.refusal
    assert len(result.parts) == 1
    part = result.parts[0]
    assert complete_leaf_block(part)
    source = part["source"]
    assert source["function_machine_code_size"] == len(CALLEE_BODY)
    assert source["machine_code_sha256"] == hashlib.sha256(CALLEE_BODY).hexdigest()
    assert part["function_entry"]["linear"] == "0x1230"
    assert part["function_entry"]["ip"] == "0x0230"
    assert part["part"]["entry_delta"] == "0x0000"
    assert set(S._ssa_register_widths()) <= set(part["outputs"])
    receipt = result.receipt
    assert receipt is not None
    assert receipt.body.size == len(CALLEE_BODY)
    assert receipt.body.bytes_hex == CALLEE_BODY.hex()
    assert receipt.body.sha256 == hashlib.sha256(CALLEE_BODY).hexdigest()
    assert receipt.body.target_linear == CALLEE_LINEAR
    assert receipt.body.terminal_opcode == 0xC3
    assert receipt.size_origin == "terminal_control_closure"
    assert receipt.call_site.site_linear == 0x1203
    assert receipt.call_site.bytes_hex == "e82a00"
    assert receipt.call_site.computed_target == CALLEE_LINEAR
    assert receipt.call_site.fallthrough_linear == 0x1206
    assert receipt.image_sha256 == hashlib.sha256((tmp_path / "case.exe").read_bytes()).hexdigest()
    assert receipt.leaf_complete and not receipt.effects
    assert result.function["size"] == len(CALLEE_BODY)


def test_admitted_parts_group_into_dependency_index(tmp_path: Path) -> None:
    project, document = _lower(
        tmp_path,
        _image(),
        [_edge_function("demo.exe:caller", "caller", offset=CALLER_OFFSET, size=7)],
        "grouped",
    )
    result = intake_uncatalogued_leaf(_request(project, document))
    assert result.admitted, result.refusal
    merged = dict(document)
    merged["functions"] = [*document["functions"], *result.parts]
    contexts = group_functions(merged)
    callee = next(c for c in contexts.values() if c.entry_linear == CALLEE_LINEAR)
    assert callee.body_size == len(CALLEE_BODY)


def test_ret_only_and_cleanup_ret_bodies(tmp_path: Path) -> None:
    for body in (bytes.fromhex("c3"), bytes.fromhex("c20400")):
        result = _intake(tmp_path, body, tag=f"ret_{body.hex()}")
        assert result.status is IntakeStatus.ADMITTED, (body.hex(), result.refusal)
        assert result.receipt.body.size == len(body)


def test_near32_call_admits(tmp_path: Path) -> None:
    image = bytearray(0x300)
    # caller @0x200: mov dx,1 ; 66 e8 rel32 (next 0x1209 -> rel 0x0027) ; ret
    image[CALLER_OFFSET : CALLER_OFFSET + 10] = bytes.fromhex("ba010066e827000000c3")
    image[CALLEE_OFFSET : CALLEE_OFFSET + len(CALLEE_BODY)] = CALLEE_BODY
    project, document = _lower(
        tmp_path,
        bytes(image),
        [_edge_function("demo.exe:caller", "caller", offset=CALLER_OFFSET, size=10)],
        "near32",
    )
    result = intake_uncatalogued_leaf(_request(project, document))
    assert result.status is IntakeStatus.ADMITTED, result.refusal
    assert result.receipt.call_site.frame_kind == "near32"
    assert result.receipt.call_site.bytes_hex == "66e827000000"


def test_changed_body_bytes_change_receipt(tmp_path: Path) -> None:
    first = _intake(tmp_path, CALLEE_BODY, tag="first")
    second = _intake(tmp_path, bytes.fromhex("b87856c3"), tag="second")  # mov ax,0x5678
    assert first.admitted and second.admitted
    assert first.receipt.body.sha256 != second.receipt.body.sha256
    assert first.parts[0]["source"]["machine_code_sha256"] != (second.parts[0]["source"]["machine_code_sha256"])


def test_stale_document_call_bytes_refused(tmp_path: Path) -> None:
    project, document = _lower(
        tmp_path,
        _image(),
        [_edge_function("demo.exe:caller", "caller", offset=CALLER_OFFSET, size=7)],
        "stale_doc",
    )
    stale = copy.deepcopy(document)
    for part in stale["functions"]:
        if part.get("source", {}).get("jumpkind") == "Ijk_Call":
            part["source"]["instructions"][-1]["bytes"] = "e85d00"  # disp 0x5d
    result = intake_uncatalogued_leaf(_request(project, stale))
    assert result.status is IntakeStatus.REFUSED
    assert result.refusal.reason is IntakeRefusalReason.CALL_BYTES_MISMATCH


def test_changed_call_bytes_refused(tmp_path: Path) -> None:
    project, document = _lower(
        tmp_path,
        _image(),
        [_edge_function("demo.exe:caller", "caller", offset=CALLER_OFFSET, size=7)],
        "fresh",
    )
    del project
    # Rebuilt binary: same shape, call now targets 0x0260 (disp 0x005a).
    image = bytearray(_image())
    image[CALLER_OFFSET + 3 : CALLER_OFFSET + 6] = bytes.fromhex("e85a00")
    image[0x260:0x264] = CALLEE_BODY
    moved_exe = tmp_path / "moved.exe"
    moved_exe.write_bytes(_mz_exe(bytes(image)))
    moved_project = S._load_lifter_project(moved_exe)
    result = intake_uncatalogued_leaf(_request(moved_project, document))
    assert result.status is IntakeStatus.REFUSED
    assert result.refusal.reason is IntakeRefusalReason.CALL_BYTES_MISMATCH


def test_fabricated_transfer_target_refused(tmp_path: Path) -> None:
    project, document = _lower(
        tmp_path,
        _image(),
        [_edge_function("demo.exe:caller", "caller", offset=CALLER_OFFSET, size=7)],
        "fabricated",
    )
    fake = copy.deepcopy(document)
    for part in fake["functions"]:
        if part.get("source", {}).get("jumpkind") == "Ijk_Call":
            part["source"]["transfer"]["target"]["raw"] = "0x1240"
    result = intake_uncatalogued_leaf(_request(project, fake))
    assert result.status is IntakeStatus.REFUSED
    assert result.refusal.reason is IntakeRefusalReason.CALL_TARGET_MISMATCH


def test_request_target_not_source_bound(tmp_path: Path) -> None:
    project, document = _lower(
        tmp_path,
        _image(),
        [_edge_function("demo.exe:caller", "caller", offset=CALLER_OFFSET, size=7)],
        "unbound",
    )
    result = intake_uncatalogued_leaf(_request(project, document, target=0x1240))
    assert result.status is IntakeStatus.REFUSED
    assert result.refusal.reason is IntakeRefusalReason.TARGET_NOT_SOURCE_BOUND


def test_caller_part_missing_and_non_call_delta(tmp_path: Path) -> None:
    project, document = _lower(
        tmp_path,
        _image(),
        [_edge_function("demo.exe:caller", "caller", offset=CALLER_OFFSET, size=7)],
        "missing",
    )
    result = intake_uncatalogued_leaf(IntakeRequest(project, document, "demo.exe:absent", 0, CALLEE_LINEAR))
    assert result.refusal.reason is IntakeRefusalReason.CALLER_PART_MISSING
    # Delta 6 is the caller's terminal RET block, not a CALL.
    result = intake_uncatalogued_leaf(IntakeRequest(project, document, "demo.exe:caller", 6, CALLEE_LINEAR))
    assert result.status is IntakeStatus.REFUSED
    assert result.refusal.reason is IntakeRefusalReason.SOURCE_CALL_NOT_ADMITTED


def test_far_call_site_refused(tmp_path: Path) -> None:
    image = bytearray(0x300)
    # caller @0x200: mov dx,1 ; 9a 30 02 00 10 (lcall 0x1000:0x0230) ; ret
    image[CALLER_OFFSET : CALLER_OFFSET + 9] = bytes.fromhex("ba01009a30020010c3")
    image[CALLEE_OFFSET : CALLEE_OFFSET + len(CALLEE_BODY)] = CALLEE_BODY
    project, document = _lower(
        tmp_path,
        bytes(image),
        [_edge_function("demo.exe:caller", "caller", offset=CALLER_OFFSET, size=9)],
        "farcall",
    )
    call_delta = next(
        S._optional_int(p["part"]["entry_delta"])
        for p in document["functions"]
        if p["source"]["jumpkind"] == "Ijk_Call"
    )
    result = intake_uncatalogued_leaf(IntakeRequest(project, document, "demo.exe:caller", call_delta, CALLEE_LINEAR))
    assert result.status is IntakeStatus.REFUSED
    assert result.refusal.reason is IntakeRefusalReason.CALL_OPCODE_UNSUPPORTED


@pytest.mark.parametrize(
    ("body", "reason"),
    [
        (bytes.fromhex("b8341290"), IntakeRefusalReason.BODY_UNTERMINATED),  # mov;nop;zeros
        (bytes.fromhex("eb02c3c3"), IntakeRefusalReason.BODY_BRANCH),  # jmp +2
        (bytes.fromhex("7402c3"), IntakeRefusalReason.BODY_ALTERNATE_EXITS),  # jz +2
        (bytes.fromhex("e80000c3"), IntakeRefusalReason.BODY_NESTED_CALL),  # call $+3
        (bytes.fromhex("cd20"), IntakeRefusalReason.BODY_INTERRUPT),  # int 0x20
        (bytes.fromhex("e460c3"), IntakeRefusalReason.BODY_ENVIRONMENT_EFFECT),  # in al,0x60
        (bytes.fromhex("e660c3"), IntakeRefusalReason.BODY_ENVIRONMENT_EFFECT),  # out 0x60,al
        (bytes.fromhex("f7f3c3"), IntakeRefusalReason.BODY_TRAP_EXITS),  # div bx;ret
        (bytes.fromhex("cb"), IntakeRefusalReason.BODY_TERMINAL_NOT_NEAR_RET),  # retf
        (bytes.fromhex("cf"), IntakeRefusalReason.BODY_TERMINAL_NOT_NEAR_RET),  # iret
        (bytes.fromhex("ffe0"), IntakeRefusalReason.BODY_INDIRECT_CONTROL),  # jmp ax
    ],
)
def test_unsupported_bodies_refuse(tmp_path: Path, body: bytes, reason: IntakeRefusalReason) -> None:
    result = _intake(tmp_path, body, tag=f"body_{body.hex()}")
    assert result.status is IntakeStatus.REFUSED
    assert result.refusal.reason is reason, result.refusal
    assert not result.parts and result.receipt is None


def test_budget_refusals(tmp_path: Path) -> None:
    result = _intake(tmp_path, CALLEE_BODY, tag="insn_budget", budget=IntakeBudget(max_instructions=1))
    assert result.status is IntakeStatus.REFUSED
    assert result.refusal.reason is IntakeRefusalReason.BODY_BUDGET_EXCEEDED
    # The byte bound is a scan bound, never a body size: a truncated window
    # without the terminal RET reports the missing terminal, not a body.
    result = _intake(tmp_path, CALLEE_BODY, tag="byte_budget", budget=IntakeBudget(max_body_bytes=3))
    assert result.status is IntakeStatus.REFUSED
    assert result.refusal.reason is IntakeRefusalReason.BODY_UNTERMINATED


def test_low16_collision_refused(tmp_path: Path) -> None:
    # Decoy in paragraph 0x0100 at offset 0xF230: entry linear 0x2000+0xF230 =
    # 0x11230 shares the requested target's low16 without sharing its full
    # loader-linear identity, so the low16 projection is ambiguous.
    image = bytearray(_image(size=0x11000))
    image[0x10230:0x10231] = b"\xc3"
    decoy = _edge_function("demo.exe:decoy", "decoy", offset=0xF230, size=1)
    decoy["entry"]["segment_para"] = "0x0100"
    decoy["entry"]["segment"] = "seg_0100"
    project, document = _lower(
        tmp_path,
        bytes(image),
        [
            _edge_function("demo.exe:caller", "caller", offset=CALLER_OFFSET, size=7),
            decoy,
        ],
        "collision",
    )
    result = intake_uncatalogued_leaf(_request(project, document))
    assert result.status is IntakeStatus.REFUSED
    assert result.refusal.reason is IntakeRefusalReason.TARGET_LOW16_COLLISION


def test_catalogued_target_refused(tmp_path: Path) -> None:
    project, document = _lower(
        tmp_path,
        _image(),
        [
            _edge_function("demo.exe:caller", "caller", offset=CALLER_OFFSET, size=7),
            _edge_function("demo.exe:callee", "callee", offset=CALLEE_OFFSET, size=len(CALLEE_BODY)),
        ],
        "catalogued",
    )
    result = intake_uncatalogued_leaf(_request(project, document))
    assert result.status is IntakeStatus.REFUSED
    assert result.refusal.reason is IntakeRefusalReason.TARGET_ALREADY_CATALOGUED


def test_unmapped_target_refused(tmp_path: Path) -> None:
    # A real CALL whose decoded target lands outside the loaded image: at
    # site 0x1203 the rel16 -0x7876 reaches loader address 0x9990.
    image = bytearray(_image())
    image[CALLER_OFFSET + 3 : CALLER_OFFSET + 6] = bytes.fromhex("e88a87")
    project, document = _lower(
        tmp_path,
        bytes(image),
        [_edge_function("demo.exe:caller", "caller", offset=CALLER_OFFSET, size=7)],
        "unmapped",
    )
    result = intake_uncatalogued_leaf(_request(project, document, target=0x9990))
    assert result.status is IntakeStatus.REFUSED
    assert result.refusal.reason is IntakeRefusalReason.TARGET_DOMAIN_UNMAPPED
