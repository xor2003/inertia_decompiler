"""Layer: Frontend tests.

Responsibility: enforce 80386EX real-mode decode and whole-instruction lift coverage.
"""

from __future__ import annotations

import importlib.util
import io
import os
import sys
from pathlib import Path

import angr
import pytest
import pyvex
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from archinfo import ArchX86

_HELPER_PATH = Path(__file__).with_name("_x86_16_borrow_80386.py")
_HELPER_SPEC = importlib.util.spec_from_file_location("x86_16_borrow_80386_helper", _HELPER_PATH)
assert _HELPER_SPEC is not None and _HELPER_SPEC.loader is not None
_HELPER_MODULE = importlib.util.module_from_spec(_HELPER_SPEC)
sys.modules[_HELPER_SPEC.name] = _HELPER_MODULE
_HELPER_SPEC.loader.exec_module(_HELPER_MODULE)
Borrow80386Case = _HELPER_MODULE.Borrow80386Case
load_borrow_80386_lifter_corpus = _HELPER_MODULE.load_borrow_80386_lifter_corpus
load_borrow_80386_lifter_cases = _HELPER_MODULE.load_borrow_80386_lifter_cases


def _project_from_bytes(code: bytes) -> angr.Project:
    """Create a segmented real-mode project for one hardware instruction case."""
    return angr.Project(
        io.BytesIO(code),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
    )


def _lift_case(case: Borrow80386Case) -> None:
    """Require one complete instruction to decode and materialize VEX effects."""
    project = _project_from_bytes(case.instruction_bytes)
    block = project.factory.block(0x1000, size=len(case.instruction_bytes), num_inst=1, opt_level=0)
    assert block.size >= 1, case.name
    assert block.vex is not None, case.name
    assert block.vex.statements is not None, case.name
    assert block.vex.jumpkind != "Ijk_NoDecode", case.name
    assert len(block.capstone.insns) >= 1, case.name


def _lift_case_direct(case: Borrow80386Case, arch: Arch86_16) -> None:
    """Lift one corpus case directly through PyVEX without per-case Project construction."""
    irsb = pyvex.lift(case.instruction_bytes, 0x1000, arch, max_inst=1, opt_level=0)
    assert irsb.size >= 1, case.name
    assert irsb.statements is not None, case.name
    assert irsb.jumpkind != "Ijk_NoDecode", case.name


def test_borrow_80386_loader_consumes_and_deduplicates_hardware_cases() -> None:
    """The acceptance corpus must remain large, deterministic, and deduplicated."""
    corpus = load_borrow_80386_lifter_corpus()
    assert corpus.total_cases > 100_000
    assert corpus.filtered_cases > 100_000
    assert corpus.deduped_cases == len(corpus.cases)
    assert corpus.deduped_cases > 50_000
    assert corpus.deduped_cases < corpus.filtered_cases
    assert corpus.skipped_lock_cases > 0
    assert all(" lock " not in f" {case.name.lower()} " for case in corpus.cases)
    sample = load_borrow_80386_lifter_cases(512)
    assert {case.source_path for case in sample} == {case.source_path for case in corpus.cases}
    assert {case.mnemonic_key for case in sample} == {case.mnemonic_key for case in corpus.cases}


@pytest.mark.parametrize("case", load_borrow_80386_lifter_cases(512))
def test_borrow_80386_real_mode_sample_whole_instruction_lifts(case: Borrow80386Case) -> None:
    """Lift an even sample across all opcode and width-form files."""
    _lift_case(case)


@pytest.mark.parametrize(
    "code,expected_size",
    (
        (bytes.fromhex("66 91"), 2),
        (bytes.fromhex("66 f7 c0 78 56 34 12"), 7),
        (bytes.fromhex("67 66 8b 44 88 10"), 6),
        (bytes.fromhex("66 b8 78 56 34 12"), 6),
    ),
)
def test_80386_width_forms_lift_exactly_one_complete_instruction(code: bytes, expected_size: int) -> None:
    """Regression-check operand override, SIB addressing, and 32-bit immediates."""
    block = _project_from_bytes(code).factory.block(0x1000, num_inst=1, opt_level=0)
    assert block.size == expected_size
    assert block.vex.jumpkind != "Ijk_NoDecode"


def test_arch_exposes_80386_general_register_names() -> None:
    """Architecture consumers must resolve every 80386 general register name."""
    arch = Arch86_16()
    for name in ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"):
        assert name in arch.registers


def test_clts_lifts_a_cr0_task_switched_bit_clear() -> None:
    """Require CLTS to decode and materialize a write to modeled CR0 state."""
    project = _project_from_bytes(b"\x0f\x06")
    block = project.factory.block(0x1000, size=2, num_inst=1, opt_level=0)
    assert block.vex.jumpkind != "Ijk_NoDecode"
    cr0_offset = project.arch.get_register_offset("cr0")
    assert any(statement.tag == "Ist_Put" and statement.offset == cr0_offset for statement in block.vex.statements)


@pytest.mark.parametrize(
    "code",
    (
        bytes.fromhex("0f a0"),
        bytes.fromhex("0f a1"),
        bytes.fromhex("0f a8"),
        bytes.fromhex("0f a9"),
        bytes.fromhex("66 0e"),
        bytes.fromhex("66 0f a0"),
        bytes.fromhex("66 0f a1"),
        bytes.fromhex("66 0f a8"),
        bytes.fromhex("66 0f a9"),
        bytes.fromhex("66 40"),
        bytes.fromhex("66 48"),
        bytes.fromhex("66 6d"),
        bytes.fromhex("66 6f"),
        bytes.fromhex("66 a5"),
        bytes.fromhex("66 a7"),
        bytes.fromhex("66 ab"),
        bytes.fromhex("66 ad"),
        bytes.fromhex("66 af"),
        bytes.fromhex("66 e0 00"),
        bytes.fromhex("66 e1 00"),
        bytes.fromhex("66 e3 00"),
        bytes.fromhex("67 66 a5"),
        bytes.fromhex("67 66 e3 00"),
        bytes.fromhex("cd 35"),
        bytes.fromhex("cd 38"),
        bytes.fromhex("cd 39"),
        bytes.fromhex("cd 3d"),
        bytes.fromhex("cd ff"),
    ),
)
def test_remaining_80386_real_mode_families_materialize_vex(code: bytes) -> None:
    """Regression-check every valid family found by the exhaustive corpus audit."""
    irsb = pyvex.lift(code, 0x1000, Arch86_16(), max_inst=1, opt_level=0)
    assert irsb.size == len(code)
    assert irsb.jumpkind != "Ijk_NoDecode"
    assert irsb.statements


@pytest.mark.parametrize(
    "code,index_name",
    ((bytes.fromhex("66 a5"), "si"), (bytes.fromhex("67 66 a5"), "esi")),
)
def test_dword_string_address_size_selects_index_width(code: bytes, index_name: str) -> None:
    """Operand-size 32 must not force 32-bit string index registers."""
    arch = Arch86_16()
    irsb = pyvex.lift(code, 0x1000, arch, max_inst=1, opt_level=0)
    index_offset = arch.get_register_offset(index_name)
    assert any(statement.tag == "Ist_Put" and statement.offset == index_offset for statement in irsb.statements)


@pytest.mark.parametrize(
    "code",
    (
        # Unsigned and signed immediate boundaries.
        bytes.fromhex("cd 00"),
        bytes.fromhex("cd 7f"),
        bytes.fromhex("cd 80"),
        bytes.fromhex("cd ff"),
        bytes.fromhex("66 6a 80"),
        bytes.fromhex("66 6a 7f"),
        bytes.fromhex("66 68 00 00 00 80"),
        bytes.fromhex("66 68 ff ff ff 7f"),
        # Shift-count boundaries around the 80386 five-bit mask.
        bytes.fromhex("66 c1 e0 00"),
        bytes.fromhex("66 c1 e0 01"),
        bytes.fromhex("66 c1 e0 1f"),
        bytes.fromhex("66 c1 e0 20"),
        bytes.fromhex("66 c1 e0 ff"),
        bytes.fromhex("66 0f a4 c8 00"),
        bytes.fromhex("66 0f a4 c8 1f"),
        bytes.fromhex("66 0f ac c8 20"),
        bytes.fromhex("66 0f ac c8 ff"),
        # Register-code endpoints and carry-preserving INC/DEC.
        bytes.fromhex("66 40"),
        bytes.fromhex("66 47"),
        bytes.fromhex("66 48"),
        bytes.fromhex("66 4f"),
        bytes.fromhex("66 b8 00 00 00 00"),
        bytes.fromhex("66 bf ff ff ff ff"),
        # MOVZX/MOVSX source widths and register/memory forms.
        bytes.fromhex("66 0f b6 c0"),
        bytes.fromhex("66 0f be ff"),
        bytes.fromhex("66 0f b7 06 ff ff"),
        bytes.fromhex("66 0f bf 3e 00 80"),
        # Relative-displacement and address-size boundaries.
        bytes.fromhex("66 e0 80"),
        bytes.fromhex("66 e1 7f"),
        bytes.fromhex("66 e3 80"),
        bytes.fromhex("67 66 e3 7f"),
        bytes.fromhex("66 a5"),
        bytes.fromhex("67 66 a5"),
        # New segment-register stack forms at both operand sizes.
        bytes.fromhex("0f a0"),
        bytes.fromhex("0f a9"),
        bytes.fromhex("66 0f a0"),
        bytes.fromhex("66 0f a9"),
    ),
)
def test_80386_real_mode_edge_values_whole_instruction_pyvex(code: bytes) -> None:
    """Lift one complete instruction for each high-risk 80386 encoding boundary."""
    irsb = pyvex.lift(code, 0x1000, Arch86_16(), max_inst=1, opt_level=0)
    assert irsb.size == len(code)
    assert irsb.instructions == 1
    assert irsb.jumpkind != "Ijk_NoDecode"
    assert irsb.statements


def test_pyvex_reference_lifts_equivalent_native_32_bit_instruction() -> None:
    """Use native PyVEX as a whole-instruction reference for a register-only 32-bit form."""
    reference = pyvex.lift(bytes.fromhex("91"), 0x1000, ArchX86(), max_inst=1, opt_level=0)
    candidate = _project_from_bytes(bytes.fromhex("66 91")).factory.block(0x1000, num_inst=1, opt_level=0).vex
    assert reference.jumpkind == candidate.jumpkind == "Ijk_Boring"
    assert any(statement.tag == "Ist_Put" for statement in reference.statements)
    assert any(statement.tag == "Ist_Put" for statement in candidate.statements)


@pytest.mark.parametrize(
    "code",
    (bytes.fromhex("f7f4"), bytes.fromhex("66f7f4"), bytes.fromhex("f6fa"), bytes.fromhex("66f7ff")),
)
def test_division_emits_guarded_zero_and_overflow_fault_exits(code: bytes) -> None:
    """Require x86 divide faults without changing the normal successor jumpkind."""
    irsb = pyvex.lift(code, 0x1000, Arch86_16(), max_inst=1, opt_level=0)
    fault_exits = [
        statement
        for statement in irsb.statements
        if isinstance(statement, pyvex.stmt.Exit) and statement.jumpkind == "Ijk_SigFPE_IntDiv"
    ]
    assert irsb.jumpkind == "Ijk_Boring"
    assert len(fault_exits) == 2


def test_address32_memory_operand_omits_out_of_scope_segment_limit_fault() -> None:
    """Keep excluded segment-limit faults out of practical-DOS control-flow IR."""
    irsb = pyvex.lift(b"\x66\x67\x8e\x97\x72\x91\xff\xff", 0x1000, Arch86_16(), max_inst=1, opt_level=0)
    fault_exits = [
        statement
        for statement in irsb.statements
        if isinstance(statement, pyvex.stmt.Exit) and statement.jumpkind == "Ijk_SigSEGV"
    ]
    assert irsb.jumpkind == "Ijk_Boring"
    assert irsb.instructions == 1
    assert not fault_exits


def test_invalid_lock_encoding_emits_illegal_instruction_fault() -> None:
    """Reject LOCK on a non-lockable PUSH instead of executing the stripped opcode."""
    irsb = pyvex.lift(b"\xf0\x68\xa7\x2f", 0x1000, Arch86_16(), max_inst=1, opt_level=0)
    fault_exits = [
        statement
        for statement in irsb.statements
        if isinstance(statement, pyvex.stmt.Exit) and statement.jumpkind == "Ijk_SigILL"
    ]
    assert irsb.jumpkind == "Ijk_Boring"
    assert len(fault_exits) == 1


def test_reserved_pop_extension_emits_illegal_instruction_fault() -> None:
    """Reject reserved 8F opcode extensions instead of decoding them as POP."""
    irsb = pyvex.lift(bytes.fromhex("8f 99 c5 32"), 0x1000, Arch86_16(), max_inst=1, opt_level=0)
    fault_exits = [
        statement
        for statement in irsb.statements
        if isinstance(statement, pyvex.stmt.Exit) and statement.jumpkind == "Ijk_SigILL"
    ]
    assert irsb.jumpkind == "Ijk_Boring"
    assert len(fault_exits) == 1


def test_borrow_80386_full_real_mode_corpus_lifts_opt_in() -> None:
    """Exhaustively lift every deduplicated hardware case when explicitly requested."""
    if os.environ.get("INERTIA_RUN_FULL_80386_LIFTER_CORPUS") != "1":
        pytest.skip("full deduplicated 80386 corpus is exhaustive and opt-in")
    cases = load_borrow_80386_lifter_cases()
    start = int(os.environ.get("INERTIA_80386_CORPUS_START", "0"))
    limit = int(os.environ.get("INERTIA_80386_CORPUS_LIMIT", "0"))
    selected = cases[start : start + limit] if limit > 0 else cases[start:]
    failures: list[str] = []
    arch = Arch86_16()
    for case in selected:
        try:
            _lift_case_direct(case, arch)
        except (Exception, SystemExit) as exc:
            failures.append(f"{case.opcode_key}: {case.name}: {type(exc).__name__}: {exc}")
    assert not failures, "\n".join(failures)
