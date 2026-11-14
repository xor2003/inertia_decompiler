# cython: language_level=3, infer_types=True
"""Layer: Helper boundary.

Responsibility: collect structured string-instruction facts and refusals from decoded instructions.
Forbidden: using source listings or generated C text as proof for string-instruction semantics.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable, MutableMapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast
import dataclasses

__all__ = (
    "StringInstructionArtifact",
    "StringInstructionCoverage8616",
    "StringInstructionRecord",
    "StringInstructionRefusal",
    "apply_x86_16_string_instruction_artifact",
    "build_x86_16_string_instruction_artifact",
    "build_x86_16_string_instruction_artifact_from_linear_range",
)


class StringInstructionCoverage8616(StrEnum):
    """Decoded instruction scope accounted for by a string intrinsic."""

    PARTIAL_FUNCTION = "partial-function"
    EXACT_FUNCTION = "exact-function"


class _DecodedInstruction(Protocol):
    address: cython.longlong
    mnemonic: object
    op_str: object


class _LinearMemory(Protocol):
    def load(self, start: cython.longlong, size: cython.longlong) -> object:
        """Read bytes from the project loader memory."""
        ...


class _ProjectLoader(Protocol):
    memory: _LinearMemory


class _CapstoneDisassembler(Protocol):
    detail: cython.bint

    def disasm(self, code: object, start: cython.longlong) -> Iterable[object]:
        """Decode bytes into instruction objects."""
        ...


class _ProjectArch(Protocol):
    capstone: _CapstoneDisassembler


class _LinearDecodeProject(Protocol):
    loader: _ProjectLoader
    arch: _ProjectArch


class _CapstoneBlock(Protocol):
    insns: object


class _ProjectBlock(Protocol):
    capstone: _CapstoneBlock


class _ProjectFactory(Protocol):
    def block(self, addr: cython.longlong, *, opt_level = 0) -> _ProjectBlock:
        """Load a project block with decoded capstone instructions."""
        del opt_level
        raise NotImplementedError


class _FunctionForStringArtifact(Protocol):
    addr: cython.longlong
    block_addrs_set: object
    info: MutableMapping[str, object]


class _FunctionManager(Protocol):
    def function(self, *, addr: cython.longlong, create: cython.bint = False) -> object | None:
        """Look up a function by address without requiring creation."""
        ...


class _KnowledgeBase(Protocol):
    functions: _FunctionManager


class _BlockDecodeProject(Protocol):
    factory: _ProjectFactory
    kb: _KnowledgeBase


class _CodegenCFunction(Protocol):
    addr: cython.longlong


class _StringArtifactCodegen(Protocol):
    cfunc: _CodegenCFunction | None
    _inertia_string_instruction_artifact: StringInstructionArtifact


@dataclasses.dataclass(frozen=True, )
class StringInstructionRecord:
    """One proven x86 string-instruction fact collected from decoded instructions."""

    index: cython.longlong
    family: object
    mnemonic: object
    repeat_kind: object
    width: cython.longlong
    source_segment: object
    destination_segment: object
    direction_mode: object
    zero_seeded_accumulator: bool | None
    zf_sensitive: cython.bint
    instruction_addr: int | None = None


@dataclasses.dataclass(frozen=True, )
class StringInstructionRefusal:
    """Reason a string-instruction artifact could not be fully trusted."""

    kind: object
    detail: object


@dataclasses.dataclass(frozen=True, )
class StringInstructionArtifact:
    """Collected string-instruction facts plus honest refusals."""

    records: tuple[StringInstructionRecord, ...] = ()
    refusals: tuple[StringInstructionRefusal, ...] = ()
    coverage: StringInstructionCoverage8616 = StringInstructionCoverage8616.PARTIAL_FUNCTION

    def to_dict(self) -> dict[str, object]:
        """Serialize the artifact for function metadata and diagnostics."""
        return {
            "coverage": self.coverage.value,
            "records": [
                {
                    "index": rec.index,
                    "family": rec.family,
                    "mnemonic": rec.mnemonic,
                    "repeat_kind": rec.repeat_kind,
                    "width": rec.width,
                    "source_segment": rec.source_segment,
                    "destination_segment": rec.destination_segment,
                    "direction_mode": rec.direction_mode,
                    "zero_seeded_accumulator": rec.zero_seeded_accumulator,
                    "zf_sensitive": rec.zf_sensitive,
                    "instruction_addr": rec.instruction_addr,
                }
                for rec in iter(self.records)
            ],
            "refusals": [{"kind": item.kind, "detail": item.detail} for item in iter(self.refusals)],
        }


@cython.ccall
def _decode_linear_insns(project: _LinearDecodeProject, start: cython.longlong, end: cython.longlong) -> tuple[object, ...]:
    """Decode a linear byte range through the project capstone boundary."""
    if end <= start:
        return ()
    code = bytes(project.loader.memory.load(start, end - start))
    capstone = project.arch.capstone
    previous_detail = capstone.detail
    try:
        capstone.detail = True
        return tuple(capstone.disasm(code, start))
    finally:
        capstone.detail = previous_detail


@cython.ccall
def _block_insns(project: _BlockDecodeProject, function: _FunctionForStringArtifact) -> tuple[object, ...]:
    """Collect decoded instructions from a function's known basic blocks."""
    block_addr: object
    block_addrs = tuple(sorted(function.block_addrs_set))
    if not block_addrs:
        return ()
    insns: list[object] = []
    for block_addr in block_addrs:
        try:
            block = project.factory.block(block_addr, opt_level=0)
        except Exception:
            continue
        insns.extend(block.capstone.insns)
    return tuple(insns)


@cython.ccall
def _normalize_string_mnemonic(mnemonic: object) -> tuple[str, str]:
    parts = mnemonic.strip().lower().split()
    if not parts:
        return "none", ""
    if parts[0] in {"rep", "repe", "repz", "repne", "repnz"}:
        prefix = parts[0]
        base = parts[-1]
        repeat_kind = ("repz" if prefix != "rep" else "rep") if prefix in {"rep", "repe", "repz"} else "repnz"
        return repeat_kind, base
    return "none", parts[-1]


@cython.ccall
def _string_family(base: object) -> object:
    if base.startswith("movs"):
        return "movs", _width_for_base(base), "ds", "es", False
    if base.startswith("lods"):
        return "lods", _width_for_base(base), "ds", None, False
    if base.startswith("stos"):
        return "stos", _width_for_base(base), None, "es", False
    if base.startswith("scas"):
        return "scas", _width_for_base(base), None, "es", True
    if base.startswith("cmps"):
        return "cmps", _width_for_base(base), "ds", "es", True
    if base.startswith("outs"):
        return "outs", _width_for_base(base), "ds", None, False
    if base.startswith("ins"):
        return "ins", _width_for_base(base), None, "es", False
    return None


@cython.ccall
def _width_for_base(base: object) -> cython.longlong:
    if base.endswith("b"):
        return 1
    if base.endswith("w"):
        return 2
    if base.endswith("d"):
        return 4
    return 0


@cython.ccall
def _register_zero_seed(insn: object, al_zero: cython.bint, ax_zero: cython.bint) -> tuple[cython.bint, cython.bint]:
    """Update accumulator zero-seed state from one decoded instruction."""
    decoded = cast(_DecodedInstruction, insn)
    mnemonic = decoded.mnemonic.strip().lower()
    op_str = decoded.op_str.strip().lower()
    text = f"{mnemonic} {op_str}".strip()
    if text in {"xor al, al", "mov al, 0", "mov al, 0x0"}:
        return True, ax_zero
    if text in {"xor ax, ax", "mov ax, 0", "mov ax, 0x0"}:
        return True, True
    if mnemonic in {"mov", "lea", "lodsb", "lodsw"} and op_str.startswith("al"):
        return False, ax_zero
    if mnemonic in {"mov", "lea"} and op_str.startswith("ax"):
        return False, False
    return al_zero, ax_zero


@cython.ccall
def _direction_state(insn: object, current: object) -> object:
    """Update string direction state from one decoded instruction."""
    mnemonic = cast(_DecodedInstruction, insn).mnemonic.strip().lower()
    if mnemonic == "cld":
        return "forward"
    if mnemonic == "std":
        return "backward"
    return current


@cython.ccall
def _records_from_insns(insns: object) -> StringInstructionArtifact:
    """Build a string-instruction artifact from decoded instruction objects."""
    info: object
    insn: object
    if not insns:
        return StringInstructionArtifact(
            refusals=(StringInstructionRefusal("no_instruction_signal", "no instruction stream available"),)
        )

    records: list[StringInstructionRecord] = []
    exact_function_coverage = True
    direction_mode = "unknown"
    al_zero = False
    ax_zero = False
    for insn in insns:
        decoded = cast(_DecodedInstruction, insn)
        direction_mode = _direction_state(insn, direction_mode)
        al_zero, ax_zero = _register_zero_seed(insn, al_zero, ax_zero)
        repeat_kind, base = _normalize_string_mnemonic(decoded.mnemonic)
        info = _string_family(base)
        if info is None:
            mnemonic = decoded.mnemonic.strip().lower()
            operand_text = decoded.op_str.strip().lower()
            destination = operand_text.split(",", maxsplit=1)[0].strip()
            setup_registers = {"al", "ax", "eax", "cx", "ecx", "si", "esi", "di", "edi", "ds", "es"}
            setup_instruction = (
                mnemonic in {"mov", "xor"}
                and destination in setup_registers
                and "[" not in operand_text
                and "]" not in operand_text
            )
            if mnemonic not in {"cld", "std", "ret", "retn"} and not setup_instruction:
                exact_function_coverage = False
            continue
        try:
            instruction_addr = int(decoded.address)
        except (AttributeError, TypeError, ValueError):
            instruction_addr = None
        family, width, source_segment, destination_segment, zf_sensitive = info
        zero_seed = None
        if family == "scas":
            zero_seed = al_zero if width == 1 else ax_zero
        records.append(
            StringInstructionRecord(
                index=len(records),
                family=family,
                mnemonic=base,
                repeat_kind=repeat_kind,
                width=width,
                source_segment=source_segment,
                destination_segment=destination_segment,
                direction_mode=direction_mode,
                zero_seeded_accumulator=zero_seed,
                zf_sensitive=zf_sensitive,
                instruction_addr=instruction_addr,
            )
        )

    if not records:
        return StringInstructionArtifact(
            refusals=(
                StringInstructionRefusal("no_string_signal", "instruction stream contains no x86 string instructions"),
            )
        )
    refusals: list[StringInstructionRefusal] = []
    concrete_directions = {item.direction_mode for item in iter(records) if item.direction_mode in {"forward", "backward"}}
    if len(concrete_directions) > 1:
        refusals.append(
            StringInstructionRefusal(
                "mixed_direction_signal",
                "string instruction stream contains both forward and backward direction evidence",
            )
        )
    return StringInstructionArtifact(
        records=tuple(records),
        refusals=tuple(refusals),
        coverage=(
            StringInstructionCoverage8616.EXACT_FUNCTION
            if exact_function_coverage
            else StringInstructionCoverage8616.PARTIAL_FUNCTION
        ),
    )


@cython.ccall
def build_x86_16_string_instruction_artifact(
    project: object, function: object
) -> StringInstructionArtifact:
    """Collect string-instruction facts from a function's decoded blocks."""
    return _records_from_insns(
        _block_insns(cast(_BlockDecodeProject, project), cast(_FunctionForStringArtifact, function))
    )


@cython.ccall
def build_x86_16_string_instruction_artifact_from_linear_range(
    project: object,
    *,
    start: cython.longlong,
    end: cython.longlong,
) -> StringInstructionArtifact:
    """Collect string-instruction facts from a linear decoded byte range."""
    return _records_from_insns(_decode_linear_insns(cast(_LinearDecodeProject, project), start, end))


@cython.ccall
def apply_x86_16_string_instruction_artifact(project: object, codegen: object) -> cython.bint:
    """Attach string-instruction facts at the third-party angr/codegen boundary."""
    cfunc: object
    function: object
    typed_project = cast(_BlockDecodeProject, project)
    typed_codegen = cast(_StringArtifactCodegen, codegen)
    cfunc = typed_codegen.cfunc
    if cfunc is None:
        return False
    function = typed_project.kb.functions.function(addr=cfunc.addr, create=False)
    if function is None:
        return False
    artifact = build_x86_16_string_instruction_artifact(project, function)
    typed_codegen._inertia_string_instruction_artifact = artifact
    cast(_FunctionForStringArtifact, function).info["x86_16_string_instruction_artifact"] = artifact.to_dict()
    return False
