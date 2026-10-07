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

from collections.abc import Iterable, MutableMapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

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
    address: int
    mnemonic: str
    op_str: str


class _LinearMemory(Protocol):
    def load(self, start: int, size: int) -> bytes:
        """Read bytes from the project loader memory."""
        ...


class _ProjectLoader(Protocol):
    memory: _LinearMemory


class _CapstoneDisassembler(Protocol):
    detail: bool

    def disasm(self, code: bytes, start: int) -> Iterable[object]:
        """Decode bytes into instruction objects."""
        ...


class _ProjectArch(Protocol):
    capstone: _CapstoneDisassembler


class _LinearDecodeProject(Protocol):
    loader: _ProjectLoader
    arch: _ProjectArch


class _CapstoneBlock(Protocol):
    insns: tuple[object, ...]


class _ProjectBlock(Protocol):
    capstone: _CapstoneBlock


class _ProjectFactory(Protocol):
    def block(self, addr: int, *, opt_level: int = 0) -> _ProjectBlock:
        """Load a project block with decoded capstone instructions."""
        del opt_level
        raise NotImplementedError


class _FunctionForStringArtifact(Protocol):
    addr: int
    block_addrs_set: set[int]
    info: MutableMapping[str, object]


class _FunctionManager(Protocol):
    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Look up a function by address without requiring creation."""
        ...


class _KnowledgeBase(Protocol):
    functions: _FunctionManager


class _BlockDecodeProject(Protocol):
    factory: _ProjectFactory
    kb: _KnowledgeBase


class _CodegenCFunction(Protocol):
    addr: int


class _StringArtifactCodegen(Protocol):
    cfunc: _CodegenCFunction | None
    _inertia_string_instruction_artifact: StringInstructionArtifact


@dataclass(frozen=True, slots=True)
class StringInstructionRecord:
    """One proven x86 string-instruction fact collected from decoded instructions."""

    index: int
    family: str
    mnemonic: str
    repeat_kind: str
    width: int
    source_segment: str | None
    destination_segment: str | None
    direction_mode: str
    zero_seeded_accumulator: bool | None
    zf_sensitive: bool
    instruction_addr: int | None = None


@dataclass(frozen=True, slots=True)
class StringInstructionRefusal:
    """Reason a string-instruction artifact could not be fully trusted."""

    kind: str
    detail: str


@dataclass(frozen=True, slots=True)
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
                for rec in self.records
            ],
            "refusals": [{"kind": item.kind, "detail": item.detail} for item in self.refusals],
        }


def _decode_linear_insns(project: _LinearDecodeProject, start: int, end: int) -> tuple[object, ...]:
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


def _block_insns(project: _BlockDecodeProject, function: _FunctionForStringArtifact) -> tuple[object, ...]:
    """Collect decoded instructions from a function's known basic blocks."""
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


def _normalize_string_mnemonic(mnemonic: str) -> tuple[str, str]:
    parts = mnemonic.strip().lower().split()
    if not parts:
        return "none", ""
    if parts[0] in {"rep", "repe", "repz", "repne", "repnz"}:
        prefix = parts[0]
        base = parts[-1]
        repeat_kind = ("repz" if prefix != "rep" else "rep") if prefix in {"rep", "repe", "repz"} else "repnz"
        return repeat_kind, base
    return "none", parts[-1]


def _string_family(base: str) -> tuple[str, int, str | None, str | None, bool] | None:
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


def _width_for_base(base: str) -> int:
    if base.endswith("b"):
        return 1
    if base.endswith("w"):
        return 2
    if base.endswith("d"):
        return 4
    return 0


def _register_zero_seed(insn: object, al_zero: bool, ax_zero: bool) -> tuple[bool, bool]:
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


def _direction_state(insn: object, current: str) -> str:
    """Update string direction state from one decoded instruction."""
    mnemonic = cast(_DecodedInstruction, insn).mnemonic.strip().lower()
    if mnemonic == "cld":
        return "forward"
    if mnemonic == "std":
        return "backward"
    return current


def _records_from_insns(insns: tuple[object, ...]) -> StringInstructionArtifact:
    """Build a string-instruction artifact from decoded instruction objects."""
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
    concrete_directions = {item.direction_mode for item in records if item.direction_mode in {"forward", "backward"}}
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


def build_x86_16_string_instruction_artifact(
    project: object, function: object
) -> StringInstructionArtifact:
    """Collect string-instruction facts from a function's decoded blocks."""
    return _records_from_insns(
        _block_insns(cast(_BlockDecodeProject, project), cast(_FunctionForStringArtifact, function))
    )


def build_x86_16_string_instruction_artifact_from_linear_range(
    project: object,
    *,
    start: int,
    end: int,
) -> StringInstructionArtifact:
    """Collect string-instruction facts from a linear decoded byte range."""
    return _records_from_insns(_decode_linear_insns(cast(_LinearDecodeProject, project), start, end))


def apply_x86_16_string_instruction_artifact(project: object, codegen: object) -> bool:
    """Attach string-instruction facts at the third-party angr/codegen boundary."""
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
