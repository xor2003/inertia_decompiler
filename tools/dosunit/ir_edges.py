from __future__ import annotations  # noqa: D100

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tools.dosunit.model import DosUnitError, normalize_hex, parse_int

REG16 = ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di")
REG8 = ("al", "cl", "dl", "bl", "ah", "ch", "dh", "bh")
SUPPORTED_BRANCH_OPS = {
    0x72: "ult",
    0x73: "uge",
    0x74: "eq",
    0x75: "ne",
    0x76: "ule",
    0x77: "ugt",
}
NEAR_BRANCH_OPS = {
    0x82: "ult",
    0x83: "uge",
    0x84: "eq",
    0x85: "ne",
    0x86: "ule",
    0x87: "ugt",
}
BRANCH_MNEMONICS = {
    "jb": "ult",
    "jnae": "ult",
    "jc": "ult",
    "jae": "uge",
    "jnb": "uge",
    "jnc": "uge",
    "je": "eq",
    "jz": "eq",
    "jne": "ne",
    "jnz": "ne",
    "jbe": "ule",
    "jna": "ule",
    "ja": "ugt",
    "jnbe": "ugt",
}
CAPSTONE_OP_REG = 1
CAPSTONE_OP_IMM = 2
CAPSTONE_OP_MEM = 3
LIFTER_SOURCE = "lifter_vex"
BYTE_SOURCE = "byte_decoder"


@dataclass(frozen=True)
class Operand:  # noqa: D101
    kind: str
    value: str | int
    width: int = 16

    def text(self) -> str:  # noqa: D102
        if self.kind == "imm":
            return str(normalize_hex(self.value, width=2 if self.width == 8 else 4))
        return str(self.value)


@dataclass(frozen=True)
class ConditionIR:  # noqa: D101
    kind: str
    left: Operand
    right: Operand | None

    def predicate_text(self) -> str:  # noqa: D102
        if self.kind in {"test_zero", "test_nonzero"} and self.right is not None:
            op = "==" if self.kind == "test_zero" else "!="
            return f"({self.left.text()} & {self.right.text()}) {op} 0x0000"
        if self.right is None:
            return f"{self.kind}({self.left.text()})"
        operators = {
            "eq": "==",
            "ne": "!=",
            "ult": "<u",
            "uge": ">=u",
            "ugt": ">u",
            "ule": "<=u",
        }
        return f"{self.left.text()} {operators.get(self.kind, self.kind)} {self.right.text()}"


@dataclass(frozen=True)
class BranchTarget:  # noqa: D101
    function_id: str
    function_name: str
    segment_para: int
    branch_ip: int
    fallthrough_ip: int
    taken_ip: int
    condition: ConditionIR
    discovery_source: str = BYTE_SOURCE

    def coverage(self, *, label: str, predicate: str) -> dict[str, Any]:  # noqa: D102
        to_ip = self.taken_ip if label == "taken" else self.fallthrough_ip
        return {
            "binary": "oracle",
            "kind": "edge",
            "function_id": self.function_id,
            "function": self.function_name,
            "from": {"cs": normalize_hex(self.segment_para, width=4), "ip": normalize_hex(self.branch_ip, width=4)},
            "to": {"cs": normalize_hex(self.segment_para, width=4), "ip": normalize_hex(to_ip, width=4)},
            "predicate": predicate,
            "label": label,
            "discovery_source": self.discovery_source,
        }


@dataclass(frozen=True)
class EdgeDiscoveryResult:  # noqa: D101
    targets: tuple[BranchTarget, ...]
    refusals: tuple[dict[str, Any], ...]
    diagnostics: tuple[dict[str, Any], ...] = ()
    source_counts: dict[str, int] = field(default_factory=dict)
    lifter_blocks_lifted: int = 0


@dataclass(frozen=True)
class _Producer:
    kind: str
    condition: ConditionIR | None = None
    reason: str | None = None
    message: str | None = None


@dataclass(frozen=True)
class _Decoded:
    length: int
    producer: _Producer | None = None
    branch_kind: str | None = None
    branch_target: int | None = None
    branch_next: int | None = None
    refusal_reason: str | None = None
    refusal_message: str | None = None


@dataclass(frozen=True)
class _ScanContext:
    function_id: str
    function_name: str
    segment_para: int
    function_base: int
    source: str


def discover_branch_targets(  # noqa: D103
    *,
    exe_path: Path,
    functions: list[dict[str, Any]],
    max_branches: int | None = None,
    scan_limit: int = 0x200,
) -> EdgeDiscoveryResult:
    image = read_mz_image(exe_path)
    targets: list[BranchTarget] = []
    refusals: list[dict[str, Any]] = []
    diagnostics: list[dict[str, Any]] = []
    source_counts: dict[str, int] = {}
    lifter_blocks_lifted = 0

    lifter_project: Any | None = None
    try:
        lifter_project = _load_lifter_project(exe_path)
    except Exception as ex:
        diagnostics.append(
            {
                "kind": "edge_discovery_fallback",
                "from": LIFTER_SOURCE,
                "to": BYTE_SOURCE,
                "reason": "lifter_unavailable",
                "message": f"{type(ex).__name__}: {ex}",
            }
        )

    for function in functions:
        if max_branches is not None and len(targets) >= max_branches:
            break
        if lifter_project is not None:
            function_targets, function_refusals, blocks_lifted = _discover_lifter_function_targets(
                project=lifter_project,
                function=function,
                remaining_branches=None if max_branches is None else max_branches - len(targets),
                scan_limit=scan_limit,
            )
            lifter_blocks_lifted += blocks_lifted
        else:
            function_targets, function_refusals = _discover_function_targets(
                image=image,
                function=function,
                remaining_branches=None if max_branches is None else max_branches - len(targets),
                scan_limit=scan_limit,
                discovery_source=BYTE_SOURCE,
            )
        targets.extend(function_targets)
        refusals.extend(function_refusals)
        for target in function_targets:
            source_counts[target.discovery_source] = source_counts.get(target.discovery_source, 0) + 1
    return EdgeDiscoveryResult(
        targets=tuple(targets),
        refusals=tuple(refusals),
        diagnostics=tuple(diagnostics),
        source_counts=dict(sorted(source_counts.items())),
        lifter_blocks_lifted=lifter_blocks_lifted,
    )


def _load_lifter_project(exe_path: Path) -> Any:  # noqa: ANN401
    try:
        import angr
        import angr_platforms.X86_16.simos_86_16  # noqa: F401
        from angr_platforms.X86_16.load_dos_mz import DOSMZ  # noqa: F401

        project = angr.Project(
            str(exe_path),
            auto_load_libs=False,
            main_opts={"backend": "dos_mz", "base_addr": 0x1000},
            simos="DOS",
        )
        project._dosunit_lifter_mode = "dos_mz"
        return project
    except Exception as package_error:
        project = _load_lightweight_lifter_project(exe_path)
        project._dosunit_lifter_mode = "blob"
        project._dosunit_lifter_fallback = f"{type(package_error).__name__}: {package_error}"
        return project


def _load_lightweight_lifter_project(exe_path: Path) -> Any:  # noqa: ANN401
    import importlib.util
    import io
    import sys

    import angr

    module_name = "_dosunit_arch_86_16"
    module = sys.modules.get(module_name)
    if module is None:
        repo_root = Path(__file__).resolve().parents[2]
        arch_path = repo_root / "angr_platforms" / "angr_platforms" / "X86_16" / "arch_86_16.py"
        spec = importlib.util.spec_from_file_location(module_name, arch_path)
        if spec is None or spec.loader is None:
            raise DosUnitError(f"failed to load x86-16 arch module from {arch_path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)

    image = read_mz_image(exe_path)
    return angr.Project(
        io.BytesIO(image),
        auto_load_libs=False,
        main_opts={
            "backend": "blob",
            "arch": module.Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
    )


def read_mz_image(path: Path) -> bytes:  # noqa: D103
    data = path.read_bytes()
    if len(data) < 0x1C or data[:2] not in {b"MZ", b"ZM"}:
        raise DosUnitError("edge strategy currently requires a DOS MZ .exe")
    lastsize = int.from_bytes(data[0x02:0x04], "little")
    nblocks = int.from_bytes(data[0x04:0x06], "little") & 0x7FF
    hdr_paras = int.from_bytes(data[0x08:0x0A], "little")
    exe_size = ((nblocks - 1) << 9) + lastsize if lastsize else nblocks << 9
    header_size = hdr_paras << 4
    if exe_size <= header_size or exe_size > len(data):
        raise DosUnitError("bad MZ image/header size")
    return data[header_size:exe_size]


def _discover_lifter_function_targets(
    *,
    project: Any,  # noqa: ANN401
    function: dict[str, Any],
    remaining_branches: int | None,
    scan_limit: int,
) -> tuple[list[BranchTarget], list[dict[str, Any]], int]:
    context, at, end, refusals = _lifter_scan_window(project, function, scan_limit)
    if context is None:
        return [], refusals, 0

    targets: list[BranchTarget] = []
    previous: _Producer | None = None
    seen: set[int] = set()
    blocks_lifted = 0
    while at < end:
        if remaining_branches is not None and len(targets) >= remaining_branches:
            break
        if at in seen:
            refusals.append(
                _refusal(
                    context.function_id,
                    "unsupported_ir",
                    "lifter scan encountered a local cycle",
                    source=LIFTER_SOURCE,
                )
            )
            break
        seen.add(at)

        block = _lift_lifter_block(project, at, end, context.function_id, refusals)
        if block is None:
            break
        blocks_lifted += 1

        lifted_insns = [item.insn for item in block.capstone.insns if item.insn.address < end]
        if not lifted_insns:
            refusals.append(
                _refusal(context.function_id, "unsupported_ir", "lifter produced an empty block", source=LIFTER_SOURCE)
            )
            break

        advanced_to, previous = _scan_lifted_insns(
            lifted_insns,
            context=context,
            previous=previous,
            targets=targets,
            refusals=refusals,
        )
        if advanced_to is None:
            last = lifted_insns[-1]
            advanced_to = last.address + max(int(last.size), 1)
        if advanced_to <= at:
            advanced_to = at + 1
        at = advanced_to

    if not targets and not refusals:
        refusals.append(
            _refusal(context.function_id, "unsupported_ir", "no supported direct branch target found", source=LIFTER_SOURCE)
        )
    return targets, refusals, blocks_lifted


def _lifter_scan_window(
    project: Any,  # noqa: ANN401
    function: dict[str, Any],
    scan_limit: int,
) -> tuple[_ScanContext | None, int, int, list[dict[str, Any]]]:
    """Resolve the lifter scan window or produce its refusal."""
    function_id = str(function.get("id", "<unknown>"))
    names = function.get("names", []) if isinstance(function.get("names"), list) else []
    function_name = str(names[0]) if names else function_id
    entry = function.get("entry", {})
    if not isinstance(entry, dict):
        return None, 0, 0, [
            _refusal(function_id, "unsupported_ir", "function entry is missing", source=LIFTER_SOURCE)
        ]
    try:
        segment_para = parse_int(entry.get("segment_para"), field="function.entry.segment_para")
        entry_ip = parse_int(entry.get("offset"), field="function.entry.offset")
    except DosUnitError as ex:
        return None, 0, 0, [_refusal(function_id, "unsupported_ir", str(ex), source=LIFTER_SOURCE)]

    linked_base = int(getattr(project.loader.main_object, "linked_base", 0))
    function_base = linked_base + (segment_para << 4)
    base = function_base + entry_ip
    size = function.get("size")
    limit = int(size) if isinstance(size, int) and size > 0 else scan_limit
    limit = max(0, min(limit, scan_limit))
    if limit <= 0:
        return None, 0, 0, [
            _refusal(function_id, "unsupported_ir", "function size/scan limit is empty", source=LIFTER_SOURCE)
        ]
    context = _ScanContext(
        function_id=function_id,
        function_name=function_name,
        segment_para=segment_para,
        function_base=function_base,
        source=LIFTER_SOURCE,
    )
    return context, base, base + limit, []


def _lift_lifter_block(
    project: Any,  # noqa: ANN401
    at: int,
    end: int,
    function_id: str,
    refusals: list[dict[str, Any]],
) -> Any:  # noqa: ANN401
    """Lift one bounded block; return None after recording its refusal."""
    try:
        block = project.factory.block(at, size=min(0x40, end - at), opt_level=0)
        _ = block.vex
    except Exception as ex:
        refusals.append(
            _refusal(
                function_id,
                "unsupported_ir",
                f"lifter block failed at {normalize_hex(at)}: {type(ex).__name__}: {ex}",
                source=LIFTER_SOURCE,
            )
        )
        return None
    return block


def _scan_lifted_insns(
    lifted_insns: list[Any],
    *,
    context: _ScanContext,
    previous: _Producer | None,
    targets: list[BranchTarget],
    refusals: list[dict[str, Any]],
) -> tuple[int | None, _Producer | None]:
    """Scan one lifted block; return (advanced_to, previous producer)."""
    for insn in lifted_insns:
        decoded = _decode_lifted_control(insn)
        if decoded.refusal_reason is not None:
            refusals.append(
                _refusal(
                    context.function_id,
                    decoded.refusal_reason,
                    decoded.refusal_message or "unsupported control flow",
                    source=context.source,
                )
            )
        if decoded.branch_kind is not None:
            _record_branch(previous, decoded, int(insn.address), context, targets, refusals)
            return decoded.branch_next, None

        producer = _producer_from_lifted_insn(insn)
        previous = producer if producer is not None else None
        if _is_terminal_lifted_control(insn):
            return insn.address + max(int(insn.size), 1), previous
    return None, previous


def _record_branch(
    previous: _Producer | None,
    decoded: _Decoded,
    branch_linear: int,
    context: _ScanContext,
    targets: list[BranchTarget],
    refusals: list[dict[str, Any]],
) -> None:
    """Record one conditional branch target or its refusal."""
    if decoded.branch_kind is None or decoded.branch_next is None:
        return
    if previous is None:
        refusals.append(
            _refusal(
                context.function_id,
                "unsupported_ir",
                "conditional branch has no supported flag producer",
                source=context.source,
            )
        )
        return
    if previous.reason is not None:
        refusals.append(
            _refusal(
                context.function_id,
                previous.reason,
                previous.message or "unsupported branch predicate",
                source=context.source,
            )
        )
        return
    if previous.condition is not None:
        condition = _condition_for_branch(previous.condition, decoded.branch_kind)
        targets.append(
            BranchTarget(
                function_id=context.function_id,
                function_name=context.function_name,
                segment_para=context.segment_para,
                branch_ip=(branch_linear - context.function_base) & 0xFFFF,
                fallthrough_ip=(decoded.branch_next - context.function_base) & 0xFFFF,
                taken_ip=(decoded.branch_target - context.function_base) & 0xFFFF
                if decoded.branch_target is not None
                else 0,
                condition=condition,
                discovery_source=context.source,
            )
        )


def _decode_lifted_control(insn: Any) -> _Decoded:  # noqa: ANN401
    mnemonic = str(insn.mnemonic).lower()
    if mnemonic in BRANCH_MNEMONICS:
        if len(insn.operands) != 1 or insn.operands[0].type != CAPSTONE_OP_IMM:
            return _Decoded(
                length=int(insn.size),
                refusal_reason="unsupported_ir",
                refusal_message="conditional branch target is not a direct immediate",
            )
        target = int(insn.operands[0].imm)
        return _Decoded(
            length=int(insn.size),
            branch_kind=BRANCH_MNEMONICS[mnemonic],
            branch_target=target,
            branch_next=int(insn.address) + int(insn.size),
        )
    if mnemonic in {"jmp", "ljmp"} and (not insn.operands or insn.operands[0].type != CAPSTONE_OP_IMM):
        return _Decoded(
            length=int(insn.size),
            refusal_reason="unbounded_indirect_control",
            refusal_message="indirect jump is unsupported for edge generation",
        )
    return _Decoded(length=int(insn.size))


def _producer_from_lifted_insn(insn: Any) -> _Producer | None:  # noqa: ANN401
    mnemonic = str(insn.mnemonic).lower()
    if mnemonic in {"call", "lcall"}:
        return _unsupported("call_unmodeled", "call before branch is not summarized")
    if mnemonic == "int":
        return _unsupported("dos_interrupt_unmodeled", "interrupt before branch is not summarized")
    if mnemonic not in {"cmp", "test", "or"}:
        return None
    operands = _predicate_operands(insn, mnemonic)
    if isinstance(operands, _Producer):
        return operands
    left, right = operands
    if mnemonic == "cmp":
        return _cmp(left, right)
    if mnemonic == "test":
        return _Producer(kind="test", condition=ConditionIR("test_nonzero", left, right))
    if left.kind == right.kind and left.value == right.value:
        return _Producer(kind="or", condition=ConditionIR("test_nonzero", left, right))
    return _unsupported("unsupported_ir", "or predicate with distinct operands is not modeled")


def _predicate_operands(insn: Any, mnemonic: str) -> tuple[Operand, Operand] | _Producer:  # noqa: ANN401
    """Return the validated predicate operand pair or an unsupported producer."""
    if len(insn.operands) != 2:
        return _unsupported("unsupported_ir", f"{mnemonic} predicate does not have two operands")
    left = _operand_from_lifted(insn, insn.operands[0])
    right = _operand_from_lifted(insn, insn.operands[1], width=left.width if isinstance(left, Operand) else None)
    if isinstance(left, _Producer):
        return left
    if isinstance(right, _Producer):
        return right
    if left.kind not in {"reg", "reg8"}:
        return _unsupported("unsupported_ir", f"{mnemonic} predicate left operand is not a register")
    if right.kind == "imm":
        right = Operand("imm", int(right.value) & ((1 << left.width) - 1), width=left.width)
    if right.width != left.width:
        return _unsupported("unsupported_ir", f"{mnemonic} predicate has mismatched operand widths")
    return (left, right)


def _operand_from_lifted(insn: Any, operand: Any, *, width: int | None = None) -> Operand | _Producer:  # noqa: ANN401
    if operand.type == CAPSTONE_OP_REG:
        name = str(insn.reg_name(operand.reg)).lower()
        if name in REG16:
            return Operand("reg", name, width=16)
        if name in REG8:
            return Operand("reg8", name, width=8)
        return _unsupported("unsupported_ir", f"unsupported register operand: {name}")
    if operand.type == CAPSTONE_OP_IMM:
        operand_width = width or int(getattr(operand, "size", 0) or 2) * 8
        if operand_width <= 0:
            operand_width = 16
        return Operand("imm", int(operand.imm), width=operand_width)
    if operand.type == CAPSTONE_OP_MEM:
        return _unsupported("unbounded_memory", "branch predicate reads memory")
    return _unsupported("unsupported_ir", "unsupported predicate operand")


def _is_terminal_lifted_control(insn: Any) -> bool:  # noqa: ANN401
    mnemonic = str(insn.mnemonic).lower()
    return mnemonic in {"ret", "retf", "iret", "jmp", "ljmp"}


def _discover_function_targets(
    *,
    image: bytes,
    function: dict[str, Any],
    remaining_branches: int | None,
    scan_limit: int,
    discovery_source: str = BYTE_SOURCE,
) -> tuple[list[BranchTarget], list[dict[str, Any]]]:
    function_id = str(function.get("id", "<unknown>"))
    names = function.get("names", []) if isinstance(function.get("names"), list) else []
    function_name = str(names[0]) if names else function_id
    entry = function.get("entry", {})
    if not isinstance(entry, dict):
        return [], [_refusal(function_id, "unsupported_ir", "function entry is missing", source=discovery_source)]
    try:
        segment_para = parse_int(entry.get("segment_para"), field="function.entry.segment_para")
        entry_ip = parse_int(entry.get("offset"), field="function.entry.offset")
    except DosUnitError as ex:
        return [], [_refusal(function_id, "unsupported_ir", str(ex), source=discovery_source)]

    base = (segment_para << 4) + entry_ip
    size = function.get("size")
    limit = int(size) if isinstance(size, int) and size > 0 else scan_limit
    limit = max(0, min(limit, scan_limit, len(image) - base))
    if base < 0 or base >= len(image) or limit <= 0:
        return [], [
            _refusal(function_id, "unsupported_ir", "function entry is outside loaded image", source=discovery_source)
        ]

    targets: list[BranchTarget] = []
    refusals: list[dict[str, Any]] = []
    previous: _Producer | None = None
    at = base
    end = base + limit
    context = _ScanContext(
        function_id=function_id,
        function_name=function_name,
        segment_para=segment_para,
        function_base=segment_para << 4,
        source=discovery_source,
    )
    while at < end:
        if remaining_branches is not None and len(targets) >= remaining_branches:
            break
        decoded = _decode_instruction(image, at, function_base=segment_para << 4)
        previous = _record_byte_decoded(
            decoded,
            at=at,
            context=context,
            previous=previous,
            targets=targets,
            refusals=refusals,
        )
        at += max(decoded.length, 1)
    if not targets and not refusals:
        refusals.append(
            _refusal(function_id, "unsupported_ir", "no supported direct branch target found", source=discovery_source)
        )
    return targets, refusals


def _record_byte_decoded(
    decoded: _Decoded,
    *,
    at: int,
    context: _ScanContext,
    previous: _Producer | None,
    targets: list[BranchTarget],
    refusals: list[dict[str, Any]],
) -> _Producer | None:
    """Record one byte-decoded step; return the next flag producer state."""
    if decoded.refusal_reason is not None:
        refusals.append(
            _refusal(
                context.function_id,
                decoded.refusal_reason,
                decoded.refusal_message or "unsupported instruction",
                source=context.source,
            )
        )
    if decoded.branch_kind is not None:
        _record_branch(previous, decoded, at, context, targets, refusals)
        return None
    if decoded.producer is not None:
        return decoded.producer
    if decoded.length > 0:
        return None
    return previous


def _decode_short_branch(image: bytes, at: int, op: int) -> _Decoded | None:
    """Decode one rel8 conditional branch opcode."""
    if op in SUPPORTED_BRANCH_OPS and at + 2 <= len(image):
        disp = _i8(image[at + 1])
        next_linear = at + 2
        return _Decoded(
            length=2,
            branch_kind=SUPPORTED_BRANCH_OPS[op],
            branch_target=next_linear + disp,
            branch_next=next_linear,
        )
    return None


def _decode_near_branch(image: bytes, at: int, op: int) -> _Decoded | None:
    """Decode one 0x0F rel16 conditional branch opcode."""
    if op == 0x0F and at + 4 <= len(image) and image[at + 1] in NEAR_BRANCH_OPS:
        disp = _i16(image[at + 2 : at + 4])
        next_linear = at + 4
        return _Decoded(
            length=4,
            branch_kind=NEAR_BRANCH_OPS[image[at + 1]],
            branch_target=next_linear + disp,
            branch_next=next_linear,
        )
    return None


def _decode_cmp_ax_imm(image: bytes, at: int, op: int) -> _Decoded | None:
    """Decode CMP AX, imm16."""
    if op == 0x3D and at + 3 <= len(image):
        imm = int.from_bytes(image[at + 1 : at + 3], "little")
        return _Decoded(length=3, producer=_cmp(Operand("reg", "ax"), Operand("imm", imm)))
    return None


def _decode_cmp_al_imm(image: bytes, at: int, op: int) -> _Decoded | None:
    """Decode CMP AL, imm8."""
    if op == 0x3C and at + 2 <= len(image):
        return _Decoded(length=2, producer=_cmp(Operand("reg8", "al", width=8), Operand("imm", image[at + 1], width=8)))
    return None


def _decode_test_ax_imm(image: bytes, at: int, op: int) -> _Decoded | None:
    """Decode TEST AX, imm16."""
    if op == 0xA9 and at + 3 <= len(image):
        imm = int.from_bytes(image[at + 1 : at + 3], "little")
        return _Decoded(
            length=3,
            producer=_Producer(
                kind="test", condition=ConditionIR("test_nonzero", Operand("reg", "ax"), Operand("imm", imm))
            ),
        )
    return None


def _decode_test_al_imm(image: bytes, at: int, op: int) -> _Decoded | None:
    """Decode TEST AL, imm8."""
    if op == 0xA8 and at + 2 <= len(image):
        return _Decoded(
            length=2,
            producer=_Producer(
                kind="test",
                condition=ConditionIR(
                    "test_nonzero", Operand("reg8", "al", width=8), Operand("imm", image[at + 1], width=8)
                ),
            ),
        )
    return None


def _decode_cmp_rm_imm(image: bytes, at: int, op: int) -> _Decoded | None:
    """Decode CMP r/m16, imm16 (0x81 /7) and CMP r/m16, imm8 (0x83 /7)."""
    if op not in {0x81, 0x83} or at + 3 > len(image):
        return None
    modrm = image[at + 1]
    mod, reg, rm = _modrm_parts(modrm)
    if reg != 7:
        return None
    if mod != 3:
        length = 2 + _modrm_displacement_size(mod, rm) + (2 if op == 0x81 else 1)
        return _Decoded(length=length, producer=_unsupported("unbounded_memory", "cmp predicate reads memory"))
    if op == 0x81:
        if at + 4 > len(image):
            return _Decoded(length=1)
        imm = int.from_bytes(image[at + 2 : at + 4], "little")
        return _Decoded(length=4, producer=_cmp(Operand("reg", REG16[rm]), Operand("imm", imm)))
    imm8 = image[at + 2]
    imm = imm8 | 0xFF00 if imm8 & 0x80 else imm8
    return _Decoded(length=3, producer=_cmp(Operand("reg", REG16[rm]), Operand("imm", imm)))


def _decode_cmp_rm8_imm(image: bytes, at: int, op: int) -> _Decoded | None:
    """Decode CMP r/m8, imm8 (0x80 /7)."""
    if op != 0x80 or at + 3 > len(image):
        return None
    modrm = image[at + 1]
    mod, reg, rm = _modrm_parts(modrm)
    if reg != 7:
        return None
    if mod != 3:
        length = 3 + _modrm_displacement_size(mod, rm)
        return _Decoded(
            length=length, producer=_unsupported("unbounded_memory", "byte cmp predicate reads memory")
        )
    return _Decoded(
        length=3, producer=_cmp(Operand("reg8", REG8[rm], width=8), Operand("imm", image[at + 2], width=8))
    )


def _decode_test_rm_imm(image: bytes, at: int, op: int) -> _Decoded | None:
    """Decode TEST r/m16, imm16 (0xF7 /0)."""
    if op != 0xF7 or at + 4 > len(image):
        return None
    modrm = image[at + 1]
    mod, reg, rm = _modrm_parts(modrm)
    if reg != 0:
        return None
    if mod != 3:
        length = 4 + _modrm_displacement_size(mod, rm)
        return _Decoded(length=length, producer=_unsupported("unbounded_memory", "test predicate reads memory"))
    imm = int.from_bytes(image[at + 2 : at + 4], "little")
    return _Decoded(
        length=4,
        producer=_Producer(
            kind="test", condition=ConditionIR("test_nonzero", Operand("reg", REG16[rm]), Operand("imm", imm))
        ),
    )


def _decode_test_rm8_imm(image: bytes, at: int, op: int) -> _Decoded | None:
    """Decode TEST r/m8, imm8 (0xF6 /0)."""
    if op != 0xF6 or at + 3 > len(image):
        return None
    modrm = image[at + 1]
    mod, reg, rm = _modrm_parts(modrm)
    if reg != 0:
        return None
    if mod != 3:
        length = 3 + _modrm_displacement_size(mod, rm)
        return _Decoded(
            length=length, producer=_unsupported("unbounded_memory", "byte test predicate reads memory")
        )
    return _Decoded(
        length=3,
        producer=_Producer(
            kind="test",
            condition=ConditionIR(
                "test_nonzero", Operand("reg8", REG8[rm], width=8), Operand("imm", image[at + 2], width=8)
            ),
        ),
    )


def _decode_reg_rm_cmp_test(image: bytes, at: int, op: int) -> _Decoded | None:
    """Decode CMP r/m16,r16 (0x39), CMP r16,r/m16 (0x3B), TEST r/m16,r16 (0x85)."""
    if op not in {0x39, 0x3B, 0x85} or at + 2 > len(image):
        return None
    modrm = image[at + 1]
    mod, reg, rm = _modrm_parts(modrm)
    if mod != 3:
        reason = "test predicate reads memory" if op == 0x85 else "cmp predicate reads memory"
        return _Decoded(
            length=2 + _modrm_displacement_size(mod, rm), producer=_unsupported("unbounded_memory", reason)
        )
    if op == 0x39:
        return _Decoded(length=2, producer=_cmp(Operand("reg", REG16[rm]), Operand("reg", REG16[reg])))
    if op == 0x3B:
        return _Decoded(length=2, producer=_cmp(Operand("reg", REG16[reg]), Operand("reg", REG16[rm])))
    return _Decoded(
        length=2,
        producer=_Producer(
            kind="test",
            condition=ConditionIR("test_nonzero", Operand("reg", REG16[rm]), Operand("reg", REG16[reg])),
        ),
    )


def _decode_or_rm(image: bytes, at: int, op: int) -> _Decoded | None:
    """Decode OR r/m16,r16 (0x09) and OR r16,r/m16 (0x0B) same-register predicates."""
    if op not in {0x09, 0x0B} or at + 2 > len(image):
        return None
    modrm = image[at + 1]
    mod, reg, rm = _modrm_parts(modrm)
    if mod != 3:
        return _Decoded(
            length=2 + _modrm_displacement_size(mod, rm),
            producer=_unsupported("unbounded_memory", "or predicate writes memory"),
        )
    left = REG16[rm] if op == 0x09 else REG16[reg]
    right = REG16[reg] if op == 0x09 else REG16[rm]
    if left == right:
        operand = Operand("reg", left)
        return _Decoded(
            length=2, producer=_Producer(kind="or", condition=ConditionIR("test_nonzero", operand, operand))
        )
    return _Decoded(
        length=2, producer=_unsupported("unsupported_ir", "or predicate with distinct registers is not modeled")
    )


def _decode_ff_indirect(image: bytes, at: int, op: int) -> _Decoded | None:
    """Decode 0xFF /4 /5 indirect jumps as refused control flow."""
    if op == 0xFF and at + 2 <= len(image):
        modrm = image[at + 1]
        _, reg, _ = _modrm_parts(modrm)
        if reg in {4, 5}:
            return _Decoded(
                length=2,
                refusal_reason="unbounded_indirect_control",
                refusal_message="indirect jump is unsupported for edge generation",
            )
    return None


_BYTE_DECODERS = (
    _decode_short_branch,
    _decode_near_branch,
    _decode_cmp_ax_imm,
    _decode_cmp_al_imm,
    _decode_test_ax_imm,
    _decode_test_al_imm,
    _decode_cmp_rm_imm,
    _decode_cmp_rm8_imm,
    _decode_test_rm_imm,
    _decode_test_rm8_imm,
    _decode_reg_rm_cmp_test,
    _decode_or_rm,
    _decode_ff_indirect,
)


def _decode_instruction(image: bytes, at: int, *, function_base: int) -> _Decoded:
    if at >= len(image):
        return _Decoded(length=1)
    op = image[at]
    for decoder in _BYTE_DECODERS:
        decoded = decoder(image, at, op)
        if decoded is not None:
            return decoded
    return _Decoded(length=_minimal_instruction_length(image, at))


def _condition_for_branch(condition: ConditionIR, branch_kind: str) -> ConditionIR:
    if condition.kind in {"test_zero", "test_nonzero"}:
        if branch_kind == "eq":
            return ConditionIR("test_zero", condition.left, condition.right)
        if branch_kind == "ne":
            return ConditionIR("test_nonzero", condition.left, condition.right)
        return ConditionIR("unsupported", condition.left, condition.right)
    if branch_kind in {"eq", "ne", "ult", "uge", "ugt", "ule"}:
        return ConditionIR(branch_kind, condition.left, condition.right)
    return ConditionIR("unsupported", condition.left, condition.right)


def _cmp(left: Operand, right: Operand) -> _Producer:
    return _Producer(kind="cmp", condition=ConditionIR("eq", left, right))


def _unsupported(reason: str, message: str) -> _Producer:
    return _Producer(kind="unsupported", reason=reason, message=message)


def _refusal(function_id: str, reason: str, message: str, *, source: str | None = None) -> dict[str, Any]:
    detail: dict[str, Any] = {
        "function_id": function_id,
        "strategy": "edge",
        "message": message,
    }
    if source is not None:
        detail["discovery_source"] = source
    return {
        "status": "refused",
        "reason": reason,
        "detail": detail,
    }


def _modrm_parts(modrm: int) -> tuple[int, int, int]:
    return (modrm >> 6) & 3, (modrm >> 3) & 7, modrm & 7


def _modrm_displacement_size(mod: int, rm: int) -> int:
    if mod == 0 and rm == 6:
        return 2
    if mod == 1:
        return 1
    if mod == 2:
        return 2
    return 0


def _minimal_instruction_length(image: bytes, at: int) -> int:
    op = image[at]
    if 0x50 <= op <= 0x5F or 0x40 <= op <= 0x4F or op in {0x90, 0xC3, 0xCB, 0x9C, 0x9D}:
        return 1
    if 0xB8 <= op <= 0xBF:
        return 3
    if 0xB0 <= op <= 0xB7:
        return 2
    if op in {0xE9, 0xE8}:
        return 3
    if op in {0xEB, 0xCD}:
        return 2
    return 1


def _i8(value: int) -> int:
    return value - 0x100 if value & 0x80 else value


def _i16(data: bytes) -> int:
    value = int.from_bytes(data, "little")
    return value - 0x10000 if value & 0x8000 else value
