from __future__ import annotations  # noqa: D100

from collections import defaultdict
from pathlib import Path
from typing import Any

from tools.dosunit.ir_edges import (
    BRANCH_MNEMONICS,
    CAPSTONE_OP_IMM,
    CAPSTONE_OP_MEM,
    CAPSTONE_OP_REG,
    _load_lifter_project,
)
from tools.dosunit.model import DosUnitError, normalize_hex, parse_int, stable_id

READ_ACCESS = 1
WRITE_ACCESS = 2
REGION_BRANCH_MNEMONICS = {
    **BRANCH_MNEMONICS,
    "jo": "of",
    "jno": "not_of",
    "js": "sign",
    "jns": "not_sign",
    "jp": "parity",
    "jpe": "parity",
    "jnp": "not_parity",
    "jpo": "not_parity",
    "jl": "slt",
    "jnge": "slt",
    "jge": "sge",
    "jnl": "sge",
    "jle": "sle",
    "jng": "sle",
    "jg": "sgt",
    "jnle": "sgt",
    "jcxz": "cx_zero",
}
CONTROL_MNEMONICS = set(REGION_BRANCH_MNEMONICS) | {
    "call",
    "lcall",
    "jmp",
    "ljmp",
    "ret",
    "retf",
    "iret",
    "int",
}
STACK_READ_MNEMONICS = {"pop", "ret", "retf", "iret"}
STACK_WRITE_MNEMONICS = {"push", "call", "lcall"}


def summarize_region_effects(  # noqa: D103
    *,
    exe_path: Path,
    functions_catalog: dict[str, Any],
    max_regions_per_function: int = 8,
    max_insns_per_region: int = 32,
    scan_limit: int = 0x200,
) -> dict[str, Any]:
    functions = list(functions_catalog.get("functions", []) or [])
    project = _load_lifter_project(exe_path)
    linked_base = int(getattr(project.loader.main_object, "linked_base", 0))
    regions: list[dict[str, Any]] = []
    refusals: list[dict[str, Any]] = []
    counters = {
        "functions_seen": len(functions),
        "functions_attempted": 0,
        "regions_emitted": 0,
        "instructions_summarized": 0,
        "lifter_blocks_lifted": 0,
        "refusals_by_reason": {},
    }

    for function in functions:
        counters["functions_attempted"] += 1
        try:
            function_regions, function_refusals, blocks_lifted = _summarize_function_regions(
                project=project,
                linked_base=linked_base,
                function=function,
                max_regions=max_regions_per_function,
                max_insns_per_region=max_insns_per_region,
                scan_limit=scan_limit,
            )
        except DosUnitError as ex:
            function_regions = []
            function_refusals = [_refusal(str(function.get("id", "<unknown>")), "unsupported_ir", str(ex))]
            blocks_lifted = 0
        regions.extend(function_regions)
        refusals.extend(function_refusals)
        counters["lifter_blocks_lifted"] += blocks_lifted

    counters["regions_emitted"] = len(regions)
    counters["instructions_summarized"] = sum(len(region.get("instructions", [])) for region in regions)
    counters["refusals_by_reason"] = _refusal_counts(refusals)
    document_without_id = {
        "schema": "dosunit.regions.v1",
        "exe": str(exe_path),
        "source": "lifter_vex",
        "module": str(functions_catalog.get("module", exe_path.name)),
        "regions": regions,
        "refusals": refusals,
        "counters": counters,
    }
    document = dict(document_without_id)
    document["id"] = stable_id("regions", document_without_id)
    return document


def compare_region_effect_documents(  # noqa: D103
    *,
    oracle: dict[str, Any],
    candidate: dict[str, Any],
) -> dict[str, Any]:
    oracle_regions = list(oracle.get("regions", []) or [])
    candidate_regions = list(candidate.get("regions", []) or [])
    candidate_by_key = _regions_by_function_and_ordinal(candidate_regions)
    function_ordinals: dict[str, int] = defaultdict(int)
    results: list[dict[str, Any]] = []

    for oracle_region in oracle_regions:
        function_id = str(oracle_region.get("function", {}).get("id", ""))
        function_name = str(oracle_region.get("function", {}).get("name", function_id))
        function_key = function_name or function_id
        ordinal = function_ordinals[function_key]
        function_ordinals[function_key] += 1
        candidate_region = candidate_by_key.get((function_key, ordinal))
        if candidate_region is None:
            results.append(
                {
                    "status": "refused",
                    "reason": "mapping_missing",
                    "function": {"id": function_id, "name": function_name},
                    "region_ordinal": ordinal,
                    "oracle_entry": oracle_region.get("entry"),
                    "candidate_entry": None,
                    "mismatches": [{"kind": "region_missing", "detail": "candidate region ordinal is missing"}],
                }
            )
            continue
        mismatches = _compare_regions(oracle_region, candidate_region)
        results.append(
            {
                "status": "passed" if not mismatches else "failed",
                "reason": None if not mismatches else "observable_mismatch",
                "function": {"id": function_id, "name": function_name},
                "region_ordinal": ordinal,
                "oracle_region": oracle_region.get("id"),
                "candidate_region": candidate_region.get("id"),
                "oracle_entry": oracle_region.get("entry"),
                "candidate_entry": candidate_region.get("entry"),
                "mismatches": mismatches,
            }
        )

    summary = {
        "total": len(results),
        "passed": sum(1 for result in results if result["status"] == "passed"),
        "failed": sum(1 for result in results if result["status"] == "failed"),
        "refused": sum(1 for result in results if result["status"] == "refused"),
    }
    document_without_id = {
        "schema": "dosunit.region_compare.v1",
        "oracle": oracle.get("exe"),
        "candidate": candidate.get("exe"),
        "summary": summary,
        "results": results,
    }
    document = dict(document_without_id)
    document["id"] = stable_id("region-compare", document_without_id)
    return document


def _summarize_function_regions(
    *,
    project: Any,  # noqa: ANN401
    linked_base: int,
    function: dict[str, Any],
    max_regions: int,
    max_insns_per_region: int,
    scan_limit: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    function_id = str(function.get("id", "<unknown>"))
    names = function.get("names", []) if isinstance(function.get("names"), list) else []
    function_name = str(names[0]) if names else function_id
    entry = function.get("entry", {})
    if not isinstance(entry, dict):
        return [], [_refusal(function_id, "unsupported_ir", "function entry is missing")], 0

    segment_para = parse_int(entry.get("segment_para"), field="function.entry.segment_para")
    entry_ip = parse_int(entry.get("offset"), field="function.entry.offset")
    function_base = linked_base + (segment_para << 4)
    start = function_base + entry_ip
    size = function.get("size")
    limit = int(size) if isinstance(size, int) and size > 0 else scan_limit
    limit = max(0, min(limit, scan_limit))
    end = start + limit
    if limit <= 0:
        return [], [_refusal(function_id, "unsupported_ir", "function size/scan limit is empty")], 0

    return _scan_function_regions(
        project=project,
        function_id=function_id,
        function_name=function_name,
        segment_para=segment_para,
        function_base=function_base,
        start=start,
        end=end,
        max_regions=max_regions,
        max_insns_per_region=max_insns_per_region,
    )


def _lift_region_block(
    project: Any,  # noqa: ANN401
    function_id: str,
    at: int,
    *,
    start: int,
    end: int,
) -> tuple[list[Any], dict[str, Any] | None]:
    """Lift one block and return its in-window instructions or a refusal."""
    try:
        block = project.factory.block(at, size=min(0x80, end - at), opt_level=0)
        _ = block.vex
    except Exception as ex:
        return [], _refusal(
            function_id,
            "unsupported_ir",
            f"lifter block failed at {normalize_hex(at)}: {type(ex).__name__}: {ex}",
        )
    lifted_insns = [item.insn for item in block.capstone.insns if start <= item.insn.address < end]
    if not lifted_insns:
        return [], _refusal(function_id, "unsupported_ir", f"lifter produced no instructions at {normalize_hex(at)}")
    return lifted_insns, None


def _scan_function_regions(
    *,
    project: Any,  # noqa: ANN401
    function_id: str,
    function_name: str,
    segment_para: int,
    function_base: int,
    start: int,
    end: int,
    max_regions: int,
    max_insns_per_region: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """BFS-scan one function window into region summaries."""
    regions: list[dict[str, Any]] = []
    refusals: list[dict[str, Any]] = []
    pending = [start]
    seen: set[int] = set()
    blocks_lifted = 0

    while pending and len(regions) < max_regions:
        at = pending.pop(0)
        if at < start or at >= end or at in seen:
            continue
        seen.add(at)
        lifted_insns, refusal = _lift_region_block(project, function_id, at, start=start, end=end)
        if refusal is not None:
            refusals.append(refusal)
            continue
        blocks_lifted += 1
        region = _summarize_region(
            function_id=function_id,
            function_name=function_name,
            segment_para=segment_para,
            function_base=function_base,
            insns=lifted_insns[:max_insns_per_region],
        )
        regions.append(region)
        for successor in region.get("successors", []):
            target = parse_int(successor.get("linear"), field="successor.linear")
            if start <= target < end and target not in seen and target not in pending:
                pending.append(target)

    if pending and len(regions) >= max_regions:
        refusals.append(_refusal(function_id, "unsupported_ir", f"region limit reached at {max_regions}"))
    if not regions and not refusals:
        refusals.append(_refusal(function_id, "unsupported_ir", "no lifter-backed regions found"))
    return regions, refusals, blocks_lifted


def _summarize_region(
    *,
    function_id: str,
    function_name: str,
    segment_para: int,
    function_base: int,
    insns: list[Any],
) -> dict[str, Any]:
    instructions = [_instruction_summary(insn, function_base=function_base) for insn in insns]
    effects = _aggregate_effects(instructions)
    exits, successors = _region_exits(insns[-1], segment_para=segment_para, function_base=function_base)
    region_without_id = {
        "function": {"id": function_id, "name": function_name},
        "entry": {
            "cs": normalize_hex(segment_para, width=4),
            "ip": normalize_hex((insns[0].address - function_base) & 0xFFFF, width=4),
            "linear": normalize_hex(insns[0].address),
        },
        "end": {
            "cs": normalize_hex(segment_para, width=4),
            "ip": normalize_hex((insns[-1].address + insns[-1].size - function_base) & 0xFFFF, width=4),
            "linear": normalize_hex(insns[-1].address + insns[-1].size),
        },
        "source": "lifter_vex",
        "instructions": instructions,
        "effects": effects,
        "exits": exits,
        "successors": successors,
    }
    region = dict(region_without_id)
    region["id"] = stable_id("region", region_without_id)
    return region


def _instruction_summary(insn: Any, *, function_base: int) -> dict[str, Any]:  # noqa: ANN401
    regs_read, regs_written = _regs_access(insn)
    operands = [_operand_summary(insn, operand) for operand in insn.operands]
    memory_reads = [
        operand["memory"]
        for operand in operands
        if operand.get("kind") == "mem" and operand.get("access") in {"read", "readwrite"}
    ]
    memory_writes = [
        operand["memory"]
        for operand in operands
        if operand.get("kind") == "mem" and operand.get("access") in {"write", "readwrite"}
    ]
    memory_reads.extend(_implicit_stack_reads(insn))
    memory_writes.extend(_implicit_stack_writes(insn))
    flags_read = sorted(reg for reg in regs_read if reg in {"flags", "eflags"})
    flags_written = sorted(reg for reg in regs_written if reg in {"flags", "eflags"})
    explicit_regs_read = sorted(reg for reg in regs_read if reg not in {"flags", "eflags"})
    explicit_regs_written = sorted(reg for reg in regs_written if reg not in {"flags", "eflags"})
    return {
        "address": {
            "ip": normalize_hex((int(insn.address) - function_base) & 0xFFFF, width=4),
            "linear": normalize_hex(int(insn.address)),
        },
        "size": int(insn.size),
        "mnemonic": str(insn.mnemonic).lower(),
        "op_str": str(insn.op_str).lower(),
        "operands": operands,
        "effects": {
            "regs_read": explicit_regs_read,
            "regs_written": explicit_regs_written,
            "flags_read": flags_read,
            "flags_written": flags_written,
            "memory_read": memory_reads,
            "memory_written": memory_writes,
        },
        "control": _instruction_control(insn),
    }


def _operand_summary(insn: Any, operand: Any) -> dict[str, Any]:  # noqa: ANN401
    access = _access_name(int(getattr(operand, "access", 0) or 0))
    width = int(getattr(operand, "size", 0) or 0) * 8
    if operand.type == CAPSTONE_OP_REG:
        return {"kind": "reg", "name": _reg_name(insn, operand.reg), "width": width, "access": access}
    if operand.type == CAPSTONE_OP_IMM:
        return {
            "kind": "imm",
            "value": _format_immediate(int(operand.imm), width=width),
            "width": width,
            "access": access,
        }
    if operand.type == CAPSTONE_OP_MEM:
        memory = _memory_operand_summary(insn, operand, access=access, width=width)
        return {"kind": "mem", "width": width, "access": access, "memory": memory}
    return {"kind": "unknown", "width": width, "access": access}


def _memory_operand_summary(insn: Any, operand: Any, *, access: str, width: int) -> dict[str, Any]:  # noqa: ANN401
    mem = operand.mem
    explicit_segment = _reg_name(insn, mem.segment) if mem.segment else None
    base = _reg_name(insn, mem.base) if mem.base else None
    index = _reg_name(insn, mem.index) if mem.index else None
    segment = explicit_segment or _default_segment(base=base, index=index)
    disp = int(mem.disp)
    summary = {
        "space": segment.upper(),
        "explicit_segment": explicit_segment.upper() if explicit_segment else None,
        "base": base,
        "index": index,
        "scale": int(mem.scale),
        "disp": _format_signed_hex(disp),
        "width": width,
        "access": access,
    }
    summary["expr"] = _memory_expr(summary)
    return summary


def _regs_access(insn: Any) -> tuple[set[str], set[str]]:  # noqa: ANN401
    try:
        read, written = insn.regs_access()
    except Exception:
        read = getattr(insn, "regs_read", [])
        written = getattr(insn, "regs_write", [])
    return {_normalize_reg(_reg_name(insn, reg)) for reg in read}, {
        _normalize_reg(_reg_name(insn, reg)) for reg in written
    }


def _reg_name(insn: Any, reg: int) -> str:  # noqa: ANN401
    if not reg:
        return ""
    return str(insn.reg_name(reg)).lower()


def _normalize_reg(reg: str) -> str:
    return "flags" if reg in {"eflags", "rflags"} else reg


def _access_name(access: int) -> str:
    reads = bool(access & READ_ACCESS)
    writes = bool(access & WRITE_ACCESS)
    if reads and writes:
        return "readwrite"
    if reads:
        return "read"
    if writes:
        return "write"
    return "none"


def _default_segment(*, base: str | None, index: str | None) -> str:
    if base in {"bp", "sp"}:
        return "SS"
    if index == "bp":
        return "SS"
    return "DS"


def _format_signed_hex(value: int) -> str:
    sign = "-" if value < 0 else ""
    return f"{sign}0x{abs(value):04x}"


def _format_immediate(value: int, *, width: int) -> str:
    if value < 0 and width > 0:
        value &= (1 << width) - 1
    return normalize_hex(value)


def _memory_expr(memory: dict[str, Any]) -> str:
    terms: list[str] = []
    if memory.get("base"):
        terms.append(str(memory["base"]))
    if memory.get("index"):
        index = str(memory["index"])
        scale = int(memory.get("scale", 1))
        terms.append(index if scale == 1 else f"{index}*{scale}")
    disp = str(memory.get("disp", "0x0000"))
    if disp != "0x0000" or not terms:
        terms.append(disp)
    expr = terms[0]
    for term in terms[1:]:
        if term.startswith("-"):
            expr += f" - {term[1:]}"
        else:
            expr += f" + {term}"
    return f"{memory['space']}:[{expr}]"


def _implicit_stack_reads(insn: Any) -> list[dict[str, Any]]:  # noqa: ANN401
    if str(insn.mnemonic).lower() not in STACK_READ_MNEMONICS:
        return []
    return [
        {
            "space": "SS",
            "explicit_segment": None,
            "base": "sp",
            "index": None,
            "scale": 1,
            "disp": "0x0000",
            "width": 16,
            "access": "read",
            "expr": "SS:[sp]",
            "implicit": True,
        }
    ]


def _implicit_stack_writes(insn: Any) -> list[dict[str, Any]]:  # noqa: ANN401
    if str(insn.mnemonic).lower() not in STACK_WRITE_MNEMONICS:
        return []
    return [
        {
            "space": "SS",
            "explicit_segment": None,
            "base": "sp",
            "index": None,
            "scale": 1,
            "disp": "-0x0002",
            "width": 16,
            "access": "write",
            "expr": "SS:[sp - 0x0002]",
            "implicit": True,
        }
    ]


def _instruction_control(insn: Any) -> dict[str, Any]:  # noqa: ANN401
    mnemonic = str(insn.mnemonic).lower()
    if mnemonic in REGION_BRANCH_MNEMONICS:
        return {
            "kind": "conditional_branch",
            "condition": REGION_BRANCH_MNEMONICS[mnemonic],
            "target": _direct_target(insn),
        }
    if mnemonic in {"jmp", "ljmp"}:
        return {"kind": "jump", "target": _direct_target(insn)}
    if mnemonic in {"call", "lcall"}:
        return {"kind": "call", "target": _direct_target(insn)}
    if mnemonic in {"ret", "retf", "iret"}:
        return {"kind": "return"}
    if mnemonic == "int":
        return {"kind": "interrupt", "vector": _direct_target(insn)}
    return {"kind": "none"}


def _direct_target(insn: Any) -> str | None:  # noqa: ANN401
    if len(insn.operands) == 1 and insn.operands[0].type == CAPSTONE_OP_IMM:
        return normalize_hex(int(insn.operands[0].imm))
    return None


def _region_exits(
    insn: Any, *, segment_para: int, function_base: int  # noqa: ANN401
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    mnemonic = str(insn.mnemonic).lower()
    next_linear = int(insn.address) + int(insn.size)
    exits: list[dict[str, Any]] = []
    successors: list[dict[str, Any]] = []

    def add_exit(kind: str, linear: int | None = None) -> None:
        item: dict[str, Any] = {"kind": kind}
        if linear is not None:
            item["target"] = {
                "cs": normalize_hex(segment_para, width=4),
                "ip": normalize_hex((linear - function_base) & 0xFFFF, width=4),
                "linear": normalize_hex(linear),
            }
            successors.append({"kind": kind, "linear": normalize_hex(linear)})
        exits.append(item)

    if mnemonic in REGION_BRANCH_MNEMONICS:
        target = _target_int(insn)
        if target is not None:
            add_exit("taken", target)
        add_exit("fallthrough", next_linear)
    elif mnemonic in {"jmp", "ljmp"}:
        target = _target_int(insn)
        add_exit("jump", target)
    elif mnemonic in {"call", "lcall"}:
        target = _target_int(insn)
        add_exit("call", target)
        add_exit("fallthrough", next_linear)
    elif mnemonic in {"ret", "retf", "iret"}:
        add_exit("return")
    elif mnemonic == "int":
        add_exit("interrupt")
    else:
        add_exit("fallthrough", next_linear)
    return exits, successors


def _target_int(insn: Any) -> int | None:  # noqa: ANN401
    if len(insn.operands) == 1 and insn.operands[0].type == CAPSTONE_OP_IMM:
        return int(insn.operands[0].imm)
    return None


def _aggregate_effects(instructions: list[dict[str, Any]]) -> dict[str, Any]:
    regs_read: set[str] = set()
    regs_written: set[str] = set()
    flags_read: set[str] = set()
    flags_written: set[str] = set()
    memory_read: dict[str, dict[str, Any]] = {}
    memory_written: dict[str, dict[str, Any]] = {}
    calls: list[dict[str, Any]] = []
    for instruction in instructions:
        effects = instruction["effects"]
        regs_read.update(effects["regs_read"])
        regs_written.update(effects["regs_written"])
        flags_read.update(effects["flags_read"])
        flags_written.update(effects["flags_written"])
        for memory in effects["memory_read"]:
            memory_read[memory["expr"]] = memory
        for memory in effects["memory_written"]:
            memory_written[memory["expr"]] = memory
        control = instruction.get("control", {})
        if control.get("kind") in {"call", "interrupt"}:
            calls.append(
                {"kind": control.get("kind"), "target": control.get("target"), "address": instruction["address"]}
            )
    return {
        "regs_read": sorted(regs_read),
        "regs_written": sorted(regs_written),
        "flags_read": sorted(flags_read),
        "flags_written": sorted(flags_written),
        "memory_read": [memory_read[key] for key in sorted(memory_read)],
        "memory_written": [memory_written[key] for key in sorted(memory_written)],
        "calls": calls,
    }


def _regions_by_function_and_ordinal(regions: list[dict[str, Any]]) -> dict[tuple[str, int], dict[str, Any]]:
    counts: dict[str, int] = defaultdict(int)
    indexed: dict[tuple[str, int], dict[str, Any]] = {}
    for region in regions:
        function = region.get("function", {})
        function_id = str(function.get("id", ""))
        function_name = str(function.get("name", function_id))
        function_key = function_name or function_id
        ordinal = counts[function_key]
        counts[function_key] += 1
        indexed[(function_key, ordinal)] = region
    return indexed


def _compare_regions(oracle_region: dict[str, Any], candidate_region: dict[str, Any]) -> list[dict[str, Any]]:
    mismatches: list[dict[str, Any]] = []
    oracle_insns = list(oracle_region.get("instructions", []) or [])
    candidate_insns = list(candidate_region.get("instructions", []) or [])
    if len(oracle_insns) != len(candidate_insns):
        mismatches.append(
            {"kind": "instruction_count_changed", "oracle": len(oracle_insns), "candidate": len(candidate_insns)}
        )
    for idx, (oracle_insn, candidate_insn) in enumerate(zip(oracle_insns, candidate_insns, strict=False)):
        oracle_context = _instruction_context(oracle_insn)
        candidate_context = _instruction_context(candidate_insn)
        oracle_mnemonic = oracle_insn.get("mnemonic")
        candidate_mnemonic = candidate_insn.get("mnemonic")
        if oracle_mnemonic != candidate_mnemonic:
            mismatches.append(
                {
                    "kind": "mnemonic_changed",
                    "instruction_index": idx,
                    "oracle_instruction": oracle_context,
                    "candidate_instruction": candidate_context,
                    "oracle": oracle_mnemonic,
                    "candidate": candidate_mnemonic,
                }
            )
        oracle_operands = [
            _comparable_operand(operand, control_kind=oracle_insn.get("control", {}).get("kind"))
            for operand in oracle_insn.get("operands", [])
        ]
        candidate_operands = [
            _comparable_operand(operand, control_kind=candidate_insn.get("control", {}).get("kind"))
            for operand in candidate_insn.get("operands", [])
        ]
        if oracle_operands != candidate_operands:
            mismatches.append(
                {
                    "kind": "instruction_operands_changed",
                    "instruction_index": idx,
                    "mnemonic": oracle_mnemonic,
                    "oracle_instruction": oracle_context,
                    "candidate_instruction": candidate_context,
                    "oracle": oracle_operands,
                    "candidate": candidate_operands,
                }
            )
        oracle_effects = _comparable_effects(oracle_insn.get("effects", {}))
        candidate_effects = _comparable_effects(candidate_insn.get("effects", {}))
        if oracle_effects != candidate_effects:
            mismatches.append(
                {
                    "kind": "instruction_effects_changed",
                    "instruction_index": idx,
                    "mnemonic": oracle_mnemonic,
                    "oracle_instruction": oracle_context,
                    "candidate_instruction": candidate_context,
                    "oracle": oracle_effects,
                    "candidate": candidate_effects,
                }
            )
    return mismatches


def _instruction_context(instruction: dict[str, Any]) -> dict[str, Any]:
    mnemonic = str(instruction.get("mnemonic", ""))
    op_str = str(instruction.get("op_str", ""))
    disassembly = mnemonic if not op_str else f"{mnemonic} {op_str}"
    return {
        "address": instruction.get("address"),
        "size": instruction.get("size"),
        "disassembly": disassembly,
    }


def _comparable_operand(operand: dict[str, Any], *, control_kind: str | None) -> dict[str, Any]:
    kind = operand.get("kind")
    if kind == "imm" and control_kind in {"conditional_branch", "jump", "call", "interrupt"}:
        return {"kind": "imm", "role": "control_target", "width": operand.get("width")}
    if kind == "mem":
        memory = operand.get("memory", {})
        return {
            "kind": "mem",
            "width": operand.get("width"),
            "access": operand.get("access"),
            "space": memory.get("space"),
            "base": memory.get("base"),
            "index": memory.get("index"),
            "scale": memory.get("scale"),
            "disp": memory.get("disp"),
        }
    return {key: operand.get(key) for key in ("kind", "name", "value", "width", "access") if key in operand}


def _comparable_effects(effects: dict[str, Any]) -> dict[str, Any]:
    return {
        "regs_read": sorted(effects.get("regs_read", [])),
        "regs_written": sorted(effects.get("regs_written", [])),
        "flags_read": sorted(effects.get("flags_read", [])),
        "flags_written": sorted(effects.get("flags_written", [])),
        "memory_read": [_comparable_memory(memory) for memory in effects.get("memory_read", [])],
        "memory_written": [_comparable_memory(memory) for memory in effects.get("memory_written", [])],
    }


def _comparable_memory(memory: dict[str, Any]) -> dict[str, Any]:
    return {
        "space": memory.get("space"),
        "base": memory.get("base"),
        "index": memory.get("index"),
        "scale": memory.get("scale"),
        "disp": memory.get("disp"),
        "width": memory.get("width"),
        "access": memory.get("access"),
        "implicit": bool(memory.get("implicit", False)),
    }


def _refusal(function_id: str, reason: str, message: str) -> dict[str, Any]:
    return {
        "status": "refused",
        "reason": reason,
        "detail": {"function_id": function_id, "strategy": "regions", "message": message},
    }


def _refusal_counts(refusals: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in refusals:
        reason = str(item.get("reason", "unknown"))
        counts[reason] = counts.get(reason, 0) + 1
    return dict(sorted(counts.items()))
