from __future__ import annotations  # noqa: D100

from pathlib import Path
from typing import Any

from tools.dosunit.ir_edges import REG8, _load_lifter_project
from tools.dosunit.model import DosUnitError, normalize_hex, parse_int, stable_id
from tools.dosunit.region_effects import REGION_BRANCH_MNEMONICS, _instruction_summary, _refusal_counts, _target_int

CALL_MNEMONICS = {"call", "lcall"}
INTERRUPT_MNEMONICS = {"int"}
JUMP_MNEMONICS = {"jmp", "ljmp"}
RETURN_MNEMONICS = {"ret", "retf", "iret"}
LOOP_MNEMONICS = {"loop", "loope", "loopne", "loopnz", "loopz"}
SHIFT_ROTATE_MNEMONICS = {"shl", "shr", "sal", "sar", "rol", "ror", "rcl", "rcr"}
MUL_DIV_MNEMONICS = {"mul", "imul", "div", "idiv", "aam", "aad"}
STRING_MNEMONIC_PREFIXES = ("movs", "stos", "lods", "scas", "cmps", "ins", "outs")
REP_PREFIXES = ("rep ", "repe ", "repne ", "repz ", "repnz ")
PARTIAL_REGS = set(REG8)
SEGMENT_SENSITIVE_SPACES = {"SS", "ES", "FS", "GS", "SEG"}

RISK_WEIGHTS = {
    "condition_count": 4,
    "call_count": 8,
    "interrupt_count": 8,
    "indirect_control_count": 12,
    "explicit_symbolic_memory_count": 5,
    "explicit_memory_write_count": 3,
    "segment_sensitive_memory_count": 2,
    "flag_read_count": 2,
    "partial_register_count": 2,
    "variable_shift_count": 4,
    "mul_div_count": 5,
    "string_instruction_count": 8,
    "loop_like_count": 8,
    "backward_branch_count": 8,
}


def analyze_function_complexity(  # noqa: D103
    *,
    exe_path: Path,
    functions_catalog: dict[str, Any],
    max_blocks_per_function: int = 32,
    max_insns_per_function: int = 128,
    max_simple_insns: int = 16,
    simple_score_threshold: int = 8,
    max_simple_symbolic_memory: int = 0,
    max_risk_points: int = 16,
    scan_limit: int = 0x200,
) -> dict[str, Any]:
    functions = list(functions_catalog.get("functions", []) or [])
    project = _load_lifter_project(exe_path)
    linked_base = int(getattr(project.loader.main_object, "linked_base", 0))
    analyzed: list[dict[str, Any]] = []
    refusals: list[dict[str, Any]] = []
    counters: dict[str, Any] = {
        "functions_seen": len(functions),
        "functions_attempted": 0,
        "functions_analyzed": 0,
        "simple_whole_functions": 0,
        "complex_functions": 0,
        "refused_functions": 0,
        "comparison_parts_emitted": 0,
        "lifter_blocks_lifted": 0,
        "instructions_scanned": 0,
        "refusals_by_reason": {},
    }

    parameters = {
        "max_blocks_per_function": max_blocks_per_function,
        "max_insns_per_function": max_insns_per_function,
        "max_simple_insns": max_simple_insns,
        "simple_score_threshold": simple_score_threshold,
        "max_simple_symbolic_memory": max_simple_symbolic_memory,
        "max_risk_points": max_risk_points,
        "scan_limit": scan_limit,
    }

    for function in functions:
        counters["functions_attempted"] += 1
        result, function_refusals, blocks_lifted = _analyze_one_function(
            project=project,
            linked_base=linked_base,
            function=function,
            max_blocks=max_blocks_per_function,
            max_insns=max_insns_per_function,
            max_simple_insns=max_simple_insns,
            simple_score_threshold=simple_score_threshold,
            max_simple_symbolic_memory=max_simple_symbolic_memory,
            max_risk_points=max_risk_points,
            scan_limit=scan_limit,
        )
        counters["lifter_blocks_lifted"] += blocks_lifted
        refusals.extend(function_refusals)
        if result is None:
            counters["refused_functions"] += 1
            continue
        analyzed.append(result)
        counters["functions_analyzed"] += 1
        counters["instructions_scanned"] += int(result.get("metrics", {}).get("instruction_count", 0))
        if result.get("classification") == "simple_whole_function":
            counters["simple_whole_functions"] += 1
        else:
            counters["complex_functions"] += 1
        counters["comparison_parts_emitted"] += len(result.get("comparison_parts", []) or [])

    counters["refusals_by_reason"] = _refusal_counts(refusals)
    document_without_id = {
        "schema": "dosunit.complexity.v1",
        "exe": str(exe_path),
        "source": "lifter_vex",
        "module": str(functions_catalog.get("module", exe_path.name)),
        "parameters": parameters,
        "risk_weights": RISK_WEIGHTS,
        "functions": analyzed,
        "refusals": refusals,
        "counters": counters,
    }
    document = dict(document_without_id)
    document["id"] = stable_id("complexity", document_without_id)
    return document


def _function_scan_window(
    function: dict[str, Any],
    function_id: str,
    *,
    linked_base: int,
    scan_limit: int,
) -> tuple[tuple[int, int, int, int, int] | None, list[dict[str, Any]]]:
    """Resolve the function scan window or return its refusal."""
    entry = function.get("entry", {})
    if not isinstance(entry, dict):
        return None, [_refusal(function_id, "unsupported_ir", "function entry is missing")]
    try:
        segment_para = parse_int(entry.get("segment_para"), field="function.entry.segment_para")
        entry_ip = parse_int(entry.get("offset"), field="function.entry.offset")
    except DosUnitError as ex:
        return None, [_refusal(function_id, "unsupported_ir", str(ex))]

    function_base = linked_base + (segment_para << 4)
    start = function_base + entry_ip
    size = function.get("size")
    limit = int(size) if isinstance(size, int) and size > 0 else scan_limit
    limit = max(0, min(limit, scan_limit))
    if limit <= 0:
        return None, [_refusal(function_id, "unsupported_ir", "function size/scan limit is empty")]
    return (segment_para, entry_ip, function_base, start, start + limit), []


def _lift_function_block(
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


def _scan_lifted_instructions(
    lifted_insns: list[Any],
    instructions: list[dict[str, Any]],
    risk_points: list[dict[str, Any]],
    seen_insns: set[int],
    *,
    function_base: int,
    max_insns: int,
    max_risk_points: int,
) -> bool:
    """Collect unique instruction summaries; return True when the limit is hit."""
    for insn in lifted_insns:
        if len(instructions) >= max_insns:
            return True
        if int(insn.address) in seen_insns:
            continue
        seen_insns.add(int(insn.address))
        summary = _instruction_summary(insn, function_base=function_base)
        summary["address_linear_int"] = int(insn.address)
        instructions.append(summary)
        _append_instruction_risk_points(risk_points, summary=summary, max_risk_points=max_risk_points)
    return False


def _scan_function_window(
    *,
    project: Any,  # noqa: ANN401
    function_id: str,
    function_base: int,
    start: int,
    end: int,
    max_blocks: int,
    max_insns: int,
    max_risk_points: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], int, bool, set[int]]:
    """BFS-scan one function window; return instructions, risks, refusals."""
    pending = [start]
    seen_blocks: set[int] = set()
    seen_insns: set[int] = set()
    instructions: list[dict[str, Any]] = []
    risk_points: list[dict[str, Any]] = []
    refusals: list[dict[str, Any]] = []
    blocks_lifted = 0
    analysis_limited = False

    while pending and len(seen_blocks) < max_blocks and len(instructions) < max_insns:
        at = pending.pop(0)
        if at < start or at >= end or at in seen_blocks:
            continue
        seen_blocks.add(at)
        lifted_insns, refusal = _lift_function_block(project, function_id, at, start=start, end=end)
        if refusal is not None:
            refusals.append(refusal)
            continue
        blocks_lifted += 1
        if _scan_lifted_instructions(
            lifted_insns,
            instructions,
            risk_points,
            seen_insns,
            function_base=function_base,
            max_insns=max_insns,
            max_risk_points=max_risk_points,
        ):
            analysis_limited = True

        successors = _successors_from_block(lifted_insns, start=start, end=end)
        for successor in successors:
            if successor not in seen_blocks and successor not in pending:
                pending.append(successor)

    if pending or len(seen_blocks) >= max_blocks or len(instructions) >= max_insns:
        analysis_limited = True
        refusals.append(_refusal(function_id, "unsupported_ir", "complexity scan reached block/instruction limit"))
    return instructions, risk_points, refusals, blocks_lifted, analysis_limited, seen_blocks




def _analyze_one_function(
    *,
    project: Any,  # noqa: ANN401
    linked_base: int,
    function: dict[str, Any],
    max_blocks: int,
    max_insns: int,
    max_simple_insns: int,
    simple_score_threshold: int,
    max_simple_symbolic_memory: int,
    max_risk_points: int,
    scan_limit: int,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]], int]:
    function_id = str(function.get("id", "<unknown>"))
    names = function.get("names", []) if isinstance(function.get("names"), list) else []
    function_name = str(names[0]) if names else function_id
    window, window_refusals = _function_scan_window(
        function,
        function_id,
        linked_base=linked_base,
        scan_limit=scan_limit,
    )
    if window is None:
        return None, window_refusals, 0
    segment_para, entry_ip, function_base, start, end = window

    instructions, risk_points, refusals, blocks_lifted, analysis_limited, seen_blocks = _scan_function_window(
        project=project,
        function_id=function_id,
        function_base=function_base,
        start=start,
        end=end,
        max_blocks=max_blocks,
        max_insns=max_insns,
        max_risk_points=max_risk_points,
    )

    if not instructions:
        if not refusals:
            refusals.append(_refusal(function_id, "unsupported_ir", "no lifter-backed instructions found"))
        return None, refusals, blocks_lifted

    metrics = _compute_metrics(instructions)
    metrics["block_count"] = len(seen_blocks)
    metrics["analysis_limited"] = int(analysis_limited)
    risk = _risk_summary(metrics)
    classification, blockers = _classify(
        metrics=metrics,
        risk_score=int(risk["score"]),
        max_simple_insns=max_simple_insns,
        simple_score_threshold=simple_score_threshold,
        max_simple_symbolic_memory=max_simple_symbolic_memory,
    )
    comparison_parts = _comparison_parts(
        classification=classification,
        function_id=function_id,
        function_name=function_name,
        segment_para=segment_para,
        function_base=function_base,
        instructions=instructions,
    )
    result_without_id = {
        "function": {"id": function_id, "name": function_name},
        "entry": {
            "cs": normalize_hex(segment_para, width=4),
            "ip": normalize_hex(entry_ip, width=4),
            "linear": normalize_hex(start),
        },
        "end": {
            "cs": normalize_hex(segment_para, width=4),
            "ip": normalize_hex(
                (instructions[-1]["address_linear_int"] + int(instructions[-1]["size"]) - function_base) & 0xFFFF,
                width=4,
            ),
            "linear": normalize_hex(instructions[-1]["address_linear_int"] + int(instructions[-1]["size"])),
        },
        "classification": classification,
        "blockers": blockers,
        "metrics": metrics,
        "risk": risk,
        "risk_points": risk_points,
        "comparison_parts": comparison_parts,
        "sample_instructions": [
            _sample_instruction(instruction) for instruction in instructions[: min(8, len(instructions))]
        ],
    }
    sample_instructions = result_without_id["sample_instructions"]
    assert isinstance(sample_instructions, list)
    for instruction in sample_instructions:
        instruction.pop("address_linear_int", None)
    result = dict(result_without_id)
    result["id"] = stable_id("complexity-function", result_without_id)
    return result, refusals, blocks_lifted


def _compute_metrics(instructions: list[dict[str, Any]]) -> dict[str, int]:
    metrics = {
        "instruction_count": len(instructions),
        "condition_count": 0,
        "branch_count": 0,
        "jump_count": 0,
        "call_count": 0,
        "interrupt_count": 0,
        "return_count": 0,
        "indirect_control_count": 0,
        "memory_read_count": 0,
        "memory_write_count": 0,
        "explicit_memory_read_count": 0,
        "explicit_memory_write_count": 0,
        "explicit_symbolic_memory_count": 0,
        "segment_sensitive_memory_count": 0,
        "flag_read_count": 0,
        "flag_write_count": 0,
        "partial_register_count": 0,
        "variable_shift_count": 0,
        "mul_div_count": 0,
        "string_instruction_count": 0,
        "loop_like_count": 0,
        "backward_branch_count": 0,
        "has_return": 0,
    }
    for instruction in instructions:
        mnemonic = str(instruction.get("mnemonic", "")).lower()
        control = instruction.get("control", {})
        control_kind = str(control.get("kind", "none"))
        _accumulate_control_metrics(metrics, instruction, mnemonic, control, control_kind)
        _accumulate_effect_metrics(metrics, instruction)

        if _is_backward_control(instruction):
            metrics["backward_branch_count"] += 1
    return metrics


def _accumulate_branch_metrics(
    metrics: dict[str, int],
    mnemonic: str,
    control: dict[str, Any],
    control_kind: str,
) -> None:
    """Accumulate branch, call, and indirect-control counters."""
    if control_kind == "conditional_branch" or mnemonic in LOOP_MNEMONICS:
        metrics["condition_count"] += 1
        metrics["branch_count"] += 1
    elif control_kind == "jump":
        metrics["jump_count"] += 1
        metrics["branch_count"] += 1
    if mnemonic in CALL_MNEMONICS:
        metrics["call_count"] += 1
        if control.get("target") is None:
            metrics["indirect_control_count"] += 1
    if mnemonic in INTERRUPT_MNEMONICS:
        metrics["interrupt_count"] += 1
    if mnemonic in RETURN_MNEMONICS:
        metrics["return_count"] += 1
        metrics["has_return"] = 1
    if mnemonic in JUMP_MNEMONICS and control.get("target") is None:
        metrics["indirect_control_count"] += 1
    if control_kind == "conditional_branch" and control.get("target") is None:
        metrics["indirect_control_count"] += 1
    if mnemonic in LOOP_MNEMONICS:
        metrics["loop_like_count"] += 1


def _accumulate_control_metrics(
    metrics: dict[str, int],
    instruction: dict[str, Any],
    mnemonic: str,
    control: dict[str, Any],
    control_kind: str,
) -> None:
    """Accumulate the control-flow and opcode-class counters."""
    _accumulate_branch_metrics(metrics, mnemonic, control, control_kind)
    if _is_string_mnemonic(mnemonic):
        metrics["string_instruction_count"] += 1
    if mnemonic in MUL_DIV_MNEMONICS:
        metrics["mul_div_count"] += 1
    if _is_variable_shift(instruction):
        metrics["variable_shift_count"] += 1
    if _uses_partial_register(instruction):
        metrics["partial_register_count"] += 1


def _accumulate_memory_effects(
    metrics: dict[str, int],
    memories: list[dict[str, Any]],
    *,
    explicit_key: str,
) -> None:
    """Accumulate explicit/symbolic/segment-sensitive memory counters."""
    for memory in memories:
        if memory.get("implicit"):
            continue
        metrics[explicit_key] += 1
        if memory.get("base") or memory.get("index"):
            metrics["explicit_symbolic_memory_count"] += 1
        if str(memory.get("space", "")).upper() in SEGMENT_SENSITIVE_SPACES or memory.get("explicit_segment"):
            metrics["segment_sensitive_memory_count"] += 1


def _accumulate_effect_metrics(metrics: dict[str, int], instruction: dict[str, Any]) -> None:
    """Accumulate the memory and flag effect counters."""
    effects = instruction.get("effects", {})
    memory_reads = list(effects.get("memory_read", []) or [])
    memory_writes = list(effects.get("memory_written", []) or [])
    metrics["memory_read_count"] += len(memory_reads)
    metrics["memory_write_count"] += len(memory_writes)
    _accumulate_memory_effects(metrics, memory_reads, explicit_key="explicit_memory_read_count")
    _accumulate_memory_effects(metrics, memory_writes, explicit_key="explicit_memory_write_count")
    metrics["flag_read_count"] += len(effects.get("flags_read", []) or [])
    metrics["flag_write_count"] += len(effects.get("flags_written", []) or [])


def _risk_summary(metrics: dict[str, int]) -> dict[str, Any]:
    factors: list[dict[str, Any]] = []
    instruction_score = metrics.get("instruction_count", 0) // 8
    if instruction_score:
        factors.append(
            {
                "kind": "instruction_count",
                "count": metrics.get("instruction_count", 0),
                "weight": "floor(count/8)",
                "score": instruction_score,
            }
        )
    for key, weight in RISK_WEIGHTS.items():
        count = int(metrics.get(key, 0))
        if count <= 0:
            continue
        factors.append({"kind": key, "count": count, "weight": weight, "score": count * weight})
    score = sum(int(item["score"]) for item in factors)
    return {"score": score, "factors": factors}


def _classify(
    *,
    metrics: dict[str, int],
    risk_score: int,
    max_simple_insns: int,
    simple_score_threshold: int,
    max_simple_symbolic_memory: int,
) -> tuple[str, list[dict[str, Any]]]:
    blockers: list[dict[str, Any]] = []

    def block(kind: str, metric: str, value: int, limit: int | str) -> None:
        blockers.append({"kind": kind, "metric": metric, "value": value, "limit": limit})

    instruction_count = int(metrics.get("instruction_count", 0))
    if instruction_count <= 0:
        block("empty_function", "instruction_count", instruction_count, "> 0")
    if instruction_count > max_simple_insns:
        block("too_many_instructions", "instruction_count", instruction_count, max_simple_insns)
    for metric, kind in (
        ("condition_count", "conditions"),
        ("jump_count", "jumps"),
        ("call_count", "calls"),
        ("interrupt_count", "interrupts"),
        ("indirect_control_count", "indirect_control"),
        ("loop_like_count", "loops"),
        ("backward_branch_count", "backward_branches"),
        ("string_instruction_count", "string_instructions"),
        ("analysis_limited", "analysis_limited"),
    ):
        value = int(metrics.get(metric, 0))
        if value:
            block(kind, metric, value, 0)
    symbolic_memory = int(metrics.get("explicit_symbolic_memory_count", 0))
    if symbolic_memory > max_simple_symbolic_memory:
        block("symbolic_memory", "explicit_symbolic_memory_count", symbolic_memory, max_simple_symbolic_memory)
    if not int(metrics.get("has_return", 0)):
        block("no_return", "has_return", 0, 1)
    if risk_score > simple_score_threshold:
        block("z3_risk_score", "risk.score", risk_score, simple_score_threshold)
    if blockers:
        return "complex", blockers
    return "simple_whole_function", []


def _comparison_parts(
    *,
    classification: str,
    function_id: str,
    function_name: str,
    segment_para: int,
    function_base: int,
    instructions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if classification != "simple_whole_function" or not instructions:
        return []
    start_linear = int(instructions[0]["address_linear_int"])
    end_linear = int(instructions[-1]["address_linear_int"]) + int(instructions[-1]["size"])
    part_without_id = {
        "kind": "whole_function",
        "function": {"id": function_id, "name": function_name},
        "entry": {
            "cs": normalize_hex(segment_para, width=4),
            "ip": normalize_hex((start_linear - function_base) & 0xFFFF, width=4),
            "linear": normalize_hex(start_linear),
        },
        "end": {
            "cs": normalize_hex(segment_para, width=4),
            "ip": normalize_hex((end_linear - function_base) & 0xFFFF, width=4),
            "linear": normalize_hex(end_linear),
        },
        "instruction_count": len(instructions),
        "reason": "simple_whole_function",
    }
    part = dict(part_without_id)
    part["id"] = stable_id("comparison-part", part_without_id)
    return [part]


def _control_risk_kinds(summary: dict[str, Any], mnemonic: str) -> list[str]:
    """Return control-flow risk kinds for one instruction summary."""
    kinds: list[str] = []
    control_kind = str(summary.get("control", {}).get("kind", "none"))
    if control_kind == "conditional_branch" or mnemonic in LOOP_MNEMONICS:
        kinds.append("condition")
    if mnemonic in CALL_MNEMONICS:
        kinds.append("call")
    if mnemonic in INTERRUPT_MNEMONICS:
        kinds.append("interrupt")
    if mnemonic in JUMP_MNEMONICS and summary.get("control", {}).get("target") is None:
        kinds.append("indirect_control")
    if _is_backward_control(summary):
        kinds.append("backward_branch")
    return kinds


def _data_risk_kinds(summary: dict[str, Any], mnemonic: str) -> list[str]:
    """Return data-path and memory risk kinds for one instruction summary."""
    kinds: list[str] = []
    if _is_variable_shift(summary):
        kinds.append("variable_shift")
    if mnemonic in MUL_DIV_MNEMONICS:
        kinds.append("mul_div")
    if _is_string_mnemonic(mnemonic):
        kinds.append("string_instruction")
    if _uses_partial_register(summary):
        kinds.append("partial_register")
    effects = summary.get("effects", {})
    for memory in list(effects.get("memory_read", []) or []) + list(effects.get("memory_written", []) or []):
        if memory.get("implicit"):
            continue
        if memory.get("base") or memory.get("index"):
            kinds.append("symbolic_memory")
            break
    return kinds




def _append_instruction_risk_points(
    risk_points: list[dict[str, Any]], *, summary: dict[str, Any], max_risk_points: int
) -> None:
    if len(risk_points) >= max_risk_points:
        return
    mnemonic = str(summary.get("mnemonic", "")).lower()
    kinds = _control_risk_kinds(summary, mnemonic) + _data_risk_kinds(summary, mnemonic)
    if not kinds:
        return
    risk_points.append(
        {
            "kinds": sorted(set(kinds)),
            "address": summary.get("address"),
            "size": summary.get("size"),
            "disassembly": _disassembly(summary),
        }
    )


def _successors_from_block(insns: list[Any], *, start: int, end: int) -> list[int]:
    if not insns:
        return []
    last = insns[-1]
    mnemonic = str(last.mnemonic).lower()
    next_linear = int(last.address) + int(last.size)
    successors: list[int] = []
    if mnemonic in REGION_BRANCH_MNEMONICS or mnemonic in LOOP_MNEMONICS:
        target = _target_int(last)
        if target is not None:
            successors.append(target)
        successors.append(next_linear)
    elif mnemonic in JUMP_MNEMONICS:
        target = _target_int(last)
        if target is not None:
            successors.append(target)
    elif mnemonic in CALL_MNEMONICS:
        successors.append(next_linear)
    elif mnemonic in RETURN_MNEMONICS or mnemonic in INTERRUPT_MNEMONICS:
        return []
    else:
        successors.append(next_linear)
    return [target for target in successors if start <= target < end]


def _is_backward_control(instruction: dict[str, Any]) -> bool:
    control = instruction.get("control", {})
    if control.get("kind") not in {"conditional_branch", "jump"}:
        return False
    target = control.get("target")
    if target is None:
        return False
    try:
        target_int = parse_int(target, field="control.target")
    except DosUnitError:
        return False
    return bool(target_int < int(instruction.get("address_linear_int", 0)))


def _is_variable_shift(instruction: dict[str, Any]) -> bool:
    mnemonic = str(instruction.get("mnemonic", "")).lower()
    if mnemonic not in SHIFT_ROTATE_MNEMONICS:
        return False
    operands = list(instruction.get("operands", []) or [])
    if len(operands) < 2:
        return False
    count_operand = operands[1]
    return count_operand.get("kind") == "reg" or count_operand.get("kind") not in {"imm"}


def _uses_partial_register(instruction: dict[str, Any]) -> bool:
    for operand in instruction.get("operands", []) or []:
        if operand.get("kind") == "reg" and str(operand.get("name", "")).lower() in PARTIAL_REGS:
            return True
    effects = instruction.get("effects", {})
    for reg in list(effects.get("regs_read", []) or []) + list(effects.get("regs_written", []) or []):
        if str(reg).lower() in PARTIAL_REGS:
            return True
    return False


def _is_string_mnemonic(mnemonic: str) -> bool:
    text = mnemonic
    for prefix in REP_PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    return text.startswith(STRING_MNEMONIC_PREFIXES)


def _sample_instruction(instruction: dict[str, Any]) -> dict[str, Any]:
    sample = {
        "address": instruction.get("address"),
        "address_linear_int": int(instruction.get("address_linear_int", 0)),
        "size": instruction.get("size"),
        "mnemonic": instruction.get("mnemonic"),
        "op_str": instruction.get("op_str"),
        "disassembly": _disassembly(instruction),
    }
    return sample


def _disassembly(instruction: dict[str, Any]) -> str:
    mnemonic = str(instruction.get("mnemonic", ""))
    op_str = str(instruction.get("op_str", ""))
    return mnemonic if not op_str else f"{mnemonic} {op_str}"


def _refusal(function_id: str, reason: str, message: str) -> dict[str, Any]:
    return {
        "status": "refused",
        "reason": reason,
        "detail": {"function_id": function_id, "strategy": "complexity", "message": message},
    }
