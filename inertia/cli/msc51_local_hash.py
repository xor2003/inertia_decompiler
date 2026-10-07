"""MSC 5.1 local variable name hash diagnostics.

Layer: CLI/fallback/reporting.
Responsibility: report optional MSC 5.1 local-name hash diagnostics without proving stack semantics.

MSC 5.1 uses a 16-bucket hash table for local variable symbols.
hash(name) = sum(ord(c.upper()) for c in name) % 16
Collision resolution: backward linear probing (probe to bucket-1).
Allocation order: iterate buckets 0..15, assigning bp-2, bp-4, ...

This module diagnoses whether recovered variable names are consistent
with MSC 5.1's hashing mechanism.
"""

from __future__ import annotations

from typing import Protocol, cast


class _CodegenFunctionLike(Protocol):
    variables_in_use: dict[object, object]
    addr: int | None


class _CodegenLike(Protocol):
    cfunc: _CodegenFunctionLike | None


def msc51_hash(name: str) -> int:
    """Compute MSC 5.1 bucket index for a local variable name."""
    return sum(ord(c.upper()) for c in name) % 16


def msc51_simulate_allocation(names: list[str]) -> dict[str, int]:
    """Simulate MSC 5.1 hash table insertion.

    Args:
        names: Variable names in declaration order.

    Returns:
        Dict mapping each name to its bucket index (0..15).
    """
    table: list[str | None] = [None] * 16
    for name in names:
        bucket = msc51_hash(name)
        for probe in range(16):
            idx = (bucket - probe) % 16
            if table[idx] is None:
                table[idx] = name
                break
        else:
            raise ValueError(f"Hash table full, cannot insert '{name}'")
    return {name: idx for idx, name in enumerate(table) if name is not None}


def msc51_bp_offset_for_bucket(bucket_idx: int, slot_size: int = 2) -> int:
    """Convert a bucket index (0..15) to a BP offset.

    MSC 5.1 allocates in bucket order: bucket 0 -> bp-2, bucket 1 -> bp-4, ...
    Each scalar gets the default 2-byte slot.
    """
    return (bucket_idx + 1) * slot_size


def _collect_named_stack_locals(codegen: object) -> list[tuple[str, int, object]]:
    """Collect named local stack variables with their BP offsets.

    Returns:
        List of (name, bp_offset, variable) sorted by bp_offset ascending
        (most negative first, i.e., bp-2 before bp-4).
        Args and synthetic locals (local_XX, arg_XX, vNN, vvar_NN) are excluded.
    """
    import re

    try:
        cfunc = cast(_CodegenLike, codegen).cfunc
    except AttributeError:
        return []
    if cfunc is None:
        return []
    variables_in_use = cfunc.variables_in_use
    if not isinstance(variables_in_use, dict):
        return []

    from angr.sim_variable import SimStackVariable

    synthetic_name_re = re.compile(
        r"^(?:local_[0-9a-fA-F]+|arg_[0-9a-fA-F]+|v\d+|vvar_\d+|s_[0-9a-fA-F]+|"
        r"ir_\d+(?:_\d+)?|a\d+)$"
    )

    named_locals: list[tuple[str, int, object]] = []
    for variable in variables_in_use:
        if not isinstance(variable, SimStackVariable):
            continue
        base = variable.base
        if base != "bp":
            continue
        offset = variable.offset
        if not isinstance(offset, int) or offset >= 0:
            continue  # skip args (positive BP offsets) for now
        name = variable.name
        if not isinstance(name, str) or not name:
            continue
        if synthetic_name_re.match(name):
            continue

        # Use absolute offset for sorting: bp-2 = 2, bp-4 = 4
        abs_offset = -offset
        named_locals.append((name, abs_offset, variable))

    return sorted(named_locals, key=lambda x: x[1])


def _probe_path_has_gaps_8616(bucket_assignments: dict[str, int], bucket_to_name: dict[int, str]) -> bool:
    """Check 1: no empty gaps in the backward probe path for any variable."""
    for name, assigned_bucket in bucket_assignments.items():
        h = msc51_hash(name)
        if h == assigned_bucket:
            continue
        idx = h
        while idx != assigned_bucket:
            if idx not in bucket_to_name:
                return True  # gap in probe path
            idx = (idx - 1) % 16
    return False


def _must_precede_map_8616(
    names: list[str], bucket_assignments: dict[str, int], bucket_to_name: dict[int, str]
) -> dict[str, set[str]]:
    """Map each displaced variable to the blockers that must precede it."""
    must_precede: dict[str, set[str]] = {name: set() for name in names}
    for name, assigned_bucket in bucket_assignments.items():
        h = msc51_hash(name)
        if h == assigned_bucket:
            continue
        idx = h
        while idx != assigned_bucket:
            blocker = bucket_to_name.get(idx)
            if blocker is not None and blocker != name:
                must_precede[name].add(blocker)
            idx = (idx - 1) % 16
    return must_precede


def _ordering_constraints_acyclic_8616(names: list[str], must_precede: dict[str, set[str]]) -> bool:
    """Check 2: ordering constraints are acyclic (iterative-coloured DFS)."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = dict.fromkeys(names, WHITE)

    def _dfs_visit(node: str) -> bool:
        color[node] = GRAY
        for pred in must_precede.get(node, set()):
            if color.get(pred) == GRAY:
                return False
            if color.get(pred) == WHITE and not _dfs_visit(pred):
                return False
        color[node] = BLACK
        return True

    return all(not (color[name] == WHITE and not _dfs_visit(name)) for name in names)


def _check_declaration_order_feasible(names: list[str], bucket_assignments: dict[str, int]) -> bool:
    """Check whether any declaration order could produce the observed bucket assignments.

    For a variable to end up at bucket b:
      1. All buckets between its hash h and b (exclusive of b, backward direction)
         must be filled by other variables. If any is unoccupied, backward probing
         would have stopped there — the assignment is impossible regardless of order.
      2. Those blocking variables must be declared BEFORE this variable.

    Returns True if both checks pass.
    """
    if len(names) <= 1:
        return True

    bucket_to_name = {b: n for n, b in bucket_assignments.items()}
    if _probe_path_has_gaps_8616(bucket_assignments, bucket_to_name):
        return False
    must_precede = _must_precede_map_8616(names, bucket_assignments, bucket_to_name)
    return _ordering_constraints_acyclic_8616(names, must_precede)


def diagnose_msc51_locals(codegen: object) -> list[str]:
    """Diagnose whether recovered local variable names match MSC 5.1 hash allocation.

    Returns one-line summary per function:
      [dbg] msc51-hash func_0xNNNN: matching compiler hash: a, b | not matching: x (at bp-2, hash says bp-14)
    """
    named_locals = _collect_named_stack_locals(codegen)
    if not named_locals:
        return []

    try:
        cfunc = cast(_CodegenLike, codegen).cfunc
    except AttributeError:
        cfunc = None
    func_addr = cfunc.addr if cfunc is not None else None
    func_label = f"func_{func_addr:#x}" if func_addr is not None else "???"

    matching: list[str] = []
    not_matching: list[str] = []

    for idx, (name, bp_offset, _variable) in enumerate(named_locals):
        h = msc51_hash(name)
        if h == idx:
            matching.append(name)
        else:
            ideal = msc51_bp_offset_for_bucket(h)
            actual = bp_offset
            not_matching.append(f"{name} (at bp-{actual:#x}, hash says bp-{ideal:#x})")

    msg = f"[dbg] msc51-hash {func_label}:"
    msg += f" matching compiler hash: {', '.join(matching) if matching else '(none)'}"
    msg += f" | not matching: {', '.join(not_matching) if not_matching else '(none)'}"

    return [msg]


def emit_msc51_diagnostic(codegen: object) -> None:
    """Emit MSC 5.1 hash diagnostic messages to stderr.

    Args:
        codegen: The angr structured codegen object.
    """
    from .cli_output import _print_diagnostic_text

    messages = diagnose_msc51_locals(codegen)
    if not messages:
        return
    _print_diagnostic_text("\n".join(messages))
