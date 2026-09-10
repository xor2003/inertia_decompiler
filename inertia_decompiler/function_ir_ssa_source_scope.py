"""Define implementation owners for the persistent function IR/SSA cache.

Layer: CLI/fallback/reporting orchestration.
Responsibility: enumerate code that can change the raw x86-16 IR/SSA bundle
without pulling downstream Alias, Widening, Types, Structuring, or Rewrite
implementation into the cache identity.

Keep this positive manifest synchronized when the frontend or IR importer gains
a new output-affecting dependency. Downstream consumers must not be added merely
because package initialization imports them.
"""

from __future__ import annotations

from pathlib import Path

_INERTIA_OWNER_NAMES_8616 = (
    "cache.py",
    "cache_io.py",
    "cache_lock.py",
    "cache_runtime_contract.py",
    "cache_source_manifest.py",
    "function_ir_ssa_cache.py",
    "function_ir_ssa_cache_codec.py",
    "function_ir_ssa_cache_identity.py",
    "function_ir_ssa_source_scope.py",
    "runtime_support.py",
)

_FRONTEND_OWNER_NAMES_8616 = (
    "__init__.py",
    "access.py",
    "address_ir.py",
    "addressing_helpers.py",
    "alu_helpers.py",
    "arch_86_16.py",
    "callee_name_normalization.py",
    "compiler_helpers.py",
    "cr.py",
    "debug.py",
    "dev_io.py",
    "direction_step.py",
    "eflags.py",
    "emu.py",
    "emulator.py",
    "exception.py",
    "exec.py",
    "frontend_block_inventory.py",
    "frontend_capstone_block.py",
    "frontend_capstone_decode.py",
    "frontend_function_boundary.py",
    "frontend_instruction_kinds.py",
    "frontend_instruction_reachability.py",
    "hardware.py",
    "instr16.py",
    "instr32.py",
    "instr_base.py",
    "instruction.py",
    "interrupt.py",
    "interrupt_contract.py",
    "io.py",
    "jcc_condition.py",
    "lift_86_16.py",
    "memory.py",
    "msvc_x87_interrupts.py",
    "parse.py",
    "processor.py",
    "regs.py",
    "segment_offset_execution.py",
    "stack_helpers.py",
    "string_helpers.py",
    "string_instruction_artifact.py",
)

_ANALYSIS_OWNER_NAMES_8616 = (
    "alias.py",
    "stack_frame_ir.py",
)

_SEMANTICS_OWNER_NAMES_8616 = (
    "alu_semantics.py",
    "evidence_cache.py",
    "immediate_semantics.py",
    "status_flag_cfg_liveness.py",
    "status_flag_contracts.py",
    "status_flag_liveness.py",
)


def function_ir_ssa_cache_source_files_8616(root: Path) -> tuple[Path, ...]:
    """Return exact frontend, IR, analysis, and cache artifact owners."""
    inertia_root = root / "inertia_decompiler"
    x86_root = root / "angr_platforms" / "angr_platforms" / "X86_16"
    discovered = {
        *(inertia_root / name for name in _INERTIA_OWNER_NAMES_8616),
        *(x86_root / name for name in _FRONTEND_OWNER_NAMES_8616),
        *(x86_root / "analysis" / name for name in _ANALYSIS_OWNER_NAMES_8616),
        *(x86_root / "semantics" / name for name in _SEMANTICS_OWNER_NAMES_8616),
        x86_root / "pipeline" / "errors.py",
        root / "pyvex_compat.py",
    }
    discovered.update((x86_root / "ir").rglob("*.py"))
    return tuple(sorted(path for path in discovered if path.is_file()))


__all__ = ["function_ir_ssa_cache_source_files_8616"]
