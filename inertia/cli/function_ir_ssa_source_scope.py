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

from inertia.ir import vex_bit_source

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
    "addressing_helpers.py",
    "arch_86_16.py",
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
)
# Historical frontend owners relocated by the layer reorganization resolve
# through canonical imports inside frontend_cache_source_files_8616:
# address_ir (ir.address_ir_8616), alu_helpers (semantics.alu_semantics),
# callee_name_normalization, compiler_helpers and string_instruction_artifact
# (all inertia/semantics).

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


def frontend_cache_source_files_8616(root: Path) -> tuple[Path, ...]:
    """Follow normal frontend imports to their authoritative source locations.

    Former frontend owners relocated by the layer reorganization are imported
    from their canonical packages so fingerprints hash implementations rather
    than compatibility shims.
    """
    from inertia import frontend, semantics
    from inertia.frontend import x86_16
    from inertia.frontend.x86_16 import (
        arch_86_16,
        control_coordinates,
        direction_step,
        interrupt_contract,
        lifter_backend,
        lifter_import,
        load_dos_mz,
        load_dos_ne,
        ne_resources,
        simos_86_16,
        vex_value_contract,
    )
    from inertia.ir import address_ir_8616
    from inertia.semantics import (
        alu_semantics,
        callee_name_normalization,
        compiler_helpers,
        immediate_semantics,
        status_flag_cfg_liveness,
        status_flag_contracts,
        status_flag_liveness,
        string_instruction_artifact,
    )

    modules = (
        frontend, x86_16, arch_86_16, control_coordinates, interrupt_contract,
        lifter_backend, lifter_import, load_dos_mz, load_dos_ne, ne_resources, simos_86_16,
        direction_step, vex_value_contract, vex_bit_source, address_ir_8616,
        semantics, alu_semantics, callee_name_normalization, compiler_helpers,
        immediate_semantics, status_flag_contracts, status_flag_liveness,
        status_flag_cfg_liveness, string_instruction_artifact,
    )
    return (
        *(Path(module.__file__) for module in modules if module.__file__ is not None),
        root / lifter_backend.LIFTER_SOURCE,
    )


def function_ir_ssa_cache_source_files_8616(root: Path) -> tuple[Path, ...]:
    """Return exact frontend, IR, analysis, and cache artifact owners."""
    from inertia import ir, pipeline, semantics
    from inertia.frontend import x86_16
    from inertia.ir import analysis as ir_analysis

    inertia_root = root / "inertia" / "cli"
    x86_root = Path(x86_16.__file__).parent
    ir_root = Path(ir.__file__).parent
    analysis_root = Path(ir_analysis.__file__).parent
    semantics_root = Path(semantics.__file__).parent
    pipeline_root = Path(pipeline.__file__).parent
    discovered = {
        *(inertia_root / name for name in _INERTIA_OWNER_NAMES_8616),
        *(x86_root / name for name in _FRONTEND_OWNER_NAMES_8616),
        *(analysis_root / name for name in _ANALYSIS_OWNER_NAMES_8616),
        *(semantics_root / name for name in _SEMANTICS_OWNER_NAMES_8616),
        pipeline_root / "errors.py",
        root / "pyvex_compat.py",
        root / "angr_platforms/__init__.py",
        root / "angr_platforms/angr_platforms/__init__.py",
        root / "angr_platforms/angr_platforms/import_identity.py",
        *ir_root.rglob("*.py"),
        *frontend_cache_source_files_8616(root),
    }
    return tuple(sorted(path for path in discovered if path.is_file()))


__all__ = ["function_ir_ssa_cache_source_files_8616"]
