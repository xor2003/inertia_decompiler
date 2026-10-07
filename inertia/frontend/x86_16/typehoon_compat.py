"""Layer: Frontend/angr compatibility.

Responsibility: patch angr Typehoon primitives so 16-bit pointer facts stay typed.
Forbidden: source/COD/text-backed type recovery or object-shape guessing.
Dynamic boundary: compatibility monkeypatches touch third-party angr Typehoon internals only.
"""

from __future__ import annotations

import contextlib
import importlib
import os
from collections import defaultdict
from typing import Any, cast

import claripy
import networkx
from angr.analyses.reaching_definitions import rd_state as _rd_state
from angr.analyses.typehoon import simple_solver as _typehoon_simple_solver
from angr.analyses.typehoon import translator as _typehoon_translator
from angr.analyses.typehoon.simple_solver import BASE_LATTICES, BASE_LATTICES_INVERTED, TypeLattice
from angr.analyses.typehoon.typeconsts import (
    BottomType,
    Int,
    Int16,
    Pointer,
    Pointer32,
    Pointer64,
    TopType,
    TypeConstant,
)
from angr.analyses.typehoon.typeconsts import Int16 as TCInt16
from angr.analyses.typehoon.typevars import TypeVariable, TypeVariableManager
from angr.analyses.variable_recovery import variable_recovery_base as _variable_recovery_base
from angr.sim_type import (
    SimTypeBottom,
    SimTypePointer,
)

try:
    _typehoon_lifter: Any | None = importlib.import_module("angr.analyses.typehoon.lifter")
except ImportError:
    _typehoon_lifter = None

__all__ = ["apply_x86_16_typehoon_compatibility"]


def apply_x86_16_typehoon_compatibility() -> None:
    """Patch angr Typehoon runtime classes across a dynamic third-party compatibility boundary."""
    solver_dynamic = cast(Any, _typehoon_simple_solver)
    translator_dynamic = cast(Any, _typehoon_translator)
    lifter_dynamic = cast(Any, _typehoon_lifter)
    _patch_stack_addr_from_offset_8616()
    _patch_initial_stack_pointer_8616()
    pointer16 = _install_pointer16_lattice_8616(solver_dynamic)
    _patch_simple_solver_8616(solver_dynamic, pointer16)
    _patch_type_translator_8616(translator_dynamic, pointer16)
    if lifter_dynamic is not None:
        _patch_type_lifter_8616(lifter_dynamic, pointer16)


def _patch_stack_addr_from_offset_8616() -> None:
    """Install the 16-bit stack-address shim on VariableRecoveryStateBase."""
    _orig_stack_addr_from_offset = _variable_recovery_base.VariableRecoveryStateBase.stack_addr_from_offset

    def _stack_addr_from_offset_8616(self: object, offset: int) -> int:
        state = cast(Any, self)
        if state.arch.bits == 16:
            return (offset + 0x7FFE) & 0xFFFF
        return int(cast(Any, _orig_stack_addr_from_offset)(self, offset))

    if (
        getattr(_variable_recovery_base.VariableRecoveryStateBase.stack_addr_from_offset, "__name__", "")
        != "_stack_addr_from_offset_8616"
    ):
        _variable_recovery_base.VariableRecoveryStateBase.stack_addr_from_offset = _stack_addr_from_offset_8616


def _patch_initial_stack_pointer_8616() -> None:
    """Install the 16-bit initial-stack-pointer shim on ReachingDefinitionsState."""
    _orig_initial_stack_pointer = _rd_state.ReachingDefinitionsState._initial_stack_pointer

    def _initial_stack_pointer_8616(self: object) -> object:
        state = cast(Any, self)
        if state.arch.bits == 16:
            return claripy.BVS("stack_base", 16, explicit_name=True)
        return cast(Any, _orig_initial_stack_pointer)(self)

    if (
        getattr(_rd_state.ReachingDefinitionsState._initial_stack_pointer, "__name__", "")
        != "_initial_stack_pointer_8616"
    ):
        cast(Any, _rd_state.ReachingDefinitionsState)._initial_stack_pointer = _initial_stack_pointer_8616


def _install_pointer16_lattice_8616(solver_dynamic: object) -> type[Pointer]:
    """Install the Pointer16 type constant and its 16-bit base lattice."""
    solver_module = cast(Any, solver_dynamic)

    class Pointer16(Pointer, TCInt16):  # type: ignore[misc, unused-ignore] # dynamic Typehoon bases
        """16-bit Typehoon pointer constant installed into angr's runtime lattice."""

        def __init__(self, basetype: TypeConstant | None = None, name: str | None = None) -> None:
            Pointer.__init__(self, basetype, name=name)
            TCInt16.__init__(self, name=name)

        def __repr__(self, memo: object | None = None) -> str:
            bt = self.basetype.__repr__(memo=memo) if isinstance(self.basetype, TCInt16) else repr(self.basetype)
            name_str = f"{self.name}#" if self.name else ""
            return f"{name_str}ptr16({bt})"

    if not hasattr(solver_module, "Pointer16"):
        solver_module.Pointer16 = Pointer16
        solver_module.Pointer16_ = Pointer16()
        solver_module.PRIMITIVE_TYPES = set(solver_module.PRIMITIVE_TYPES) | {
            solver_module.Pointer16_
        }

    base_lattice_16_graph = networkx.DiGraph()
    base_lattice_16_graph.add_edge(TopType(), Int())
    base_lattice_16_graph.add_edge(Int(), Int16())
    base_lattice_16_graph.add_edge(Int16(), solver_module.Pointer16_)
    base_lattice_16_graph.add_edge(solver_module.Pointer16_, BottomType())
    BASE_LATTICES[16] = TypeLattice(base_lattice_16_graph)
    BASE_LATTICES_INVERTED[16] = BASE_LATTICES[16].inverted()
    return Pointer16


def _init_simple_solver_16_8616(
    solver_obj: object,
    constraints: object,
    typevars: object,
    constraint_set_degradation_threshold: int,
    stackvar_max_sizes: dict[TypeVariable, int] | None,
    tv_manager: TypeVariableManager | None,
) -> None:
    """Initialize SimpleSolver state for the 16-bit lattice and degrade threshold."""
    solver = cast(Any, solver_obj)
    constraints_payload = cast(Any, constraints)
    typevars_payload = cast(Any, typevars)

    threshold_raw = os.environ.get("INERTIA_X86_16_TYPEHOON_DEGRADE_THRESHOLD", "").strip()
    if threshold_raw:
        with contextlib.suppress(ValueError):
            constraint_set_degradation_threshold = max(1, int(threshold_raw, 0))
    else:
        constraint_set_degradation_threshold = min(int(constraint_set_degradation_threshold), 32)

    solver.bits = 16
    solver._constraints = constraints_payload
    solver._typevars = typevars_payload
    solver.tv_manager = tv_manager if tv_manager is not None else TypeVariableManager(0x1337)
    solver.stackvar_max_sizes = stackvar_max_sizes if stackvar_max_sizes is not None else {}
    solver._constraint_set_degradation_threshold = constraint_set_degradation_threshold
    solver._base_lattice = cast(Any, BASE_LATTICES[16])
    solver._base_lattice_inverted = cast(Any, BASE_LATTICES_INVERTED[16])

    solver.processed_constraints_count = 0
    solver.simplified_constraints_count = 0
    solver.eqclass_constraints_count = []

    solver._equivalence = defaultdict(dict)
    for func_tv in list(solver._constraints):
        if solver._constraints[func_tv]:
            solver.processed_constraints_count += len(solver._constraints[func_tv])
            solver.preprocess(func_tv)
            solver.simplified_constraints_count += len(solver._constraints[func_tv])

    solver._repr_tv_to_tvs = defaultdict(set)
    for tv, repr_tv in solver._equivalence.items():
        solver._repr_tv_to_tvs[repr_tv].add(tv)

    solver.solution = {}
    for tv, sol in solver._equivalence.items():
        if isinstance(tv, TypeVariable) and isinstance(sol, TypeConstant):
            solver.solution[tv] = sol

    solver._solution_cache = {}
    solver.solve()
    for func_tv in list(solver._constraints):
        solver._convert_arrays(solver._constraints[func_tv])

    for tv, tv_eq in solver._equivalence.items():
        if tv not in solver.solution and tv_eq in solver.solution:
            solver.solution[tv] = solver.solution[tv_eq]


def _patch_simple_solver_8616(solver_dynamic: object, pointer16: type[Pointer]) -> None:
    """Patch SimpleSolver dispatch, determination, and init for 16-bit pointers."""
    solver_module = cast(Any, solver_dynamic)

    def _pointer_class_16(self: object) -> type[object]:
        solver = cast(Any, self)
        if solver.bits == 16:
            return pointer16
        if solver.bits == 32:
            return cast(type[object], Pointer32)
        if solver.bits == 64:
            return cast(type[object], Pointer64)
        raise NotImplementedError(f"Unsupported bits {solver.bits}")

    solver_module.SimpleSolver._pointer_class = _pointer_class_16
    _patch_simple_solver_determine_8616(solver_module)
    _patch_simple_solver_init_8616(solver_module)


def _patch_simple_solver_determine_8616(solver_module: object) -> None:
    """Install the unsolved-roots determination shim once."""
    solver_mod = cast(Any, solver_module)
    if getattr(_typehoon_simple_solver.SimpleSolver.determine, "__name__", "") == "_determine_unsolved_roots_8616":
        return
    _orig_determine = _typehoon_simple_solver.SimpleSolver.determine

    def _determine_unsolved_roots_8616(
        self: object,
        sketches: object,
        tvs: object,
        equivalence_classes: dict[TypeVariable, TypeVariable],
        solution: dict[object, object],
        nodes: set[object] | None = None,
    ) -> None:
        """Avoid re-solving 16-bit roots already proven by a connected solve."""
        solver = cast(Any, self)
        if solver.bits != 16 or nodes is not None:
            cast(Any, _orig_determine)(
                self,
                sketches,
                tvs,
                equivalence_classes,
                solution,
                nodes=nodes,
            )
            return

        sketches_by_typevar = cast(Any, sketches)
        for typevar in cast(Any, tvs):
            if typevar in solution:
                continue
            solver._solution_cache = {}
            solver._determine(
                typevar,
                sketches_by_typevar[typevar],
                equivalence_classes,
                solution,
                nodes=None,
            )

        for variable, equivalent in solver._equivalence.items():
            if variable not in solution and equivalent in solution:
                solution[variable] = solution[equivalent]

    solver_mod.SimpleSolver.determine = _determine_unsolved_roots_8616


def _patch_simple_solver_init_8616(solver_module: object) -> None:
    """Install the 16-bit SimpleSolver initializer once."""
    solver_mod = cast(Any, solver_module)
    _orig_simple_solver_init = _typehoon_simple_solver.SimpleSolver.__init__

    def _simple_solver_init_8616(
        self: object,
        bits: int,
        constraints: object,
        typevars: object,
        constraint_set_degradation_threshold: int = 150,
        stackvar_max_sizes: dict[TypeVariable, int] | None = None,
        tv_manager: TypeVariableManager | None = None,
    ) -> None:
        if bits != 16:
            cast(Any, _orig_simple_solver_init)(
                self,
                bits,
                cast(Any, constraints),
                cast(Any, typevars),
                constraint_set_degradation_threshold=constraint_set_degradation_threshold,
                stackvar_max_sizes=stackvar_max_sizes,
                tv_manager=tv_manager,
            )
            return None
        _init_simple_solver_16_8616(
            self,
            constraints,
            typevars,
            constraint_set_degradation_threshold,
            stackvar_max_sizes,
            tv_manager,
        )

    if getattr(_typehoon_simple_solver.SimpleSolver.__init__, "__name__", "") != "_simple_solver_init_8616":
        solver_mod.SimpleSolver.__init__ = _simple_solver_init_8616


def _patch_type_translator_8616(translator_dynamic: object, pointer16: type[Pointer]) -> None:
    """Patch TypeTranslator handlers so SimTypePointer survives 16-bit."""
    translator_module = cast(Any, translator_dynamic)

    def _translate_pointer16(self: object, tc: object) -> SimTypePointer:
        translator = cast(Any, self)
        pointer = cast(Any, tc)
        if isinstance(pointer.basetype, _typehoon_translator.typeconsts.BottomType):
            internal = SimTypeBottom(label="void").with_arch(translator.arch)
        else:
            internal = translator._tc2simtype(pointer.basetype)
        return SimTypePointer(internal).with_arch(translator.arch)

    def _translate_simtype_pointer_16(self: object, st: object) -> object:
        translator = cast(Any, self)
        sim_type = cast(Any, st)
        base = translator._simtype2tc(sim_type.pts_to)
        if translator.arch.bits == 16:
            return pointer16(base)
        if translator.arch.bits == 32:
            return Pointer32(base)
        if translator.arch.bits == 64:
            return Pointer64(base)
        raise TypeError(f"Unsupported pointer size {translator.arch.bits}")

    translator_module.TypeTranslator._translate_Pointer16 = _translate_pointer16
    translator_module.TypeTranslator._translate_SimTypePointer = _translate_simtype_pointer_16
    translator_module.TypeConstHandlers[pointer16] = translator_module.TypeTranslator._translate_Pointer16
    translator_module.SimTypeHandlers[SimTypePointer] = translator_module.TypeTranslator._translate_SimTypePointer


def _patch_type_lifter_8616(lifter_dynamic: object, pointer16: type[Pointer]) -> None:
    """Patch TypeLifter so 16-bit SimTypePointer values lift to Pointer16."""
    lifter_module = cast(Any, lifter_dynamic)
    _orig_lifter_init = lifter_module.TypeLifter.__init__

    def _typelifter_init_16(self: object, bits: int) -> None:
        lifter = cast(Any, self)
        if bits not in (16, 32, 64):
            raise ValueError("TypeLifter only supports 16-bit, 32-bit, or 64-bit pointers.")
        lifter.bits = bits
        lifter.memo = {}

    def _lift_simtype_pointer_16(self: object, ty: object) -> object:
        lifter = cast(Any, self)
        sim_type = cast(Any, ty)
        if lifter.bits == 16:
            return pointer16(lifter.lift(sim_type.pts_to))
        if lifter.bits == 32:
            return lifter_module.Pointer32(lifter.lift(sim_type.pts_to))
        if lifter.bits == 64:
            return lifter_module.Pointer64(lifter.lift(sim_type.pts_to))
        raise ValueError(f"Unsupported bits {lifter.bits}.")

    lifter_module.TypeLifter.__init__ = _typelifter_init_16
    lifter_module.TypeLifter._lift_SimTypePointer = _lift_simtype_pointer_16
