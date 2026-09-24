"""Publish proven register locals to angr structured codegen.

Layer: Types/Lowering.
Responsibility: keep typed register storage identities and C local declaration
metadata coherent after semantic lowering creates or rebinds a register local.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

This module does not infer register use or names. Callers must provide an exact
typed ``SimRegisterVariable`` identity already proven by their owning lowering
contract.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.ailment import Expr
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.rustylib.ailment import VirtualVariableCategory
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypeShort
from angr.sim_variable import SimRegisterVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from ..pipeline.errors import PipelineHardError

__all__ = [
    "RegisterLocalDeclarationResult8616",
    "materialize_typed_register_locals_8616",
    "register_typed_register_local_8616",
]


class _CFunctionDeclarationBoundary8616(Protocol):
    """Third-party CFunction declaration maps consumed by code generation."""

    addr: object
    variables_in_use: object
    unified_local_vars: object
    variable_manager: object
    statements: object


class _CodegenDeclarationBoundary8616(Protocol):
    """Third-party structured-codegen surface containing the active function."""

    cfunc: object
    project: object


class _ProjectArchBoundary8616(Protocol):
    """Third-party project architecture used for exact register identities."""

    arch: object


class _ArchRegistersBoundary8616(Protocol):
    """Third-party architecture register-name and shape maps."""

    registers: dict[str, tuple[int, int]]


class _VariableManagerBoundary8616(Protocol):
    """Third-party angr variable manager exposing unified storage identity."""

    def unified_variable(self, variable: SimRegisterVariable) -> object | None:
        """Return angr's exact unified identity for one register variable."""


class _RootAddressBoundary8616(Protocol):
    """Third-party C-AST root exposing an optional function address."""

    addr: object


class _RegisterLocalResultBoundary8616(Protocol):
    """Dynamic codegen boundary carrying the latest declaration result."""

    _inertia_register_local_declaration_result_8616: RegisterLocalDeclarationResult8616


@dataclass(frozen=True, slots=True)
class RegisterLocalDeclarationResult8616:
    """Closed evidence counters for one typed register-local replay."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    changed_count: int = 0

    @property
    def changed(self) -> bool:
        """Return whether declaration metadata changed."""
        return self.changed_count > 0

    @property
    def closed(self) -> bool:
        """Return whether every observed register use has one terminal lane."""
        return bool(
            self.raw_fact_count == self.normalized_fact_count + self.failure_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count == self.materialized_count
            and 0 <= self.changed_count <= self.materialized_count
        )


_NONLOCAL_REGISTER_NAMES_8616 = frozenset(
    {"bp", "cs", "ds", "eip", "es", "flags", "fs", "gs", "ip", "sp", "ss"}
)


def _register_scalar_type_8616(size: int, arch: object) -> object | None:
    """Return the exact unsigned scalar type for one physical register width."""
    scalar_type = {
        1: SimTypeChar(False),
        2: SimTypeShort(False),
        4: SimTypeInt(False),
    }.get(size)
    return scalar_type.with_arch(arch) if scalar_type is not None else None


@dataclass(slots=True)
class _RegisterCarrierContext8616:
    """Shared boundary and evidence state for the carrier rebinding pass."""

    codegen: object
    project: _ProjectArchBoundary8616
    region: int
    exact_registers: set[tuple[int, int, str]]
    declarations: dict[tuple[int, int, str], structured_c.CVariable]
    register_variables: dict[tuple[int, int, str], SimRegisterVariable]
    changed_count: int = 0


def _carrier_boundary_8616(
    codegen: object,
) -> tuple[_ProjectArchBoundary8616, dict[str, tuple[int, int]], _CFunctionDeclarationBoundary8616] | None:
    """Resolve the typed codegen boundary for register materialization."""
    try:
        boundary = cast(_CodegenDeclarationBoundary8616, codegen)
        project = cast(_ProjectArchBoundary8616, boundary.project)
        arch = cast(_ArchRegistersBoundary8616, project.arch)
        registers = arch.registers
        cfunc = cast(_CFunctionDeclarationBoundary8616, boundary.cfunc)
    except AttributeError:
        return None
    if not isinstance(registers, dict):
        return None
    return project, registers, cfunc


def _declaration_region_8616(cfunc: object, root: object) -> int | None:
    """Resolve the owning region address from the function or root node."""
    try:
        region = cast(_CFunctionDeclarationBoundary8616, cfunc).addr
    except AttributeError:
        region = None
    if not isinstance(region, int):
        try:
            region = cast(_RootAddressBoundary8616, root).addr
        except AttributeError:
            return None
    return region if isinstance(region, int) else None


def _exact_register_keys_8616(registers: object) -> set[tuple[int, int, str]]:
    """Collect exact (offset, size, lowercase-name) register identities."""
    return {
        (shape[0], shape[1], name.lower())
        for name, shape in cast(dict[object, object], registers).items()
        if isinstance(name, str)
        and isinstance(shape, tuple)
        and len(shape) >= 2
        and isinstance(shape[0], int)
        and isinstance(shape[1], int)
    }


def _shared_register_variable_8616(
    ctx: _RegisterCarrierContext8616, offset: int, size: int, normalized_name: str
) -> SimRegisterVariable:
    """Return the shared SimRegisterVariable for one exact register lane."""
    key = (offset, size, normalized_name)
    shared = ctx.register_variables.get(key)
    if shared is None:
        shared = SimRegisterVariable(
            offset,
            size,
            ident=f"inertia-register-{normalized_name}",
            region=ctx.region,
            name=normalized_name,
        )
        ctx.register_variables[key] = shared
    return shared


def _rebind_c_variable_8616(ctx: _RegisterCarrierContext8616, node: object) -> object | None:
    """Rebind one direct CVariable register carrier, or None."""
    if not isinstance(node, structured_c.CVariable) or not isinstance(node.variable, SimRegisterVariable):
        return None
    variable = node.variable
    normalized_name = variable.name.lower() if isinstance(variable.name, str) else None
    if normalized_name is None:
        return None
    key = (variable.reg, variable.size, normalized_name)
    if key not in ctx.exact_registers or normalized_name in _NONLOCAL_REGISTER_NAMES_8616:
        return None
    shared = _shared_register_variable_8616(ctx, variable.reg, variable.size, normalized_name)
    if node.variable is not shared or node.unified_variable is not shared:
        node.variable = shared
        node.unified_variable = shared
        ctx.changed_count += 1
    if node.variable_type is None:
        node.variable_type = _register_scalar_type_8616(variable.size, ctx.project.arch)
    return cast(object, node)


def _virtual_dirty_key_8616(
    virtual: Expr.VirtualVariable, exact_registers: set[tuple[int, int, str]]
) -> tuple[int, int, str] | None:
    """Resolve a dirty virtual register to its exact register-set key."""
    if virtual.category is not VirtualVariableCategory.REGISTER:
        return None
    offset = virtual.oident
    size = virtual.size
    name = dict(virtual.tags).get("reg_name")
    if not isinstance(offset, int) or not isinstance(size, int):
        return None
    if not isinstance(name, str):
        matching_names = {
            register_name
            for register_offset, register_size, register_name in exact_registers
            if register_offset == offset and register_size == size
        }
        if len(matching_names) != 1:
            return None
        name = next(iter(matching_names))
    normalized_name = name.lower()
    key = (offset, size, normalized_name)
    if key not in exact_registers or normalized_name in _NONLOCAL_REGISTER_NAMES_8616:
        return None
    return key


def _rebind_virtual_dirty_8616(ctx: _RegisterCarrierContext8616, node: object) -> object:
    """Rebind one register-origin dirty virtual carrier to a typed local."""
    if not isinstance(node, structured_c.CDirtyExpression) or not isinstance(node.dirty, Expr.VirtualVariable):
        return node
    key = _virtual_dirty_key_8616(node.dirty, ctx.exact_registers)
    if key is None:
        return node
    offset, size, normalized_name = key
    variable_type = _register_scalar_type_8616(size, ctx.project.arch)
    if variable_type is None:
        return node
    declaration = ctx.declarations.get(key)
    if declaration is None:
        shared = _shared_register_variable_8616(ctx, offset, size, normalized_name)
        declaration = structured_c.CVariable(
            shared,
            unified_variable=shared,
            variable_type=variable_type,
            codegen=ctx.codegen,
        )
        ctx.declarations[key] = declaration
    ctx.changed_count += 1
    return declaration


def _materialize_register_virtual_carriers_8616(codegen: object, root: object) -> int:
    """Rebind exact general-register virtual carriers to typed C locals."""
    boundary = _carrier_boundary_8616(codegen)
    if boundary is None:
        return 0
    project, registers, cfunc = boundary
    region = _declaration_region_8616(cfunc, root)
    if region is None:
        return 0
    ctx = _RegisterCarrierContext8616(
        codegen,
        project,
        region,
        _exact_register_keys_8616(registers),
        {},
        {},
    )

    def _transform(node: object) -> object:
        """Replace one exact register-origin virtual carrier."""
        result = _rebind_c_variable_8616(ctx, node)
        if result is not None:
            return result
        return _rebind_virtual_dirty_8616(ctx, node)

    _replace_c_children_8616(root, _transform)
    return ctx.changed_count


def _remove_declaration_entries_8616(
    entries: set[object],
    declaration: structured_c.CVariable,
    *,
    keep: tuple[object, object] | None = None,
) -> bool:
    """Remove stale entries for one declaration without dropping its peers."""
    stale_entries = {
        entry
        for entry in entries
        if isinstance(entry, tuple)
        and bool(entry)
        and entry[0] is declaration
        and entry != keep
    }
    if not stale_entries:
        return False
    entries.difference_update(stale_entries)
    return True


def _unified_register_identity_8616(
    cfunc: _CFunctionDeclarationBoundary8616,
    variable: SimRegisterVariable,
) -> SimRegisterVariable:
    """Resolve an exact angr unified identity without guessing by register shape."""
    try:
        variable_manager = cfunc.variable_manager
        unified = cast(_VariableManagerBoundary8616, variable_manager).unified_variable(variable)
    except (AttributeError, KeyError, TypeError, ValueError):
        return variable
    return unified if isinstance(unified, SimRegisterVariable) else variable


def _register_declaration_maps_8616(
    codegen: object,
) -> tuple[
    _CFunctionDeclarationBoundary8616,
    dict[object, object],
    dict[object, object],
]:
    """Return the two angr declaration maps or raise a contract error."""
    try:
        cfunc = cast(_CFunctionDeclarationBoundary8616, cast(_CodegenDeclarationBoundary8616, codegen).cfunc)
        variables_in_use = cfunc.variables_in_use
        unified_local_vars = cfunc.unified_local_vars
    except AttributeError as exc:
        raise PipelineHardError(
            "structured codegen omitted register-local declaration maps",
            layer="types/lowering:register_local_declarations",
        ) from exc
    if not isinstance(variables_in_use, dict) or not isinstance(unified_local_vars, dict):
        raise PipelineHardError(
            "structured codegen exposed invalid register-local declaration maps",
            layer="types/lowering:register_local_declarations",
        )
    return cfunc, variables_in_use, unified_local_vars


def _sync_variables_in_use_8616(
    variables_in_use: dict[object, object],
    variable: SimRegisterVariable,
    declaration: structured_c.CVariable,
) -> bool:
    """Drop stale aliases and bind the declaration under its variable."""
    changed = False
    for prior_variable, prior_declaration in tuple(variables_in_use.items()):
        if prior_declaration is declaration and prior_variable is not variable:
            del variables_in_use[prior_variable]
            changed = True
    if variables_in_use.get(variable) is not declaration:
        variables_in_use[variable] = declaration
        changed = True
    return changed


def _sync_unified_local_vars_8616(
    unified_local_vars: dict[object, object],
    declaration_identity: SimRegisterVariable,
    declaration: structured_c.CVariable,
    variable_type: object,
) -> bool:
    """Keep the identity's typed-entry set holding exactly this declaration."""
    changed = False
    typed_entry = (declaration, variable_type)
    for prior_variable, entries in tuple(unified_local_vars.items()):
        if prior_variable is declaration_identity or not isinstance(entries, set):
            continue
        typed_entries = cast(set[object], entries)
        if _remove_declaration_entries_8616(typed_entries, declaration):
            changed = True
            if not typed_entries:
                del unified_local_vars[prior_variable]
    entries = unified_local_vars.get(declaration_identity)
    if not isinstance(entries, set):
        unified_local_vars[declaration_identity] = {typed_entry}
        return True
    typed_entries = cast(set[object], entries)
    if _remove_declaration_entries_8616(typed_entries, declaration, keep=typed_entry):
        changed = True
    if typed_entry not in typed_entries:
        typed_entries.add(typed_entry)
        changed = True
    return changed


def register_typed_register_local_8616(
    codegen: object,
    declaration: structured_c.CVariable,
) -> bool:
    """Register one exact typed register local and return whether maps changed.

    A proven register assignment is not recompilable until the same storage
    identity is present in both angr declaration maps. Missing maps are a hard
    pipeline contract failure, not permission to emit an undeclared variable.
    """
    variable = declaration.variable
    if not isinstance(variable, SimRegisterVariable):
        raise PipelineHardError(
            "typed register local declaration requires SimRegisterVariable storage",
            layer="types/lowering:register_local_declarations",
        )
    cfunc, variables_in_use, unified_local_vars = _register_declaration_maps_8616(codegen)

    variable_type = declaration.variable_type
    if variable_type is None:
        raise PipelineHardError(
            "typed register local declaration omitted its proven type",
            layer="types/lowering:register_local_declarations",
        )

    declaration_identity = _unified_register_identity_8616(cfunc, variable)
    changed = declaration_identity is not variable and declaration.unified_variable is not declaration_identity
    if changed:
        declaration.unified_variable = declaration_identity
    if _sync_variables_in_use_8616(variables_in_use, variable, declaration):
        changed = True
    if _sync_unified_local_vars_8616(
        unified_local_vars, declaration_identity, declaration, variable_type
    ):
        changed = True
    return changed


def materialize_typed_register_locals_8616(codegen: object) -> RegisterLocalDeclarationResult8616:
    """Publish every typed live register local after a Lowering/AST replay."""
    try:
        boundary = cast(_CodegenDeclarationBoundary8616, codegen)
        cfunc = cast(_CFunctionDeclarationBoundary8616, boundary.cfunc)
        arch = cast(_ProjectArchBoundary8616, boundary.project).arch
        root = cfunc.statements
    except AttributeError as exc:
        raise PipelineHardError(
            "structured codegen omitted the register-local AST boundary",
            layer="types/lowering:register_local_declarations",
        ) from exc

    _materialize_register_virtual_carriers_8616(codegen, root)
    raw_fact_count = 0
    normalized_fact_count = 0
    classified_fact_count = 0
    materialized_count = 0
    failure_count = 0
    changed_count = 0
    seen: set[int] = set()
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, structured_c.CVariable) or id(node) in seen:
            continue
        seen.add(id(node))
        if not isinstance(node.variable, SimRegisterVariable):
            continue
        raw_fact_count += 1
        declaration_changed = False
        if node.variable_type is None:
            variable_type = _register_scalar_type_8616(node.variable.size, arch)
            if variable_type is None:
                failure_count += 1
                continue
            node.variable_type = variable_type
            declaration_changed = True
        normalized_fact_count += 1
        classified_fact_count += 1
        changed_count += int(register_typed_register_local_8616(codegen, node) or declaration_changed)
        materialized_count += 1

    result = RegisterLocalDeclarationResult8616(
        raw_fact_count=raw_fact_count,
        normalized_fact_count=normalized_fact_count,
        classified_fact_count=classified_fact_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
        changed_count=changed_count,
    )
    cast(_RegisterLocalResultBoundary8616, codegen)._inertia_register_local_declaration_result_8616 = result
    if not result.closed:
        raise PipelineHardError(
            "register-local declaration evidence accounting did not close",
            layer="types/lowering:register_local_declarations",
        )
    if failure_count:
        raise PipelineHardError(
            "live register locals omitted proven declaration types: "
            f"raw={raw_fact_count} normalized={normalized_fact_count} failures={failure_count}",
            layer="types/lowering:register_local_declarations",
        )
    return result
