"""Layer: CLI/fallback/reporting.

Responsibility: expose the command entrypoint and compatibility imports.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import contextlib
import os
import sys
from collections.abc import Callable
from importlib import import_module
from types import ModuleType
from typing import TYPE_CHECKING, cast

from .architecture_runtime_guard import (
    DecompilerArchitectureGuardError,
    assert_decompiler_architecture_clean,
)

try:
    assert_decompiler_architecture_clean()
except DecompilerArchitectureGuardError as ex:
    print(str(ex), file=sys.stderr)
    raise SystemExit(3) from ex

if TYPE_CHECKING:
    pass


_WideningAttr = Callable[..., object]


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


_CLI_PROXY_MODULES: tuple[str, ...] = (
    "cli_core",
    "cli_function_discovery",
    "cli_decompilation",
    "cli_fallback_decompilation",
    "cli_c_ast_rewrites",
    "cli_c_text_postprocess",
    "cli_interrupt_modeling",
    "cache",
    "cli_access_profiles",
    "non_optimized_fallback",
    "disassembly_helpers",
    "project_loading",
    "runtime_support",
    "sidecar_metadata",
    "sidecar_parsers",
    "tail_validation",
    "work_items",
)
_PROXY_MODULE_CACHE: dict[str, ModuleType] = {}
_PROXY_LOADING: set[str] = set()
_PROXY_ATTR_OVERRIDES: dict[str, object] = {}
_CLI_DISABLE_LAZY_IMPORTS: bool = _env_truthy("INERTIA_DISABLE_CLI_LAZY_IMPORTS")


def _import_cli_module(module_name: str) -> ModuleType:
    module = _PROXY_MODULE_CACHE.get(module_name)
    if module is not None:
        return module
    if module_name in _PROXY_LOADING:
        raise RuntimeError(f"circular lazy import detected for inertia_decompiler.{module_name}")
    _PROXY_LOADING.add(module_name)
    try:
        module = import_module(f"{__package__}.{module_name}")
        if not isinstance(module, ModuleType):
            raise TypeError(f"inertia_decompiler.{module_name} is not a ModuleType: {type(module)!r}")
        for override_name, override_value in _PROXY_ATTR_OVERRIDES.items():
            if override_name == "_recovery_code_labels" and module.__name__.endswith("sidecar_metadata"):
                continue
            if hasattr(module, override_name):
                ModuleType.__setattr__(module, override_name, override_value)
        _PROXY_MODULE_CACHE[module_name] = module
        return module
    finally:
        _PROXY_LOADING.discard(module_name)


_CLI_SPECIAL_ATTRS: dict[str, str] = {
    "main": "cli_core",
    "_linear_disassembly": "disassembly_helpers",
    "_probe_lift_break": "disassembly_helpers",
}


def _load_alias_query_attr(name: str) -> object:
    if name == "describe_alias_storage":
        from angr_platforms.X86_16.semantics.alias_query import describe_alias_storage

        return describe_alias_storage
    raise AttributeError(name)


def _load_structured_c() -> object:
    from angr.analyses.decompiler import structured_codegen

    return structured_codegen.c


def _load_cod_extract_attr(name: str) -> object:
    """Load explicit X86_16 COD extraction compatibility exports."""
    from angr_platforms.X86_16.cod_extract import join_cod_entries_with_synthetic_globals

    if name == "join_cod_entries_with_synthetic_globals":
        return join_cod_entries_with_synthetic_globals
    raise AttributeError(name)


def _load_widening_attr(name: str) -> _WideningAttr:
    from angr_platforms.X86_16.widening.register_widening import (
        can_join_adjacent_register_slices,
        join_adjacent_register_slices,
    )
    from angr_platforms.X86_16.widening_model import analyze_adjacent_storage_slices

    if name == "analyze_adjacent_storage_slices":
        return cast(_WideningAttr, analyze_adjacent_storage_slices)
    if name == "join_adjacent_register_slices":
        return cast(_WideningAttr, join_adjacent_register_slices)
    if name == "can_join_adjacent_register_slices":
        return cast(_WideningAttr, can_join_adjacent_register_slices)
    raise AttributeError(name)


def _load_angr_sim_types(name: str) -> object:
    if name in {"SimTypeChar", "SimTypePointer", "SimTypeShort"}:
        from angr.sim_type import SimTypeChar, SimTypePointer, SimTypeShort

        return {"SimTypeChar": SimTypeChar, "SimTypePointer": SimTypePointer, "SimTypeShort": SimTypeShort}[name]
    if name in {"SimMemoryVariable", "SimRegisterVariable", "SimStackVariable"}:
        from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

        return {
            "SimMemoryVariable": SimMemoryVariable,
            "SimRegisterVariable": SimRegisterVariable,
            "SimStackVariable": SimStackVariable,
        }[name]
    raise AttributeError(name)


def _load_access_profile_attr(name: str) -> object:
    from . import cli_access_profiles

    return {
        "_AccessTraitEvidenceProfile": cli_access_profiles.AccessTraitEvidenceProfile,
        "_AccessTraitStrideEvidence": cli_access_profiles.AccessTraitStrideEvidence,
    }[name]


def _resolve_proxy_attr(name: str) -> object:
    if name in _CLI_SPECIAL_ATTRS:
        module = _import_cli_module(_CLI_SPECIAL_ATTRS[name])
        value = ModuleType.__getattribute__(module, name)
        globals()[name] = value
        return value
    if name == "structured_c":
        value = _load_structured_c()
        globals()[name] = value
        return value
    if name == "join_cod_entries_with_synthetic_globals":
        value = _load_cod_extract_attr(name)
        globals()[name] = value
        return value
    if name.startswith("Sim"):
        value = _load_angr_sim_types(name)
        globals()[name] = value
        return value
    if name in {"SimTypeChar", "SimTypePointer", "SimTypeShort", "_AccessTraitEvidenceProfile", "_AccessTraitStrideEvidence", "describe_alias_storage"}:
        value = _load_typed_proxy_attr(name)
        globals()[name] = value
        return value
    if name in {"analyze_adjacent_storage_slices", "join_adjacent_register_slices", "can_join_adjacent_register_slices"}:
        value = _load_widening_attr(name)
        globals()[name] = value
        return value
    for module_name in _CLI_PROXY_MODULES:
        module = _import_cli_module(module_name)
        if hasattr(module, name):
            value = ModuleType.__getattribute__(module, name)
            globals()[name] = value
            return value
    raise AttributeError(name)


def _load_typed_proxy_attr(name: str) -> object:
    """Load one typed surface from its owning lazy module."""
    if name in {"SimTypeChar", "SimTypePointer", "SimTypeShort"}:
        return _load_angr_sim_types(name)
    if name in {"_AccessTraitEvidenceProfile", "_AccessTraitStrideEvidence"}:
        return _load_access_profile_attr(name)
    return _load_alias_query_attr(name)


structured_c: object
_AccessTraitEvidenceProfile: type
_AccessTraitStrideEvidence: type


def _normalized_high_slice_expr(current_high_expr: object) -> object:
    """Unwrap one Mul/Shl high-byte scale wrapper into its inner view."""
    from angr.analyses.decompiler.structured_codegen.c import CBinaryOp

    from .cli_c_ast_rewrites import _c_constant_value, _unwrap_c_casts

    if isinstance(current_high_expr, CBinaryOp) and current_high_expr.op in {"Mul", "Shl"}:
        for maybe_inner, maybe_scale in (
            (current_high_expr.lhs, current_high_expr.rhs),
            (current_high_expr.rhs, current_high_expr.lhs),
        ):
            scale = _c_constant_value(_unwrap_c_casts(maybe_scale))
            if scale not in {8, 0x100}:
                continue
            return _unwrap_c_casts(maybe_inner)
    return current_high_expr


def _joinable_register_pair_proof(analysis: object) -> object | None:
    """Return the widening proof when its register-pair versions agree."""
    # Dynamic codegen boundary: widening proof shape comes from X86_16 analysis helpers.
    proof = getattr(analysis, "proof", None)
    if proof is None:
        return None
    # Dynamic codegen boundary: widening proof fields are analysis-owned evidence.
    if getattr(proof, "register_pair", None) is None:
        return None
    # Dynamic codegen boundary: widening proof fields are analysis-owned evidence.
    if getattr(proof, "left_version", None) is None or getattr(proof, "right_version", None) is None:
        return None
    # Dynamic codegen boundary: widening proof fields are analysis-owned evidence.
    if getattr(proof, "left_version", None) != getattr(proof, "right_version", None):
        return None
    return proof


def _match_adjacent_register_pair_impl(
    low_expr: object,
    high_expr: object,
    codegen: object,
) -> object | None:
    """Join two proven adjacent byte slices into one widened expression."""
    from angr.analyses.decompiler.structured_codegen.c import CVariable
    from angr.sim_variable import SimRegisterVariable
    from angr_platforms.X86_16.widening_model import analyze_adjacent_storage_slices

    from .cli_c_ast_rewrites import _get_or_seed_inertia_alias_state

    current_low_expr = low_expr
    current_high_expr = _normalized_high_slice_expr(high_expr)
    if not isinstance(current_low_expr, CVariable) or not isinstance(current_high_expr, CVariable):
        return None
    # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
    low_var = getattr(current_low_expr, "variable", None)
    # Dynamic codegen boundary: CVariable payloads are optional in angr structured C.
    high_var = getattr(current_high_expr, "variable", None)
    if not isinstance(low_var, SimRegisterVariable) or not isinstance(high_var, SimRegisterVariable):
        return None
    # Dynamic codegen boundary: SimRegisterVariable slice size comes from angr variable metadata.
    if getattr(low_var, "size", None) != 1 or getattr(high_var, "size", None) != 1:
        return None
    alias_state = _get_or_seed_inertia_alias_state(codegen)
    if alias_state is None:
        return None
    analysis = analyze_adjacent_storage_slices(current_low_expr, current_high_expr, alias_state=alias_state)
    if not analysis.ok:
        return None
    proof = _joinable_register_pair_proof(analysis)
    if proof is None:
        return None
    can_join_attr = _load_widening_attr("can_join_adjacent_register_slices")
    if not can_join_attr(current_low_expr, current_high_expr, alias_state=alias_state, proof=proof):
        return None
    join_attr = _load_widening_attr("join_adjacent_register_slices")
    return join_attr(
        current_low_expr, current_high_expr, codegen, alias_state=alias_state, proof=proof
    )


def _match_adjacent_register_pair_var_expr(low_expr: object, high_expr: object, codegen: object) -> object | None:
    # Compatibility surface for legacy tests and callers importing from decompile/cli.
    return _match_adjacent_register_pair_impl(low_expr, high_expr, codegen)


def _compat_module_getattr(name_or_self: object, name: object | None = None) -> object:
    """Resolve one legacy CLI export lazily."""
    target_name = name if name is not None else name_or_self
    if not isinstance(target_name, str):
        raise TypeError(f"attribute name must be str, got {type(target_name).__name__}")
    return _resolve_proxy_attr(target_name)


def _compat_module_setattr(
    name_or_self: object,
    name_or_value: object | None = None,
    value: object | None = None,
) -> None:
    """Mirror one legacy monkeypatch into loaded compatibility modules."""
    if isinstance(name_or_self, ModuleType):
        module = name_or_self
        override_name = name_or_value
        override_value = value
    else:
        module = sys.modules[__name__]
        override_name = name_or_self
        override_value = name_or_value
    if not isinstance(override_name, str):
        # Ignore non-string bootstrap payloads if passed by import internals.
        return None
    ModuleType.__setattr__(module, override_name, override_value)
    if override_name == "main":
        return None
    _PROXY_ATTR_OVERRIDES[override_name] = override_value
    for module_name in _CLI_PROXY_MODULES:
        cached_module = _PROXY_MODULE_CACHE.get(module_name)
        if cached_module is None:
            loaded = sys.modules.get(f"{__package__}.{module_name}")
            if isinstance(loaded, ModuleType):
                cached_module = loaded
        if cached_module is None:
            continue
        if cached_module.__name__.endswith("sidecar_metadata") and override_name == "_recovery_code_labels":
            continue
        if hasattr(cached_module, override_name):
            ModuleType.__setattr__(cached_module, override_name, override_value)


def _compat_module_dir(self: object | None = None) -> list[str]:
    """List known eager and loaded lazy compatibility exports."""
    module = self if isinstance(self, ModuleType) else sys.modules[__name__]
    names = set(ModuleType.__dir__(module))
    names.update(__all__)
    names.update(_PROXY_ATTR_OVERRIDES)
    for module in _PROXY_MODULE_CACHE.values():
        names.update(dir(module))
    return sorted(names)


_CompatModule = cast(
    type[ModuleType],
    type(
        "_CompatModule",
        (ModuleType,),
        {
            "__slots__": (),
            "__getattr__": _compat_module_getattr,
            "__setattr__": _compat_module_setattr,
            "__dir__": _compat_module_dir,
        },
    ),
)


_THIS_MODULE = sys.modules[__name__]
_THIS_MODULE.__class__ = _CompatModule


__all__: tuple[str, ...] = (
    "SimMemoryVariable",
    "SimRegisterVariable",
    "SimStackVariable",
    "SimTypePointer",
    "SimTypeShort",
    "_AccessTraitEvidenceProfile",
    "_AccessTraitStrideEvidence",
    "_addr_exprs_are_byte_pair",
    "_canonicalize_stack_cvar_expr",
    "_canonicalize_stack_cvars",
    "_classify_segmented_addr_expr",
    "_coalesce_cod_word_global_loads",
    "_coalesce_direct_ss_local_word_statements",
    "_coalesce_far_pointer_stack_expressions",
    "_coalesce_linear_recurrence_statements",
    "_coalesce_segmented_word_load_expressions",
    "_coalesce_segmented_word_store_statements",
    "_linear_disassembly",
    "_make_word_dereference_from_addr_expr",
    "_match_adjacent_register_pair_var_expr",
    "_match_byte_load_addr_expr",
    "_match_byte_store_addr_expr",
    "_match_duplicate_word_increment_shift_expr",
    "_match_shift_right_8_expr",
    "_match_shifted_high_byte_addr_expr",
    "_match_ss_local_plus_const",
    "_match_word_rhs_from_byte_pair",
    "_materialize_missing_stack_local_declarations",
    "_probe_lift_break",
    "_resolve_stack_cvar_from_addr_expr",
    "_rewrite_ss_stack_byte_offsets",
    "_same_c_expression",
    "_seed_adjacent_byte_pair_aliases",
    "_simplify_x86_16_conditions",
    "_simplify_x86_16_stack_byte_pointers",
    "_stack_slot_identity_can_join",
    "analyze_adjacent_storage_slices",
    "can_join_adjacent_register_slices",
    "describe_alias_storage",
    "join_adjacent_register_slices",
    "main",
    "structured_c",
)


def _prime_eager_cli_exports() -> None:
    """Load all CLI proxy modules up front for debugger-friendly execution."""
    if not _CLI_DISABLE_LAZY_IMPORTS:
        return
    for module_name in (
        *_CLI_PROXY_MODULES,
        "disassembly_helpers",
        "project_loading",
    ):
        _import_cli_module(module_name)
    for name in list(__all__):
        if name not in globals():
            with contextlib.suppress(AttributeError):
                globals()[name] = _resolve_proxy_attr(name)
    for module in _PROXY_MODULE_CACHE.values():
        try:
            public_names = ModuleType.__getattribute__(module, "__all__")
        except AttributeError:
            public_names = None
        candidates = list(public_names) if public_names else dir(module)
        for name in candidates:
            if not isinstance(name, str) or name.startswith("__"):
                continue
            if name in globals():
                continue
            globals()[name] = ModuleType.__getattribute__(module, name)


if _CLI_DISABLE_LAZY_IMPORTS:
    _prime_eager_cli_exports()


def main(argv: list[str] | None = None) -> int:
    """Proxy the real CLI entrypoint through lazy module loading."""

    entrypoint = cast("Callable[[list[str] | None], int]", _resolve_proxy_attr("main"))
    return entrypoint(argv)


if __name__ == "__main__":
    raise SystemExit(main())
