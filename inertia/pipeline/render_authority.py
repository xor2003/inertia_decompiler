"""Typed contract for selecting the authoritative generated-C render source.

Layer: Pipeline governance.
Responsibility: Owns runtime ordering, invariant checks, hard failures, and final emission gates.
Do not recover semantic facts or perform IR, alias, widening,
lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting
work here. This module only identifies which already-installed codegen surface
owns final rendering.
Dynamic boundary: this governance module reads and installs typed extension
fields on third-party angr codegen objects.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Protocol, cast, runtime_checkable

from .errors import PipelineHardError

__all__ = [
    "CodegenRenderAuthority8616",
    "CodegenRenderIntegrityGuard8616",
    "codegen_render_authority_8616",
    "install_codegen_render_integrity_guard_8616",
    "mark_cfunction_ast_render_authority_8616",
    "require_codegen_render_integrity_8616",
]


class CodegenRenderAuthority8616(Enum):
    """Authoritative source for rendering a third-party angr codegen object."""

    CFUNCTION_AST = "cfunction_ast"
    PROVEN_FULL_FUNCTION_OVERRIDE = "proven_full_function_override"


@runtime_checkable
class CodegenRenderIntegrityGuard8616(Protocol):
    """Owned live-state guard invoked immediately before codegen rendering."""

    def verify(self, codegen: object, *, context: str) -> None:
        """Hard-fail when the owning layer's live render contract is invalid."""


def codegen_render_authority_8616(codegen: object) -> CodegenRenderAuthority8616 | None:
    """Read the typed authority installed on a third-party angr codegen object."""
    authority = getattr(codegen, "_inertia_codegen_render_authority_8616", None)
    return authority if isinstance(authority, CodegenRenderAuthority8616) else None


def mark_cfunction_ast_render_authority_8616(codegen: object) -> CodegenRenderAuthority8616:
    """Mark a successfully rendered live C AST without replacing a proven override."""
    authority = codegen_render_authority_8616(codegen)
    if authority is CodegenRenderAuthority8616.PROVEN_FULL_FUNCTION_OVERRIDE:
        return authority
    # Dynamic boundary: angr owns the codegen class; Inertia owns this extension field.
    cast(Any, codegen)._inertia_codegen_render_authority_8616 = CodegenRenderAuthority8616.CFUNCTION_AST
    return CodegenRenderAuthority8616.CFUNCTION_AST


def install_codegen_render_integrity_guard_8616(
    codegen: object,
    guard: CodegenRenderIntegrityGuard8616,
) -> None:
    """Install an owning-layer guard at the third-party angr codegen boundary."""
    cast(Any, codegen)._inertia_codegen_render_integrity_guard_8616 = guard


def require_codegen_render_integrity_8616(codegen: object, *, context: str) -> None:
    """Invoke the installed owning-layer guard before rendering generated C."""
    guard = getattr(codegen, "_inertia_codegen_render_integrity_guard_8616", None)
    if guard is None:
        return
    if not isinstance(guard, CodegenRenderIntegrityGuard8616):
        raise PipelineHardError(
            "invalid codegen render integrity guard",
            layer="pipeline",
            details={"context": context, "guard_type": type(guard).__name__},
        )
    guard.verify(codegen, context=context)
