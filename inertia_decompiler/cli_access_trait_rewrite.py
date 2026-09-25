"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import re
import typing
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .cli_access_object_hints import AccessTraitObjectHint, BaseKey
from .cli_access_rewrite_artifact import AccessRewriteArtifact

type StableHints = dict[BaseKey, AccessTraitObjectHint]
type ReplaceCChildren = Callable[[object, Callable[[object], object]], bool]


class _CFunctionLike(Protocol):
    """Structured C function surface needed by access-trait renaming."""

    addr: int
    statements: object
    variables_in_use: object


class _CodegenLike(Protocol):
    """Codegen surface needed by access-trait renaming."""

    cfunc: _CFunctionLike | None


def _should_attach_access_trait_names(
    codegen: object,
    *,
    has_access_rewrite_artifact: Callable[[object], bool],
) -> bool:
    return has_access_rewrite_artifact(codegen)



def _should_attach_access_trait_names(
    codegen: object,
    *,
    has_access_rewrite_artifact: Callable[[object], bool],
) -> bool:
    return has_access_rewrite_artifact(codegen)


def _is_generic_stack_name_8616(name: object) -> bool:
    """Return whether a rendered name is a generic temp/field placeholder."""
    return isinstance(name, str) and re.fullmatch(r"(?:v\d+|vvar_\d+)", name) is not None


def _load_access_artifact_8616(
    project: object,
    codegen: _CodegenLike,
    should_attach_access_trait_names: Callable[[object], bool],
    load_access_rewrite_artifact: Callable[[object, object], AccessRewriteArtifact | None],
) -> AccessRewriteArtifact | None:
    """Load the access-rewrite artifact, or None when attachment must refuse."""
    cfunc = codegen.cfunc
    if cfunc is None:
        return None
    if not should_attach_access_trait_names(codegen):
        return None
    artifact = load_access_rewrite_artifact(project, cfunc.addr)
    if artifact is None or not artifact.object_hints:
        return None
    return artifact


@dataclass
class _AccessTraitFieldRename8616:
    """Run state for stack-field name attachment."""

    artifact: AccessRewriteArtifact
    stable_access_object_hint_for_key: Callable[[StableHints, BaseKey | None], AccessTraitObjectHint | None]
    access_trait_variable_key: Callable[[object], BaseKey | None]
    stack_object_name: Callable[[int], str]
    access_trait_field_name: Callable[[int, int], str]
    changed: bool = False

    def stack_rewrite_decision(self, variable: object) -> AccessTraitObjectHint | None:
        """Return the rename decision for one stack variable, or None."""
        base_key = self.access_trait_variable_key(variable)
        if base_key is None:
            return None
        if base_key in self.artifact.refusal_reasons or (len(base_key) == 4 and base_key[:3] in self.artifact.refusal_reasons):
            return None
        return self.stable_access_object_hint_for_key(self.artifact.object_hints, base_key)

    def rename_stack_variable(self, cvar: structured_c.CVariable, *, suffix: int = 0) -> object | None:
        """Rename one stack CVariable to its evidence-backed field name."""
        # Dynamic codegen boundary: angr CVariable payloads are optional.
        variable = getattr(cvar, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        decision = self.stack_rewrite_decision(variable)
        if decision is None or not decision.should_rename_stack():
            return None
        name = variable.name
        if not _is_generic_stack_name_8616(name) and not (isinstance(name, str) and name.startswith("field_")):
            return None
        if decision.kind == "stack":
            field_name = self.stack_object_name(variable.offset)
        else:
            field_name = self.access_trait_field_name(suffix, variable.size)
        if variable.name != field_name:
            variable.name = field_name
            self.changed = True
        # Dynamic codegen boundary: structured C variables may expose a rendered name.
        if getattr(cvar, "name", None) != field_name:
            try:
                # Dynamic codegen boundary: angr CVariable.name is runtime-mutable despite a read-only stub.
                typing.cast(typing.Any, cvar).name = field_name
            except Exception:
                pass
            else:
                self.changed = True
        return typing.cast(object, cvar)

    def transform(self, node: object) -> object:
        """Rename one C AST node when it is a rewritable stack CVariable."""
        if isinstance(node, structured_c.CVariable):
            renamed = self.rename_stack_variable(node, suffix=0)
            if renamed is not None:
                return renamed
        return node


def _attach_access_trait_field_names(
    project: object,
    codegen: _CodegenLike,
    *,
    should_attach_access_trait_names: Callable[[object], bool],
    load_access_rewrite_artifact: Callable[[object, object], AccessRewriteArtifact | None],
    stable_access_object_hint_for_key: Callable[[StableHints, BaseKey | None], AccessTraitObjectHint | None],
    access_trait_variable_key: Callable[[object], BaseKey | None],
    stack_object_name: Callable[[int], str],
    access_trait_field_name: Callable[[int, int], str],
    replace_c_children: ReplaceCChildren,
) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False
    artifact = _load_access_artifact_8616(
        project, codegen, should_attach_access_trait_names, load_access_rewrite_artifact,
    )
    if artifact is None:
        return False
    rename = _AccessTraitFieldRename8616(
        artifact=artifact,
        stable_access_object_hint_for_key=stable_access_object_hint_for_key,
        access_trait_variable_key=access_trait_variable_key,
        stack_object_name=stack_object_name,
        access_trait_field_name=access_trait_field_name,
    )
    root = cfunc.statements
    new_root = rename.transform(root)
    if new_root is not root:
        cfunc.statements = new_root
        root = new_root
        rename.changed = True
    if replace_c_children(root, rename.transform):
        rename.changed = True
    return rename.changed


@dataclass
class _PointerMemberRename8616:
    """Run state for pointer/member name attachment."""

    artifact: AccessRewriteArtifact
    stable_access_object_hint_for_key: Callable[[StableHints, BaseKey | None], AccessTraitObjectHint | None]
    access_trait_variable_key: Callable[[object], BaseKey | None]
    access_trait_field_name: Callable[[int, int], str]
    changed: bool = False
    assigned_names: dict[int, str] = field(default_factory=dict)
    name_cursors: dict[BaseKey, int] = field(default_factory=dict)

    def candidate_field_names(self, base_key: BaseKey) -> tuple[str, ...]:
        """Return candidate field names for one non-refused base key."""
        if base_key in self.artifact.refusal_reasons or (
            len(base_key) == 4 and base_key[:3] in self.artifact.refusal_reasons
        ):
            return ()
        hint = self.stable_access_object_hint_for_key(self.artifact.object_hints, base_key)
        if hint is None:
            return ()
        if hint.kind not in {"member", "array", "induction"}:
            return ()
        return typing.cast(
            tuple[str, ...],
            hint.candidate_field_names(access_trait_field_name=self.access_trait_field_name),
        )

    def assign_member_name(self, base_key: BaseKey) -> str | None:
        """Return the next unused candidate name for one base key."""
        names = self.candidate_field_names(base_key)
        if not names:
            return None
        index = self.name_cursors.get(base_key, 0)
        if index < len(names):
            field_name = names[index]
            self.name_cursors[base_key] = index + 1
            return field_name
        return names[-1]

    def assign_tracked_names(self, variables_in_use: object) -> None:
        """Pre-assign member names across variables_in_use."""
        if not isinstance(variables_in_use, dict):
            return
        for variable, cvar in list(variables_in_use.items()):
            if not isinstance(variable, (SimRegisterVariable, SimStackVariable, SimMemoryVariable)):
                continue
            # Dynamic codegen boundary: CVariable rendered names are optional.
            if not _is_generic_stack_name_8616(variable.name) and not _is_generic_stack_name_8616(getattr(cvar, "name", None)):
                continue
            base_key = self.access_trait_variable_key(variable)
            if base_key is None:
                continue
            field_name = self.assign_member_name(base_key)
            if field_name is None:
                continue
            # Dynamic codegen boundary: CVariable may carry a unified variable payload.
            target = getattr(cvar, "unified_variable", None) or getattr(cvar, "variable", None)
            # Dynamic codegen boundary: target variable names are optional codegen metadata.
            if target is not None and getattr(target, "name", None) != field_name:
                target.name = field_name
                self.changed = True
            if variable.name != field_name:
                variable.name = field_name
                self.changed = True
            # Dynamic codegen boundary: CVariable rendered names are optional.
            if getattr(cvar, "name", None) != field_name:
                cvar.name = field_name
                self.changed = True
            self.assigned_names[id(variable)] = field_name

    def rename_member_variable(self, cvar: object) -> object | None:
        """Apply an artifact-backed member name, refusing unrelated variables."""
        if not isinstance(cvar, structured_c.CVariable):
            return None
        # Dynamic codegen boundary: angr CVariable payloads are optional.
        variable = getattr(cvar, "variable", None)
        if not isinstance(variable, (SimRegisterVariable, SimStackVariable, SimMemoryVariable)):
            return None
        # Dynamic codegen boundary: CVariable rendered names are optional.
        if not _is_generic_stack_name_8616(variable.name) and not _is_generic_stack_name_8616(getattr(cvar, "name", None)):
            return None
        base_key = self.access_trait_variable_key(variable)
        if base_key is None:
            return None
        field_name = self.assigned_names.get(id(variable))
        if field_name is None:
            field_name = self.assign_member_name(base_key)
        if field_name is None:
            return None
        self._apply_member_name(variable, cvar, field_name)
        renamed_cvar = typing.cast(object, cvar)
        return renamed_cvar

    def _apply_member_name(self, variable: object, cvar: structured_c.CVariable, field_name: str) -> None:
        """Write the member name onto the variable and rendered CVariable."""
        if variable.name != field_name:
            variable.name = field_name
            self.changed = True
        # Dynamic codegen boundary: CVariable rendered names are optional.
        if getattr(cvar, "name", None) != field_name:
            try:
                # Dynamic codegen boundary: angr CVariable.name is runtime-mutable despite a read-only stub.
                typing.cast(typing.Any, cvar).name = field_name
            except Exception:
                pass
            else:
                self.changed = True

    def transform(self, node: object) -> object:
        """Rename one C AST node when it is a rewritable member CVariable."""
        if isinstance(node, structured_c.CVariable):
            renamed = self.rename_member_variable(node)
            if renamed is not None:
                return renamed
        return node


def _attach_pointer_member_names(
    project: object,
    codegen: _CodegenLike,
    *,
    should_attach_access_trait_names: Callable[[object], bool],
    load_access_rewrite_artifact: Callable[[object, object], AccessRewriteArtifact | None],
    stable_access_object_hint_for_key: Callable[[StableHints, BaseKey | None], AccessTraitObjectHint | None],
    access_trait_variable_key: Callable[[object], BaseKey | None],
    access_trait_field_name: Callable[[int, int], str],
    replace_c_children: ReplaceCChildren,
) -> bool:
    cfunc = codegen.cfunc
    if cfunc is None:
        return False
    artifact = _load_access_artifact_8616(
        project, codegen, should_attach_access_trait_names, load_access_rewrite_artifact,
    )
    if artifact is None:
        return False

    rename = _PointerMemberRename8616(
        artifact=artifact,
        stable_access_object_hint_for_key=stable_access_object_hint_for_key,
        access_trait_variable_key=access_trait_variable_key,
        access_trait_field_name=access_trait_field_name,
    )
    rename.assign_tracked_names(cfunc.variables_in_use)

    root = cfunc.statements
    new_root = rename.transform(root)
    if new_root is not root:
        cfunc.statements = new_root
        root = new_root
        rename.changed = True
    if replace_c_children(root, rename.transform):
        rename.changed = True
    return rename.changed
