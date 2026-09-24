"""Layer: Optional evidence/reporting.

Responsibility: carry source/COD annotation metadata as optional labels and comments.
Forbidden: materializing prototypes, arguments, stack aliases, or types as recovered semantics.

Dynamic boundary: third-party angr project/function/COD/capstone metadata is
inspected dynamically and may be absent depending on loader and analysis mode.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Mapping, MutableMapping
from enum import StrEnum
from typing import Protocol, cast

from angr.sim_type import SimTypeFunction
from angr.utils.library import convert_cproto_to_py

from .analysis_helpers import seed_calling_conventions
from .arch_86_16 import Arch86_16
from .simos_86_16 import SimCC8616MSCsmall

ANNOTATION_KEY: str = "x86_16_annotations"

_PROTO_EMIT_TYPEDEFS_8616 = (
    "typedef unsigned long clock_t;",
    "typedef unsigned short clock_t;",
    "typedef long time_t;",
    "typedef unsigned long time_t;",
)


class _AnnotatedFunction(Protocol):
    """angr function record subset used by optional annotations."""

    name: str
    prototype: SimTypeFunction | None
    is_prototype_guessed: bool
    calling_convention: object
    info: MutableMapping[str, object]


class _FunctionInfoCarrier(Protocol):
    """angr function subset carrying mutable annotation info."""

    info: MutableMapping[str, object]


class _FunctionManager(Protocol):
    """angr function manager subset used by optional annotations."""

    def function(self, *, addr: int, **_kwargs: object) -> object | None:
        """Return or create a function record."""
        ...

    def __getitem__(self, addr: int) -> object:
        """Return a function record by address."""
        ...


class _CfgFastResult(Protocol):
    """angr CFGFast result subset used by annotation-assisted decompilation."""

    functions: _FunctionManager


class _KnowledgeBase(Protocol):
    """angr knowledge-base subset used by optional annotations."""

    labels: MutableMapping[int, str]
    functions: _FunctionManager


class _AnnotationProject(Protocol):
    """angr project subset used by optional metadata annotations."""

    kb: _KnowledgeBase
    arch: object


class _AnalysisFactory(Protocol):
    """angr analysis factory subset used by annotation-assisted decompilation."""

    def CFGFast(self, **_kwargs: object) -> _CfgFastResult:
        """Build a CFGFast analysis."""
        ...

    def Decompiler(self, func: object, *, cfg: object) -> object:
        """Build a decompiler analysis."""
        ...


class _DecompileProject(_AnnotationProject, Protocol):
    """angr project subset used by the annotation decompile convenience helper."""

    analyses: _AnalysisFactory


def _source_prototype_calling_convention_8616(project: object) -> SimCC8616MSCsmall | None:
    """Return the source-prototype calling convention for a third-party angr project dynamic boundary."""
    arch = getattr(project, "arch", None)
    if not isinstance(arch, Arch86_16):
        return None
    return SimCC8616MSCsmall(arch)


_C_TYPE_KEYWORDS_8616 = {
    "char",
    "const",
    "double",
    "enum",
    "extern",
    "float",
    "int",
    "long",
    "register",
    "short",
    "signed",
    "static",
    "struct",
    "union",
    "unsigned",
    "void",
    "volatile",
}
type AnnotationSpec8616 = str | dict[str, object]


class StackAnnotationPurpose8616(StrEnum):
    """Distinguish optional labels from explicit stack-layout contracts."""

    NAME_ONLY = "name_only"
    EXPLICIT_LAYOUT = "explicit_layout"


def stack_layout_annotation_specs_8616(annotations: object) -> dict[int, AnnotationSpec8616]:
    """Return layout contracts without promoting optional names to semantic facts.

    Legacy explicit annotations omit purpose. COD producers must mark their
    entries NAME_ONLY; those entries remain available to naming consumers but
    cannot create, move, widen, or remove a parameter. Unknown purposes refuse.
    """
    if not isinstance(annotations, Mapping):
        return {}
    specs = annotations.get("stack_vars")
    if not isinstance(specs, Mapping):
        return {}
    selected: dict[int, AnnotationSpec8616] = {}
    for offset, spec in specs.items():
        if not isinstance(offset, int) or not isinstance(spec, (str, dict)):
            continue
        if isinstance(spec, dict) and spec.get("purpose") not in (
            None, StackAnnotationPurpose8616.EXPLICIT_LAYOUT,
        ):
            continue
        selected[offset] = spec
    return selected

_SOURCE_DECL_RE_8616 = re.compile(
    r"^(?P<prefix>(?:(?:extern|static|inline|const|volatile|unsigned|signed|struct|union|enum|long|short|int|char|_Bool|[A-Za-z_]\w*)|\s|\*)+?)"
    r"\s*(?P<name>[A-Za-z_][\w$?@]*)\s*\([^()]*\)\s*(?:\{|;)?\s*$"
)


def _opaque_typedef_headers_for_c_decl_8616(c_decl: str) -> tuple[str, ...]:
    match = re.match(
        r"^\s*(?P<ret>.*?)\b(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*;?\s*$",
        c_decl,
    )
    if match is None:
        return ()
    function_name = match.group("name")
    candidate_type_names: set[str] = set()
    chunks = [match.group("ret")]
    chunks.extend(part.strip() for part in match.group("args").split(",") if part.strip() and part.strip() != "void")
    for chunk_index, chunk in enumerate(chunks):
        cleaned = re.sub(r"\[[^\]]*\]", " ", chunk.replace("*", " "))
        tokens = re.findall(r"[A-Za-z_]\w*", cleaned)
        if not tokens:
            continue
        if chunk_index > 0 and len(tokens) > 1:
            tokens = tokens[:-1]
        for index, token in enumerate(tokens):
            if token == function_name or token in _C_TYPE_KEYWORDS_8616:
                continue
            if index > 0 and tokens[index - 1] in {"struct", "union", "enum"}:
                continue
            candidate_type_names.add(token)
    return tuple(f"typedef unsigned short {name};" for name in sorted(candidate_type_names))


def _converted_c_prototype_or_none_8616(source: str) -> tuple[str, SimTypeFunction, str] | None:
    converted = convert_cproto_to_py(source)
    if len(converted) >= 2 and converted[1] is not None:
        return cast(tuple[str, SimTypeFunction, str], converted)
    return None


def _c_decl_requires_opaque_typedefs_8616(c_decl: str) -> bool:
    normalized_decl = _normalize_c_decl_text(c_decl)
    try:
        if _converted_c_prototype_or_none_8616(normalized_decl) is not None:
            return False
    except Exception:
        pass
    for typedef_header in _PROTO_EMIT_TYPEDEFS_8616:
        try:
            if _converted_c_prototype_or_none_8616(f"{typedef_header}\n{normalized_decl}") is not None:
                return False
        except Exception:
            pass
    return bool(_opaque_typedef_headers_for_c_decl_8616(normalized_decl))


def _parse_c_prototype_8616(c_decl: str) -> tuple[str, SimTypeFunction, str]:
    normalized_decl = _normalize_c_decl_text(c_decl)
    try:
        converted = _converted_c_prototype_or_none_8616(normalized_decl)
        if converted is not None:
            return converted
    except Exception:
        pass

    for typedef_header in _PROTO_EMIT_TYPEDEFS_8616:
        try:
            converted = _converted_c_prototype_or_none_8616(f"{typedef_header}\n{normalized_decl}")
            if converted is not None:
                return converted
        except Exception:
            pass

    opaque_headers = _opaque_typedef_headers_for_c_decl_8616(normalized_decl)
    if opaque_headers:
        try:
            converted = _converted_c_prototype_or_none_8616("\n".join((*opaque_headers, normalized_decl)))
            if converted is not None:
                return converted
        except Exception:
            pass

    raise


def _annotation_dict(function: object) -> MutableMapping[str, object]:
    """Return the optional annotation dict on a third-party angr function dynamic boundary."""
    info = getattr(function, "info", None)
    carrier = cast(_FunctionInfoCarrier, function)
    if not isinstance(info, MutableMapping):
        carrier.info = {}
        info = carrier.info
    return cast(
        MutableMapping[str, object],
        info.setdefault(
            ANNOTATION_KEY,
            {
                "stack_vars": {},
                "global_vars": {},
                "source_lines": (),
                "source_return_lines": (),
            },
        ),
    )


def _normalize_bp_disp(offset: int) -> int:
    return offset - 2


def _normalize_arg_names(arg_names: list[str] | tuple[str, ...], count: int) -> list[str]:
    normalized: list[str] = []
    used: set[str] = set()
    source = list(arg_names)
    for index in range(count):
        base_name = source[index] if index < len(source) else None
        if not isinstance(base_name, str) or not base_name:
            base_name = f"a{index}"
        candidate = base_name
        suffix = 2
        while candidate in used:
            candidate = f"{base_name}_{suffix}"
            suffix += 1
        normalized.append(candidate)
        used.add(candidate)
    return normalized


def _normalize_c_decl_text(c_decl: str) -> str:
    normalized = c_decl
    replacements = (
        (r"\buint8\b", "unsigned char"),
        (r"\buint16\b", "unsigned short"),
        (r"\buint32\b", "unsigned long"),
        (r"\bint8\b", "signed char"),
        (r"\bint16\b", "short"),
        (r"\bint32\b", "long"),
        (r"\bFAR\b", ""),
        (r"\bfar\b", ""),
    )
    for pattern, replacement in replacements:
        normalized = re.sub(pattern, replacement, normalized)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    normalized = re.sub(r"\s+\)", ")", normalized)
    normalized = re.sub(r"\(\s+", "(", normalized)
    normalized = re.sub(r"\s+;", ";", normalized)
    return normalized


def _source_decl_from_cod_source_lines(
    _source_lines: tuple[str, ...], function_name: str | None = None
) -> str | None:
    return None


@functools.lru_cache(maxsize=4096)
def _source_decl_from_cod_source_lines_cached_8616(
    _source_lines: tuple[str, ...],
    function_name: str | None = None,
) -> str | None:
    return None


def _source_args_from_cod_source_lines(_source_lines: tuple[str, ...], _func_name: str | None) -> str | None:
    return None


def _source_function_pointer_local_types_8616(_project: object, _source_lines: tuple[str, ...]) -> dict[str, object]:
    return {}


def annotate_function(
    project: object,
    func_addr: int,
    *,
    name: str | None = None,
    c_decl: str | None = None,
    prototype: SimTypeFunction | None = None,
    calling_convention: object | None = None,
    arg_names: list[str] | tuple[str, ...] | None = None,
    stack_vars: dict[int, AnnotationSpec8616] | None = None,
    bp_stack_vars: dict[int, AnnotationSpec8616] | None = None,
    global_vars: dict[int, AnnotationSpec8616] | None = None,
) -> object:
    """Attach optional annotation labels, prototypes, and names to a function."""

    def _impl() -> object:
        annotation_project = cast(_AnnotationProject, project)
        arch = cast(Arch86_16, annotation_project.arch)
        func = cast(
            _AnnotatedFunction | None,
            annotation_project.kb.functions.function(addr=func_addr, create=True),
        )
        if func is None:
            raise KeyError(func_addr)
        annotations = _annotation_dict(func)

        parsed_name = None
        parsed_proto = None
        if c_decl is not None:
            parsed_name, parsed_proto, _ = _parse_c_prototype_8616(c_decl)
            if parsed_proto is None:
                raise ValueError(f"Failed to parse C declaration: {c_decl}")
            parsed_proto = cast(SimTypeFunction, parsed_proto.with_arch(arch))

        final_name = name if name is not None else parsed_name
        if final_name is not None:
            func.name = final_name

        final_proto = cast(SimTypeFunction, prototype.with_arch(arch)) if prototype is not None else parsed_proto
        if final_proto is not None:
            func.prototype = final_proto
            func.is_prototype_guessed = False
            annotations["prototype"] = final_proto

        if calling_convention is not None:
            func.calling_convention = calling_convention

        if arg_names is not None:
            if func.prototype is None:
                raise ValueError("Cannot assign argument names without a prototype.")
            normalized_names = _normalize_arg_names(arg_names, len(func.prototype.args))
            renamed_proto = SimTypeFunction(
                func.prototype.args,
                func.prototype.returnty,
                arg_names=tuple(normalized_names),
                variadic=func.prototype.variadic,
            )
            func.prototype = cast(SimTypeFunction, renamed_proto.with_arch(arch))
            func.is_prototype_guessed = False

        if stack_vars:
            stack_annotations = cast(MutableMapping[int, MutableMapping[str, object]], annotations["stack_vars"])
            for offset, spec in stack_vars.items():
                entry = stack_annotations.setdefault(offset, {})
                if isinstance(spec, str):
                    entry["name"] = spec
                else:
                    entry.update(spec)

        if bp_stack_vars:
            translated = {}
            for bp_disp, spec in bp_stack_vars.items():
                translated[_normalize_bp_disp(bp_disp)] = spec
            annotate_function(project, func_addr, stack_vars=translated)

        if global_vars:
            global_annotations = cast(MutableMapping[int, dict[str, object]], annotations["global_vars"])
            for addr, spec in global_vars.items():
                global_entry: dict[str, object]
                if isinstance(spec, str):
                    global_entry = {"name": spec}
                    label = spec
                elif isinstance(spec, dict):
                    global_entry = dict(spec)
                    candidate_label = global_entry.get("name")
                    if not isinstance(candidate_label, str):
                        raise ValueError(f"Global annotation for {addr:#x} must include a string name.")
                    label = candidate_label
                else:
                    raise TypeError(f"Unsupported global annotation spec for {addr:#x}: {type(spec).__name__}")
                global_annotations[addr] = global_entry
                annotation_project.kb.labels[addr] = label

        return func

    return _impl()


def annotate_stack_variable(
    project: object, func_addr: int, offset: int, name: str, type_: object | None = None
) -> object:
    """Attach an optional stack-variable label to a function annotation record."""
    spec: dict[str, object] = {"name": name}
    if type_ is not None:
        spec["type"] = type_
    return annotate_function(project, func_addr, stack_vars={offset: spec})


def annotate_bp_stack_variable(
    project: object, func_addr: int, bp_disp: int, name: str, type_: object | None = None
) -> object:
    """Attach an optional BP-relative stack-variable label to a function record."""
    spec: dict[str, object] = {"name": name}
    if type_ is not None:
        spec["type"] = type_
    return annotate_function(project, func_addr, bp_stack_vars={bp_disp: spec})


def annotate_global_variable(project: object, addr: int, name: str) -> str:
    """Attach an optional global label without treating it as recovered semantics."""
    cast(_AnnotationProject, project).kb.labels[addr] = name
    return name


def _apply_known_helper_signatures(_project: object, _cod_metadata: object | None = None) -> bool:
    return False


def _split_source_arg_names_8616(source_arg_text: str | None) -> list[str]:
    def _impl() -> list[str]:
        if not source_arg_text:
            return []
        source_arg_names: list[str] = []
        current: list[str] = []
        depth_paren = depth_bracket = depth_brace = 0
        for char in source_arg_text:
            if char == "," and depth_paren == depth_bracket == depth_brace == 0:
                part = "".join(current).strip()
                if part:
                    match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", part)
                    if match is not None:
                        source_arg_names.append(match.group(1))
                current = []
                continue
            current.append(char)
            if char == "(":
                depth_paren += 1
            elif char == ")" and depth_paren > 0:
                depth_paren -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]" and depth_bracket > 0:
                depth_bracket -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}" and depth_brace > 0:
                depth_brace -= 1
        if current:
            part = "".join(current).strip()
            if part:
                match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", part)
                if match is not None:
                    source_arg_names.append(match.group(1))
        return source_arg_names

    return _impl()


def _apply_source_prototype_annotations_8616(
    project: object, func_addr: int, func: object, _source_lines: tuple[str, ...]
) -> bool:
    return False


def apply_x86_16_metadata_annotations(
    project: object,
    *,
    func_addr: int | None = None,
    cod_metadata: object | None = None,
    lst_metadata: object | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
) -> bool:
    """Apply optional source/listing metadata as labels only, never as semantic proof."""

    def _impl() -> bool:
        """Apply metadata labels from third-party COD/LST dynamic-boundary objects."""
        changed = False
        annotation_project = cast(_AnnotationProject, project)

        if lst_metadata is not None:
            for offset, name in getattr(lst_metadata, "data_labels", {}).items():
                if annotation_project.kb.labels.get(offset) != name:
                    annotation_project.kb.labels[offset] = name
                    changed = True

            if func_addr is not None:
                code_name = getattr(lst_metadata, "code_labels", {}).get(func_addr)
                if isinstance(code_name, str) and code_name:
                    func = cast(
                        _AnnotatedFunction | None,
                        annotation_project.kb.functions.function(addr=func_addr, create=True),
                    )
                    if func is not None and getattr(func, "name", None) != code_name:
                        func.name = code_name
                        changed = True

        if cod_metadata is not None:
            changed |= _apply_known_helper_signatures(project, cod_metadata)

        if func_addr is not None and synthetic_globals:
            seen_addrs: set[int] = set()
            for addr, (raw_name, _width) in synthetic_globals.items():
                if addr in seen_addrs:
                    continue
                seen_addrs.add(addr)
                if isinstance(raw_name, str) and raw_name and annotation_project.kb.labels.get(addr) != raw_name:
                    annotation_project.kb.labels[addr] = raw_name
                    changed = True

        return changed

    return _impl()


def decompile_function(project: object, func_addr: int, **annotations: object) -> object:
    """Run decompilation after applying optional annotation metadata."""
    decompile_project = cast(_DecompileProject, project)
    cfg = decompile_project.analyses.CFGFast(normalize=True)
    cod_metadata = annotations.get("cod_metadata")
    lst_metadata = annotations.get("lst_metadata")
    synthetic_globals = cast(dict[int, tuple[str, int]] | None, annotations.get("synthetic_globals"))
    if cod_metadata is not None or lst_metadata is not None or synthetic_globals is not None:
        apply_x86_16_metadata_annotations(
            project,
            func_addr=func_addr,
            cod_metadata=cod_metadata,
            lst_metadata=lst_metadata,
            synthetic_globals=synthetic_globals,
        )
    seed_calling_conventions(cfg)
    func = cfg.functions[func_addr]
    direct_keys = {
        "name",
        "c_decl",
        "prototype",
        "calling_convention",
        "arg_names",
        "stack_vars",
        "bp_stack_vars",
        "global_vars",
    }
    if any(key in annotations for key in direct_keys):
        annotate_function(
            project,
            func_addr,
            name=cast(str | None, annotations.get("name")),
            c_decl=cast(str | None, annotations.get("c_decl")),
            prototype=cast(SimTypeFunction | None, annotations.get("prototype")),
            calling_convention=annotations.get("calling_convention"),
            arg_names=cast(list[str] | tuple[str, ...] | None, annotations.get("arg_names")),
            stack_vars=cast(dict[int, AnnotationSpec8616] | None, annotations.get("stack_vars")),
            bp_stack_vars=cast(dict[int, AnnotationSpec8616] | None, annotations.get("bp_stack_vars")),
            global_vars=cast(dict[int, AnnotationSpec8616] | None, annotations.get("global_vars")),
        )
        func = decompile_project.kb.functions[func_addr]
    apply_x86_16_metadata_annotations(
        project,
        func_addr=func_addr,
        cod_metadata=cod_metadata,
        lst_metadata=lst_metadata,
        synthetic_globals=synthetic_globals,
    )
    return decompile_project.analyses.Decompiler(func, cfg=cfg)
