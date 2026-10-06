"""Read bounded QA target inventories without executing Make recipes.

Layer: Tooling/gates.
Responsibility: preserve assignment order, appends, and duplicates in static
Makefile word lists consumed by architecture checks. This is not a general
Make evaluator: it expands only literal ``$(NAME)``/``${NAME}`` word-list
references through ``=``/``:=``/``::=``/``+=``/``?=`` assignments, literal
repo-local ``include`` files, ``override`` freezes, and ``undefine``
removals under GNU Make override precedence (a plain ``undefine`` is
ignored for ``override``-origin variables; ``override undefine``
removes any file-level variable), with GNU Make recursive-versus-simple
timing. Conditional guards,
``define`` bodies, ``!=`` shell captures, substitution references,
functions, environment, and command-line variables are never evaluated.
A guarded ``override`` inside an unevaluated conditional marks the
variable unresolved instead of being applied, so a later non-override
write cannot claim the value and only an unconditional ``override``
redefinition re-proves it.
Unresolvable references stay in the output as explicit ``$(NAME)`` tokens
and unresolvable directives produce typed diagnostics so callers fail
closed instead of silently dropping entries. Expansion work and include
fan-out are bounded by explicit budgets; exhaustion is a diagnostic plus a
fail-closed gap, never a silent truncation.
Unsupported global assignment names or prefixes open a gap because they may
install override origin. Target-specific assignments and recipe execution are
outside this global inventory contract and are not evaluated as global writes.
"""

from __future__ import annotations

import dataclasses
import enum
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

_MAX_INCLUDE_FILES = 128
_MAX_INCLUDE_DEPTH = 64
_MAX_EXPANSION_OPERATIONS = 100_000
_MAX_EXPANSION_CHARS = 8_000_000


class MakefileInventoryDiagKind(enum.Enum):
    """Typed reasons the static inventory cannot fully prove a Makefile."""

    INCLUDE_NO_BASE_DIR = "include-no-base-dir"
    INCLUDE_NONLITERAL_NAME = "include-nonliteral-name"
    INCLUDE_MISSING = "include-missing"
    INCLUDE_SKIPPED_OPTIONAL = "include-skipped-optional"
    INCLUDE_OUTSIDE_ROOT = "include-outside-root"
    INCLUDE_CYCLE = "include-cycle"
    INCLUDE_READ_ERROR = "include-read-error"
    INCLUDE_DEPTH_LIMIT = "include-depth-limit"
    INCLUDE_FILE_LIMIT = "include-file-limit"
    CONDITIONAL_INCLUDE = "conditional-include"
    UNDEFINE_NONLITERAL = "undefine-nonliteral"
    MALFORMED_DIRECTIVE = "malformed-directive"
    UNTERMINATED_BLOCK = "unterminated-block"
    UNSUPPORTED_STATEMENT = "unsupported-statement"
    UNSUPPORTED_GLOBAL_ASSIGNMENT = "unsupported-global-assignment"
    EXPANSION_BUDGET = "expansion-budget"


@dataclass(frozen=True)
class MakefileInventoryDiagnostic:
    """One fail-closed evidence record from a static inventory scan.

    ``location`` is ``"<origin>:<line>"`` where ``origin`` is the Makefile
    label or the root-relative include path that produced the diagnostic.
    """

    kind: MakefileInventoryDiagKind
    location: str
    detail: str


class _VariableFlavor(enum.Enum):
    """How a variable's stored text is interpreted at expansion time."""

    SIMPLE = "simple"
    RECURSIVE = "recursive"
    OPAQUE = "opaque"


class _AssignmentOperator(enum.Enum):
    """Assignment operators the static reader understands."""

    RECURSIVE = "="
    SIMPLE = ":="
    APPEND = "+="
    CONDITIONAL = "?="
    SHELL = "!="


@dataclass(frozen=True)
class _VariableState:
    """Recorded state for one Makefile variable while scanning top to bottom.

    ``conditional`` marks values that depend on an ``if`` guard the reader
    cannot evaluate. ``partial`` marks values that may have been altered
    inside an include or directive the reader could not apply. ``override``
    records GNU Make ``override`` marking, which freezes the variable
    against later non-override file assignments. ``override_possible``
    records that an unevaluated conditional block may have installed an
    ``override`` for this variable: GNU Make would honor such an
    ``override`` over any later non-override write, so the variable stays
    unresolved until an unconditional ``override`` redefinition re-proves
    it. Conditional and partial states keep references explicit instead of
    guessed.
    """

    flavor: _VariableFlavor
    text: str
    conditional: bool = False
    override: bool = False
    partial: bool = False
    override_possible: bool = False


@dataclass
class _ScanContext:
    """Mutable state shared across a Makefile and its resolved includes.

    ``gap`` records that some construct could not be proven; it also marks
    every already-defined variable ``partial`` because the unapplied text
    could have reassigned, appended to, or ``undefine``d it. ``unapplied_text``
    records the stronger event that text with possible variable effects was
    skipped entirely: skipped text could have carried an ``override``
    assignment, so later non-override writes cannot close the question and
    only an ``override`` redefinition re-proves a variable. ``ops_left``
    and ``chars_left`` implement the expansion budget.
    """

    env: dict[str, _VariableState]
    diagnostics: list[MakefileInventoryDiagnostic]
    gap: bool
    unapplied_text: bool
    base_dir: Path | None
    include_root: Path | None
    files_read: int
    ops_left: int
    chars_left: int
    budget_reported: bool


_OPERATOR = {
    "=": _AssignmentOperator.RECURSIVE,
    ":=": _AssignmentOperator.SIMPLE,
    "::=": _AssignmentOperator.SIMPLE,
    "+=": _AssignmentOperator.APPEND,
    "?=": _AssignmentOperator.CONDITIONAL,
    "!=": _AssignmentOperator.SHELL,
}

_ASSIGNMENT = re.compile(
    r"^ *((?:(?:export|override) +)*)([A-Za-z0-9_.-]+) *(::=|:=|\+=|\?=|!=|=) *(.*)$"
)
_CONDITIONAL_OPEN = re.compile(r"^ *if(?:eq|neq|def|ndef)\b")
_CONDITIONAL_ELSEIF = re.compile(r"^ *else +if(?:eq|neq|def|ndef)\b")
_CONDITIONAL_ELSE = re.compile(r"^ *else\b")
_CONDITIONAL_CLOSE = re.compile(r"^ *endif\b")
_DEFINE_OPEN = re.compile(r"^ *((?:(?:export|override) +)*)define +([A-Za-z0-9_.-]+)")
_DEFINE_CLOSE = re.compile(r"^ *endef\b")
_INCLUDE = re.compile(r"^ *(-?s?include)(?:[ \t]+(.*))?$")
_UNDEFINE = re.compile(r"^ *(override +)?undefine(?:[ \t]+(.*))? *$")
_OVERRIDE_BARE = re.compile(r"^ *override +[A-Za-z0-9_.-]+ *$")
_DOLLAR_STATEMENT = re.compile(r"^ *\$\(")
_SIMPLE_NAME = re.compile(r"[A-Za-z0-9_.-]+")
_NONLITERAL_PATH_CHARS = "$*?[]~"


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """Fold continued physical lines, yielding ``(start_lineno, text)`` pairs."""
    pending = ""
    start = 0
    for lineno, line in enumerate(text.splitlines(), start=1):
        if pending:
            pending += line.lstrip()
        else:
            pending = line
            start = lineno
        if pending.endswith("\\"):
            pending = pending[:-1] + " "
            continue
        yield start, pending
        pending = ""
    if pending:
        yield start, pending


def _strip_comment(line: str) -> str:
    """Remove an unescaped ``#`` comment suffix from a logical line."""
    escaped = False
    for index, char in enumerate(line):
        if char == "#" and not escaped:
            return line[:index]
        escaped = char == "\\" and not escaped
    return line


def _scan_reference(text: str, start: int) -> tuple[str, str, int] | None:
    """Return ``(token, inner, end)`` for the ``$(``/``${`` opener at ``start``.

    Nested ``$(``/``${`` openers keep the reference open so unsupported
    constructs (function calls, substitution references, computed names)
    round-trip as one verbatim token. ``None`` means the reference is
    unterminated; callers keep the remainder of the text untouched.
    """
    stack = [")" if text[start + 1] == "(" else "}"]
    index = start + 2
    while index < len(text):
        char = text[index]
        if char == "$" and index + 1 < len(text) and text[index + 1] in "({":
            stack.append(")" if text[index + 1] == "(" else "}")
            index += 2
            continue
        if char == stack[-1]:
            stack.pop()
            index += 1
            if not stack:
                token = text[start:index]
                return token, token[2:-1], index
            continue
        index += 1
    return None


def _spend(ctx: _ScanContext, chars: int) -> bool:
    """Charge one expansion and ``chars`` emitted bytes to the budget.

    Exhaustion is recorded once as a diagnostic and opens a fail-closed
    gap; callers re-emit the offending reference verbatim so the inventory
    keeps explicit unresolved evidence instead of truncating.
    """
    ctx.ops_left -= 1
    ctx.chars_left -= chars
    if ctx.ops_left >= 0 and ctx.chars_left >= 0:
        return True
    _report_budget_exhaustion(ctx)
    return False


def _report_budget_exhaustion(ctx: _ScanContext) -> None:
    """Emit the expansion-budget diagnostic once and open a fail-closed gap."""
    if not ctx.budget_reported:
        ctx.budget_reported = True
        ctx.diagnostics.append(
            MakefileInventoryDiagnostic(
                MakefileInventoryDiagKind.EXPANSION_BUDGET,
                "Makefile",
                "expansion budget exhausted; remaining references stay verbatim",
            )
        )
    ctx.gap = True


def _literal_run(text: str, index: int) -> tuple[str, int]:
    """Return ``(literal, index)`` up to the next ``$(``/``${`` or the end.

    ``$$`` folds to a literal ``$`` inside the run as in Make; a bare ``$``
    that introduces no reference stays verbatim. The returned index sits
    at the opening ``$`` of the next reference or at ``len(text)``.
    """
    start = index
    while index < len(text):
        if text[index] != "$" or index + 1 >= len(text):
            index += 1
            continue
        follower = text[index + 1]
        if follower == "$":
            index += 2
            continue
        if follower in "({":
            break
        index += 1
    return text[start:index].replace("$$", "$"), index


def _expand_reference(
    cur_text: str,
    cur_index: int,
    env: Mapping[str, _VariableState],
    in_progress: frozenset[str],
    ctx: _ScanContext,
    cur_out: list[str],
) -> tuple[int, tuple[str, _VariableState] | None]:
    """Process the ``$(``/``${`` reference at ``cur_index``.

    Returns ``(next_index, descent)``: ``descent`` is ``(name, state)``
    when a recursive-flavor value must be expanded as a nested frame,
    else ``None`` after the token was emitted verbatim or a simple-flavor
    value was expanded in place.
    """
    scanned = _scan_reference(cur_text, cur_index)
    if scanned is None:
        cur_out.append(cur_text[cur_index:])
        return len(cur_text), None
    token, inner, end = scanned
    name = inner.strip()
    state = env.get(name)
    if state is None or _reference_unresolved(name, inner, state, in_progress):
        cur_out.append(token)
        return end, None
    charge = len(state.text) if state.flavor is _VariableFlavor.SIMPLE else 0
    if not _spend(ctx, charge):
        cur_out.append(token)
        return end, None
    if state.flavor is _VariableFlavor.SIMPLE:
        cur_out.append(state.text)
        return end, None
    return end, (name, state)


def _expand_text(
    text: str,
    env: Mapping[str, _VariableState],
    in_progress: frozenset[str],
    ctx: _ScanContext,
) -> str:
    """Expand only ``$(NAME)``/``${NAME}`` references against ``env``.

    Unknown, cyclic, conditional, partial, opaque, or unsupported references
    are re-emitted verbatim so unresolved evidence stays visible to callers.
    ``$$`` collapses to a literal ``$`` as in Make; other bare ``$`` bytes
    are preserved untouched. The expansion loop is iterative so arbitrarily
    deep named chains cannot exhaust the Python call stack.
    """
    root_out: list[str] = []
    stack: list[tuple[str, int, frozenset[str], list[str]]] = []
    cur_text, cur_index, cur_prog, cur_out = text, 0, in_progress, root_out
    while True:
        descent: tuple[str, _VariableState] | None = None
        while cur_index < len(cur_text):
            literal, cur_index = _literal_run(cur_text, cur_index)
            cur_out.append(literal)
            if cur_index < len(cur_text):
                cur_index, descent = _expand_reference(
                    cur_text, cur_index, env, cur_prog, ctx, cur_out
                )
            if descent is not None:
                break
        if descent is not None:
            name, descend_state = descent
            stack.append((cur_text, cur_index, cur_prog, cur_out))
            cur_text, cur_index, cur_prog, cur_out = (
                descend_state.text,
                0,
                cur_prog | {name},
                [],
            )
            continue
        finished = "".join(cur_out)
        if not stack:
            return finished
        ctx.chars_left -= len(finished)
        if ctx.chars_left < 0:
            _report_budget_exhaustion(ctx)
        cur_text, cur_index, cur_prog, cur_out = stack.pop()
        cur_out.append(finished)


def _reference_unresolved(
    name: str,
    inner: str,
    state: _VariableState,
    in_progress: frozenset[str],
) -> bool:
    """Report whether a ``$(NAME)``/``${NAME}`` token cannot be expanded.

    Nested ``$`` content, non-simple names, in-progress cycles, conditional
    or partial values, and opaque definitions all fail closed.
    """
    if "$" in inner or _SIMPLE_NAME.fullmatch(name) is None:
        return True
    if name in in_progress:
        return True
    return (
        state.conditional
        or state.partial
        or state.override_possible
        or state.flavor is _VariableFlavor.OPAQUE
    )


def _apply_assignment(
    state: _VariableState | None,
    operator: _AssignmentOperator,
    value: str,
    ctx: _ScanContext,
    conditional: bool,
    is_override: bool,
) -> _VariableState:
    """Apply one parsed assignment to a variable's recorded state.

    A variable marked ``override`` ignores later non-override file
    assignments, matching GNU Make origin precedence. Conditional
    assignments are not applied — their guard cannot be proven — but they
    mark the variable conditional so references stay explicit instead of
    being guessed. A conditional ``override`` assignment additionally
    records ``override_possible``: the guard may have installed an
    ``override`` that GNU Make honors over later non-override writes, so
    those writes keep the variable unresolved. Once text was skipped
    unapplied, a later assignment cannot erase the ``partial`` flag
    unless it re-proves the value: the skipped text may have installed
    an ``override`` that GNU Make would honor over any later non-override
    write.
    """
    if state is not None and state.override and not is_override:
        return state
    if conditional:
        return _mark_conditional(state, is_override)
    if operator is _AssignmentOperator.SHELL:
        result = _VariableState(_VariableFlavor.OPAQUE, "", override=is_override)
    elif operator is _AssignmentOperator.CONDITIONAL:
        if state is not None:
            return state
        result = _VariableState(_VariableFlavor.RECURSIVE, value, override=is_override)
    elif operator is _AssignmentOperator.APPEND:
        result = _apply_append(state, value, ctx, is_override)
    elif operator is _AssignmentOperator.SIMPLE:
        result = _VariableState(
            _VariableFlavor.SIMPLE,
            _expand_text(value, ctx.env, frozenset(), ctx),
            override=is_override,
        )
    else:
        result = _VariableState(_VariableFlavor.RECURSIVE, value, override=is_override)
    reproves = _reproves_after_gap(operator, state, is_override)
    if ctx.unapplied_text and not result.partial and not reproves:
        result = dataclasses.replace(result, partial=True)
    if state is not None and state.override_possible and not reproves:
        result = dataclasses.replace(result, conditional=True, override_possible=True)
    return result


def _mark_conditional(
    state: _VariableState | None,
    is_override: bool,
) -> _VariableState:
    """Flag a variable whose guarded assignment cannot be proven.

    The guarded value is not applied. A guarded ``override`` line
    additionally records possible override origin so later non-override
    writes and plain ``undefine`` keep the variable unresolved.
    """
    if state is None:
        state = _VariableState(_VariableFlavor.RECURSIVE, "")
    return dataclasses.replace(
        state,
        conditional=True,
        override_possible=state.override_possible or is_override,
    )


def _reproves_after_gap(
    operator: _AssignmentOperator,
    state: _VariableState | None,
    is_override: bool,
) -> bool:
    """Report whether an assignment re-proves a variable after skipped text.

    ``override X =``/``override X :=`` rewrite the value outright, so they
    also erase whatever an unapplied include or directive installed.
    ``+=`` and ``?=`` read the prior value and re-prove only when the
    recorded state is itself fully proven.
    """
    if is_override and operator in (
        _AssignmentOperator.RECURSIVE,
        _AssignmentOperator.SIMPLE,
    ):
        return True
    return (
        operator in (_AssignmentOperator.APPEND, _AssignmentOperator.CONDITIONAL)
        and state is not None
        and not state.partial
        and not state.conditional
    )


def _apply_append(
    state: _VariableState | None,
    value: str,
    ctx: _ScanContext,
    is_override: bool,
) -> _VariableState:
    """Apply ``+=`` with GNU Make flavor rules.

    Undefined variables take the recursive flavor like ``=``; simple
    variables expand the append now, recursive variables keep it raw.
    An ``override`` append still applies and marks the variable override.
    """
    if state is None:
        return _VariableState(_VariableFlavor.RECURSIVE, value, override=is_override)
    if state.flavor is _VariableFlavor.OPAQUE:
        return state
    separator = " " if state.text else ""
    if state.flavor is _VariableFlavor.SIMPLE:
        expanded = _expand_text(value, ctx.env, frozenset(), ctx)
        return _VariableState(
            _VariableFlavor.SIMPLE,
            state.text + separator + expanded,
            state.conditional,
            is_override or state.override,
            state.partial,
            state.override_possible,
        )
    return _VariableState(
        _VariableFlavor.RECURSIVE,
        state.text + separator + value,
        state.conditional,
        is_override or state.override,
        state.partial,
        state.override_possible,
    )


def _note_gap(
    ctx: _ScanContext,
    kind: MakefileInventoryDiagKind,
    location: str,
    detail: str,
) -> None:
    """Record an unproven construct and taint every defined variable.

    Skipped text may contain assignments or ``undefine`` lines for any
    variable already seen, so no recorded value is provably final; each
    becomes ``partial`` and its word list gains the explicit ``$(NAME)``
    trailer.
    """
    ctx.diagnostics.append(MakefileInventoryDiagnostic(kind, location, detail))
    ctx.gap = True
    ctx.unapplied_text = True
    for name, state in ctx.env.items():
        if not state.partial:
            ctx.env[name] = dataclasses.replace(state, partial=True)


def _note_diag(
    ctx: _ScanContext,
    kind: MakefileInventoryDiagKind,
    location: str,
    detail: str,
) -> None:
    """Record a diagnostic that does not affect provability of variables."""
    ctx.diagnostics.append(MakefileInventoryDiagnostic(kind, location, detail))


def _apply_undefine(
    ctx: _ScanContext,
    arguments: str,
    conditional: bool,
    is_override: bool,
    location: str,
) -> None:
    """Apply ``undefine``/``override undefine`` for a literal variable name.

    GNU Make precedence: a plain ``undefine`` is ignored for variables
    whose origin is ``override``; ``override undefine`` removes any
    file-level variable outright. Removal is only provable when nothing
    unproven could have re-marked the variable — a conditional or
    gap-tainted state, or earlier skipped text that could have installed
    an ``override``, all leave the outcome open, so the variable is kept
    ``partial`` instead of being dropped silently. Non-literal arguments
    open a fail-closed gap because the removed name cannot be identified.
    """
    names = arguments.split()
    if len(names) != 1 or _SIMPLE_NAME.fullmatch(names[0]) is None:
        _note_gap(
            ctx,
            MakefileInventoryDiagKind.UNDEFINE_NONLITERAL,
            location,
            f"undefine argument {arguments!r} is not one literal variable name",
        )
        return
    name = names[0]
    if conditional:
        state = ctx.env.get(name)
        if state is not None:
            ctx.env[name] = dataclasses.replace(state, conditional=True)
        return
    state = ctx.env.get(name)
    if state is None or is_override:
        ctx.env.pop(name, None)
        return
    if state.override:
        return
    if (
        state.conditional
        or state.partial
        or state.override_possible
        or ctx.unapplied_text
    ):
        ctx.env[name] = dataclasses.replace(state, partial=True)
        return
    ctx.env.pop(name)


def _resolve_include(
    ctx: _ScanContext,
    name: str,
    optional: bool,
    location: str,
) -> Path | None:
    """Resolve one literal include name to a file inside ``include_root``.

    Returns the resolved path when the file may be read, or ``None`` after
    recording the appropriate diagnostic. Missing optional includes are a
    proven no-op; every other refusal opens a fail-closed gap.
    """
    if any(char in _NONLITERAL_PATH_CHARS for char in name):
        _note_gap(
            ctx,
            MakefileInventoryDiagKind.INCLUDE_NONLITERAL_NAME,
            location,
            f"include name {name!r} is not a literal path",
        )
        return None
    if ctx.base_dir is None or ctx.include_root is None:
        _note_gap(
            ctx,
            MakefileInventoryDiagKind.INCLUDE_NO_BASE_DIR,
            location,
            f"cannot resolve include {name!r} without a base directory",
        )
        return None
    candidate = Path(name)
    resolved = candidate if candidate.is_absolute() else ctx.base_dir / candidate
    try:
        resolved = resolved.resolve()
    except OSError as exc:
        _note_gap(
            ctx,
            MakefileInventoryDiagKind.INCLUDE_READ_ERROR,
            location,
            f"include {name!r} cannot be resolved: {exc}",
        )
        return None
    if not resolved.is_relative_to(ctx.include_root):
        _note_gap(
            ctx,
            MakefileInventoryDiagKind.INCLUDE_OUTSIDE_ROOT,
            location,
            f"include {name!r} resolves outside the allowed root {ctx.include_root}",
        )
        return None
    if resolved.is_file():
        return resolved
    if optional:
        _note_diag(
            ctx,
            MakefileInventoryDiagKind.INCLUDE_SKIPPED_OPTIONAL,
            location,
            f"optional include {name!r} is absent; proven no-op",
        )
        return None
    _note_gap(
        ctx,
        MakefileInventoryDiagKind.INCLUDE_MISSING,
        location,
        f"required include {name!r} does not exist",
    )
    return None


def _apply_include(
    ctx: _ScanContext,
    kind: str,
    names_text: str,
    conditional: bool,
    include_stack: tuple[Path, ...],
    location: str,
) -> None:
    """Process one ``include``/``-include``/``sinclude`` directive in place.

    Literal repo-local files are scanned at this point, preserving GNU
    Make's textual insertion order. Includes inside an unevaluated
    conditional cannot be proven, so they open a gap instead of guessing.
    """
    if conditional:
        _note_gap(
            ctx,
            MakefileInventoryDiagKind.CONDITIONAL_INCLUDE,
            location,
            f"'{kind}' sits inside a conditional block that cannot be evaluated",
        )
        return
    optional = kind != "include"
    for name in names_text.split():
        resolved = _resolve_include(ctx, name, optional, location)
        if resolved is None:
            continue
        if resolved in include_stack:
            _note_gap(
                ctx,
                MakefileInventoryDiagKind.INCLUDE_CYCLE,
                location,
                f"include cycle through {name!r}",
            )
            continue
        if len(include_stack) >= _MAX_INCLUDE_DEPTH:
            _note_gap(
                ctx,
                MakefileInventoryDiagKind.INCLUDE_DEPTH_LIMIT,
                location,
                f"include depth exceeds {_MAX_INCLUDE_DEPTH} at {name!r}",
            )
            continue
        if ctx.files_read >= _MAX_INCLUDE_FILES:
            _note_gap(
                ctx,
                MakefileInventoryDiagKind.INCLUDE_FILE_LIMIT,
                location,
                f"include count exceeds {_MAX_INCLUDE_FILES} at {name!r}",
            )
            continue
        try:
            text = resolved.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            _note_gap(
                ctx,
                MakefileInventoryDiagKind.INCLUDE_READ_ERROR,
                location,
                f"include {name!r} cannot be read: {exc}",
            )
            continue
        ctx.files_read += 1
        origin = str(resolved.relative_to(ctx.include_root)) if ctx.include_root else str(resolved)
        _collect_into(text, ctx, (*include_stack, resolved), origin)


def _conditional_directive(
    line: str,
    depth: int,
    ctx: _ScanContext,
    location: str,
) -> int | None:
    """Update conditional nesting for one ``if``/``else``/``endif`` line.

    Returns the new depth, or ``None`` when the line is not a conditional
    directive. ``else`` and ``else if*`` clauses keep the enclosing depth:
    one ``endif`` closes the whole chain in GNU Make. A closer or ``else``
    without an open conditional is a GNU Make syntax error, so it opens a
    fail-closed gap instead of being ignored.
    """
    if _CONDITIONAL_CLOSE.match(line):
        if depth == 0:
            _note_gap(
                ctx,
                MakefileInventoryDiagKind.MALFORMED_DIRECTIVE,
                location,
                "'endif' without an open conditional",
            )
            return 0
        return depth - 1
    if _CONDITIONAL_OPEN.match(line):
        return depth + 1
    if _CONDITIONAL_ELSEIF.match(line) or _CONDITIONAL_ELSE.match(line):
        if depth == 0:
            _note_gap(
                ctx,
                MakefileInventoryDiagKind.MALFORMED_DIRECTIVE,
                location,
                "'else' without an open conditional",
            )
        return depth
    return None


def _apply_define(
    ctx: _ScanContext,
    name: str,
    conditional: bool,
    is_override: bool,
) -> None:
    """Record a ``define`` block's effect on ``name`` under GNU precedence.

    The body is opaque to the reader. A non-override ``define`` is ignored
    whenever GNU Make override precedence would ignore it — a proven
    ``override`` variable, or a possible conditional ``override`` — so the
    recorded state keeps its uncertainty instead of being clobbered. A
    conditional ``define`` flags the variable unresolved; a conditional
    ``override define`` additionally records possible override origin.
    """
    prior = ctx.env.get(name)
    if (
        prior is not None
        and (prior.override or prior.override_possible)
        and not is_override
    ):
        return
    if conditional:
        base = prior if prior is not None else _VariableState(_VariableFlavor.OPAQUE, "")
        ctx.env[name] = dataclasses.replace(
            base,
            conditional=True,
            override_possible=base.override_possible or is_override,
        )
        return
    ctx.env[name] = _VariableState(_VariableFlavor.OPAQUE, "", override=is_override)


def _apply_directive_line(
    stripped: str,
    ctx: _ScanContext,
    conditional: bool,
    include_stack: tuple[Path, ...],
    location: str,
) -> bool:
    """Apply include/undefine/malformed lines; return True when consumed."""
    include_match = _INCLUDE.match(stripped)
    if include_match is not None:
        _apply_include(
            ctx,
            include_match.group(1),
            include_match.group(2) or "",
            conditional,
            include_stack,
            location,
        )
        return True
    undefine_match = _UNDEFINE.match(stripped)
    if undefine_match is not None:
        _apply_undefine(
            ctx,
            undefine_match.group(2) or "",
            conditional,
            undefine_match.group(1) is not None,
            location,
        )
        return True
    if _OVERRIDE_BARE.match(stripped):
        _note_gap(
            ctx,
            MakefileInventoryDiagKind.MALFORMED_DIRECTIVE,
            location,
            "bare 'override NAME' is invalid Make syntax",
        )
        return True
    if _DOLLAR_STATEMENT.match(stripped):
        _note_gap(
            ctx,
            MakefileInventoryDiagKind.UNSUPPORTED_STATEMENT,
            location,
            "top-level $(...) statement could alter variables or abort parsing",
        )
        return True
    return False


def _note_unterminated(
    ctx: _ScanContext,
    conditional_depth: int,
    in_define: bool,
    define_name: str,
    origin: str,
) -> None:
    """Report blocks still open when a Makefile's text ran out."""
    if conditional_depth > 0:
        _note_gap(
            ctx,
            MakefileInventoryDiagKind.UNTERMINATED_BLOCK,
            f"{origin}:end",
            f"conditional opened but never closed in {origin}",
        )
    if in_define:
        _note_gap(
            ctx,
            MakefileInventoryDiagKind.UNTERMINATED_BLOCK,
            f"{origin}:end",
            f"define {define_name} missing endef in {origin}",
        )


def _is_unknown_global_assignment(line: str) -> bool:
    """Recognize unapplied global writes without treating rules as assignments.

    Called only after supported directives and literal assignments fail to
    match. References in a computed name are skipped as units so an internal
    colon/equal sign cannot be confused with a rule or assignment separator.
    A rule colon or leading recipe tab leaves the line outside this contract.
    This detector refuses syntax; it never evaluates names or Make prefixes.
    """
    if line.startswith("\t"):
        return False
    index = 0
    while index < len(line):
        if line[index:index + 2] in {"$(", "${"}:
            reference = _scan_reference(line, index)
            if reference is None:
                return False
            index = reference[2]
            continue
        if line[index] == ":":
            return bool(line[:index].strip()) and (
                line.startswith(":=", index) or line.startswith("::=", index)
            )
        if line[index] == "=":
            return bool(line[:index].strip())
        index += 1
    return False


def _collect_into(
    makefile_text: str,
    ctx: _ScanContext,
    include_stack: tuple[Path, ...],
    origin: str,
) -> None:
    """Fold one Makefile's directives into ``ctx.env`` top to bottom.

    ``define`` bodies mark the name opaque and are skipped. ``ifdef``-family
    guards mark enclosed assignments conditional. ``include`` directives
    resolve literal repo-local files in place; unresolvable ones open a
    fail-closed gap through ``_note_gap``. Recipe/rule lines never match the
    directive patterns, so their effects stay unresolved rather than
    guessed.
    """
    conditional_depth = 0
    in_define = False
    define_name = ""
    for lineno, line in _logical_lines(makefile_text):
        if in_define:
            if _DEFINE_CLOSE.match(line):
                in_define = False
            continue
        location = f"{origin}:{lineno}"
        new_depth = _conditional_directive(line, conditional_depth, ctx, location)
        if new_depth is not None:
            conditional_depth = new_depth
            continue
        stripped = _strip_comment(line).rstrip()
        define_match = _DEFINE_OPEN.match(line)
        if define_match is not None:
            prefixes, define_name = define_match.groups()
            _apply_define(
                ctx,
                define_name,
                conditional_depth > 0,
                "override" in prefixes.split(),
            )
            in_define = True
            continue
        if _apply_directive_line(
            stripped, ctx, conditional_depth > 0, include_stack, location
        ):
            continue
        assignment = _ASSIGNMENT.fullmatch(stripped)
        if assignment is None:
            if _is_unknown_global_assignment(stripped):
                _note_gap(
                    ctx,
                    MakefileInventoryDiagKind.UNSUPPORTED_GLOBAL_ASSIGNMENT,
                    location,
                    "unsupported global assignment name or prefix could alter variable origin/value",
                )
            continue
        prefixes, name, operator_text, value = assignment.groups()
        ctx.env[name] = _apply_assignment(
            ctx.env.get(name),
            _OPERATOR[operator_text],
            value,
            ctx,
            conditional_depth > 0,
            "override" in prefixes.split(),
        )
    _note_unterminated(ctx, conditional_depth, in_define, define_name, origin)


def _scan(
    makefile_text: str,
    base_dir: Path | None,
    include_root: Path | None,
    origin: str,
) -> _ScanContext:
    """Collect variables, diagnostics, and the gap flag for ``makefile_text``."""
    resolved_base = base_dir.resolve() if base_dir is not None else None
    resolved_root: Path | None
    if include_root is not None:
        resolved_root = include_root.resolve()
    else:
        resolved_root = resolved_base
    ctx = _ScanContext(
        env={},
        diagnostics=[],
        gap=False,
        unapplied_text=False,
        base_dir=resolved_base,
        include_root=resolved_root,
        files_read=0,
        ops_left=_MAX_EXPANSION_OPERATIONS,
        chars_left=_MAX_EXPANSION_CHARS,
        budget_reported=False,
    )
    _collect_into(makefile_text, ctx, (), origin)
    return ctx


def _words_from_scan(ctx: _ScanContext, variable_name: str) -> tuple[str, ...]:
    """Project one variable's recorded state into its final word list."""
    state = ctx.env.get(variable_name)
    marker = f"$({variable_name})"
    if state is None:
        return (marker,) if ctx.gap else ()
    if state.flavor is _VariableFlavor.OPAQUE:
        return (marker,)
    if state.flavor is _VariableFlavor.SIMPLE:
        text = state.text
    else:
        text = _expand_text(state.text, ctx.env, frozenset({variable_name}), ctx)
    words = tuple(text.split())
    if state.conditional or state.partial or state.override_possible:
        words += (marker,)
    return words


def makefile_variable_words(
    makefile_text: str,
    variable_name: str,
    *,
    base_dir: str | Path | None = None,
    include_root: str | Path | None = None,
) -> tuple[str, ...]:
    """Return the final word list for ``variable_name``.

    ``$(NAME)``/``${NAME}`` references provable from plain ``=``/``:=``/
    ``::=``/``+=``/``?=`` assignments expand in place with GNU Make
    recursive-versus-simple timing; ``override`` freezes a variable against
    later non-override file assignments and ``undefine`` removes it.
    Literal ``include`` targets are read in place when ``base_dir`` is
    given: relative names resolve against ``base_dir`` (matching GNU
    Make's working-directory semantics) and must stay inside
    ``include_root`` (default: ``base_dir``). Cycles, escapes, missing
    required files, non-literal names, and exhausted budgets fail closed:
    every variable whose value may have been altered gains a trailing
    ``$(NAME)`` marker so architecture checks flag it instead of accepting
    a guessed list, and the cause is emitted through
    :func:`makefile_inventory_diagnostics`. Skipped text (an unresolved
    include, unsupported statement, or malformed directive) may have
    installed an ``override``, so the marker survives later non-override
    assignments and ``undefine`` lines; only an ``override``
    redefinition re-proves the variable. A guarded ``override`` inside an
    unevaluated conditional marks the variable unresolved the same way.
    Unknown, cyclic, conditional, function, shell, or
    environment-dependent references stay explicit ``$(NAME)`` tokens.
    """
    ctx = _scan(
        makefile_text,
        Path(base_dir) if base_dir is not None else None,
        Path(include_root) if include_root is not None else None,
        "Makefile",
    )
    return _words_from_scan(ctx, variable_name)


def makefile_inventory_diagnostics(
    makefile_text: str,
    *,
    base_dir: str | Path | None = None,
    include_root: str | Path | None = None,
) -> tuple[MakefileInventoryDiagnostic, ...]:
    """Return typed diagnostics for constructs that could not be applied.

    Diagnostics explain every fail-closed marker produced by
    :func:`makefile_variable_words`: unresolvable or skipped includes,
    non-literal ``undefine`` arguments, malformed directives, unterminated
    blocks, ``$(...)`` statement lines, and budget exhaustion.
    """
    ctx = _scan(
        makefile_text,
        Path(base_dir) if base_dir is not None else None,
        Path(include_root) if include_root is not None else None,
        "Makefile",
    )
    return tuple(ctx.diagnostics)


def makefile_variable_words_from_file(
    makefile_path: str | Path,
    variable_name: str,
    *,
    include_root: str | Path | None = None,
) -> tuple[str, ...]:
    """Read ``variable_name``'s word list from a Makefile on disk.

    Includes resolve relative to the Makefile's directory (matching
    ``make -C`` semantics) and must stay inside ``include_root``, which
    defaults to that directory so repository Makefiles cannot pull in
    files outside the tree.
    """
    path = Path(makefile_path)
    text = path.read_text(encoding="utf-8")
    root = Path(include_root) if include_root is not None else path.parent
    ctx = _scan(text, path.parent, root, path.name)
    return _words_from_scan(ctx, variable_name)


def makefile_inventory_diagnostics_from_file(
    makefile_path: str | Path,
    *,
    include_root: str | Path | None = None,
) -> tuple[MakefileInventoryDiagnostic, ...]:
    """Return diagnostics for a Makefile on disk; see ``_from_file`` words."""
    path = Path(makefile_path)
    text = path.read_text(encoding="utf-8")
    root = Path(include_root) if include_root is not None else path.parent
    ctx = _scan(text, path.parent, root, path.name)
    return tuple(ctx.diagnostics)
