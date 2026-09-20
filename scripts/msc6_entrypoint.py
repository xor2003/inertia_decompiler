"""Bind a linked fixture's proven main address to the MS C executable harness.

Layer: Tooling/gates.
Responsibility: append only a CRT entry wrapper around an existing generated
function. The fixture builder supplies its same-build main label address;
neither function behavior nor argument values are recovered here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from pycparser import c_ast

from scripts.generated_c_contracts import _parse_generated_c

_INTEGER_TYPE_WORDS: frozenset[str] = frozenset({"signed", "unsigned", "char", "short", "int", "long"})


class EntryBindingStatus(StrEnum):
    """Typed fixture-entry acceptance and refusal outcomes."""

    EXISTING = "existing"
    BOUND = "bound"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class EntryBinding:
    """Unchanged generated source plus an optional explicit fixture wrapper."""

    source: str
    status: EntryBindingStatus
    symbol: str | None = None
    detail: str | None = None


def _zero_argument_integer_function(function: c_ast.FuncDef) -> bool:
    """Require an integral result and no argument synthesis for the wrapper."""
    declaration = function.decl.type
    if not isinstance(declaration, c_ast.FuncDecl) or not isinstance(declaration.type, c_ast.TypeDecl):
        return False
    return_type = declaration.type.type
    if not isinstance(return_type, c_ast.IdentifierType) or not set(return_type.names) <= _INTEGER_TYPE_WORDS:
        return False
    if declaration.args is None:
        return True
    parameters = declaration.args.params
    if len(parameters) != 1 or not isinstance(parameters[0], c_ast.Typename):
        return False
    parameter_type = parameters[0].type
    return (
        isinstance(parameter_type, c_ast.TypeDecl)
        and isinstance(parameter_type.type, c_ast.IdentifierType)
        and parameter_type.type.names == ["void"]
    )


def bind_msc6_fixture_entrypoint(source: str, *, main_address: int | None) -> EntryBinding:
    """Invoke the exact linked-main numeric symbol, refusing missing evidence.

    Parsing inspects declarations only; the original generated source is retained
    byte-for-byte. The address must come from the fixture's same-build labels,
    not the DOS startup address or a guess based on function contents.
    """
    try:
        parsed = _parse_generated_c(source)
    except ValueError as error:
        return EntryBinding(source, EntryBindingStatus.REFUSED, detail=str(error))
    definitions = [node for node in parsed.ext if isinstance(node, c_ast.FuncDef)]
    if any(function.decl.name == "main" for function in definitions):
        return EntryBinding(source, EntryBindingStatus.EXISTING, symbol="main")
    if type(main_address) is not int or main_address < 0:
        return EntryBinding(source, EntryBindingStatus.REFUSED, detail="same-build main address unavailable")
    symbol = f"sub_{main_address:x}"
    matches = [function for function in definitions if function.decl.name == symbol]
    if len(matches) != 1 or not _zero_argument_integer_function(matches[0]):
        return EntryBinding(source, EntryBindingStatus.REFUSED, symbol, "expected one zero-argument integer entry definition")
    wrapper = f"\n/* Fixture CRT entry; generated function body remains unchanged. */\nint main(void) {{ return (int){symbol}(); }}\n"
    return EntryBinding(source + wrapper, EntryBindingStatus.BOUND, symbol)
