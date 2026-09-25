"""Layer: Optional evidence/reporting.

Responsibility: decode Borland C++ mangled names (``@scope@name$Q<types>``)
into a typed AST for debug-schema reporting and signature recovery.
Forbidden: requiring mangled names for arguments, types, control flow, or
validation success — mangled names are optional evidence only.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class BorlandSpecial(Enum):
    """Special-name categories encoded in Borland C++ mangled symbols."""

    NONE = "function"
    CONSTRUCTOR = "constructor"
    DESTRUCTOR = "destructor"
    OPERATOR = "operator"
    CONVERSION = "conversion"
    DATA_MEMBER = "data_member"
    VTABLE = "vtable"


class BorlandTypeKind(Enum):
    """Borland mangled type node kinds."""

    BUILTIN = "builtin"
    CLASS = "class"
    POINTER = "pointer"
    REFERENCE = "reference"
    ARRAY = "array"
    FUNCTION = "function"
    MEMBER_POINTER = "member_pointer"
    UNKNOWN = "unknown"


_BORLAND_BUILTIN_TYPES = {
    "V": "void",
    "C": "char",
    "S": "short",
    "I": "int",
    "L": "long",
    "F": "float",
    "D": "double",
    "G": "long double",
    "B": "bool",
    "E": "...",
}

_BORLAND_POINTER_SPACES = {
    "P": "near",
    "N": "far",
    "R": "near",
    "M": "far",
}

# Documented Borland operator encodings (`$b<op>`).
_BORLAND_OPERATORS = {
    "badd": "+",
    "badr": "&",
    "band": "&",
    "barow": "->",
    "barwm": "->*",
    "basg": "=",
    "bcall": "()",
    "bcmp": "~",
    "bcoma": ",",
    "bdec": "--",
    "bdele": "delete",
    "bdiv": "/",
    "beql": "==",
    "bgeq": ">=",
    "bgtr": ">",
    "binc": "++",
    "bind": "*",
    "bland": "&&",
    "blor": "||",
    "bleq": "<=",
    "blsh": "<<",
    "blss": "<",
    "bmod": "%",
    "bmul": "*",
    "bneq": "!=",
    "bnew": "new",
    "bnot": "!",
    "bor": "|",
    "brand": "&=",
    "brdiv": "/=",
    "brlsh": "<<=",
    "brmin": "-=",
    "brmod": "%=",
    "brmul": "*=",
    "bror": "|=",
    "brplu": "+=",
    "brrsh": ">>=",
    "brsh": ">>",
    "brxor": "^=",
    "bsub": "-",
    "bsubs": "[]",
    "bxor": "^",
    "bnwa": "new[]",
    "bdla": "delete[]",
}


@dataclass(frozen=True)
class BorlandType:
    """One node of a decoded Borland mangled type."""

    kind: BorlandTypeKind
    builtin: str = ""
    class_name: str = ""
    space: str = ""
    quals: frozenset[str] = frozenset()
    target: BorlandType | None = None
    params: tuple[BorlandType, ...] = ()
    result: BorlandType | None = None
    array_size: int | None = None
    member_of: str = ""


@dataclass(frozen=True)
class BorlandSignature:
    """A decoded Borland mangled symbol."""

    raw: str
    scopes: tuple[str, ...]
    name: str
    special: BorlandSpecial
    params: tuple[BorlandType, ...] = ()
    operator: str = ""
    conversion_target: BorlandType | None = None
    parse_error: str = ""


def _render_type(type_node: BorlandType) -> str:
    """Render a decoded type as C-flavoured text (optional evidence)."""
    if type_node.kind is BorlandTypeKind.BUILTIN:
        quals = " ".join(sorted(type_node.quals))
        return f"{quals} {type_node.builtin}".strip() or type_node.builtin
    if type_node.kind is BorlandTypeKind.CLASS:
        return type_node.class_name
    if type_node.kind is BorlandTypeKind.POINTER:
        if type_node.target is not None and type_node.target.kind is BorlandTypeKind.FUNCTION:
            params = ", ".join(
                _render_type(p) for p in type_node.target.params
            )
            return (
                f"{_render_type(type_node.target.result)}"
                f"({type_node.space}*)({params})"
            )
        return f"{_render_type(type_node.target)} {type_node.space} *".strip()
    if type_node.kind is BorlandTypeKind.REFERENCE:
        return f"{_render_type(type_node.target)} {type_node.space} &".strip()
    if type_node.kind is BorlandTypeKind.FUNCTION:
        params = ", ".join(_render_type(p) for p in type_node.params) or "void"
        return f"({params}) -> {_render_type(type_node.result)}"
    if type_node.kind is BorlandTypeKind.ARRAY:
        return f"{_render_type(type_node.target)}[{type_node.array_size}]"
    if type_node.kind is BorlandTypeKind.MEMBER_POINTER:
        return f"{_render_type(type_node.target)} {type_node.member_of}::*"
    return "?"


def _render_callable_name(sig: BorlandSignature, prefix: str) -> str:
    """Pick the display name and scope prefix for a callable symbol."""
    if sig.special is BorlandSpecial.CONSTRUCTOR:
        leaf = sig.scopes[-1] if sig.scopes else sig.name
        return f"{prefix}{leaf}::{leaf}"
    if sig.special is BorlandSpecial.DESTRUCTOR:
        leaf = sig.scopes[-1] if sig.scopes else sig.name
        return f"{prefix}{leaf}::~{leaf}"
    if sig.special is BorlandSpecial.OPERATOR:
        sep = " " if sig.operator[:1].isalpha() else ""
        return f"{prefix}operator{sep}{sig.operator}"
    if sig.special is BorlandSpecial.CONVERSION:
        target = _render_type(sig.conversion_target) if sig.conversion_target else "?"
        return f"{prefix}operator {target}"
    return f"{prefix}{sig.name}"


def render_borland_signature(sig: BorlandSignature) -> str:
    """Render a decoded symbol as TDUMP-style demangled text."""
    if sig.parse_error:
        return sig.raw
    scope = "::".join(sig.scopes)
    prefix = f"{scope}::" if scope else ""
    if sig.special is BorlandSpecial.VTABLE:
        return f"{prefix}vtable"
    if sig.special is BorlandSpecial.DATA_MEMBER:
        return f"{prefix}{sig.name}"
    params = ", ".join(_render_type(p) for p in sig.params)
    if all(p.builtin in ("void", "...") for p in sig.params):
        params = ""
    return f"{_render_callable_name(sig, prefix)}({params})"


class _BorlandNameParser:
    """Recursive-descent parser for Borland C++ mangled names."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.history: list[BorlandType] = []

    def _peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def _take(self) -> str:
        ch = self._peek()
        self.pos += 1
        return ch

    def _take_decimal(self) -> int | None:
        start = self.pos
        while self._peek().isdigit():
            self.pos += 1
        if self.pos == start:
            return None
        return int(self.text[start : self.pos])

    def _take_class_name(self) -> str | None:
        """Parse a <decimal-length><name> class token."""
        length = self._take_decimal()
        if length is None or length <= 0 or self.pos + length > len(self.text):
            return None
        name = self.text[self.pos : self.pos + length]
        self.pos += length
        return name

    def _take_quals(self) -> frozenset[str]:
        """Consume leading signedness/CV qualifier letters."""
        quals: set[str] = set()
        while self._peek() in "UZWXuzwx":
            ch = self._take().upper()
            quals.add({"U": "unsigned", "Z": "signed", "X": "const", "W": "volatile"}[ch])
        return frozenset(quals)

    def _parse_indirection(self, ch: str, quals: frozenset[str]) -> BorlandType:
        """Parse P/N/R/M indirections, including member pointers."""
        self.pos += 1
        space = _BORLAND_POINTER_SPACES[ch]
        # 'M' followed by a class length is a member pointer.
        if ch == "M" and self._peek().isdigit():
            owner = self._take_class_name()
            return BorlandType(
                BorlandTypeKind.MEMBER_POINTER,
                member_of=owner or "",
                target=self.parse_type(),
                quals=quals,
            )
        kind = (
            BorlandTypeKind.POINTER
            if ch in "PN"
            else BorlandTypeKind.REFERENCE
        )
        return BorlandType(
            kind, space=space, target=self.parse_type(), quals=quals
        )

    def _parse_repeat(self) -> BorlandType:
        """Resolve a T<n> back-reference to an earlier argument type."""
        self.pos += 1
        index = self._take_decimal()
        if index is None or index < 1 or index > len(self.history):
            return BorlandType(BorlandTypeKind.UNKNOWN)
        return self.history[index - 1]

    def _parse_function_type(self) -> BorlandType:
        """Parse a function type in pointer position (params, '$', result)."""
        self.pos += 1
        params = self.parse_param_list(until="$")
        if self._peek() == "$":
            self.pos += 1
        return BorlandType(
            BorlandTypeKind.FUNCTION, params=params, result=self.parse_type()
        )

    def _parse_array_type(self, quals: frozenset[str]) -> BorlandType:
        """Parse an ``a<size>$<element>`` array type."""
        self.pos += 1
        size = self._take_decimal()
        if self._peek() == "$":
            self.pos += 1
        return BorlandType(
            BorlandTypeKind.ARRAY,
            target=self.parse_type(),
            array_size=size,
            quals=quals,
        )

    def parse_type(self) -> BorlandType:
        """Parse one type at the cursor, honouring T<n> arg repeats."""
        quals = self._take_quals()
        ch = self._peek().upper()
        if ch == "T":
            return self._parse_repeat()
        if ch in _BORLAND_BUILTIN_TYPES:
            self.pos += 1
            return BorlandType(
                BorlandTypeKind.BUILTIN,
                builtin=_BORLAND_BUILTIN_TYPES[ch],
                quals=quals,
            )
        if ch == "Q":
            return self._parse_function_type()
        if ch == "A":
            return self._parse_array_type(quals)
        if ch in "PNRM":
            return self._parse_indirection(ch, quals)
        if self._peek().isdigit():
            name = self._take_class_name()
            if name is None:
                return BorlandType(BorlandTypeKind.UNKNOWN)
            return BorlandType(
                BorlandTypeKind.CLASS, class_name=name, quals=quals
            )
        return BorlandType(BorlandTypeKind.UNKNOWN)

    def parse_param_list(self, *, until: str = "") -> tuple[BorlandType, ...]:
        """Parse parameter types into the repeat history."""
        params: list[BorlandType] = []
        while self.pos < len(self.text) and self._peek() != until:
            before = self.pos
            param = self.parse_type()
            params.append(param)
            self.history.append(param)
            if self.pos == before:
                break
        return tuple(params)


def _parse_special_tail(
    tail: str,
) -> tuple[
    BorlandSpecial,
    str,
    BorlandType | None,
    tuple[BorlandType, ...],
    str,
]:
    """Parse the ``$``-tail of a mangled name into signature components."""
    parser = _BorlandNameParser(tail)
    lower = tail.lower()
    special = BorlandSpecial.NONE
    operator = ""
    conversion_target: BorlandType | None = None
    if lower.startswith("bctr"):
        special = BorlandSpecial.CONSTRUCTOR
        parser.pos += 4
    elif lower.startswith("bdtr"):
        special = BorlandSpecial.DESTRUCTOR
        parser.pos += 4
    elif lower.startswith("b"):
        special = BorlandSpecial.OPERATOR
        for code in sorted(_BORLAND_OPERATORS, key=len, reverse=True):
            if lower.startswith(code):
                operator = _BORLAND_OPERATORS[code]
                parser.pos += len(code)
                break
    elif lower.startswith("o"):
        special = BorlandSpecial.CONVERSION
        parser.pos += 1
        conversion_target = parser.parse_type()
    if parser._peek() == "$":
        parser.pos += 1
    params: tuple[BorlandType, ...] = ()
    if parser._peek().upper() == "Q":
        parser.pos += 1
        params = parser.parse_param_list()
    parse_error = (
        "" if parser.pos == len(tail) else f"trailing bytes at {parser.pos}"
    )
    return special, operator, conversion_target, params, parse_error


def demangle_borland_name(name: str) -> BorlandSignature:
    """Decode one Borland C++ mangled name into a typed signature.

    Grammar (Borland Open Architecture): ``@scope@...@name$q<types>`` where
    ``$b`` marks constructors/destructors/operators, ``$o`` conversions,
    and a bare ``@class@`` names the class vtable.
    """
    if not name.startswith("@"):
        return BorlandSignature(
            raw=name, scopes=(), name=name, special=BorlandSpecial.NONE,
            parse_error="not a Borland-mangled name",
        )
    body = name[1:]
    dollar = body.find("$")
    head = body if dollar < 0 else body[:dollar]
    parts = [part for part in head.split("@") if part]
    scopes = tuple(parts[:-1])
    leaf = parts[-1] if parts else ""
    special = BorlandSpecial.NONE
    operator = ""
    conversion_target: BorlandType | None = None
    params: tuple[BorlandType, ...] = ()
    parse_error = ""

    if dollar < 0:
        # @class@ = vtable; @class@member = data member
        special = (
            BorlandSpecial.VTABLE
            if head.endswith("@") or not leaf
            else BorlandSpecial.DATA_MEMBER
        )
        if special is BorlandSpecial.VTABLE:
            scopes = tuple(parts)
            leaf = parts[-1] if parts else ""
    else:
        special, operator, conversion_target, params, parse_error = (
            _parse_special_tail(body[dollar + 1 :])
        )
    return BorlandSignature(
        raw=name,
        scopes=scopes,
        name=leaf,
        special=special,
        params=params,
        operator=operator,
        conversion_target=conversion_target,
        parse_error=parse_error,
    )
