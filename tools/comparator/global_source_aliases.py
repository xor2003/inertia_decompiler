"""Layer: validation declared global correspondence.

Responsibility: recover explicit renamed-global claims from decompiler source
metadata, corroborated by declarations and original data labels. These claims
are relocation premises, never type, memory-layout or behavioral proofs.
"""
from __future__ import annotations

import re
from pathlib import Path

_DECLARATION = r"[A-Za-z_][A-Za-z_0-9 \t*]*?[ \t*]+(?P<name>[A-Za-z_][A-Za-z_0-9]*)(?:\[[^\]\r\n]*\])*"
_EXTERN = re.compile(r"^extern[ \t]+" + _DECLARATION + r";[ \t\r]*(?://[^\n]*)?$", re.MULTILINE)
_ANNOTATION = re.compile(r"^//[ \t]*(?P<address>[0-9A-Fa-f]{1,8}): using guessed type "
                         + _DECLARATION + r";[ \t\r]*$", re.MULTILINE)


def declared_global_aliases(path: Path, original_symbols: dict[str, int]) -> dict[str, int]:
    """Read a caller-supplied name/address premise without inventing data objects.

    Only names declared as extern data and annotated with an actual original
    data-label address qualify. The LINK-map consumer independently checks the
    candidate data segment and loaded section. Ambiguous names reject rather
    than selecting the final annotation. Guessed types are deliberately unused.
    """
    source = path.read_text(errors="strict")
    declared = {match["name"] for match in _EXTERN.finditer(source)}
    addresses = set(original_symbols.values())
    claims: dict[str, int] = {}
    for match in _ANNOTATION.finditer(source):
        name, address = match["name"], int(match["address"], 16)
        if name not in declared:
            continue
        if claims.get(name, address) != address or original_symbols.get(name, address) != address:
            raise ValueError(f"conflicting source global aliases for {name}")
        claims[name] = address
    return {name: address for name, address in claims.items() if address in addresses}
