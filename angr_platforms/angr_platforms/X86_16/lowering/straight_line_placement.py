"""Check statement placement without inferring dataflow or branch semantics.

Layer: Types/Lowering.
Responsibility: allow existing expressions to move across transparent statement
groups only. Conditionals, loops, labels and every other statement remain
opaque boundaries; a generic recursive AST walk cannot prove adjacency.
"""

from __future__ import annotations

from angr.analyses.decompiler.structured_codegen.c import CStatements


def adjacent_straight_line_statements_8616(
    root: CStatements, first: object, second: object,
) -> bool:
    """Require unique adjacent occurrences in the same unconditional sequence.

    Only CStatements is transparent. In particular, do not enter conditional
    bodies: adjacency of their descendants is not an execution-order proof.
    Shared occurrences are ambiguous and must not authorize moving an effect.
    """
    pending: list[object] = [root]
    flattened: list[object] = []
    expanded: set[int] = set()
    while pending:
        node = pending.pop()
        if isinstance(node, CStatements):
            if id(node) in expanded:
                return False
            expanded.add(id(node))
            pending.extend(reversed(node.statements))
        else:
            flattened.append(node)
    first_positions = [index for index, node in enumerate(flattened) if node is first]
    second_positions = [index for index, node in enumerate(flattened) if node is second]
    return (
        len(first_positions) == len(second_positions) == 1
        and second_positions[0] == first_positions[0] + 1
    )
