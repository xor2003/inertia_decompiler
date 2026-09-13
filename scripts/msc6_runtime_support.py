"""Provide linkable architectural state for MS C generated-code checks.

Layer: Tooling/gates.
Responsibility: emit the target runtime definitions required by generated C,
using Lowering's authoritative GP storage ABI. This is not an emulator or
semantic recovery pass. It must not replace generated function bodies.
"""

from __future__ import annotations


def msc6_runtime_state_declarations() -> str:
    """Declare the known GP ABI before generic missing-global preparation."""
    from angr_platforms.X86_16.lowering.gp_register_state import runtime_gp_state_symbols_8616

    return "".join(
        f"extern unsigned long {symbol};\n" for symbol in runtime_gp_state_symbols_8616()
    )


def msc6_runtime_support_source() -> str:
    """Return C89 runtime support, with MS C's 32-bit unsigned-long GP lanes."""
    from angr_platforms.X86_16.lowering.gp_register_state import runtime_gp_state_symbols_8616

    definitions = "\n".join(
        f"unsigned long {symbol} = 0UL;" for symbol in runtime_gp_state_symbols_8616()
    )
    return (
        "/* Generic runtime state for rebuilt decompiler output. */\n"
        + definitions
        + "\nvoid aNchkstk(void) {}\nvoid __aNchkstk(void) {}\n"
    )
