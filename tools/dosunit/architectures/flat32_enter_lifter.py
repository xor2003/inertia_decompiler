"""Layer: validation binary frontend.

Responsibility: lift default operand-size i386 ENTER through PyVEX's native
fallback interface, preserving its ordered stack writes and display reads.
The comparison model already requires fault-free flat memory accesses; this
adapter does not model segmentation faults or override-prefixed ENTER forms.
"""

from __future__ import annotations

from pyvex.lifting import lifters, register
from pyvex.lifting.util import GymratLifter, Instruction, Type


class Enter32Instruction(Instruction):  # type: ignore[misc]  # Dynamic third-party PyVEX base.
    """Decode C8 iw ib and emit full 32-bit stack/frame effects without flag writes."""

    name: str = "ENTER32"
    bin_format: str = "11001000llllllllhhhhhhhhnnnnnnnn"

    def compute_result(self, *_operands: object) -> None:
        """Push the old frame and nesting display in architectural memory order.

        Nesting is the low five bits of the immediate. Display loads must see
        preceding pushes when EBP aliases the live stack; materializing every
        load/store in order retains that behavior. Allocation changes ESP only.
        """
        allocation = int(self.data["h"] + self.data["l"], 2)
        nesting = int(self.data["n"], 2) & 0x1F
        word = self.constant(4, Type.int_32)
        old_frame = self.get("ebp", Type.int_32)
        stack = self.get("esp", Type.int_32) - word
        self.store(old_frame, stack)
        self.put(stack, "esp")
        frame = stack
        cursor = old_frame
        if nesting:
            for _level in range(1, nesting):
                cursor = cursor - word
                value = self.load(cursor, Type.int_32)
                stack = stack - word
                self.store(value, stack)
                self.put(stack, "esp")
            stack = stack - word
            self.store(frame, stack)
            self.put(stack, "esp")
        self.put(frame, "ebp")
        self.put(stack - self.constant(allocation, Type.int_32), "esp")


class Flat32EnterLifter(GymratLifter):  # type: ignore[misc]  # Dynamic third-party PyVEX base.
    """Fallback after libVEX; unsupported bytes retain the normal NoDecode result."""

    instrs: tuple[type[Enter32Instruction], ...] = (Enter32Instruction,)


def ensure_flat32_enter_lifter() -> None:
    """Register the fallback once through PyVEX's public extension interface.

    The existing VEX cache identity seals the ordered backend registry and this
    module's bytes. Registration does not replace libVEX or mutate SSA globals.
    """
    if Flat32EnterLifter not in lifters["X86"]:
        register(Flat32EnterLifter, "X86")
