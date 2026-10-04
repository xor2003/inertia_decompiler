"""Quantified stack-word proposals for joint recursive transition proofs.

Layer: dosunit recursive proof invariant proposals (staging).
Responsibility: describe initialized return slots without unrolling call depth.
The slot frontier saturates after stack-offset wrap; it never assumes infinite
stack storage. Every initiation and transition still needs solver discharge.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import z3


@dataclass(frozen=True, slots=True)
class StackWordLayout:
    """Uniform near-call frame proposal with explicit segmented/flat addressing."""

    offset_bits: int
    word_bits: int
    segmented: bool
    continuations: tuple[int, ...]
    component_ranges: tuple[tuple[int, int], ...]

    def __post_init__(self) -> None:
        """Require supported widths and complete nonempty executable boundaries."""
        if self.offset_bits not in {16, 32} or self.word_bits not in {16, 32}:
            raise ValueError("unsupported stack word widths")
        if self.segmented != (self.offset_bits == 16):
            raise ValueError("segmented stack requires 16-bit offsets")
        if not self.continuations or len(set(self.continuations)) != len(self.continuations):
            raise ValueError("continuations must be nonempty and unique")
        if not self.component_ranges or any(not 0 <= start < end <= 1 << 32
                                            for start, end in self.component_ranges):
            raise ValueError("component ranges must be nonempty half-open intervals")
        if any(not any(start <= target < end for start, end in self.component_ranges)
               for target in self.continuations):
            raise ValueError("continuation outside component")

    @property
    def frame_bytes(self) -> int:
        """Physical stack bytes occupied by this proposed near-call frame."""
        return self.word_bits // 8

    @property
    def rank_bits(self) -> int:
        """Number of frame positions in the finite modular offset space."""
        return self.offset_bits - (self.frame_bytes.bit_length() - 1)

    @property
    def capacity(self) -> int:
        """Count of same-alignment slots before the first physical stack wrap."""
        return 1 << self.rank_bits


@dataclass(frozen=True, slots=True)
class StackWordDomain:
    """Ghost frontier, entry frame and complete return-value/address domains."""

    layout: StackWordLayout
    root_offset: z3.BitVecRef
    rank: z3.BitVecRef
    allocated: z3.BitVecRef
    caller_word: z3.BitVecRef
    stack_selector: z3.BitVecRef | None
    code_selector: z3.BitVecRef | None

    @classmethod
    def create(cls, layout: StackWordLayout, *, stack_selector: z3.BitVecRef | None = None,
               code_selector: z3.BitVecRef | None = None) -> StackWordDomain:
        """Create proof-local symbols without replacing machine-state values."""
        if layout.segmented and (stack_selector is None or code_selector is None):
            raise ValueError("segmented frame domain requires SS and CS")
        return cls(layout, z3.BitVec("frame_root_offset", layout.offset_bits),
                   z3.BitVec("frame_rank", layout.rank_bits),
                   z3.BitVec("frame_allocated", layout.rank_bits + 1),
                   z3.BitVec("frame_caller_word", layout.word_bits), stack_selector, code_selector)

    def offset(self, rank: z3.BitVecRef) -> z3.BitVecRef:
        """Relate each ghost rank to its modular architectural stack offset."""
        return self.root_offset - z3.ZeroExt(self.layout.offset_bits - rank.size(), rank) * self.layout.frame_bytes

    def address(self, offset: z3.BitVecRef, byte: int) -> z3.BitVecRef:
        """Wrap each byte within its stack offset space before forming its address."""
        offset = offset + z3.BitVecVal(byte, self.layout.offset_bits)
        linear = z3.ZeroExt(32 - self.layout.offset_bits, offset) if self.layout.offset_bits < 32 else offset
        if self.stack_selector is not None:
            linear = (z3.ZeroExt(16, self.stack_selector) << 4) + linear
        return linear

    def word(self, memory: z3.ArrayRef, rank: z3.BitVecRef) -> z3.BitVecRef:
        """Read every frame byte with segmented wrap and little-endian order."""
        offset = self.offset(rank)
        return cast(z3.BitVecRef, z3.Concat(*[z3.Select(memory, self.address(offset, byte))
                           for byte in reversed(range(self.layout.frame_bytes))]))

    def physical_control(self, word: z3.BitVecRef) -> z3.BitVecRef:
        """Convert a saved architectural offset into its full loaded destination."""
        result = z3.ZeroExt(32 - word.size(), word) if word.size() < 32 else word
        if self.code_selector is not None:
            result = (z3.ZeroExt(16, self.code_selector) << 4) + result
        return result

    def continuation_words(self) -> tuple[z3.BitVecRef, ...]:
        """Derive saved words from physical continuations and the admitted CS."""
        base = z3.BitVecVal(0, 32) if self.code_selector is None else z3.ZeroExt(16, self.code_selector) << 4
        return tuple(cast(z3.BitVecRef, z3.Extract(self.layout.word_bits - 1, 0, z3.BitVecVal(value, 32) - base))
                     for value in self.layout.continuations)

    def bounds(self, rank: z3.BitVecRef, allocated: z3.BitVecRef) -> z3.BoolRef:
        """Keep the rank inside the initialized prefix or saturated whole stack."""
        capacity = z3.BitVecVal(self.layout.capacity, allocated.size())
        conditions = [z3.ULE(allocated, capacity), z3.ULE(z3.ZeroExt(1, rank), allocated)]
        caller = self.physical_control(self.caller_word)
        conditions += [z3.Or(z3.ULT(caller, start), z3.UGE(caller, end))
                       for start, end in self.layout.component_ranges]
        if self.code_selector is not None:
            base = z3.ZeroExt(16, self.code_selector) << 4
            conditions += [z3.And(z3.ULE(base, start), z3.ULE(z3.BitVecVal(end - 1, 32) - base, 0xFFFF))
                           for start, end in self.layout.component_ranges]
        return cast(z3.BoolRef, z3.And(*conditions))

    def invariant(self, memory: z3.ArrayRef, rank: z3.BitVecRef,
                  allocated: z3.BitVecRef) -> z3.BoolRef:
        """Propose valid initialized return words and the unoverwritten entry frame."""
        index = z3.BitVec("frame_quantified_slot", self.layout.rank_bits)
        return z3.ForAll([index], self.local_invariant(memory, rank, allocated, index))

    def local_invariant(self, memory: z3.ArrayRef, rank: z3.BitVecRef,
                        allocated: z3.BitVecRef, index: z3.BitVecRef) -> z3.BoolRef:
        """Expose one arbitrary slot of the universally required invariant.

        Proving this clause for an unconstrained fresh index proves every slot.
        Input instances follow from the universal invariant. A checker that
        assumes only these instances establishes a stronger implication than
        one that assumes every initialized slot at once.
        """
        return cast(z3.BoolRef, z3.And(self.bounds(rank, allocated), self.slot_clause(memory, index, allocated),
                                     self.root_frame_clause(memory, allocated)))

    def root_frame_clause(self, memory: z3.ArrayRef, allocated: z3.BitVecRef) -> z3.BoolRef:
        """Keep the caller frame exact until finite stack wrap overwrites it."""
        full = allocated == z3.BitVecVal(self.layout.capacity, allocated.size())
        root = self.word(memory, z3.BitVecVal(0, self.layout.rank_bits))
        return z3.Implies(z3.Not(full), root == self.caller_word)

    def slot_clause(self, memory: z3.ArrayRef, index: z3.BitVecRef,
                    allocated: z3.BitVecRef) -> z3.BoolRef:
        """Own the universally quantified initialized-slot predicate.

        Concrete instances of this exact predicate follow from the invariant;
        callers may expose them to guide solver instantiation without assuming
        additional initialized words or restricting recursive depth.
        """
        word = self.word(memory, index)
        member = z3.Or(*[word == value for value in self.continuation_words()])
        return z3.Implies(self.initialized_slot(index, allocated), member)

    def initialized_slot(self, index: z3.BitVecRef, allocated: z3.BitVecRef) -> z3.BoolRef:
        """Identify precisely the initialized prefix, including saturated wrap."""
        full = allocated == z3.BitVecVal(self.layout.capacity, allocated.size())
        return cast(z3.BoolRef, z3.Or(full, z3.And(index != 0, z3.ULE(z3.ZeroExt(1, index), allocated))))

    def push_frontier_lemma(self, index: z3.BitVecRef) -> z3.BoolRef:
        """Propose that a PUSH initializes only its new slot beyond the old prefix.

        This is an algebraic proposal, not an assumption. The checker must
        discharge it separately before adding it to array reasoning.
        """
        rank, allocated = self.after_push()
        ordinal_bounds = z3.And(z3.ULE(self.allocated, self.layout.capacity),
                                z3.ULE(z3.ZeroExt(1, self.rank), self.allocated))
        covered = z3.Or(self.initialized_slot(index, self.allocated), index == rank)
        return z3.Implies(ordinal_bounds, z3.Implies(self.initialized_slot(index, allocated), covered))

    def after_push(self) -> tuple[z3.BitVecRef, z3.BitVecRef]:
        """Advance and saturate the frontier, retaining actual modular aliasing."""
        rank = self.rank + 1
        capacity = z3.BitVecVal(self.layout.capacity, self.allocated.size())
        wide_rank = z3.ZeroExt(1, rank)
        allocated = z3.If(z3.Or(self.allocated == capacity, rank == 0), capacity,
                          z3.If(z3.UGT(wide_rank, self.allocated), wide_rank, self.allocated))
        return rank, cast(z3.BitVecRef, allocated)
