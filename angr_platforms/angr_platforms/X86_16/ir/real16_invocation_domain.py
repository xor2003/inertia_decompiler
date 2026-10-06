"""Bind a source-initialized real16 invocation to one exact CS domain.

Layer: IR.
Responsibility: prove the numeric CS selector domain for one exact direct
near CALL under a single typed invocation. The admitted premise shapes are
a source-bound program boot (``BOOT_ENTRY_PATH``) and a chained-callee
premise (``CALL_CHAINED``) that transports the parent's proven
callsite-call register state — captured at the parent's CALL row, after
that instruction's push effects — across one exact bound near-call edge
into the callee head, then reruns the identical census over the callsite
artifact. A link's callee artifact is bound by closed CFG agreement, a
full instruction census, registry identity when registered, and the
authoritative importer re-derivation inside the census — never by claim.
The caller's recompute authority must replay the retained MZ source bytes,
declared environment and header-derived entry until an equal boot object
is produced, then the proven entry CS is traced along the caller
artifact's own typed CFG to the callsite.

A proven domain binds four independent facts:

* the supplied boot is authentic — the caller's recompute authority
  reconstructs an equal boot from the retained MZ bytes, and the retained
  file fingerprint still matches a fresh digest of the source;
* the caller artifact is the project's own registered raw IR for the
  declared function boundary (closed coverage proof, identity-checked
  project);
* every machine instruction that may execute between the program entry
  and the callsite — every block that can reach the callsite block — is
  fetched inside the proven selector's fetch window, carries bytes
  identical to the boot image at the same linear address, never writes
  the CS register, and never crosses a CALL boundary without a complete
  bound preservation proof that retains ``cs``;
* every raw memory store on that path — including the callsite
  instruction's own stack push — is evaluated under the initialized
  invocation state (header CS:IP and SS:SP, the declared PSP segment and
  register file) and is proven disjoint from every fetched instruction
  byte on the path, so no store can rewrite code before it is fetched.
  A store whose physical address cannot be exactly evaluated, a CALL
  boundary whose callee writes cannot be censused, and any unrecognized
  IR effect all refuse explicitly: unknown effects never preserve code
  by omission. Every non-control, non-store effect — whatever its
  destination — is admitted only when the authoritative
  ``scalar_instruction_effects`` classification closes it as a scalar
  destination write; UNKNOWN kinds and memory/IP clobbers refuse as
  ``path_effect_unproven``;
* every simulated IR row is source-bound: each censused block must equal
  the block the authoritative ``vex_import`` importer re-derives from
  the fetched native bytes under the same boundary. The address census
  alone cannot prove effects — an inserted, deleted, reordered, or
  operand-tampered row (including one carrying a copied ``origin`` tag)
  diverges from the re-derived block and refuses
  ``native_effect_unproven``. Binding is exact over *every declared
  field* of every row — including ``compare=False`` capture identities
  such as ``IRValue.source_tmp`` — and runs before any of the block's
  effects materialize; rows of an unbound block are staged as classified
  refusals so the ledger stays closed. Admitted callee artifacts are
  bound the same way before their effects are simulated;
* every block successor leaving that path set stays inside the same
  fetch window, so the lifted linear control flow equals real execution
  under the proven selector.

Path-state fixpoint contract (the loop obligation): the scope head's
entry is the must-meet of the invocation seed *and every in-scope
backedge exit*, not the seed alone. A loop that mutates a proven
register — e.g. repeated ``push ss`` shrinking ``sp`` until a push
overwrites not-yet-fetched CALL bytes — drops the carried constant at
the meet and the affected store refuses as ``store_address_unproven``;
a trip count is never invented. Blocks whose in-scope predecessors have
produced no exit yet wait a round instead of simulating under an
empty-poisoned state; the iteration bound plus the shared work
cap/deadline refuse a census that cannot close.

Register storage is the authoritative lane model from
``semantics.register_value_preservation``: writing ``al``/``ah``/``eax``
invalidates or re-projects every storage-family member (``ax`` cannot
stay a stale constant), and a wider read recomposes from proven sibling
lanes only. Store spans additionally require fetched-byte proof that the
owning machine instruction kept the 16-bit effective-address domain — a
``0x67`` address-size prefix refuses, since the IR offset was truncated
to a word.

The premise retains its unproven inputs as typed ``assumptions``; the
deterministic authority is the independent ``mz_invocation_source_8616``
recompute from the retained MZ bytes, and the caller-supplied
``boot_recompute`` callback is recorded as corroboration only — it can
refuse but can never grant a fact the source does not already prove.

The domain is the proven selector singleton. It is consumed only by
``real16_invocation_discharges_8616``/``Real16CallInvocation8616`` to
discharge the selector-window obligation of the direct near-CALL target
binding; every other production check is untouched, and a premise that is
unneeded (target already inside the default all-fetch-windows bound) is
simply not retained. Absent or insufficient evidence produces a
reason-coded UNKNOWN_REFUSE, never a guessed selector.

The premise is invocation-local: it asserts the CS domain for one entry
→ one callsite under one boot identity — or, for ``CALL_CHAINED``, for
one exact bound call chain under that same boot identity. It never
becomes universal function or callee equality. A chained premise is
conditional on its retained chain: it proves the transported entry state
for the callee head *through the bound edges it names*; entries through
other edges are outside the claim and are recorded as the typed
``CHAINED_CALL_ENTRY`` assumption.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, fields, is_dataclass, replace
from enum import StrEnum
from typing import Protocol, cast

from angr.errors import AngrError
from capstone import CsError
from pyvex.errors import PyVEXError

from ...real16_resize_response8616 import (
    ResizeRefusal8616,
    resize_response_8616,
)
from ..frontend_block_inventory import decoded_block_instructions_8616
from ..frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
)
from ..frontend_function_boundary import ExactFunctionRangeBoundary8616
from ..mz_invocation_source import (
    MzInvocationSource8616,
    mz_invocation_source_8616,
)
from ..mz_static_boot import MzStaticBoot8616
from ..semantics.register_value_preservation import (
    register_value_family_8616,
    register_value_projection_8616,
)
from .core import (
    IRActiveUnary8616,
    IRAddress,
    IRBinaryValue,
    IRBlock,
    IRCallOutputProvenance8616,
    IRCallStackEffect8616,
    IRCondition,
    IRFunctionArtifact,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
)
from .instruction_origin import IRInstructionOrigin8616
from .ir_boundary_cfg import (
    IRBoundaryCoverageResult8616,
    _instruction_census_matches_8616,
    closed_ir_boundary_cfg_8616,
)
from .real16_declared_interrupt8616 import (
    DeclaredInterruptRefusal8616,
    DeclaredInterruptService8616,
    DeclaredResizeConsumption8616,
    DeclaredResizeSurface8616,
    DeclaredServiceConsumption8616,
    declared_environment_digest_8616,
    declared_resize_consumption_8616,
    declared_service_arena_8616,
    declared_service_consumption_8616,
    interrupt_call_vector_8616,
    service_relation_for_8616,
)
from .real16_edge_feasibility8616 import (
    DirectionTracker8616,
    Real16EdgeFeasibility8616,
    invocation_feasible_scope_8616,
)
from .real16_initial_memory8616 import InvocationInitialMemory8616, invocation_initial_memory_8616
from .real16_path_memory8616 import (
    SEGMENT_BASE_NAME_8616,
    PathMemory8616,
    PathMemorySnapshot8616,
    meet_path_memory_8616,
    path_load_value_8616,
    path_memory_initial_8616,
    path_memory_tainted_8616,
    restore_path_memory_8616,
    snapshot_path_memory_8616,
    store_atom_clean_8616,
)
from .real16_repeated_store8616 import (
    RepeatedStoreStatus8616,
    native_repeated_store_8616,
    repeated_store_effect_8616,
)
from .real16_wide_multiply8616 import wide_multiply_value_8616
from .scalar_instruction_effects import (
    ScalarInstructionClobber8616,
    ScalarInstructionEffectKind8616,
    scalar_instruction_effect_8616,
)
from .segment_call_preservation import SegmentCallPreservationResult8616
from .segment_effect_closure import SegmentEffectClosureResult8616
from .segment_state_transfer import call_preservation_at_instruction_8616
from .ssa_function import build_x86_16_ir_predecessor_map

__all__ = [
    "Real16CallChainLink8616",
    "Real16CallInvocation8616",
    "Real16EnclosedEntryLink8616",
    "Real16InvocationAssumption8616",
    "Real16InvocationDomain8616",
    "Real16InvocationFailure8616",
    "Real16InvocationKind8616",
    "Real16InvocationRefusalSite8616",
    "prove_real16_chained_invocation_domain_8616",
    "prove_real16_enclosed_invocation_domain_8616",
    "prove_real16_invocation_domain_8616",
    "real16_invocation_discharges_8616",
    "real16_native_census_import_8616",
]

_WORD_LIMIT_8616 = 0xFFFF
_FULL_WORD_LIMIT_8616 = 0xFFFFFFFF
_SEGMENT_SHIFT_8616 = 4
# Shared absolute census budget: the fixpoint iteration cap alone does not
# bound decode calls, per-row evaluation, or callee replay. Every census
# loop consumes ``work_units`` against this cap and ``time.monotonic``
# against one deadline started when the proof begins; exceeding either
# refuses as ``census_work_exceeded``/``census_deadline_exceeded``.
_CENSUS_WORK_LIMIT_8616 = 20000
_CENSUS_DEADLINE_SECONDS_8616 = 20.0
# x86 legacy prefix opcodes that may precede a real-mode opcode byte. A
# 0x67 byte anywhere in this run selects 32-bit effective addressing for
# that instruction; the IR address offsets it produces are no longer the
# 16-bit domain this domain models.
_LEGACY_PREFIX_BYTES_8616: frozenset[int] = frozenset(
    {0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3}
)
# Named decode-boundary failure types only: the frontend decode owner
# caches and re-raises whatever the VEX/Capstone/angr lift produced.
# RuntimeError/TypeError/IndexError/KeyError are deliberately absent —
# catching them here would mask census defects (AGENTS.md loud
# exceptions); anything outside the named boundary propagates.
_DECODE_REFUSAL_TYPES_8616: tuple[type[Exception], ...] = (
    AngrError,
    PyVEXError,
    CsError,
    ArithmeticError,
    ValueError,
)
# Declared 32-bit environment registers and the 16-bit GP lanes they seed.
# ``esp`` is absent: the authoritative header SP supersedes it at boot.
_ENVIRONMENT_WORD_REGISTERS_8616: tuple[tuple[str, str], ...] = (
    ("eax", "ax"),
    ("ebx", "bx"),
    ("ecx", "cx"),
    ("edx", "dx"),
    ("esi", "si"),
    ("edi", "di"),
    ("ebp", "bp"),
)
# Chaotic-iteration bound for the path-state fixpoint. Entries only lose
# proven constants under join, so convergence is fast; the bound exists so
# a malformed census can never loop.
_PATH_STATE_ITERATION_LIMIT_8616 = 64
# Recursive parent-replay bound for chained premises. A retained chain
# re-derives its parent in full, so a cyclic or runaway chain must refuse
# at a fixed depth rather than recursing unboundedly.
_CHAIN_DEPTH_LIMIT_8616 = 16
# The effective-address segment bases this census resolves: owned by
# ``real16_path_memory8616`` so the concrete evaluator and the known-bits
# feasibility interpreter resolve spans identically.
_SEGMENT_BASE_NAME_8616 = SEGMENT_BASE_NAME_8616


class Real16InvocationFailure8616(StrEnum):
    """Typed refusal reasons for source-bound invocation-domain proofs."""

    BOOT_UNBOUND = "boot_unbound"
    BOOT_MALFORMED = "boot_malformed"
    BOOT_NOT_REPRODUCED = "boot_not_reproduced"
    COVERAGE_UNBOUND = "coverage_unbound"
    PROJECT_MISMATCH = "project_mismatch"
    ENTRY_NOT_FUNCTION_HEAD = "entry_not_function_head"
    CALLSITE_UNREACHABLE = "callsite_unreachable"
    CALLSITE_UNBOUND = "callsite_unbound"
    CALLSITE_AMBIGUOUS = "callsite_ambiguous"
    PATH_DECODE_MISMATCH = "path_decode_mismatch"
    FETCH_WINDOW_VIOLATION = "fetch_window_violation"
    CODE_SCOPE_VIOLATION = "code_scope_violation"
    NATIVE_BYTES_MISMATCH = "native_bytes_mismatch"
    CS_PATH_UNPROVEN = "cs_path_unproven"
    CALL_BOUNDARY_UNPROVEN = "call_boundary_unproven"
    STORE_ADDRESS_UNPROVEN = "store_address_unproven"
    CODE_WRITE_VIOLATION = "code_write_violation"
    NATIVE_EFFECT_UNPROVEN = "native_effect_unproven"
    PATH_EFFECT_UNPROVEN = "path_effect_unproven"
    CALLEE_WRITE_UNPROVEN = "callee_write_unproven"
    CHAIN_LINK_UNPROVEN = "chain_link_unproven"
    ENCLOSED_LINK_UNPROVEN = "enclosed_link_unproven"
    DECLARED_SERVICE_UNPROVEN = "declared_service_unproven"
    CENSUS_WORK_EXCEEDED = "census_work_exceeded"
    CENSUS_DEADLINE_EXCEEDED = "census_deadline_exceeded"


class Real16InvocationAssumption8616(StrEnum):
    """Inputs a proven premise consumed but could not itself prove.

    These are retained, not hidden: a consumer must see exactly which
    facts came from the deterministic MZ-source recompute and which were
    declared by the caller or the boot object.
    """

    #: Entry CS:IP projected from the retained MZ header by
    #: ``mz_invocation_source_8616``; authoritative, not caller-supplied.
    MZ_HEADER_ENTRY = "mz_header_entry"
    #: Initial SS:SP projected from the same retained MZ header.
    MZ_HEADER_STACK = "mz_header_stack"
    #: A static-header input carries no declared environment: the seed
    #: contains only the header CS:IP/SS:SP, every other register stays
    #: unknown, and path effects depending on unknown state must refuse.
    STATIC_HEADER_STATE = "static_header_state"
    #: DS/ES seeded from the caller-declared PSP segment and the 16-bit GP
    #: lanes seeded from the declared 32-bit environment register file;
    #: the environment is a declared loader contract, not binary evidence.
    DECLARED_ENVIRONMENT = "declared_environment"
    #: Fetched instructions are required to sit inside the boot's declared
    #: ``code_ranges``; that scope is a boot declaration, not a recovered
    #: guarantee about the rest of the image.
    DECLARED_CODE_SCOPE = "declared_code_scope"
    #: The caller's ``boot_recompute`` callback had to reproduce an equal
    #: boot object; it corroborates but is never the authority, which is
    #: the deterministic ``mz_invocation_source_8616`` recompute.
    REPLAY_CORROBORATION = "replay_corroboration"
    #: A ``CALL_CHAINED`` premise transports the proven call-row state
    #: across one exact bound near-call edge. That transported entry is
    #: conditional on the recorded edge: other edges into the same callee
    #: head are outside this premise's claim and are not censused.
    CHAINED_CALL_ENTRY = "chained_call_entry"
    #: An ``ENCLOSED_ENTRY`` premise transports the proven call-row state
    #: across one exact bound near-call edge into an *enclosing* entry
    #: whose own closed boundary contains the callee head, then the path
    #: census proves the fallthrough from that entry to the enclosed head.
    #: Entries into the enclosed head through edges outside the retained
    #: enclosing boundary are outside this premise's claim.
    ENCLOSED_ENTRY = "enclosed_entry"
    #: The census crossed at least one interrupt-service boundary under an
    #: explicitly declared, environment-bound relation
    #: (``DeclaredInterruptService8616``). Every consumed relation is
    #: retained on the domain's ``service_consumptions`` and replays
    #: identically; the declaration is conditional caller evidence, never
    #: a proven universal DOS model.
    DECLARED_INTERRUPT_SERVICE = "declared_interrupt_service"


_BOOT_ENTRY_ASSUMPTIONS_8616: tuple[Real16InvocationAssumption8616, ...] = (
    Real16InvocationAssumption8616.MZ_HEADER_ENTRY,
    Real16InvocationAssumption8616.MZ_HEADER_STACK,
    Real16InvocationAssumption8616.DECLARED_ENVIRONMENT,
    Real16InvocationAssumption8616.DECLARED_CODE_SCOPE,
    Real16InvocationAssumption8616.REPLAY_CORROBORATION,
)


_STATIC_ENTRY_ASSUMPTIONS_8616: tuple[Real16InvocationAssumption8616, ...] = (
    Real16InvocationAssumption8616.MZ_HEADER_ENTRY,
    Real16InvocationAssumption8616.MZ_HEADER_STACK,
    Real16InvocationAssumption8616.STATIC_HEADER_STATE,
    Real16InvocationAssumption8616.DECLARED_CODE_SCOPE,
    Real16InvocationAssumption8616.REPLAY_CORROBORATION,
)


class Real16InvocationKind8616(StrEnum):
    """The admitted premise shapes.

    ``BOOT_ENTRY_PATH``: the proven selector starts at the source-bound
    program entry and holds along every raw instruction path to the
    callsite. ``CALL_CHAINED``: the proven entry state is transported
    across an explicit chain of bound near-call edges — each edge's parent
    premise, decoded callsite entry, and raw physical target re-validated
    — then the identical path census proves the selector along every raw
    instruction path from the callee head to the callsite.
    ``ENCLOSED_ENTRY``: the decoded near-call edge lands on an enclosing
    entry — not the callee head — whose own closed boundary provably
    contains the whole callee artifact; the census then proves the
    selector from the enclosing head along every raw instruction path
    through that fallthrough to the callsite.
    """

    BOOT_ENTRY_PATH = "boot_entry_path"
    CALL_CHAINED = "call_chained"
    ENCLOSED_ENTRY = "enclosed_entry"


class _BootEntrySurface8616(Protocol):
    """Typed entry/stack contract consumed from the boot authority."""

    @property
    def segment(self) -> int:
        """Read the source-authenticated segment without mutating the boot."""
        ...

    @property
    def offset(self) -> int:
        """Read the source-authenticated offset without mutating the boot."""
        ...

    def linear(self) -> int:
        """Return the entry linear address."""
        ...


class _BootRangeSurface8616(Protocol):
    """Typed code-range contract consumed from the boot authority."""

    def contains(self, address: int, size: int = 1) -> bool:
        """Return whether [address, address + size) is declared code."""
        ...


class _BootImageSurface8616(Protocol):
    """Typed loaded-image contract consumed from the boot authority."""

    @property
    def chunks(self) -> tuple[tuple[int, bytes], ...]:
        """Read the retained relocated load-module chunks."""
        ...

    @property
    def code_ranges(self) -> tuple[_BootRangeSurface8616, ...]:
        """Read the declared fetch ranges through their containment contract."""
        ...

    @property
    def load_segment(self) -> int:
        """Read the paragraph used to relocate the retained module."""
        ...

    @property
    def file_sha256(self) -> str:
        """Read the retained MZ source identity."""
        ...

    @property
    def image_sha256(self) -> str:
        """Read the relocated image identity."""
        ...

    @property
    def reloc_sha256(self) -> str:
        """Read the source relocation-table identity."""
        ...

    @property
    def code_scope(self) -> str:
        """Read how the declared fetch ranges were selected."""
        ...


class _BootEnvironmentSurface8616(Protocol):
    """Declared environment fields consumed for the invocation seed.

    The production owner ``tools.dosunit.real16_program_boot`` documents
    DS/ES as loader-owned by the PSP and the 32-bit register file as
    caller-declared; only those typed fields seed the path simulation.
    """

    psp_segment: int
    registers: tuple[tuple[str, int], ...]
    fs: int
    gs: int


class _BootSurface8616(Protocol):
    """Typed boot contract consumed from the caller's MZ authority.

    The production owner is ``tools.dosunit.real16_program_boot``; this
    Protocol keeps the IR layer backend-neutral: any object that presents
    source bytes, a typed entry/stack, a typed image surface, an
    environment and a boot digest may stand in, but the caller's recompute
    authority decides what "authentic" means.
    """

    source: bytes
    entry: _BootEntrySurface8616
    stack: _BootEntrySurface8616
    image: _BootImageSurface8616
    environment: _BootEnvironmentSurface8616
    boot_sha256: str


class _DecodedInstructionSurface8616(Protocol):
    """Typed fields of decoded instructions consumed for byte binding."""

    address: int
    size: int


@dataclass(frozen=True, slots=True)
class _BootEvidence8616:
    """Normalized typed boot surface extracted for derivation."""

    source: bytes
    entry_segment: int
    entry_offset: int
    entry_linear: int
    stack_segment: int
    stack_offset: int
    load_segment: int
    image: _BootImageSurface8616
    boot_sha256: str
    register_seed: tuple[tuple[str, int], ...]
    entry_assumptions: tuple[Real16InvocationAssumption8616, ...]
    environment_digest: str | None
    #: The declared environment object itself — the census re-derives the
    #: canonical service surface from it at every consumption, never
    #: trusting the presented relation's effect fields.
    environment: object | None
    #: Declared allocation ``[start, end)``; a DOS entry inside it is a
    #: program-owned handler, not an external declared service.
    arena: tuple[int, int] | None


@dataclass(frozen=True, slots=True)
class _DerivedDomain8616:
    """The recomputed product of one successful derivation."""

    minimum_selector: int
    maximum_selector: int
    entry_segment: int
    entry_offset: int
    stack_segment: int
    stack_offset: int
    load_segment: int
    source_sha256: str
    path_block_addrs: tuple[int, ...]
    fetched_range_count: int
    checked_store_count: int
    assumptions: tuple[Real16InvocationAssumption8616, ...]
    callsite_artifact: IRFunctionArtifact | None
    callsite_boundary: ExactFunctionRangeBoundary8616 | None
    callsite_call_state: tuple[tuple[str, int], ...]
    #: The callsite-row memory overlay's frozen image — the identical
    #: bytes the transported register state was proven under, so a
    #: chained or enclosed seed consumes the same memory, never a
    #: silently reset initial image. ``None`` when the census never
    #: reached its callsite row.
    callsite_memory: PathMemorySnapshot8616 | None
    service_consumptions: tuple[
        DeclaredServiceConsumption8616 | DeclaredResizeConsumption8616, ...
    ]
    #: ``(block_addr, successor_addr)`` edges proven untraversable by the
    #: invocation-local known-bits feasibility pass; empty when nothing
    #: was proven dead.
    infeasible_edges: tuple[tuple[int, int], ...] = ()


class _DecodedNativeInstruction8616(Protocol):
    """Third-party decoded instruction carrying native byte evidence."""

    address: int
    size: int
    bytes: bytes


class _CensusImportGuard8616(Protocol):
    """Project-owned depth marker for census re-derivation imports.

    While nonzero, importer re-entry for byte binding must not rerun
    callsite evidence collection: the census compares the in-flight
    artifact's *pre-discharge* blocks against a freshly imported copy, so
    the re-derived artifact must carry the identical pending refusals and
    must not recurse into premise construction.
    """

    _inertia_real16_native_census_8616: int


@dataclass(frozen=True, slots=True)
class Real16InvocationRefusalSite8616:
    """The exact classified census row that first returned a typed failure.

    ``function_addr`` is the censused artifact's head — which may be a
    nested replay's parent surface, never relabeled as the consuming
    callsite — ``block_addr`` the IR block the row belongs to, and
    ``instruction_addr`` the instruction's own machine address. The site
    is recorded only when an actual instruction-level census row is
    classified and refused; structural, binding, and budget refusals that
    never reach a row keep ``None`` on the derivation.
    """

    function_addr: int
    block_addr: int
    instruction_addr: int


@dataclass(frozen=True, slots=True)
class _NestedRefusal8616:
    """A link-seed refusal carrying the nested derivation's real row site.

    A chained or enclosed parent replay that refuses at a classified
    census row keeps that exact site so the outer derivation reports the
    failing instruction instead of a bare ``*_LINK_UNPROVEN`` with the
    location erased.
    """

    failure: Real16InvocationFailure8616
    refusal_site: Real16InvocationRefusalSite8616 | None


@dataclass(frozen=True, slots=True)
class _Derivation8616:
    """One derivation attempt: the domain, the refusal, and real counts.

    The five stage counts are the actual census — real instruction rows
    seen, normalized, classified, materialized, refused — so a refusal
    still reports how far the bounded census progressed. ``refusal_site``
    names the first classified row that failed; it stays ``None`` for
    pre-census refusals that never observed an instruction row.
    """

    domain: _DerivedDomain8616 | None
    failure: Real16InvocationFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    refusal_site: Real16InvocationRefusalSite8616 | None = None
    #: Edges the invocation-local feasibility pass proved untraversable
    #: before the refusal; diagnostic evidence, never universal.
    infeasible_edges: tuple[tuple[int, int], ...] = ()


def _early_derivation_8616(
    failure: Real16InvocationFailure8616,
    *,
    refusal_site: Real16InvocationRefusalSite8616 | None = None,
) -> _Derivation8616:
    """Return a refused derivation before any census row was observed.

    ``failure_count`` is the classified-row refusal ledger: a pre-census
    refusal classified no rows, so it reports ``0`` — the typed
    ``failure`` field carries the refusal itself and
    ``classified == materialized + failure`` stays closed. A nested
    replay may still supply a real ``refusal_site`` its own census
    recorded; refusals with no classified row keep ``None``.
    """
    return _Derivation8616(
        domain=None,
        failure=failure,
        raw_fact_count=0,
        normalized_fact_count=0,
        classified_fact_count=0,
        materialized_count=0,
        failure_count=0,
        refusal_site=refusal_site,
    )


def _normalize_instruction_8616(instruction: object) -> tuple[int, int] | None:
    """Return (address, size) for one decoded instruction or ``None``."""
    try:
        boundary = cast(_DecodedInstructionSurface8616, instruction)
        address, size = boundary.address, boundary.size
    except AttributeError:
        return None
    if type(address) is not int or type(size) is not int or size <= 0:
        return None
    return address, size


def _image_slice_8616(image: _BootImageSurface8616, addr: int, size: int) -> bytes | None:
    """Return the exact image bytes at ``[addr, addr+size)`` or ``None``."""
    for base, data in image.chunks:
        if type(base) is not int or not isinstance(data, bytes | bytearray):
            continue
        if base <= addr and addr + size <= base + len(data):
            return bytes(data[addr - base : addr - base + size])
    return None


def _instruction_bytes_8616(instruction: object) -> bytes | None:
    """Read bytes across the dynamic angr/Capstone instruction boundary."""
    try:
        # Third-party Capstone and angr wrappers expose bytes at different
        # depths; dynamic lookup is confined to that external boundary.
        raw = getattr(instruction, "bytes", None)
        if raw is None:
            insn = getattr(instruction, "insn", None)
            raw = getattr(insn, "bytes", None)
        if raw is None:
            return None
        return bytes(raw)
    except (AttributeError, TypeError, ValueError):
        return None


def _writes_segment_register_8616(instruction: IRInstr, register: str) -> bool:
    """Return whether the instruction directly writes ``register``."""
    dst = instruction.dst
    return (
        isinstance(dst, IRValue)
        and dst.space == MemSpace.REG
        and dst.name == register
    )


def _word_8616(value: object) -> bool:
    """Return whether ``value`` is an exact 16-bit word."""
    return type(value) is int and 0 <= value <= _WORD_LIMIT_8616


def _environment_seed_8616(environment: object) -> tuple[tuple[str, int], ...] | None:
    """Validate the declared environment into a 16-bit register seed.

    Only documented loader-owned or caller-declared fields are consumed:
    the PSP segment seeds DS and ES (the production replay owner seeds them
    identically), and the declared 32-bit register file seeds the 16-bit GP
    lanes. ``esp``/``eflags`` are not seeded: header SS:SP and CS:IP stay
    authoritative. Anything but an exact typed declaration is malformed.
    """
    try:
        boundary = cast(_BootEnvironmentSurface8616, environment)
        psp_segment = boundary.psp_segment
        registers = boundary.registers
        fs = boundary.fs
        gs = boundary.gs
    except AttributeError:
        return None
    if not isinstance(registers, tuple):
        return None
    if not all(_word_8616(value) for value in (psp_segment, fs, gs)):
        return None
    seed: dict[str, int] = {"ds": psp_segment, "es": psp_segment}
    for pair in registers:
        if not isinstance(pair, tuple) or len(pair) != 2:
            return None
        name, value = pair
        if (
            type(name) is not str
            or type(value) is not int
            or not 0 <= value <= _FULL_WORD_LIMIT_8616
        ):
            return None
        lane = dict(_ENVIRONMENT_WORD_REGISTERS_8616).get(name)
        if lane is not None:
            seed[lane] = value & _WORD_LIMIT_8616
    _environment_byte_fanout_8616(seed)
    return tuple(sorted(seed.items()))


def _environment_byte_fanout_8616(seed: dict[str, int]) -> None:
    """Fan each declared 16-bit lane into its contained byte lanes.

    The declaration is a complete constant, so ``al``/``ah`` projections are
    pure evidence, not inference. Without them a proven ``mov ah,imm`` would
    leave the declared AL unprovable at a later boundary.
    """
    for lane_name, lane_value in tuple(seed.items()):
        if lane_name in ("ds", "es"):
            continue
        for member in register_value_family_8616(lane_name):
            projection = register_value_projection_8616(lane_name, member)
            if projection is None or member in seed:
                continue
            shift, bits = projection
            seed[member] = (lane_value >> shift) & ((1 << bits) - 1)


def _boot_point_valid_8616(point: object) -> bool:
    """Return whether one typed entry/stack coordinate is self-consistent."""
    if point is None:
        return False
    try:
        boundary = cast(_BootEntrySurface8616, point)
        segment = boundary.segment
        offset = boundary.offset
        linear = boundary.linear()
    except (AttributeError, TypeError, ValueError):
        return False
    return (
        _word_8616(segment)
        and _word_8616(offset)
        and type(linear) is int
        and linear == (segment << _SEGMENT_SHIFT_8616) + offset
    )


def _boot_image_valid_8616(image: object) -> bool:
    """Return whether the declared image surface has typed evidence fields."""
    try:
        boundary = cast(_BootImageSurface8616, image)
        chunks = boundary.chunks
        code_ranges = boundary.code_ranges
        load_segment = boundary.load_segment
        file_sha256 = boundary.file_sha256
        image_sha256 = boundary.image_sha256
        reloc_sha256 = boundary.reloc_sha256
    except (AttributeError, TypeError):
        return False
    if not _word_8616(load_segment):
        return False
    if not all(
        isinstance(digest, str)
        for digest in (file_sha256, image_sha256, reloc_sha256)
    ):
        return False
    if not isinstance(chunks, tuple) or not isinstance(code_ranges, tuple):
        return False
    return bool(chunks) and all(
        type(base) is int and isinstance(data, bytes | bytearray)
        for base, data in chunks
    )


def _boot_fields_reproduced_8616(
    entry: _BootEntrySurface8616,
    stack: _BootEntrySurface8616,
    image: _BootImageSurface8616,
    derived: MzInvocationSource8616,
) -> bool:
    """Return whether declared boot fields equal the source-derived ones."""
    points_match = (
        entry.segment == derived.entry_segment
        and entry.offset == derived.entry_offset
        and stack.segment == derived.stack_segment
        and stack.offset == derived.stack_offset
    )
    image_match = (
        image.chunks == ((derived.module_base, derived.module),)
        and image.file_sha256 == derived.file_sha256
    )
    return points_match and image_match


def _boot_evidence_8616(boot: object) -> _BootEvidence8616 | Real16InvocationFailure8616:
    """Extract and validate the normalized boot surface.

    Header and module authentication derive independently from retained MZ
    bytes through the shared Frontend owner. Caller callbacks cannot grant
    an invented selector or relocated image.
    """
    if boot is None:
        return Real16InvocationFailure8616.BOOT_UNBOUND
    try:
        boundary = cast(_BootSurface8616, boot)
        source = boundary.source
        entry = boundary.entry
        stack = boundary.stack
        image = boundary.image
        environment = boundary.environment
        digest = boundary.boot_sha256
    except AttributeError:
        return Real16InvocationFailure8616.BOOT_MALFORMED
    if not isinstance(source, bytes | bytearray) or not source:
        return Real16InvocationFailure8616.BOOT_MALFORMED
    if environment is None or not isinstance(digest, str) or not digest:
        return Real16InvocationFailure8616.BOOT_MALFORMED
    register_seed = _environment_seed_8616(environment)
    if register_seed is None:
        return Real16InvocationFailure8616.BOOT_MALFORMED
    if not _boot_point_valid_8616(entry) or not _boot_point_valid_8616(stack):
        return Real16InvocationFailure8616.BOOT_MALFORMED
    if not _boot_image_valid_8616(image):
        return Real16InvocationFailure8616.BOOT_MALFORMED
    try:
        derived = mz_invocation_source_8616(bytes(source), image.load_segment)
    except (TypeError, ValueError):
        return Real16InvocationFailure8616.BOOT_NOT_REPRODUCED
    if not _boot_fields_reproduced_8616(entry, stack, image, derived):
        return Real16InvocationFailure8616.BOOT_NOT_REPRODUCED
    return _BootEvidence8616(
        source=bytes(source),
        entry_segment=entry.segment,
        entry_offset=entry.offset,
        entry_linear=entry.linear(),
        stack_segment=stack.segment,
        stack_offset=stack.offset,
        load_segment=image.load_segment,
        image=image,
        boot_sha256=digest,
        register_seed=register_seed,
        entry_assumptions=_BOOT_ENTRY_ASSUMPTIONS_8616,
        environment_digest=declared_environment_digest_8616(environment),
        environment=environment,
        arena=declared_service_arena_8616(environment),
    )


def _static_boot_evidence_8616(
    boot: MzStaticBoot8616,
) -> _BootEvidence8616 | Real16InvocationFailure8616:
    """Extract the source-authenticated surface of one static-header input.

    The input authenticates the identical entry/stack/module/fingerprint
    fields as a declared boot — entry and stack linear must re-derive from
    retained source bytes and the claimed load paragraph, every relocated
    module word must match, and the digests must bind — but carries no
    environment. The register seed therefore contains only the header CS/SS/
    SP lanes; every other register stays unknown so effects depending on it
    refuse downstream. ``entry_assumptions`` records that distinction: the
    premise declares ``STATIC_HEADER_STATE`` rather than
    ``DECLARED_ENVIRONMENT``.
    """
    if type(boot) is not MzStaticBoot8616:
        return Real16InvocationFailure8616.BOOT_UNBOUND
    source = boot.source
    digest = boot.boot_sha256
    if type(source) is not bytes or not source:
        return Real16InvocationFailure8616.BOOT_MALFORMED
    if type(digest) is not str or not digest:
        return Real16InvocationFailure8616.BOOT_MALFORMED
    entry = boot.entry
    stack = boot.stack
    image = boot.image
    if not _boot_point_valid_8616(entry) or not _boot_point_valid_8616(stack):
        return Real16InvocationFailure8616.BOOT_MALFORMED
    if not _boot_image_valid_8616(image):
        return Real16InvocationFailure8616.BOOT_MALFORMED
    try:
        derived = mz_invocation_source_8616(bytes(source), image.load_segment)
    except (TypeError, ValueError):
        return Real16InvocationFailure8616.BOOT_NOT_REPRODUCED
    if not _boot_fields_reproduced_8616(entry, stack, image, derived):
        return Real16InvocationFailure8616.BOOT_NOT_REPRODUCED
    return _BootEvidence8616(
        source=bytes(source),
        entry_segment=entry.segment,
        entry_offset=entry.offset,
        entry_linear=entry.linear(),
        stack_segment=stack.segment,
        stack_offset=stack.offset,
        load_segment=image.load_segment,
        image=image,
        boot_sha256=digest,
        register_seed=(
            ("cs", entry.segment),
            ("ss", stack.segment),
            ("sp", stack.offset),
        ),
        entry_assumptions=_STATIC_ENTRY_ASSUMPTIONS_8616,
        environment_digest=None,
        environment=None,
        arena=None,
    )


def _invocation_boot_evidence_8616(
    boot: object,
) -> _BootEvidence8616 | Real16InvocationFailure8616:
    """Extract normalized boot evidence through the typed input's surface.

    Declared ``ProgramBoot`` objects authenticate environment lanes through
    ``_boot_evidence_8616``; static-header ``MzStaticBoot8616`` inputs go
    through the header-only surface. Either path refuses rather than guess:
    a malformed or unreproduced field is a typed failure, never a default.
    """
    if type(boot) is MzStaticBoot8616:
        return _static_boot_evidence_8616(boot)
    return _boot_evidence_8616(boot)


def _recompute_boot_8616(
    boot: object,
    boot_recompute: Callable[[object], object] | None,
) -> Real16InvocationFailure8616 | None:
    """Require source-derived fields before any supplementary callback replay."""
    source_evidence = _invocation_boot_evidence_8616(boot)
    if isinstance(source_evidence, Real16InvocationFailure8616):
        return source_evidence
    if boot_recompute is None or not callable(boot_recompute):
        return Real16InvocationFailure8616.BOOT_UNBOUND
    try:
        recomputed = boot_recompute(boot)
    except (ValueError, TypeError, KeyError, AttributeError):
        return Real16InvocationFailure8616.BOOT_NOT_REPRODUCED
    if type(recomputed) is not type(boot) or recomputed != boot:
        return Real16InvocationFailure8616.BOOT_NOT_REPRODUCED
    return None


def _callsite_block_8616(
    artifact: IRFunctionArtifact,
    callsite_addr: int,
) -> IRBlock | Real16InvocationFailure8616:
    """Return the unique artifact block containing the callsite."""
    owners = [
        block
        for block in artifact.blocks
        if any(instruction.addr == callsite_addr for instruction in block.instrs)
    ]
    if not owners:
        return Real16InvocationFailure8616.CALLSITE_UNBOUND
    if len(owners) != 1:
        return Real16InvocationFailure8616.CALLSITE_AMBIGUOUS
    return owners[0]


def _dangerous_block_addrs_8616(
    artifact: IRFunctionArtifact, call_block: IRBlock
) -> frozenset[int]:
    """Return the set of blocks that can reach the callsite block."""
    predecessor_map = build_x86_16_ir_predecessor_map(artifact)
    pending = [call_block.addr]
    reached = {call_block.addr}
    while pending:
        addr = pending.pop()
        for predecessor in predecessor_map.get(addr, ()):
            if predecessor not in reached:
                reached.add(predecessor)
                pending.append(predecessor)
    return frozenset(reached)


@dataclass(slots=True)
class _PathCensusContext8616:
    """Shared authority for one root-to-callsite raw-effect census.

    ``manifest`` accumulates every proved fetched instruction byte range
    (call path plus every admitted leaf callee) before and during effect
    simulation, so each STORE is checked against *all* bytes that may be
    fetched — including bytes fetched after the store executes.
    ``machine_bytes`` retains each censused instruction's fetched bytes so
    a store can prove its effective-address domain (``0x67`` address-size
    overrides refuse). ``callsite_addr``/``stop_block_addr`` are rebound
    for callee scopes. ``callsite_call_state`` captures the exact register
    state the callsite CALL row executes under — after that instruction's
    own push rows — so a ``CALL_CHAINED`` consumer can transport it as the
    callee head's entry state; it stays ``None`` when the callsite is not
    a CALL row.

    ``entry_call_preservations`` carries in-flight caller callsite records
    (``EntryDomainCallPreservation8616``) alongside the registry-bound
    ``call_preservations`` pool: the callsite artifact of a
    ``CALL_CHAINED`` premise may be unregistered, so its interior calls
    cannot carry coverage-bound proofs. Both pools bind the identical
    artifact/block/instruction objects and revalidate at consumption.

    Memory writes are *not* kept on this context: they are path facts,
    carried inside each ``_PathState8616``'s ``PathMemory8616`` overlay
    and must-met per predecessor by ``_simulate_scope_8616`` — census
    visitation order is never memory execution order. The union-of-spans
    IVT/code guards are answered path-sensitively by the overlay itself
    (any possibly-written byte revokes), which is strictly more precise
    and no less conservative.

    The five counter sets key real instruction rows by
    ``(block_addr, instr_index)`` — rows seen, normalized, classified,
    materialized, refused — so reported census counts are the actual
    staged evidence, not one aggregate fact. The ledger is closed:
    ``failures`` counts exactly the rows that reached classification and
    were refused, so ``classified == materialized + failures`` holds on
    every path. Census-level refusals that never classified a row —
    decode/byte binding, importer re-derivation, budget and deadline
    exhaustion — return their typed failure without inflating the row
    ledger. ``work_units``/``deadline`` bound every census loop;
    exceeding either refuses with a typed failure rather than claiming
    exhaustion as coverage.

    ``native_blocks`` maps each censused artifact's ``function_addr`` to
    the block map the authoritative ``vex_import`` importer re-derives
    from the fetched native bytes under that artifact's own boundary.
    A block's simulated effects count only when the artifact block
    exactly equals the re-derived one; the registry is never consulted,
    so a published artifact cannot borrow native identity.
    """

    project: object
    selector: int
    image: _BootImageSurface8616
    boot: object
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | None
    call_preservations: tuple[SegmentCallPreservationResult8616, ...]
    entry_call_preservations: tuple[object, ...]
    declared_services: tuple[DeclaredInterruptService8616, ...]
    environment_digest: str | None
    #: The boot's declared environment object — the consumption re-derives
    #: the canonical service surface from it, so a relation whose effect
    #: fields were replaced under an unchanged digest still refuses.
    environment: object | None
    #: Declared allocation ``[start, end)`` for program-owned-handler checks.
    arena: tuple[int, int] | None
    service_consumptions: list[
        DeclaredServiceConsumption8616 | DeclaredResizeConsumption8616
    ]
    stop_block_addr: int | None
    callsite_addr: int | None
    callsite_call_state: dict[str, int] | None
    #: The callsite-row memory overlay captured beside
    #: ``callsite_call_state`` — the callee's exact entry memory, so a
    #: transported premise's seed carries the same bytes the register
    #: state was proven under.
    callsite_memory: PathMemory8616 | None
    manifest: list[tuple[int, int]]
    machine_bytes: dict[int, bytes]
    native_blocks: dict[int, dict[int, IRBlock]]
    checked_stores: int
    censused_callees: set[int]
    raw_facts: set[tuple[int, int]]
    normalized_facts: set[tuple[int, int]]
    classified_facts: set[tuple[int, int]]
    materialized_facts: set[tuple[int, int]]
    failures: int
    work_units: int
    work_limit: int
    deadline: float
    accounted_work_units: int = 0
    #: The first classified instruction row the census refused — real
    #: diagnostic evidence for the exact failing site, never a guess.
    first_failure_site: Real16InvocationRefusalSite8616 | None = None
    #: Per-edge feasibility verdicts computed once between byte binding
    #: and path-callee/effect simulation; ``live_blocks`` is the scope
    #: both later phases consume.
    edge_feasibility: Real16EdgeFeasibility8616 | None = None
    initial_memory: InvocationInitialMemory8616 | None = None


def _census_work_exceeded_8616(ctx: _PathCensusContext8616) -> bool:
    """Charge nested census work to the ambient replay budget as well as locally."""
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_work_units += ctx.work_units - ctx.accounted_work_units
        ctx.accounted_work_units = ctx.work_units
        return (
            ctx.work_units > ctx.work_limit
            or traversal.census_work_units > _CENSUS_WORK_LIMIT_8616
        )


def _census_deadline_8616() -> float:
    """Share the original deadline across nested domain and preservation replay."""
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    with segment_call_dependency_traversal_scope_8616() as traversal:
        if traversal.census_deadline is None:
            traversal.census_deadline = time.monotonic() + _CENSUS_DEADLINE_SECONDS_8616
        return traversal.census_deadline


def _census_reimport_8616(
    ctx: _PathCensusContext8616,
    boundary: ExactFunctionRangeBoundary8616,
) -> IRFunctionArtifact | Real16InvocationFailure8616:
    """Re-import one boundary under the census guard, finally-restored.

    The re-derived artifact must compare equal to the consumed one,
    including pre-discharge pending refusals, so importer re-entry here
    suppresses callsite-evidence collection entirely. The guard also
    prevents a census re-import from recursing back into premise
    construction. Restore the marker even when the import raises.
    """
    guard = cast(_CensusImportGuard8616, ctx.project)
    try:
        guard_depth = guard._inertia_real16_native_census_8616
    except AttributeError:
        guard_depth = 0
    if type(guard_depth) is not int or guard_depth < 0:
        raise TypeError("invocation census import guard must be an int")
    guard._inertia_real16_native_census_8616 = guard_depth + 1
    try:
        # Deferred: the authoritative importer is resolved at census time so
        # loading this module first cannot deadlock against the package
        # initializer — the binding owner imports this module back.
        from .vex_import import build_x86_16_ir_function_artifact

        return build_x86_16_ir_function_artifact(ctx.project, boundary)
    except _DECODE_REFUSAL_TYPES_8616:
        return Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    finally:
        guard._inertia_real16_native_census_8616 = guard_depth


def _native_effect_blocks_8616(
    ctx: _PathCensusContext8616,
    boundary: ExactFunctionRangeBoundary8616,
) -> dict[int, IRBlock] | Real16InvocationFailure8616:
    """Re-derive one artifact's native blocks through the authoritative importer.

    The importer lifts the project's loaded bytes — already proven equal
    to the retained boot image for every in-scope fetched instruction —
    under the artifact's own exact boundary. Only named decode-boundary
    failures translate to ``native_effect_unproven``; the returned map is
    per-block so each simulated block can be compared in full (rows,
    refusals, and successors), never just by shared address.
    """
    if time.monotonic() > ctx.deadline:
        return Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
    if boundary.project is not ctx.project:
        return Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    relifted = _census_reimport_8616(ctx, boundary)
    if isinstance(relifted, Real16InvocationFailure8616):
        return relifted
    if not isinstance(relifted, IRFunctionArtifact):
        return Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    ctx.work_units += len(relifted.blocks) + sum(
        len(block.instrs) for block in relifted.blocks
    )
    if _census_work_exceeded_8616(ctx):
        return Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
    if time.monotonic() > ctx.deadline:
        return Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
    blocks: dict[int, IRBlock] = {}
    for block in relifted.blocks:
        if type(block.addr) is not int or block.addr in blocks:
            return Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
        blocks[block.addr] = block
    return blocks


# ---------------------------------------------------------------------
# Exact native block binding
#
# ``IRBlock.__eq__`` is not a binding oracle: several census-consumed
# fields are ``compare=False`` (``IRValue.source_tmp``,
# ``IRValue.memory_access_insn``, ``IRCondition.width_bits``), so two
# blocks can compare equal while the simulator consumes different
# capture identities. The comparators below prove equality over *every
# declared field* of every typed IR node on the block — operands,
# destinations, capture ids, origin provenance, refusals, successors —
# against the block the authoritative importer re-derives from the
# fetched native bytes. Each comparator first verifies that the node's
# declared field set still equals its owned expectation; a field added
# to an IR type without updating the matching set fails closed (the
# block is unbound) instead of silently skipping the new field. The
# depth bound keeps a pathologically nested fabricated value a bounded
# refusal, never a stack overflow.
# ---------------------------------------------------------------------

_NATIVE_BINDING_DEPTH_LIMIT_8616 = 16

# Owned field sets — exactly the fields each comparator below examines.
_IR_BLOCK_FIELDS_8616 = frozenset(
    {"addr", "instrs", "refusals", "successor_addrs"}
)
_IR_INSTR_FIELDS_8616 = frozenset(
    {"op", "dst", "args", "size", "addr", "call_stack_effect", "origin"}
)
_IR_VALUE_FIELDS_8616 = frozenset(
    {
        "space", "name", "offset", "const", "size", "version", "expr",
        "index", "index_shift", "memory_access_size", "memory_access_insn",
        "source_tmp", "call_output", "active_unary",
    }
)
_IR_ACTIVE_UNARY_FIELDS_8616 = frozenset({"op", "operand", "result_bits"})
_IR_BINARY_VALUE_FIELDS_8616 = frozenset({"op", "lhs", "rhs", "size"})
_IR_ADDRESS_FIELDS_8616 = frozenset(
    {
        "space", "base", "offset", "size", "status", "segment_origin",
        "expr", "version", "base_values",
    }
)
_IR_CONDITION_FIELDS_8616 = frozenset({"op", "args", "expr", "width_bits"})
_IR_CALL_EFFECT_FIELDS_8616 = frozenset(
    {
        "net_stack_delta", "preserved_ranges", "escaped_ranges",
        "complete", "bp_preserved",
    }
)
_IR_CALL_OUTPUT_FIELDS_8616 = frozenset(
    {"callsite_addr", "target_addr", "shape"}
)
_IR_ORIGIN_FIELDS_8616 = frozenset(
    {
        "block_addr", "statement_index", "address_tmp", "is_block_next",
        "block_next_tmp", "is_instruction_mark",
    }
)
_IR_REFUSAL_FIELDS_8616 = frozenset({"kind", "detail", "block_addr"})


def _native_fields_current_8616(node: object, expected: frozenset[str]) -> bool:
    """Return whether ``node`` still declares exactly the owned field set."""
    if not is_dataclass(node):
        return False
    return frozenset(member.name for member in fields(node)) == expected


def _native_term_equal_8616(left: object, right: object, depth: int) -> bool:
    """Compare two packed binding terms exactly.

    ``False`` covers both a real difference and a structure the
    comparator cannot prove complete — an unprovable field is a refusal,
    not a pass.
    """
    if depth > _NATIVE_BINDING_DEPTH_LIMIT_8616 or type(left) is not type(right):
        return False
    if isinstance(left, (tuple, list)) and isinstance(right, (tuple, list)):
        return len(left) == len(right) and all(
            _native_term_equal_8616(item_left, item_right, depth + 1)
            for item_left, item_right in zip(left, right, strict=True)
        )
    comparator = _NATIVE_COMPARATORS_8616.get(type(left))
    if comparator is not None:
        return comparator(left, right, depth)
    # A typed IR node this comparator does not own cannot be fully
    # compared -> refuse. Plain leaves (ints, strings, enums, None)
    # compare by value under the already-proven common type.
    return not is_dataclass(left) and left == right


def _native_value_equal_8616(left: IRValue, right: IRValue, depth: int) -> bool:
    """All-field binding equality for one IRValue, capture ids included."""
    if not _native_fields_current_8616(left, _IR_VALUE_FIELDS_8616):
        return False
    return _native_term_equal_8616(
        (
            left.space, left.name, left.offset, left.const, left.size,
            left.version, left.expr, left.index, left.index_shift,
            left.memory_access_size, left.memory_access_insn,
            left.source_tmp, left.call_output, left.active_unary,
        ),
        (
            right.space, right.name, right.offset, right.const, right.size,
            right.version, right.expr, right.index, right.index_shift,
            right.memory_access_size, right.memory_access_insn,
            right.source_tmp, right.call_output, right.active_unary,
        ),
        depth + 1,
    )


def _native_active_unary_equal_8616(
    left: IRActiveUnary8616, right: IRActiveUnary8616, depth: int
) -> bool:
    """All-field binding equality for one active unary evidence node."""
    if not _native_fields_current_8616(left, _IR_ACTIVE_UNARY_FIELDS_8616):
        return False
    return _native_term_equal_8616(
        (left.op, left.operand, left.result_bits),
        (right.op, right.operand, right.result_bits),
        depth + 1,
    )


def _native_binary_value_equal_8616(
    left: IRBinaryValue, right: IRBinaryValue, depth: int
) -> bool:
    """All-field binding equality for one typed binary value expression."""
    if not _native_fields_current_8616(left, _IR_BINARY_VALUE_FIELDS_8616):
        return False
    return _native_term_equal_8616(
        (left.op, left.lhs, left.rhs, left.size),
        (right.op, right.lhs, right.rhs, right.size),
        depth + 1,
    )


def _native_address_equal_8616(
    left: IRAddress, right: IRAddress, depth: int
) -> bool:
    """All-field binding equality for one typed segmented address."""
    if not _native_fields_current_8616(left, _IR_ADDRESS_FIELDS_8616):
        return False
    return _native_term_equal_8616(
        (
            left.space, left.base, left.offset, left.size, left.status,
            left.segment_origin, left.expr, left.version, left.base_values,
        ),
        (
            right.space, right.base, right.offset, right.size, right.status,
            right.segment_origin, right.expr, right.version,
            right.base_values,
        ),
        depth + 1,
    )


def _native_condition_equal_8616(
    left: IRCondition, right: IRCondition, depth: int
) -> bool:
    """All-field binding equality for one typed branch condition."""
    if not _native_fields_current_8616(left, _IR_CONDITION_FIELDS_8616):
        return False
    return _native_term_equal_8616(
        (left.op, left.args, left.expr, left.width_bits),
        (right.op, right.args, right.expr, right.width_bits),
        depth + 1,
    )


def _native_call_effect_equal_8616(
    left: IRCallStackEffect8616, right: IRCallStackEffect8616, depth: int
) -> bool:
    """All-field binding equality for one typed call stack effect."""
    if not _native_fields_current_8616(left, _IR_CALL_EFFECT_FIELDS_8616):
        return False
    return _native_term_equal_8616(
        (
            left.net_stack_delta, left.preserved_ranges, left.escaped_ranges,
            left.complete, left.bp_preserved,
        ),
        (
            right.net_stack_delta, right.preserved_ranges,
            right.escaped_ranges, right.complete, right.bp_preserved,
        ),
        depth + 1,
    )


def _native_call_output_equal_8616(
    left: IRCallOutputProvenance8616,
    right: IRCallOutputProvenance8616,
    depth: int,
) -> bool:
    """All-field binding equality for one call-output provenance record."""
    if not _native_fields_current_8616(left, _IR_CALL_OUTPUT_FIELDS_8616):
        return False
    return _native_term_equal_8616(
        (left.callsite_addr, left.target_addr, left.shape),
        (right.callsite_addr, right.target_addr, right.shape),
        depth + 1,
    )


def _native_origin_equal_8616(
    left: IRInstructionOrigin8616, right: IRInstructionOrigin8616, depth: int
) -> bool:
    """All-field binding equality for one instruction origin tag."""
    if not _native_fields_current_8616(left, _IR_ORIGIN_FIELDS_8616):
        return False
    return _native_term_equal_8616(
        (
            left.block_addr, left.statement_index, left.address_tmp,
            left.is_block_next, left.block_next_tmp, left.is_instruction_mark,
        ),
        (
            right.block_addr, right.statement_index, right.address_tmp,
            right.is_block_next, right.block_next_tmp, right.is_instruction_mark,
        ),
        depth + 1,
    )


def _native_refusal_equal_8616(
    left: IRRefusal, right: IRRefusal, depth: int
) -> bool:
    """All-field binding equality for one typed IR refusal."""
    if not _native_fields_current_8616(left, _IR_REFUSAL_FIELDS_8616):
        return False
    return _native_term_equal_8616(
        (left.kind, left.detail, left.block_addr),
        (right.kind, right.detail, right.block_addr),
        depth + 1,
    )


def _native_instr_equal_8616(left: IRInstr, right: IRInstr, depth: int) -> bool:
    """All-field binding equality for one typed instruction row."""
    if not _native_fields_current_8616(left, _IR_INSTR_FIELDS_8616):
        return False
    return _native_term_equal_8616(
        (
            left.op, left.dst, left.args, left.size, left.addr,
            left.call_stack_effect, left.origin,
        ),
        (
            right.op, right.dst, right.args, right.size, right.addr,
            right.call_stack_effect, right.origin,
        ),
        depth + 1,
    )


def _native_block_equal_8616(left: IRBlock, right: IRBlock, depth: int) -> bool:
    """All-field binding equality for one typed IR block."""
    if not _native_fields_current_8616(left, _IR_BLOCK_FIELDS_8616):
        return False
    return _native_term_equal_8616(
        (left.addr, left.instrs, left.refusals, left.successor_addrs),
        (right.addr, right.instrs, right.refusals, right.successor_addrs),
        depth + 1,
    )


_NATIVE_COMPARATORS_8616: dict[type, Callable[..., bool]] = {
    IRBlock: _native_block_equal_8616,
    IRInstr: _native_instr_equal_8616,
    IRValue: _native_value_equal_8616,
    IRBinaryValue: _native_binary_value_equal_8616,
    IRAddress: _native_address_equal_8616,
    IRCondition: _native_condition_equal_8616,
    IRCallStackEffect8616: _native_call_effect_equal_8616,
    IRCallOutputProvenance8616: _native_call_output_equal_8616,
    IRActiveUnary8616: _native_active_unary_equal_8616,
    IRInstructionOrigin8616: _native_origin_equal_8616,
    IRRefusal: _native_refusal_equal_8616,
}


def _native_block_bound_8616(native: object, block: IRBlock) -> bool:
    """Return whether ``block`` is the exact re-derived native block.

    Whole-block source/effect/provenance binding: the artifact block and
    the block re-derived by the authoritative importer must be the same
    type and equal over every declared field of every row. ``native`` is
    ``None`` or a non-block when the census never bound this block's
    bytes — an unbound block can never prove a native effect, so binding
    refuses rather than comparing.
    """
    return (
        type(native) is IRBlock
        and type(block) is IRBlock
        and _native_block_equal_8616(native, block, 0)
    )


def _machine_census_8616(
    ctx: _PathCensusContext8616, block_addr: int
) -> dict[int, tuple[int, bytes]] | Real16InvocationFailure8616:
    """Decode and dedupe one block's machine instructions with exact bytes.

    Only the named frontend decode-boundary failure types translate to a
    typed refusal; anything else (``RuntimeError``, ``TypeError``,
    ``IndexError``, ``KeyError``, ...) is a census defect and propagates
    loudly.
    """
    if time.monotonic() > ctx.deadline:
        return Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
    try:
        decoded = decoded_block_instructions_8616(ctx.project, block_addr, opt_level=0)
    except _DECODE_REFUSAL_TYPES_8616:
        return Real16InvocationFailure8616.PATH_DECODE_MISMATCH
    ctx.work_units += len(decoded)
    if _census_work_exceeded_8616(ctx):
        return Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
    machine_addrs: dict[int, tuple[int, bytes]] = {}
    for raw_instruction in decoded:
        normalized = _normalize_instruction_8616(raw_instruction)
        if normalized is None:
            return Real16InvocationFailure8616.PATH_DECODE_MISMATCH
        address, size = normalized
        if address in machine_addrs:
            return Real16InvocationFailure8616.PATH_DECODE_MISMATCH
        encoded = _instruction_bytes_8616(raw_instruction)
        if encoded is None or len(encoded) != size:
            return Real16InvocationFailure8616.PATH_DECODE_MISMATCH
        machine_addrs[address] = (size, encoded)
    return machine_addrs


def _bind_fetched_bytes_8616(
    machine_addrs: dict[int, tuple[int, bytes]],
    in_scope: frozenset[int] | set[int],
    *,
    selector: int,
    image: _BootImageSurface8616,
) -> Real16InvocationFailure8616 | None:
    """Bind every in-scope fetched instruction byte range to the image."""
    window_base = selector << _SEGMENT_SHIFT_8616
    window_end = window_base + _WORD_LIMIT_8616
    for address in sorted(in_scope):
        size, encoded = machine_addrs[address]
        if not window_base <= address or address + size > window_end + 1:
            return Real16InvocationFailure8616.FETCH_WINDOW_VIOLATION
        if not any(
            code_range.contains(address, size) for code_range in image.code_ranges
        ):
            return Real16InvocationFailure8616.CODE_SCOPE_VIOLATION
        image_slice = _image_slice_8616(image, address, size)
        if image_slice is None or image_slice != encoded:
            return Real16InvocationFailure8616.NATIVE_BYTES_MISMATCH
    return None


class _CensusBlockExtent8616(Protocol):
    """Frontend partition block geometry at the dynamic decode boundary."""

    addr: int
    size: int


def _partition_machine_census_8616(
    machine: dict[int, tuple[int, bytes]],
    boundary: ExactFunctionRangeBoundary8616,
    block_addr: int,
) -> dict[int, tuple[int, bytes]] | Real16InvocationFailure8616:
    """Use the authenticated frontend extent, never the claimed IR suffix."""
    matches = tuple(
        cast(_CensusBlockExtent8616, candidate)
        for candidate in boundary.blocks
        if cast(_CensusBlockExtent8616, candidate).addr == block_addr
    )
    if len(matches) != 1:
        return Real16InvocationFailure8616.PATH_DECODE_MISMATCH
    size = matches[0].size
    if type(size) is not int or size <= 0:
        return Real16InvocationFailure8616.PATH_DECODE_MISMATCH
    end = block_addr + size
    selected = {addr: row for addr, row in machine.items() if block_addr <= addr < end}
    cursor = block_addr
    for addr, (length, _encoded) in sorted(selected.items()):
        if addr != cursor:
            return Real16InvocationFailure8616.PATH_DECODE_MISMATCH
        cursor = addr + length
    if cursor != end:
        return Real16InvocationFailure8616.PATH_DECODE_MISMATCH
    return selected


def _census_block_bytes_8616(
    ctx: _PathCensusContext8616,
    block: IRBlock,
    *,
    stop_after: int | None,
    boundary: ExactFunctionRangeBoundary8616 | None = None,
) -> Real16InvocationFailure8616 | None:
    """Census one block's fetched bytes and append them to the manifest.

    ``stop_after`` truncates the in-scope census at the callsite machine
    instruction for the block that owns it; every other block binds its
    full decoded instruction set within its authenticated frontend partition.
    A claimed IR suffix cannot shorten that partition. Without an explicit
    boundary, retain the full natural decode rather than guessing an extent.
    """
    window_base = ctx.selector << _SEGMENT_SHIFT_8616
    window_end = window_base + _WORD_LIMIT_8616
    for successor in block.successor_addrs:
        if not window_base <= successor <= window_end:
            return Real16InvocationFailure8616.FETCH_WINDOW_VIOLATION
    machine_addrs = _machine_census_8616(ctx, block.addr)
    if isinstance(machine_addrs, Real16InvocationFailure8616):
        return machine_addrs
    if boundary is not None:
        machine_addrs = _partition_machine_census_8616(machine_addrs, boundary, block.addr)
        if isinstance(machine_addrs, Real16InvocationFailure8616):
            return machine_addrs
    artifact_addrs = {
        instruction.addr
        for instruction in block.instrs
        if type(instruction.addr) is int
    }
    if stop_after is None:
        in_scope = set(machine_addrs)
        expected = artifact_addrs
    else:
        in_scope = {address for address in machine_addrs if address <= stop_after}
        expected = {addr for addr in artifact_addrs if addr <= stop_after}
    if in_scope != expected:
        return Real16InvocationFailure8616.PATH_DECODE_MISMATCH
    failure = _bind_fetched_bytes_8616(
        machine_addrs, in_scope, selector=ctx.selector, image=ctx.image
    )
    if failure is not None:
        return failure
    ctx.manifest.extend(
        (address, machine_addrs[address][0]) for address in sorted(in_scope)
    )
    for address in sorted(in_scope):
        ctx.machine_bytes[address] = machine_addrs[address][1]
    return None


def _eval_atom_8616(
    atom: object,
    registers: dict[str, int],
    tmps: dict[int, int],
) -> int | None:
    """Evaluate one typed atom to an exact value or ``None`` (unknown)."""
    if isinstance(atom, IRValue):
        return _eval_value_8616(atom, registers, tmps)
    if isinstance(atom, IRBinaryValue):
        left = _eval_atom_8616(atom.lhs, registers, tmps)
        right = _eval_atom_8616(atom.rhs, registers, tmps)
        if left is None or right is None:
            return None
        return _eval_binary_op_8616(atom.op, left, right, operands=(atom.lhs, atom.rhs), result_size=atom.size)
    return None


def _value_mask_8616(size: object) -> int | None:
    """Return the wrap mask for one declared byte width, else ``None``.

    Unknown widths refuse rather than silently defaulting to 16 bits:
    masking a wider value to a word would invent a false constant.
    """
    if type(size) is not int or size not in (1, 2, 4, 8):
        return None
    return (1 << (size * 8)) - 1


def _register_width_8616(name: str) -> int | None:
    """Return the authoritative bit width of one register name, or ``None``."""
    projection = register_value_projection_8616(name, name)
    return None if projection is None else projection[1]


def _register_tile_8616(name: str, width: int, state: dict[str, int]) -> int | None:
    """Tile one register view from proven contained family lanes.

    Every bit of ``name``'s view must be covered by a proven family member
    contained in it (``al``/``ah`` for ``ax``); overlapping contributors
    must agree on shared bits. Missing or conflicting lanes return
    ``None``.
    """
    covered = 0
    value = 0
    for member in register_value_family_8616(name):
        lane = register_value_projection_8616(name, member)
        if lane is None:
            continue
        source = state.get(member)
        if source is None:
            continue
        shift, bits = lane
        lane_mask = ((1 << bits) - 1) << shift
        if covered & lane_mask:
            if (value >> shift) & ((1 << bits) - 1) != source & ((1 << bits) - 1):
                return None
            continue
        value |= (source & ((1 << bits) - 1)) << shift
        covered |= lane_mask
    if covered != (1 << width) - 1:
        return None
    return value


def _register_read_8616(name: str, state: dict[str, int]) -> int | None:
    """Read one register, recomposing wider views from proven lanes only.

    Uses the authoritative ``register_value_projection_8616`` lane model:
    a proven containing member (``eax`` for ``ax``) projects the view
    directly; otherwise the view is tiled from proven contained members
    (``al``+``ah`` for ``ax``) and must cover every bit without
    disagreement. Missing or conflicting lanes leave the read unknown.
    """
    direct = state.get(name)
    if direct is not None:
        return direct
    width = _register_width_8616(name)
    if width is None:
        return None
    for member in register_value_family_8616(name):
        if member == name:
            continue
        container = register_value_projection_8616(member, name)
        if container is None:
            continue
        source = state.get(member)
        if source is not None:
            # ``member`` storage fully contains the requested view.
            return (source >> container[0]) & ((1 << width) - 1)
    return _register_tile_8616(name, width, state)


# Exact ``Iop_<src>to<dst>`` / ``Iop_<src><U|S|HI>to<dst>`` conversion or
# ``Iop_Not<width>`` spellings — the only unary identities this evaluator
# interprets. Anything else is unsupported and evaluates to unknown.
_UNARY_CONVERT_OP_8616 = re.compile(r"^Iop_(\d+)(U|S|HI)?to(\d+)$")
_UNARY_NOT_OP_8616 = re.compile(r"^Iop_Not(\d+)$")
# Bound on nested active-unary evaluation; genuine VEX chains are shallow.
_UNARY_DEPTH_LIMIT_8616 = 8


def _eval_unary_op_8616(op: str, operand: int, result_bits: int) -> int | None:
    """Apply one typed active unary op to a concrete operand value.

    Only exact VEX op identities are interpreted: ``Not`` at its declared
    width, ``<src>to<dst>`` low-half truncation, ``<src>Uto<dst>`` zero
    extension, ``<src>Sto<dst>`` sign extension and ``<2n>HIto<n>`` high
    half extraction. The op's declared result width must equal the
    evidence's authoritative ``result_bits``; anything else is unknown.
    """
    if type(result_bits) is not int or result_bits <= 0:
        return None
    not_match = _UNARY_NOT_OP_8616.fullmatch(op)
    if not_match is not None:
        bits = int(not_match.group(1))
        if bits != result_bits:
            return None
        return ~operand & ((1 << bits) - 1)
    match = _UNARY_CONVERT_OP_8616.fullmatch(op)
    if match is None:
        return None
    return _eval_convert_unary_8616(match, operand, result_bits)


def _eval_convert_unary_8616(
    match: re.Match[str], operand: int, result_bits: int
) -> int | None:
    """Apply one concrete ``<src>[U|S|HI]to<dst>`` conversion operand."""
    src_bits = int(match.group(1))
    sign = match.group(2)
    dst_bits = int(match.group(3))
    if dst_bits != result_bits:
        return None
    src_mask = (1 << src_bits) - 1
    operand &= src_mask
    if sign == "HI":
        if src_bits != 2 * dst_bits:
            return None
        return (operand >> dst_bits) & ((1 << dst_bits) - 1)
    if src_bits > dst_bits:
        return operand & ((1 << dst_bits) - 1)
    if src_bits == dst_bits or sign not in ("U", "S"):
        return None
    if sign == "S" and operand & (1 << (src_bits - 1)):
        return operand | (((1 << dst_bits) - 1) ^ src_mask)
    return operand


def _eval_value_8616(
    value: IRValue,
    registers: dict[str, int],
    tmps: dict[int, int],
) -> int | None:
    """Evaluate one typed value against the abstract invocation state."""
    return _eval_value_inner_8616(value, registers, tmps, 0)


def _eval_value_inner_8616(
    value: IRValue,
    registers: dict[str, int],
    tmps: dict[int, int],
    depth: int,
) -> int | None:
    """Evaluate one typed value, honoring capture identity and unary ops.

    ``source_tmp`` names the already-computed tmp result — an immutable
    capture whose ``offset``/``expr`` are producer provenance and are
    never replayed against a newer register value. ``active_unary`` is
    the authoritative pending operation and is evaluated on its typed
    operand first; both set at once is contradictory evidence and
    refuses. Without either, ``expr`` tokens are provenance: whitelisted
    binop fold tags pass, any other ``Iop_*`` unary projection cannot be
    authenticated and refuses.
    """
    if depth > _UNARY_DEPTH_LIMIT_8616:
        return None
    if value.index is not None or value.index_shift:
        return None
    if type(value.offset) is not int:
        return None
    if value.source_tmp is not None:
        if value.active_unary is not None:
            return None
        captured = tmps.get(value.source_tmp)
        if captured is None:
            return None
        mask = _value_mask_8616(value.size)
        return None if mask is None else captured & mask
    if value.active_unary is not None:
        operand = _eval_value_inner_8616(
            value.active_unary.operand, registers, tmps, depth + 1
        )
        if operand is None:
            return None
        return _eval_unary_op_8616(
            value.active_unary.op, operand, value.active_unary.result_bits
        )
    return _eval_plain_value_8616(value, registers)


def _expr_provenance_only_8616(value: IRValue) -> bool:
    """Return whether every ``Iop_*`` ``expr`` token is a binop fold tag."""
    for token in value.expr or ():
        if token.startswith("Iop_") and token not in _BINARY_OPS_8616:
            return False
    return True


def _eval_plain_value_8616(
    value: IRValue, registers: dict[str, int]
) -> int | None:
    """Evaluate a provenance-only CONST/REG view plus its folded offset.

    Any ``Iop_*`` ``expr`` token that is not a whitelisted binop fold tag
    is an unauthenticated unary projection and refuses.
    """
    if not _expr_provenance_only_8616(value):
        return None
    base: int | None
    if value.space is MemSpace.CONST:
        if type(value.const) is not int:
            return None
        base = value.const
    elif value.space is MemSpace.REG:
        if value.name is None:
            return None
        base = _register_read_8616(value.name, registers)
    else:
        return None
    if base is None:
        return None
    mask = _value_mask_8616(value.size)
    if mask is None:
        return None
    return (base + value.offset) & mask


# Exact supported VEX integer binops: ``Iop_<name><width>`` only. Any
# other operation name — including names that merely *contain* one of
# these substrings — is unsupported and evaluates to unknown.
_BINARY_OPS_8616: frozenset[str] = frozenset(
    {
        f"Iop_{name}{width}"
        for name in ("Add", "Sub", "Mul", "And", "Or", "Xor", "Shl", "Shr")
        for width in (8, 16, 32, 64)
    }
)


def _binary_parts_8616(op: str) -> tuple[str, int]:
    """Split a whitelisted ``Iop_<name><width>`` into exact name and width."""
    digits = ""
    for char in reversed(op):
        if not char.isdigit():
            break
        digits = char + digits
    return op[4 : len(op) - len(digits)], int(digits)


def _eval_binary_op_8616(
    op: str, left: int, right: int, *,
    operands: tuple[object, object] | None = None, result_size: int | None = None,
) -> int | None:
    """Apply an exact-whitelisted VEX integer binop at its declared width."""
    if op not in _BINARY_OPS_8616:
        return wide_multiply_value_8616(op, left, right, operands, result_size)
    name, width = _binary_parts_8616(op)
    mask = (1 << width) - 1
    left &= mask
    right &= mask
    if name == "Add":
        return (left + right) & mask
    if name == "Sub":
        return (left - right) & mask
    if name == "Mul":
        return (left * right) & mask
    if name == "And":
        return left & right
    if name == "Or":
        return left | right
    if name == "Xor":
        return left ^ right
    if name == "Shl":
        return (left << right) & mask if 0 <= right < width else 0
    if name == "Shr":
        return left >> right if 0 <= right < width else 0
    return None


def _binary_width_digits_8616(op: str) -> int:
    """Return the exact declared bit width suffix of a whitelisted op."""
    return int(op.rsplit("_", 1)[-1])


def _eval_base_value_8616(
    value: IRValue,
    instruction_entry: dict[str, int],
    dirty: frozenset[str] | set[str],
    tmps: dict[int, int],
    depth: int = 0,
) -> int | None:
    """Evaluate one captured base-register read of a typed address.

    ``source_tmp`` pins the read to its exact VEX capture point (already
    evaluated in instruction order); the stored view's ``offset``/``expr``
    are producer provenance and are never replayed. ``active_unary``
    evidence is applied to its own operand — a converted base must not
    silently read the unconverted register. Otherwise the read must be of
    a register unmodified inside this machine instruction so the
    instruction-entry state is the authoritative value; unauthenticated
    unary ``expr`` projections on unpinned views refuse.
    """
    if depth > _UNARY_DEPTH_LIMIT_8616:
        return None
    if not isinstance(value, IRValue) or value.index is not None or value.index_shift:
        return None
    if type(value.offset) is not int:
        return None
    if value.source_tmp is not None:
        if value.active_unary is not None:
            return None
        base = tmps.get(value.source_tmp)
        return None if base is None else base & _WORD_LIMIT_8616
    if value.active_unary is not None:
        operand = _eval_base_value_8616(
            value.active_unary.operand, instruction_entry, dirty, tmps, depth + 1
        )
        if operand is None:
            return None
        evaluated = _eval_unary_op_8616(
            value.active_unary.op, operand, value.active_unary.result_bits
        )
        return None if evaluated is None else evaluated & _WORD_LIMIT_8616
    return _eval_base_plain_8616(value, instruction_entry, dirty)


def _eval_base_plain_8616(
    value: IRValue,
    instruction_entry: dict[str, int],
    dirty: frozenset[str] | set[str],
) -> int | None:
    """Evaluate a provenance-only address base against instruction-entry state.

    A register modified inside the machine instruction cannot use the
    entry snapshot; unauthenticated unary ``expr`` projections refuse.
    """
    if not _expr_provenance_only_8616(value):
        return None
    if value.space is MemSpace.REG and value.name is not None:
        if value.name in dirty:
            return None
        base = _register_read_8616(value.name, instruction_entry)
        return None if base is None else (base + value.offset) & _WORD_LIMIT_8616
    if value.space is MemSpace.CONST and type(value.const) is int:
        return value.const + value.offset
    return None


def _store_span_8616(
    instruction: IRInstr,
    address: object,
    instruction_entry: dict[str, int],
    dirty: set[str],
    tmps: dict[int, int],
) -> tuple[int, int] | None:
    """Return the exact physical [base, base+size) one STORE writes."""
    if not isinstance(address, IRAddress) or type(address.offset) is not int:
        return None
    size = address.size if type(address.size) is int and address.size > 0 else instruction.size
    if type(size) is not int or size <= 0:
        return None
    if address.space is MemSpace.UNKNOWN:
        # A bare constant address is the only segment-free form: the offset
        # is already the physical linear target.
        if address.base or address.base_values or address.expr != ("absolute_const",):
            return None
        return address.offset, size
    segment = _SEGMENT_BASE_NAME_8616.get(address.space)
    if segment is None or segment in dirty:
        return None
    segment_value = instruction_entry.get(segment)
    if segment_value is None:
        return None
    bases = address.base_values or tuple(
        IRValue(MemSpace.REG, name=name, size=2) for name in address.base
    )
    offset_total = 0
    for value in bases:
        base_value = _eval_base_value_8616(value, instruction_entry, dirty, tmps)
        if base_value is None:
            return None
        offset_total += base_value
    offset16 = (offset_total + address.offset) & _WORD_LIMIT_8616
    return (segment_value << _SEGMENT_SHIFT_8616) + offset16, size


def _meet_registers_8616(states: Iterable[dict[str, int]]) -> dict[str, int]:
    """Join predecessor exit states: a value is kept iff all paths agree."""
    iterator = iter(states)
    try:
        merged = dict(next(iterator))
    except StopIteration:
        return {}
    for state in iterator:
        for name in tuple(merged):
            if state.get(name) != merged[name]:
                del merged[name]
    return merged


@dataclass(slots=True)
class _PathState8616:
    """One abstract path position: proven register lanes + memory overlay.

    The pair is the complete state the scope fixpoint meets per
    predecessor and each block transfer consumes — a register constant
    and a memory byte are proven under the identical must discipline, so
    alternative branch histories can never collapse into whichever block
    the census visited last. ``memory`` is the shared
    ``PathMemory8616`` overlay from ``real16_path_memory8616``.
    """

    registers: dict[str, int]
    memory: PathMemory8616
    #: Proven DF only, independent of the unknown remainder of FLAGS.
    direction: bool | None = None


def _meet_path_state_8616(states: Iterable[_PathState8616]) -> _PathState8616:
    """Meet whole path states componentwise under the must discipline."""
    items = list(states)
    return _PathState8616(
        registers=_meet_registers_8616(state.registers for state in items),
        memory=meet_path_memory_8616(state.memory for state in items),
        direction=(items[0].direction if items and all(state.direction == items[0].direction for state in items) else None),
    )


def _apply_register_write_8616(
    name: str,
    dst_size: object,
    value: int | None,
    registers: dict[str, int],
    dirty: set[str],
) -> None:
    """Apply one register write through the authoritative lane model.

    Every storage-family member that overlaps the written view is marked
    dirty; members fully contained in the written view are re-projected
    from ``value`` (or dropped when it is unknown), and members containing
    the written view are invalidated — a write to ``al`` must not leave a
    stale ``ax`` constant. Disjoint lanes of the same storage (``al`` vs
    ``ah``) keep their values.
    """
    width = _register_width_8616(name)
    known = (
        value
        if value is not None
        and width is not None
        and type(dst_size) is int
        and dst_size * 8 == width
        else None
    )
    for member in register_value_family_8616(name):
        if member == name:
            continue
        contained = register_value_projection_8616(name, member)
        contains = register_value_projection_8616(member, name)
        if contained is None and contains is None:
            # Disjoint lanes of the same storage are unaffected.
            continue
        dirty.add(member)
        if known is not None and contained is not None:
            shift, bits = contained
            registers[member] = (known >> shift) & ((1 << bits) - 1)
        else:
            registers.pop(member, None)
    dirty.add(name)
    if known is None:
        registers.pop(name, None)
    elif width is not None:
        registers[name] = known & ((1 << width) - 1)


def _simulate_reg_write_8616(
    instruction: IRInstr,
    dst: IRValue,
    registers: dict[str, int],
    tmps: dict[int, int],
    dirty: set[str],
) -> Real16InvocationFailure8616 | None:
    """Apply one register-writing effect through the lane model."""
    if dst.name is None:
        return Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
    evaluated: int | None = None
    if instruction.op == "MOV" and len(instruction.args) == 1:
        evaluated = _eval_atom_8616(instruction.args[0], registers, tmps)
    _apply_register_write_8616(dst.name, dst.size, evaluated, registers, dirty)
    return None


def _simulate_tmp_write_8616(
    instruction: IRInstr,
    dst: IRValue,
    registers: dict[str, int],
    tmps: dict[int, int],
) -> None:
    """Apply one tmp-writing effect; unevaluable results stay unknown."""
    if type(dst.source_tmp) is not int:
        return
    evaluated: int | None = None
    if instruction.op == "MOV" and len(instruction.args) == 1:
        evaluated = _eval_atom_8616(instruction.args[0], registers, tmps)
    elif instruction.op.startswith("Iop_") and len(instruction.args) == 2:
        left = _eval_atom_8616(instruction.args[0], registers, tmps)
        right = _eval_atom_8616(instruction.args[1], registers, tmps)
        if left is not None and right is not None:
            evaluated = _eval_binary_op_8616(
                instruction.op, left, right,
                operands=(instruction.args[0], instruction.args[1]), result_size=dst.size,
            )
    if evaluated is None:
        tmps.pop(dst.source_tmp, None)
    else:
        tmps[dst.source_tmp] = evaluated


def _simulate_census_tmp_write_8616(
    ctx: _PathCensusContext8616, instruction: IRInstr, dst: IRValue,
    instruction_entry: dict[str, int], dirty: set[str], tmps: dict[int, int],
    memory: PathMemory8616, registers: dict[str, int],
) -> None:
    """Transfer a native tmp row, reading only authenticated initialized bytes."""
    if instruction.op != "LOAD":
        _simulate_tmp_write_8616(instruction, dst, registers, tmps)
        return
    value = path_load_value_8616(
        instruction,
        _store_span_8616(instruction, instruction.args[0] if instruction.args else None,
                         instruction_entry, dirty, tmps),
        memory, ctx.initial_memory,
    )
    if type(dst.source_tmp) is int:
        if value is None:
            tmps.pop(dst.source_tmp, None)
        else:
            tmps[dst.source_tmp] = value


def _transfer_row_failure_8616(
    ctx: _PathCensusContext8616,
    instruction: IRInstr,
    block: IRBlock,
) -> Real16InvocationFailure8616 | None:
    """Classify one CJMP/JMP/RET row's effect on the path state.

    The callsite row is the census boundary: a CALL's state is captured by
    ``_cross_call_8616``, and a pending JMP's symbolic transfer is the very
    obligation the premise discharges — its target is not an in-path
    effect. Any other symbolic (non-constant ``dst``) transfer refuses.
    """
    if instruction.op == "CJMP" and instruction is not block.instrs[-1]:
        # A single linear pass cannot establish effects after an internal
        # exit (notably every iteration of REP). Require an authenticated
        # complete transfer; visiting the rows once can miss later code writes.
        return Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
    if instruction.addr == ctx.callsite_addr:
        return None
    if instruction.dst is not None:
        return Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
    return None


def _simulate_instruction_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    block: IRBlock,
    instruction: IRInstr,
    registers: dict[str, int],
    tmps: dict[int, int],
    instruction_entry: dict[str, int],
    dirty: set[str],
    memory: PathMemory8616,
    row: tuple[int, int],
) -> Real16InvocationFailure8616 | None:
    """Apply one in-path instruction's typed effect to the abstract state.

    ``row`` is the real ``(block_addr, instr_index)`` census key; the five
    stage counters count actual rows, not aggregates. Every row that
    passes the budget gate is normalized and classified; exactly one
    refusal tail then keeps the ledger closed — a classified row is either
    materialized or counted once in ``failures``. Budget exhaustion is a
    census-level refusal and is deliberately *not* a row failure.
    """
    ctx.raw_facts.add(row)
    ctx.work_units += 1
    if _census_work_exceeded_8616(ctx):
        return Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
    ctx.normalized_facts.add(row)
    ctx.classified_facts.add(row)
    op = instruction.op
    failure: Real16InvocationFailure8616 | None
    if _writes_segment_register_8616(instruction, "cs"):
        failure = Real16InvocationFailure8616.CS_PATH_UNPROVEN
    elif op == "STORE":
        failure = _census_store_8616(
            ctx, instruction, instruction_entry, dirty, tmps, memory
        )
    elif op == "CALL":
        failure = (
            Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
            if instruction.dst is not None
            else _cross_call_8616(
                ctx, artifact, block, instruction, registers, memory
            )
        )
    elif op in ("CJMP", "JMP", "RET"):
        failure = _transfer_row_failure_8616(ctx, instruction, block)
    else:
        # Every other effect must be closed by the authoritative scalar
        # classifier before any destination is accepted: an UNKNOWN kind,
        # a memory clobber escaping the store path, or an IP clobber
        # escaping the control path is an unproven raw path effect, never
        # a silently dropped write.
        effect = scalar_instruction_effect_8616(instruction)
        dst = instruction.dst
        if (
            effect.kind is ScalarInstructionEffectKind8616.CLOSED_DESTINATION
            and effect.clobber is ScalarInstructionClobber8616.DATA_REGISTER
            and isinstance(dst, IRValue)
            and dst.space is MemSpace.REG
        ):
            failure = _simulate_reg_write_8616(
                instruction, dst, registers, tmps, dirty
            )
        elif (
            effect.kind is ScalarInstructionEffectKind8616.CLOSED_DESTINATION
            and effect.clobber is ScalarInstructionClobber8616.NONE
            and isinstance(dst, IRValue)
            and dst.space is MemSpace.TMP
        ):
            _simulate_census_tmp_write_8616(
                ctx, instruction, dst, instruction_entry, dirty, tmps, memory, registers
            )
            failure = None
        elif (
            effect.kind is ScalarInstructionEffectKind8616.NO_REGISTER_WRITE
            and effect.clobber is ScalarInstructionClobber8616.NONE
            and instruction.dst is None
        ):
            # A mark-bound no-effect row (canonical NOP bytes authenticated by
            # the census against the bound project) preserves every simulated
            # register and memory byte; it materializes with no state change.
            failure = None
        else:
            failure = Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
    if failure is not None:
        # A later fixpoint visit can revoke an earlier row's proof when
        # incoming states meet. The final ledger must not retain that
        # stale materialization alongside its recorded failure.
        ctx.materialized_facts.discard(row)
        ctx.failures += 1
        _record_first_failure_site_8616(ctx, artifact, block, instruction)
        return failure
    ctx.materialized_facts.add(row)
    return None


def _record_first_failure_site_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    block: IRBlock,
    instruction: IRInstr,
) -> None:
    """Retain the first classified row's exact site on the census.

    Only the earliest refused row is kept — later failures on the same
    census never overwrite it — and only rows whose machine address is a
    real integer qualify, so a malformed row can never mint a site. The
    artifact head is recorded verbatim: on a nested replay the site names
    the parent surface that actually failed, not the consuming callsite.
    """
    if ctx.first_failure_site is not None:
        return
    if (
        type(artifact.function_addr) is not int
        or type(block.addr) is not int
        or type(instruction.addr) is not int
    ):
        return
    ctx.first_failure_site = Real16InvocationRefusalSite8616(
        function_addr=artifact.function_addr,
        block_addr=block.addr,
        instruction_addr=instruction.addr,
    )


def _address_domain16_8616(encoded: bytes) -> bool:
    """Return whether fetched bytes keep the 16-bit effective-address domain.

    Only the leading legacy-prefix run can change the address size: a
    ``0x67`` byte in that run selects 32-bit effective addressing, whose
    truncated IR offsets this domain cannot soundly model.
    """
    index = 0
    while index < len(encoded) and encoded[index] in _LEGACY_PREFIX_BYTES_8616:
        if encoded[index] == 0x67:
            return False
        index += 1
    return True


def _store_data_bytes_8616(
    instruction: IRInstr,
    instruction_entry: dict[str, int],
    dirty: set[str],
    tmps: dict[int, int],
    size: int,
) -> bytes | None:
    """Return the exact bytes one proven STORE writes, or ``None``.

    The value is evaluated under the same instruction-entry state and
    dirty-name discipline as the address: anything unproven — a memory
    read, an unknown tmp, a register modified inside this machine
    instruction — records ``None`` (span proven, bytes unknown) instead
    of a guessed constant.
    """
    atom = instruction.args[1]
    if not store_atom_clean_8616(atom, dirty):
        return None
    evaluated = _eval_atom_8616(atom, instruction_entry, tmps)
    mask = _value_mask_8616(size)
    if evaluated is None or mask is None:
        return None
    return (evaluated & mask).to_bytes(size, "little")


def _census_store_8616(
    ctx: _PathCensusContext8616,
    instruction: IRInstr,
    instruction_entry: dict[str, int],
    dirty: set[str],
    tmps: dict[int, int],
    memory: PathMemory8616,
) -> Real16InvocationFailure8616 | None:
    """Require one raw STORE to be provably disjoint from fetched code.

    On success the write commits to the *path's* memory overlay — known
    bytes when the data atom evaluates, unknown bytes when only the span
    is proven — so joins meet the store under the identical
    per-predecessor must discipline as register facts.
    """
    if len(instruction.args) != 2 or instruction.dst is not None:
        return Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
    if type(instruction.addr) is not int:
        return Real16InvocationFailure8616.STORE_ADDRESS_UNPROVEN
    encoded = ctx.machine_bytes.get(instruction.addr)
    if encoded is None or not _address_domain16_8616(encoded):
        # Without fetched-byte proof of a 16-bit effective-address domain
        # the typed offsets cannot be trusted (a 0x67 prefix widens them).
        return Real16InvocationFailure8616.STORE_ADDRESS_UNPROVEN
    span = _store_span_8616(
        instruction, instruction.args[0], instruction_entry, dirty, tmps
    )
    if span is None:
        return Real16InvocationFailure8616.STORE_ADDRESS_UNPROVEN
    base, size = span
    for start, extent in ctx.manifest:
        if base < start + extent and base + size > start:
            return Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    ctx.checked_stores += 1
    memory.apply_write(
        base,
        size,
        _store_data_bytes_8616(instruction, instruction_entry, dirty, tmps, size),
    )
    return None


class _BoundaryProof8616(Protocol):
    """Shared bound-proof surface consumed at a call boundary.

    Both pools expose the identical contract: the required-entry
    projection, a scope-authenticated completeness replay, the scoped
    preserved-segment projection, and the callee's segment-effect
    closure. The census never reads the universal properties of
    conditional evidence; every consumption names its authenticated
    entry.
    """

    @property
    def required_scope(self) -> Real16InvocationDomain8616 | None:
        """Return the entry scope a consumer must authenticate, or None."""
        ...

    @property
    def complete(self) -> bool:
        """Revalidate the retained evidence chain end to end."""
        ...

    def complete_for(
        self, invocation_scope: Real16InvocationDomain8616 | None
    ) -> bool:
        """Revalidate only under the authenticated consuming entry."""
        ...

    @property
    def preserved_registers(self) -> tuple[str, ...]:
        """Project segment identities proven at entry and every RET exit."""
        ...

    def preserved_registers_for(
        self, invocation_scope: Real16InvocationDomain8616 | None
    ) -> tuple[str, ...]:
        """Project registers only under the authenticated consuming entry."""
        ...

    @property
    def callee(self) -> SegmentEffectClosureResult8616 | None:
        """Return the bound callee segment-effect closure."""
        ...


def _derivation_scope_bound_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    required: Real16InvocationDomain8616 | None,
) -> bool:
    """Authenticate one conditional record's scope against this census.

    The census's consuming scope is the domain under construction, which
    is not yet a materialized premise; the required entry provenance must
    therefore equal the derivation's own: the identical project and boot
    objects and source digest, plus the same transport anchor — a chained
    derivation admits only a scope carrying a coterminous retained link,
    while a boot derivation admits only the boot premise over the
    identical censused artifact. Anything weaker is a different entry and
    stays refused; the produced domain's own ``complete`` replay re-runs
    this check on every replay.
    """
    if required is None:
        return True
    if type(required) is not Real16InvocationDomain8616:
        return False
    if not (
        required.project is ctx.project
        and required.boot is ctx.boot
        and required.source_sha256 == ctx.image.file_sha256
    ):
        return False
    chain = ctx.chain
    if chain is None:
        return (
            required.kind is Real16InvocationKind8616.BOOT_ENTRY_PATH
            and required.chain is None
            and required.coverage is not None
            and required.coverage.artifact is artifact
        )
    return _in_flight_scopes_coterminous_8616(required.chain, chain, 0)


def _ctx_consuming_scope_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    proof: _BoundaryProof8616,
) -> Real16InvocationDomain8616 | object | None:
    """Return the authenticated scope this census may consume under.

    ``None`` means the proof is universal evidence; the record's own
    ``required_scope`` means conditional evidence the census may consume
    under that authenticated entry. The sentinel ``_CTX_SCOPE_REFUSE``
    means the record's required entry provenance differs from the scope
    this census derives, so the evidence cannot cross this path.
    """
    required = proof.required_scope
    if required is None:
        return None
    if not _derivation_scope_bound_8616(ctx, artifact, required):
        return _CTX_SCOPE_REFUSE_8616
    return required


_CTX_SCOPE_REFUSE_8616: object = object()


def _call_boundary_proof_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    block: IRBlock,
    instruction: IRInstr,
) -> _BoundaryProof8616 | None:
    """Select the bound complete call proof for one in-path CALL row.

    The registry-bound pool serves registered caller artifacts; the
    entry-domain pool serves the in-flight callsite artifact whose own
    calls cannot carry coverage-bound proofs. Both bind the identical
    artifact, block, and instruction objects, and each candidate's
    scoped revalidation re-runs its whole retained chain under the
    authenticated consuming entry — a stale, forged, or foreign-scope
    record is refused rather than inherited.
    """
    proof = call_preservation_at_instruction_8616(
        artifact, block, instruction, ctx.call_preservations
    )
    if proof is not None:
        return proof
    if instruction.op == "CALL" and any(
        candidate is block for candidate in artifact.blocks
    ):
        # Conditional registry evidence only counts under an authenticated
        # scope: exactly one bound record must own this row, and its
        # required entry must authenticate against this derivation.
        scoped = tuple(
            proof
            for proof in ctx.call_preservations
            if proof.caller.artifact is artifact
            and proof.callsite_addr == instruction.addr
            and proof.required_scope is not None
        )
        if len(scoped) == 1:
            scope = _ctx_consuming_scope_8616(ctx, artifact, scoped[0])
            if scope is not _CTX_SCOPE_REFUSE_8616 and scoped[0].complete_for(
                cast(Real16InvocationDomain8616 | None, scope)
            ):
                return scoped[0]
    if not ctx.entry_call_preservations:
        return None
    # Deferred import: the entry-domain owner is staged against the same
    # package and loads after this module inside the importer fan-in.
    from .entry_domain_call_preservation import (
        EntryDomainCallPreservation8616,
    )

    candidates = tuple(
        record
        for record in ctx.entry_call_preservations
        if type(record) is EntryDomainCallPreservation8616
        and record.artifact is artifact
        and record.block is block
        and record.instruction is instruction
        and record.callsite_addr == instruction.addr
    )
    if len(candidates) != 1:
        return None
    record = candidates[0]
    ctx.work_units += 1
    if _census_work_exceeded_8616(ctx):
        return None
    scope = _ctx_consuming_scope_8616(ctx, artifact, record)
    if scope is _CTX_SCOPE_REFUSE_8616:
        return None
    if not record.complete_for(cast(Real16InvocationDomain8616 | None, scope)):
        return None
    return cast(_BoundaryProof8616, record)


def _declared_service_frame_8616(
    ctx: _PathCensusContext8616,
    bound: DeclaredInterruptService8616,
    registers: dict[str, int],
    artifact: IRFunctionArtifact,
) -> int | Real16InvocationFailure8616:
    """Validate the architectural INT frame span against proven SS:SP.

    The frame is a real 6-byte write below proven SP entering the same
    store ledger as every censused STORE: it must not alias the declared
    IVT slot for the vector (dispatch would be undefined) and must stay
    disjoint from every instruction byte this surface may fetch — the
    already-censused manifest and every instruction span in the artifact,
    including bytes fetched after this crossing. Returns the frame's
    linear base on success.
    """
    ss = _register_read_8616("ss", registers)
    sp = _register_read_8616("sp", registers)
    if ss is None or sp is None or sp < bound.frame_bytes:
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    frame_linear = (ss << _SEGMENT_SHIFT_8616) + (sp - bound.frame_bytes)
    frame_end = frame_linear + bound.frame_bytes
    slot_linear = bound.vector * 4
    if frame_linear < slot_linear + 4 and slot_linear < frame_end:
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    if any(
        frame_linear < start + extent and start < frame_end
        for start, extent in ctx.manifest
    ):
        return Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    for block in artifact.blocks:
        for fetched in block.instrs:
            if (
                type(fetched.addr) is int
                and type(fetched.size) is int
                and fetched.size > 0
                and frame_linear < fetched.addr + fetched.size
                and fetched.addr < frame_end
            ):
                # The frame would clobber bytes fetched later — code must
                # never share the stack frame's written span.
                return Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    entry_linear = (
        bound.ivt_entry_segment << _SEGMENT_SHIFT_8616
    ) + bound.ivt_entry_offset
    if _image_slice_8616(ctx.image, entry_linear, 1) is not None:
        # A DOS vector pointing inside the loaded module is a program-owned
        # handler, not an external declared service.
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    if (
        ctx.arena is not None
        and ctx.arena[0] <= entry_linear < ctx.arena[1]
    ):
        # The declared handler address lies inside the program's own
        # allocated arena — that is program-owned code, never DOS.
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    if ctx.arena is None:
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    return frame_linear


def _declared_service_crossing_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    instruction: IRInstr,
    registers: dict[str, int],
    memory: PathMemory8616,
) -> Real16InvocationFailure8616 | None:
    """Cross one interrupt-service boundary under an exact declared relation.

    Ordinary call rows keep the unchanged ``CALL_BOUNDARY_UNPROVEN`` verdict.
    For a CALL row that lifts to an interrupt vector, the crossing needs
    every declared input bound to *proven* state: AH/AL constants at the
    callsite equal to the declared function/selector, exactly one
    structurally valid relation naming this caller head, callsite, vector
    and the identical environment digest, and a proven SS/SP whose
    architectural INT frame span is disjoint from every fetched byte and
    from the declared IVT slot. The declared DOS entry must lie outside the
    loaded module bytes. A bound resize relation (``bound.resize``) commits
    through the canonical allocator model — proven ES/BX/AX inputs, current
    MCB bytes, register/CF effects and the metadata write — instead of a
    declared answer triple. On success the canonical answer is applied
    through the lane model — ``eax``/``ebx``/``ecx`` upper halves are
    invalidated — every lane the relation does not declare written or
    preserved is dropped, and the consumption is recorded on the census.
    Anything insufficient refuses; a declaration never proves itself.
    """
    vector = interrupt_call_vector_8616(instruction)
    if vector is None:
        return Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    if instruction.addr is None:
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    ah = _register_read_8616("ah", registers)
    al = _register_read_8616("al", registers)
    if ah is None or al is None:
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    bound = service_relation_for_8616(
        ctx.declared_services,
        caller_addr=artifact.function_addr,
        callsite_addr=instruction.addr,
        vector=vector,
        function=ah,
        selector=al,
        environment_sha256=ctx.environment_digest,
        environment=ctx.environment,
    )
    if type(bound) is not DeclaredInterruptService8616:
        return (
            Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
            if bound is DeclaredInterruptRefusal8616.RELATION_ABSENT
            else Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
        )
    if _declared_ivt_revoked_8616(memory, bound.vector):
        # Any path may have written the declared slot's bytes: the live
        # IVT may differ from the declared initial layout, so the
        # declared dispatch evidence is revoked — even when the stored
        # value was unknown.
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    if bound.resize is not None:
        return _declared_resize_service_apply_8616(
            ctx, bound, bound.resize, registers, artifact, memory
        )
    frame_linear = _declared_service_frame_8616(
        ctx, bound, registers, artifact
    )
    if isinstance(frame_linear, Real16InvocationFailure8616):
        return frame_linear
    _declared_version_service_apply_8616(
        ctx, bound, registers, frame_linear, memory
    )
    return None


def _declared_version_service_apply_8616(
    ctx: _PathCensusContext8616,
    bound: DeclaredInterruptService8616,
    registers: dict[str, int],
    frame_linear: int,
    memory: PathMemory8616,
) -> None:
    """Commit one declared version crossing under the bound relation.

    The architectural frame joins the path's memory overlay (span proven,
    contents unmodeled), the declared answer triple is applied through
    the lane model — containing lanes keep no false constant — and every
    lane the relation neither writes nor declares preserved drops to
    unknown.
    """
    # The architectural frame is a real write: it joins the path overlay
    # exactly like a censused STORE so later evidence sees the six
    # written bytes rather than stale initial memory. Its contents are
    # never modeled — the overlay marks the span modified-unproven.
    memory.apply_write(frame_linear, bound.frame_bytes, None)
    ctx.checked_stores += 1
    ctx.service_consumptions.append(
        declared_service_consumption_8616(bound, frame_linear=frame_linear)
    )
    dirty: set[str] = set()
    for name, answer in (
        ("ax", bound.answer_ax),
        ("bx", bound.answer_bx),
        ("cx", bound.answer_cx),
    ):
        _apply_register_write_8616(name, 2, answer, registers, dirty)
    accounted = (*bound.preserved, "ax", "bx", "cx")
    for name in tuple(registers):
        covered = any(
            register_value_projection_8616(lane, name) is not None
            for lane in accounted
        )
        if not covered:
            # An unaccounted lane loses its constant honestly rather than
            # surviving on an undeclared preservation claim.
            del registers[name]


def _declared_ivt_revoked_8616(
    memory: PathMemory8616, vector: int
) -> bool:
    """Return whether any path may have written the declared IVT slot.

    Conservative over the path overlay: a byte provably written on every
    path (``known``), a byte possibly modified on some path or with
    unproven contents (``unknown``), and any unbounded write boundary
    (``tainted``) all revoke the declared initial-layout evidence — the
    live IVT may differ from the declared slot, so the declared dispatch
    evidence is revoked even when the stored value was never proven.
    """
    if memory.tainted:
        return True
    slot_linear = vector * 4
    return any(
        byte in memory.known or byte in memory.unknown
        for byte in range(slot_linear, slot_linear + 4)
    )


def _resize_current_metadata_8616(
    memory: PathMemory8616,
    surface: DeclaredResizeSurface8616,
) -> bytes | None:
    """Recompute the current MCB bytes at a declared resize boundary.

    Reads the *path's* must-meet byte overlay, never a visitation-order
    ledger: a byte provably written on every path supplies its proven
    value, a byte possibly modified or content-unproven leaves the
    metadata incomplete, and an unmodified byte keeps the declared
    initial value. ``None`` means the current metadata is incomplete:
    the canonical owner is never fed guessed bytes.
    """
    if memory.tainted:
        return None
    mcb = bytearray(surface.metadata)
    for offset in range(len(mcb)):
        byte_addr = surface.metadata_linear + offset
        if byte_addr in memory.known:
            mcb[offset] = memory.known[byte_addr]
        elif byte_addr in memory.unknown:
            return None
    return bytes(mcb)


def _resize_metadata_write_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    bound: DeclaredInterruptService8616,
    surface: DeclaredResizeSurface8616,
    current: bytes,
    updated: bytes,
    memory: PathMemory8616,
) -> Real16InvocationFailure8616 | None:
    """Serialize the canonical MCB write into the path's memory overlay.

    The response's replacement metadata is compared byte-for-byte; the
    exact changed span must be disjoint from every fetched byte, the
    module manifest and the declared IVT slot, then it commits to the
    path overlay with its proven bytes so a repeated resize or later
    evidence reads them rather than stale initial memory. An unchanged
    response records no write.
    """
    if updated == current:
        return None
    changed = [
        index for index in range(len(current)) if updated[index] != current[index]
    ]
    write_base = surface.metadata_linear + changed[0]
    write = updated[changed[0] : changed[-1] + 1]
    write_end = write_base + len(write)
    for start, extent in ctx.manifest:
        if write_base < start + extent and start < write_end:
            return Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    for block in artifact.blocks:
        for fetched in block.instrs:
            if (
                type(fetched.addr) is int
                and type(fetched.size) is int
                and fetched.size > 0
                and write_base < fetched.addr + fetched.size
                and fetched.addr < write_end
            ):
                return Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    slot_linear = bound.vector * 4
    if write_base < slot_linear + 4 and slot_linear < write_end:
        # The modeled metadata write would land on the declared
        # dispatch slot — outside the declared service semantics.
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    memory.apply_write(write_base, len(write), write)
    ctx.checked_stores += 1
    return None


def _resize_register_effects_8616(
    bound: DeclaredInterruptService8616,
    response_ax: int,
    response_bx: int,
    carry: bool,
    registers: dict[str, int],
) -> None:
    """Apply the canonical AX/BX/CF effects through the lane model.

    ``ax``/``bx`` lane writes keep their proven high halves through the
    family model — containing lanes (``eax``/``ebx``) lose the constant
    honestly. The canonical contract writes only the carry flag: when a
    flag lane is proven it is rewritten with CF applied and every other
    bit preserved; when it is not, it stays unknown rather than surviving
    on an undeclared preservation claim. Any lane the relation neither
    writes nor declares preserved drops to unknown.
    """
    dirty: set[str] = set()
    _apply_register_write_8616("ax", 2, response_ax, registers, dirty)
    _apply_register_write_8616("bx", 2, response_bx, registers, dirty)
    accounted = (*bound.preserved, "ax", "bx")
    eflags = _register_read_8616("eflags", registers)
    flags = _register_read_8616("flags", registers)
    if eflags is not None:
        _apply_register_write_8616(
            "eflags", 4, (eflags & ~1) | int(carry), registers, dirty
        )
        accounted = (*accounted, "eflags")
    elif flags is not None:
        _apply_register_write_8616(
            "flags", 2, (flags & ~1) | int(carry), registers, dirty
        )
        accounted = (*accounted, "flags")
    for name in tuple(registers):
        covered = any(
            register_value_projection_8616(lane, name) is not None
            for lane in accounted
        )
        if not covered:
            del registers[name]


def _declared_resize_service_apply_8616(
    ctx: _PathCensusContext8616,
    bound: DeclaredInterruptService8616,
    surface: DeclaredResizeSurface8616,
    registers: dict[str, int],
    artifact: IRFunctionArtifact,
    memory: PathMemory8616,
) -> Real16InvocationFailure8616 | None:
    """Commit one declared tail-resize crossing under the bound relation.

    Requires the complete canonical input surface: proven full AX/ES/BX
    lanes, the shared frame/IVT/handler checks, the architectural frame
    disjoint from the modeled MCB, and complete *current* MCB bytes read
    from this path's must-meet overlay over the declared initial bytes —
    a repeated resize observes the previous response's metadata and an
    earlier proven store's bytes, while a byte any predecessor path left
    unproven refuses. The shared canonical owner then computes the
    response: its typed OTHER_BLOCK/CHAIN refusals refuse the crossing,
    its effects are serialized by the helpers above.
    """
    ax = _register_read_8616("ax", registers)
    es = _register_read_8616("es", registers)
    bx = _register_read_8616("bx", registers)
    if ax is None or es is None or bx is None:
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    frame_linear = _declared_service_frame_8616(
        ctx, bound, registers, artifact
    )
    if isinstance(frame_linear, Real16InvocationFailure8616):
        return frame_linear
    metadata_end = surface.metadata_linear + len(surface.metadata)
    if (
        frame_linear < metadata_end
        and surface.metadata_linear < frame_linear + bound.frame_bytes
    ):
        # The architectural entry frame would clobber modeled allocator
        # metadata — the service read could not be authenticated.
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    current = _resize_current_metadata_8616(memory, surface)
    if current is None:
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    response = resize_response_8616(
        block_segment=surface.block_segment,
        maximum=surface.maximum,
        segment=es,
        paragraphs=bx,
        ax=ax,
        metadata=current,
    )
    if isinstance(response, ResizeRefusal8616):
        # OTHER_BLOCK/CHAIN are undeclared allocator state, never a DOS
        # error result — the crossing keeps the typed refusal.
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    # The architectural frame is a real write; its contents stay unmodeled.
    memory.apply_write(frame_linear, bound.frame_bytes, None)
    ctx.checked_stores += 1
    failure = _resize_metadata_write_8616(
        ctx, artifact, bound, surface, current, response.metadata, memory
    )
    if failure is not None:
        return failure
    ctx.service_consumptions.append(
        declared_resize_consumption_8616(
            bound,
            frame_linear=frame_linear,
            request_ax=ax,
            answer_ax=response.ax,
            answer_bx=response.bx,
            carry=response.carry,
            metadata_before=current,
            metadata_after=response.metadata,
        )
    )
    _resize_register_effects_8616(
        bound, response.ax, response.bx, response.carry, registers
    )
    return None


def _cross_call_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    block: IRBlock,
    instruction: IRInstr,
    registers: dict[str, int],
    memory: PathMemory8616,
) -> Real16InvocationFailure8616 | None:
    """Close one interior CALL boundary or the proved callsite itself."""
    if ctx.callsite_addr is None:
        # Callee scope: admitted callees are leaf, so any nested CALL is an
        # uncensused callee-write boundary.
        return Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
    if instruction.addr == ctx.callsite_addr:
        # The proven callsite: its own stack push was already censused as a
        # STORE row. The register and memory state at this row — after that
        # machine instruction's push effects — is the callee's exact entry
        # state; retain both so a CALL_CHAINED premise can transport the
        # identical state, then the callee the call reaches is bound by
        # the discharge check.
        ctx.callsite_call_state = dict(registers)
        ctx.callsite_memory = memory.copy()
        registers.clear()
        return None
    proof = _call_boundary_proof_8616(ctx, artifact, block, instruction)
    if proof is None:
        # No near-call boundary proof binds this row: either it lifts to an
        # interrupt vector — where exactly one declared service relation may
        # carry it — or it keeps the unchanged unproven-call verdict.
        return _declared_service_crossing_8616(
            ctx, artifact, instruction, registers, memory
        )
    callee = proof.callee
    # Reauthenticate the consuming entry at the use itself: the projection
    # may only be read under the scope the census derives.
    scope = _ctx_consuming_scope_8616(ctx, artifact, proof)
    if (
        scope is _CTX_SCOPE_REFUSE_8616
        or not proof.complete_for(cast(Real16InvocationDomain8616 | None, scope))
        or type(callee) is not SegmentEffectClosureResult8616
        or type(callee.coverage.artifact) is not IRFunctionArtifact
    ):
        return Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    preserved_scope = cast(Real16InvocationDomain8616 | None, scope)
    if "cs" not in proof.preserved_registers_for(preserved_scope):
        return Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    callee_addr = callee.coverage.artifact.function_addr
    window_base = ctx.selector << _SEGMENT_SHIFT_8616
    if not window_base <= callee_addr <= window_base + _WORD_LIMIT_8616:
        return Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    callee_exits = _simulate_callee_8616(
        ctx, proof, _PathState8616(dict(registers), memory.copy())
    )
    if isinstance(callee_exits, Real16InvocationFailure8616):
        return callee_exits
    preserved = set(proof.preserved_registers_for(preserved_scope))
    for name in tuple(registers):
        if name not in preserved:
            del registers[name]
    registers.update(_post_call_registers_8616(callee, callee_exits))
    memory.assign(_post_call_memory_8616(callee, callee_exits))
    return None


def _post_call_registers_8616(
    callee: SegmentEffectClosureResult8616,
    callee_exits: dict[int, _PathState8616],
) -> dict[str, int]:
    """Return the bound callee's must-met post-return continuation state.

    The post-call ``sp`` is not a preservation claim: it is the bound
    callee's own simulated return state, met must-style across every
    return exit. An empty map — the caller key stays dropped and later
    stack rows refuse honestly — when the callee has no return blocks,
    when a return exit carried no ``sp``, or when the exits disagree.
    """
    if not callee.return_block_addrs:
        return {}
    if any(
        return_addr not in callee_exits
        or "sp" not in callee_exits[return_addr].registers
        for return_addr in callee.return_block_addrs
    ):
        return {}
    sp = _meet_registers_8616(
        [
            callee_exits[return_addr].registers
            for return_addr in callee.return_block_addrs
        ]
    ).get("sp")
    return {"sp": sp} if type(sp) is int else {}


def _post_call_memory_8616(
    callee: SegmentEffectClosureResult8616,
    callee_exits: dict[int, _PathState8616],
) -> PathMemory8616:
    """Return the bound callee's must-met post-return memory overlay.

    Mirrors the register rule: the caller-visible memory after the call
    is the must-meet of every proven return exit — a byte some return
    path leaves unproven, and a callee that never provably returns at
    all, both degrade to the fully unproven overlay rather than keeping
    stale pre-call bytes.
    """
    if not callee.return_block_addrs or any(
        return_addr not in callee_exits
        for return_addr in callee.return_block_addrs
    ):
        return path_memory_tainted_8616()
    return meet_path_memory_8616(
        callee_exits[return_addr].memory
        for return_addr in callee.return_block_addrs
    )


def _census_callee_bytes_8616(
    ctx: _PathCensusContext8616,
    proof: _BoundaryProof8616,
) -> Real16InvocationFailure8616 | None:
    """Append a complete leaf callee's fetched bytes to the manifest.

    Byte census is seed-independent, so it runs once per callee identity
    before path simulation: caller stores that execute before a call are
    still checked against bytes the callee will fetch.
    """
    callee = proof.callee
    if type(callee) is not SegmentEffectClosureResult8616:
        return Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
    artifact = callee.coverage.artifact
    if not isinstance(artifact, IRFunctionArtifact):
        return Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
    callee_addr = artifact.function_addr
    if callee_addr in ctx.censused_callees:
        return None
    native = _native_effect_blocks_8616(ctx, callee.coverage.boundary)
    if isinstance(native, Real16InvocationFailure8616):
        # Census-level refusal: no row was classified, so the row ledger
        # stays untouched — the typed failure is the report.
        return native
    ctx.native_blocks[callee_addr] = native
    for block in sorted(artifact.blocks, key=lambda entry: entry.addr):
        failure = _census_block_bytes_8616(
            ctx, block, stop_after=None, boundary=callee.coverage.boundary,
        )
        if failure is not None:
            return failure
    ctx.censused_callees.add(callee_addr)
    return None


def _simulate_callee_8616(
    ctx: _PathCensusContext8616,
    proof: _BoundaryProof8616,
    seed: _PathState8616,
) -> dict[int, _PathState8616] | Real16InvocationFailure8616:
    """Census a complete leaf callee's raw effects under the call state.

    The preservation result guarantees a leaf (no nested calls). Callee
    fetched bytes were already appended to the shared manifest by
    ``_census_callee_bytes_8616`` before path simulation began. The seed
    carries the caller's live register *and* memory overlay — the callee
    sees the bytes the caller provably wrote, and its own stores must
    meet back into the caller's continuation under the identical must
    discipline. On success the callee's own per-block exit states are
    returned: the post-call continuation state is evidence the bound
    simulation computed, never a caller-side guess.
    """
    callee = proof.callee
    if type(callee) is not SegmentEffectClosureResult8616:
        return Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
    artifact = callee.coverage.artifact
    if not isinstance(artifact, IRFunctionArtifact):
        return Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
    return _simulate_scope_8616(
        ctx,
        artifact,
        frozenset(block.addr for block in artifact.blocks),
        artifact.function_addr,
        seed,
        stop_after=None,
        callsite_addr=None,
    )


def _refuse_unbound_block_rows_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    block: IRBlock,
    stop_after: int | None,
) -> None:
    """Stage every in-scope row of an unbound block as classified-refused.

    Binding runs before any effect materializes, so the rejected block's
    rows never enter ``materialized_facts``; each row the simulation loop
    would have visited is still a classified census fact whose admission
    was refused, contributing exactly one ledger failure apiece — keeping
    ``classified == materialized + failures`` closed. Rows past
    ``stop_after`` or without an integer address mirror the simulation
    loop's own boundary and are never staged. The earliest staged row
    also records the census's first refusal site: these are real
    classified refusals, so the diagnostic names the exact instruction
    whose block failed native binding.
    """
    for index, instruction in enumerate(block.instrs):
        if type(instruction.addr) is not int:
            break
        if stop_after is not None and instruction.addr > stop_after:
            break
        row = (block.addr, index)
        ctx.raw_facts.add(row)
        ctx.normalized_facts.add(row)
        ctx.classified_facts.add(row)
        ctx.materialized_facts.discard(row)
        ctx.failures += 1
        _record_first_failure_site_8616(ctx, artifact, block, instruction)


def _apply_repeated_store_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
    registers: dict[str, int], memory: PathMemory8616, direction: bool | None,
    *, count_store: bool = True,
) -> tuple[RepeatedStoreStatus8616, Real16InvocationFailure8616 | None]:
    """Bind and consume one whole REP effect, including all fetched-byte checks."""
    encoded = ctx.machine_bytes.get(block.addr)
    if encoded is None:
        return RepeatedStoreStatus8616.NOT_APPLICABLE, None
    repeat = native_repeated_store_8616(ctx.project, block, encoded)
    if repeat is None:
        return RepeatedStoreStatus8616.NOT_APPLICABLE, None
    native = ctx.native_blocks.get(artifact.function_addr, {}).get(block.addr)
    if not _native_block_bound_8616(native, block):
        return RepeatedStoreStatus8616.REFUSED, Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    effect = repeated_store_effect_8616(repeat, registers, direction)
    if effect is None:
        return RepeatedStoreStatus8616.REFUSED, Real16InvocationFailure8616.STORE_ADDRESS_UNPROVEN
    ctx.work_units += effect.size + len(block.instrs) + 1
    if _census_work_exceeded_8616(ctx):
        return RepeatedStoreStatus8616.REFUSED, Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
    if time.monotonic() > ctx.deadline:
        return RepeatedStoreStatus8616.REFUSED, Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
    if effect.size and any(effect.base < start + size and start < effect.base + effect.size for start, size in ctx.manifest):
        return RepeatedStoreStatus8616.REFUSED, Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    memory.apply_write(effect.base, effect.size, effect.data)
    if effect.size:
        if count_store:
            ctx.checked_stores += 1
        assert effect.final_di is not None
        _apply_register_write_8616("di", 2, effect.final_di, registers, set())
    _apply_register_write_8616("cx", 2, 0, registers, set())
    return RepeatedStoreStatus8616.APPLIED, None


def _record_repeated_store_rows_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
    failure: Real16InvocationFailure8616 | None,
) -> None:
    """Close the row ledger for a native instruction consumed as one effect."""
    for index, instruction in enumerate(block.instrs):
        row = (block.addr, index)
        ctx.raw_facts.add(row)
        ctx.normalized_facts.add(row)
        ctx.classified_facts.add(row)
        if failure is None:
            ctx.materialized_facts.add(row)
        else:
            ctx.materialized_facts.discard(row)
            ctx.failures += 1
            _record_first_failure_site_8616(ctx, artifact, block, instruction)


def _simulate_path_block_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    block: IRBlock,
    entry: _PathState8616,
    *,
    stop_after: int | None,
) -> _PathState8616 | Real16InvocationFailure8616:
    """Bind then simulate one block's ordered effects; return exit state."""
    if time.monotonic() > ctx.deadline:
        return Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
    ctx.work_units += len(block.instrs) + 1
    if _census_work_exceeded_8616(ctx):
        return Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
    native_blocks = ctx.native_blocks.get(artifact.function_addr)
    native_block = (
        None if native_blocks is None else native_blocks.get(block.addr)
    )
    if not _native_block_bound_8616(native_block, block):
        # Binding precedes materialization: the simulated rows must be
        # exactly what the authoritative importer re-derives from the
        # fetched native bytes. Inserted, deleted, reordered, or
        # operand/capture-tampered rows — including rows carrying a
        # copied origin tag or mutated ``compare=False`` capture ids —
        # diverge from the re-derived block and can never prove a native
        # effect. The block's in-scope rows are real census rows, so each
        # is classified and individually refused to keep the ledger
        # closed rather than retaining phantom materializations.
        _refuse_unbound_block_rows_8616(ctx, artifact, block, stop_after)
        return Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    registers = dict(entry.registers)
    memory = entry.memory.copy()
    status, failure = _apply_repeated_store_8616(
        ctx, artifact, block, registers, memory, entry.direction,
    )
    if status is not RepeatedStoreStatus8616.NOT_APPLICABLE:
        _record_repeated_store_rows_8616(ctx, artifact, block, failure)
        return failure if failure is not None else _PathState8616(registers, memory, entry.direction)
    direction = DirectionTracker8616(registers, entry.direction)
    tmps: dict[int, int] = {}
    dirty: set[str] = set()
    instruction_entry = dict(registers)
    current_addr: int | None = None
    for index, instruction in enumerate(block.instrs):
        if type(instruction.addr) is not int:
            return Real16InvocationFailure8616.PATH_DECODE_MISMATCH
        if stop_after is not None and instruction.addr > stop_after:
            break
        if instruction.addr != current_addr:
            current_addr = instruction.addr
            instruction_entry = dict(registers)
            dirty = set()
        failure = _simulate_instruction_8616(
            ctx, artifact, block, instruction,
            registers, tmps, instruction_entry, dirty, memory,
            (block.addr, index),
        )
        if failure is not None:
            return failure
        direction.step(instruction, registers, tmps)
    return _PathState8616(registers, memory, direction.direction())


def _simulate_scope_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    scope: frozenset[int],
    head: int,
    seed: _PathState8616,
    *,
    stop_after: int | None,
    callsite_addr: int | None,
    infeasible_edges: frozenset[tuple[int, int]] = frozenset(),
) -> dict[int, _PathState8616] | Real16InvocationFailure8616:
    """Fixpoint-simulate every in-scope block's effects under the seed.

    Returns the per-block exit state map on success so a callee-scope
    caller can recover the bound callee's proven return state; a typed
    refusal otherwise. Only the authenticated root census supplies
    ``infeasible_edges``; nested callee scopes keep the empty default and
    never inherit unrelated root pruning from the shared context.

    Register facts *and* memory bytes join must-style (kept only when
    every contributing predecessor exit agrees), so loops and
    alternative paths degrade to explicit refusals instead of guessed
    constants — a STORE on one branch can never be hidden by another
    branch's overwrite order because visitation order is not execution
    order. The head's entry is the meet of ``seed`` *and every in-scope
    predecessor exit* — backedges included — so a loop-carried mutation
    (``push`` shrinking ``sp``, a store rewriting metadata) removes the
    carried constant instead of resurrecting the seed. A non-head block
    waits until at least one predecessor exit exists; chaotic iteration
    then converges to the must-fixpoint. Every scope block must be
    simulated at least once: an unvisited block's effects were never
    checked.
    """
    blocks_by_addr = {block.addr: block for block in artifact.blocks}
    predecessor_map = build_x86_16_ir_predecessor_map(artifact)
    entries: dict[int, _PathState8616] = {}
    exits: dict[int, _PathState8616] = {}
    scope_callsite = ctx.callsite_addr
    ctx.callsite_addr = callsite_addr
    try:
        for _ in range(_PATH_STATE_ITERATION_LIMIT_8616):
            if time.monotonic() > ctx.deadline:
                return Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
            changed = False
            for addr in sorted(scope):
                predecessors = [
                    pred for pred in predecessor_map.get(addr, ())
                    if pred in scope and (pred, addr) not in infeasible_edges
                ]
                if addr == head:
                    entry = _meet_path_state_8616(
                        [
                            _PathState8616(
                                dict(seed.registers), seed.memory, seed.direction
                            )
                        ]
                        + [exits[pred] for pred in predecessors if pred in exits]
                    )
                else:
                    ready = [exits[pred] for pred in predecessors if pred in exits]
                    if predecessors and not ready:
                        # No predecessor exit exists yet; simulating under
                        # an empty state would poison the meet. Wait a
                        # round — exits only grow, so this starves only
                        # for blocks no in-scope path can reach, which the
                        # exits check below then refuses.
                        continue
                    entry = _meet_path_state_8616(ready)
                if entries.get(addr) == entry and addr in exits:
                    continue
                entries[addr] = entry
                block = blocks_by_addr[addr]
                stop = stop_after if addr == ctx.stop_block_addr else None
                exit_state = _simulate_path_block_8616(
                    ctx, artifact, block, entry, stop_after=stop
                )
                if isinstance(exit_state, Real16InvocationFailure8616):
                    return exit_state
                exits[addr] = exit_state
                changed = True
            if not changed:
                break
        else:
            return Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
    finally:
        ctx.callsite_addr = scope_callsite
    if any(addr not in exits for addr in scope):
        return Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
    return exits


def _invocation_seed_8616(evidence: _BootEvidence8616) -> dict[str, int]:
    """Return the initialized invocation register state for the path."""
    seed = dict(evidence.register_seed)
    seed["cs"] = evidence.entry_segment
    seed["ss"] = evidence.stack_segment
    seed["sp"] = evidence.stack_offset
    return seed


def _feasibility_apply_service_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    instruction: IRInstr,
    registers: dict[str, int],
    memory: PathMemory8616,
) -> bool:
    """Apply a declared interrupt-service answer for edge feasibility.

    Runs the identical authenticated crossing — relation binding, IVT
    slot, architectural frame disjointness, arena exclusion, *current*
    metadata recompute — against a scratch census ledger, so the scratch
    consumption never enters the real receipts. ``memory`` is the
    feasibility pass's own must-meet overlay: the crossing reads the
    metadata this path actually wrote, never initial bytes after a
    store, and its modeled writes commit back so a second service sees
    them. The crossing mutates ``registers`` and ``memory`` in place;
    its work is charged back to the shared budget. ``True`` means the
    declared lanes were applied; ``False`` means the crossing refused
    and the caller must conservatively drop the state — the real census
    will refuse the same row honestly if the block stays live.
    """
    before = ctx.work_units
    scratch = replace(
        ctx,
        service_consumptions=[],
        callsite_call_state=None,
        callsite_memory=None,
        first_failure_site=None,
        edge_feasibility=None,
    )
    result = _declared_service_crossing_8616(
        scratch, artifact, instruction, registers, memory
    )
    ctx.work_units += scratch.work_units - before
    return result is None


def _census_invocation_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    dangerous: frozenset[int],
    call_block: IRBlock,
    callsite_addr: int,
    seed: _PathState8616,
) -> Real16InvocationFailure8616 | None:
    """Run the full root-to-callsite raw-effect census in three phases.

    Phase 0 re-derives the artifact's native blocks through the
    authoritative importer so every simulated row is bound to the fetched
    bytes rather than to census addresses alone. Phase 1 decodes and
    byte-binds every fetched instruction on the path. Phase 1b appends
    every provably-complete leaf callee's fetched bytes — and binds its
    native rows the same way — so caller stores are also disjoint from
    bytes fetched across the call. Phase 2 simulates every in-path block
    under ``seed`` — the initialized invocation state for a boot-rooted
    premise, or the transported call-row state for a chained one — and
    requires each raw STORE to be exactly evaluated and disjoint from the
    whole fetched-byte manifest.
    """
    native = _native_effect_blocks_8616(ctx, boundary)
    if isinstance(native, Real16InvocationFailure8616):
        # Census-level refusal: no row was classified, so the row ledger
        # stays untouched — the typed failure is the report.
        return native
    ctx.native_blocks[artifact.function_addr] = native
    blocks_by_addr = {block.addr: block for block in artifact.blocks}
    for addr in sorted(dangerous):
        if time.monotonic() > ctx.deadline:
            return Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
        block = blocks_by_addr[addr]
        failure = _census_block_bytes_8616(
            ctx, block, stop_after=callsite_addr if block is call_block else None,
            boundary=boundary,
        )
        if failure is not None:
            return failure
    # Invocation-local edge feasibility: a proven-infeasible branch edge
    # removes its unreachable tail from the call/effect obligations below.
    # Byte binding above stays over the full syntactic cone, and the row
    # ledger in the simulation phases keeps every still-live row closed —
    # pruning only skips obligations for blocks no converged must-state
    # can reach. An unproven edge changes nothing.
    load_rows = {
        id(row): (row, native_row)
        for addr in dangerous
        if _native_block_bound_8616(native.get(addr), blocks_by_addr[addr])
        for row, native_row in zip(blocks_by_addr[addr].instrs, native[addr].instrs, strict=True)
        if row.op == "LOAD"
    }

    def read_load(
        instruction: IRInstr, span: tuple[int, int] | None, memory: PathMemory8616,
    ) -> int | None:
        """Bind native LOAD identity before publishing any feasibility constant."""
        pair = load_rows.get(id(instruction))
        if pair is None or pair[0] is not instruction or not _native_instr_equal_8616(instruction, pair[1], 0):
            return None
        return path_load_value_8616(instruction, span, memory, ctx.initial_memory)

    def apply_repeat(
        block: IRBlock, registers: dict[str, int], memory: PathMemory8616,
        direction: bool | None,
    ) -> RepeatedStoreStatus8616:
        """Consume the identical source-bound repeat before any edge pruning."""
        status, _ = _apply_repeated_store_8616(ctx, artifact, block, registers, memory, direction, count_store=False)
        return status

    ctx.edge_feasibility = invocation_feasible_scope_8616(
        artifact=artifact,
        dangerous=dangerous,
        predecessor_map=build_x86_16_ir_predecessor_map(artifact),
        head_addr=artifact.function_addr,
        call_block_addr=call_block.addr,
        callsite_addr=callsite_addr,
        seed=seed.registers,
        seed_memory=seed.memory,
        read_load=read_load,
        apply_repeat=apply_repeat,
        apply_service=(
            lambda instruction, registers, memory: (
                _feasibility_apply_service_8616(
                    ctx, artifact, instruction, registers, memory
                )
            )
        ),
        iteration_limit=_PATH_STATE_ITERATION_LIMIT_8616,
        deadline=ctx.deadline,
        work_limit=max(0, ctx.work_limit - ctx.work_units),
    )
    ctx.work_units += ctx.edge_feasibility.work_units
    live = ctx.edge_feasibility.live_blocks
    failure = _census_path_callees_8616(ctx, artifact, blocks_by_addr, live, callsite_addr)
    if failure is not None:
        return failure
    exits = _simulate_scope_8616(
        ctx,
        artifact,
        live,
        artifact.function_addr,
        seed,
        stop_after=callsite_addr,
        callsite_addr=callsite_addr,
        infeasible_edges=frozenset(ctx.edge_feasibility.infeasible_edges),
    )
    if isinstance(exits, Real16InvocationFailure8616):
        return exits
    return None


def _census_path_callees_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    blocks_by_addr: dict[int, IRBlock],
    dangerous: frozenset[int],
    callsite_addr: int,
) -> Real16InvocationFailure8616 | None:
    """Bind the fetched-byte manifest of each authenticated interior callee."""
    for addr in sorted(dangerous):
        for instruction in blocks_by_addr[addr].instrs:
            if instruction.op != "CALL" or instruction.addr == callsite_addr:
                continue
            proof = _call_boundary_proof_8616(
                ctx,
                artifact,
                blocks_by_addr[addr],
                instruction,
            )
            if proof is None:
                continue
            scope = _ctx_consuming_scope_8616(ctx, artifact, proof)
            if scope is _CTX_SCOPE_REFUSE_8616 or not proof.complete_for(
                cast(Real16InvocationDomain8616 | None, scope)
            ):
                continue
            failure = _census_callee_bytes_8616(ctx, proof)
            if failure is not None:
                return failure
    return None


def _census_counts_8616(ctx: _PathCensusContext8616) -> tuple[int, int, int, int, int]:
    """Return the actual five-stage census counts from the context."""
    return (
        len(ctx.raw_facts),
        len(ctx.normalized_facts),
        len(ctx.classified_facts),
        len(ctx.materialized_facts),
        ctx.failures,
    )


@dataclass(frozen=True, slots=True)
class Real16CallChainLink8616:
    """Retained transport edge from a parent premise's proved callsite
    into a chained callee-head domain.

    A link binds every replayable witness needed to reproduce the
    parent's path to its proven callsite and to cross that exact edge:

    - ``parent`` — the complete invocation premise whose census reached
      ``callsite_addr`` inside ``callsite_artifact``;
    - ``callsite_index`` — the retained project callsite index that
      materialized ``callsite``;
    - ``callsite`` — the exact decoded direct near-call row inside the
      parent artifact (``caller_start`` is the parent head, and the row
      must be indexed under the callee head's normalized identity);
    - ``callsite_artifact`` / ``callsite_boundary`` — the identical IR
      artifact and boundary objects the parent premise censused;
    - ``call_state`` — the callsite-row register state the parent census
      captured (after the call's own push rows), replayable as the
      callee-head entry state;
    - ``callee_artifact`` / ``callee_boundary`` — the identical artifact
      and boundary objects the chained census runs over.

    ``complete`` replays the parent premise and re-runs the structural
    identity checks; the full capture-equality check happens inside
    derivation because it requires the parent's replayed census state.
    The link is evidence for exactly one edge — it is never a general
    statement about the callee under other entries.
    """

    parent: Real16InvocationDomain8616
    callsite_index: DecodedDirectCallsiteIndex8616
    callsite: DecodedDirectCallsite8616
    callsite_artifact: IRFunctionArtifact
    callsite_boundary: ExactFunctionRangeBoundary8616
    call_state: tuple[tuple[str, int], ...]
    callee_artifact: IRFunctionArtifact
    callee_boundary: ExactFunctionRangeBoundary8616
    edge: object | None = None

    @property
    def complete(self) -> bool:
        """Replay the parent premise and re-check the retained identities.

        The replayed-capture equality against ``call_state`` is enforced
        by derivation itself; this check re-runs the parent proof and
        confirms every retained object identity still binds the same
        caller edge and callee head.
        """
        parent = self.parent
        if (
            type(parent) is not Real16InvocationDomain8616
            or not parent.complete
            or parent.coverage is None
        ):
            return False
        if (
            self.callsite_artifact is not parent.coverage.artifact
            or self.callsite_boundary is not parent.coverage.boundary
        ):
            return False
        if type(self.callsite_index) is not DecodedDirectCallsiteIndex8616:
            return False
        if not self.callsite_index.stats.closed:
            return False
        callsite = self.callsite
        if type(callsite) is not DecodedDirectCallsite8616 or callsite.is_far:
            return False
        if (
            callsite.callsite_addr != parent.callsite_addr
            or callsite.caller_start != parent.coverage.artifact.function_addr
        ):
            return False
        callee_artifact = self.callee_artifact
        callee_boundary = self.callee_boundary
        if (
            type(callee_artifact) is not IRFunctionArtifact
            or not isinstance(callee_boundary, ExactFunctionRangeBoundary8616)
            or callee_boundary.project is not parent.project
            or callee_boundary.addr != callee_artifact.function_addr
        ):
            return False
        if not _bound_callsite_entry_8616(
            parent, self.callsite_index, callsite, callee_artifact.function_addr,
        ):
            return False
        if not _chain_edge_bound_8616(
            parent,
            parent.coverage.artifact,
            callee_artifact.function_addr,
            self.edge,
        ):
            return False
        return _transported_call_state_8616(self.call_state) is not None


@dataclass(frozen=True, slots=True)
class Real16EnclosedEntryLink8616:
    """Retained transport edge into an *enclosing* entry, not the callee head.

    A chained premise requires the decoded near-call row to land on the
    callee head itself. Real binaries also enter a function through an
    enclosing entry — an alignment/NOP pad or a shared prefix the decoded
    ``call`` target actually names — whose own closed boundary contains
    the whole callee artifact. A link therefore binds two surfaces:

    - the caller edge: ``parent`` premise, retained index row
      ``callsite``, the identical caller ``callsite_artifact`` /
      ``callsite_boundary`` the parent censused, and the captured
      ``call_state`` transported to the destination decoded from the row's bytes;
    - the enclosing surface: ``enclosing_artifact`` /
      ``enclosing_boundary`` rooted *exactly* at that encoded destination,
      whose closed CFG and instruction census must contain the enclosed
      callee head and every callee block;
    - the enclosed anchor: ``callee_artifact`` / ``callee_boundary`` — the
      identical objects the consuming artifact surface carries, never a
      re-derived look-alike.

    The path census runs over the enclosing surface: the transported
    state enters at the enclosing head and every in-boundary path to the
    callsite — including the fallthrough into the enclosed head — is
    proven under the identical fetched-code/code-write closure. The
    enclosed anchor is what ``real16_invocation_discharges_8616`` binds
    the consumed block to; it plays no role in the census itself.

    ``complete`` replays the parent premise and re-runs every structural
    identity and enclosure check; the capture-equality replay happens
    inside derivation because it needs the parent's replayed census. The
    link is evidence for exactly one edge and one enclosing boundary —
    it is never a general statement about the callee under other entries.
    """

    parent: Real16InvocationDomain8616
    callsite_index: DecodedDirectCallsiteIndex8616
    callsite: DecodedDirectCallsite8616
    callsite_artifact: IRFunctionArtifact
    callsite_boundary: ExactFunctionRangeBoundary8616
    call_state: tuple[tuple[str, int], ...]
    enclosing_artifact: IRFunctionArtifact
    enclosing_boundary: ExactFunctionRangeBoundary8616
    callee_artifact: IRFunctionArtifact
    callee_boundary: ExactFunctionRangeBoundary8616
    edge: object | None = None

    @property
    def complete(self) -> bool:
        """Replay the parent premise and re-check every retained identity.

        The replayed-capture equality against ``call_state`` is enforced
        by derivation itself; this check re-runs the parent proof and
        confirms every retained object identity still binds the same
        caller edge, the same enclosing root, and the same enclosed head.
        """
        parent = self.parent
        if not _enclosed_parent_bound_8616(self):
            return False
        callsite = self.callsite
        enclosing_artifact = self.enclosing_artifact
        enclosing_boundary = self.enclosing_boundary
        if (
            type(enclosing_artifact) is not IRFunctionArtifact
            or type(enclosing_boundary)
            is not ExactFunctionRangeBoundary8616
            or enclosing_boundary.project is not parent.project
            or enclosing_boundary.addr != enclosing_artifact.function_addr
        ):
            return False
        if not _enclosed_surface_bound_8616(
            enclosing_boundary, self.callee_artifact, self.callee_boundary
        ):
            return False
        if not _bound_callsite_entry_8616(
            parent, self.callsite_index, callsite, enclosing_boundary.addr,
        ):
            return False
        if not _chain_edge_bound_8616(
            parent,
            self.callsite_artifact,
            enclosing_boundary.addr,
            self.edge,
        ):
            return False
        return _transported_call_state_8616(self.call_state) is not None


def _enclosed_parent_bound_8616(
    link: Real16EnclosedEntryLink8616,
) -> bool:
    """Re-check the retained parent premise and callsite row identity.

    The parent must still prove complete coverage over the identical
    callsite artifact/boundary pair, the index must remain a closed
    decoded index, and the retained row must be the exact in-index row
    at the parent's proven callsite inside the parent's proven head.
    """
    parent = link.parent
    if (
        type(parent) is not Real16InvocationDomain8616
        or not parent.complete
        or parent.coverage is None
    ):
        return False
    if (
        link.callsite_artifact is not parent.coverage.artifact
        or link.callsite_boundary is not parent.coverage.boundary
    ):
        return False
    if (
        type(link.callsite_index) is not DecodedDirectCallsiteIndex8616
        or not link.callsite_index.stats.closed
    ):
        return False
    callsite = link.callsite
    if type(callsite) is not DecodedDirectCallsite8616 or callsite.is_far:
        return False
    return (
        callsite.callsite_addr == parent.callsite_addr
        and callsite.caller_start == parent.coverage.artifact.function_addr
    )



def _bound_callsite_entry_8616(
    parent: Real16InvocationDomain8616,
    index: DecodedDirectCallsiteIndex8616,
    callsite: DecodedDirectCallsite8616,
    entry: int,
) -> bool:
    """Bind lookup membership and execution target to the parent's native CALL.

    A normalized lookup row cannot certify entry after an unexecuted prefix.
    A counterfeit index cannot replace bytes from the parent's native census.
    The caller separately replays the parent against its source-bound boot.
    """
    if parent.coverage is None:
        return False
    encoded = callsite.bound_near_coordinates(parent.coverage.boundary)
    return (
        encoded is not None and encoded[1] == entry
        and any(row is callsite for row in index.for_target(callsite.target_addr))
    )


def _enclosed_surface_bound_8616(
    enclosing_boundary: ExactFunctionRangeBoundary8616,
    callee_artifact: object,
    callee_boundary: object,
) -> bool:
    """Prove the callee surface is strictly enclosed by the boundary.

    The enclosed head must sit strictly inside the enclosing boundary —
    the enclosing root is the decoded edge target, never the callee head
    itself — and every decoded callee instruction must belong to the
    enclosing boundary's closed reachable instruction census, so the
    enclosing path proof actually covers the consumed surface.
    Instruction-level containment is required because the enclosing
    decode partitions its pad prefix and the callee head into blocks by
    its own control flow; a block-identity subset test would refuse a
    genuinely enclosing surface whose first block merely spans the
    fallthrough into the callee head. Both objects must be the owned
    typed records on the same project.
    """
    if (
        type(callee_artifact) is not IRFunctionArtifact
        or type(callee_boundary) is not ExactFunctionRangeBoundary8616
        or callee_boundary.project is not enclosing_boundary.project
        or callee_boundary.addr != callee_artifact.function_addr
        or callee_artifact.function_addr == enclosing_boundary.addr
    ):
        return False
    reachable = enclosing_boundary.reachable_instruction_addrs
    if callee_artifact.function_addr not in reachable:
        return False
    return (
        bool(callee_boundary.reachable_instruction_addrs)
        and callee_boundary.reachable_instruction_addrs <= reachable
    )


def _edge_proof_bound_8616(
    proof: object,
    callsite_artifact: IRFunctionArtifact,
    callsite_addr: int,
    callee_head: int,
    consuming_scope: Real16InvocationDomain8616 | None,
) -> bool:
    """Return whether one retained record binds this exact call edge.

    A bound edge proof must be complete under the consuming entry,
    anchored on the identical callsite artifact and callsite row, point
    at the proved callee head, and retain the exact ``"cs"`` identity —
    otherwise it is not evidence for this chain.
    """
    callee: object = None
    if type(proof) is SegmentCallPreservationResult8616:
        if proof.caller.artifact is not callsite_artifact:
            return False
        callee = proof.callee
    else:
        from .entry_domain_call_preservation import (
            EntryDomainCallPreservation8616,
        )

        if type(proof) is not EntryDomainCallPreservation8616:
            return False
        if proof.artifact is not callsite_artifact:
            return False
        callee = proof.callee
    if proof.callsite_addr != callsite_addr:
        return False
    if not proof.complete_for(consuming_scope):
        return False
    if "cs" not in proof.preserved_registers_for(consuming_scope):
        return False
    return bool(
        type(callee) is SegmentEffectClosureResult8616
        and type(callee.coverage.artifact) is IRFunctionArtifact
        and callee.coverage.artifact.function_addr == callee_head
    )


def _chain_edge_bound_8616(
    parent: Real16InvocationDomain8616,
    callsite_artifact: IRFunctionArtifact,
    callee_head: int,
    edge: object | None,
) -> bool:
    """Enforce the retained-edge proof rule for the parent callsite.

    Any evidence the caller supplies — the link's retained ``edge`` or
    any pool record sitting on the edge callsite — must be a complete
    bound proof retaining ``"cs"`` into the proved callee head; stale or
    refused records cannot be omitted to bypass the check. When no bound
    proof exists at all — the in-flight case, where the callee cannot
    yet carry a registry-bound closure — the decoded near-call row plus
    the parent census's replayed capture is sufficient: a chained premise
    claims only the callee *entry* state, and a near ``CALL`` transports
    CS unchanged by machine semantics.
    """
    pools: tuple[object, ...] = (
        *parent.call_preservations,
        *parent.entry_call_preservations,
    )
    found: list[object] = []
    for proof in pools:
        if type(proof) is SegmentCallPreservationResult8616:
            if proof.caller.artifact is not callsite_artifact:
                continue
        else:
            from .entry_domain_call_preservation import (
                EntryDomainCallPreservation8616,
            )

            if type(proof) is not EntryDomainCallPreservation8616:
                continue
            if proof.artifact is not callsite_artifact:
                continue
        if proof.callsite_addr == parent.callsite_addr:
            found.append(proof)
    if edge is not None and not _edge_proof_bound_8616(
        edge, callsite_artifact, parent.callsite_addr, callee_head, parent
    ):
        return False
    return all(
        _edge_proof_bound_8616(
            proof, callsite_artifact, parent.callsite_addr, callee_head, parent
        )
        for proof in found
    )


def _transported_call_state_8616(
    state: tuple[tuple[str, int], ...],
) -> dict[str, int] | None:
    """Normalize a retained call-row state into a seed map or ``None``.

    Every retained row must be a ``(name, word)`` pair; ``cs`` and ``sp``
    are mandatory because the transported premise cannot prove a selector
    or stack window without them.
    """
    registers: dict[str, int] = {}
    for item in state:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not int
            or not 0 <= item[1] <= _WORD_LIMIT_8616
        ):
            return None
        registers[item[0]] = item[1]
    if "cs" not in registers or "sp" not in registers:
        return None
    return registers


def _chain_link_identity_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    chain: Real16CallChainLink8616,
) -> Real16InvocationFailure8616 | None:
    """Bind the retained link's static identities before any replay.

    Every identity in the link must be the exact retained object: the
    typed parent premise with its coverage, the identical caller artifact
    and boundary objects the parent censused, the closed typed index, the
    exact decoded near-call row, the identical callee artifact/boundary
    under proof, index membership under the callee head's normalized
    identity, and the bound-edge proof rule. Any divergence refuses
    ``chain_link_unproven``.
    """
    parent = chain.parent
    if (
        type(parent) is not Real16InvocationDomain8616
        or parent.project is not project
        or parent.coverage is None
    ):
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    parent_artifact = parent.coverage.artifact
    if (
        chain.callsite_artifact is not parent_artifact
        or chain.callsite_boundary is not parent.coverage.boundary
    ):
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    if (
        type(chain.callsite_index) is not DecodedDirectCallsiteIndex8616
        or not chain.callsite_index.stats.closed
    ):
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    callsite = chain.callsite
    if type(callsite) is not DecodedDirectCallsite8616 or callsite.is_far:
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    if (
        callsite.callsite_addr != parent.callsite_addr
        or callsite.caller_start != parent_artifact.function_addr
    ):
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    if (
        chain.callee_artifact is not artifact
        or chain.callee_boundary is not boundary
    ):
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    # Lookup membership alone cannot prove the executed destination. Bind
    # the retained encoding to the parent census and require exact entry.
    if not _bound_callsite_entry_8616(
        parent, chain.callsite_index, callsite, artifact.function_addr,
    ):
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    if not _chain_edge_bound_8616(
        parent, parent_artifact, artifact.function_addr, chain.edge
    ):
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    return None


def _chain_link_seed_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    chain: Real16CallChainLink8616,
    chain_depth: int,
) -> (
    tuple[dict[str, int], PathMemory8616]
    | Real16InvocationFailure8616
    | _NestedRefusal8616
):
    """Validate one retained chain edge and return the transported seed.

    Every leg of the edge is independently replayed: the parent premise
    is re-derived in full (including its own chain, recursively, under
    the shared depth bound), the retained callsite row must be the exact
    row the retained index materialized under the callee head's proven
    target identity, the parent-side artifact and boundary must be the
    identical objects the parent premise censused, the callee side must
    be the identical artifact/boundary under proof, a complete bound call
    proof retaining ``"cs"`` must cover the edge, and the retained
    ``call_state`` must equal the state the replayed parent census
    captured at the exact callsite row. Any divergence refuses
    ``chain_link_unproven``; nothing about the callee entry is assumed.
    """
    if _chain_link_depth_exceeded_8616(chain_depth):
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    identity_failure = _chain_link_identity_8616(
        project, artifact, boundary, chain
    )
    if identity_failure is not None:
        return identity_failure
    parent = chain.parent
    retained_state = _transported_call_state_8616(chain.call_state)
    if retained_state is None:
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    derived = _derive_invocation_domain_8616(
        project,
        parent.coverage,
        parent.callsite_addr,
        parent.boot,
        parent.boot_recompute,
        parent.call_preservations,
        chain=parent.chain,
        entry_call_preservations=parent.entry_call_preservations,
        declared_services=parent.declared_services,
        chain_depth=chain_depth + 1,
    )
    if derived.failure is not None or derived.domain is None:
        return _NestedRefusal8616(
            Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN,
            derived.refusal_site,
        )
    replayed = derived.domain
    if not _replayed_domain_equal_8616(derived, parent):
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    captured = dict(replayed.callsite_call_state)
    if captured != retained_state:
        # A retained state that disagrees with the freshly replayed
        # capture is forged or stale evidence, never a valid seed.
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    if captured["cs"] != parent.entry_segment:
        # The captured call-row CS must be exactly the selector the
        # parent premise proved; anything else means the path state
        # diverged from the premise's own claim.
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    if replayed.callsite_memory is None:
        # The replayed census reached the callsite without a captured
        # memory overlay — the transported seed cannot pretend initial
        # bytes.
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    # Memory transports from the *freshly replayed* capture, never a
    # retained field: the replayed equality above binds it to the same
    # callsite row the registers were captured at.
    return captured, restore_path_memory_8616(replayed.callsite_memory)


def _chain_link_depth_exceeded_8616(chain_depth: int) -> bool:
    """Return whether the recursive chain replay exceeded its bound."""
    return chain_depth >= _CHAIN_DEPTH_LIMIT_8616


def _enclosed_link_identity_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    link: Real16EnclosedEntryLink8616,
) -> Real16InvocationFailure8616 | None:
    """Bind the retained enclosed link's identities before any replay.

    The census surface is the *enclosing* pair: it must be the identical
    objects the link retains, rooted exactly at the destination decoded from
    the row's native bytes, and the enclosed callee pair must sit strictly inside
    that closed boundary. Every other leg — parent premise, typed index,
    exact near row, bound-edge proof — matches the chained rule. Any
    divergence refuses ``enclosed_link_unproven``.
    """
    parent = link.parent
    if (
        type(parent) is not Real16InvocationDomain8616
        or parent.project is not project
        or parent.coverage is None
    ):
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    parent_artifact = parent.coverage.artifact
    if (
        link.callsite_artifact is not parent_artifact
        or link.callsite_boundary is not parent.coverage.boundary
    ):
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    if (
        type(link.callsite_index) is not DecodedDirectCallsiteIndex8616
        or not link.callsite_index.stats.closed
    ):
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    callsite = link.callsite
    if type(callsite) is not DecodedDirectCallsite8616 or callsite.is_far:
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    if (
        callsite.callsite_addr != parent.callsite_addr
        or callsite.caller_start != parent_artifact.function_addr
    ):
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    if (
        link.enclosing_artifact is not artifact
        or link.enclosing_boundary is not boundary
        or boundary.addr != artifact.function_addr
    ):
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    if not _enclosed_surface_bound_8616(
        boundary, link.callee_artifact, link.callee_boundary
    ):
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    # Bind the indexed row to native bytes before transporting the prefix;
    # normalized lookup identities cannot replace its execution destination.
    if not _bound_callsite_entry_8616(
        parent, link.callsite_index, callsite, boundary.addr,
    ):
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    if not _chain_edge_bound_8616(
        parent, parent_artifact, boundary.addr, link.edge
    ):
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    return None


def _enclosed_link_seed_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    link: Real16EnclosedEntryLink8616,
    chain_depth: int,
) -> (
    tuple[dict[str, int], PathMemory8616]
    | Real16InvocationFailure8616
    | _NestedRefusal8616
):
    """Validate one retained enclosed edge and return the transported seed.

    The replay contract is the chained one verbatim — the parent premise
    re-derives in full under the shared depth bound, the retained row must
    be the exact index row for the enclosing head, and the captured
    call-row state must equal the replayed capture — plus the enclosing
    obligations: identical census surface, edge target equal to the
    enclosing root, and the enclosed callee provably inside the boundary.
    Any divergence refuses ``enclosed_link_unproven``; nothing about the
    enclosed entry is assumed.
    """
    if _chain_link_depth_exceeded_8616(chain_depth):
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    identity_failure = _enclosed_link_identity_8616(
        project, artifact, boundary, link
    )
    if identity_failure is not None:
        return identity_failure
    parent = link.parent
    retained_state = _transported_call_state_8616(link.call_state)
    if retained_state is None:
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    derived = _derive_invocation_domain_8616(
        project,
        parent.coverage,
        parent.callsite_addr,
        parent.boot,
        parent.boot_recompute,
        parent.call_preservations,
        chain=parent.chain,
        entry_call_preservations=parent.entry_call_preservations,
        declared_services=parent.declared_services,
        chain_depth=chain_depth + 1,
    )
    if derived.failure is not None or derived.domain is None:
        return _NestedRefusal8616(
            Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN,
            derived.refusal_site,
        )
    replayed = derived.domain
    if not _replayed_domain_equal_8616(derived, parent):
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    captured = dict(replayed.callsite_call_state)
    if captured != retained_state:
        # A retained state that disagrees with the freshly replayed
        # capture is forged or stale evidence, never a valid seed.
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    if captured["cs"] != parent.entry_segment:
        # The captured call-row CS must be exactly the selector the
        # parent premise proved; anything else means the path state
        # diverged from the premise's own claim.
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    if replayed.callsite_memory is None:
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    return captured, restore_path_memory_8616(replayed.callsite_memory)


def _replayed_domain_equal_8616(
    derived: _Derivation8616,
    domain: Real16InvocationDomain8616,
) -> bool:
    """Return whether a fresh derivation reproduces the retained domain."""
    replayed = derived.domain
    return (
        replayed is not None
        and replayed.minimum_selector == domain.minimum_selector
        and replayed.maximum_selector == domain.maximum_selector
        and replayed.entry_segment == domain.entry_segment
        and replayed.entry_offset == domain.entry_offset
        and replayed.stack_segment == domain.stack_segment
        and replayed.stack_offset == domain.stack_offset
        and replayed.load_segment == domain.load_segment
        and replayed.source_sha256 == domain.source_sha256
        and replayed.path_block_addrs == tuple(domain.path_block_addrs)
        and replayed.fetched_range_count == domain.fetched_range_count
        and replayed.checked_store_count == domain.checked_store_count
        and replayed.assumptions == domain.assumptions
        and replayed.callsite_call_state == tuple(domain.callsite_call_state)
        and replayed.callsite_memory == domain.callsite_memory
        and replayed.service_consumptions == tuple(domain.service_consumptions)
        and derived.raw_fact_count == domain.raw_fact_count
        and derived.normalized_fact_count == domain.normalized_fact_count
        and derived.classified_fact_count == domain.classified_fact_count
        and derived.materialized_count == domain.materialized_count
        and derived.failure_count == domain.failure_count
        and domain.materialized_count == domain.classified_fact_count
        and domain.classified_fact_count > 0
    )


def _derive_census_surface_8616(
    coverage: IRBoundaryCoverageResult8616 | None,
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | None,
) -> (
    tuple[IRFunctionArtifact, ExactFunctionRangeBoundary8616]
    | Real16InvocationFailure8616
):
    """Resolve the identical artifact/boundary pair this census consumes.

    Complete registry-bound coverage is the ordinary surface for a
    boot-rooted derivation. A retained link names two pairs: the *census
    surface* the path proof actually runs over — the callee pair for a
    ``CALL_CHAINED`` link, the enclosing pair for an ``ENCLOSED_ENTRY``
    link — and the *anchor pair* — always the callee pair — that a
    supplied coverage must bind when present. An enclosed parent's
    coverage therefore certifies the registered callee surface the next
    link's callsite side consumes, while its census still runs over the
    identical enclosing pair. In-flight callsite artifacts cannot
    produce registry-owned coverage, so a link's exact census objects
    anchor identity instead — the closed-CFG plus instruction-census
    checks bind them to the binary the same way coverage would. Anything
    else is ``coverage_unbound`` or, for a mismatched coverage/link
    pair, the link's own typed refusal.
    """
    surface_artifact: object = None
    surface_boundary: object = None
    anchor_artifact: object = None
    anchor_boundary: object = None
    link_failure: Real16InvocationFailure8616 | None = None
    if type(chain) is Real16CallChainLink8616:
        surface_artifact = chain.callee_artifact
        surface_boundary = chain.callee_boundary
        anchor_artifact = chain.callee_artifact
        anchor_boundary = chain.callee_boundary
        link_failure = Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    elif type(chain) is Real16EnclosedEntryLink8616:
        surface_artifact = chain.enclosing_artifact
        surface_boundary = chain.enclosing_boundary
        anchor_artifact = chain.callee_artifact
        anchor_boundary = chain.callee_boundary
        link_failure = Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    elif chain is not None:
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    if (
        coverage is not None
        and isinstance(coverage, IRBoundaryCoverageResult8616)
        and coverage.complete
    ):
        if chain is not None and (
            coverage.artifact is not anchor_artifact
            or coverage.boundary is not anchor_boundary
        ):
            # A supplied coverage must bind the link's anchor pair — the
            # identical callee surface — never the enclosing census
            # surface or a foreign look-alike.
            return (
                link_failure
                or Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
            )
        if chain is None:
            return coverage.artifact, coverage.boundary
    if chain is not None and link_failure is not None:
        candidate_artifact = surface_artifact
        candidate_boundary = surface_boundary
        if (
            not isinstance(candidate_artifact, IRFunctionArtifact)
            or not isinstance(
                candidate_boundary, ExactFunctionRangeBoundary8616
            )
            or not closed_ir_boundary_cfg_8616(
                candidate_boundary, candidate_artifact
            )
            or not _instruction_census_matches_8616(
                candidate_boundary, candidate_artifact
            )
        ):
            return Real16InvocationFailure8616.COVERAGE_UNBOUND
        return candidate_artifact, candidate_boundary
    return Real16InvocationFailure8616.COVERAGE_UNBOUND


def _invocation_entry_seed_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    evidence: _BootEvidence8616,
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | None,
    chain_depth: int,
) -> (
    tuple[
        int,
        _PathState8616,
        int,
        int,
        int,
        int,
        tuple[Real16InvocationAssumption8616, ...],
    ]
    | Real16InvocationFailure8616
    | _NestedRefusal8616
):
    """Resolve the census selector/seed/entry coordinate for this domain.

    A ``None`` chain keeps the boot-entry rule: the source-authenticated
    MZ entry must equal the censused function head, and the seed is the
    initialized invocation state over initial memory. A retained chain
    instead replays the complete edge and seeds the transported call-row
    register state *and the replayed callsite memory overlay* — the
    callee census consumes the identical bytes the parent's callsite row
    was proven under, never a silently reset initial image; the chain
    surface head — the callee head, or the enclosing head for an
    ``ENCLOSED_ENTRY`` link — must sit inside the transported selector's
    addressable band.
    """
    if chain is None:
        if evidence.entry_linear != artifact.function_addr:
            return Real16InvocationFailure8616.ENTRY_NOT_FUNCTION_HEAD
        return (
            evidence.entry_segment,
            _PathState8616(
                _invocation_seed_8616(evidence), path_memory_initial_8616()
            ),
            evidence.entry_segment,
            evidence.entry_offset,
            evidence.stack_segment,
            evidence.stack_offset,
            evidence.entry_assumptions,
        )
    if boundary.addr != artifact.function_addr:
        return Real16InvocationFailure8616.ENTRY_NOT_FUNCTION_HEAD
    if type(chain) is Real16CallChainLink8616:
        seed = _chain_link_seed_8616(
            project, artifact, boundary, chain, chain_depth
        )
        if isinstance(seed, _NestedRefusal8616 | Real16InvocationFailure8616):
            return seed
        assumption = Real16InvocationAssumption8616.CHAINED_CALL_ENTRY
        link_failure = Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    elif type(chain) is Real16EnclosedEntryLink8616:
        seed = _enclosed_link_seed_8616(
            project, artifact, boundary, chain, chain_depth
        )
        if isinstance(seed, _NestedRefusal8616 | Real16InvocationFailure8616):
            return seed
        assumption = Real16InvocationAssumption8616.ENCLOSED_ENTRY
        link_failure = Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    else:
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    seed_registers, seed_memory = seed
    selector = seed_registers["cs"]
    entry_offset = artifact.function_addr - (selector << _SEGMENT_SHIFT_8616)
    if not 0 <= entry_offset <= _WORD_LIMIT_8616 or "ss" not in seed_registers:
        return link_failure
    return (
        selector,
        _PathState8616(seed_registers, seed_memory),
        selector,
        entry_offset,
        seed_registers["ss"],
        seed_registers["sp"],
        (*chain.parent.assumptions, assumption),
    )


def _service_assumption_8616(
    assumptions: tuple[Real16InvocationAssumption8616, ...],
    consumptions: tuple[DeclaredServiceConsumption8616 | DeclaredResizeConsumption8616, ...],
) -> tuple[Real16InvocationAssumption8616, ...]:
    """Mark the consumed declared-service evidence on the proven premise."""
    if not consumptions:
        return assumptions
    return (
        *assumptions,
        Real16InvocationAssumption8616.DECLARED_INTERRUPT_SERVICE,
    )


def _derive_invocation_domain_8616(
    project: object,
    coverage: IRBoundaryCoverageResult8616 | None,
    callsite_addr: int,
    boot: object,
    boot_recompute: Callable[[object], object] | None,
    call_preservations: tuple[SegmentCallPreservationResult8616, ...],
    *,
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | None = None,
    entry_call_preservations: tuple[object, ...] = (),
    declared_services: tuple[DeclaredInterruptService8616, ...] = (),
    chain_depth: int = 0,
) -> _Derivation8616:
    """Keep all nested domain derivations inside one shared replay budget."""
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    with segment_call_dependency_traversal_scope_8616():
        if time.monotonic() > _census_deadline_8616():
            return _early_derivation_8616(Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED)
        return _derive_invocation_domain_body_8616(
            project, coverage, callsite_addr, boot, boot_recompute, call_preservations,
            chain=chain, entry_call_preservations=entry_call_preservations,
            declared_services=declared_services,
            chain_depth=chain_depth,
        )


def _seeded_refusal_derivation_8616(
    seeded: Real16InvocationFailure8616 | _NestedRefusal8616,
) -> _Derivation8616:
    """Project a refused entry-seed union into a typed derivation.

    A link-seed refusal may carry the nested replay's real census site;
    surface it rather than collapsing to a bare enum. A plain
    ``Real16InvocationFailure8616`` is a structural refusal with no row
    site. Callers must pass only the refusal members of the seed union.
    """
    if isinstance(seeded, _NestedRefusal8616):
        return _early_derivation_8616(
            seeded.failure, refusal_site=seeded.refusal_site
        )
    return _early_derivation_8616(seeded)


def _derive_invocation_domain_body_8616(
    project: object,
    coverage: IRBoundaryCoverageResult8616 | None,
    callsite_addr: int,
    boot: object,
    boot_recompute: Callable[[object], object] | None,
    call_preservations: tuple[SegmentCallPreservationResult8616, ...],
    *,
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | None = None,
    entry_call_preservations: tuple[object, ...] = (),
    declared_services: tuple[DeclaredInterruptService8616, ...] = (),
    chain_depth: int = 0,
) -> _Derivation8616:
    """Derive the exact CS selector domain, or a typed refusal + counts.

    A ``None`` chain derives the boot-entry premise exactly as before: the
    source-authenticated MZ entry must be the censused function head. A
    retained chain instead validates the complete edge — parent premise,
    exact callsite row, caller/callee identities, bound ``"cs"`` call
    proof, replayed capture — and seeds the identical census from the
    transported call-row state. The census surface is the link's callee
    pair for ``CALL_CHAINED`` or its enclosing pair for
    ``ENCLOSED_ENTRY``.
    """
    surface = _derive_census_surface_8616(coverage, chain)
    if isinstance(surface, Real16InvocationFailure8616):
        return _early_derivation_8616(surface)
    artifact, boundary = surface
    if boundary.project is not project:
        return _early_derivation_8616(Real16InvocationFailure8616.PROJECT_MISMATCH)
    if callsite_addr not in boundary.reachable_instruction_addrs:
        return _early_derivation_8616(Real16InvocationFailure8616.CALLSITE_UNREACHABLE)
    evidence = _invocation_boot_evidence_8616(boot)
    if isinstance(evidence, Real16InvocationFailure8616):
        return _early_derivation_8616(evidence)
    failure = _recompute_boot_8616(boot, boot_recompute)
    if failure is not None:
        return _early_derivation_8616(failure)
    if (
        hashlib.sha256(evidence.source).hexdigest()
        != evidence.image.file_sha256
    ):
        return _early_derivation_8616(Real16InvocationFailure8616.BOOT_NOT_REPRODUCED)
    seeded = _invocation_entry_seed_8616(
        project, artifact, boundary, evidence, chain, chain_depth
    )
    if isinstance(seeded, _NestedRefusal8616 | Real16InvocationFailure8616):
        return _seeded_refusal_derivation_8616(seeded)
    (
        selector,
        seed,
        entry_segment,
        entry_offset,
        stack_segment,
        stack_offset,
        assumptions,
    ) = seeded
    call_block = _callsite_block_8616(artifact, callsite_addr)
    if isinstance(call_block, Real16InvocationFailure8616):
        return _early_derivation_8616(call_block)
    dangerous = _dangerous_block_addrs_8616(artifact, call_block)
    ctx = _PathCensusContext8616(
        project=project,
        selector=selector,
        initial_memory=invocation_initial_memory_8616(
            evidence.environment, evidence.environment_digest, evidence.image.chunks
        ),
        image=evidence.image,
        boot=boot,
        chain=chain,
        call_preservations=call_preservations,
        entry_call_preservations=entry_call_preservations,
        declared_services=declared_services,
        environment_digest=evidence.environment_digest,
        environment=evidence.environment,
        arena=evidence.arena,
        service_consumptions=[],
        stop_block_addr=call_block.addr,
        callsite_addr=callsite_addr,
        callsite_call_state=None,
        callsite_memory=None,
        manifest=[],
        machine_bytes={},
        native_blocks={},
        checked_stores=0,
        censused_callees=set(),
        raw_facts=set(),
        normalized_facts=set(),
        classified_facts=set(),
        materialized_facts=set(),
        failures=0,
        work_units=0,
        work_limit=_CENSUS_WORK_LIMIT_8616,
        deadline=_census_deadline_8616(),
        first_failure_site=None,
    )
    failure = _census_invocation_8616(
        ctx, artifact, boundary, dangerous, call_block, callsite_addr, seed
    )
    (
        raw_fact_count,
        normalized_fact_count,
        classified_fact_count,
        materialized_count,
        failure_count,
    ) = _census_counts_8616(ctx)
    if failure is not None:
        return _Derivation8616(
            domain=None,
            failure=failure,
            raw_fact_count=raw_fact_count,
            normalized_fact_count=normalized_fact_count,
            classified_fact_count=classified_fact_count,
            materialized_count=materialized_count,
            failure_count=failure_count,
            refusal_site=ctx.first_failure_site,
            infeasible_edges=(
                ()
                if ctx.edge_feasibility is None
                else ctx.edge_feasibility.infeasible_edges
            ),
        )
    consumptions = tuple(ctx.service_consumptions)
    assumptions = _service_assumption_8616(assumptions, consumptions)
    path_blocks = (
        dangerous
        if ctx.edge_feasibility is None
        else ctx.edge_feasibility.live_blocks
    )
    return _Derivation8616(
        domain=_DerivedDomain8616(
            minimum_selector=selector,
            maximum_selector=selector,
            entry_segment=entry_segment,
            entry_offset=entry_offset,
            stack_segment=stack_segment,
            stack_offset=stack_offset,
            load_segment=evidence.load_segment,
            source_sha256=evidence.image.file_sha256,
            path_block_addrs=tuple(sorted(path_blocks)),
            fetched_range_count=len(ctx.manifest),
            checked_store_count=ctx.checked_stores,
            assumptions=assumptions,
            callsite_artifact=artifact,
            callsite_boundary=boundary,
            callsite_call_state=(
                ()
                if ctx.callsite_call_state is None
                else tuple(sorted(ctx.callsite_call_state.items()))
            ),
            callsite_memory=(
                None
                if ctx.callsite_memory is None
                else snapshot_path_memory_8616(ctx.callsite_memory)
            ),
            service_consumptions=consumptions,
            infeasible_edges=(
                ()
                if ctx.edge_feasibility is None
                else ctx.edge_feasibility.infeasible_edges
            ),
        ),
        failure=None,
        raw_fact_count=raw_fact_count,
        normalized_fact_count=normalized_fact_count,
        classified_fact_count=classified_fact_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
    )


def _service_consumption_dict_8616(
    consumption: DeclaredServiceConsumption8616 | DeclaredResizeConsumption8616,
) -> dict[str, object]:
    """Serialize one consumed declared-service record with its kind tag."""
    if isinstance(consumption, DeclaredServiceConsumption8616):
        return {
            "kind": "version",
            "callsite_addr": consumption.callsite_addr,
            "vector": consumption.vector,
            "function": consumption.function,
            "selector": consumption.selector,
            "answer_ax": consumption.answer_ax,
            "answer_bx": consumption.answer_bx,
            "answer_cx": consumption.answer_cx,
            "frame_linear": consumption.frame_linear,
            "frame_bytes": consumption.frame_bytes,
            "relation_sha256": consumption.relation_sha256,
        }
    return {
        "kind": "resize",
        "callsite_addr": consumption.callsite_addr,
        "vector": consumption.vector,
        "function": consumption.function,
        "request_ax": consumption.request_ax,
        "answer_ax": consumption.answer_ax,
        "answer_bx": consumption.answer_bx,
        "carry": consumption.carry,
        "metadata_linear": consumption.metadata_linear,
        "metadata_before_hex": consumption.metadata_before.hex(),
        "metadata_after_hex": consumption.metadata_after.hex(),
        "frame_linear": consumption.frame_linear,
        "frame_bytes": consumption.frame_bytes,
        "relation_sha256": consumption.relation_sha256,
    }


@dataclass(frozen=True, slots=True)
class Real16InvocationDomain8616:
    """A typed, immutable, invocation-local proof of one CS domain.

    Retained state is exactly what is required to replay the proof:
    identity-bound ``project`` and ``coverage``, the authentic ``boot``
    object with its recompute authority, the callsite, and the derived
    domain plus the checked path block census. ``complete`` re-derives
    everything; consumption goes through
    ``real16_invocation_discharges_8616``.
    """

    coverage: IRBoundaryCoverageResult8616 | None
    boot: object | None
    boot_recompute: Callable[[object], object] | None = field(compare=False)
    callsite_addr: int
    entry_segment: int
    entry_offset: int
    stack_segment: int
    stack_offset: int
    load_segment: int
    source_sha256: str
    minimum_selector: int
    maximum_selector: int
    kind: Real16InvocationKind8616
    path_block_addrs: tuple[int, ...]
    fetched_range_count: int
    checked_store_count: int
    assumptions: tuple[Real16InvocationAssumption8616, ...]
    call_preservations: tuple[SegmentCallPreservationResult8616, ...]
    failure: Real16InvocationFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    project: object = field(compare=False, repr=False)
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | None = field(
        default=None, compare=False
    )
    entry_call_preservations: tuple[object, ...] = field(
        default=(), compare=False
    )
    callsite_call_state: tuple[tuple[str, int], ...] = ()
    #: Frozen callsite-row memory overlay captured beside
    #: ``callsite_call_state``; replayed-equality transport evidence for
    #: chained and enclosed seeds.
    callsite_memory: PathMemorySnapshot8616 | None = None
    declared_services: tuple[DeclaredInterruptService8616, ...] = ()
    service_consumptions: tuple[
        DeclaredServiceConsumption8616 | DeclaredResizeConsumption8616, ...
    ] = ()
    #: The exact classified census row that first failed, when the census
    #: reached one; ``None`` on success and on structural/budget refusals
    #: that never classified a row.
    refusal_site: Real16InvocationRefusalSite8616 | None = None
    #: ``(block_addr, successor_addr)`` edges proven untraversable under
    #: this exact invocation by the converged known-bits feasibility pass.
    #: Invocation-local evidence only — never a universal dead-code claim.
    infeasible_edges: tuple[tuple[int, int], ...] = ()

    @property
    def complete(self) -> bool:
        """Replay once per shared bounded traversal; cyclic evidence refuses."""
        from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

        with segment_call_dependency_traversal_scope_8616() as traversal:
            identity = id(self)
            if identity in traversal.active_domains:
                return False
            if time.monotonic() > _census_deadline_8616():
                return False
            if identity in traversal.domain_verdicts:
                return traversal.domain_verdicts[identity]
            if traversal.remaining_domains <= 0 or len(traversal.active_domains) >= _CHAIN_DEPTH_LIMIT_8616:
                return False
            traversal.remaining_domains -= 1
            traversal.retained_domains[identity] = self
            traversal.active_domains.add(identity)
            try:
                verdict = self._replay_complete_8616()
            finally:
                traversal.active_domains.remove(identity)
            traversal.domain_verdicts[identity] = verdict
            return verdict

    def _replay_complete_8616(self) -> bool:
        """Recompute the retained domain only after entering the shared guard."""
        if self.failure is not None:
            return False
        if self.kind is Real16InvocationKind8616.BOOT_ENTRY_PATH:
            link_bound = self.chain is None
        elif self.kind is Real16InvocationKind8616.CALL_CHAINED:
            link_bound = type(self.chain) is Real16CallChainLink8616
        elif self.kind is Real16InvocationKind8616.ENCLOSED_ENTRY:
            link_bound = type(self.chain) is Real16EnclosedEntryLink8616
        else:
            link_bound = False
        if not link_bound:
            # Kind and retained edge must agree: a transported premise
            # without its retained link — or a boot premise carrying one —
            # is a forged record, not a replayable proof.
            return False
        derived = _derive_invocation_domain_8616(
            self.project,
            self.coverage,
            self.callsite_addr,
            self.boot,
            self.boot_recompute,
            self.call_preservations,
            chain=self.chain,
            entry_call_preservations=self.entry_call_preservations,
            declared_services=self.declared_services,
        )
        if derived.failure is not None or derived.domain is None:
            return False
        return _replayed_domain_equal_8616(derived, self)

    @property
    def domain_interval(self) -> tuple[int, int] | None:
        """Return the proven linear target interval or ``None``."""
        if not self.complete:
            return None
        base = self.maximum_selector << _SEGMENT_SHIFT_8616
        end = (self.minimum_selector << _SEGMENT_SHIFT_8616) + _WORD_LIMIT_8616
        return (base, end)

    def to_dict(self) -> dict[str, object]:
        """Serialize the typed proof for receipts and logging."""
        return {
            "verdict": "proven" if self.complete else "unknown_refuse",
            "failure": self.failure.value if self.failure else None,
            "refusal_site": (
                None
                if self.refusal_site is None
                else {
                    "function_addr": self.refusal_site.function_addr,
                    "block_addr": self.refusal_site.block_addr,
                    "instruction_addr": self.refusal_site.instruction_addr,
                }
            ),
            "kind": self.kind.value,
            "callsite_addr": self.callsite_addr,
            "entry_segment": self.entry_segment,
            "entry_offset": self.entry_offset,
            "stack_segment": self.stack_segment,
            "stack_offset": self.stack_offset,
            "load_segment": self.load_segment,
            "source_sha256": self.source_sha256,
            "minimum_selector": self.minimum_selector,
            "maximum_selector": self.maximum_selector,
            "path_block_addrs": list(self.path_block_addrs),
            "infeasible_edges": [list(edge) for edge in self.infeasible_edges],
            "fetched_range_count": self.fetched_range_count,
            "checked_store_count": self.checked_store_count,
            "chained": self.chain is not None,
            "callsite_call_state": dict(self.callsite_call_state),
            "callsite_memory": (
                None
                if self.callsite_memory is None
                else {
                    "known": [list(pair) for pair in self.callsite_memory.known],
                    "unknown": list(self.callsite_memory.unknown),
                    "tainted": self.callsite_memory.tainted,
                }
            ),
            "service_consumptions": [
                _service_consumption_dict_8616(consumption)
                for consumption in self.service_consumptions
            ],
            "assumptions": [assumption.value for assumption in self.assumptions],
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclass(frozen=True, slots=True)
class Real16CallInvocation8616:
    """A premise bound to one exact project/block/callsite/target use.

    ``project`` and ``block`` are retained as object-identity anchors, not
    compared by value; ``complete`` replays the premise and the binding.
    """

    premise: Real16InvocationDomain8616
    callsite_addr: int
    target_addr: int
    project: object = field(compare=False, repr=False)
    block: IRBlock = field(compare=False, repr=False)

    @property
    def complete(self) -> bool:
        """Re-validate the premise and this exact consumption binding."""
        return real16_invocation_discharges_8616(
            self.premise,
            project=self.project,
            block=self.block,
            callsite_addr=self.callsite_addr,
            target_addr=self.target_addr,
        )


def real16_invocation_discharges_8616(
    premise: Real16InvocationDomain8616 | None,
    *,
    project: object,
    block: IRBlock,
    callsite_addr: int,
    target_addr: int,
) -> bool:
    """Return whether the proven exact domain keeps ``target_addr`` fixed.

    Requires a complete premise bound to this exact callsite, the supplied
    project identity, and the calling block's membership in the retained
    artifact. The admit condition is the closed interval test: target
    invariant under the proven domain iff
    ``(maximum << 4) <= target <= (minimum << 4) + 0xFFFF``.
    """
    if premise is None or not isinstance(premise, Real16InvocationDomain8616):
        return False
    if not premise.complete:
        return False
    if premise.callsite_addr != callsite_addr:
        return False
    coverage = premise.coverage
    if coverage is not None:
        if coverage.boundary.project is not project:
            return False
        artifact = coverage.artifact
    elif premise.chain is not None:
        # Transported premises may prove an in-flight callee artifact that
        # cannot carry registry coverage; the retained link's identical
        # callee objects are the consumption anchor instead. For an
        # ``ENCLOSED_ENTRY`` link the census ran over the enclosing pair,
        # but consumption still binds the enclosed callee surface.
        if premise.chain.callee_boundary.project is not project:
            return False
        artifact = premise.chain.callee_artifact
    else:
        return False
    if not any(owner is block for owner in artifact.blocks):
        return False
    base = premise.maximum_selector << _SEGMENT_SHIFT_8616
    end = (premise.minimum_selector << _SEGMENT_SHIFT_8616) + _WORD_LIMIT_8616
    return base <= target_addr <= end


def _domain_from_derivation_8616(
    project: object,
    coverage: IRBoundaryCoverageResult8616 | None,
    callsite_addr: int,
    boot: object | None,
    boot_recompute: Callable[[object], object] | None,
    preservations: tuple[SegmentCallPreservationResult8616, ...],
    entry_preservations: tuple[object, ...],
    declared_services: tuple[DeclaredInterruptService8616, ...],
    kind: Real16InvocationKind8616,
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | None,
    derived: _Derivation8616,
) -> Real16InvocationDomain8616:
    """Project one derivation into the immutable retained premise record."""
    if derived.failure is not None or derived.domain is None:
        return Real16InvocationDomain8616(
            coverage=coverage,
            boot=boot,
            boot_recompute=boot_recompute,
            callsite_addr=callsite_addr,
            entry_segment=0,
            entry_offset=0,
            stack_segment=0,
            stack_offset=0,
            load_segment=0,
            source_sha256="",
            minimum_selector=0,
            maximum_selector=0,
            kind=kind,
            path_block_addrs=(),
            fetched_range_count=0,
            checked_store_count=0,
            assumptions=(),
            call_preservations=preservations,
            failure=(
                derived.failure
                if derived.failure is not None
                else Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
            ),
            raw_fact_count=derived.raw_fact_count,
            normalized_fact_count=derived.normalized_fact_count,
            classified_fact_count=derived.classified_fact_count,
            materialized_count=derived.materialized_count,
            failure_count=derived.failure_count,
            project=project,
            chain=chain,
            entry_call_preservations=entry_preservations,
            declared_services=declared_services,
            refusal_site=derived.refusal_site,
            infeasible_edges=derived.infeasible_edges,
        )
    domain = derived.domain
    return Real16InvocationDomain8616(
        coverage=coverage,
        boot=boot,
        boot_recompute=boot_recompute,
        callsite_addr=callsite_addr,
        entry_segment=domain.entry_segment,
        entry_offset=domain.entry_offset,
        stack_segment=domain.stack_segment,
        stack_offset=domain.stack_offset,
        load_segment=domain.load_segment,
        source_sha256=domain.source_sha256,
        minimum_selector=domain.minimum_selector,
        maximum_selector=domain.maximum_selector,
        kind=kind,
        path_block_addrs=domain.path_block_addrs,
        fetched_range_count=domain.fetched_range_count,
        checked_store_count=domain.checked_store_count,
        assumptions=domain.assumptions,
        call_preservations=preservations,
        failure=None,
        raw_fact_count=derived.raw_fact_count,
        normalized_fact_count=derived.normalized_fact_count,
        classified_fact_count=derived.classified_fact_count,
        materialized_count=derived.materialized_count,
        failure_count=derived.failure_count,
        project=project,
        chain=chain,
        entry_call_preservations=entry_preservations,
        callsite_call_state=domain.callsite_call_state,
        callsite_memory=domain.callsite_memory,
        declared_services=declared_services,
        service_consumptions=domain.service_consumptions,
        infeasible_edges=domain.infeasible_edges,
    )


def prove_real16_invocation_domain_8616(
    project: object,
    coverage: IRBoundaryCoverageResult8616 | None,
    callsite_addr: int,
    *,
    boot: object | None,
    boot_recompute: Callable[[object], object] | None,
    call_preservations: Sequence[SegmentCallPreservationResult8616] = (),
    entry_call_preservations: Sequence[object] = (),
    declared_services: Sequence[DeclaredInterruptService8616] = (),
    kind: Real16InvocationKind8616 = Real16InvocationKind8616.BOOT_ENTRY_PATH,
) -> Real16InvocationDomain8616:
    """Prove the exact invocation CS domain for one direct near CALL site.

    Authentication is recomputation: the caller's ``boot_recompute``
    authority must reconstruct an object equal to the supplied ``boot``
    before any derived number is believed. This entry point proves only
    ``BOOT_ENTRY_PATH`` premises; ``kind`` is retained as supplied for
    diagnostic records but a non-boot derivation must go through
    ``prove_real16_chained_invocation_domain_8616``.

    ``call_preservations`` is the registry-bound interior-call pool;
    ``entry_call_preservations`` is the in-flight entry-domain pool
    collected for the identical censused artifact — a boot-entry prefix
    may itself contain interior near calls whose bound evidence is the
    only sound way across. ``declared_services`` carries the caller's
    explicitly declared interrupt-service relations: each must bind an
    exact callsite, vector, proven AH/AL selectors and the identical
    declared environment before the census consumes it — conditional
    declared evidence, never a universal DOS model.
    """
    preservations = tuple(call_preservations)
    entry_preservations = tuple(entry_call_preservations)
    services = tuple(declared_services)
    derived = _derive_invocation_domain_8616(
        project,
        coverage,
        callsite_addr,
        boot,
        boot_recompute,
        preservations,
        entry_call_preservations=entry_preservations,
        declared_services=services,
    )
    return _domain_from_derivation_8616(
        project,
        coverage,
        callsite_addr,
        boot,
        boot_recompute,
        preservations,
        entry_preservations,
        services,
        kind,
        None,
        derived,
    )


def prove_real16_chained_invocation_domain_8616(
    project: object,
    coverage: IRBoundaryCoverageResult8616 | None,
    callsite_addr: int,
    *,
    boot: object | None,
    boot_recompute: Callable[[object], object] | None,
    chain: Real16CallChainLink8616 | None,
    call_preservations: Sequence[SegmentCallPreservationResult8616] = (),
    entry_call_preservations: Sequence[object] = (),
    declared_services: Sequence[DeclaredInterruptService8616] = (),
) -> Real16InvocationDomain8616:
    """Prove a callee-head CS domain transported across one bound edge.

    The retained ``chain`` must name the complete parent premise, the
    exact decoded near-call row inside the parent artifact, the identical
    caller/callee artifacts and boundaries, and the call-row register
    state the parent census captured. ``call_preservations`` is the
    registry-bound interior-call pool; ``entry_call_preservations`` is
    the in-flight entry-domain pool recorded during the same import that
    is asking for this premise — the callsite artifact may not yet be
    registered, so its interior calls cannot carry coverage-bound proofs.

    Authentication is unchanged: the boot surface is still recomputed and
    byte-bound before any derived number is believed, and the census runs
    over the identical re-derived native blocks. A ``None`` or divergent
    link refuses ``chain_link_unproven``.
    """
    preservations = tuple(call_preservations)
    entry_preservations = tuple(entry_call_preservations)
    services = tuple(declared_services)
    derived = _derive_invocation_domain_8616(
        project,
        coverage,
        callsite_addr,
        boot,
        boot_recompute,
        preservations,
        chain=chain,
        entry_call_preservations=entry_preservations,
        declared_services=services,
    )
    return _domain_from_derivation_8616(
        project,
        coverage,
        callsite_addr,
        boot,
        boot_recompute,
        preservations,
        entry_preservations,
        services,
        Real16InvocationKind8616.CALL_CHAINED,
        chain,
        derived,
    )


def prove_real16_enclosed_invocation_domain_8616(
    project: object,
    coverage: IRBoundaryCoverageResult8616 | None,
    callsite_addr: int,
    *,
    boot: object | None,
    boot_recompute: Callable[[object], object] | None,
    chain: Real16EnclosedEntryLink8616 | None,
    call_preservations: Sequence[SegmentCallPreservationResult8616] = (),
    entry_call_preservations: Sequence[object] = (),
    declared_services: Sequence[DeclaredInterruptService8616] = (),
) -> Real16InvocationDomain8616:
    """Prove a callee CS domain transported into an enclosing entry.

    The retained ``chain`` must name the complete parent premise, the
    exact decoded near-call row inside the parent artifact whose raw
    ``target_addr`` is the enclosing boundary's root, the identical
    caller/enclosing/callee surfaces, and the call-row register state the
    parent census captured. The census surface is the enclosing pair:
    ``coverage``, when supplied, must bind the identical *callee* pair —
    the registered anchor a downstream link's callsite side consumes —
    never the enclosing surface or a re-derived look-alike. An in-flight
    callee carries ``coverage=None`` and its pair anchors discharge
    through the retained link instead.

    Authentication is unchanged: the boot surface is still recomputed and
    byte-bound before any derived number is believed, and the census runs
    over the identical re-derived native blocks. A ``None`` or divergent
    link refuses ``enclosed_link_unproven``.
    """
    preservations = tuple(call_preservations)
    entry_preservations = tuple(entry_call_preservations)
    services = tuple(declared_services)
    derived = _derive_invocation_domain_8616(
        project,
        coverage,
        callsite_addr,
        boot,
        boot_recompute,
        preservations,
        chain=chain,
        entry_call_preservations=entry_preservations,
        declared_services=services,
    )
    return _domain_from_derivation_8616(
        project,
        coverage,
        callsite_addr,
        boot,
        boot_recompute,
        preservations,
        entry_preservations,
        services,
        Real16InvocationKind8616.ENCLOSED_ENTRY,
        chain,
        derived,
    )


def real16_native_census_import_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
) -> IRFunctionArtifact | None:
    """Import one boundary under the native census guard, finally-restored.

    The invocation census re-derives consumed artifacts through the
    authoritative importer *with discharge suppressed*, so a census
    surface built at link-construction time must come from the same
    guarded import or the re-derived blocks will not bind. Only named
    decode-boundary failures translate to ``None``; anything else
    propagates so census defects stay loud.
    """
    guard = cast(_CensusImportGuard8616, project)
    try:
        guard_depth = guard._inertia_real16_native_census_8616
    except AttributeError:
        guard_depth = 0
    if type(guard_depth) is not int or guard_depth < 0:
        raise TypeError("invocation census import guard must be an int")
    guard._inertia_real16_native_census_8616 = guard_depth + 1
    try:
        # Deferred: the authoritative importer is resolved at census time
        # so loading this module first cannot deadlock against the
        # package initializer.
        from .vex_import import build_x86_16_ir_function_artifact

        artifact = build_x86_16_ir_function_artifact(project, boundary)
    except _DECODE_REFUSAL_TYPES_8616:
        return None
    finally:
        guard._inertia_real16_native_census_8616 = guard_depth
    if type(artifact) is not IRFunctionArtifact:
        return None
    return artifact


def _link_scope_anchor_8616(
    left: Real16CallChainLink8616 | Real16EnclosedEntryLink8616,
    right: Real16CallChainLink8616 | Real16EnclosedEntryLink8616,
) -> bool:
    """Bind two retained transport links to the same proven edge.

    The identical decoded row and index objects anchor the edge to the
    source-authenticated callsite inventory; the identical caller and
    callee artifact objects anchor both surfaces; equal boundary, index,
    and transported call-state values bind what identity cannot. An
    enclosed link additionally binds its enclosing census pair. Object
    identity is required where the contract already demands it; equality
    is used only for value-typed witnesses two derivations legitimately
    rebuild.
    """
    if not (
        left.callsite is right.callsite
        and left.callsite_index is right.callsite_index
        and left.callsite_artifact is right.callsite_artifact
        and left.callsite_boundary == right.callsite_boundary
        and left.callee_artifact is right.callee_artifact
        and left.callee_boundary == right.callee_boundary
        and left.call_state == right.call_state
    ):
        return False
    if type(left) is Real16EnclosedEntryLink8616:
        if type(right) is not Real16EnclosedEntryLink8616:
            return False
        return (
            left.enclosing_artifact is right.enclosing_artifact
            and left.enclosing_boundary == right.enclosing_boundary
        )
    return True


def _in_flight_scopes_coterminous_8616(
    left: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | None,
    right: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | None,
    depth: int,
) -> bool:
    """Authenticate two unregistered scopes through retained transport edges.

    An in-flight surface carries no registry coverage, so its entry
    identity is the transported chain itself: two such scopes describe
    the same entry exactly when their retained links bind the same proven
    edge under ``_link_scope_anchor_8616`` and their parent scopes
    authenticate under this same contract. The parent leg still requires
    the strict registered check — separately derived chains deeper than
    the first registered parent conservatively refuse, which is the
    documented in-flight bootstrap limitation. ``depth`` bounds the
    structural recursion; exceeding it refuses rather than recursing
    without bound.
    """
    if type(left) not in (Real16CallChainLink8616, Real16EnclosedEntryLink8616):
        return False
    if type(right) not in (Real16CallChainLink8616, Real16EnclosedEntryLink8616):
        return False
    if type(right) is not type(left):
        return False
    if depth >= _CHAIN_DEPTH_LIMIT_8616:
        return False
    left_link = cast(Real16CallChainLink8616 | Real16EnclosedEntryLink8616, left)
    right_link = cast(Real16CallChainLink8616 | Real16EnclosedEntryLink8616, right)
    if not _link_scope_anchor_8616(left_link, right_link):
        return False
    return _same_scope_8616(left_link.parent, right_link.parent, depth + 1)


def _same_scope_8616(
    offered: Real16InvocationDomain8616 | None,
    required: Real16InvocationDomain8616 | None,
    depth: int,
) -> bool:
    """Authenticate shared entry provenance; selector coincidence is insufficient."""
    if required is None:
        return offered is None
    if type(offered) is not Real16InvocationDomain8616 or type(required) is not Real16InvocationDomain8616:
        return False
    if not (
        offered.project is required.project
        and offered.boot is required.boot
        and offered.boot_recompute is required.boot_recompute
        and offered.kind is required.kind
        and offered.source_sha256 == required.source_sha256
    ):
        return False
    if offered.coverage is not None and required.coverage is not None:
        # Registered scopes keep the strict retained-identity rule: the
        # same registered artifact plus the identical retained chain.
        identity = (
            offered.coverage.artifact is required.coverage.artifact
            and offered.chain is required.chain
        )
    else:
        # At least one side is an in-flight surface: the same entry
        # exists only when both transport through coterminous retained
        # links. A boot-rooted scope on either side names a different
        # provenance class and refuses.
        identity = _in_flight_scopes_coterminous_8616(
            offered.chain, required.chain, depth
        )
    return identity and offered.complete and required.complete


def same_real16_entry_scope_8616(
    offered: Real16InvocationDomain8616 | None,
    required: Real16InvocationDomain8616 | None,
) -> bool:
    """Authenticate shared entry provenance; selector coincidence is insufficient."""
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    with segment_call_dependency_traversal_scope_8616():
        return _same_scope_8616(offered, required, 0)


def real16_scope_crosses_call_8616(
    caller: Real16InvocationDomain8616 | None,
    callee: Real16InvocationDomain8616,
    coverage: IRBoundaryCoverageResult8616,
    callsite_addr: int,
) -> bool:
    """Authenticate retained caller-to-callee transport for a scoped summary.

    In-flight scopes retain their identical callee surface on the native-bound
    chain instead of universal registry coverage. The chain and domain must
    still revalidate independently; absence of coverage never supplies proof.
    A supplied coverage continues to require the exact retained callee body.
    """
    link = callee.chain
    if type(link) is not Real16CallChainLink8616:
        return False
    if callee.coverage is not None and link.callee_artifact is not callee.coverage.artifact:
        return False
    return (
        same_real16_entry_scope_8616(caller, link.parent)
        and link.parent.callsite_addr == callsite_addr
        and link.callsite_artifact is coverage.artifact
        and link.complete
        and callee.complete
    )
