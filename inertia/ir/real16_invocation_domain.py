"""Bind a source-initialized real16 invocation to one exact CS domain.

Layer: IR.
Responsibility: prove the numeric CS selector domain for one exact direct
near CALL under a single typed invocation. The admitted premise shapes are
a source-bound program boot (``BOOT_ENTRY_PATH``), a raw startup census
over an authenticated but registry-unpublished surface whose pending
terminal jump is re-proven under live path state (``RAW_BOOT_ENTRY_PATH``),
and a chained-callee
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
from typing import TYPE_CHECKING, Protocol, cast

from angr.errors import AngrError
from capstone import CsError
from pyvex.errors import PyVEXError

from inertia.frontend.real16_dosbox_int21_frame import (
    DosBoxInt21Registers8616,
    DosBoxInt21Write8616,
    dosbox_int21_frame_effects_8616,
)
from inertia.frontend.real16_resize_response8616 import ResizeRefusal8616, resize_response_8616
from inertia.frontend.real16_vector_response8616 import (
    INT21_SET_VECTOR_8616,
    VectorResponseEffect8616,
    VectorResponseRefusal8616,
    vector_response_8616,
)
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_block_inventory import decoded_block_instructions_8616
from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.frontend.x86_16.mz_invocation_source import (
    MzInvocationSource8616,
    mz_invocation_source_8616,
)
from inertia.frontend.x86_16.mz_static_boot import MzStaticBoot8616
from inertia.semantics.register_value_preservation import (
    register_value_family_8616,
    register_value_projection_8616,
)

from . import real16_edge_feasibility8616 as kb_owner_8616
from . import real16_fused_callee_transfer as fused_callee_owner_8616
from . import real16_fused_caller_prefix as caller_prefix_owner_8616
from . import real16_initial_memory8616 as initial_memory_owner_8616
from . import real16_path_memory8616 as path_memory_owner_8616
from . import real16_persistent_bytes8616 as persistent_bytes_owner_8616
from . import real16_repeated_store8616 as repeated_store_owner_8616
from . import real16_wide_multiply8616 as multiply_owner_8616
from . import scalar_instruction_effects as scalar_owner_8616
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
from .frozen_dispatch import FrozenDispatch, frozen_dispatch_lookup
from .instruction_origin import IRInstructionOrigin8616
from .ir_boundary_cfg import (
    IRBoundaryCoverageResult8616,
    _instruction_census_matches_8616,
    closed_ir_boundary_cfg_8616,
)
from .real16_boot_entry_link import (
    RawBootEntrySurface8616,
    raw_boot_entry_surface_pending_8616,
)
from .real16_census_fact_ownership import (
    CensusFactOwnership8616,
    census_fact_ownership_8616,
    census_fact_ownership_current_8616,
    new_census_fact_sets_8616,
)
from .real16_declared_interrupt8616 import (
    DeclaredInterruptRefusal8616,
    DeclaredInterruptService8616,
    DeclaredResizeConsumption8616,
    DeclaredResizeSurface8616,
    DeclaredServiceConsumption8616,
    DeclaredVectorConsumption8616,
    DeclaredVectorSurface8616,
    declared_environment_digest_8616,
    declared_memory_span_8616,
    declared_resize_consumption_8616,
    declared_service_arena_8616,
    declared_service_consumption_8616,
    declared_vector_consumption_8616,
    interrupt_call_vector_8616,
    service_relation_for_8616,
)
from .real16_dosbox_resize_effects import (
    DosboxResizeEffects8616,
    DosboxResizeEffectsRefusal8616,
    stage_dosbox_resize_effects_8616,
)
from .real16_edge_feasibility8616 import (
    BranchSnapshotReplay8616,
    DirectionTracker8616,
    LoadSnapshotReplay8616,
    Real16EdgeFeasibility8616,
    acyclic_invocation_order_8616,
    invocation_feasible_scope_8616,
    invocation_transfer_order_8616,
)
from .real16_fused_callee_transfer import (
    FusedCalleeOperations8616,
    active_fused_callee_transfer_8616,
    source_bound_callee_transfer_8616,
    try_fused_callee_transfer_8616,
)
from .real16_fused_caller_prefix import FusedCallerPrefix8616, try_fused_caller_prefix_8616
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
    repeated_store_candidate_shape_8616,
    repeated_store_effect_8616,
)
from .real16_scratch_protection import (
    CallerIntervalSelectionStatus8616,
    ScratchCallerRange8616,
    select_caller_intervals_8616,
    written_address_envelope_8616,
)
from .real16_wide_multiply8616 import wide_multiply_value_8616
from .scalar_instruction_effects import (
    ScalarInstructionClobber8616,
    ScalarInstructionEffectKind8616,
    scalar_instruction_effect_8616,
    scalar_select_result_bits_8616,
)
from .segment_call_preservation import SegmentCallPreservationResult8616
from .segment_effect_closure import SegmentEffectClosureResult8616
from .segment_state_transfer import bound_call_preservation_at_instruction_8616
from .ssa_function import build_x86_16_ir_predecessor_map

if TYPE_CHECKING:
    from inertia.frontend.x86_16.declared_function_entry import DeclaredFunctionEntryAdmission8616
    from inertia.semantics.direct_near_call_target_binding import DirectNearCallTargetBinding8616

    from .declared_selector_invariant import DeclaredSegmentInvariant
    from .native_import_surface_cache import NativeCensusSourceBinding8616


__all__ = [
    "DeclaredFunctionEntryLink8616",
    "Real16CallChainLink8616",
    "Real16CallInvocation8616",
    "Real16EnclosedEntryLink8616",
    "Real16InvocationAssumption8616",
    "Real16InvocationDomain8616",
    "Real16InvocationFailure8616",
    "Real16InvocationKind8616",
    "Real16InvocationRefusalSite8616",
    "prove_fresh_real16_chained_invocation_domain_8616",
    "prove_fresh_real16_declared_function_entry_domain_8616",
    "prove_real16_chained_invocation_domain_8616",
    "prove_real16_declared_function_entry_domain_8616",
    "prove_real16_enclosed_invocation_domain_8616",
    "prove_real16_invocation_domain_8616",
    "prove_real16_raw_boot_invocation_domain_8616",
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
_CENSUS_DEADLINE_SECONDS_8616 = 40.0
_OWNED_CALLEE_ORDER_8616: Callable[..., kb_owner_8616.Real16InvocationOrder8616] = acyclic_invocation_order_8616
_CALLEE_ORDER_ADVICE_LIMIT_8616: int = 64
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

    DECLARED_ENTRY_UNPROVEN = "declared_entry_unproven"
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
    #: Explicit source-bound application state; original startup reachability is unproved.
    DECLARED_FUNCTION_ENTRY = "declared_function_entry"
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

    DECLARED_FUNCTION_ENTRY = "declared_function_entry"
    BOOT_ENTRY_PATH = "boot_entry_path"
    #: ``RAW_BOOT_ENTRY_PATH``: the same source-bound program entry, proven
    #: over an authenticated raw census surface — a retained
    #: ``RawBootEntrySurface8616`` whose only outstanding obligation is a
    #: pending selector-window terminal jump. The surface grants neither
    #: complete coverage nor registry publication; each traversed pending
    #: transfer re-proves its destination under the live register/tmp
    #: state, and the premise stays invocation-local.
    RAW_BOOT_ENTRY_PATH = "raw_boot_entry_path"
    CALL_CHAINED = "call_chained"
    ENCLOSED_ENTRY = "enclosed_entry"


@dataclass(frozen=True, slots=True)
class DeclaredFunctionEntryLink8616:
    """Bind an explicit conditional entry declaration to its native census surface.

    The declaration supplies entry state, never original-program reachability.
    Every derivation reauthenticates its source, environment and live image.
    """

    admission: DeclaredFunctionEntryAdmission8616
    artifact: IRFunctionArtifact
    boundary: ExactFunctionRangeBoundary8616


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

    The production owner ``tools.dosunit.runtime.real16_program_boot`` documents
    DS/ES as loader-owned by the PSP and the 32-bit register file as
    caller-declared; only those typed fields seed the path simulation.
    """

    psp_segment: int
    registers: tuple[tuple[str, int], ...]
    fs: int
    gs: int


class _BootSurface8616(Protocol):
    """Typed boot contract consumed from the caller's MZ authority.

    The production owner is ``tools.dosunit.runtime.real16_program_boot``; this
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


class _PersistentBytesOwnerLike8616(Protocol):
    """Producer-enumeration surface of the persistent-bytes owner module.

    ``real16_persistent_bytes8616`` sits outside the strictly typed file
    set, so the module resolves dynamically here; this Protocol names
    only the producer census entry point this consumer invokes.
    """

    def persistent_bytes_producers_8616(self) -> tuple[object, ...]:
        """Return the persistent-bytes production callables."""
        ...


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
        DeclaredServiceConsumption8616
        | DeclaredResizeConsumption8616
        | DeclaredVectorConsumption8616,
        ...,
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


class _EntryCallPoolConsultation8616(StrEnum):
    """Observed entry-call evidence-pool consultation of one derivation.

    ``UNKNOWN`` is the only value a derivation may carry without running
    the canonical census: early, structural, and mock attempts report no
    observation, never a claimed absence of dependency. ``UNUSED`` is
    reported only by a census that ran to its post-census exit without
    any CALL row — real or feasibility scratch — reaching the pool
    lookup; ``READ`` means at least one lookup executed, including
    failed or empty-pool lookups. This is dependency evidence, never a
    semantic-equality input.
    """

    UNKNOWN = "unknown"
    UNUSED = "unused"
    READ = "read"


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
    #: Actual resolved edge from a synchronous construction, never a pending request.
    constructed_chain: Real16CallChainLink8616 | None = None
    #: Observed entry-call evidence-pool dependency. Only the canonical
    #: post-census exits report ``UNUSED``/``READ``; the ``UNKNOWN``
    #: default must never be read as proof of no dependency.
    entry_call_pool_consultation: _EntryCallPoolConsultation8616 = (
        _EntryCallPoolConsultation8616.UNKNOWN
    )
    #: Private diagnostic ownership only; never a CURRENT admission or proof.
    prefix_census: _OwnedPrefixCensus8616 | None = field(default=None, compare=False, repr=False)


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


class _LoaderMemorySurface8616(Protocol):
    """Dynamic angr loader-memory read boundary (``Clemory.load``)."""

    def load(self, addr: int, n: int) -> bytes:
        """Read up to ``n`` bytes; short reads stop at unallocated regions."""
        ...


class _LoaderSurface8616(Protocol):
    """Loader handle exposing the byte-memory surface."""

    @property
    def memory(self) -> _LoaderMemorySurface8616:
        """Read the loader's byte memory."""
        ...


class _ProjectLoaderSurface8616(Protocol):
    """Project slot carrying the dynamic third-party loader boundary."""

    @property
    def loader(self) -> _LoaderSurface8616:
        """Read the project's loader handle."""
        ...


def _loaded_bytes_8616(project: object, addr: int, size: int) -> bytes | None:
    """Read the project's currently loaded bytes, ``None`` when unreadable.

    The frontend decode cache keys on address and decode options, not byte
    freshness, so the retained machine census must also bind to what the
    loader actually maps now. ``Clemory.load`` stops at the first
    unallocated region and raises ``KeyError`` when nothing backs the
    start; a short read is unreadable for this contract and becomes
    ``None`` — a typed byte-binding refusal downstream, never a
    substituted default.
    """
    try:
        loaded = cast(_ProjectLoaderSurface8616, project).loader.memory.load(addr, size)
    except (KeyError, TypeError):
        return None
    if not isinstance(loaded, bytes | bytearray | memoryview):
        return None
    live = bytes(loaded)
    return live if len(live) == size else None


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
    return _recompute_validated_boot_8616(boot, boot_recompute)


def _recompute_validated_boot_8616(
    boot: object,
    boot_recompute: Callable[[object], object] | None,
) -> Real16InvocationFailure8616 | None:
    """Replay the callback immediately after this operation validates the source.

    The derivation owner already extracted source evidence synchronously. It
    consumes that fresh check once; independent callers use the full wrapper.
    No positive verdict or mutable boot identity is retained between operations.
    """
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


@dataclass(frozen=True, slots=True, eq=False)
class _PrefixTerminalCall8616:
    """Core-private terminal continuation; scalar containers move out of the walk.

    CALL resets only the separate direction tracker and register dictionary.
    The callsite register/memory copies remain owned by the census context.
    No subsequent row may mutate the transferred continuation containers.
    """

    artifact: IRFunctionArtifact
    block: IRBlock
    index: int
    instruction: IRInstr
    direction: bool | None
    tmps: dict[int, int]
    dirty: set[str]
    instruction_entry: dict[str, int]
    current_addr: int


@dataclass(slots=True)
class _PrefixSourceBindings8616:
    """Shared capture metadata; scratch scopes cannot hide missing authority."""

    bindings: dict[int, NativeCensusSourceBinding8616] = field(default_factory=dict)
    complete: bool = True


@dataclass(frozen=True, slots=True, eq=False)
class _PrefixConsumedCall8616:
    """Exact successful ordinary CALL consumption, never callback authority."""

    artifact: IRFunctionArtifact
    block: IRBlock
    instruction: IRInstr
    proof: _BoundaryProof8616
    scope: Real16InvocationDomain8616 | None
    preserved_registers: tuple[str, ...]


@dataclass(frozen=True, slots=True, eq=False)
class _OwnedPrefixCensus8616:
    """Private successful-census data, requiring fresh admission before any reuse.

    Retaining context ownership avoids another fact/row scan. This is neither
    detached public data nor an authenticated receipt, and never bypasses calls.
    """

    context: _PathCensusContext8616 = field(repr=False)
    seed: _PathState8616 = field(repr=False)
    artifact: IRFunctionArtifact = field(repr=False)
    boundary: ExactFunctionRangeBoundary8616 = field(repr=False)
    boot_recompute: Callable[[object], object] | None = field(repr=False)
    counts: tuple[int, int, int, int, int] = (0, 0, 0, 0, 0)
    stores: int = 0
    producers: tuple[object, ...] = field(default=(), repr=False)
    simulation_work: int = 0
    fact_ownership: CensusFactOwnership8616 | None = field(default=None, repr=False)
    consumed_calls: tuple[_PrefixConsumedCall8616, ...] = field(default=(), repr=False)


@dataclass(slots=True)
class _PathCensusContext8616:
    """Shared authority for one root-to-callsite raw-effect census.

    ``manifest`` retains every distinct proved fetched instruction byte range
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
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | RawBootEntrySurface8616 | DeclaredFunctionEntryLink8616 | None
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
        DeclaredServiceConsumption8616
        | DeclaredResizeConsumption8616
        | DeclaredVectorConsumption8616
    ]
    stop_block_addr: int | None
    callsite_addr: int | None
    callsite_call_state: dict[str, int] | None
    #: The callsite-row memory overlay captured beside
    #: ``callsite_call_state`` — the callee's exact entry memory, so a
    #: transported premise's seed carries the same bytes the register
    #: state was proven under.
    callsite_memory: PathMemory8616 | None
    manifest: set[tuple[int, int]]
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
    #: Count every authenticated fetched-span admission, including repeats;
    #: protection uses the distinct manifest, while public replay/counts retain
    #: the original admission multiplicity.
    fetched_span_admissions: int = 0
    #: Exact raw terminals whose current callee projection proves a return.
    #: Scoped to synchronous callee replay; never inherited by another body.
    callee_return_rows: tuple[IRInstr, ...] = ()
    accounted_work_units: int = 0
    #: The first classified instruction row the census refused — real
    #: diagnostic evidence for the exact failing site, never a guess.
    first_failure_site: Real16InvocationRefusalSite8616 | None = None
    #: Per-edge feasibility verdicts computed once between byte binding
    #: and path-callee/effect simulation; ``live_blocks`` is the scope
    #: both later phases consume.
    edge_feasibility: Real16EdgeFeasibility8616 | None = None
    initial_memory: InvocationInitialMemory8616 | None = None
    #: Monotonic consultation receipt for the in-flight entry-domain
    #: pool: set once any CALL row reaches the pool lookup in
    #: ``_consume_call_boundary_8616`` — a failed or empty lookup still
    #: counts as a read. Feasibility scratch copies propagate it back to
    #: the owning context on every exit so a scratch-only consultation is
    #: never reported as unused.
    entry_call_pool_consulted: bool = False
    #: Opt-in private diagnostics, never proof authority; scratch work cannot
    #: retain the requested CALL because it clears callsite_addr.
    prefix_capture_requested: bool = False
    prefix_consumed: bool = False
    prefix_simulation_work: int = 0
    prefix_boot_recompute: Callable[[object], object] | None = field(default=None, repr=False)
    prefix_terminal_call: _PrefixTerminalCall8616 | None = None
    prefix_call_consumptions: list[_PrefixConsumedCall8616] = field(default_factory=list, repr=False)
    #: Existing immutable import keys retained only for opt-in capture. Missing
    #: or changed authority keeps the data ineligible for future continuation.
    prefix_sources: _PrefixSourceBindings8616 = field(default_factory=_PrefixSourceBindings8616)
    #: ``(function_addr, block_addr) -> (boundary, stop_after)`` for each
    #: ``ctx.native_blocks`` entry that is a consumed-row prefix copy rather
    #: than a whole block. Whole-block consumers (repeated stores) re-derive
    #: the full block through the recorded authenticated boundary before
    #: binding; never a proof or reuse authority on its own.
    prefix_native_entries: dict[
        tuple[int, int], tuple[ExactFunctionRangeBoundary8616, int],
    ] = field(default_factory=dict, repr=False)


def _census_work_exceeded_8616(ctx: _PathCensusContext8616) -> bool:
    """Charge nested census work to the ambient replay budget as well as locally."""
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_work_units += ctx.work_units - ctx.accounted_work_units
        ctx.accounted_work_units = ctx.work_units
        return (
            ctx.work_units > ctx.work_limit
            or traversal.census_work_units > traversal.census_work_limit
        )


def _census_resource_failure_8616(
    ctx: _PathCensusContext8616,
) -> Real16InvocationFailure8616 | None:
    """Account shared work and retain resource refusal before proof fallbacks."""
    if _census_work_exceeded_8616(ctx):
        return Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
    if time.monotonic() > ctx.deadline:
        return Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
    return None


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


_CANONICAL_CENSUS_REIMPORT_8616 = _census_reimport_8616


def _native_effect_blocks_8616(
    ctx: _PathCensusContext8616,
    boundary: ExactFunctionRangeBoundary8616,
    *,
    selected_blocks: frozenset[int] | None = None,
    terminal: tuple[int, int] | None = None,
) -> dict[int, IRBlock] | Real16InvocationFailure8616:
    """Re-derive one artifact's native blocks through the authoritative importer.

    The importer lifts the project's loaded bytes — already proven equal
    to the retained boot image for every in-scope fetched instruction —
    under the artifact's own exact boundary. Only named decode-boundary
    failures translate to ``native_effect_unproven``; the returned map is
    per-block so each simulated block can be compared in full (rows,
    refusals, and successors), never just by shared address. ``terminal``
    is an optional explicit ``(block_addr, stop_after)`` consumed-row
    cutoff: the detached copy of that one block then carries only the
    prefix rows the census consumes, recorded in
    ``ctx.prefix_native_entries`` so whole-block consumers re-derive or
    decline; suffix rows are never authorized.
    """
    if time.monotonic() > ctx.deadline:
        return Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
    if boundary.project is not ctx.project:
        return Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    from .native_import_surface_cache import _request_native_census_blocks_8616
    from .vex_import import (
        _census_finishing_producers_8616,
        _census_raw_native_blocks_8616,
        _native_import_producers_8616,
    )

    if _census_reimport_8616 is _CANONICAL_CENSUS_REIMPORT_8616:
        try:
            selected = _request_native_census_blocks_8616(
                ctx.project, boundary, _census_raw_native_blocks_8616,
                selected_blocks=selected_blocks,
                producers=(
                    _census_reimport_8616,
                    *_census_finishing_producers_8616(),
                    *_native_import_producers_8616(),
                ),
                terminal=terminal,
                allow_conditional_source=ctx.prefix_capture_requested,
            )
        except _DECODE_REFUSAL_TYPES_8616:
            return Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
        if selected is not None:
            ctx.work_units += selected.work_units
            if _census_work_exceeded_8616(ctx):
                return Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
            if time.monotonic() > ctx.deadline:
                return Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
            _record_native_prefix_selection_8616(ctx, boundary, selected.blocks, selected.prefix_rows)
            _retain_prefix_source_binding_8616(ctx, boundary, selected.source_binding)
            return selected.blocks
    _retain_prefix_source_binding_8616(ctx, boundary, None)
    result = _uncached_native_effect_blocks_8616(ctx, boundary)
    if not isinstance(result, Real16InvocationFailure8616):
        _record_native_prefix_selection_8616(ctx, boundary, result, ())
    return result


def _record_native_prefix_selection_8616(
    ctx: _PathCensusContext8616, boundary: ExactFunctionRangeBoundary8616,
    blocks: dict[int, IRBlock], prefix_rows: tuple[tuple[int, int], ...],
) -> None:
    """Replace cutoff metadata for the actual detached blocks being returned.

    A full selection supersedes an earlier prefix: historical cutoffs must
    never weaken later whole-block binding. Other selected block entries and
    other functions retain their independently bound records.
    """
    for block_addr in blocks:
        ctx.prefix_native_entries.pop((boundary.addr, block_addr), None)
    for block_addr, stop_after in prefix_rows:
        ctx.prefix_native_entries[(boundary.addr, block_addr)] = (boundary, stop_after)


def _retain_prefix_source_binding_8616(
    ctx: _PathCensusContext8616, boundary: ExactFunctionRangeBoundary8616,
    binding: NativeCensusSourceBinding8616 | None,
) -> None:
    """Retain existing source keys without rescanning facts or granting reuse."""
    if not ctx.prefix_capture_requested:
        return
    retained = ctx.prefix_sources
    previous = retained.bindings.get(boundary.addr)
    # Cache hits retain the same immutable projection key object. A rebuilt or
    # evicted projection declines optional capture rather than scanning the key.
    if binding is None or (previous is not None and previous.key is not binding.key):
        retained.complete = False
    elif previous is None:
        retained.bindings[boundary.addr] = binding


def _uncached_native_effect_blocks_8616(
    ctx: _PathCensusContext8616,
    boundary: ExactFunctionRangeBoundary8616,
) -> dict[int, IRBlock] | Real16InvocationFailure8616:
    """Retain the full authoritative import for unsupported/custom producers."""
    if time.monotonic() > ctx.deadline:
        return Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
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
_NATIVE_BINDING_MEMO_MAX_PAIRS_8616 = 2048

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
        "complete", "bp_preserved", "stack_coordinates", "scoped_coordinates",
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


class _NativeTermMemo8616:
    """Identity memo and schema cache scoped to one binding comparison.

    The all-field comparator walks shared immutable IR DAGs and revisits
    the same ``(left, right)`` object pair many times. Pair results are
    monotone in ``depth``: a pair proven equal at depth ``d`` stays equal
    at every shallower depth (the bound only gains headroom), and a pair
    refused at ``d`` stays refused at every deeper depth — every
    non-depth refusal (type, field schema, length, leaf value) is
    depth-independent, and a depth-exceeded subtree only exceeds earlier
    at greater depths. The memo therefore records the deepest proven
    depth and the shallowest refused depth per identity pair; a hit must
    still satisfy the caller's depth, so memoization never bypasses the
    bound. Stored typed-node pairs are pinned for the memo's lifetime so
    recycled identities cannot alias a stale key. Projection tuples and
    mutable containers are not memoized. At the pair cap, new pairs use
    ordinary recursive comparison without retention. The memo is
    constructed per top-level comparison, never shared across requests,
    and the per-type schema cache cannot outlive the classes it read.
    """

    __slots__ = ("_false_depths", "_pins", "_schemas", "_true_depths")

    def __init__(self) -> None:
        """Create an empty per-comparison memo."""
        self._true_depths: dict[tuple[int, int], int] = {}
        self._false_depths: dict[tuple[int, int], int] = {}
        self._pins: dict[tuple[int, int], tuple[object, object]] = {}
        self._schemas: dict[type, frozenset[str]] = {}

    def lookup(self, key: tuple[int, int], depth: int) -> bool | None:
        """Return a stored verdict still valid at ``depth``, else ``None``."""
        proven = self._true_depths.get(key)
        if proven is not None and depth <= proven:
            return True
        refused = self._false_depths.get(key)
        if refused is not None and depth >= refused:
            return False
        return None

    def store(
        self,
        key: tuple[int, int],
        left: object,
        right: object,
        depth: int,
        result: bool,
    ) -> None:
        """Record ``result`` at ``depth`` and pin both keyed objects."""
        if key not in self._pins:
            if len(self._pins) >= _NATIVE_BINDING_MEMO_MAX_PAIRS_8616:
                return
            self._pins[key] = (left, right)
        if result:
            previous = self._true_depths.get(key)
            if previous is None or previous < depth:
                self._true_depths[key] = depth
        else:
            previous = self._false_depths.get(key)
            if previous is None or previous > depth:
                self._false_depths[key] = depth

    def declared_fields(self, node_type: type) -> frozenset[str]:
        """Return the dataclass field names declared by ``node_type``."""
        declared = self._schemas.get(node_type)
        if declared is None:
            declared = frozenset(
                member.name for member in fields(node_type)
            )
            self._schemas[node_type] = declared
        return declared


def _native_fields_current_8616(
    node: object, expected: frozenset[str], memo: _NativeTermMemo8616
) -> bool:
    """Return whether ``node`` still declares exactly the owned field set."""
    return is_dataclass(node) and memo.declared_fields(type(node)) == expected


def _native_sequence_equal_8616(
    left: tuple[object, ...] | list[object],
    right: tuple[object, ...] | list[object],
    depth: int,
    memo: _NativeTermMemo8616,
) -> bool:
    """Compare sequence fields without recursive calls for exact scalar leaves.

    Scalar leaves still consume the ordinary child depth. Subclasses, enums
    and owned nodes take the full comparator, including its refusal and memo
    rules; identical containers never bypass validation of their contents.
    """
    if len(left) != len(right):
        return False
    for item_left, item_right in zip(left, right, strict=True):
        leaf_type = type(item_left)
        scalar = leaf_type is int or leaf_type is str or leaf_type is bool or item_left is None
        if scalar and leaf_type is type(item_right):
            if depth >= _NATIVE_BINDING_DEPTH_LIMIT_8616 or item_left != item_right:
                return False
        elif not _native_term_equal_8616(item_left, item_right, depth + 1, memo):
            return False
    return True


def _native_term_equal_8616(
    left: object,
    right: object,
    depth: int,
    memo: _NativeTermMemo8616 | None = None,
) -> bool:
    """Compare two packed binding terms exactly.

    ``False`` covers both a real difference and a structure the
    comparator cannot prove complete — an unprovable field is a refusal,
    not a pass. ``memo`` scopes identity memoization to one top-level
    comparison; omitted, it is created fresh.
    """
    if memo is None:
        memo = _NativeTermMemo8616()
    if depth > _NATIVE_BINDING_DEPTH_LIMIT_8616 or type(left) is not type(right):
        return False
    if isinstance(left, (tuple, list)) and isinstance(right, (tuple, list)):
        return _native_sequence_equal_8616(left, right, depth, memo)
    comparator = frozen_dispatch_lookup(_NATIVE_COMPARATORS_8616, type(left))
    if comparator is not None:
        key = (id(left), id(right))
        hit = memo.lookup(key, depth)
        if hit is not None:
            return hit
        result = comparator(left, right, depth, memo)
        memo.store(key, left, right, depth, result)
        return result
    # A typed IR node this comparator does not own cannot be fully
    # compared -> refuse. Plain leaves (ints, strings, enums, None)
    # compare by value under the already-proven common type.
    return not is_dataclass(left) and left == right


def _native_value_equal_8616(
    left: IRValue,
    right: IRValue,
    depth: int,
    memo: _NativeTermMemo8616 | None = None,
) -> bool:
    """All-field binding equality for one IRValue, capture ids included."""
    if memo is None:
        memo = _NativeTermMemo8616()
    if not _native_fields_current_8616(left, _IR_VALUE_FIELDS_8616, memo):
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
        memo,
    )


def _native_active_unary_equal_8616(
    left: IRActiveUnary8616,
    right: IRActiveUnary8616,
    depth: int,
    memo: _NativeTermMemo8616 | None = None,
) -> bool:
    """All-field binding equality for one active unary evidence node."""
    if memo is None:
        memo = _NativeTermMemo8616()
    if not _native_fields_current_8616(left, _IR_ACTIVE_UNARY_FIELDS_8616, memo):
        return False
    return _native_term_equal_8616(
        (left.op, left.operand, left.result_bits),
        (right.op, right.operand, right.result_bits),
        depth + 1,
        memo,
    )


def _native_binary_value_equal_8616(
    left: IRBinaryValue,
    right: IRBinaryValue,
    depth: int,
    memo: _NativeTermMemo8616 | None = None,
) -> bool:
    """All-field binding equality for one typed binary value expression."""
    if memo is None:
        memo = _NativeTermMemo8616()
    if not _native_fields_current_8616(left, _IR_BINARY_VALUE_FIELDS_8616, memo):
        return False
    return _native_term_equal_8616(
        (left.op, left.lhs, left.rhs, left.size),
        (right.op, right.lhs, right.rhs, right.size),
        depth + 1,
        memo,
    )


def _native_address_equal_8616(
    left: IRAddress,
    right: IRAddress,
    depth: int,
    memo: _NativeTermMemo8616 | None = None,
) -> bool:
    """All-field binding equality for one typed segmented address."""
    if memo is None:
        memo = _NativeTermMemo8616()
    if not _native_fields_current_8616(left, _IR_ADDRESS_FIELDS_8616, memo):
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
        memo,
    )


def _native_condition_equal_8616(
    left: IRCondition,
    right: IRCondition,
    depth: int,
    memo: _NativeTermMemo8616 | None = None,
) -> bool:
    """All-field binding equality for one typed branch condition."""
    if memo is None:
        memo = _NativeTermMemo8616()
    if not _native_fields_current_8616(left, _IR_CONDITION_FIELDS_8616, memo):
        return False
    return _native_term_equal_8616(
        (left.op, left.args, left.expr, left.width_bits),
        (right.op, right.args, right.expr, right.width_bits),
        depth + 1,
        memo,
    )


def _native_call_effect_equal_8616(
    left: IRCallStackEffect8616,
    right: IRCallStackEffect8616,
    depth: int,
    memo: _NativeTermMemo8616 | None = None,
) -> bool:
    """All-field binding equality for one typed call stack effect."""
    if memo is None:
        memo = _NativeTermMemo8616()
    if not _native_fields_current_8616(left, _IR_CALL_EFFECT_FIELDS_8616, memo):
        return False
    # Native detach retains the scoped carrier as live authority. A new
    # carrier cannot acquire that binding through equal serialized scalars;
    # replaying its scopes here would recurse through this same native bind.
    if left.scoped_coordinates is not right.scoped_coordinates:
        return False
    left_coordinates = left.stack_coordinates
    right_coordinates = right.stack_coordinates
    from .source_graph_json import canonical_json_dumps_8616

    if left_coordinates is not None and right_coordinates is not None:
        left_source = left_coordinates.source
        right_source = right_coordinates.source
        if left_source is not None and right_source is not None and left_source.project is not right_source.project:
            return False
    return _native_term_equal_8616(
        (
            left.net_stack_delta, left.preserved_ranges, left.escaped_ranges,
            left.complete, left.bp_preserved, left.current_net_stack_delta,
            None if left_coordinates is None else canonical_json_dumps_8616(left_coordinates.to_dict()),
        ),
        (
            right.net_stack_delta, right.preserved_ranges,
            right.escaped_ranges, right.complete, right.bp_preserved, right.current_net_stack_delta,
            None if right_coordinates is None else canonical_json_dumps_8616(right_coordinates.to_dict()),
        ),
        depth + 1,
        memo,
    )


def _native_call_output_equal_8616(
    left: IRCallOutputProvenance8616,
    right: IRCallOutputProvenance8616,
    depth: int,
    memo: _NativeTermMemo8616 | None = None,
) -> bool:
    """All-field binding equality for one call-output provenance record."""
    if memo is None:
        memo = _NativeTermMemo8616()
    if not _native_fields_current_8616(left, _IR_CALL_OUTPUT_FIELDS_8616, memo):
        return False
    return _native_term_equal_8616(
        (left.callsite_addr, left.target_addr, left.shape),
        (right.callsite_addr, right.target_addr, right.shape),
        depth + 1,
        memo,
    )


def _native_origin_equal_8616(
    left: IRInstructionOrigin8616,
    right: IRInstructionOrigin8616,
    depth: int,
    memo: _NativeTermMemo8616 | None = None,
) -> bool:
    """All-field binding equality for one instruction origin tag."""
    if memo is None:
        memo = _NativeTermMemo8616()
    if not _native_fields_current_8616(left, _IR_ORIGIN_FIELDS_8616, memo):
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
        memo,
    )


def _native_refusal_equal_8616(
    left: IRRefusal,
    right: IRRefusal,
    depth: int,
    memo: _NativeTermMemo8616 | None = None,
) -> bool:
    """All-field binding equality for one typed IR refusal."""
    if memo is None:
        memo = _NativeTermMemo8616()
    if not _native_fields_current_8616(left, _IR_REFUSAL_FIELDS_8616, memo):
        return False
    return _native_term_equal_8616(
        (left.kind, left.detail, left.block_addr),
        (right.kind, right.detail, right.block_addr),
        depth + 1,
        memo,
    )


def _native_instr_equal_8616(
    left: IRInstr,
    right: IRInstr,
    depth: int,
    memo: _NativeTermMemo8616 | None = None,
) -> bool:
    """All-field binding equality for one typed instruction row."""
    if memo is None:
        memo = _NativeTermMemo8616()
    if not _native_fields_current_8616(left, _IR_INSTR_FIELDS_8616, memo):
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
        memo,
    )


def _native_block_equal_8616(
    left: IRBlock,
    right: IRBlock,
    depth: int,
    memo: _NativeTermMemo8616 | None = None,
) -> bool:
    """All-field binding equality for one typed IR block."""
    if memo is None:
        memo = _NativeTermMemo8616()
    if not _native_fields_current_8616(left, _IR_BLOCK_FIELDS_8616, memo):
        return False
    return _native_term_equal_8616(
        (left.addr, left.instrs, left.refusals, left.successor_addrs),
        (right.addr, right.instrs, right.refusals, right.successor_addrs),
        depth + 1,
        memo,
    )


_NATIVE_COMPARATORS_8616: FrozenDispatch[type, Callable[..., bool]] = (
    (IRBlock, _native_block_equal_8616),
    (IRInstr, _native_instr_equal_8616),
    (IRValue, _native_value_equal_8616),
    (IRBinaryValue, _native_binary_value_equal_8616),
    (IRAddress, _native_address_equal_8616),
    (IRCondition, _native_condition_equal_8616),
    (IRCallStackEffect8616, _native_call_effect_equal_8616),
    (IRCallOutputProvenance8616, _native_call_output_equal_8616),
    (IRActiveUnary8616, _native_active_unary_equal_8616),
    (IRInstructionOrigin8616, _native_origin_equal_8616),
    (IRRefusal, _native_refusal_equal_8616),
)


def _native_prefix_count_8616(block: IRBlock, stop_after: int) -> int | None:
    """Select exactly the same ordered native prefix the effect walker consumes."""
    if type(stop_after) is not int or type(block.addr) is not int or stop_after < block.addr:
        return None
    for index, instruction in enumerate(block.instrs):
        if type(instruction) is not IRInstr or type(instruction.addr) is not int:
            return None
        if instruction.addr > stop_after:
            return index
    return len(block.instrs)


def _native_block_bound_8616(
    native: object, block: IRBlock | None, *, stop_after: int | None = None,
) -> bool:
    """Return whether ``block`` is the exact re-derived native block.

    An absent root block refuses through the same exact-type gate as missing
    native input. Whole-block source/effect/provenance binding: the artifact block and
    the block re-derived by the authoritative importer must be the same
    type and equal over every declared field of every row. ``native`` is
    ``None`` or a non-block when the census never bound this block's
    bytes — an unbound block can never prove a native effect, so binding
    refuses rather than comparing. An explicit cutoff binds every consumed row
    and all block metadata; no suffix row is consumed or authorized. Whole-block
    consumers, including repeated stores, retain the default full binding.
    """
    if type(native) is not IRBlock or type(block) is not IRBlock:
        return False
    if stop_after is None:
        return _native_block_equal_8616(native, block, 0)
    count = _native_prefix_count_8616(block, stop_after)
    native_count = _native_prefix_count_8616(native, stop_after)
    if count is None or count != native_count:
        return False
    memo = _NativeTermMemo8616()
    if not _native_fields_current_8616(native, _IR_BLOCK_FIELDS_8616, memo):
        return False
    return _native_term_equal_8616(
        (native.addr, native.instrs[:count], native.refusals, native.successor_addrs),
        (block.addr, block.instrs[:count], block.refusals, block.successor_addrs),
        1, memo,
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


@dataclass(slots=True)
class _FetchedByteExtent8616:
    """Half-open envelope covering every instruction byte the binding bound.

    ``low``/``high`` are accumulated during the mandatory per-instruction
    byte-binding traversal, so the extent derives only from the
    authenticated machine census — never from a claimed IR suffix or an
    unauthenticated block size. The range may include holes between
    instruction extents, making it a conservative superset of the fetched
    bytes: a declared-data span outside it is proven disjoint from every
    bound instruction. ``low is None`` marks an empty scope, which admits
    no span test.
    """

    low: int | None = None
    high: int = 0


def _bind_fetched_bytes_8616(
    machine_addrs: dict[int, tuple[int, bytes]],
    in_scope: frozenset[int] | set[int],
    *,
    selector: int,
    image: _BootImageSurface8616,
    project: object,
    fetched_extent: _FetchedByteExtent8616 | None = None,
) -> Real16InvocationFailure8616 | None:
    """Bind every in-scope fetched instruction byte range to the image.

    The decoded ``encoded`` bytes can come from the frontend block-inventory
    cache, which is keyed on decode coordinates, not byte freshness. The
    retained bytes must therefore agree three ways: with the boot source
    image, with the census decode, and with the bytes the project loader
    maps right now. A loader read that cannot produce exactly ``size``
    bytes, or any disagreement, is ``native_bytes_mismatch``.

    When ``fetched_extent`` is given, the same already-required traversal
    records the half-open range covering every bound instruction extent —
    a caller-side disjointness envelope, never a substitute for the
    per-instruction authentication above.
    """
    window_base = selector << _SEGMENT_SHIFT_8616
    window_end = window_base + _WORD_LIMIT_8616
    extent_low: int | None = None
    extent_high = 0
    for address in sorted(in_scope):
        size, encoded = machine_addrs[address]
        if not window_base <= address or address + size > window_end + 1:
            return Real16InvocationFailure8616.FETCH_WINDOW_VIOLATION
        if extent_low is None:
            extent_low = address
        if address + size > extent_high:
            extent_high = address + size
        if not any(
            code_range.contains(address, size) for code_range in image.code_ranges
        ):
            return Real16InvocationFailure8616.CODE_SCOPE_VIOLATION
        image_slice = _image_slice_8616(image, address, size)
        if image_slice is None or image_slice != encoded:
            return Real16InvocationFailure8616.NATIVE_BYTES_MISMATCH
        live = _loaded_bytes_8616(project, address, size)
        if live is None or live != image_slice:
            return Real16InvocationFailure8616.NATIVE_BYTES_MISMATCH
    if fetched_extent is not None and extent_low is not None:
        fetched_extent.low = extent_low
        fetched_extent.high = extent_high
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
    """Census current block bytes before adding distinct protected spans.

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
    failure = _bind_census_fetched_bytes_8616(ctx, machine_addrs, in_scope)
    if failure is not None:
        return failure
    ctx.manifest.update(
        (address, machine_addrs[address][0]) for address in sorted(in_scope)
    )
    ctx.fetched_span_admissions += len(in_scope)
    for address in sorted(in_scope):
        ctx.machine_bytes[address] = machine_addrs[address][1]
    return None


def _bind_census_fetched_bytes_8616(
    ctx: _PathCensusContext8616,
    machine: dict[int, tuple[int, bytes]], in_scope: set[int],
) -> Real16InvocationFailure8616 | None:
    """Protect every fetched body from declared data, including descendants.

    A whole-image MZ range authorizes decoding; it does not classify every
    byte as immutable code. Check the original declaration directly so a
    transported or joined path-memory ledger cannot erase this obligation.

    The byte bind returns the authenticated fetched-byte envelope covering
    every bound in-scope instruction extent. A span wholly outside that
    envelope is disjoint from every fetched instruction by the envelope's
    own derivation, so one charged determination replaces its
    per-instruction scans; a span intersecting the envelope — including
    one sitting only in an interior hole — keeps the original
    per-instruction billing and overlap checks. Every envelope determination
    is charged, including an intersecting span's check before the exact walk.
    """
    extent = _FetchedByteExtent8616()
    failure = _bind_fetched_bytes_8616(
        machine, in_scope, selector=ctx.selector, image=ctx.image, project=ctx.project,
        fetched_extent=extent,
    )
    if failure is not None:
        return failure
    authority = _declared_entry_authority_8616(ctx.chain)
    if isinstance(authority, Real16InvocationFailure8616):
        return authority
    if authority is None or not in_scope:
        return None
    if extent.low is None:
        return Real16InvocationFailure8616.PATH_DECODE_MISMATCH
    for span in authority.spec.memory:
        ctx.work_units += 1
        failure = _census_resource_failure_8616(ctx)
        if failure is not None:
            return failure
        span_end = span.address + len(span.data)
        if span_end <= extent.low or extent.high <= span.address:
            continue
        failure = _check_fetched_data_overlap_8616(
            ctx, machine, in_scope, span.address, span_end,
        )
        if failure is not None:
            return failure
    return None


def _check_fetched_data_overlap_8616(
    ctx: _PathCensusContext8616,
    machine: dict[int, tuple[int, bytes]],
    in_scope: set[int],
    span_start: int,
    span_end: int,
) -> Real16InvocationFailure8616 | None:
    """Check a possibly intersecting data span against every actual fetched row."""
    for address in in_scope:
        ctx.work_units += 1
        failure = _census_resource_failure_8616(ctx)
        if failure is not None:
            return failure
        if span_start < address + machine[address][0] and address < span_end:
            return Real16InvocationFailure8616.CODE_WRITE_VIOLATION
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


def _eval_comparison_or_product_8616(
    op: str, left: int, right: int,
    operands: tuple[object, object] | None, result_size: int | None,
) -> int | None:
    """Reuse canonical comparison semantics only for fully known operands."""
    bits = scalar_owner_8616._COMPARISON_OPS_8616.get(op)
    if bits is None:
        return wide_multiply_value_8616(op, left, right, operands, result_size)
    mask = (1 << bits) - 1
    compared = kb_owner_8616._kb_binary_op_8616(
        op, (mask, left & mask), (mask, right & mask),
    )
    return compared[1] if compared is not None and compared[0] == 1 else None


def _eval_binary_op_8616(
    op: str, left: int, right: int, *,
    operands: tuple[object, object] | None = None, result_size: int | None = None,
) -> int | None:
    """Apply an exact-whitelisted VEX integer binop at its declared width."""
    if op not in _BINARY_OPS_8616:
        return _eval_comparison_or_product_8616(op, left, right, operands, result_size)
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
    elif (select_bits := scalar_select_result_bits_8616(instruction)) is not None:
        guard = _eval_atom_8616(instruction.args[0], registers, tmps)
        if guard is not None:
            chosen = instruction.args[1 if guard & 1 else 2]
            selected = _eval_atom_8616(chosen, registers, tmps)
            if selected is not None:
                evaluated = selected & ((1 << select_bits) - 1)
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
    registers: dict[str, int],
    tmps: dict[int, int],
) -> Real16InvocationFailure8616 | None:
    """Classify one CJMP/JMP/RET row's effect on the path state.

    The callsite row is the census boundary: a CALL's state is captured by
    ``_cross_call_8616``, and a pending JMP's symbolic transfer is the very
    obligation the premise discharges — its target is not an in-path
    effect. Any other symbolic (non-constant ``dst``) transfer refuses.
    Targets use the owned typed-atom evaluator: unresolved expressions refuse
    instead of reading fields belonging only to scalar ``IRValue`` objects.
    """
    if instruction.op == "CJMP" and instruction is not block.instrs[-1]:
        # A single linear pass cannot establish effects after an internal
        # exit (notably every iteration of REP). Require an authenticated
        # complete transfer; visiting the rows once can miss later code writes.
        return Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
    if instruction.addr == ctx.callsite_addr:
        return None
    if any(instruction is row for row in ctx.callee_return_rows):
        # Native binding still precedes transfer. The scoped projection,
        # authenticated at callee entry, owns this JMP-to-RET interpretation.
        return None
    if type(ctx.chain) in (RawBootEntrySurface8616, DeclaredFunctionEntryLink8616) and block.refusals:
        if instruction.op != "JMP" or len(instruction.args) != 1:
            return Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
        target = _eval_atom_8616(instruction.args[0], registers, tmps)
        if target is None or block.successor_addrs != (target,):
            return Real16InvocationFailure8616.CS_PATH_UNPROVEN
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
        failure = _transfer_row_failure_8616(ctx, instruction, block, registers, tmps)
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


def _native_store_span_8616(
    instruction: IRInstr,
    instruction_entry: dict[str, int],
    dirty: set[str],
    tmps: dict[int, int],
) -> tuple[int, int] | None:
    """Bind a raw STORE span to its already evaluated native address.

    The census authenticates the whole native block, including each exact
    Store statement's origin, before calling this helper. Temporary values
    are block-local and evaluated in native order. An unsupported storage
    space can therefore retain a proven machine write span without acquiring
    a guessed segment alias. LOAD consumers keep their existing address model.
    An independently proven segmented span uses the instruction-entry snapshot,
    never a later register reread. A native capture also remains valid when
    that segment state is unavailable, without granting a guessed alias.
    Contradictory spans refuse; absence of both proofs refuses.
    """
    address = instruction.args[0]
    if not isinstance(address, IRAddress):
        return None
    logical = _store_span_8616(instruction, address, instruction_entry, dirty, tmps)
    origin = instruction.origin
    if origin is None or origin.address_tmp is None:
        return logical
    captured = tmps.get(origin.address_tmp)
    if captured is None:
        return logical
    size = address.size if type(address.size) is int and address.size > 0 else instruction.size
    if type(size) is not int or size <= 0 or type(captured) is not int:
        return None
    if not 0 <= captured <= (_WORD_LIMIT_8616 << _SEGMENT_SHIFT_8616) + _WORD_LIMIT_8616:
        return None
    native = (captured, size)
    if logical is not None:
        return logical if logical == native else None
    return native


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
    span = _native_store_span_8616(instruction, instruction_entry, dirty, tmps)
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
        """Replay completeness for the entry; return empty for incomplete evidence."""
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
    if type(chain) is DeclaredFunctionEntryLink8616:
        return (
            required.kind is Real16InvocationKind8616.DECLARED_FUNCTION_ENTRY
            and _in_flight_scopes_coterminous_8616(required.chain, chain, 0)
        )
    if type(chain) is RawBootEntrySurface8616:
        return (
            required.kind is Real16InvocationKind8616.RAW_BOOT_ENTRY_PATH
            and type(required.chain) is RawBootEntrySurface8616
            and required.chain.artifact is artifact
            and required.chain.boundary is chain.boundary
        )
    if chain is None:
        return (
            required.kind is Real16InvocationKind8616.BOOT_ENTRY_PATH
            and required.chain is None
            and required.coverage is not None
            and required.coverage.artifact is artifact
        )
    return _in_flight_scopes_coterminous_8616(required.chain, chain, 0)


def _selector_scope_for_proof_8616(proof: _BoundaryProof8616) -> DeclaredSegmentInvariant | None:
    """Read the distinct weak premise only from its canonical entry-record owner."""
    from .entry_domain_call_preservation import EntryDomainCallPreservation8616

    if type(proof) is not EntryDomainCallPreservation8616:
        return None
    return proof.selector_scope


def _selector_derivation_bound_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
    proof: _BoundaryProof8616, scope: DeclaredSegmentInvariant,
) -> bool:
    """Bind weak selector evidence to the identical declared root and incoming CS."""
    from .declared_selector_invariant import DeclaredSegmentInvariant
    from .entry_domain_call_preservation import EntryDomainCallPreservation8616

    if type(scope) is not DeclaredSegmentInvariant or type(proof) is not EntryDomainCallPreservation8616:
        return False
    record = proof
    root = scope.root_link
    source = scope.source
    projection = record.selector_projection
    if type(root) is not DeclaredFunctionEntryLink8616 or source is None or projection is None:
        return False
    if (ctx.chain is not root or ctx.project is not scope.project or ctx.boot is not source.boot
            or artifact is not root.artifact or record.boundary is not root.boundary):
        return False
    if (record.artifact is not artifact or root.admission is not scope.admission
            or root.boundary.project is not ctx.project or projection.incoming_cs != ctx.selector):
        return False
    return projection.scope is scope and record.required_scope is None


def _ctx_consuming_scope_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    proof: _BoundaryProof8616,
) -> Real16InvocationDomain8616 | object | None:
    """Return the authenticated scope this census may consume under.

    ``None`` means no full-invocation premise. Selector records retain their
    separate scope on ``_ConsumedCallBoundary8616`` and authenticate their root
    here; only records lacking both scopes are universal. The record's own
    ``required_scope`` means conditional evidence the census may consume
    under that authenticated entry. The sentinel ``_CTX_SCOPE_REFUSE``
    means the record's required entry provenance differs from the scope
    this census derives, so the evidence cannot cross this path.
    """
    selector = _selector_scope_for_proof_8616(proof)
    if selector is not None:
        return None if _selector_derivation_bound_8616(ctx, artifact, proof, selector) else _CTX_SCOPE_REFUSE_8616
    required = proof.required_scope
    if required is None:
        return None
    if not _derivation_scope_bound_8616(ctx, artifact, required):
        return _CTX_SCOPE_REFUSE_8616
    return required


_CTX_SCOPE_REFUSE_8616: object = object()


@dataclass(frozen=True, slots=True)
class _ConsumedCallBoundary8616:
    """Synchronous call authentication result; never retained across phases."""

    proof: _BoundaryProof8616
    scope: Real16InvocationDomain8616 | None
    preserved_registers: tuple[str, ...] | None
    selector_scope: DeclaredSegmentInvariant | None = None


def _selector_incoming_state_bound_8616(
    consumed: _ConsumedCallBoundary8616, registers: dict[str, int],
) -> bool:
    """Require the actual caller CS before using a weak selector projection."""
    if consumed.selector_scope is None:
        return True
    from .entry_domain_call_preservation import EntryDomainCallPreservation8616

    proof = consumed.proof
    if type(proof) is not EntryDomainCallPreservation8616:
        return False
    projection = proof.selector_projection
    return projection is not None and registers.get("cs") == projection.incoming_cs


def _call_scope_uses_owned_identity_8616(ctx: _PathCensusContext8616) -> bool:
    """Restrict immediate reuse to scopes whose matching cannot replay parents."""
    return ctx.chain is None or type(ctx.chain) in (
        DeclaredFunctionEntryLink8616, RawBootEntrySurface8616,
    )


def _call_boundary_proof_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    block: IRBlock,
    instruction: IRInstr,
) -> _BoundaryProof8616 | None:
    """Select one currently authenticated CALL proof without retaining replay."""
    consumed = _consume_call_boundary_8616(ctx, artifact, block, instruction)
    if consumed is None or consumed.selector_scope is not None:
        # Bare-proof consumers have no slot to retain weak provenance.
        return None
    if _call_scope_uses_owned_identity_8616(ctx) and _ctx_consuming_scope_8616(
        ctx, artifact, consumed.proof,
    ) is not consumed.scope:
        return None
    return consumed.proof


def _consume_call_boundary_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    block: IRBlock,
    instruction: IRInstr,
    *,
    project_registers: bool = False,
) -> _ConsumedCallBoundary8616 | None:
    """Select the bound complete call proof for one in-path CALL row.

    The registry-bound pool serves registered caller artifacts; the
    entry-domain pool serves the in-flight callsite artifact whose own
    calls cannot carry coverage-bound proofs. Both bind the identical
    artifact, block, and instruction objects, and each candidate's
    scoped revalidation re-runs its whole retained chain under the
    authenticated consuming entry — a stale, forged, or foreign-scope
    record is refused rather than inherited.
    """
    proof = bound_call_preservation_at_instruction_8616(
        artifact, block, instruction, ctx.call_preservations
    )
    if proof is not None and proof.complete_for(None):
        names = proof.preserved_registers_for(None) if project_registers else None
        return _ConsumedCallBoundary8616(proof, None, names)
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
                typed_scope = cast(Real16InvocationDomain8616 | None, scope)
                names = scoped[0].preserved_registers_for(typed_scope) if project_registers else None
                return _ConsumedCallBoundary8616(scoped[0], typed_scope, names)
    # Reaching the pool lookup is itself a consultation, hit or miss.
    ctx.entry_call_pool_consulted = True
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
    return _consume_entry_call_record_8616(
        cast(_BoundaryProof8616, record),
        cast(Real16InvocationDomain8616 | None, scope),
        project_registers=project_registers,
        selector_scope=record.selector_scope,
    )


def _consume_entry_call_record_8616(
    record: _BoundaryProof8616,
    scope: Real16InvocationDomain8616 | None,
    *,
    project_registers: bool,
    selector_scope: DeclaredSegmentInvariant | None = None,
) -> _ConsumedCallBoundary8616 | None:
    """Authenticate either the record or its immediate segment projection once."""
    if selector_scope is not None:
        from .entry_domain_call_preservation import EntryDomainCallPreservation8616

        if type(record) is not EntryDomainCallPreservation8616 or scope is not None:
            return None
        selector_record = record
        if project_registers:
            names = selector_record.preserved_registers_for_selector(selector_scope)
            if not names:
                return None
        else:
            if not selector_record.complete_for_selector(selector_scope):
                return None
            names = None
        return _ConsumedCallBoundary8616(record, None, names, selector_scope)
    if project_registers:
        names = record.preserved_registers_for(scope)
        # Entry proofs require preserved CS to be complete; an empty
        # projection therefore keeps the original service-fallback route.
        if not names:
            return None
    else:
        if not record.complete_for(scope):
            return None
        names = None
    return _ConsumedCallBoundary8616(record, scope, names)


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
    linear base on success. Every frame byte requires declared memory coverage;
    header stack containment cannot authorize an arbitrary runtime SS:SP.
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
    if (ctx.arena is None
            or declared_memory_span_8616(ctx.environment, frame_linear, bound.frame_bytes) is None):
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    return frame_linear


def _declared_dosbox_entry_writes_8616(
    ctx: _PathCensusContext8616,
    bound: DeclaredInterruptService8616,
    registers: dict[str, int],
    artifact: IRFunctionArtifact,
) -> tuple[DosBoxInt21Write8616, ...] | Real16InvocationFailure8616:
    """Validate every explicit backend write before committing ordered effects."""
    policy = bound.dosbox_int21_entry_policy
    if policy is None:
        return ()
    ss = _register_read_8616("ss", registers)
    sp = _register_read_8616("sp", registers)
    if ss is None or sp is None:
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    saved = DosBoxInt21Registers8616(*(
        _register_read_8616(name, registers)
        for name in ("ax", "bx", "cx", "dx", "si", "di", "bp", "ds", "es")
    ))
    effects = dosbox_int21_frame_effects_8616(
        psp_segment=policy.psp_segment, ss=ss, sp=sp, registers=saved,
    )
    if effects.failure is not None:
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    # The shared architectural frame is consumed separately exactly once.
    writes = effects.writes[1:]
    spans = [*ctx.manifest]
    spans.extend((row.addr, row.size) for block in artifact.blocks for row in block.instrs
                 if row.addr is not None and row.size is not None)
    for write in writes:
        start, end = write.linear, write.linear + write.size
        if declared_memory_span_8616(ctx.environment, start, write.size) is None:
            return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
        if start < 0x400:
            return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
        if any(start < base + size and base < end for base, size in spans):
            return Real16InvocationFailure8616.CODE_WRITE_VIOLATION
        frame = effects.writes[0]
        if start < frame.linear + frame.size and frame.linear < end:
            return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
        if _dosbox_metadata_alias_8616(bound, start, end):
            return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    return writes


def _dosbox_metadata_alias_8616(bound: DeclaredInterruptService8616, start: int, end: int) -> bool:
    """Keep entry writes from invalidating the allocator's authenticated input."""
    surface = bound.resize
    if surface is not None and surface.dosbox is not None:
        return any(start < entry.address + len(entry.image) and entry.address < end
                   for entry in surface.dosbox.chain)
    return (surface is not None and start < surface.metadata_linear + len(surface.metadata)
            and surface.metadata_linear < end)


def _commit_dosbox_entry_writes_8616(
    ctx: _PathCensusContext8616, memory: PathMemory8616,
    writes: tuple[DosBoxInt21Write8616, ...],
) -> None:
    """Materialize native store order; unknown words revoke stale byte facts."""
    for write in writes:
        memory.apply_write(write.linear, write.size, write.data)
        ctx.checked_stores += 1


def _declared_service_crossing_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    instruction: IRInstr,
    registers: dict[str, int],
    memory: PathMemory8616,
) -> Real16InvocationFailure8616 | None:
    """Apply services only under an explicit application memory baseline.

    Existing boot routes keep their declared environment contract. Arbitrary
    application entries cannot inherit IVT or allocator bytes from startup
    unless their conditional declaration explicitly includes that baseline.
    Ordinary CALLs are not services and retain their call-boundary refusal.
    """
    if interrupt_call_vector_8616(instruction) is None:
        return Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    authority = _declared_entry_authority_8616(ctx.chain)
    if isinstance(authority, Real16InvocationFailure8616):
        return authority
    if authority is not None and not authority.spec.use_environment_memory:
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    return _cross_authenticated_declared_service_8616(ctx, artifact, instruction, registers, memory)


def _cross_authenticated_declared_service_8616(
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
    if bound.vectors is not None:
        return _declared_vector_service_apply_8616(
            ctx, bound, bound.vectors, registers, artifact, memory, al
        )
    frame_linear = _declared_service_frame_8616(
        ctx, bound, registers, artifact
    )
    if isinstance(frame_linear, Real16InvocationFailure8616):
        return frame_linear
    entry_writes = _declared_dosbox_entry_writes_8616(ctx, bound, registers, artifact)
    if isinstance(entry_writes, Real16InvocationFailure8616):
        return entry_writes
    _commit_dosbox_entry_writes_8616(ctx, memory, entry_writes)
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


def _vector_current_slot_8616(
    memory: PathMemory8616,
    surface: DeclaredVectorSurface8616,
    number: int,
) -> bytes | None:
    """Recompute the live four bytes of IVT slot ``number`` on this path.

    Reads the *path's* must-meet byte overlay, never a visitation-order
    ledger: a byte provably written on every path supplies its proven
    value, a byte possibly modified or content-unproven leaves the slot
    incomplete, and an unmodified byte keeps the declared initial IVT
    image the bound surface carries. ``None`` means the live slot is
    incomplete: the canonical owner is never fed guessed bytes. A prior
    admitted AH=25h commit is observed here because it joined the same
    overlay — query-after-update consumes the updated state, not the
    initial snapshot.
    """
    if memory.tainted:
        return None
    slot_linear = number * 4
    slot = bytearray(surface.ivt[slot_linear : slot_linear + 4])
    if len(slot) != 4:
        return None
    for offset in range(4):
        byte_addr = slot_linear + offset
        if byte_addr in memory.known:
            slot[offset] = memory.known[byte_addr]
        elif byte_addr in memory.unknown:
            return None
    return bytes(slot)


def _vector_slot_write_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    slot_linear: int,
    slot_after: bytes,
    memory: PathMemory8616,
) -> Real16InvocationFailure8616 | None:
    """Serialize one canonical IVT slot write into the path memory overlay.

    The exact four-byte span must be disjoint from every fetched byte and
    the module manifest, then commits with its proven bytes so a later
    AH=35h query on this path reads them rather than the declared initial
    image.
    """
    write_end = slot_linear + len(slot_after)
    for start, extent in ctx.manifest:
        if slot_linear < start + extent and start < write_end:
            return Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    for block in artifact.blocks:
        for fetched in block.instrs:
            if (
                type(fetched.addr) is int
                and type(fetched.size) is int
                and fetched.size > 0
                and slot_linear < fetched.addr + fetched.size
                and fetched.addr < write_end
            ):
                return Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    memory.apply_write(slot_linear, len(slot_after), slot_after)
    ctx.checked_stores += 1
    return None


def _vector_register_effects_8616(
    response: VectorResponseEffect8616,
    registers: dict[str, int],
) -> None:
    """Apply only the canonical ES/BX word writes; retain untouched lane facts.

    The validated vector relation models no other register changes. A proven
    EBX value preserves its high word when the BX result is installed; an
    unknown EBX stays unknown rather than acquiring invented upper bits.
    """
    if response.es is None or response.bx is None:
        return
    prior_ebx = _register_read_8616("ebx", registers)
    dirty: set[str] = set()
    _apply_register_write_8616("es", 2, response.es, registers, dirty)
    _apply_register_write_8616("bx", 2, response.bx, registers, dirty)
    if prior_ebx is not None:
        registers["ebx"] = (prior_ebx & 0xFFFF0000) | response.bx


def _declared_vector_service_apply_8616(
    ctx: _PathCensusContext8616,
    bound: DeclaredInterruptService8616,
    surface: DeclaredVectorSurface8616,
    registers: dict[str, int],
    artifact: IRFunctionArtifact,
    memory: PathMemory8616,
    number: int,
) -> Real16InvocationFailure8616 | None:
    """Commit one declared get/set-vector crossing under the bound relation.

    Requires proven AH (already bound as ``bound.function``), proven AL as
    the target vector ``number``, a proven SS/SP architectural frame
    disjoint from the dispatch slot, the *target* slot and every fetched
    byte, and — for AH=25h — proven DS/DX. The live slot bytes come from
    this path's must-meet overlay over the declared initial IVT image, so
    an earlier AH=25h commit or proven store is observed and a byte any
    predecessor path left unproven refuses. The shared canonical owner
    ``vector_response_8616`` computes the admitted effect; its typed
    DOS_UPDATE/FUNCTION_UNSUPPORTED refusals refuse the crossing honestly.
    Every AH=25h answer commits a real slot write, including identical bytes.
    The write still requires code/frame disjointness and joins the census.
    A later dispatch may conservatively refuse because its slot was written.
    """
    frame_linear = _declared_service_frame_8616(
        ctx, bound, registers, artifact
    )
    if isinstance(frame_linear, Real16InvocationFailure8616):
        return frame_linear
    slot_linear = number * 4
    if (
        frame_linear < slot_linear + 4
        and slot_linear < frame_linear + bound.frame_bytes
    ):
        # The architectural entry frame would clobber the live slot the
        # service reads or writes — the effect could not be authenticated.
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    entry_writes = _declared_dosbox_entry_writes_8616(
        ctx, bound, registers, artifact
    )
    if isinstance(entry_writes, Real16InvocationFailure8616):
        return entry_writes
    slot_before = _vector_current_slot_8616(memory, surface, number)
    if slot_before is None:
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    ds = dx = None
    if bound.function == INT21_SET_VECTOR_8616:
        ds = _register_read_8616("ds", registers)
        dx = _register_read_8616("dx", registers)
        if ds is None or dx is None:
            return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    response = vector_response_8616(
        function=bound.function,
        number=number,
        slot_before=slot_before,
        ds=ds,
        dx=dx,
    )
    if isinstance(response, VectorResponseRefusal8616):
        # DOS_UPDATE/FUNCTION_UNSUPPORTED are undeclared service state,
        # never a DOS error result — the crossing keeps the typed refusal.
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    # The architectural frame is a real write; its contents stay unmodeled.
    memory.apply_write(frame_linear, bound.frame_bytes, None)
    ctx.checked_stores += 1
    _commit_dosbox_entry_writes_8616(ctx, memory, entry_writes)
    if response.slot_after is not None:
        failure = _vector_slot_write_8616(
            ctx, artifact, slot_linear, response.slot_after, memory
        )
        if failure is not None:
            return failure
    ctx.service_consumptions.append(
        declared_vector_consumption_8616(
            bound,
            frame_linear=frame_linear,
            number=number,
            slot_before=slot_before,
            slot_after=response.slot_after,
            answer_es=response.es,
            answer_bx=response.bx,
            request_ds=ds,
            request_dx=dx,
        )
    )
    _vector_register_effects_8616(response, registers)
    return None


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


def _dosbox_resize_code_spans_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
) -> tuple[tuple[int, int], ...]:
    """Protect every previously fetched and retained native instruction byte."""
    return (*sorted(ctx.manifest), *((row.addr, row.size)
            for block in artifact.blocks for row in block.instrs
            if type(row.addr) is int and type(row.size) is int and row.size > 0))


def _dosbox_resize_metadata_after_8616(
    surface: DeclaredResizeSurface8616, effects: DosboxResizeEffects8616,
) -> bytes:
    """Project exact final-header effects without dropping other ordered writes."""
    updated = bytearray(effects.current_chain[-1])
    for write in effects.response.writes:
        if surface.metadata_linear <= write.address < surface.metadata_linear + len(updated):
            offset = write.address - surface.metadata_linear
            updated[offset:offset + len(write.data)] = write.data
    return bytes(updated)


def _declared_dosbox_resize_apply_8616(
    ctx: _PathCensusContext8616, bound: DeclaredInterruptService8616,
    surface: DeclaredResizeSurface8616, registers: dict[str, int],
    artifact: IRFunctionArtifact, memory: PathMemory8616,
) -> Real16InvocationFailure8616 | None:
    """Stage the entire native prefix and allocator effect before committing it."""
    policy = surface.dosbox
    ax, es, bx = (_register_read_8616(name, registers) for name in ("ax", "es", "bx"))
    if policy is None or ax is None or es is None or bx is None:
        return Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    frame = _declared_service_frame_8616(ctx, bound, registers, artifact)
    if isinstance(frame, Real16InvocationFailure8616):
        return frame
    entry = _declared_dosbox_entry_writes_8616(ctx, bound, registers, artifact)
    if isinstance(entry, Real16InvocationFailure8616):
        return entry
    # Model prefix order on a private path copy. A header touched by unknown
    # frame/save bytes must refuse, even when its initial bytes were declared.
    prepared = memory.copy()
    prepared.apply_write(frame, bound.frame_bytes, None)
    for write in entry:
        prepared.apply_write(write.linear, write.size, write.data)
    effects = stage_dosbox_resize_effects_8616(
        policy, environment=ctx.environment, memory=prepared,
        segment=es, paragraphs=bx, ax=ax,
        code_spans=_dosbox_resize_code_spans_8616(ctx, artifact),
        frame_spans=((frame, bound.frame_bytes),
                     *((write.linear, write.size) for write in entry[1:])),
    )
    if isinstance(effects, DosboxResizeEffectsRefusal8616):
        return (Real16InvocationFailure8616.CODE_WRITE_VIOLATION
                if effects is DosboxResizeEffectsRefusal8616.CODE_WRITE
                else Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN)
    response = effects.response
    memory.apply_write(frame, bound.frame_bytes, None)
    ctx.checked_stores += 1
    _commit_dosbox_entry_writes_8616(ctx, memory, entry)
    for allocator_write in response.writes:
        memory.apply_write(allocator_write.address, len(allocator_write.data), allocator_write.data)
        ctx.checked_stores += 1
    ctx.service_consumptions.append(declared_resize_consumption_8616(
        bound, frame_linear=frame, request_ax=ax,
        answer_ax=response.ax, answer_bx=response.bx, carry=response.carry,
        metadata_before=effects.current_chain[-1],
        metadata_after=_dosbox_resize_metadata_after_8616(surface, effects),
        dosbox_writes=response.writes, dosbox_current_chain=effects.current_chain,
        dosbox_new_header_before=effects.new_header_before,
    ))
    _resize_register_effects_8616(bound, response.ax, response.bx, response.carry, registers)
    return None


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
    if surface.dosbox is not None:
        return _declared_dosbox_resize_apply_8616(ctx, bound, surface, registers, artifact, memory)
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
    entry_writes = _declared_dosbox_entry_writes_8616(ctx, bound, registers, artifact)
    if isinstance(entry_writes, Real16InvocationFailure8616):
        return entry_writes
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
    _commit_dosbox_entry_writes_8616(ctx, memory, entry_writes)
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


def _consume_cross_call_boundary_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    block: IRBlock,
    instruction: IRInstr,
) -> _ConsumedCallBoundary8616 | None:
    """Share immediate authentication only when scope matching has no callbacks."""
    if _call_scope_uses_owned_identity_8616(ctx):
        return _consume_call_boundary_8616(
            ctx, artifact, block, instruction, project_registers=True,
        )
    proof = _call_boundary_proof_8616(ctx, artifact, block, instruction)
    if proof is None:
        return None
    scope = _ctx_consuming_scope_8616(ctx, artifact, proof)
    if scope is _CTX_SCOPE_REFUSE_8616:
        return _ConsumedCallBoundary8616(proof, None, ())
    typed_scope = cast(Real16InvocationDomain8616 | None, scope)
    names = proof.preserved_registers_for(typed_scope)
    return _ConsumedCallBoundary8616(proof, typed_scope, names)


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
        # A native interrupt has a separate source-bound declared effect.
        # Consume its frame, memory and register evidence in callee walks too;
        # ordinary nested calls still need a separate callee-write proof.
        return (
            _declared_service_crossing_8616(ctx, artifact, instruction, registers, memory)
            if interrupt_call_vector_8616(instruction) is not None
            else Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
        )
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
    consumed = _consume_cross_call_boundary_8616(ctx, artifact, block, instruction)
    if consumed is None:
        # No near-call boundary proof binds this row: either it lifts to an
        # interrupt vector — where exactly one declared service relation may
        # carry it — or it keeps the unchanged unproven-call verdict.
        return _unbound_call_failure_8616(
            ctx, artifact, instruction, registers, memory
        )
    proof = consumed.proof
    if (
        consumed.preserved_registers is None
        or "cs" not in consumed.preserved_registers
        or (
            _call_scope_uses_owned_identity_8616(ctx)
            and _ctx_consuming_scope_8616(ctx, artifact, proof) is not consumed.scope
        )
    ):
        return Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    if not _selector_incoming_state_bound_8616(consumed, registers):
        return Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    preserved_scope = consumed.scope
    callee = proof.callee
    if (
        type(callee) is not SegmentEffectClosureResult8616
        or type(callee.coverage.artifact) is not IRFunctionArtifact
    ):
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
    failure = _reconcile_call_exit_8616(
        proof, preserved_scope, callee, callee_exits, registers, memory,
        selector_scope=consumed.selector_scope,
    )
    if failure is None and ctx.prefix_capture_requested:
        _record_prefix_call_8616(ctx, artifact, block, instruction, consumed)
    return failure


def _record_prefix_call_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
    instruction: IRInstr, consumed: _ConsumedCallBoundary8616,
) -> None:
    """Charge optional exact consumption retention without revoking success."""
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    if consumed.selector_scope is not None:
        ctx.prefix_capture_requested = False
        return
    with segment_call_dependency_traversal_scope_8616() as traversal:
        pending = ctx.work_units - ctx.accounted_work_units
        if (time.monotonic() > ctx.deadline or ctx.work_units + 1 > ctx.work_limit
            or traversal.census_work_units + pending + 1 > traversal.census_work_limit):
            ctx.prefix_capture_requested = False
            return
        names = consumed.preserved_registers
        if names is None:
            ctx.prefix_capture_requested = False
            return
        ctx.work_units += 1
        ctx.prefix_call_consumptions.append(_PrefixConsumedCall8616(
            artifact, block, instruction, consumed.proof, consumed.scope, names,
        ))


def _unbound_call_failure_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    instruction: IRInstr,
    registers: dict[str, int],
    memory: PathMemory8616,
) -> Real16InvocationFailure8616 | None:
    """Preserve exhausted proof resources before admitting service fallback."""
    failure = _census_resource_failure_8616(ctx)
    if failure is not None:
        return failure
    return _declared_service_crossing_8616(
        ctx, artifact, instruction, registers, memory,
    )


def _reconcile_call_exit_8616(
    proof: _BoundaryProof8616,
    scope: Real16InvocationDomain8616 | None,
    callee: SegmentEffectClosureResult8616,
    callee_exits: dict[int, _PathState8616],
    registers: dict[str, int],
    memory: PathMemory8616,
    *, selector_scope: DeclaredSegmentInvariant | None = None,
) -> Real16InvocationFailure8616 | None:
    """Reauthenticate after simulation before transporting any callee effects."""
    if selector_scope is not None:
        from .entry_domain_call_preservation import EntryDomainCallPreservation8616

        if type(proof) is not EntryDomainCallPreservation8616 or scope is not None:
            return Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
        selector_record = proof
        preserved = set(selector_record.preserved_registers_for_selector(selector_scope))
    else:
        preserved = set(proof.preserved_registers_for(scope))
    if "cs" not in preserved:
        return Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    for name in tuple(registers):
        if name not in preserved:
            del registers[name]
    returned = _post_call_registers_8616(callee, callee_exits)
    dirty: set[str] = set()
    # Write narrow views first so a proven containing view restores all of
    # its lanes last; partial returns invalidate stale containing constants.
    for name in sorted(returned, key=lambda item: (_register_width_8616(item) or 0, item)):
        width = _register_width_8616(name)
        if width is not None:
            _apply_register_write_8616(name, width // 8, returned[name], registers, dirty)
    memory.assign(_post_call_memory_8616(callee, callee_exits))
    return None


def _post_call_registers_8616(
    callee: SegmentEffectClosureResult8616,
    callee_exits: dict[int, _PathState8616],
) -> dict[str, int]:
    """Meet source-bound return values independently across every return exit.

    Normalize overlapping register views through the canonical lane owner
    before meeting: a return with AX and one with AL/AH can prove the same
    AX. Missing or disagreeing values stay unknown independently, including
    SP. Callee IP/EIP describe its return transfer, never caller data state.
    """
    if not callee.return_block_addrs or any(
        address not in callee_exits for address in callee.return_block_addrs
    ):
        return {}
    states = [callee_exits[address].registers for address in callee.return_block_addrs]
    candidates = {
        member
        for register in Arch86_16.register_list
        if register.general_purpose
        for member in register_value_family_8616(register.name)
    }
    normalized: list[dict[str, int]] = []
    for state in states:
        projected: dict[str, int] = {}
        for name in sorted(candidates):
            value = _register_read_8616(name, state)
            if type(value) is int:
                projected[name] = value
        normalized.append(projected)
    return _meet_registers_8616(normalized)


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


def _universal_callee_native_blocks_8616(
    ctx: _PathCensusContext8616, callee: SegmentEffectClosureResult8616,
    native: dict[int, IRBlock],
) -> dict[int, IRBlock] | Real16InvocationFailure8616:
    """Bind published leaf normalization to an independently proved native copy."""
    artifact = callee.coverage.artifact
    view = callee.coverage.scoped_view
    if (view is None and not callee.callsite_addrs
            and any(not _native_block_bound_8616(native.get(block.addr), block)
                    for block in artifact.blocks)):
        from .vex_import import universally_normalized_census_blocks_8616

        normalized = universally_normalized_census_blocks_8616(ctx.project, callee.coverage.boundary)
        if normalized is None:
            return Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
        raw_blocks, normalized_blocks = normalized
        ctx.work_units += sum(1 + len(block.instrs) for block in (*raw_blocks, *normalized_blocks))
        failure = _census_resource_failure_8616(ctx)
        if failure is not None:
            return failure
        if (set(native) != {block.addr for block in raw_blocks}
                or any(not _native_block_bound_8616(native.get(block.addr), block) for block in raw_blocks)):
            return Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
        # Only the canonical fresh universal theorem changes this reference.
        # The actual callee still binds every complete row before simulation.
        native = {block.addr: block for block in normalized_blocks}
    return native


def _census_callee_bytes_8616(
    ctx: _PathCensusContext8616,
    proof: _BoundaryProof8616,
) -> Real16InvocationFailure8616 | None:
    """Append a complete leaf callee's fetched bytes to the manifest.

    Byte census is seed-independent, so it runs once per callee identity
    before path simulation: caller stores that execute before a call are
    still checked against bytes the callee will fetch.
    A current scoped projection may reduce detached native IR copying only.
    All raw bytes remain protected, and simulation independently establishes
    its live scope and binds every executed row to the selected native IR.
    """
    callee = proof.callee
    if type(callee) is not SegmentEffectClosureResult8616:
        return Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
    callee = callee
    artifact = callee.coverage.artifact
    if not isinstance(artifact, IRFunctionArtifact):
        return Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
    callee_addr = artifact.function_addr
    if callee_addr in ctx.censused_callees:
        return None
    selected_blocks: frozenset[int] | None = None
    view = callee.coverage.scoped_view
    if view is not None:
        projection = view.cfg_projection_for(callee.state.invocation_scope)
        if projection is None or projection.source_artifact is not artifact:
            return Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
        selected_blocks = frozenset(block.addr for block in artifact.blocks) - projection.unreachable_block_addrs
    native = (
        _native_effect_blocks_8616(ctx, callee.coverage.boundary)
        if selected_blocks is None else
        _native_effect_blocks_8616(ctx, callee.coverage.boundary, selected_blocks=selected_blocks)
    )
    if isinstance(native, Real16InvocationFailure8616):
        # Census-level refusal: no row was classified, so the row ledger
        # stays untouched — the typed failure is the report.
        return native
    native = _universal_callee_native_blocks_8616(ctx, callee, native)
    if isinstance(native, Real16InvocationFailure8616):
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


def _callee_feasible_scope_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
    returns: frozenset[int], seed: _PathState8616,
    *, transfer_order: tuple[int, ...] | None = None,
) -> tuple[frozenset[int], frozenset[tuple[int, int]]] | Real16InvocationFailure8616:
    """Prune a shared-return callee under its own seed without dropping required exits."""
    if time.monotonic() > ctx.deadline:
        return Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
    if _census_work_exceeded_8616(ctx):
        return Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
    scope = frozenset(block.addr for block in artifact.blocks)
    dead_edges: frozenset[tuple[int, int]] = frozenset()
    # The return-summary consumer still requires every original return exit.
    # Restrict this optimization to the shared-return shape, preserving the
    # existing complete scope for multiple-return and malformed closures.
    if len(returns) == 1 and returns <= scope and any(
        row.op == "CJMP" for block in artifact.blocks for row in block.instrs
    ):
        blocks = {block.addr: block for block in artifact.blocks}
        terminal = blocks[next(iter(returns))]
        if terminal.instrs and type(terminal.instrs[-1].addr) is int:
            native = ctx.native_blocks.get(artifact.function_addr, {})
            load_rows = {
                id(row): (row, native_row)
                for block in artifact.blocks
                if any(type(row) is IRInstr and row.op == "LOAD" for row in block.instrs)
                if _native_block_bound_8616(native.get(block.addr), block)
                for row, native_row in zip(block.instrs, native[block.addr].instrs, strict=True)
                if row.op == "LOAD"
            }

            def read_load(
                instruction: IRInstr, span: tuple[int, int] | None, memory: PathMemory8616,
            ) -> int | None:
                """Publish callee LOAD constants only from native-bound rows and live memory."""
                pair = load_rows.get(id(instruction))
                if pair is None or pair[0] is not instruction or not _native_instr_equal_8616(instruction, pair[1], 0):
                    return None
                value = path_load_value_8616(instruction, span, memory, ctx.initial_memory)
                return value if type(value) is int else None

            feasible = invocation_feasible_scope_8616(
                artifact=artifact, dangerous=scope,
                predecessor_map=build_x86_16_ir_predecessor_map(artifact),
                head_addr=artifact.function_addr, call_block_addr=terminal.addr,
                callsite_addr=terminal.instrs[-1].addr,
                seed=seed.registers, seed_memory=seed.memory, read_load=read_load,
                apply_service=lambda _instruction, _registers, _memory: False,
                iteration_limit=_PATH_STATE_ITERATION_LIMIT_8616,
                deadline=ctx.deadline, work_limit=max(0, ctx.work_limit - ctx.work_units),
                transfer_order=transfer_order,
                load_snapshot_replay=(
                    LoadSnapshotReplay8616.READ_ONLY_OWNED
                    if ctx.initial_memory is None or type(ctx.initial_memory) is InvocationInitialMemory8616
                    else LoadSnapshotReplay8616.OBSERVABLE
                ),
                branch_snapshot_replay=(
                    BranchSnapshotReplay8616.PURE_TRANSFER
                    if _CANONICAL_SNAPSHOT_CHECK_8616()
                    and (ctx.initial_memory is None or type(ctx.initial_memory) is InvocationInitialMemory8616)
                    else BranchSnapshotReplay8616.OBSERVABLE
                ),
            )
            ctx.work_units += feasible.work_units
            if time.monotonic() > ctx.deadline:
                return Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
            if _census_work_exceeded_8616(ctx):
                return Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
            if returns <= feasible.live_blocks:
                scope = feasible.live_blocks
                dead_edges = frozenset(feasible.infeasible_edges)
    return scope, dead_edges


def _projected_callee_return_rows_8616(
    callee: SegmentEffectClosureResult8616,
) -> tuple[IRInstr, ...] | None:
    """Bind raw return terminals to the current authenticated callee projection."""
    view = callee.coverage.scoped_view
    if view is None:
        return ()
    projection = view.cfg_projection_for(callee.state.invocation_scope)
    artifact = callee.coverage.artifact
    if projection is None or projection.source_artifact is not artifact:
        return None
    effective = {block.addr: block for block in projection.blocks}
    rows: list[IRInstr] = []
    for block in artifact.blocks:
        if block.addr not in callee.return_block_addrs:
            continue
        projected = effective.get(block.addr)
        if (projected is None or not projected.instrs or not block.instrs
                or projected.instrs[-1].op != "RET"):
            return None
        terminal = block.instrs[-1]
        if terminal.op == "JMP" and terminal.dst is None and len(terminal.args) == 1:
            rows.append(terminal)
    return tuple(rows)


def _callee_transfer_order_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
) -> tuple[int, ...] | Real16InvocationFailure8616 | None:
    """Attempt optional ordering once after a cycle, without retaining proof.

    Advice only selects the ordinary bounded fixpoint. It cannot supply an
    order, eliminate an edge or replace native effect authentication. Keep
    custom producers observable and check budgets even when advice is used.
    """
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    failure = _census_resource_failure_8616(ctx)
    if failure is not None:
        return failure
    owned = acyclic_invocation_order_8616 is _OWNED_CALLEE_ORDER_8616
    with segment_call_dependency_traversal_scope_8616() as traversal:
        if owned and artifact.function_addr in traversal.callee_default_order:
            return None
        ordered = acyclic_invocation_order_8616(
            frozenset(block.addr for block in artifact.blocks),
            build_x86_16_ir_predecessor_map(artifact), deadline=ctx.deadline,
            work_limit=max(0, ctx.work_limit - ctx.work_units),
        )
        ctx.work_units += ordered.work_units
        failure = _census_resource_failure_8616(ctx)
        if failure is not None:
            return failure
        if (owned and ordered.blocks is None
                and len(traversal.callee_default_order) < _CALLEE_ORDER_ADVICE_LIMIT_8616):
            traversal.callee_default_order.add(artifact.function_addr)
        blocks: tuple[int, ...] | None = ordered.blocks
        return blocks


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
    callee = callee
    artifact = callee.coverage.artifact
    if not isinstance(artifact, IRFunctionArtifact):
        return Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
    transfer_order: tuple[int, ...] | None = None
    if not callee.callsite_addrs and ctx.work_units < ctx.work_limit:
        order = _callee_transfer_order_8616(ctx, artifact)
        if isinstance(order, Real16InvocationFailure8616):
            return order
        transfer_order = order
    feasible = _callee_feasible_scope_8616(
        ctx, artifact, frozenset(callee.return_block_addrs), seed,
        transfer_order=transfer_order,
    )
    if isinstance(feasible, Real16InvocationFailure8616):
        return feasible
    scope, dead_edges = feasible
    return_rows = _projected_callee_return_rows_8616(callee)
    if return_rows is None:
        return Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
    fused_operations = _BASE_FUSED_CALLEE_OPERATIONS_8616 if not callee.callsite_addrs else None
    prior_return_rows = ctx.callee_return_rows
    ctx.callee_return_rows = return_rows
    try:
        with source_bound_callee_transfer_8616(ctx, artifact, fused_operations):
            return _simulate_scope_8616(
                ctx,
                artifact,
                scope,
                artifact.function_addr,
                seed,
                stop_after=None,
                callsite_addr=None,
                infeasible_edges=dead_edges,
                transfer_order=(
                    tuple(addr for addr in transfer_order if addr in scope)
                    if transfer_order is not None else None
                ),
            )
    finally:
        ctx.callee_return_rows = prior_return_rows


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


def _repeated_store_native_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
) -> tuple[object, Real16InvocationFailure8616 | None]:
    """Resolve the whole native block a repeated store must bind.

    A recorded consumed-row prefix copy can never satisfy a whole-block
    effect: the full block is re-derived through the same authenticated
    boundary the census already proved, the map entry is upgraded and the
    prefix record is consumed. ``(None, failure)`` refuses; ``(block,
    None)`` leaves the ordinary whole-block binding unchanged.
    """
    entry = ctx.prefix_native_entries.get((artifact.function_addr, block.addr))
    if entry is None:
        return ctx.native_blocks.get(artifact.function_addr, {}).get(block.addr), None
    full = _native_effect_blocks_8616(ctx, entry[0], selected_blocks=frozenset({block.addr}))
    if isinstance(full, Real16InvocationFailure8616):
        return None, full
    if block.addr in full:
        ctx.native_blocks[artifact.function_addr][block.addr] = full[block.addr]
    ctx.prefix_native_entries.pop((artifact.function_addr, block.addr), None)
    return full.get(block.addr), None


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
    native, prefix_failure = _repeated_store_native_8616(ctx, artifact, block)
    if prefix_failure is not None or not _native_block_bound_8616(native, block):
        return RepeatedStoreStatus8616.REFUSED, (
            prefix_failure
            if prefix_failure is not None
            else Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
        )
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
    fused = _try_active_fused_callee_transfer_8616(ctx, artifact, block, entry, stop_after)
    if fused is not None:
        return fused
    prefix: FusedCallerPrefix8616 | _PathState8616 | Real16InvocationFailure8616 | None
    prefix = _try_fused_caller_prefix_8616(ctx, artifact, block, entry, stop_after)
    if prefix is None:
        prefix = _prepare_ordinary_path_block_8616(ctx, artifact, block, entry, stop_after)
    if not isinstance(prefix, FusedCallerPrefix8616):
        assert prefix is not None
        return prefix
    return _resume_path_block_8616(ctx, artifact, block, prefix, stop_after)


def _prepare_ordinary_path_block_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
    entry: _PathState8616, stop_after: int | None,
) -> FusedCallerPrefix8616 | _PathState8616 | Real16InvocationFailure8616:
    """Preserve ordinary bind-before-effects ordering, including repeated stores."""
    binding_failure = _bind_path_block_before_transfer_8616(ctx, artifact, block, stop_after)
    if binding_failure is not None:
        return binding_failure
    registers = dict(entry.registers)
    memory = entry.memory.copy()
    status, failure = _apply_repeated_store_8616(
        ctx, artifact, block, registers, memory, entry.direction,
    )
    if status is not RepeatedStoreStatus8616.NOT_APPLICABLE:
        _record_repeated_store_rows_8616(ctx, artifact, block, failure)
        return failure if failure is not None else _PathState8616(registers, memory, entry.direction)
    return FusedCallerPrefix8616(
        0, registers, memory, DirectionTracker8616(registers, entry.direction),
        {}, set(), dict(registers), None,
    )


def _resume_path_block_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
    state: FusedCallerPrefix8616, stop_after: int | None,
) -> _PathState8616 | Real16InvocationFailure8616:
    """Execute only the bound suffix, retaining the complete scalar prefix state."""
    for index in range(state.next_index, len(block.instrs)):
        instruction = block.instrs[index]
        if type(instruction.addr) is not int:
            return Real16InvocationFailure8616.PATH_DECODE_MISMATCH
        if stop_after is not None and instruction.addr > stop_after:
            break
        if instruction.addr != state.current_addr:
            state.current_addr = instruction.addr
            state.instruction_entry = dict(state.registers)
            state.dirty = set()
        capture_terminal = (
            ctx.prefix_capture_requested and instruction.op == "CALL"
            and instruction.addr == ctx.callsite_addr and index == len(block.instrs) - 1
        )
        direction_before_call = state.direction.direction() if capture_terminal else None
        failure = _simulate_instruction_8616(
            ctx, artifact, block, instruction,
            state.registers, state.tmps, state.instruction_entry, state.dirty, state.memory,
            (block.addr, index),
        )
        if failure is not None:
            return failure
        if capture_terminal:
            # The row's existing charge includes constant-size continuation
            # metadata. No scalar container or fact set is copied here.
            ctx.prefix_terminal_call = _PrefixTerminalCall8616(
                artifact, block, index, instruction, direction_before_call,
                state.tmps, state.dirty, state.instruction_entry, instruction.addr,
            )
        state.direction.step(instruction, state.registers, state.tmps)
    return _PathState8616(state.registers, state.memory, state.direction.direction())


_CANONICAL_TERMINAL_CONTINUATION_8616: tuple[object, ...] = (
    _simulate_instruction_8616, _resume_path_block_8616, DirectionTracker8616.step,
)


def _terminal_call_owned_8616(
    artifact: IRFunctionArtifact, terminal: _PrefixTerminalCall8616,
) -> bool:
    """Require the exact physical-last CALL row before any continuation work."""
    block = terminal.block
    index = terminal.index
    if type(index) is not int or index < 0 or index != len(block.instrs) - 1:
        return False
    if terminal.artifact is not artifact or not any(owned is block for owned in artifact.blocks):
        return False
    return (
        block.instrs[index] is terminal.instruction
        and terminal.instruction.op == "CALL"
        and terminal.current_addr == terminal.instruction.addr
    )


def _prefix_cut_state_matches_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
    terminal: _PrefixTerminalCall8616, state: _PathState8616,
) -> bool:
    """Compare current converged cut data with the complete ordinary state.

    This prerequisite grants no native/source, seed, callback or fact-ledger
    authority. A consumer must establish those separately before resuming.
    Exact equality deliberately rejects extra or missing facts, partial joins,
    tainted memory and duplicate projection entries. Comparison consumes this
    operation's existing work/deadline allowance before touching containers.
    """
    feasible = ctx.edge_feasibility
    if feasible is None or not feasible.converged or feasible.call_cut is None:
        return False
    cut = feasible.call_cut
    ctx.work_units += (
        len(artifact.blocks) + len(cut.registers) + len(state.registers)
        + len(cut.memory_known) + len(state.memory.known)
        + len(cut.memory_unknown) + len(state.memory.unknown) + 1
    )
    if _census_resource_failure_8616(ctx) is not None:
        return False
    if not _terminal_call_owned_8616(artifact, terminal) or state.memory.tainted:
        return False
    direction_bound = cut.direction is state.direction and terminal.direction is state.direction
    if (
        cut.artifact is not artifact or cut.block is not terminal.block
        or cut.instruction is not terminal.instruction or cut.index != terminal.index
        or not direction_bound
    ):
        return False
    if (
        len(cut.registers) != len(state.registers)
        or len(cut.memory_known) != len(state.memory.known)
        or len(cut.memory_unknown) != len(state.memory.unknown)
    ):
        return False
    equal = (
        dict(cut.registers) == state.registers
        and dict(cut.memory_known) == state.memory.known
        and set(cut.memory_unknown) == state.memory.unknown
    )
    return equal and _census_resource_failure_8616(ctx) is None


def _resume_terminal_call_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
    terminal: _PrefixTerminalCall8616, state: _PathState8616,
) -> _PathState8616 | Real16InvocationFailure8616:
    """Execute a CURRENT-authenticated CALL continuation through ordinary effects.

    This low-level seam grants no prefix admission. Its caller must freshly
    establish seed/source/callback and must-state authority before supplying
    retained data. Native rows and carried writes still bind against this
    operation's complete manifest here. CALL's prior push rows are not rerun;
    the ordinary CALL interpreter authenticates and applies its callee afresh.
    """
    if time.monotonic() > ctx.deadline:
        return Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
    ctx.work_units += len(artifact.blocks) + 1
    failure = _census_resource_failure_8616(ctx)
    if failure is not None:
        return failure
    if not _terminal_call_owned_8616(artifact, terminal):
        return Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    ctx.work_units += len(state.registers) + len(state.memory.known) + len(state.memory.unknown) + 4
    failure = _census_resource_failure_8616(ctx)
    if failure is not None:
        return failure
    failure = _bind_path_block_before_transfer_8616(ctx, artifact, terminal.block, None)
    if failure is not None:
        return failure
    if not _feasibility_code_unmodified_8616(ctx, state.memory):
        return _census_resource_failure_8616(ctx) or Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    current = (_simulate_instruction_8616, _resume_path_block_8616, DirectionTracker8616.step)
    if not all(left is right for left, right in zip(current, _CANONICAL_TERMINAL_CONTINUATION_8616, strict=True)):
        return Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    registers = dict(state.registers)
    # This exact final CALL cannot write scalar temporaries, dirty lanes or
    # instruction-entry registers. The canonical interpreter receives them
    # only for reads; no suffix exists that could mutate the captured maps.
    continuation = FusedCallerPrefix8616(
        terminal.index, registers, state.memory.copy(),
        DirectionTracker8616(registers, terminal.direction),
        terminal.tmps, terminal.dirty, terminal.instruction_entry,
        terminal.current_addr,
    )
    stop = ctx.callsite_addr if terminal.block.addr == ctx.stop_block_addr else None
    return _resume_path_block_8616(ctx, artifact, terminal.block, continuation, stop)


def _scope_path_entry_8616(
    addr: int,
    head: int,
    predecessors: list[int],
    exits: dict[int, _PathState8616],
    seed: _PathState8616,
) -> _PathState8616 | None:
    """Meet available predecessors, including backedges into the seeded head."""
    ready = [exits[pred] for pred in predecessors if pred in exits]
    if addr == head:
        return _meet_path_state_8616(
            [_PathState8616(dict(seed.registers), seed.memory, seed.direction), *ready]
        )
    if predecessors and not ready:
        # Wait for a contributing predecessor; an empty meet would lose facts.
        return None
    return _meet_path_state_8616(ready)


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
    transfer_order: tuple[int, ...] | None = None,
    prefix_exit: tuple[int, _PathState8616] | None = None,
) -> dict[int, _PathState8616] | Real16InvocationFailure8616:
    """Fixpoint-simulate every in-scope block's effects under the seed.

    Returns the per-block exit state map on success so a callee-scope
    caller can recover the bound callee's proven return state; a typed
    refusal otherwise. Each authenticated root or callee census supplies
    only its own ``infeasible_edges``; callee scopes never inherit unrelated
    root pruning from the shared context.

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
    order = invocation_transfer_order_8616(scope, transfer_order)
    if order is None:
        return Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
    blocks_by_addr = {block.addr: block for block in artifact.blocks}
    predecessor_map = build_x86_16_ir_predecessor_map(artifact)
    entries: dict[int, _PathState8616] = {}
    exits: dict[int, _PathState8616] = {} if prefix_exit is None else {prefix_exit[0]: prefix_exit[1]}
    scope_callsite = ctx.callsite_addr
    ctx.callsite_addr = callsite_addr
    try:
        for _ in range(_PATH_STATE_ITERATION_LIMIT_8616):
            if time.monotonic() > ctx.deadline:
                return Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
            changed = False
            for addr in order:
                predecessors = [
                    pred for pred in predecessor_map.get(addr, ())
                    if (pred in scope or (prefix_exit is not None and pred == prefix_exit[0]))
                    and (pred, addr) not in infeasible_edges
                ]
                entry = _scope_path_entry_8616(addr, head, predecessors, exits, seed)
                if entry is None:
                    continue
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
        prefix_call_consumptions=[],
        callsite_call_state=None,
        callsite_memory=None,
        first_failure_site=None,
        edge_feasibility=None,
    )
    try:
        result = _declared_service_crossing_8616(
            scratch, artifact, instruction, registers, memory
        )
    finally:
        ctx.entry_call_pool_consulted = (
            ctx.entry_call_pool_consulted or scratch.entry_call_pool_consulted
        )
    ctx.work_units += scratch.work_units - before
    return result is None


def _feasibility_caller_range_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
) -> tuple[int, int] | None:
    """Protect the closed native interval after charged block-extent checks.

    Frontend closure partitions every decoded block into contiguous positive
    instructions inside decode_start..decode_end. Recheck primitive native
    extents and complete block-head correspondence here, rather than expanding
    every native instruction into all its IR rows. Including intervening gaps
    is conservative protection, never evidence authorizing effects.
    """
    ctx.work_units += 1
    if time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
        return None
    if type(boundary) is not ExactFunctionRangeBoundary8616 or boundary.project is not ctx.project or boundary.addr != artifact.function_addr:
        return None
    start, end = boundary.decode_start, boundary.decode_end
    if type(start) is not int or type(end) is not int or not 0 <= start <= boundary.addr < end:
        return None
    native_heads: set[int] = set()
    for candidate in boundary.blocks:
        ctx.work_units += 1
        if time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
            return None
        native_block = cast(_CensusBlockExtent8616, candidate)
        if type(native_block.addr) is not int or type(native_block.size) is not int or native_block.size <= 0 or native_block.addr in native_heads or not start <= native_block.addr < native_block.addr + native_block.size <= end:
            return None
        native_heads.add(native_block.addr)
    artifact_heads: set[int] = set()
    for block in artifact.blocks:
        ctx.work_units += 1
        if time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx) or type(block.addr) is not int or block.addr in artifact_heads:
            return None
        artifact_heads.add(block.addr)
    if not native_heads or native_heads != boundary.block_addrs_set or artifact_heads != native_heads:
        return None
    return start, end


@dataclass(frozen=True, slots=True)
class _FeasibilityCallBinding8616:
    """Owned callable over one private call map and captured native geometry.

    The rejection predicate and actual handler read the same private map.
    They are owned methods rather than caller-supplied proof callbacks.
    """

    ctx: _PathCensusContext8616
    artifact: IRFunctionArtifact
    boundary: ExactFunctionRangeBoundary8616
    selected_rows: dict[int, tuple[IRBlock, IRInstr]]
    blocks: tuple[IRBlock, ...]
    native_blocks: object
    captured: tuple[int, int]

    def __call__(
        self, instruction: IRInstr, registers: dict[str, int], memory: PathMemory8616,
    ) -> bool:
        """Bind current native geometry before fresh callee scratch effects."""
        ctx = self.ctx
        if time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
            return False
        pair = self.selected_rows.get(id(instruction))
        if self.artifact.blocks is not self.blocks or self.boundary.blocks is not self.native_blocks:
            return False
        if self.boundary.project is not ctx.project or self.boundary.addr != self.artifact.function_addr or (self.boundary.decode_start, self.boundary.decode_end) != self.captured:
            return False
        if pair is None or pair[1] is not instruction:
            return False
        start, end = self.captured
        return _feasibility_call_scratch_8616(
            ctx, self.artifact, pair[0], instruction, registers, memory,
            (*ctx.manifest, (start, end - start)),
            caller_range=ScratchCallerRange8616(start, end),
        )

    def terminal_noop(self, instruction: IRInstr) -> bool:
        """Prove this handler rejects the exact row before scratch effects."""
        if type(self.selected_rows) is not dict:
            return False
        pair = self.selected_rows.get(id(instruction))
        if pair is None:
            return True
        return type(pair) is tuple and len(pair) == 2 and pair[1] is not instruction


def _feasibility_call_handler_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    call_rows: dict[int, tuple[IRBlock, IRInstr]],
) -> _FeasibilityCallBinding8616 | None:
    """Capture a conservative native range and a detached private call map.

    The closed Frontend boundary protects every native instruction byte,
    including gaps between reachable blocks. Current fetched spans and all
    call/native proofs remain fresh per crossing.
    """
    if ctx.callsite_addr is None or not call_rows or time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
        return None
    captured = _feasibility_caller_range_8616(ctx, artifact, boundary)
    if captured is None:
        return None
    ctx.work_units += len(call_rows)
    if time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
        return None
    return _FeasibilityCallBinding8616(
        ctx, artifact, boundary, dict(call_rows), artifact.blocks, boundary.blocks, captured,
    )


def _feasibility_call_rows_8616(
    blocks: dict[int, IRBlock], native: dict[int, IRBlock],
    dangerous: frozenset[int], callsite_addr: int,
    *, call_cut: kb_owner_8616.Real16CallCutRequest8616 | None = None,
    prefix_blocks: frozenset[int] = frozenset(),
) -> dict[int, tuple[IRBlock, IRInstr]]:
    """Name native-bound interior CALLs for fresh branch or requested-cut state.

    An exact optional cut also needs current callee effects in a branchless
    scope. It opts into ordinary fresh hooks under the existing budgets; it
    never authorizes cached effects or changes the default no-branch shortcut.
    ``prefix_blocks`` names blocks whose native copy is a consumed-row prefix;
    they bind at the exact ``callsite_addr`` cutoff, never as whole blocks.
    """
    if call_cut is None and not any(row.op == "CJMP" for address in dangerous for row in blocks[address].instrs):
        # This pass only proves branch edges. Ordinary census simulation still
        # applies callee effects when a straight-line caller has no edge to prune.
        return {}
    return {
        id(row): (block, row)
        for address in dangerous
        for block in (blocks[address],)
        if any(type(row) is IRInstr and row.op == "CALL" and row.addr != callsite_addr for row in block.instrs)
        if _native_block_bound_8616(
            native.get(address), block,
            stop_after=callsite_addr if address in prefix_blocks else None,
        )
        for row in (
            block.instrs[:len(native[address].instrs)]
            if address in prefix_blocks else block.instrs
        )
        if row.op == "CALL" and row.addr != callsite_addr
    }


def _feasibility_protected_union_8616(
    ctx: _PathCensusContext8616, *, caller_range: ScratchCallerRange8616 | None = None,
    disjoint_outside: tuple[int, int] | None = None,
) -> tuple[tuple[int, int], ...] | None:
    """Build an operation-local exact interval union under the census budget.

    Each input-span insertion and each unique-span merge charges one work
    unit. Sorting only the unique typed intervals is bounded by that charged
    input size; it never visits their bytes. The original manifest remains
    authoritative and unchanged, and no union survives this operation.

    ``disjoint_outside`` is an optional half-open interval proven to contain
    every byte of interest. When the union's own accumulated envelope —
    derived during the already-charged input walk — cannot overlap it, the
    merge is skipped and an empty union is returned: no input span could
    intersect the byte range either way, so the exact merged form is
    unobservable to the caller. Intersecting or unproven envelopes keep the
    original charged merge unchanged.
    """
    intervals, envelope = _feasibility_union_inputs_8616(ctx, caller_range)
    if intervals is None:
        return None
    if disjoint_outside is not None and envelope is not None:
        exact_bounds = type(disjoint_outside[0]) is int and type(disjoint_outside[1]) is int
        if exact_bounds and (disjoint_outside[1] <= envelope[0] or envelope[1] <= disjoint_outside[0]):
            return ()
    merged: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        ctx.work_units += 1
        if time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
            return None
        if merged and start <= merged[-1][1]:
            previous_start, previous_end = merged[-1]
            merged[-1] = (previous_start, max(previous_end, end))
        else:
            merged.append((start, end))
    return tuple(merged)


def _feasibility_code_unmodified_8616(
    ctx: _PathCensusContext8616, memory: PathMemory8616,
    *, caller_range: ScratchCallerRange8616 | None = None,
) -> bool:
    """Check exact code/write overlap using the cheaper bounded query lane.

    Union construction is charged by its owner. Each span-size inspection,
    binary-search comparison and final containment check charges one unit;
    the dense lane retains one unit per protected-byte membership query.
    Written-byte ledgers are never copied and no result survives this call.

    Canonical tracked known bytes provide constant-time address bounds;
    small or foreign-root ledgers retain a bounded charged scan. Unknown
    bytes are always inspected. Envelope inspection costs less than the input
    walk it may spare. A written
    envelope provably disjoint from the union envelope skips the merge,
    size and lane work entirely with the identical ``True`` verdict;
    intersecting, unbounded or oversized ledgers keep the original exact
    lanes, paying at most this one bounded extra pass.
    """
    if memory.tainted or time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
        return False
    written_bytes = len(memory.known) + len(memory.unknown)
    manifest_size = (
        len(ctx.manifest)
        if type(ctx.manifest) in (set, frozenset, list, tuple) else 0
    )
    disjoint_outside = written_address_envelope_8616(
        ctx, memory.known, memory.unknown, manifest_size, _census_work_exceeded_8616,
    )
    if _census_resource_failure_8616(ctx) is not None:
        return False
    spans = _feasibility_protected_union_8616(
        ctx, caller_range=caller_range, disjoint_outside=disjoint_outside,
    )
    if spans is None:
        return False
    if not memory.known and not memory.unknown:
        return True
    protected_bytes = 0
    for start, end in spans:
        ctx.work_units += 1
        if time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
            return False
        protected_bytes += end - start
    if len(spans) + written_bytes * (len(spans).bit_length() + 1) < protected_bytes:
        return _feasibility_sparse_code_walk_8616(ctx, memory, spans)
    return _feasibility_code_byte_walk_8616(ctx, memory, spans)


def _feasibility_sparse_code_walk_8616(
    ctx: _PathCensusContext8616, memory: PathMemory8616,
    spans: tuple[tuple[int, int], ...],
) -> bool:
    """Check each written byte against the sorted union under the census budget."""
    for written in (memory.known, memory.unknown):
        for address in written:
            if not _feasibility_written_byte_outside_code_8616(ctx, spans, address):
                return False
    return True


def _feasibility_written_byte_outside_code_8616(
    ctx: _PathCensusContext8616, spans: tuple[tuple[int, int], ...], address: int,
) -> bool:
    """Charge each search comparison and exact half-open containment query."""
    lower, upper = 0, len(spans)
    while lower < upper:
        ctx.work_units += 1
        if time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
            return False
        middle = (lower + upper) // 2
        if spans[middle][0] <= address:
            lower = middle + 1
        else:
            upper = middle
    ctx.work_units += 1
    if time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
        return False
    return not lower or address >= spans[lower - 1][1]


def _feasibility_code_byte_walk_8616(
    ctx: _PathCensusContext8616, memory: PathMemory8616,
    spans: tuple[tuple[int, int], ...],
) -> bool:
    """Retain the dense lane's charged protected-byte membership queries."""
    for start, end in spans:
        for address in range(start, end):
            ctx.work_units += 1
            if time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
                return False
            if address in memory.known or address in memory.unknown:
                return False
    return True


def _feasibility_callsite_bytes_current_8616(
    ctx: _PathCensusContext8616, instruction: IRInstr,
) -> bool:
    """Rebind the exact caller CALL bytes after callee-side callbacks."""
    address = instruction.addr
    if type(address) is not int:
        return False
    encoded = ctx.machine_bytes.get(address)
    if encoded is None:
        return False
    ctx.work_units += len(encoded)
    if time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
        return False
    return _bind_fetched_bytes_8616(
        {address: (len(encoded), encoded)}, {address}, selector=ctx.selector,
        image=ctx.image, project=ctx.project,
    ) is None


def _feasibility_call_effect_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
    instruction: IRInstr, state: _PathState8616,
    *, caller_range: ScratchCallerRange8616 | None = None,
) -> bool:
    """Authenticate, byte-bind and simulate one nonrecursive leaf call."""
    consumed = _consume_cross_call_boundary_8616(ctx, artifact, block, instruction)
    if consumed is None or consumed.preserved_registers is None or "cs" not in consumed.preserved_registers:
        return False
    proof = consumed.proof
    if not _selector_incoming_state_bound_8616(consumed, state.registers):
        return False
    if _call_scope_uses_owned_identity_8616(ctx) and _ctx_consuming_scope_8616(ctx, artifact, proof) is not consumed.scope:
        return False
    callee = proof.callee
    if type(callee) is not SegmentEffectClosureResult8616 or type(callee.coverage.artifact) is not IRFunctionArtifact:
        return False
    address = callee.coverage.artifact.function_addr
    window = ctx.selector << _SEGMENT_SHIFT_8616
    if not window <= address <= window + _WORD_LIMIT_8616:
        return False
    if _census_callee_bytes_8616(ctx, proof) is not None:
        return False
    if not _feasibility_code_unmodified_8616(ctx, state.memory, caller_range=caller_range):
        return False
    exits = _simulate_callee_8616(ctx, proof, state)
    if isinstance(exits, Real16InvocationFailure8616):
        return False
    return _feasibility_callsite_bytes_current_8616(ctx, instruction) and _reconcile_call_exit_8616(
        proof, consumed.scope, callee, exits, state.registers, state.memory,
        selector_scope=consumed.selector_scope,
    ) is None


def _feasibility_apply_call_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    block: IRBlock,
    instruction: IRInstr,
    registers: dict[str, int],
    memory: PathMemory8616,
) -> bool:
    """Apply one current bound leaf call without publishing speculative census.

    Native bytes and the full caller/callee code manifest precede simulation;
    incoming path writes may not overlap either fetched-code surface. Late
    proof authentication precedes committing data effects. All speculative
    work is charged through the original resource owner, but its receipts,
    manifests and row ledgers never enter the real census.
    """
    if ctx.callsite_addr is None or instruction.addr == ctx.callsite_addr:
        return False
    if time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
        return False
    protected_spans = _dosbox_resize_code_spans_8616(ctx, artifact)
    return _feasibility_call_scratch_8616(
        ctx, artifact, block, instruction, registers, memory, protected_spans,
    )


def _feasibility_call_scratch_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
    instruction: IRInstr, registers: dict[str, int], memory: PathMemory8616,
    caller_spans: tuple[tuple[int, int], ...] | frozenset[tuple[int, int]],
    *, caller_range: ScratchCallerRange8616 | None = None,
) -> bool:
    """Run unchanged fresh call authentication over detached protective data.

    Prepared coordinates are not evidence: the canonical call proof, native
    callee binding, caller bytes and late preservation still authenticate every
    crossing. This private scratch consumer never publishes its manifest.
    """
    if ctx.callsite_addr is None or instruction.addr == ctx.callsite_addr:
        return False
    if time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
        return False
    before = ctx.work_units
    protected_spans = caller_spans
    scratch = replace(
        ctx,
        service_consumptions=[],
        prefix_call_consumptions=[],
        callsite_call_state=None,
        callsite_memory=None,
        manifest=set(protected_spans),
        fetched_span_admissions=0,
        machine_bytes={instruction.addr: ctx.machine_bytes[instruction.addr]} if instruction.addr in ctx.machine_bytes else {},
        native_blocks={},
        prefix_native_entries={},
        censused_callees=set(),
        raw_facts=set(), normalized_facts=set(), classified_facts=set(),
        materialized_facts=set(), failures=0, checked_stores=0,
        first_failure_site=None, edge_feasibility=None,
    )
    try:
        if time.monotonic() > scratch.deadline or _census_work_exceeded_8616(scratch):
            return False
        scratch.work_units += len(protected_spans) + len(registers) + memory.copy_work_units_8616()
        if _census_work_exceeded_8616(scratch):
            return False
        state = _PathState8616(dict(registers), memory.copy())
        applied = (
            _feasibility_call_effect_8616(scratch, artifact, block, instruction, state)
            if caller_range is None else
            _feasibility_call_effect_8616(scratch, artifact, block, instruction, state, caller_range=caller_range)
        )
        if not applied:
            return False
        if time.monotonic() > scratch.deadline or _census_work_exceeded_8616(scratch):
            return False
        registers.clear()
        registers.update(state.registers)
        memory.assign(state.memory)
        return True
    finally:
        ctx.work_units += scratch.work_units - before
        ctx.accounted_work_units = scratch.accounted_work_units
        ctx.entry_call_pool_consulted = (
            ctx.entry_call_pool_consulted or scratch.entry_call_pool_consulted
        )


def _prefix_execution_producers_8616() -> tuple[object, ...]:
    """Name current ordinary effect owners, including mutable dispatch owners."""
    return (*_fused_callee_producers_8616(), _simulate_scope_8616, _resume_path_block_8616,
            _cross_call_8616, _consume_cross_call_boundary_8616, _reconcile_call_exit_8616,
            _record_prefix_call_8616, _prefix_call_pools_bound_8616,
            _prefix_call_bound_8616, _prefix_calls_current_8616,
            _PrefixConsumedCall8616, _PrefixConsumedCall8616.__init__,
            new_census_fact_sets_8616, census_fact_ownership_8616, census_fact_ownership_current_8616)


def _prefix_root_bound_8616(old: _PathCensusContext8616, current: _PathCensusContext8616) -> bool:
    """Require the same authenticated root declaration and callback inputs."""
    left, right = old.chain, current.chain
    if type(left) is DeclaredFunctionEntryLink8616 and type(right) is DeclaredFunctionEntryLink8616:
        if left.admission is not right.admission:
            return False
    elif type(left) is not RawBootEntrySurface8616 or type(right) is not RawBootEntrySurface8616:
        return False
    return (old.project is current.project and old.boot is current.boot
            and old.selector == current.selector and old.environment is current.environment
            and old.environment_digest == current.environment_digest
            and old.arena == current.arena)


def _prefix_initial_memory_equal_8616(
    ctx: _PathCensusContext8616, left: InvocationInitialMemory8616 | None,
    right: InvocationInitialMemory8616 | None,
) -> bool:
    """Charge byte comparisons when fresh equivalent snapshots do not share bytes."""
    if left is None or right is None:
        return left is right
    ctx.work_units += len(left.chunks) + len(left.write_ranges) + 1
    if _census_resource_failure_8616(ctx) is not None:
        return False
    if left.write_ranges != right.write_ranges or len(left.chunks) != len(right.chunks):
        return False
    for (address, old), (current_address, current) in zip(left.chunks, right.chunks, strict=True):
        if address != current_address or len(old) != len(current):
            return False
        if old is not current:
            ctx.work_units += len(old)
            if _census_resource_failure_8616(ctx) is not None or old != current:
                return False
    return _census_resource_failure_8616(ctx) is None


def _prefix_inputs_equal_8616(
    ctx: _PathCensusContext8616, data: _OwnedPrefixCensus8616, seed: _PathState8616,
) -> bool:
    """Charge and match exact seeds, immutable initial bytes and proof pools."""
    old = data.context
    ctx.work_units += (len(seed.registers) + len(data.seed.registers)
                       + len(seed.memory.known) + len(data.seed.memory.known)
                       + len(seed.memory.unknown) + len(data.seed.memory.unknown)
                       + len(old.call_preservations) + len(old.entry_call_preservations) + 1)
    if _census_resource_failure_8616(ctx) is not None:
        return False
    if (data.boot_recompute is not ctx.prefix_boot_recompute or old.service_consumptions
        or not _prefix_root_bound_8616(old, ctx) or data.seed != seed):
        return False
    if not _prefix_call_pools_bound_8616(ctx, data):
        return False
    return _prefix_initial_memory_equal_8616(ctx, old.initial_memory, ctx.initial_memory)


def _prefix_call_pools_bound_8616(ctx: _PathCensusContext8616, data: _OwnedPrefixCensus8616) -> bool:
    """Match used CALL identities, preserving strict registry/service influence.

    Only entry-pool permutations and unused record regeneration are supported.
    Registry priority and service fallback retain their original identity order.
    A new proof object for a used CALL never substitutes the old authority.
    """
    old = data.context
    pools = ((old.call_preservations, ctx.call_preservations), (old.declared_services, ctx.declared_services))
    ctx.work_units += sum(len(a) for a, _ in pools) + len(data.consumed_calls) * (
        len(ctx.call_preservations) + len(ctx.entry_call_preservations) + 1)
    if _census_resource_failure_8616(ctx) is not None:
        return False
    if any(len(a) > len(b) or any(x is not y for x, y in zip(a, b[:len(a)], strict=True)) for a, b in pools):
        return False
    for consumed in data.consumed_calls:
        callee = consumed.proof.callee
        if (consumed.artifact is not data.artifact or callee is None or type(callee) is not SegmentEffectClosureResult8616
            or callee.callsite_addrs):
            return False
        if not any(proof is consumed.proof for proof in ctx.call_preservations) and not any(
            proof is consumed.proof for proof in ctx.entry_call_preservations
        ):
            return False
    return True


def _prefix_structural_extension_lower_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    *, reject_at: int | None = None,
) -> int | None:
    """Meter a lower bound, stopping once advice already rejects extension.

    An early bound grants no structural authority. Omitting later positive
    costs can only decline an unprofitable optimization; admitted extensions
    still require the full independent structural and native checks.
    """
    lower = 6 * len(artifact.blocks) + 5 * len(boundary.successor_edges) + 3
    if _census_resource_failure_8616(ctx) is not None:
        return None
    for block in artifact.blocks:
        if reject_at is not None and lower >= reject_at:
            return lower
        ctx.work_units += 1
        if _census_resource_failure_8616(ctx) is not None or type(block) is not IRBlock:
            return None
        lower += len(block.instrs) + 3 * len(block.successor_addrs)
    # Match the mandatory scans in real16_prefix_cut and the metered shared
    # CFG owner: input rows, six block-header visits, three IR-edge visits,
    # and five native-edge visits. Region/dominance work is additional.
    return lower


def _prefix_extension_profitable_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616, data: _OwnedPrefixCensus8616,
) -> bool:
    """Charge a conservative extension-only lower bound; grant no authority.

    Header lengths count mandatory structural prepayment/global census and
    retained native rebinding. Ordinary shared feasibility/native work is not
    included. Advice may only choose whether independent proof checks run.
    """
    lower = _prefix_structural_extension_lower_8616(ctx, artifact, boundary, reject_at=data.simulation_work)
    if lower is None:
        return False
    old = data.context
    if old.edge_feasibility is None:
        return False
    for function, blocks in old.native_blocks.items():
        ctx.work_units += 1
        if _census_resource_failure_8616(ctx) is not None:
            return False
        for address, block in blocks.items():
            ctx.work_units += 1
            if _census_resource_failure_8616(ctx) is not None or type(block) is not IRBlock:
                return False
            if function != data.artifact.function_addr or address in old.edge_feasibility.live_blocks:
                lower += len(block.instrs) + 1
    return lower < data.simulation_work and _census_resource_failure_8616(ctx) is None


def _select_prefix_extension_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616, seed: _PathState8616, callsite_addr: int,
) -> _OwnedPrefixCensus8616 | None:
    """Select guarded private data; selection grants no continuation authority."""
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    if type(ctx.chain) not in (DeclaredFunctionEntryLink8616, RawBootEntrySurface8616):
        return None
    selected = None
    with segment_call_dependency_traversal_scope_8616() as traversal:
        for identity, data in traversal.invocation_prefixes.items():
            ctx.work_units += 1
            if _census_resource_failure_8616(ctx) is not None:
                return None
            domain = traversal.retained_domains.get(identity)
            if (domain is None or identity in traversal.active_domains
                or traversal.domain_verdicts.get(identity) is not True):
                continue
            old = data.context
            # Owned closure authenticates membership without a second row walk.
            # Native comparisons still cost at least one visit per retained row.
            if (data.fact_ownership is None
                or len(old.raw_facts) + len(data.producers) >= data.simulation_work):
                continue
            if old.edge_feasibility is None or ctx.stop_block_addr in old.edge_feasibility.live_blocks:
                continue
            if (old.prefix_consumed or data.artifact is not artifact or data.boundary is not boundary
                or old.callsite_addr == callsite_addr or not _prefix_terminal_data_bound_8616(data)):
                continue
            if (_prefix_extension_profitable_8616(ctx, artifact, boundary, data)
                and _prefix_inputs_equal_8616(ctx, data, seed)
                and (selected is None or len(old.raw_facts) > len(selected.context.raw_facts))):
                selected = data
    return selected


def _prefix_feasibility_request_8616(
    data: _OwnedPrefixCensus8616 | None,
) -> kb_owner_8616.Real16CallCutRequest8616 | None:
    """Observe the selected row during the existing current feasibility walk."""
    terminal = None if data is None else data.context.prefix_terminal_call
    if terminal is None:
        return None
    return kb_owner_8616.Real16CallCutRequest8616(
        terminal.artifact, terminal.block, terminal.index, terminal.instruction,
    )


def _prefix_suffix_scope_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, data: _OwnedPrefixCensus8616,
) -> frozenset[int] | None:
    """Charge the existing live graph's suffix and require unchanged prefix joins."""
    feasible, old_feasible = ctx.edge_feasibility, data.context.edge_feasibility
    terminal = data.context.prefix_terminal_call
    if feasible is None or old_feasible is None or terminal is None:
        return None
    blocks = {block.addr: block for block in artifact.blocks}
    pending, suffix = list(terminal.block.successor_addrs), set()
    dead = frozenset(feasible.infeasible_edges)
    while pending:
        addr = pending.pop()
        ctx.work_units += 1
        if _census_resource_failure_8616(ctx) is not None:
            return None
        if addr in suffix or addr not in feasible.live_blocks:
            continue
        suffix.add(addr)
        ctx.work_units += len(blocks[addr].successor_addrs)
        pending.extend(next_addr for next_addr in blocks[addr].successor_addrs if (addr, next_addr) not in dead)
    prefix = feasible.live_blocks - suffix
    if prefix != old_feasible.live_blocks or terminal.block.addr in suffix:
        return None
    old_dead = frozenset(edge for edge in old_feasible.infeasible_edges if edge[0] in prefix and edge[1] in prefix)
    current_dead = frozenset(edge for edge in feasible.infeasible_edges if edge[0] in prefix and edge[1] in prefix)
    return frozenset(suffix) if old_dead == current_dead else None


def _prefix_sources_current_8616(ctx: _PathCensusContext8616, data: _OwnedPrefixCensus8616) -> bool:
    """Reauthenticate all retained byte/producer keys after current callbacks."""
    from .native_import_surface_cache import native_census_source_current_8616
    from .vex_import import (
        _census_finishing_producers_8616,
        _census_raw_native_blocks_8616,
        _native_import_producers_8616,
    )

    old = data.context
    if (not old.prefix_sources.complete or not ctx.prefix_sources.complete
        or data.artifact.function_addr not in old.prefix_sources.bindings):
        return False
    producers = (_census_raw_native_blocks_8616, _census_reimport_8616,
                 *_census_finishing_producers_8616(), *_native_import_producers_8616())
    for address, binding in old.prefix_sources.bindings.items():
        current = ctx.prefix_sources.bindings.get(address)
        ctx.work_units += len(binding.boundary.reachable_instruction_addrs) + binding.boundary.size + 1
        if _census_resource_failure_8616(ctx) is not None:
            return False
        if (current is None or current.boundary is not binding.boundary
            or current.key is not binding.key or not native_census_source_current_8616(
                binding, producers=producers, allow_conditional_source=True)):
            return False
    actual = _prefix_execution_producers_8616()
    ctx.work_units += len(actual)
    return (len(actual) == len(data.producers) == len(_CANONICAL_PREFIX_EXECUTION_PRODUCERS_8616)
            and all(a is b is c for a, b, c in zip(
                actual, data.producers, _CANONICAL_PREFIX_EXECUTION_PRODUCERS_8616, strict=True))
            and _census_resource_failure_8616(ctx) is None)


def _prefix_block_facts_bound_8616(
    ctx: _PathCensusContext8616, data: _OwnedPrefixCensus8616,
    root_blocks: dict[int, IRBlock], function: int, address: int, block: IRBlock,
) -> int | None:
    """Rebind native rows, comparing an identical root owner only once.

    First binding authenticates all fields. With no intervening callback,
    repeating those exact inputs adds no evidence. Distinct root objects keep
    independent binding and work; post-callback freshness stays separate.
    """
    native = ctx.native_blocks.get(function, {}).get(address)
    ctx.work_units += len(block.instrs) + 1
    if _census_resource_failure_8616(ctx) is not None or not _native_block_bound_8616(native, block):
        return None
    if function == data.artifact.function_addr:
        root = root_blocks.get(address)
        if root is not block:
            ctx.work_units += len(block.instrs) + 1
        if (_census_resource_failure_8616(ctx) is not None
            or (root is not block and not _native_block_bound_8616(native, root))):
            return None
    return len(block.instrs)


def _prefix_native_rows_current_8616(ctx: _PathCensusContext8616, data: _OwnedPrefixCensus8616) -> bool:
    """Rebind retained root IR after callbacks without reopening transferred ledgers."""
    old_feasible = data.context.edge_feasibility
    if old_feasible is None:
        return False
    native = ctx.native_blocks.get(data.artifact.function_addr, {})
    for block in data.artifact.blocks:
        if block.addr not in old_feasible.live_blocks:
            continue
        ctx.work_units += len(block.instrs) + 1
        if _census_resource_failure_8616(ctx) is not None or not _native_block_bound_8616(native.get(block.addr), block):
            return False
    return True


def _prefix_call_bound_8616(
    ctx: _PathCensusContext8616, data: _OwnedPrefixCensus8616, block: IRBlock, row: IRInstr,
) -> bool:
    """Close one ordinary proof callback under the exact consuming scope."""
    consumed = _consume_cross_call_boundary_8616(ctx, data.artifact, block, row)
    if consumed is None or consumed.selector_scope is not None:
        return False
    if consumed.preserved_registers is None or "cs" not in consumed.preserved_registers:
        return False
    if (_call_scope_uses_owned_identity_8616(ctx)
        and _ctx_consuming_scope_8616(ctx, data.artifact, consumed.proof) is not consumed.scope):
        return False
    retained = tuple(record for record in data.consumed_calls if record.instruction is row)
    ctx.work_units += len(data.consumed_calls)
    if _census_resource_failure_8616(ctx) is not None or not retained:
        return False
    if any(record.artifact is not data.artifact or record.block is not block
           or record.proof is not consumed.proof or record.scope is not consumed.scope
           or record.preserved_registers != consumed.preserved_registers for record in retained):
        return False
    callee = consumed.proof.callee
    if (callee is None or type(callee) is not SegmentEffectClosureResult8616
        or type(callee.coverage) is not IRBoundaryCoverageResult8616
        or type(callee.coverage.artifact) is not IRFunctionArtifact):
        return False
    address = callee.coverage.artifact.function_addr
    return address in data.context.native_blocks and address in ctx.native_blocks


def _prefix_calls_current_8616(ctx: _PathCensusContext8616, data: _OwnedPrefixCensus8616) -> bool:
    """Perform ordinary fresh proof authentication for every skipped earlier CALL."""
    feasible = data.context.edge_feasibility
    terminal = data.context.prefix_terminal_call
    if feasible is None or terminal is None:
        return False
    rows: set[int] = set()
    for block in data.artifact.blocks:
        if block.addr not in feasible.live_blocks:
            continue
        for row in block.instrs:
            ctx.work_units += 1
            if _census_resource_failure_8616(ctx) is not None:
                return False
            if row.op != "CALL" or row is terminal.instruction:
                continue
            rows.add(id(row))
            if not _prefix_call_bound_8616(ctx, data, block, row):
                return False
    ctx.work_units += len(data.consumed_calls)
    if any(id(record.instruction) not in rows for record in data.consumed_calls):
        return False
    return _census_resource_failure_8616(ctx) is None


def _prefix_enrolled_current_8616(ctx: _PathCensusContext8616, data: _OwnedPrefixCensus8616) -> bool:
    """Require the exact still-guarded canonical enrollment at consumption."""
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    with segment_call_dependency_traversal_scope_8616() as traversal:
        for identity, retained in traversal.invocation_prefixes.items():
            ctx.work_units += 1
            if _census_resource_failure_8616(ctx) is not None:
                return False
            if retained is data:
                domain = traversal.retained_domains.get(identity)
                return (domain is not None and domain.project is ctx.project
                        and identity not in traversal.active_domains
                        and traversal.domain_verdicts.get(identity) is True)
    return False


def _prefix_facts_bound_8616(ctx: _PathCensusContext8616, data: _OwnedPrefixCensus8616) -> bool:
    """Authenticate unchanged owned ledgers and independently rebind native rows.

    Guarded successful enrollment and pinned canonical producers establish the
    original row provenance. The current ownership receipt detects subsequent
    ledger edits. Native maps can include unvisited callee blocks, so their row
    union is not a second definition of the completed census fact set.
    """
    old = data.context
    if data.counts != _census_counts_8616(old) or data.stores != old.checked_stores or old.failures:
        return False
    ctx.work_units += 32
    if _census_resource_failure_8616(ctx) is not None:
        return False
    if data.fact_ownership is None or not census_fact_ownership_current_8616(
        data.fact_ownership, (old.raw_facts, old.normalized_facts, old.classified_facts, old.materialized_facts),
    ):
        return False
    if old.edge_feasibility is None:
        return False
    ctx.work_units += len(data.artifact.blocks)
    root_blocks = {block.addr: block for block in data.artifact.blocks}
    for function, blocks in old.native_blocks.items():
        for address, block in blocks.items():
            if function == data.artifact.function_addr and address not in old.edge_feasibility.live_blocks:
                continue
            if _prefix_block_facts_bound_8616(ctx, data, root_blocks, function, address, block) is None:
                return False
    return _census_resource_failure_8616(ctx) is None


def _prefix_work_allowance_8616(ctx: _PathCensusContext8616) -> int:
    """Respect the same local and ambient allowance before structural work."""
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    with segment_call_dependency_traversal_scope_8616() as traversal:
        pending = ctx.work_units - ctx.accounted_work_units
        return max(0, min(ctx.work_limit - ctx.work_units,
                          traversal.census_work_limit - traversal.census_work_units - pending))


def _prefix_after_callbacks_8616(
    ctx: _PathCensusContext8616, data: _OwnedPrefixCensus8616,
) -> Real16InvocationFailure8616 | None:
    """Fail closed after ownership transfer if callbacks invalidate old sources."""
    ctx.work_units += len(data.context.prefix_sources.bindings)
    failure = _census_resource_failure_8616(ctx)
    if failure is not None:
        return failure
    if any(binding.boundary.near_return_continuations is not None
           for binding in data.context.prefix_sources.bindings.values()) and not _prefix_calls_current_8616(ctx, data):
        return _census_resource_failure_8616(ctx) or Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN
    if _prefix_sources_current_8616(ctx, data) and _prefix_native_rows_current_8616(ctx, data):
        return None
    return _census_resource_failure_8616(ctx) or Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN


def _prefix_extension_inputs_8616(
    ctx: _PathCensusContext8616, data: _OwnedPrefixCensus8616, seed: _PathState8616,
) -> bool:
    """Keep completion, ownership and admission checks before any data move."""
    return (_census_counts_8616(ctx) == (0, 0, 0, 0, 0) and ctx.checked_stores == 0
            and not ctx.service_consumptions and _prefix_enrolled_current_8616(ctx, data)
            and _prefix_inputs_equal_8616(ctx, data, seed))


def _try_prefix_extension_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616, seed: _PathState8616, data: _OwnedPrefixCensus8616,
) -> bool | Real16InvocationFailure8616:
    """Authenticate once, transfer exact ledgers, then run fresh CALL and suffix."""
    from .real16_prefix_cut import PrefixCallRow8616, PrefixCutBudget8616, PrefixCutExtent8616, admit_prefix_cut_8616

    old, terminal = data.context, data.context.prefix_terminal_call
    feasible = ctx.edge_feasibility
    if (ctx.callsite_addr is None or feasible is None or old.prefix_consumed
        or terminal is None or not _prefix_extension_inputs_8616(ctx, data, seed)):
        return False
    later = _callsite_block_8616(artifact, ctx.callsite_addr)
    if isinstance(later, Real16InvocationFailure8616):
        return False
    rows = [(index, row) for index, row in enumerate(later.instrs) if row.op == "CALL" and row.addr == ctx.callsite_addr]
    if len(rows) != 1 or ctx.stop_block_addr != later.addr:
        return False
    budget = PrefixCutBudget8616(_prefix_work_allowance_8616(ctx), ctx.deadline)
    structural = admit_prefix_cut_8616(
        artifact, boundary, PrefixCallRow8616(artifact, terminal.block, terminal.index, terminal.instruction),
        PrefixCallRow8616(artifact, later, rows[0][0], rows[0][1]), budget=budget,
        extent=PrefixCutExtent8616.BEFORE_LATER_CALL,
    )
    ctx.work_units += structural.work_units
    if not structural.complete:
        return _census_resource_failure_8616(ctx) or False
    suffix = _prefix_suffix_scope_8616(ctx, artifact, data)
    # The executor stops rows within the target block, not the graph globally.
    # Authenticate every actual live/suffix block against the absorbing extent.
    ctx.work_units += len(feasible.live_blocks) + (0 if suffix is None else len(suffix))
    if (_census_resource_failure_8616(ctx) is not None
        or structural.witness is None or suffix is None
        or not feasible.live_blocks.issubset(structural.witness.region)
        or not suffix.issubset(structural.witness.region)):
        return _census_resource_failure_8616(ctx) or False
    if (not _prefix_calls_current_8616(ctx, data)
        or not _prefix_sources_current_8616(ctx, data) or not _prefix_facts_bound_8616(ctx, data)):
        return _census_resource_failure_8616(ctx) or False
    if old.callsite_call_state is None or old.callsite_memory is None:
        return False
    state = _PathState8616(old.callsite_call_state, old.callsite_memory, terminal.direction)
    if not _prefix_cut_state_matches_8616(ctx, artifact, terminal, state):
        return _census_resource_failure_8616(ctx) or False
    if not _feasibility_code_unmodified_8616(ctx, state.memory):
        return _census_resource_failure_8616(ctx) or False
    return _execute_prefix_extension_8616(ctx, artifact, seed, data, state, suffix)


def _execute_prefix_extension_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, seed: _PathState8616,
    data: _OwnedPrefixCensus8616, state: _PathState8616, suffix: frozenset[int],
) -> bool | Real16InvocationFailure8616:
    """Move single-use facts and execute only current ordinary CALL/suffix effects."""
    old, terminal, feasible = data.context, data.context.prefix_terminal_call, ctx.edge_feasibility
    if terminal is None or feasible is None:
        return False
    ctx.work_units += len(data.consumed_calls)
    failure = _census_resource_failure_8616(ctx)
    if failure is not None:
        return failure
    ctx.prefix_call_consumptions.extend(data.consumed_calls)
    old.prefix_consumed = True
    ctx.raw_facts, old.raw_facts = old.raw_facts, set()
    ctx.normalized_facts, old.normalized_facts = old.normalized_facts, set()
    ctx.classified_facts, old.classified_facts = old.classified_facts, set()
    ctx.materialized_facts, old.materialized_facts = old.materialized_facts, set()
    ctx.checked_stores = old.checked_stores
    ctx.entry_call_pool_consulted |= old.entry_call_pool_consulted
    resumed = _resume_terminal_call_8616(ctx, artifact, terminal, state)
    if isinstance(resumed, Real16InvocationFailure8616):
        return resumed
    failure = _prefix_after_callbacks_8616(ctx, data)
    if failure is not None:
        return failure
    exits = _simulate_scope_8616(
        ctx, artifact, suffix, artifact.function_addr, seed,
        stop_after=ctx.callsite_addr, callsite_addr=ctx.callsite_addr,
        infeasible_edges=frozenset(feasible.infeasible_edges),
        prefix_exit=(terminal.block.addr, resumed),
    )
    if isinstance(exits, Real16InvocationFailure8616):
        return exits
    failure = _prefix_after_callbacks_8616(ctx, data)
    return failure if failure is not None else True


def _complete_prefix_extension_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616, seed: _PathState8616,
    prefix: _OwnedPrefixCensus8616 | None,
) -> bool | Real16InvocationFailure8616:
    """Keep optional absence on the ordinary path without fabricating facts."""
    return False if prefix is None else _try_prefix_extension_8616(ctx, artifact, boundary, seed, prefix)


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
    prefix = _select_prefix_extension_8616(ctx, artifact, boundary, seed, callsite_addr)
    native = _native_effect_blocks_8616(
        ctx, boundary, selected_blocks=dangerous,
        terminal=(call_block.addr, callsite_addr),
    )
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
    truncated = frozenset(
        address for function, address in ctx.prefix_native_entries
        if function == artifact.function_addr
    )
    load_rows = {
        id(row): (row, native_row)
        for addr in dangerous
        if any(type(row) is IRInstr and row.op == "LOAD" for row in blocks_by_addr[addr].instrs)
        if _native_block_bound_8616(
            native.get(addr), blocks_by_addr[addr],
            stop_after=callsite_addr if addr in truncated else None,
        )
        for row, native_row in zip(
            blocks_by_addr[addr].instrs[:len(native[addr].instrs)],
            native[addr].instrs, strict=True,
        )
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

    call_cut = _prefix_feasibility_request_8616(prefix)
    call_rows = _feasibility_call_rows_8616(
        blocks_by_addr, native, dangerous, callsite_addr, call_cut=call_cut,
        prefix_blocks=truncated,
    )

    call_binding = _feasibility_call_handler_8616(ctx, artifact, boundary, call_rows)
    apply_call = (
        call_binding
        if call_binding is not None and ctx.callsite_addr is not None
        else None
    )

    omission = (
        _snapshot_omission_hooks_8616(ctx)
        if _snapshot_omission_hooks_8616 is _CANONICAL_SNAPSHOT_HOOKS_8616
        else None
    )
    repeat_consult_noop = None if omission is None else omission[0]
    load_reader_readonly = None if omission is None else omission[1]
    terminal_call_noop = (
        _snapshot_terminal_noop_8616(call_binding, apply_call)
        if repeat_consult_noop is not None
        and _snapshot_terminal_noop_8616 is _CANONICAL_TERMINAL_NOOP_8616
        else None
    )
    call_replay_unobserved = (
        _snapshot_call_unobserved_8616(call_binding, apply_call)
        if omission is not None
        and _snapshot_call_unobserved_8616 is _CANONICAL_CALL_UNOBSERVED_8616
        else None
    )
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
        apply_call=apply_call,
        repeat_consult_noop=repeat_consult_noop,
        load_reader_readonly=load_reader_readonly,
        terminal_call_noop=terminal_call_noop,
        call_replay_unobserved=call_replay_unobserved,
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
        call_cut=call_cut,
    )
    failure = _census_feasible_path_callees_8616(
        ctx, artifact, blocks_by_addr, ctx.edge_feasibility, callsite_addr,
    )
    if failure is not None:
        return failure
    return _finish_invocation_scope_8616(ctx, artifact, boundary, seed, callsite_addr, prefix)


def _finish_invocation_scope_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616, seed: _PathState8616,
    callsite_addr: int, prefix: _OwnedPrefixCensus8616 | None,
) -> Real16InvocationFailure8616 | None:
    """Use admitted continuation or retain the ordinary full scope walk."""
    feasible = ctx.edge_feasibility
    if feasible is None:
        return Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN
    extended = _complete_prefix_extension_8616(ctx, artifact, boundary, seed, prefix)
    if isinstance(extended, Real16InvocationFailure8616):
        return extended
    if extended:
        return None
    before = ctx.work_units
    exits = _simulate_scope_8616(
        ctx,
        artifact,
        feasible.live_blocks,
        artifact.function_addr,
        seed,
        stop_after=callsite_addr,
        callsite_addr=callsite_addr,
        infeasible_edges=frozenset(feasible.infeasible_edges),
    )
    if isinstance(exits, Real16InvocationFailure8616):
        return exits
    ctx.prefix_simulation_work = ctx.work_units - before
    return None


def _census_feasible_path_callees_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    blocks_by_addr: dict[int, IRBlock],
    feasibility: Real16EdgeFeasibility8616,
    callsite_addr: int,
) -> Real16InvocationFailure8616 | None:
    """Account feasibility work before admitting further callee-proof consumers.

    Scratch call work and the feasibility row walk share this census budget.
    A resource refusal must survive instead of becoming missing-call evidence
    through further authentication after budget or deadline exhaustion.
    """
    ctx.work_units += feasibility.work_units
    failure = _census_resource_failure_8616(ctx)
    if failure is not None:
        return failure
    return _census_path_callees_8616(
        ctx, artifact, blocks_by_addr, feasibility.live_blocks, callsite_addr,
    )


def _census_path_callees_8616(
    ctx: _PathCensusContext8616,
    artifact: IRFunctionArtifact,
    blocks_by_addr: dict[int, IRBlock],
    dangerous: frozenset[int],
    callsite_addr: int,
) -> Real16InvocationFailure8616 | None:
    """Bind interior callee bytes only within the authenticated terminal prefix.

    The owning terminal block stops at its requested machine instruction,
    exactly as the caller byte census does. Other predecessor blocks remain
    complete even when their addresses exceed that terminal coordinate.
    """
    for addr in sorted(dangerous):
        for instruction in blocks_by_addr[addr].instrs:
            if instruction.op != "CALL" or instruction.addr == callsite_addr:
                continue
            if (addr == ctx.stop_block_addr and type(instruction.addr) is int
                    and instruction.addr > callsite_addr):
                continue
            consumed = _consume_call_boundary_8616(
                ctx, artifact, blocks_by_addr[addr], instruction,
            )
            if consumed is None:
                continue
            # Retain both premise kinds during byte-manifest authentication.
            # No selector effects are projected before path-state simulation.
            proof = consumed.proof
            if not _call_scope_uses_owned_identity_8616(ctx):
                scope = _ctx_consuming_scope_8616(ctx, artifact, proof)
                if scope is _CTX_SCOPE_REFUSE_8616 or not proof.complete_for(
                    cast(Real16InvocationDomain8616 | None, scope),
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


def _retained_parent_census_surface_8616(
    parent: Real16InvocationDomain8616 | None,
) -> tuple[IRFunctionArtifact, ExactFunctionRangeBoundary8616] | None:
    """Name the exact artifact/boundary objects a parent premise censused.

    Ordinary proven coverage is the retained surface. A
    ``RAW_BOOT_ENTRY_PATH`` premise carries no coverage by contract; its
    identical census objects live on the retained
    ``RawBootEntrySurface8616`` chain. This accessor only *names* retained
    objects — it grants no proof: ``parent.complete`` replays, decoded-row
    and index membership, and every edge identity check remain mandatory
    at their own sites. A coverage-free chained parent retains the callee
    surface reached by its link, not the earlier caller surface. Other kinds
    without an explicit retained surface still return ``None``.
    """
    if type(parent) is not Real16InvocationDomain8616:
        return None
    coverage = parent.coverage
    if coverage is not None:
        if type(coverage) is not IRBoundaryCoverageResult8616:
            return None
        return coverage.artifact, coverage.boundary
    chain = parent.chain
    if (
        parent.kind in (Real16InvocationKind8616.RAW_BOOT_ENTRY_PATH, Real16InvocationKind8616.DECLARED_FUNCTION_ENTRY)
        and (type(chain) is RawBootEntrySurface8616 or type(chain) is DeclaredFunctionEntryLink8616)
        and type(chain.artifact) is IRFunctionArtifact
        and type(chain.boundary) is ExactFunctionRangeBoundary8616
    ):
        return chain.artifact, chain.boundary
    if (parent.kind is Real16InvocationKind8616.CALL_CHAINED
            and type(chain) is Real16CallChainLink8616
            and type(chain.callee_artifact) is IRFunctionArtifact
            and type(chain.callee_boundary) is ExactFunctionRangeBoundary8616):
        return chain.callee_artifact, chain.callee_boundary
    return None


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

    Optional ``entry_binding`` independently proves the native near-CALL's
    control target under the identical parent prefix. It permits entry-only
    transport while the current candidate's return certificate is unfinished
    and remains visible in the parent pool. Callee return effects still need
    their own closure; an explicitly supplied invalid ``edge`` still refuses.
    Links without this certificate retain the existing edge-proof contract.
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
    entry_binding: DirectNearCallTargetBinding8616 | None = None

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
        ):
            return False
        parent_surface = _retained_parent_census_surface_8616(parent)
        if (
            parent_surface is None
            or self.callsite_artifact is not parent_surface[0]
            or self.callsite_boundary is not parent_surface[1]
        ):
            return False
        parent_artifact = parent_surface[0]
        if type(self.callsite_index) is not DecodedDirectCallsiteIndex8616:
            return False
        if not self.callsite_index.stats.closed:
            return False
        callsite = self.callsite
        if type(callsite) is not DecodedDirectCallsite8616 or callsite.is_far:
            return False
        if (
            callsite.callsite_addr != parent.callsite_addr
            or callsite.caller_start != parent_artifact.function_addr
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
        if not _chain_call_entry_bound_8616(self):
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

    The parent must still replay complete and name the identical retained
    census artifact/boundary pair, the index must remain a closed
    decoded index, and the retained row must be the exact in-index row
    at the parent's proven callsite inside the parent's proven head.
    """
    parent = link.parent
    if (
        type(parent) is not Real16InvocationDomain8616
        or not parent.complete
    ):
        return False
    parent_surface = _retained_parent_census_surface_8616(parent)
    if parent_surface is None:
        return False
    parent_artifact, parent_boundary = parent_surface
    if (
        link.callsite_artifact is not parent_artifact
        or link.callsite_boundary is not parent_boundary
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
        and callsite.caller_start == parent_artifact.function_addr
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
    parent_surface = _retained_parent_census_surface_8616(parent)
    if parent_surface is None:
        return False
    encoded = callsite.bound_near_coordinates(parent_surface[1])
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


def _near_call_entry_binding_bound_8616(
    chain: Real16CallChainLink8616,
    consumer: Callable[[Real16CallInvocation8616], bool] | None = None,
) -> bool:
    """Reauthenticate entry-only control evidence against the native CALL.

    This certificate proves the unconsumed near-CALL transports entry state;
    it proves no callee return or preservation effects. The parent pool stays
    intact, including this candidate's unfinished preservation record.
    """
    from inertia.semantics.direct_near_call_target_binding import (
        DirectNearCallTargetBinding8616,
        _consume_direct_near_call_target_binding_from_decoded_8616,
        _retained_binding_fields_equal_8616,
        _retained_coordinate_facts_8616,
    )

    binding = chain.entry_binding
    if binding is None or type(binding) is not DirectNearCallTargetBinding8616 or binding.invocation is None:
        return False
    invocation = binding.invocation
    parent = chain.parent
    if (
        type(invocation) is not Real16CallInvocation8616
        or invocation.premise is not parent or invocation.project is not parent.project
        or type(binding.callsite_addr) is not int or type(binding.target_addr) is not int
    ):
        return False
    if (
        binding.callsite_addr != parent.callsite_addr
        or binding.target_addr != chain.callee_artifact.function_addr
        or invocation.callsite_addr != binding.callsite_addr
        or invocation.target_addr != binding.target_addr
        or not any(block is invocation.block for block in chain.callsite_artifact.blocks)
    ):
        return False
    if not (
        _retained_coordinate_facts_8616(binding.callsite_addr, binding.target_addr, binding.shape)
        and binding.stats.closed
    ):
        return False
    instructions = tuple(
        row for row in invocation.block.instrs
        if row.op == "CALL" and row.addr == parent.callsite_addr
    )
    if len(instructions) != 1:
        return False
    def revalidate(candidate: Real16CallInvocation8616) -> bool:
        """Retain the transporting premise even when the target needs none."""
        return candidate.complete

    # A forward target may be unconditional while its callee entry is not.
    # The public target-only proof drops unnecessary invocation premises;
    # this entry-transport consumer must freshly validate and retain its own.
    replayed = _consume_direct_near_call_target_binding_from_decoded_8616(
        parent.project, block=invocation.block, instruction=instructions[0],
        decoded=chain.callsite, invocation=parent,
        consumer=revalidate if consumer is None else consumer,
    )
    # Reconcile only exact owned primitive records after the forced census:
    # no property/equality hook can invalidate the capture during this step.
    return _retained_binding_fields_equal_8616(binding, replayed)



def _chain_call_entry_bound_8616(chain: Real16CallChainLink8616) -> bool:
    """Select entry-only control or the unchanged retained-return contract."""
    if chain.entry_binding is None:
        return _chain_edge_bound_8616(
            chain.parent,chain.callsite_artifact,chain.callee_artifact.function_addr,chain.edge,
        )
    if chain.edge is not None and not _edge_proof_bound_8616(
        chain.edge,chain.callsite_artifact,chain.parent.callsite_addr,
        chain.callee_artifact.function_addr,chain.parent,
    ):
        return False
    return _near_call_entry_binding_bound_8616(chain)


def _chain_link_owned_identity_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    chain: Real16CallChainLink8616,
) -> Real16InvocationFailure8616 | None:
    """Bind exact owned parent/index/near-row and caller/callee surface identities.

    Native encoding, lookup membership and edge proof belong to the wrapper;
    this subset executes no native getter, loader callback or parent replay.
    """
    parent = chain.parent
    if (
        type(parent) is not Real16InvocationDomain8616
        or parent.project is not project
    ):
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    parent_surface = _retained_parent_census_surface_8616(parent)
    if parent_surface is None:
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    parent_artifact, parent_boundary = parent_surface
    if (
        chain.callsite_artifact is not parent_artifact
        or chain.callsite_boundary is not parent_boundary
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
    return None


def _chain_link_identity_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    chain: Real16CallChainLink8616,
    *,
    validate_entry: bool = True,
) -> Real16InvocationFailure8616 | None:
    """Bind the retained link's static identities before any replay.

    Every identity in the link must be the exact retained object: the
    typed parent premise with its retained census surface, the identical
    caller artifact and boundary objects the parent censused, the closed
    typed index, the exact decoded near-call row, the identical callee
    artifact/boundary
    under proof, index membership under the callee head's normalized
    identity, and the bound-edge proof rule. Any divergence refuses
    ``chain_link_unproven``.
    """
    failure = _chain_link_owned_identity_8616(project, artifact, boundary, chain)
    if failure is not None:
        return failure
    parent, callsite = chain.parent, chain.callsite
    # Lookup membership alone cannot prove the executed destination. Bind
    # the retained encoding to the parent census and require exact entry.
    if not _bound_callsite_entry_8616(
        parent, chain.callsite_index, callsite, artifact.function_addr,
    ):
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    if validate_entry and not _chain_call_entry_bound_8616(chain):
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    return None


def _derive_parent_for_chain_8616(
    parent: Real16InvocationDomain8616, chain_depth: int,
) -> _Derivation8616:
    """Force one current parent derivation without admitting a cached verdict."""
    return _derive_invocation_domain_8616(
        parent.project, parent.coverage, parent.callsite_addr, parent.boot,
        parent.boot_recompute, parent.call_preservations, chain=parent.chain,
        entry_call_preservations=parent.entry_call_preservations,
        declared_services=parent.declared_services, chain_depth=chain_depth + 1,
        prefix_capture=type(parent.chain) in (DeclaredFunctionEntryLink8616, RawBootEntrySurface8616),
    )


def _consume_chain_parent_8616(
    chain: Real16CallChainLink8616, chain_depth: int,
) -> _Derivation8616 | None:
    """Capture the one forced parent replay performed after native CALL gates."""
    captured: _Derivation8616 | None = None
    parent = chain.parent

    def consume(invocation: Real16CallInvocation8616) -> bool:
        """Force this exact parent capture inside the ordinary admission guard."""
        def verify() -> bool:
            """Capture source-bound effects while the parent remains active."""
            nonlocal captured
            captured = _derive_parent_for_chain_8616(parent, chain_depth)
            if captured.failure is not None or captured.domain is None:
                return False
            accepted = (
                _replayed_domain_equal_8616(captured, parent)
                and _invocation_use_bound_8616(
                    parent, project=invocation.project, block=invocation.block,
                    callsite_addr=invocation.callsite_addr, target_addr=invocation.target_addr,
                )
            )
            if accepted:
                _enroll_prefix_census_data_8616(parent, captured)
            return accepted

        if not _retained_domain_kind_bound_8616(parent):
            return False
        return parent._consume_completion_8616(verify, force_current=True)

    accepted = _near_call_entry_binding_bound_8616(chain, consume)
    if accepted:
        return captured
    if captured is not None and captured.failure is not None:
        return captured
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
    consume_entry = chain.entry_binding is not None and chain.edge is None
    identity_failure = _chain_link_identity_8616(
        project, artifact, boundary, chain, validate_entry=not consume_entry,
    )
    if identity_failure is not None:
        return identity_failure
    parent = chain.parent
    retained_state = _transported_call_state_8616(chain.call_state)
    if retained_state is None:
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    derived = (
        _consume_chain_parent_8616(chain, chain_depth) if consume_entry
        else _derive_parent_for_chain_8616(parent, chain_depth)
    )
    if derived is None:
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    return _chain_seed_from_capture_8616(chain, derived, retained_state)


def _chain_seed_from_capture_8616(
    chain: Real16CallChainLink8616, derived: _Derivation8616,
    retained_state: dict[str, int] | None = None,
) -> tuple[dict[str, int], PathMemory8616] | Real16InvocationFailure8616 | _NestedRefusal8616:
    """Consume exact caller state and memory without callbacks or another replay."""
    parent = chain.parent
    current_state = _transported_call_state_8616(chain.call_state)
    # Native binding callbacks run after the initial retained-state read.
    # That earlier copy cannot authenticate a link changed by a callback.
    if current_state is None or (retained_state is not None and retained_state != current_state):
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN
    retained_state = current_state
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
    parent_surface = _retained_parent_census_surface_8616(parent)
    if (
        type(parent) is not Real16InvocationDomain8616
        or parent.project is not project
        or parent_surface is None
        or link.callsite_artifact is not parent_surface[0]
        or link.callsite_boundary is not parent_surface[1]
    ):
        return Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN
    parent_artifact = parent_surface[0]
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


def _census_link_surface_8616(
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | RawBootEntrySurface8616 | DeclaredFunctionEntryLink8616,
) -> (
    tuple[object, object, object, object, Real16InvocationFailure8616]
    | Real16InvocationFailure8616
):
    """Name one retained link's census surface, anchor pair, and refusal.

    The *census surface* is the artifact/boundary pair the path proof
    actually runs over — the callee pair for a ``CALL_CHAINED`` link, the
    enclosing pair for an ``ENCLOSED_ENTRY`` link, the raw pair itself for
    a raw boot surface — while the *anchor pair* — always the callee pair
    — is what a supplied coverage must bind. A raw boot surface is
    eligible only when every retained refusal is a pending selector-window
    gate; raw census geometry is not edge proof, so any other refusal
    stays unbound. A declared application link accepts a refusal-free or
    selector-pending surface; its distinct seed authenticates the explicit
    entry authority instead of assuming original startup reaches that head.
    """
    if type(chain) is DeclaredFunctionEntryLink8616:
        pending = RawBootEntrySurface8616(chain.artifact, chain.boundary)
        refusals = (*chain.artifact.refusals, *(row for block in chain.artifact.blocks for row in block.refusals))
        if refusals and not raw_boot_entry_surface_pending_8616(pending):
            return Real16InvocationFailure8616.COVERAGE_UNBOUND
        return (chain.artifact, chain.boundary, chain.artifact, chain.boundary,
                Real16InvocationFailure8616.DECLARED_ENTRY_UNPROVEN)
    if type(chain) is RawBootEntrySurface8616:
        if not raw_boot_entry_surface_pending_8616(chain):
            return Real16InvocationFailure8616.COVERAGE_UNBOUND
        return (
            chain.artifact,
            chain.boundary,
            chain.artifact,
            chain.boundary,
            Real16InvocationFailure8616.COVERAGE_UNBOUND,
        )
    if type(chain) is Real16CallChainLink8616:
        return (
            chain.callee_artifact,
            chain.callee_boundary,
            chain.callee_artifact,
            chain.callee_boundary,
            Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN,
        )
    if type(chain) is Real16EnclosedEntryLink8616:
        return (
            chain.enclosing_artifact,
            chain.enclosing_boundary,
            chain.callee_artifact,
            chain.callee_boundary,
            Real16InvocationFailure8616.ENCLOSED_LINK_UNPROVEN,
        )
    return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN


def _derive_census_surface_8616(
    coverage: IRBoundaryCoverageResult8616 | None,
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | RawBootEntrySurface8616 | DeclaredFunctionEntryLink8616 | None,
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
    if chain is not None:
        link_surface = _census_link_surface_8616(chain)
        if isinstance(link_surface, Real16InvocationFailure8616):
            return link_surface
        (
            surface_artifact,
            surface_boundary,
            anchor_artifact,
            anchor_boundary,
            link_failure,
        ) = link_surface
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


def _declared_function_entry_seed_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    evidence: _BootEvidence8616,
    link: DeclaredFunctionEntryLink8616,
) -> tuple[int, _PathState8616, int, int, int, int, tuple[Real16InvocationAssumption8616, ...]] | Real16InvocationFailure8616:
    """Authenticate declared application state without traversing original startup.

    Source image bytes authenticate native instructions, not writable data at
    the application entry. Only the explicit baseline premise and overlays
    initialize memory; absent register lanes remain unknown.
    """
    from inertia.frontend.x86_16.declared_function_entry import (
        DeclaredFunctionEntryAdmission8616,
        revalidate_declared_function_entry_8616,
    )

    if type(link.admission) is not DeclaredFunctionEntryAdmission8616:
        return Real16InvocationFailure8616.DECLARED_ENTRY_UNPROVEN
    specification = link.admission.spec
    chunks = evidence.image.chunks
    if len(chunks) != 1 or chunks[0][0] != evidence.load_segment << _SEGMENT_SHIFT_8616:
        return Real16InvocationFailure8616.DECLARED_ENTRY_UNPROVEN
    base, module = chunks[0]
    if (
        evidence.environment_digest is None
        or not revalidate_declared_function_entry_8616(
            link.admission, source=evidence.source, loaded_module=module,
            environment_sha256=evidence.environment_digest,
        )
    ):
        return Real16InvocationFailure8616.DECLARED_ENTRY_UNPROVEN
    if (
        _loaded_bytes_8616(project, base, len(module)) != module
        or specification.load_segment != evidence.load_segment
        or specification.range_start != boundary.addr
        or specification.range_end != boundary.addr + boundary.size
    ):
        return Real16InvocationFailure8616.DECLARED_ENTRY_UNPROVEN
    if (
        (specification.entry_segment << _SEGMENT_SHIFT_8616) + specification.entry_offset != artifact.function_addr
        or link.artifact is not artifact or link.boundary is not boundary
    ):
        return Real16InvocationFailure8616.DECLARED_ENTRY_UNPROVEN
    registers = dict(specification.registers)
    registers["cs"] = specification.entry_segment
    memory = path_memory_initial_8616()
    for span in specification.memory:
        # Declared application memory may override writable module data, but
        # must not overlay this complete native function. Every fetched callee
        # is checked separately against the same original declaration.
        if span.address < boundary.addr + boundary.size and boundary.addr < span.address + len(span.data):
            return Real16InvocationFailure8616.CODE_WRITE_VIOLATION
        memory.apply_write(span.address, len(span.data), span.data)
    return (
        specification.entry_segment, _PathState8616(registers, memory),
        specification.entry_segment, specification.entry_offset,
        registers["ss"], registers["sp"],
        (Real16InvocationAssumption8616.DECLARED_FUNCTION_ENTRY,
         Real16InvocationAssumption8616.DECLARED_CODE_SCOPE,
         Real16InvocationAssumption8616.REPLAY_CORROBORATION),
    )


def _invocation_entry_seed_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
    evidence: _BootEvidence8616,
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | RawBootEntrySurface8616 | DeclaredFunctionEntryLink8616 | None,
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

    A ``None`` chain keeps the boot-entry rule — and a retained
    ``RawBootEntrySurface8616`` uses that same boot-entry seed, since a raw
    startup surface is boot-rooted too; only its census surface and
    pending-transfer handling differ: the source-authenticated
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
    if type(chain) is DeclaredFunctionEntryLink8616:
        return _declared_function_entry_seed_8616(project, artifact, boundary, evidence, chain)
    if chain is None or type(chain) is RawBootEntrySurface8616:
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
    consumptions: tuple[
        DeclaredServiceConsumption8616
        | DeclaredResizeConsumption8616
        | DeclaredVectorConsumption8616,
        ...,
    ],
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
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | RawBootEntrySurface8616 | DeclaredFunctionEntryLink8616 | None = None,
    entry_call_preservations: tuple[object, ...] = (),
    declared_services: tuple[DeclaredInterruptService8616, ...] = (),
    chain_depth: int = 0,
    construction: _DeclaredCallChainConstruction8616 | None = None,
    prefix_capture: bool = False,
) -> _Derivation8616:
    """Share the replay budget; optionally retain private diagnostic census data.

    Prefix capture grants no admission or reuse authority and is disabled for
    ordinary callers until current authentication and extension are implemented.
    """
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    with segment_call_dependency_traversal_scope_8616() as traversal:
        if time.monotonic() > _census_deadline_8616():
            return _early_derivation_8616(Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED)
        if traversal.census_work_units > traversal.census_work_limit:
            return _early_derivation_8616(Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED)
        return _derive_invocation_domain_body_8616(
            project, coverage, callsite_addr, boot, boot_recompute, call_preservations,
            chain=chain, entry_call_preservations=entry_call_preservations,
            declared_services=declared_services,
            chain_depth=chain_depth, construction=construction, prefix_capture=prefix_capture,
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


def _declared_entry_authority_8616(
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | RawBootEntrySurface8616 | DeclaredFunctionEntryLink8616 | None,
) -> DeclaredFunctionEntryAdmission8616 | Real16InvocationFailure8616 | None:
    """Inspect the root after all allowed links; refuse an unresolved origin.

    Entry seeding permits sixteen transport links followed by a declared root.
    An origin beyond that cap must not inherit the ordinary boot baseline.
    """
    for _ in range(_CHAIN_DEPTH_LIMIT_8616 + 1):
        if type(chain) is DeclaredFunctionEntryLink8616:
            return chain.admission
        if type(chain) not in (Real16CallChainLink8616, Real16EnclosedEntryLink8616):
            return None
        chain = cast(Real16CallChainLink8616 | Real16EnclosedEntryLink8616, chain).parent.chain
    return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN


def _invocation_initial_memory_for_entry_8616(
    evidence: _BootEvidence8616,
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | RawBootEntrySurface8616 | DeclaredFunctionEntryLink8616 | None,
) -> InvocationInitialMemory8616 | None:
    """Keep a declared root's unknown-memory policy across transported calls.

    The callsite snapshot transports known overlays. A descendant must not
    resurrect undeclared module/global bytes from the original loader state.
    """
    authority = _declared_entry_authority_8616(chain)
    if isinstance(authority, Real16InvocationFailure8616):
        return None
    initialized = invocation_initial_memory_8616(
        evidence.environment, evidence.environment_digest, evidence.image.chunks,
    )
    if authority is None:
        return initialized
    # Allocation authority does not imply known initial contents. Fresh native
    # writes may be read within authenticated ranges even when the entry omits
    # baseline bytes; unwritten data must stay unknown in descendants as well.
    chunks = (
        initialized.chunks
        if initialized is not None and authority.spec.use_environment_memory
        else ()
    )
    write_ranges = (
        () if initialized is None
        else tuple((base, len(data)) for base, data in initialized.chunks)
    )
    return InvocationInitialMemory8616(
        chunks + tuple((span.address, span.data) for span in authority.spec.memory),
        write_ranges=write_ranges,
    )


def _derive_invocation_domain_body_8616(
    project: object,
    coverage: IRBoundaryCoverageResult8616 | None,
    callsite_addr: int,
    boot: object,
    boot_recompute: Callable[[object], object] | None,
    call_preservations: tuple[SegmentCallPreservationResult8616, ...],
    *,
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | RawBootEntrySurface8616 | DeclaredFunctionEntryLink8616 | None = None,
    entry_call_preservations: tuple[object, ...] = (),
    declared_services: tuple[DeclaredInterruptService8616, ...] = (),
    chain_depth: int = 0,
    construction: _DeclaredCallChainConstruction8616 | None = None,
    prefix_capture: bool = False,
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
    surface = _construction_census_surface_8616(coverage, chain, construction)
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
    failure = _recompute_validated_boot_8616(boot, boot_recompute)
    if failure is not None:
        return _early_derivation_8616(failure)
    if (
        hashlib.sha256(evidence.source).hexdigest()
        != evidence.image.file_sha256
    ):
        return _early_derivation_8616(Real16InvocationFailure8616.BOOT_NOT_REPRODUCED)
    seeded, chain = _construction_entry_seed_8616(
        project, artifact, boundary, evidence, chain, chain_depth, construction,
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
    facts = new_census_fact_sets_8616() if prefix_capture else (set(), set(), set(), set())
    ctx = _PathCensusContext8616(
        project=project,
        selector=selector,
        initial_memory=_invocation_initial_memory_for_entry_8616(evidence, chain),
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
        manifest=set(),
        machine_bytes={},
        native_blocks={},
        checked_stores=0,
        censused_callees=set(),
        raw_facts=facts[0],
        normalized_facts=facts[1],
        classified_facts=facts[2],
        materialized_facts=facts[3],
        failures=0,
        work_units=0,
        work_limit=_CENSUS_WORK_LIMIT_8616,
        deadline=_census_deadline_8616(),
        first_failure_site=None,
        prefix_capture_requested=prefix_capture,
        prefix_boot_recompute=boot_recompute,
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
    consultation = (
        _EntryCallPoolConsultation8616.READ
        if ctx.entry_call_pool_consulted
        else _EntryCallPoolConsultation8616.UNUSED
    )
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
            entry_call_pool_consultation=consultation,
        )
    consumptions = tuple(ctx.service_consumptions)
    assumptions = _service_assumption_8616(assumptions, consumptions)
    path_blocks = (
        dangerous
        if ctx.edge_feasibility is None
        else ctx.edge_feasibility.live_blocks
    )
    captured = _retain_prefix_census_8616(ctx, seed, artifact, boundary, boot_recompute)
    return _Derivation8616(
        constructed_chain=chain if construction is not None and type(chain) is Real16CallChainLink8616 else None,
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
            fetched_range_count=ctx.fetched_span_admissions,
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
        entry_call_pool_consultation=consultation,
        prefix_census=captured,
    )


def _retain_prefix_census_8616(
    ctx: _PathCensusContext8616, seed: _PathState8616,
    artifact: IRFunctionArtifact, boundary: ExactFunctionRangeBoundary8616,
    boot_recompute: Callable[[object], object] | None,
) -> _OwnedPrefixCensus8616 | None:
    """Transfer successful private data if the original budget admits one handoff.

    Called only after ordinary census success. A capture miss keeps that success;
    it grants no authentication, replay verdict or extension permission.
    """
    if ctx.prefix_consumed or not ctx.prefix_capture_requested or ctx.prefix_terminal_call is None:
        return None
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    with segment_call_dependency_traversal_scope_8616() as traversal:
        pending = ctx.work_units - ctx.accounted_work_units
        estimate_work = len(artifact.blocks)
        if (time.monotonic() > ctx.deadline or ctx.work_units + estimate_work > ctx.work_limit
                or traversal.census_work_units + pending + estimate_work > traversal.census_work_limit):
            return None
        lower = _prefix_structural_extension_lower_8616(
            ctx, artifact, boundary, reject_at=ctx.prefix_simulation_work,
        )
        if lower is None or lower >= ctx.prefix_simulation_work:
            return None
        pending = ctx.work_units - ctx.accounted_work_units
        capture_work = 3 * len(_BASE_FUSED_CALLEE_OPERATIONS_8616.producers) + 39 + len(ctx.prefix_call_consumptions)
        if (time.monotonic() > ctx.deadline or ctx.work_units + capture_work > ctx.work_limit
                or traversal.census_work_units + pending + capture_work > traversal.census_work_limit):
            return None
        ctx.work_units += capture_work
        producers = _prefix_execution_producers_8616()
        ownership = census_fact_ownership_8616(
            (ctx.raw_facts, ctx.normalized_facts, ctx.classified_facts, ctx.materialized_facts),
        )
        if _census_resource_failure_8616(ctx) is not None:
            return None
        ctx.prefix_capture_requested = False
        return _OwnedPrefixCensus8616(
            ctx, seed, artifact, boundary, boot_recompute,
            _census_counts_8616(ctx), ctx.checked_stores, producers, ctx.prefix_simulation_work, ownership,
            tuple(ctx.prefix_call_consumptions),
        )


def _service_consumption_dict_8616(
    consumption: (
        DeclaredServiceConsumption8616
        | DeclaredResizeConsumption8616
        | DeclaredVectorConsumption8616
    ),
) -> dict[str, object]:
    """Serialize one consumed declared-service record with its kind tag."""
    if isinstance(consumption, DeclaredVectorConsumption8616):
        return {
            "kind": "vector",
            "callsite_addr": consumption.callsite_addr,
            "vector": consumption.vector,
            "function": consumption.function,
            "number": consumption.number,
            "slot_linear": consumption.slot_linear,
            "slot_before_hex": consumption.slot_before.hex(),
            "slot_after_hex": (
                None if consumption.slot_after is None
                else consumption.slot_after.hex()
            ),
            "answer_es": consumption.answer_es,
            "answer_bx": consumption.answer_bx,
            "request_ds": consumption.request_ds,
            "request_dx": consumption.request_dx,
            "frame_linear": consumption.frame_linear,
            "frame_bytes": consumption.frame_bytes,
            "relation_sha256": consumption.relation_sha256,
        }
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
    record: dict[str, object] = {
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
    if consumption.dosbox_writes is not None:
        record["dosbox_writes"] = [
            {"address": write.address, "data_hex": write.data.hex()}
            for write in consumption.dosbox_writes
        ]
        record["dosbox_current_chain"] = (
            None if consumption.dosbox_current_chain is None
            else [image.hex() for image in consumption.dosbox_current_chain]
        )
        record["dosbox_new_header_before_hex"] = (
            None if consumption.dosbox_new_header_before is None
            else consumption.dosbox_new_header_before.hex()
        )
    return record


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
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | RawBootEntrySurface8616 | DeclaredFunctionEntryLink8616 | None = field(
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
        DeclaredServiceConsumption8616
        | DeclaredResizeConsumption8616
        | DeclaredVectorConsumption8616,
        ...,
    ] = ()
    #: The exact classified census row that first failed, when the census
    #: reached one; ``None`` on success and on structural/budget refusals
    #: that never classified a row.
    refusal_site: Real16InvocationRefusalSite8616 | None = None
    #: ``(block_addr, successor_addr)`` edges proven untraversable under
    #: this exact invocation by the converged known-bits feasibility pass.
    #: Invocation-local evidence only — never a universal dead-code claim.
    infeasible_edges: tuple[tuple[int, int], ...] = ()

    #: Historical canonical consultation is scheduling advice only. Sharing
    #: still requires a fresh UNUSED receipt, not this retained observation.
    entry_call_pool_advice: _EntryCallPoolConsultation8616 = _EntryCallPoolConsultation8616.UNKNOWN

    @property
    def complete(self) -> bool:
        """Replay once per shared bounded traversal; cyclic evidence refuses."""
        return self._complete_with_fresh_derivation_8616(None)

    def _complete_with_fresh_derivation_8616(self, derived: _Derivation8616 | None) -> bool:
        """Apply the normal traversal gate to replay or an immediate derivation.

        Checked factories supply ``derived`` synchronously; public completeness
        supplies ``None`` and reauthenticates through its ordinary replay.
        """
        def verify() -> bool:
            """Consume the immediate derivation or perform ordinary replay."""
            if derived is None:
                return self._replay_complete_8616()
            return derived.failure is None and _replayed_domain_equal_8616(derived, self)

        return self._consume_completion_8616(verify)

    def _consume_completion_8616(
        self, verify: Callable[[], bool], *, force_current: bool = False,
    ) -> bool:
        """Run ordinary or forced-current verification inside one shared guard.

        Ordinary completeness retains its per-traversal verdict behavior. A
        synchronous consumer forces the verifier after all native callbacks,
        even for a cached positive, while preserving active-domain/depth bounds
        and charging an uncached domain only once. Cached refusals never replay.
        """
        return _consume_invocation_admission_8616(self, verify, force_current=force_current)

    def _replay_complete_8616(self) -> bool:
        """Recompute the retained domain only after entering the shared guard."""
        if self.failure is not None:
            return False
        link_bound = _retained_domain_kind_bound_8616(self)
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
            prefix_capture=type(self.chain) in (DeclaredFunctionEntryLink8616, RawBootEntrySurface8616),
        )
        if derived.failure is not None or derived.domain is None:
            return False
        if not _replayed_domain_equal_8616(derived, self):
            return False
        _enroll_prefix_census_data_8616(self, derived)
        return True

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
        authority = _declared_entry_authority_8616(self.chain)
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
            "entry_call_pool_advice": self.entry_call_pool_advice.value,
            "fetched_range_count": self.fetched_range_count,
            "checked_store_count": self.checked_store_count,
            "declared_function_entry": (
                authority.to_dict()
                if authority is not None and not isinstance(authority, Real16InvocationFailure8616) else None
            ),
            "chained": isinstance(
                self.chain,
                (Real16CallChainLink8616, Real16EnclosedEntryLink8616),
            ),
            "call_entry_binding": (
                {
                    "callsite_addr": self.chain.entry_binding.callsite_addr,
                    "target_addr": self.chain.entry_binding.target_addr,
                    "shape": (
                        self.chain.entry_binding.shape.to_dict()
                        if self.chain.entry_binding.shape is not None else None
                    ),
                    "entry_only": True,
                }
                if isinstance(self.chain, Real16CallChainLink8616)
                and self.chain.entry_binding is not None else None
            ),
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
class _DeclaredInvocationConstruction8616:
    """Resource-admission target for a fresh prefix; never a proof claim."""

    project: object
    surface: DeclaredFunctionEntryLink8616 | Real16CallChainLink8616
    callsite_addr: int
    boot: object
    boot_recompute: Callable[[object], object] | None
    coverage: IRBoundaryCoverageResult8616 | None = None
    entry_call_preservations: tuple[object, ...] = ()
    declared_services: tuple[DeclaredInterruptService8616, ...] = ()
    call_preservations: tuple[SegmentCallPreservationResult8616, ...] = ()
    required_scope: Real16InvocationDomain8616 | None = None

    @property
    def artifact(self) -> IRFunctionArtifact:
        """Name the caller artifact owned by this exact entry surface."""
        return self.surface.artifact if isinstance(self.surface, DeclaredFunctionEntryLink8616) else self.surface.callee_artifact

    @property
    def boundary(self) -> ExactFunctionRangeBoundary8616:
        """Name the caller boundary owned by this exact entry surface."""
        return self.surface.boundary if isinstance(self.surface, DeclaredFunctionEntryLink8616) else self.surface.callee_boundary


class _DeclaredNearBindingProvider8616(Protocol):
    """Canonical native binding owner invoked before the caller is constructed."""

    def __call__(
        self, factory: Callable[[], Real16CallInvocation8616 | None], /,
    ) -> DirectNearCallTargetBinding8616:
        """Run native gates first, then call the IR-owned fresh factory once."""
        ...


@dataclass(frozen=True, slots=True)
class _DeclaredCallChainConstruction8616:
    """Operation-local inputs; grants neither a premise nor a retained edge."""

    caller: _DeclaredInvocationConstruction8616
    callsite_index: DecodedDirectCallsiteIndex8616
    callsite: DecodedDirectCallsite8616
    block: IRBlock
    callee_artifact: IRFunctionArtifact
    callee_boundary: ExactFunctionRangeBoundary8616
    binding_provider: _DeclaredNearBindingProvider8616



_InvocationEntrySeed8616 = tuple[
    int, _PathState8616, int, int, int, int,
    tuple[Real16InvocationAssumption8616, ...],
]
type _RetainedInvocationLink8616 = (
    Real16CallChainLink8616 | Real16EnclosedEntryLink8616
    | RawBootEntrySurface8616 | DeclaredFunctionEntryLink8616 | None
)


def _construction_census_surface_8616(
    coverage: IRBoundaryCoverageResult8616 | None,
    chain: _RetainedInvocationLink8616,
    request: _DeclaredCallChainConstruction8616 | None,
) -> tuple[IRFunctionArtifact, ExactFunctionRangeBoundary8616] | Real16InvocationFailure8616:
    """Select only the raw native intake surface before a pending edge exists."""
    if request is None:
        return _derive_census_surface_8616(coverage, chain)
    if (not closed_ir_boundary_cfg_8616(request.callee_boundary, request.callee_artifact)
            or not _instruction_census_matches_8616(request.callee_boundary, request.callee_artifact)):
        return Real16InvocationFailure8616.COVERAGE_UNBOUND
    return request.callee_artifact, request.callee_boundary


def _construction_entry_seed_8616(
    project: object, artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616, evidence: _BootEvidence8616,
    chain: _RetainedInvocationLink8616, chain_depth: int,
    request: _DeclaredCallChainConstruction8616 | None,
) -> tuple[_InvocationEntrySeed8616 | Real16InvocationFailure8616 | _NestedRefusal8616, _RetainedInvocationLink8616]:
    """Resolve a pending edge only after boot callbacks, transporting pure capture."""
    if request is None:
        return _invocation_entry_seed_8616(project, artifact, boundary, evidence, chain, chain_depth), chain
    if _chain_link_depth_exceeded_8616(chain_depth):
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN, None
    resolved = _construct_declared_chain_entry_8616(request)
    if resolved is None:
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN, None
    actual, parent_capture = resolved
    captured_seed = _chain_seed_from_capture_8616(actual, parent_capture)
    if isinstance(captured_seed, _NestedRefusal8616 | Real16InvocationFailure8616):
        return captured_seed, actual
    registers, memory = captured_seed
    selector = registers["cs"]
    offset = artifact.function_addr - (selector << _SEGMENT_SHIFT_8616)
    if not 0 <= offset <= _WORD_LIMIT_8616 or "ss" not in registers:
        return Real16InvocationFailure8616.CHAIN_LINK_UNPROVEN, actual
    return (
        selector, _PathState8616(registers, memory), selector, offset,
        registers["ss"], registers["sp"],
        (*actual.parent.assumptions, Real16InvocationAssumption8616.CHAINED_CALL_ENTRY),
    ), actual


def _construct_declared_chain_entry_8616(
    request: _DeclaredCallChainConstruction8616,
) -> tuple[Real16CallChainLink8616, _Derivation8616] | None:
    """Bind native row/provenance first, then capture one guarded caller prefix."""
    target = request.caller
    row = request.callsite
    artifact, boundary = target.artifact, target.boundary
    if (type(row) is not DecodedDirectCallsite8616
            or type(request.callsite_index) is not DecodedDirectCallsiteIndex8616):
        return None
    encoded = row.bound_near_coordinates(boundary)
    if (
        encoded is None or encoded[1] != request.callee_artifact.function_addr
        or row.callsite_addr != target.callsite_addr
        or row.caller_start != artifact.function_addr
        or not request.callsite_index.stats.closed
    ):
        return None
    if not any(item is row for item in request.callsite_index.for_target(row.target_addr)):
        return None
    captured: tuple[Real16InvocationDomain8616, _Derivation8616] | None = None
    invocation: Real16CallInvocation8616 | None = None

    def construct() -> Real16CallInvocation8616 | None:
        """Authenticate after the provider's last native callback, once only."""
        nonlocal captured, invocation
        if captured is not None:
            return None
        captured = _construct_declared_invocation_domain_8616(target)
        if captured is None:
            return None
        parent, _derived = captured
        if not _invocation_use_bound_8616(
            parent, project=target.project, block=request.block,
            callsite_addr=target.callsite_addr, target_addr=request.callee_artifact.function_addr,
        ):
            return None
        invocation = Real16CallInvocation8616(
            parent, target.callsite_addr, request.callee_artifact.function_addr,
            target.project, request.block,
        )
        return invocation

    binding = request.binding_provider(construct)
    if (captured is None or invocation is None or binding.invocation is not invocation
            or binding.failure is not None or not binding.stats.closed):
        return None
    parent, derived = captured
    chain = Real16CallChainLink8616(
        parent, request.callsite_index, row, artifact, boundary,
        parent.callsite_call_state, request.callee_artifact, request.callee_boundary,
        entry_binding=binding,
    )
    if _chain_link_owned_identity_8616(
        target.project, request.callee_artifact, request.callee_boundary, chain,
    ) is not None:
        return None
    return chain, derived


def _construct_declared_chained_invocation_domain_8616(
    request: _DeclaredCallChainConstruction8616,
) -> tuple[DirectNearCallTargetBinding8616, Real16InvocationDomain8616] | None:
    """Validate callee boot first, then construct its caller and pure entry transport."""
    target = request.caller
    derived = _derive_invocation_domain_8616(
        target.project, None, request.callee_artifact.function_addr,
        target.boot, target.boot_recompute, (),
        declared_services=target.declared_services, construction=request,
    )
    chain = derived.constructed_chain
    if chain is None or chain.entry_binding is None:
        return None
    domain = _domain_from_derivation_8616(
        target.project, None, request.callee_artifact.function_addr,
        target.boot, target.boot_recompute, (), (), target.declared_services,
        Real16InvocationKind8616.CALL_CHAINED, chain, derived,
    )
    if not domain._complete_with_fresh_derivation_8616(derived):
        return None
    return chain.entry_binding, domain


def _consume_invocation_admission_8616(
    subject: Real16InvocationDomain8616 | _DeclaredInvocationConstruction8616,
    verify: Callable[[], bool],
    *, force_current: bool = False,
) -> bool:
    """Own the single active/depth/deadline/domain guard for replay and construction.

    Construction tokens acquire resource admission only. They neither retain a
    verdict nor occupy the proof registry; their live invocation pins identity
    until the active guard leaves. Canonical successful factories enroll only
    the real domain produced by the admitted native derivation.
    """
    construction = isinstance(subject, _DeclaredInvocationConstruction8616)
    if isinstance(subject, Real16InvocationDomain8616) and subject.failure is not None:
        return False
    from .segment_call_preservation import (
        DeclaredInvocationConstructionKey8616,
        segment_call_dependency_traversal_scope_8616,
    )

    with segment_call_dependency_traversal_scope_8616() as traversal:
        domain_identity = id(subject)
        identity = (
            DeclaredInvocationConstructionKey8616(
                id(subject.project), subject.artifact.function_addr, subject.callsite_addr,
            )
            if isinstance(subject, _DeclaredInvocationConstruction8616) else domain_identity
        )
        if identity in traversal.active_domains or time.monotonic() > _census_deadline_8616():
            return False
        cached = not construction and domain_identity in traversal.domain_verdicts
        if cached and (not force_current or not traversal.domain_verdicts[domain_identity]):
            return traversal.domain_verdicts[domain_identity]
        if traversal.census_work_units > traversal.census_work_limit:
            return False
        if (not cached and traversal.remaining_domains <= 0) or len(traversal.active_domains) >= _CHAIN_DEPTH_LIMIT_8616:
            return False
        if not cached:
            traversal.remaining_domains -= 1
        if isinstance(subject, Real16InvocationDomain8616):
            traversal.retained_domains[domain_identity] = subject
        traversal.active_domains.add(identity)
        verdict = False
        try:
            verdict = verify()
        finally:
            traversal.active_domains.remove(identity)
            if not construction and not verdict:
                # Paired admission may fail after its inner derivation succeeds.
                # Pending data never outlives a failed or exceptional verifier.
                traversal.invocation_prefixes.pop(domain_identity, None)
        if not construction:
            traversal.domain_verdicts[domain_identity] = verdict
        return verdict


def _nested_scope_inputs_8616(subject: Real16InvocationDomain8616) -> tuple[object, ...]:
    """Pin one operation's owned scope fields without equality callbacks."""
    memory = subject.callsite_memory
    return (
        subject.project, subject.coverage, subject.boot, subject.boot_recompute,
        subject.chain, subject.callsite_addr, subject.kind, subject.call_preservations,
        subject.entry_call_preservations, subject.declared_services, subject.entry_segment,
        subject.entry_offset, subject.stack_segment, subject.stack_offset, subject.load_segment,
        subject.source_sha256, subject.minimum_selector, subject.maximum_selector,
        subject.path_block_addrs, subject.fetched_range_count, subject.checked_store_count,
        subject.assumptions, subject.failure, subject.raw_fact_count, subject.normalized_fact_count,
        subject.classified_fact_count, subject.materialized_count, subject.failure_count,
        subject.callsite_call_state, memory, subject.service_consumptions, subject.infeasible_edges,
        None if memory is None else memory.known, None if memory is None else memory.unknown,
        None if memory is None else memory.tainted,
    )


def _nested_chain_inputs_8616(chain: Real16CallChainLink8616) -> tuple[object, ...] | None:
    """Pin bounded ancestry fields across the same synchronous native operation."""
    from inertia.frontend.x86_16.declared_function_entry import DeclaredFunctionEntryAdmission8616

    captured: list[object] = []
    current: _RetainedInvocationLink8616 = chain
    for _ in range(_CHAIN_DEPTH_LIMIT_8616):
        if current is None:
            captured.append(None)
            return tuple(captured)
        if type(current) is DeclaredFunctionEntryLink8616:
            if type(current.admission) is not DeclaredFunctionEntryAdmission8616:
                return None
            captured.extend((current, current.admission, current.admission.spec, current.artifact, current.boundary))
            return tuple(captured)
        if type(current) is RawBootEntrySurface8616:
            captured.extend((current, current.artifact, current.boundary))
            return tuple(captured)
        if type(current) not in (Real16CallChainLink8616, Real16EnclosedEntryLink8616):
            return None
        current = cast(Real16CallChainLink8616 | Real16EnclosedEntryLink8616, current)
        if type(current.parent) is not Real16InvocationDomain8616:
            return None
        captured.extend((current, current.parent, current.callsite_index, current.callsite,
                         current.callsite_artifact, current.callsite_boundary, current.call_state,
                         current.callee_artifact, current.callee_boundary, current.edge))
        if type(current) is Real16CallChainLink8616:
            captured.append(current.entry_binding)
        elif type(current) is Real16EnclosedEntryLink8616:
            captured.extend((current.enclosing_artifact, current.enclosing_boundary))
        captured.extend(_nested_scope_inputs_8616(current.parent))
        current = current.parent.chain
    return None


def _nested_capture_admitted_8616(units: int) -> bool:
    """Charge synchronous identity snapshots to the unchanged ambient allowance."""
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_work_units += units
        return (traversal.census_work_units <= traversal.census_work_limit
                and time.monotonic() <= _census_deadline_8616())


def _derive_construction_target_8616(
    target: _DeclaredInvocationConstruction8616,
) -> tuple[Real16InvocationDomain8616, _Derivation8616] | None:
    """Authenticate the original scope before one fresh caller construction."""
    surface = target.surface
    if type(surface) is DeclaredFunctionEntryLink8616:
        return _derive_declared_function_entry_domain_8616(
            target.project, surface, target.callsite_addr,
            boot=target.boot, boot_recompute=target.boot_recompute,
            coverage=target.coverage, entry_call_preservations=target.entry_call_preservations,
            declared_services=target.declared_services, prefix_capture=True,
        )
    required = target.required_scope
    if type(surface) is not Real16CallChainLink8616 or type(required) is not Real16InvocationDomain8616:
        return None
    captured = _nested_scope_inputs_8616(required)
    chain_capture = _nested_chain_inputs_8616(surface)
    if chain_capture is None or not _nested_capture_admitted_8616(len(captured) + len(chain_capture)):
        return None
    if (required.chain is not surface or required.project is not target.project
        or required.boot is not target.boot or required.boot_recompute is not target.boot_recompute):
        return None
    if (required.kind is not Real16InvocationKind8616.CALL_CHAINED
        or required.entry_call_preservations is not target.entry_call_preservations
        or required.declared_services is not target.declared_services or not required.complete):
        return None
    derived = _derive_chained_invocation_domain_8616(
        target.project, target.coverage, target.callsite_addr,
        boot=target.boot, boot_recompute=target.boot_recompute, chain=surface,
        call_preservations=target.call_preservations,
        entry_call_preservations=target.entry_call_preservations, declared_services=target.declared_services,
    )
    current = _nested_scope_inputs_8616(required)
    current_chain = _nested_chain_inputs_8616(surface)
    if current_chain is None or not _nested_capture_admitted_8616(len(current) + len(current_chain)):
        return None
    if (not all(left is right for left, right in zip(captured, current, strict=True))
        or len(chain_capture) != len(current_chain)
        or not all(left is right for left, right in zip(chain_capture, current_chain, strict=True))):
        return None
    if target.surface is not surface or derived[0].source_sha256 != required.source_sha256:
        return None
    return derived


def _construct_declared_invocation_domain_8616(
    target: _DeclaredInvocationConstruction8616,
) -> tuple[Real16InvocationDomain8616, _Derivation8616] | None:
    """Derive exactly once after normal admission, returning only current facts."""
    captured: tuple[Real16InvocationDomain8616, _Derivation8616] | None = None

    def verify() -> bool:
        """Run the canonical producer while construction remains active."""
        nonlocal captured
        captured = _derive_construction_target_8616(target)
        if captured is None:
            return False
        domain, derived = captured
        return derived.failure is None and _replayed_domain_equal_8616(derived, domain)

    if not _consume_invocation_admission_8616(target, verify):
        return None
    if captured is None:
        return None
    domain, _derived = captured
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.retained_domains[id(domain)] = domain
        traversal.domain_verdicts[id(domain)] = True
        _enroll_prefix_census_data_8616(domain, _derived)
    return captured


def _prefix_terminal_data_bound_8616(data: _OwnedPrefixCensus8616) -> bool:
    """Bind terminal metadata to its captured row without claiming native proof."""
    ctx = data.context
    terminal = ctx.prefix_terminal_call
    if terminal is None:
        return False
    index = terminal.index
    if type(index) is not int or index < 0 or index != len(terminal.block.instrs) - 1:
        return False
    return (
        terminal.artifact is data.artifact
        and ctx.stop_block_addr == terminal.block.addr
        and terminal.block.instrs[index] is terminal.instruction
        and terminal.instruction.addr == ctx.callsite_addr
    )


def _enroll_prefix_census_data_8616(
    subject: Real16InvocationDomain8616, derived: _Derivation8616,
) -> None:
    """Keep guarded successful replay data within its existing bounded traversal.

    Callers invoke this only after projection equality succeeds. Enrollment
    does not authenticate carried effects or permit callback/continuation reuse.
    Missing capture authority leaves the ordinary completed proof unchanged.
    """
    data = derived.prefix_census
    if derived.failure is not None or derived.domain is None or data is None:
        return
    chain = subject.chain
    if type(chain) not in (DeclaredFunctionEntryLink8616, RawBootEntrySurface8616):
        return
    root = cast(DeclaredFunctionEntryLink8616 | RawBootEntrySurface8616, chain)
    ctx = data.context
    if ctx.prefix_consumed:
        return
    source = ctx.prefix_sources.bindings.get(data.artifact.function_addr)
    if not ctx.prefix_sources.complete or source is None or not _prefix_terminal_data_bound_8616(data):
        return
    if (
        ctx.project is not subject.project or ctx.chain is not chain
        or data.artifact is not root.artifact or data.boundary is not root.boundary
    ):
        return
    if ctx.boot is not subject.boot or data.boot_recompute is not subject.boot_recompute:
        return
    if (
        source.project is not subject.project or source.boundary is not data.boundary
        or ctx.callsite_addr != subject.callsite_addr
    ):
        return
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    with segment_call_dependency_traversal_scope_8616() as traversal:
        identity = id(subject)
        if traversal.retained_domains.get(identity) is not subject:
            return
        if identity not in traversal.active_domains and traversal.domain_verdicts.get(identity) is not True:
            return
        traversal.invocation_prefixes[identity] = data


def _retained_domain_kind_bound_8616(domain: Real16InvocationDomain8616) -> bool:
    """Require the retained provenance link to match its typed domain kind."""
    if domain.kind is Real16InvocationKind8616.DECLARED_FUNCTION_ENTRY:
        link_bound = type(domain.chain) is DeclaredFunctionEntryLink8616
    elif domain.kind is Real16InvocationKind8616.BOOT_ENTRY_PATH:
        link_bound = domain.chain is None
    elif domain.kind is Real16InvocationKind8616.RAW_BOOT_ENTRY_PATH:
        link_bound = type(domain.chain) is RawBootEntrySurface8616 and domain.coverage is None
    elif domain.kind is Real16InvocationKind8616.CALL_CHAINED:
        link_bound = type(domain.chain) is Real16CallChainLink8616
    elif domain.kind is Real16InvocationKind8616.ENCLOSED_ENTRY:
        link_bound = type(domain.chain) is Real16EnclosedEntryLink8616
    else:
        link_bound = False
    return link_bound


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


def _discharge_consuming_artifact_8616(
    premise: Real16InvocationDomain8616,
    project: object,
) -> IRFunctionArtifact | None:
    """Return the premise's consumption-anchored artifact for ``project``.

    A coverage-bound premise consumes its registered artifact. A retained
    raw boot surface and a transported link — which may prove an in-flight
    callee artifact that cannot carry registry coverage — instead consume
    their identical retained census objects: the surface pair itself, or
    the link's callee pair for an ``ENCLOSED_ENTRY`` link whose census ran
    over the enclosing pair. Project identity is part of the anchor; a
    foreign project has no consuming surface.
    """
    coverage = premise.coverage
    if coverage is not None:
        if coverage.boundary.project is not project:
            return None
        return coverage.artifact
    chain = premise.chain
    if type(chain) is RawBootEntrySurface8616 or type(chain) is DeclaredFunctionEntryLink8616:
        if chain.boundary.project is not project:
            return None
        return chain.artifact
    if type(chain) not in (Real16CallChainLink8616, Real16EnclosedEntryLink8616):
        return None
    link = cast(Real16CallChainLink8616 | Real16EnclosedEntryLink8616, chain)
    if link.callee_boundary.project is not project:
        return None
    return link.callee_artifact


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
    return _invocation_use_bound_8616(
        premise, project=project, block=block, callsite_addr=callsite_addr,
        target_addr=target_addr,
    )


def _invocation_use_bound_8616(
    premise: Real16InvocationDomain8616,
    *, project: object, block: IRBlock, callsite_addr: int, target_addr: int,
) -> bool:
    """Check pure consumption coordinates after current premise authentication."""
    if premise.callsite_addr != callsite_addr:
        return False
    artifact = _discharge_consuming_artifact_8616(premise, project)
    if artifact is None:
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
    chain: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | RawBootEntrySurface8616 | DeclaredFunctionEntryLink8616 | None,
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
            entry_call_pool_advice=derived.entry_call_pool_consultation,
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
        entry_call_pool_advice=derived.entry_call_pool_consultation,
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


def _derive_declared_function_entry_domain_8616(
    project: object,
    surface: DeclaredFunctionEntryLink8616 | None,
    callsite_addr: int,
    *,
    boot: object,
    boot_recompute: Callable[[object], object] | None,
    coverage: IRBoundaryCoverageResult8616 | None = None,
    entry_call_preservations: Sequence[object] = (),
    declared_services: Sequence[DeclaredInterruptService8616] = (),
    prefix_capture: bool = False,
) -> tuple[Real16InvocationDomain8616, _Derivation8616]:
    """Prove a local native prefix under one explicit conditional entry authority.

    Missing declarations refuse; this route never substitutes the MZ header's
    entry or publishes a function artifact universally.
    """
    records = tuple(entry_call_preservations)
    services = tuple(declared_services)
    derived = (
        _early_derivation_8616(Real16InvocationFailure8616.DECLARED_ENTRY_UNPROVEN)
        if type(surface) is not DeclaredFunctionEntryLink8616 else _derive_invocation_domain_8616(
            project, coverage, callsite_addr, boot, boot_recompute, (),
            chain=surface, entry_call_preservations=records, declared_services=services,
            prefix_capture=prefix_capture,
        )
    )
    domain = _domain_from_derivation_8616(
        project, coverage, callsite_addr, boot, boot_recompute, (), records,
        services, Real16InvocationKind8616.DECLARED_FUNCTION_ENTRY, surface, derived,
    )
    return domain, derived


def prove_real16_declared_function_entry_domain_8616(
    project: object,
    surface: DeclaredFunctionEntryLink8616 | None,
    callsite_addr: int,
    *,
    boot: object,
    boot_recompute: Callable[[object], object] | None,
    coverage: IRBoundaryCoverageResult8616 | None = None,
    entry_call_preservations: Sequence[object] = (),
    declared_services: Sequence[DeclaredInterruptService8616] = (),
) -> Real16InvocationDomain8616:
    """Construct a retained conditional domain; later completeness replays normally."""
    domain, _derived = _derive_declared_function_entry_domain_8616(
        project, surface, callsite_addr, boot=boot, boot_recompute=boot_recompute,
        coverage=coverage, entry_call_preservations=entry_call_preservations,
        declared_services=declared_services,
    )
    return domain


def prove_fresh_real16_declared_function_entry_domain_8616(
    project: object,
    surface: DeclaredFunctionEntryLink8616 | None,
    callsite_addr: int,
    *,
    boot: object,
    boot_recompute: Callable[[object], object] | None,
    coverage: IRBoundaryCoverageResult8616 | None = None,
    entry_call_preservations: Sequence[object] = (),
    declared_services: Sequence[DeclaredInterruptService8616] = (),
) -> Real16InvocationDomain8616 | None:
    """Consume one new authenticated derivation without immediately deriving it twice.

    Projection equality and the unchanged traversal/deadline gate admit only
    the same fresh result. No derived evidence or positive cache is exported:
    later public ``domain.complete`` still invokes native/source replay.
    """
    if type(surface) is not DeclaredFunctionEntryLink8616:
        return None
    captured = _construct_declared_invocation_domain_8616(
        _DeclaredInvocationConstruction8616(
            project, surface, callsite_addr, boot, boot_recompute, coverage,
            tuple(entry_call_preservations), tuple(declared_services),
        )
    )
    return None if captured is None else captured[0]


def prove_real16_raw_boot_invocation_domain_8616(
    project: object,
    surface: RawBootEntrySurface8616,
    callsite_addr: int,
    *,
    boot: object,
    boot_recompute: Callable[[object], object] | None,
    entry_call_preservations: Sequence[object] = (),
    declared_services: Sequence[DeclaredInterruptService8616] = (),
) -> Real16InvocationDomain8616:
    """Census authenticated raw startup facts without publishing pending edges."""
    records = tuple(entry_call_preservations)
    services = tuple(declared_services)
    derived = _derive_invocation_domain_8616(
        project, None, callsite_addr, boot, boot_recompute, (),
        chain=surface, entry_call_preservations=records,
        declared_services=services,
    )
    return _domain_from_derivation_8616(
        project, None, callsite_addr, boot, boot_recompute, (), records,
        services, Real16InvocationKind8616.RAW_BOOT_ENTRY_PATH, surface, derived,
    )


def _derive_chained_invocation_domain_8616(
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
) -> tuple[Real16InvocationDomain8616, _Derivation8616]:
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
    domain = _domain_from_derivation_8616(
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
    return domain, derived


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
    """Construct a retained chained domain; public completeness replays normally."""
    domain, _derived = _derive_chained_invocation_domain_8616(
        project, coverage, callsite_addr, boot=boot, boot_recompute=boot_recompute,
        chain=chain, call_preservations=call_preservations,
        entry_call_preservations=entry_call_preservations, declared_services=declared_services,
    )
    return domain


def prove_fresh_real16_chained_invocation_domain_8616(
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
) -> Real16InvocationDomain8616 | None:
    """Consume one fresh chained derivation under unchanged traversal admission.

    Exact link typing retains the public replay kind/link gate. No fresh
    derivation escapes this factory; later public completeness still replays.
    """
    if type(chain) is not Real16CallChainLink8616:
        return None
    domain, derived = _derive_chained_invocation_domain_8616(
        project, coverage, callsite_addr, boot=boot, boot_recompute=boot_recompute,
        chain=chain, call_preservations=call_preservations,
        entry_call_preservations=entry_call_preservations, declared_services=declared_services,
    )
    return domain if domain._complete_with_fresh_derivation_8616(derived) else None



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


# Identity pin for the census importer: a rebound native-facts route skips
# this import only while the canonical producer itself is installed, so a
# replaced census importer is always invoked and never silently bypassed.
_CANONICAL_NATIVE_CENSUS_IMPORT_8616 = real16_native_census_import_8616


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
    if isinstance(left, Real16CallChainLink8616) and isinstance(right, Real16CallChainLink8616):
        left_binding, right_binding = left.entry_binding, right.entry_binding
        if left_binding is None or right_binding is None:
            return left_binding is right_binding
        return (
            left_binding.callsite_addr == right_binding.callsite_addr
            and left_binding.target_addr == right_binding.target_addr
            and left_binding.shape == right_binding.shape
            and left_binding.invocation is not None
            and right_binding.invocation is not None
            and left_binding.invocation.block is right_binding.invocation.block
            and left_binding.invocation.project is right_binding.invocation.project
        )
    return True


def _in_flight_scopes_coterminous_8616(
    left: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | RawBootEntrySurface8616 | DeclaredFunctionEntryLink8616 | None,
    right: Real16CallChainLink8616 | Real16EnclosedEntryLink8616 | RawBootEntrySurface8616 | DeclaredFunctionEntryLink8616 | None,
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
    if type(left) is DeclaredFunctionEntryLink8616 or type(right) is DeclaredFunctionEntryLink8616:
        return (
            type(left) is DeclaredFunctionEntryLink8616
            and type(right) is DeclaredFunctionEntryLink8616
            and left.admission is right.admission
            and left.artifact is right.artifact
            and left.boundary is right.boundary
        )
    if type(left) is RawBootEntrySurface8616 or type(right) is RawBootEntrySurface8616:
        if type(left) is not RawBootEntrySurface8616 or type(right) is not RawBootEntrySurface8616:
            return False
        raw_left = left
        raw_right = right
        return (
            raw_left.artifact is raw_right.artifact
            and raw_left.boundary is raw_right.boundary
        )
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


def _shared_replay_inputs_8616(
    offered: Real16InvocationDomain8616,
    required: Real16InvocationDomain8616,
) -> bool:
    """Require exact root replay inputs, including entry-call pool identity."""
    return (
        _shared_root_replay_inputs_8616(offered, required)
        and offered.entry_call_preservations is required.entry_call_preservations
    )


def _shared_root_replay_inputs_8616(
    offered: Real16InvocationDomain8616,
    required: Real16InvocationDomain8616,
) -> bool:
    """Bind root replay inputs apart from the separately observed entry pool.

    A single replay may stand in for ``offered.complete`` and
    ``required.complete`` only for declared-entry or raw-boot roots when every
    non-entry-pool input ``_derive_invocation_domain_8616`` consumes is identical —
    tuples that the census compares by identity internally are admitted
    only as the same tuple or as both empty — or, for the root link types
    whose entire consumed surface is their identity-bound fields, when
    those fields are the identical objects. Transported links always retain
    independent replay: the root capture does not freeze their mutable
    parent, edge, binding and call-state surfaces, even for one shared link.
    """
    def _same_consumables(
        left: tuple[object, ...], right: tuple[object, ...],
    ) -> bool:
        """Share only exact tuple identities or genuine empty immutable tuples."""
        return type(left) is tuple and type(right) is tuple and (
            left is right or (len(left) == 0 and len(right) == 0)
        )

    if not (
        offered.project is required.project
        and offered.boot is required.boot
        and offered.boot_recompute is required.boot_recompute
        and offered.coverage is required.coverage
        and offered.callsite_addr == required.callsite_addr
        and _same_consumables(offered.call_preservations, required.call_preservations)
        and type(offered.entry_call_preservations) is tuple
        and type(required.entry_call_preservations) is tuple
        and _same_consumables(offered.declared_services, required.declared_services)
    ):
        return False
    left, right = offered.chain, required.chain
    if type(left) is not type(right):
        return False
    if type(left) is DeclaredFunctionEntryLink8616:
        declared, peer = left, cast(DeclaredFunctionEntryLink8616, right)
        return (
            declared.admission is peer.admission
            and declared.artifact is peer.artifact
            and declared.boundary is peer.boundary
        )
    if type(left) is RawBootEntrySurface8616:
        raw_left = left
        raw_right = cast(RawBootEntrySurface8616, right)
        return (
            raw_left.artifact is raw_right.artifact
            and raw_left.boundary is raw_right.boundary
        )
    return False


@dataclass(frozen=True, slots=True)
class _EntryPoolGateScan8616:
    """One charged row scan's unique owner, CALL blocks and CFG edge census."""

    owner: IRBlock
    other_calls: frozenset[int]
    edges: frozenset[tuple[int, int]]
    block_addrs: frozenset[int]
    successor_count: int


def _scan_entry_pool_gate_8616(
    artifact: IRFunctionArtifact, callsite_addr: int,
) -> _EntryPoolGateScan8616 | None:
    """Inspect each row once, retaining owner uniqueness and suffix CALL facts."""
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    owner: IRBlock | None = None
    other_calls: set[int] = set()
    edges: set[tuple[int, int]] = set()
    block_addrs: set[int] = set()
    successor_count = 0
    with segment_call_dependency_traversal_scope_8616() as traversal:
        deadline = _census_deadline_8616()
        for block in artifact.blocks:
            traversal.census_work_units += 1 + len(block.successor_addrs)
            if traversal.census_work_units > traversal.census_work_limit or time.monotonic() > deadline:
                return None
            block_addrs.add(block.addr)
            successor_count += len(block.successor_addrs)
            edges.update((block.addr, successor) for successor in block.successor_addrs)
            owns_callsite = False
            for instruction in block.instrs:
                traversal.census_work_units += 1
                if traversal.census_work_units > traversal.census_work_limit or time.monotonic() > deadline:
                    return None
                owns_callsite = owns_callsite or instruction.addr == callsite_addr
                if instruction.op == "CALL" and instruction.addr != callsite_addr:
                    other_calls.add(block.addr)
            if owns_callsite:
                if owner is not None:
                    return None
                owner = block
        if owner is None:
            return None
        traversal.census_work_units += len(other_calls) + len(edges) + len(block_addrs)
        if traversal.census_work_units > traversal.census_work_limit or time.monotonic() > deadline:
            return None
        return _EntryPoolGateScan8616(owner, frozenset(other_calls), frozenset(edges), frozenset(block_addrs), successor_count)


def _entry_pool_unused_prefix_8616(subject: Real16InvocationDomain8616) -> bool:
    """Charge one row scan and canonical CFG discovery for pool independence.

    The stop block's suffix is included. Graph construction does not scan
    instruction rows, so its block/edge visits are charged separately from
    the single owner/CALL row walk; no proof budget or deadline is renewed.
    """
    from .segment_call_preservation import segment_call_dependency_traversal_scope_8616

    chain = subject.chain
    if type(chain) is DeclaredFunctionEntryLink8616 or type(chain) is RawBootEntrySurface8616:
        artifact = chain.artifact
    else:
        return False
    if type(artifact) is not IRFunctionArtifact:
        return False
    with segment_call_dependency_traversal_scope_8616() as traversal:
        scan = _scan_entry_pool_gate_8616(artifact, subject.callsite_addr)
        if scan is None:
            return False
        deadline = _census_deadline_8616()
        # Canonical predecessor construction visits four block projections,
        # all successor rows, and each distinct predecessor edge on output.
        traversal.census_work_units += 4 * len(artifact.blocks) + scan.successor_count + len(scan.edges)
        if traversal.census_work_units > traversal.census_work_limit or time.monotonic() > deadline:
            return False
        dangerous = _dangerous_block_addrs_8616(artifact, scan.owner)
        # BFS visits each reached node and its distinct incoming predecessors.
        traversal.census_work_units += len(scan.edges)
        if traversal.census_work_units > traversal.census_work_limit or time.monotonic() > deadline:
            return False
        traversal.census_work_units += len(dangerous) + sum(
            1 for source, target in scan.edges if source in scan.block_addrs and target in dangerous
        ) + len(scan.other_calls)
        if traversal.census_work_units > traversal.census_work_limit or time.monotonic() > deadline:
            return False
        return dangerous.isdisjoint(scan.other_calls)


@dataclass(frozen=True, slots=True)
class _SharedReplayCapture8616:
    """Retain exact replay input identities before any native callback executes."""

    identities: tuple[object, ...]
    root_surface: tuple[object, ...]
    callsite_addr: int
    kind: Real16InvocationKind8616

    def binds(self, subject: Real16InvocationDomain8616) -> bool:
        """Reject replacement inputs even when both subjects changed identically."""
        current = _capture_shared_replay_8616(subject)
        return (
            current is not None
            and self.callsite_addr == current.callsite_addr
            and self.kind is current.kind
            and all(left is right for left, right in zip(self.identities, current.identities, strict=True))
            and all(left is right for left, right in zip(self.root_surface, current.root_surface, strict=True))
        )


def _capture_shared_replay_8616(
    subject: Real16InvocationDomain8616,
) -> _SharedReplayCapture8616 | None:
    """Capture typed consumables and each root link's authority surface separately."""
    consumables = (
        subject.call_preservations, subject.entry_call_preservations,
        subject.declared_services,
    )
    if (
        subject.failure is not None
        or not _retained_domain_kind_bound_8616(subject)
        or type(subject.callsite_addr) is not int
        or any(type(value) is not tuple for value in consumables)
    ):
        return None
    chain = subject.chain
    root_surface: tuple[object, ...] = ()
    if type(chain) is DeclaredFunctionEntryLink8616:
        root_surface = (chain.admission, chain.artifact, chain.boundary)
    elif type(chain) is RawBootEntrySurface8616:
        raw_chain = chain
        root_surface = (raw_chain.artifact, raw_chain.boundary)
    else:
        # Only these roots have their whole consumed surface captured here.
        return None
    return _SharedReplayCapture8616(
        (subject.project, subject.coverage, subject.boot, subject.boot_recompute,
         subject.chain, *consumables),
        root_surface, subject.callsite_addr, subject.kind,
    )


def _consume_required_pool_result_8616(
    required: Real16InvocationDomain8616,
    derived: _Derivation8616,
    captures_bound: Callable[[], bool],
) -> bool:
    """Share an observed unused pool or authenticate required independently.

    The caller owns required's existing active guard; offered has already
    left its inner guard before this fallback invokes native callbacks.
    """
    if derived.entry_call_pool_consultation is _EntryCallPoolConsultation8616.UNUSED:
        return _replayed_domain_equal_8616(derived, required)
    return required._replay_complete_8616() and captures_bound()


def _complete_shared_replay_8616(
    offered: Real16InvocationDomain8616,
    required: Real16InvocationDomain8616,
    *, require_unused_entry_pool: bool = False,
) -> bool:
    """Authenticate two input-identical domains with one current derivation.

    Both identities acquire ordinary resource admission, including cached
    refusals and cycle/depth limits. Forced-current verification prevents a
    cached positive from skipping the pair check. Per-subject input captures
    bind the replay after callbacks, before either fresh result is consumed.
    """
    offered_capture = _capture_shared_replay_8616(offered)
    required_capture = _capture_shared_replay_8616(required)
    if offered_capture is None or required_capture is None:
        return False
    derived: _Derivation8616 | None = None

    def derive_offered() -> bool:
        """Derive once, authenticate offered and preserve both exact captures."""
        nonlocal derived
        if not offered_capture.binds(offered) or not required_capture.binds(required):
            return False
        derived = _derive_invocation_domain_8616(
            offered.project,
            offered.coverage,
            offered.callsite_addr,
            offered.boot,
            offered.boot_recompute,
            offered.call_preservations,
            chain=offered.chain,
            entry_call_preservations=offered.entry_call_preservations,
            declared_services=offered.declared_services,
            prefix_capture=True,
        )
        accepted = (
            derived.failure is None and derived.domain is not None
            and offered_capture.binds(offered)
            and required_capture.binds(required)
            and _replayed_domain_equal_8616(derived, offered)
        )
        if accepted:
            _enroll_prefix_census_data_8616(offered, derived)
        return accepted

    def verify_both() -> bool:
        """Bind exact-input peers to one current derivation."""
        return derive_offered() and derived is not None and _replayed_domain_equal_8616(derived, required)

    def admit_required() -> bool:
        """Keep the peer independently active while deriving the common result."""
        return required._consume_completion_8616(verify_both, force_current=True)

    def verify_required_pool() -> bool:
        """Share UNUSED or retain independent replay after offered leaves active."""
        if not offered._consume_completion_8616(derive_offered, force_current=True) or derived is None:
            return False
        return _consume_required_pool_result_8616(
            required, derived,
            lambda: offered_capture.binds(offered) and required_capture.binds(required),
        )

    if require_unused_entry_pool:
        return required._consume_completion_8616(verify_required_pool, force_current=True)
    return offered._consume_completion_8616(admit_required, force_current=True)


def _self_scope_forces_root_parent_8616(
    scope: Real16InvocationDomain8616, depth: int,
) -> bool:
    """Select exact-self transport whose ordinary replay authenticates its root.

    This grants no proof: the caller must still consume ``scope.complete``.
    A native entry-only chain forces its parent's current derivation after
    native callbacks, including retained-domain equality and admission guards.
    Replaying that root before the child's replay is redundant. Keep the
    coterminality gates here; other chain shapes retain the ordinary path.
    """
    chain = scope.chain
    if (scope.coverage is not None or type(chain) is not Real16CallChainLink8616
            or depth >= _CHAIN_DEPTH_LIMIT_8616):
        return False
    if chain.edge is not None or chain.entry_binding is None:
        return False
    parent = chain.parent
    if (type(parent) is not Real16InvocationDomain8616
            or type(parent.chain) not in (DeclaredFunctionEntryLink8616, RawBootEntrySurface8616)):
        return False
    return _link_scope_anchor_8616(chain, chain) and _in_flight_scopes_coterminous_8616(
        parent.chain, parent.chain, depth + 1,
    )


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
    if offered is required and _self_scope_forces_root_parent_8616(offered, depth):
        return offered.complete
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
    if not identity:
        return False
    if offered is required:
        return offered.complete
    if _shared_replay_inputs_8616(offered, required):
        return _complete_shared_replay_8616(offered, required)
    if (
        offered.entry_call_preservations is not required.entry_call_preservations
        and _shared_root_replay_inputs_8616(offered, required)
        and _unused_pool_replay_selected_8616(offered)
    ):
        return _complete_shared_replay_8616(offered, required, require_unused_entry_pool=True)
    return offered.complete and required.complete


def _unused_pool_replay_selected_8616(subject: Real16InvocationDomain8616) -> bool:
    """Use prior consultation only to select work; fresh replay owns sharing.

    READ keeps independent replay. UNUSED avoids the redundant static scan,
    but the chosen consumer must still derive and check a new UNUSED receipt.
    Unknown or foreign advice retains the conservative charged eligibility gate.
    """
    advice = subject.entry_call_pool_advice
    if advice is _EntryCallPoolConsultation8616.READ:
        return False
    return advice is _EntryCallPoolConsultation8616.UNUSED or _entry_pool_unused_prefix_8616(subject)


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


def _fused_callee_header_equal_8616(
    native: IRBlock, block: IRBlock, memo: _NativeTermMemo8616,
) -> bool:
    """Bind whole-block metadata at the original comparator nesting depth."""
    return (
        type(native) is IRBlock and type(block) is IRBlock
        and type(native.instrs) is tuple and type(block.instrs) is tuple
        and len(native.instrs) == len(block.instrs)
        and _native_fields_current_8616(native, _IR_BLOCK_FIELDS_8616, memo)
        and _native_term_equal_8616(
            (native.addr, native.refusals, native.successor_addrs),
            (block.addr, block.refusals, block.successor_addrs), 1, memo,
        )
    )


def _fused_callee_producers_8616() -> tuple[object, ...]:
    """Capture every evaluator/reader/store boundary allowed in pure transfer."""
    from .call_stack_coordinates import IRCallStackCoordinates8616
    from .source_graph_json import canonical_json_dumps_8616

    path_memory_bindings = cast(path_memory_owner_8616.PathMemoryProducerBindings8616, path_memory_owner_8616)
    fused_callee_bindings = cast(fused_callee_owner_8616.FusedCalleeProducerBindings8616, fused_callee_owner_8616)
    scalar_bindings = cast(scalar_owner_8616.ScalarSemanticProducerBindings8616, scalar_owner_8616)
    kb_bindings = cast(kb_owner_8616.EdgeFeasibilityProducerBindings8616, kb_owner_8616)
    persistent_bytes_bindings = cast(_PersistentBytesOwnerLike8616, persistent_bytes_owner_8616)
    return (
        canonical_json_dumps_8616,
        IRCallStackEffect8616.current_net_stack_delta,
        IRCallStackCoordinates8616.to_dict,
        IRCallStackCoordinates8616.has_proven_sp_delta,
        IRCallStackCoordinates8616.closed,
        IRCallStackCoordinates8616.callee_return_sp_delta,
        IRCallStackCoordinates8616._slot_values,
        IRCallStackCoordinates8616._layout_valid,
        caller_prefix_owner_8616.fused_caller_prefix_producers_8616,
        *caller_prefix_owner_8616.fused_caller_prefix_producers_8616(),
        frozen_dispatch_lookup, scalar_owner_8616.frozen_dispatch_lookup, kb_owner_8616.frozen_dispatch_lookup,
        _simulate_instruction_8616, _census_store_8616, _eval_value_8616,
        _native_store_span_8616, _store_span_8616, _store_data_bytes_8616, _address_domain16_8616,
        _eval_atom_8616, _eval_unary_op_8616, _eval_convert_unary_8616,
        _eval_binary_op_8616, _eval_comparison_or_product_8616, _eval_base_plain_8616,
        _simulate_census_tmp_write_8616, _simulate_reg_write_8616,
        _binary_parts_8616, _expr_provenance_only_8616, _register_read_8616,
        _register_tile_8616, _register_width_8616, _value_mask_8616,
        register_value_family_8616, register_value_projection_8616,
        store_atom_clean_8616, wide_multiply_value_8616,
        _simulate_tmp_write_8616, _transfer_row_failure_8616,
        _apply_register_write_8616, _writes_segment_register_8616,
        _eval_value_inner_8616, _eval_plain_value_8616, _eval_base_value_8616,
        _native_instr_equal_8616, _native_term_equal_8616,
        _native_fields_current_8616, _apply_repeated_store_8616,
        native_repeated_store_8616, scalar_instruction_effect_8616,
        scalar_select_result_bits_8616, scalar_owner_8616._SELECT_BITS_8616,
        path_load_value_8616, path_memory_owner_8616._path_byte_8616, _census_work_exceeded_8616,
        DirectionTracker8616.__init__, DirectionTracker8616.step, DirectionTracker8616.direction,
        _PathState8616.__init__, _PathCensusContext8616.__init__, _NativeTermMemo8616,
        _fused_callee_header_equal_8616, _refuse_unbound_block_rows_8616, _record_first_failure_site_8616,
        PathMemory8616.copy, PathMemory8616.apply_write, PathMemory8616.assign,
        PathMemory8616.__post_init__, PathMemory8616.__copy__,
        PathMemory8616.copy_work_units_8616,
        path_memory_bindings.canonical_known_root_8616,
        fused_callee_bindings.canonical_known_root_8616,
        persistent_bytes_bindings.persistent_bytes_producers_8616,
        *persistent_bytes_bindings.persistent_bytes_producers_8616(),
        InvocationInitialMemory8616.byte_at, InvocationInitialMemory8616.permits_write_read,
        initial_memory_owner_8616._valid_write_ranges_8616,
        multiply_owner_8616.wide_multiply_shape_8616,
        path_memory_owner_8616.store_atom_clean_8616,
        scalar_owner_8616._unknown_8616, scalar_owner_8616._readable_scalar_source_8616,
        scalar_owner_8616._closed_destination_8616, scalar_owner_8616._closed_write_8616,
        scalar_owner_8616._const_target_8616, scalar_owner_8616._binary_operands_valid_8616,
        scalar_owner_8616._classify_comparison_8616, scalar_owner_8616._classify_binary_8616,
        scalar_owner_8616._classify_boolean_binary_8616, scalar_owner_8616._classify_widening_product_8616,
        scalar_owner_8616._classify_select_8616,
        scalar_bindings.no_effect_claim_shape_8616, scalar_bindings.scalar_binary_operation_8616,
        type(scalar_owner_8616._CLASSIFIERS_8616),
        scalar_owner_8616._CLASSIFIERS_8616,
        kb_owner_8616._kb_width_mask_8616,
        kb_owner_8616._kb_lowest_unknown_8616,
        kb_owner_8616._kb_add_8616,
        kb_owner_8616._kb_sub_8616,
        kb_owner_8616._kb_and_8616,
        kb_owner_8616._kb_or_8616,
        kb_owner_8616._kb_xor_8616,
        kb_owner_8616._kb_not_8616,
        kb_owner_8616._kb_shift_8616,
        kb_owner_8616._kb_cmp_eq_8616,
        kb_owner_8616._kb_cmp_ne_8616,
        kb_owner_8616._kb_cmp_order_8616,
        kb_owner_8616._kb_mul_8616,
        kb_owner_8616._kb_binary_op_8616,
        kb_owner_8616._kb_unary_op_8616,
        kb_owner_8616._kb_unary_evidence_8616,
        kb_owner_8616._kb_expr_provenance_only_8616,
        kb_owner_8616._kb_convert_token_8616,
        kb_owner_8616._kb_read_register_8616,
        kb_owner_8616._kb_write_register_8616,
        kb_owner_8616._kb_eval_value_8616,
        kb_owner_8616._kb_eval_plain_8616,
        kb_owner_8616._kb_fit_width_8616,
        kb_owner_8616._kb_seed_state_8616,
        kb_owner_8616._kb_poison_destination_8616,
        kb_owner_8616._kb_dirty_write_8616,
        kb_owner_8616._kb_dirty_all_8616,
        kb_owner_8616._kb_eval_base_8616,
        kb_owner_8616._kb_eval_base_plain_8616,
        kb_owner_8616._kb_data_row_8616,
        kb_owner_8616._kb_tmp_write_8616,
        kb_owner_8616._kb_select_value_8616,
        kb_owner_8616.scalar_select_result_bits_8616,
        kb_owner_8616.direction_fact_8616,
        type(kb_owner_8616._KB_BINOP_PLAIN_8616),
        kb_owner_8616._KB_BINOP_PLAIN_8616,
        kb_bindings.scalar_instruction_effect_8616, kb_bindings.register_value_family_8616, kb_bindings.register_value_projection_8616, kb_bindings.wide_multiply_shape_8616, kb_bindings.wide_multiply_value_8616,


        type(_NATIVE_COMPARATORS_8616),
        _NATIVE_COMPARATORS_8616,
    )


def _make_fused_callee_operations_8616() -> FusedCalleeOperations8616:
    """Retain exact canonical producers before tests/plugins can replace them."""
    return FusedCalleeOperations8616(
        _fused_callee_producers_8616(), _PathCensusContext8616, _NativeTermMemo8616,
        _fused_callee_header_equal_8616, _native_instr_equal_8616,
        _simulate_instruction_8616, _census_work_exceeded_8616,
        _refuse_unbound_block_rows_8616, _PathState8616,
        Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN,
        Real16InvocationFailure8616.PATH_EFFECT_UNPROVEN,
        Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED,
        Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED,
        Real16InvocationFailure8616.PATH_DECODE_MISMATCH, _record_first_failure_site_8616,
    )


_CANONICAL_FUSED_FACTORY_8616 = _make_fused_callee_operations_8616
_CANONICAL_FUSED_PRODUCER_BUILDER_8616 = _fused_callee_producers_8616
_CANONICAL_CALLER_PRODUCER_BUILDER_8616 = caller_prefix_owner_8616.fused_caller_prefix_producers_8616
_BASE_FUSED_CALLEE_OPERATIONS_8616 = _make_fused_callee_operations_8616()
_CANONICAL_PREFIX_EXECUTION_PRODUCERS_8616 = _prefix_execution_producers_8616()


def _try_fused_caller_prefix_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
    entry: _PathState8616, stop_after: int | None,
) -> FusedCallerPrefix8616 | Real16InvocationFailure8616 | None:
    """Attempt caller fusion only when its charged identity seal can save work."""
    if type(ctx.callsite_addr) is not int:
        return None
    ctx.work_units += 1
    if type(block) is not IRBlock or type(block.instrs) is not tuple:
        return None
    if len(block.instrs) <= len(_BASE_FUSED_CALLEE_OPERATIONS_8616.producers) + 17:
        return None
    if (_make_fused_callee_operations_8616 is not _CANONICAL_FUSED_FACTORY_8616
            or _fused_callee_producers_8616 is not _CANONICAL_FUSED_PRODUCER_BUILDER_8616
            or caller_prefix_owner_8616.fused_caller_prefix_producers_8616
            is not _CANONICAL_CALLER_PRODUCER_BUILDER_8616):
        return None
    return try_fused_caller_prefix_8616(
        ctx, artifact, block, entry, stop_after=stop_after,
        operations=_make_fused_callee_operations_8616(),
        canonical_operations=_BASE_FUSED_CALLEE_OPERATIONS_8616,
    )


def _try_active_fused_callee_transfer_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact, block: IRBlock,
    entry: _PathState8616, stop_after: int | None,
) -> _PathState8616 | Real16InvocationFailure8616 | None:
    """Keep ordinary blocks untouched; check live authority only in fresh scope."""
    if not active_fused_callee_transfer_8616(ctx, artifact):
        return None
    # The fixed authority walk cannot save work on short blocks. The ordinary
    # or verified fused consumer accounts this visit at its existing work gate.
    ctx.work_units += 1
    if type(block) is not IRBlock or type(block.instrs) is not tuple:
        return None
    if len(block.instrs) <= len(_BASE_FUSED_CALLEE_OPERATIONS_8616.producers) + 18:
        return None
    # Builders themselves must be canonical before any callback-capable
    # producer discovery executes. The next existing gate charges these visits.
    ctx.work_units += 2
    if (_make_fused_callee_operations_8616 is not _CANONICAL_FUSED_FACTORY_8616
            or _fused_callee_producers_8616 is not _CANONICAL_FUSED_PRODUCER_BUILDER_8616):
        return None
    return try_fused_callee_transfer_8616(
        ctx, artifact, block, entry, stop_after=stop_after,
        operations=_make_fused_callee_operations_8616(),
    )


def _bind_path_block_before_transfer_8616(
    ctx: _PathCensusContext8616, artifact: IRFunctionArtifact,
    block: IRBlock, stop_after: int | None,
) -> Real16InvocationFailure8616 | None:
    """Preserve the original charged whole-block binding for ordinary transfers."""
    if time.monotonic() > ctx.deadline:
        return Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
    prefix_count = None if stop_after is None else _native_prefix_count_8616(block, stop_after)
    ctx.work_units += (len(block.instrs) if prefix_count is None else prefix_count) + 1
    if _census_work_exceeded_8616(ctx):
        return Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
    native_blocks = ctx.native_blocks.get(artifact.function_addr)
    native_block = (
        None if native_blocks is None else native_blocks.get(block.addr)
    )
    if not _native_block_bound_8616(native_block, block, stop_after=stop_after):
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
    return None


def _feasibility_union_inputs_8616(
    ctx: _PathCensusContext8616, caller_range: ScratchCallerRange8616 | None,
) -> tuple[set[tuple[int, int]] | None, tuple[int, int] | None]:
    """Collect the original or exactly equivalent temporary interval input.

    The second return is a half-open ``(low, high)`` envelope covering every
    emitted interval, accumulated during the same charged span walk at no
    extra billed cost. It is ``None`` when any emitted coordinate is not an
    exact ``int`` or when no positive extent exists; a caller may only use
    it as conservative evidence, never as admission.
    """
    if caller_range is not None:
        selection = select_caller_intervals_8616(ctx, ctx.manifest, caller_range, _census_work_exceeded_8616)
        if selection.status is CallerIntervalSelectionStatus8616.REFUSED:
            return None, None
        if selection.status is CallerIntervalSelectionStatus8616.SELECTED:
            return selection.intervals, selection.envelope
    intervals: set[tuple[int, int]] = set()
    envelope_low: int | None = None
    envelope_high = 0
    envelope_exact = True
    for span in ctx.manifest:
        start, extent = span
        ctx.work_units += 1
        if time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
            return None, None
        if type(span) is not tuple or type(start) is not int or type(extent) is not int:
            envelope_exact = False
        if extent > 0:
            intervals.add((start, start + extent))
            if type(start) is int and type(extent) is int:
                if envelope_exact:
                    envelope_low = start if envelope_low is None else min(envelope_low, start)
                    envelope_high = max(envelope_high, start + extent)
            else:
                envelope_exact = False
    envelope = (
        (envelope_low, envelope_high)
        if envelope_exact and envelope_low is not None else None
    )
    return intervals, envelope


def _snapshot_omission_hooks_8616(
    ctx: _PathCensusContext8616,
) -> tuple[Callable[[IRBlock], bool], Callable[[], bool]] | None:
    """Per-moment no-op proofs for the root census's discarded snapshot replays.

    The first predicate answers whether the canonical repeat hook is a
    proven side-effect-free non-candidate for one block *now*; the second
    answers whether the census LOAD reader is a pure owned lookup *now*.
    Both re-read the live ``ctx`` fields and current module bindings on
    every call, so a rebound helper, foreign decoder, replaced project or
    manifest mapping, or foreign initial memory keeps the ordinary
    observable replay instead of a stale verdict. Declined ``None`` under
    an expired deadline or exceeded work boundary: no optional policy is
    prepared past the current budget. No caller-supplied flag grants this
    authority — only the owned chain's own current state does.
    """
    if not _CANONICAL_SNAPSHOT_CHECK_8616():
        return None
    if time.monotonic() > ctx.deadline or _census_work_exceeded_8616(ctx):
        return None
    project = ctx.project

    def repeat_consult_noop(block: IRBlock) -> bool:
        """True only while the repeat hook provably returns before any effect."""
        machine_bytes = ctx.machine_bytes
        if type(machine_bytes) is not dict or ctx.project is not project:
            return False
        encoded = machine_bytes.get(block.addr)
        if encoded is not None:
            if type(encoded) is not bytes:
                return False
            # Cheap structural gate first: a possible candidate never pays
            # the full producer check and always keeps its obligatory replay.
            if _CANONICAL_REPEAT_SHAPE_8616(block, encoded):
                return False
        return _CANONICAL_SNAPSHOT_CHECK_8616()

    def load_reader_readonly() -> bool:
        """True only while the census LOAD reader remains side-effect-free."""
        if not _CANONICAL_SNAPSHOT_CHECK_8616():
            return False
        initial = ctx.initial_memory
        return initial is None or type(initial) is InvocationInitialMemory8616

    return repeat_consult_noop, load_reader_readonly


def _snapshot_terminal_noop_8616(
    call_binding: _FeasibilityCallBinding8616 | None,
    apply_call: Callable[[IRInstr, dict[str, int], PathMemory8616], bool] | None,
) -> Callable[[IRInstr], bool] | None:
    """Per-moment inert verdict for the exact terminal CALL row's consult.

    True only while consulting the call hook on one exact row is provably
    inert *now*: no handler exists, or the current apply object is the
    canonical handler whose own paired map verdict already proves it rejects
    this row before any scratch effect. Interrupt/service rows and foreign
    or rebound consult chains always decline to the ordinary observable
    replay.
    """
    if not _CANONICAL_SNAPSHOT_CHECK_8616():
        return None

    def terminal_call_noop(instruction: IRInstr) -> bool:
        """True only while this exact CALL row's consult is provably inert."""
        if type(instruction) is not IRInstr or type(instruction.op) is not str:
            return False
        if not _CANONICAL_SNAPSHOT_CHECK_8616():
            return False
        if not kb_owner_8616._ordinary_call_target_8616(instruction):
            return False
        if interrupt_call_vector_8616(instruction) is not None:
            return False
        if apply_call is None:
            return True
        if type(call_binding) is not _FeasibilityCallBinding8616 or apply_call is not call_binding:
            return False
        return call_binding.terminal_noop(instruction)

    return terminal_call_noop


def _snapshot_call_unobserved_8616(
    call_binding: _FeasibilityCallBinding8616 | None,
    apply_call: Callable[[IRInstr, dict[str, int], PathMemory8616], bool] | None,
) -> Callable[[IRInstr], bool] | None:
    """Per-moment confinement verdict for one ordinary CALL row's replay.

    True only while consulting the call handler on this exact row inside the
    discarded snapshot walk provably cannot publish anything the walk or the
    census retains: the row must be an ordinary non-interrupt target, and
    the apply chain must be absent — leaving only block-local taint — or the
    canonical owned binding whose scratch consult writes back work accounting
    plus the monotone pool-consultation flag the fixpoint's identical
    transfer consult already saturated on the same converged entry. This is
    a confinement verdict, not an inertness verdict: bound selected rows may
    still run real scratch authentication, but every retained product of
    that consult was already produced by the mandatory first pass. Interrupt
    or service rows, non-ordinary targets, and foreign or rebound consult
    chains always decline to the ordinary observable replay. The verdict
    grants no exemption on a block carrying a requested call cut; the walk
    withholds it there before consulting.
    """
    if not _CANONICAL_SNAPSHOT_CHECK_8616():
        return None

    def call_replay_unobserved(instruction: IRInstr) -> bool:
        """True only while this exact CALL row's replay consult is confined."""
        if type(instruction) is not IRInstr or type(instruction.op) is not str:
            return False
        if not _CANONICAL_SNAPSHOT_CHECK_8616():
            return False
        if interrupt_call_vector_8616(instruction) is not None:
            return False
        if not kb_owner_8616._ordinary_call_target_8616(instruction):
            return False
        if apply_call is None:
            return True
        if type(call_binding) is not _FeasibilityCallBinding8616 or apply_call is not call_binding:
            return False
        # Callee LOADs can reach this reader even when the caller block has
        # none. A foreign reader may observe another consult; keep replay.
        initial_memory = call_binding.ctx.initial_memory
        return initial_memory is None or type(initial_memory) is InvocationInitialMemory8616

    return call_replay_unobserved


def _snapshot_bindings_check_8616() -> bool:
    """Current self-check via the captured canonical verifier only."""
    return (
        _snapshot_bindings_check_8616 is _CANONICAL_SNAPSHOT_CHECK_8616
        and _snapshot_bindings_current_8616 is _CANONICAL_SNAPSHOT_BINDINGS_8616
        and _CANONICAL_SNAPSHOT_BINDINGS_8616()
    )


def _snapshot_bindings_current_8616() -> bool:
    """Every consulted snapshot boundary still denotes the owned implementation.

    The builder identities are compared before either is invoked so a
    rebound producer function is never called to judge itself. The fresh
    tuple is then compared elementwise by identity — not equality — against
    the import-time capture, mirroring ``canonical_fused_operations_match``.
    """
    if (_fused_callee_producers_8616 is not _CANONICAL_FUSED_PRODUCER_BUILDER_8616
            or _snapshot_omission_producers_8616 is not _CANONICAL_SNAPSHOT_PRODUCER_BUILDER_8616
            or _FeasibilityCallBinding8616 is not _CANONICAL_FEASIBILITY_BINDING_CLASS_8616):
        return False
    actual = _CANONICAL_SNAPSHOT_PRODUCER_BUILDER_8616()
    return len(actual) == len(_BASE_SNAPSHOT_PRODUCERS_8616) and all(
        left is right
        for left, right in zip(actual, _BASE_SNAPSHOT_PRODUCERS_8616, strict=True)
    )


def _snapshot_omission_producers_8616() -> tuple[object, ...]:
    """Every evaluator/hook boundary a discarded snapshot replay may reach.

    Extends the existing fused-callee producer boundary — which already pins
    the repeat hook, scalar classifier, LOAD evaluator, and the complete
    known-bits lattice — with the snapshot walk's own consult chain and the
    repeated-store decoder boundary. It widens no authority: every name is
    checked, never trusted.
    """
    return (
        *_CANONICAL_FUSED_PRODUCER_BUILDER_8616(),
        _apply_repeated_store_8616,
        repeated_store_candidate_shape_8616,
        repeated_store_owner_8616.repeated_store_candidate_shape_8616,
        repeated_store_owner_8616.native_repeated_store_8616,
        repeated_store_owner_8616.decoded_repeated_store_8616,
        repeated_store_owner_8616.repeated_store_effect_8616,
        interrupt_call_vector_8616,
        kb_owner_8616.interrupt_call_vector_8616,
        kb_owner_8616.path_memory_tainted_8616,
        kb_owner_8616._kb_snapshot_observed_8616,
        kb_owner_8616._branch_transfer_collector_8616,
        kb_owner_8616._BranchTransferCollector8616,
        kb_owner_8616._BranchTransferCollector8616.__init__,
        kb_owner_8616._BranchTransferCollector8616.__call__,
        kb_owner_8616._BranchTransferObservation8616,
        kb_owner_8616._BranchTransferObservation8616.__init__,
        kb_owner_8616._kb_fixpoint_8616,
        kb_owner_8616._KbFixpointResult8616,
        kb_owner_8616._KbFixpointResult8616.__init__,
        kb_owner_8616._kb_ready_entry_8616,
        kb_owner_8616._kb_entry_chain_edges_8616,
        kb_owner_8616._kb_entry_chain_scope_8616,
        kb_owner_8616.BranchSnapshotReplay8616,
        kb_owner_8616._snapshot_terminal_exemption_8616,
        kb_owner_8616._kb_block_exit_8616,
        kb_owner_8616._kb_repeat_exit_8616,
        kb_owner_8616._kb_known_registers_8616,
        kb_owner_8616._kb_transfer_effect_8616,
        kb_owner_8616._kb_call_row_8616,
        kb_owner_8616._ordinary_call_target_8616,
        kb_owner_8616._kb_store_row_8616,
        kb_owner_8616._kb_store_span_8616,
        kb_owner_8616._kb_store_data_8616,
        kb_owner_8616._kb_eval_atom_8616,
        kb_owner_8616.store_atom_clean_8616,
        kb_owner_8616._kb_cjmp_exit_8616,
        kb_owner_8616._kb_cjmp_path_exit_8616,
        kb_owner_8616._cjmp_live_successor_8616,
        PathMemory8616.taint,
        _FeasibilityCallBinding8616,
        _FeasibilityCallBinding8616.__init__,
        _FeasibilityCallBinding8616.__call__,
        _FeasibilityCallBinding8616.terminal_noop,
        _feasibility_call_handler_8616,
        _feasibility_call_rows_8616,
        _snapshot_omission_hooks_8616,
        _snapshot_terminal_noop_8616,
        _snapshot_call_unobserved_8616,
        _feasibility_call_scratch_8616,
        _feasibility_call_effect_8616,
        _consume_cross_call_boundary_8616,
        _census_callee_bytes_8616,
        _feasibility_code_unmodified_8616,
        _feasibility_callsite_bytes_current_8616,
        _simulate_callee_8616,
        _reconcile_call_exit_8616,
        _snapshot_bindings_check_8616,
        _snapshot_bindings_current_8616,
        InvocationInitialMemory8616,
    )


_CANONICAL_REPEAT_SHAPE_8616 = repeated_store_candidate_shape_8616
_CANONICAL_FEASIBILITY_BINDING_CLASS_8616 = _FeasibilityCallBinding8616
_CANONICAL_SNAPSHOT_PRODUCER_BUILDER_8616 = _snapshot_omission_producers_8616
_CANONICAL_SNAPSHOT_BINDINGS_8616 = _snapshot_bindings_current_8616
_CANONICAL_SNAPSHOT_CHECK_8616 = _snapshot_bindings_check_8616
_CANONICAL_SNAPSHOT_HOOKS_8616 = _snapshot_omission_hooks_8616
_CANONICAL_TERMINAL_NOOP_8616 = _snapshot_terminal_noop_8616
_CANONICAL_CALL_UNOBSERVED_8616 = _snapshot_call_unobserved_8616
_BASE_SNAPSHOT_PRODUCERS_8616 = _snapshot_omission_producers_8616()
