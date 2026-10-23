"""DOSBox declared-chain resize profile plumbing controls.

The reviewed pure model ``inertia.frontend.real16_dosbox_resize`` is not
re-tested here; these controls pin the environment integration contract:
strict ``dosbox_initial_owned_tail`` JSON, arena/PSP/entry-policy binding,
declared MCB bytes in the memory layout, environment digest binding of
every chain byte, and fail-closed relation authentication.
"""

from dataclasses import replace

import pytest

from inertia.frontend.real16_dosbox_entry_policy import DosBoxInt21EntryPolicy8616
from inertia.frontend.real16_dosbox_resize import (
    DOSBOX_MCB_FINAL_MARKER,
    DOSBOX_MCB_MIDDLE_MARKER,
    DosboxMcbEntry,
    DosboxResizePolicy,
)
from inertia.ir.real16_declared_interrupt8616 import (
    DeclaredInterruptRefusal8616,
    DeclaredInterruptService8616,
    DeclaredResizeSurface8616,
    declared_environment_digest_8616,
    declared_resize_expectation_8616,
    service_relation_for_8616,
    validated_declared_service_8616,
)
from tools.dosunit.runtime.real16_declared_invocation8616 import (
    declared_int21_resize_service_8616,
)
from tools.dosunit.runtime.real16_program_boot import ProgramEnvironment
from tools.dosunit.runtime.real16_program_memory import InitialMemoryRegion
from tools.dosunit.runtime.real16_program_resize import (
    DOSBOX_CHAIN_ENTRY_LIMIT,
    DOSBOX_RESIZE_PROFILE,
    TailResizePolicy,
    parse_resize_policy,
    resize_policy_document,
)
from tools.dosunit.runtime.real16_program_vectors import VectorPolicy, vector_bytes
from tools.dosunit.runtime.real16_program_version import VersionPolicy
from tools.dosunit.runtime.real16_replay_model import SegOffset

pytestmark = pytest.mark.dosunit

PSP = 0x0402
FINAL_SIZE = 0x0400
DOS_ENTRY = SegOffset(0xF000, 0xF100)
REGISTERS = tuple(
    (name, 0)
    for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags")
)


def mcb(marker: int, owner: int, size: int, tail: bytes = bytes(11)) -> bytes:
    """Build one exact 16-byte MCB image: marker, owner word, size word, tail."""
    return (
        bytes((marker,))
        + owner.to_bytes(2, "little")
        + size.to_bytes(2, "little")
        + tail
    )


def chain() -> tuple[DosboxMcbEntry, ...]:
    """One contiguous chain ending in the PSP-owned final block at PSP-1."""
    return (
        DosboxMcbEntry(0x0080, mcb(DOSBOX_MCB_MIDDLE_MARKER, 0x0008, 0x0180, b"ENVBLOCK\0\0\0")),
        DosboxMcbEntry(0x0201, mcb(DOSBOX_MCB_MIDDLE_MARKER, PSP, 0x0100, b"mid-one-tal")),
        DosboxMcbEntry(0x0302, mcb(DOSBOX_MCB_MIDDLE_MARKER, PSP, 0x00FE, b"mid-two-tal")),
        DosboxMcbEntry(0x0401, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, FINAL_SIZE, b"\0\0\0CMP16\0\0\0")),
    )


def policy() -> DosboxResizePolicy:
    """The declared initial owned-tail policy for the test environment."""
    return DosboxResizePolicy(PSP, chain())


def _ivt() -> bytes:
    table = bytearray(0x400)
    table[0x84:0x88] = vector_bytes(DOS_ENTRY)
    return bytes(table)


def environment(*, resize: object = None, entry: bool = True) -> ProgramEnvironment:
    """One declared DOSBox environment: arena == final block, IVT supplied."""
    return ProgramEnvironment(
        psp_segment=PSP,
        allocation=bytes(FINAL_SIZE * 16),
        registers=REGISTERS,
        fs=0,
        gs=0,
        version_policy=VersionPolicy(major=5, minor=0, oem=0, serial=0),
        resize_policy=policy() if resize is None else resize,
        vector_policy=VectorPolicy(DOS_ENTRY),
        extra_memory=(InitialMemoryRegion(SegOffset(0, 0), _ivt()),),
        dosbox_int21_entry_policy=DosBoxInt21EntryPolicy8616(PSP) if entry else None,
    )


def _mint(env: ProgramEnvironment, callsite: int = 0x5000) -> DeclaredInterruptService8616:
    relation = declared_int21_resize_service_8616(
        env, caller_addr=0x4100, callsite_addr=callsite
    )
    assert isinstance(relation, DeclaredInterruptService8616)
    return relation


def _bind(env: ProgramEnvironment, relation: DeclaredInterruptService8616) -> object:
    return service_relation_for_8616(
        (relation,),
        caller_addr=relation.caller_addr,
        callsite_addr=relation.callsite_addr,
        vector=relation.vector,
        function=0x4A,
        selector=0,
        environment_sha256=declared_environment_digest_8616(env),
        environment=env,
    )


def test_profile_json_roundtrip_and_strict_schema() -> None:
    declared = policy()
    document = resize_policy_document(declared)
    assert document == {
        "profile": DOSBOX_RESIZE_PROFILE,
        "psp_segment": PSP,
        "chain": [
            {"segment": entry.segment, "mcb_hex": entry.image.hex()}
            for entry in declared.chain
        ],
    }
    assert parse_resize_policy(document) == declared
    assert parse_resize_policy(None) is None


@pytest.mark.parametrize(
    "document",
    [
        {"profile": DOSBOX_RESIZE_PROFILE},
        {"profile": DOSBOX_RESIZE_PROFILE, "psp_segment": PSP},
        {"profile": DOSBOX_RESIZE_PROFILE, "psp_segment": PSP, "chain": [], "extra": 1},
        {"profile": DOSBOX_RESIZE_PROFILE, "psp_segment": PSP, "chain": []},
        {"profile": DOSBOX_RESIZE_PROFILE, "psp_segment": True, "chain": [{}]},
        {"profile": DOSBOX_RESIZE_PROFILE, "psp_segment": PSP, "chain": {}},
        {
            "profile": DOSBOX_RESIZE_PROFILE,
            "psp_segment": PSP,
            "chain": [{"segment": 0x0401, "mcb_hex": "5a920100040000b24b56314b5052304"}],
        },
        {
            "profile": DOSBOX_RESIZE_PROFILE,
            "psp_segment": PSP,
            "chain": [{"segment": 0x0401, "mcb_hex": "5a9201 0040000b24b56314b505230 47"}],
        },
        {
            "profile": DOSBOX_RESIZE_PROFILE,
            "psp_segment": PSP,
            "chain": [{"segment": 0x0401, "mcb_hex": "zz920100040000b24b56314b50523047"}],
        },
        {
            "profile": DOSBOX_RESIZE_PROFILE,
            "psp_segment": PSP,
            "chain": [{"segment": 0x0401}],
        },
        {
            "profile": DOSBOX_RESIZE_PROFILE,
            "psp_segment": PSP,
            "chain": [{"segment": True, "mcb_hex": "5a920100040000b24b56314b50523047"}],
        },
    ],
)
def test_malformed_profile_documents_refuse(document: dict) -> None:
    with pytest.raises(ValueError):
        parse_resize_policy(document)


def test_chain_list_is_capped_before_decoding() -> None:
    document = {
        "profile": DOSBOX_RESIZE_PROFILE,
        "psp_segment": PSP,
        # Geometric bound: entries precede the PSP block; PSP+1 already
        # exceeds it, never mind the absolute paragraph-space cap.
        "chain": [{"segment": 0, "mcb_hex": "00" * 16}] * (PSP + 1),
    }
    with pytest.raises(ValueError, match="paragraph bound"):
        parse_resize_policy(document)
    oversized = {
        "profile": DOSBOX_RESIZE_PROFILE,
        "psp_segment": 0xFFFF,
        "chain": [{"segment": 0, "mcb_hex": "00" * 16}] * (DOSBOX_CHAIN_ENTRY_LIMIT + 1),
    }
    with pytest.raises(ValueError, match="paragraph bound"):
        parse_resize_policy(oversized)


@pytest.mark.parametrize(
    "entries",
    [
        # Non-contiguous chain.
        (
            DosboxMcbEntry(0x0080, mcb(DOSBOX_MCB_MIDDLE_MARKER, 0x0008, 0x0180)),
            DosboxMcbEntry(0x0400, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, FINAL_SIZE)),
        ),
        # Final block not owned by the declared PSP.
        (DosboxMcbEntry(0x0401, mcb(DOSBOX_MCB_FINAL_MARKER, 0x0999, FINAL_SIZE)),),
        # Missing final Z marker.
        (DosboxMcbEntry(0x0401, mcb(DOSBOX_MCB_MIDDLE_MARKER, PSP, FINAL_SIZE)),),
        # Adjacent free pair makes CompressMemory a live side effect.
        (
            DosboxMcbEntry(0x0300, mcb(DOSBOX_MCB_MIDDLE_MARKER, 0, 0x0050)),
            DosboxMcbEntry(0x0351, mcb(DOSBOX_MCB_MIDDLE_MARKER, 0, 0x00AF)),
            DosboxMcbEntry(0x0401, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, FINAL_SIZE)),
        ),
    ],
)
def test_malformed_chains_refuse_at_declaration(entries: tuple) -> None:
    with pytest.raises(ValueError):
        DosboxResizePolicy(PSP, entries)


def test_environment_binds_psp_arena_and_entry_premise() -> None:
    env = environment()
    declared = policy()
    assert env.resize_policy == declared
    layout = env.memory_layout()
    # Every declared MCB header keeps its real guest coordinate as its own
    # exact chunk; the block data separating headers is never declared.
    for entry in declared.chain:
        assert (entry.address, entry.image) in layout.chunks
    assert not layout.contains(declared.chain[0].address + 16, 16)


def test_environment_refuses_foreign_psp() -> None:
    foreign = DosboxResizePolicy(
        0x0999, (DosboxMcbEntry(0x0401, mcb(DOSBOX_MCB_FINAL_MARKER, 0x0999, FINAL_SIZE)),)
    )
    with pytest.raises(ValueError, match="arena PSP"):
        environment(resize=foreign)
    wrong_final = DosboxResizePolicy(
        PSP, (DosboxMcbEntry(0x0300, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, FINAL_SIZE)),)
    )
    with pytest.raises(ValueError, match="arena PSP"):
        environment(resize=wrong_final)


def test_environment_refuses_allocation_mismatch() -> None:
    env = environment()
    with pytest.raises(ValueError, match="equal the final block"):
        replace(env, allocation=bytes((FINAL_SIZE - 1) * 16))


def test_environment_refuses_absent_entry_policy() -> None:
    with pytest.raises(ValueError, match="explicit DOSBox INT21 entry policy"):
        environment(entry=False)


def test_environment_refuses_foreign_entry_psp() -> None:
    env = environment()
    with pytest.raises(ValueError, match="exact environment PSP"):
        replace(env, dosbox_int21_entry_policy=DosBoxInt21EntryPolicy8616(PSP + 1))


def test_overlapping_chain_and_extra_memory_refuses() -> None:
    # Wholly covering a header with divergent bytes is a conflict.
    covering = InitialMemoryRegion(SegOffset(0x0080, 0), bytes(16))
    with pytest.raises(ValueError, match="conflicts"):
        ProgramEnvironment(
            psp_segment=PSP,
            allocation=bytes(FINAL_SIZE * 16),
            registers=REGISTERS,
            fs=0,
            gs=0,
            resize_policy=policy(),
            extra_memory=(covering,),
            dosbox_int21_entry_policy=DosBoxInt21EntryPolicy8616(PSP),
        )
    # A snapshot covering only part of a header is a partial overlap.
    partial = InitialMemoryRegion(SegOffset(0x0080, 8), bytes(16))
    with pytest.raises(ValueError, match="partially overlaps"):
        ProgramEnvironment(
            psp_segment=PSP,
            allocation=bytes(FINAL_SIZE * 16),
            registers=REGISTERS,
            fs=0,
            gs=0,
            resize_policy=policy(),
            extra_memory=(partial,),
            dosbox_int21_entry_policy=DosBoxInt21EntryPolicy8616(PSP),
        )


def test_every_chain_byte_is_digest_bound_or_refused() -> None:
    baseline = declared_environment_digest_8616(environment())
    baseline_document = resize_policy_document(policy())
    assert baseline is not None
    for index, entry in enumerate(chain()):
        for position in range(16):
            image = bytearray(entry.image)
            image[position] ^= 0xFF
            try:
                mutated = (
                    *chain()[:index],
                    DosboxMcbEntry(entry.segment, bytes(image)),
                    *chain()[index + 1 :],
                )
                candidate = DosboxResizePolicy(PSP, mutated)
                digest = declared_environment_digest_8616(environment(resize=candidate))
            except ValueError:
                continue  # bound by refusal: the byte is validated state
            # An admitted mutation must change both the canonical document
            # and the authenticated environment digest.
            assert resize_policy_document(candidate) != baseline_document
            assert digest is not None and digest != baseline, (index, position)


def test_minted_relation_binds_whole_policy_and_site() -> None:
    env = environment()
    relation = _mint(env)
    assert relation.resize is not None
    assert relation.resize.dosbox == policy()
    assert relation.resize.block_segment == PSP
    assert relation.resize.metadata_linear == (PSP - 1) << 4
    assert relation.resize.metadata == policy().final_entry.image
    assert relation.resize.maximum == FINAL_SIZE
    assert relation.dosbox_int21_entry_policy == DosBoxInt21EntryPolicy8616(PSP)
    assert _bind(env, relation) is relation
    expectation = declared_resize_expectation_8616(env)
    assert not isinstance(expectation, DeclaredInterruptRefusal8616)
    assert expectation.resize == relation.resize


def test_forged_dosbox_surfaces_fail_closed() -> None:
    env = environment()
    relation = _mint(env)
    assert relation.resize is not None
    # Divergent final image: surface/policy incoherence is malformed.
    forged = replace(
        relation, resize=replace(relation.resize, metadata=bytes(16))
    )
    assert _bind(env, forged) is DeclaredInterruptRefusal8616.RELATION_MALFORMED
    # A coherently forged whole policy mismatches the derived expectation.
    other = DosboxResizePolicy(
        PSP, (DosboxMcbEntry(0x0401, mcb(DOSBOX_MCB_FINAL_MARKER, PSP, FINAL_SIZE)),)
    )
    forged = replace(
        relation,
        resize=DeclaredResizeSurface8616(
            block_segment=PSP,
            metadata_linear=(PSP - 1) << 4,
            metadata=other.final_entry.image,
            maximum=FINAL_SIZE,
            dosbox=other,
        ),
    )
    assert _bind(env, forged) is DeclaredInterruptRefusal8616.ENVIRONMENT_MISMATCH
    # Dropping the chain authority cannot keep the derived surface.
    forged = replace(relation, resize=replace(relation.resize, dosbox=None))
    assert _bind(env, forged) is DeclaredInterruptRefusal8616.ENVIRONMENT_MISMATCH
    # A DOSBox relation without its INT21 entry premise is malformed.
    forged = replace(relation, dosbox_int21_entry_policy=None)
    assert validated_declared_service_8616(forged) is (
        DeclaredInterruptRefusal8616.RELATION_MALFORMED
    )


def test_dosbox_relation_does_not_bind_kvikdos_environment() -> None:
    kvikdos_mcb = bytes.fromhex("5a9201009f0000b24b56314b50523047")
    kvikdos_env = ProgramEnvironment(
        psp_segment=0x100,
        allocation=bytes(0x9F000),
        registers=REGISTERS,
        fs=0,
        gs=0,
        resize_policy=TailResizePolicy(0x100, kvikdos_mcb),
        vector_policy=VectorPolicy(DOS_ENTRY),
        extra_memory=(InitialMemoryRegion(SegOffset(0, 0), _ivt()),),
    )
    relation = _mint(environment())
    assert _bind(kvikdos_env, relation) is (
        DeclaredInterruptRefusal8616.ENVIRONMENT_MISMATCH
    )


def test_legacy_kvikdos_profile_unchanged() -> None:
    kvikdos_mcb = bytes.fromhex("5a9201009f0000b24b56314b50523047")
    tail = TailResizePolicy(0x100, kvikdos_mcb)
    document = resize_policy_document(tail)
    assert document == {
        "profile": "kvikdos_single_tail",
        "segment": 0x100,
        "mcb_hex": kvikdos_mcb.hex(),
    }
    assert parse_resize_policy(document) == tail
    kvikdos_env = ProgramEnvironment(
        psp_segment=0x100,
        allocation=bytes(0x9F000),
        registers=REGISTERS,
        fs=0,
        gs=0,
        resize_policy=tail,
        vector_policy=VectorPolicy(DOS_ENTRY),
        extra_memory=(InitialMemoryRegion(SegOffset(0, 0), _ivt()),),
    )
    # Baseline digest computed from the pre-change contract implementation.
    assert declared_environment_digest_8616(kvikdos_env) == (
        "add24995cffd2130dc3ff9cf92d97027b91540a2c7e797809edfcd971feb1bf0"
    )
    relation = declared_int21_resize_service_8616(
        kvikdos_env, caller_addr=0x4100, callsite_addr=0x5000
    )
    assert isinstance(relation, DeclaredInterruptService8616)
    assert relation.resize is not None and relation.resize.dosbox is None
    assert _bind(kvikdos_env, relation) is relation
