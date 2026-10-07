"""Durable tests for the function-entry fetch-domain proof and application.

Layer: Tests.
Responsibility: pin the native indexed-loop entry-JMP theorem — importer
discharge, the five-stage typed proof with closed ledger accounting, the
typed source binding, and bound application — against the real encoded
fixture bytes. Changed input surfaces, bindings, or admitted edges must
produce typed refusals or the ``STALE_INPUT`` non-result, never an edge.
"""

from __future__ import annotations

import io
from collections.abc import Callable
from dataclasses import replace
from types import SimpleNamespace

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
)
from inertia.ir.entry_jump_domain import (
    AdmittedTerminalJump8616,
    EntryJumpDomainApplication8616,
    EntryJumpDomainApplicationStatus8616,
    EntryJumpDomainBudget8616,
    EntryJumpDomainProof8616,
    EntryJumpDomainRefusal8616,
    apply_entry_jump_domain_8616,
    prove_entry_jump_domains_8616,
)
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.ir.vex_terminal_jump import (
    TerminalJumpEvidence8616,
    TerminalJumpEvidenceStats8616,
    TerminalJumpRefusalReason8616,
)
from pyvex.errors import PyVEXError

from inertia.frontend.x86_16.relative_control_edge import (
    DecodedRelativeEdge,
    decode_relative_edge,
)

_FUNCTION_ADDR = 0x1000
_JMP_BLOCK = 0x1011
_JMP_HEAD = 0x101B
_JMP_ENCODING = b"\xeb\xee"
_JMP_TARGET = 0x100B
_Status = EntryJumpDomainApplicationStatus8616
_Reason = EntryJumpDomainRefusal8616
_UNPROVED = TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED.value
_APPLIED = _Status.APPLIED
_STALE = _Status.STALE_INPUT
_STALE_KIND = _Reason.APPLICATION_INPUT_STALE.value

# push bp; mov bp,sp; sub sp,2; mov word [bp-2],0 | cmp word [bp-2],4;
# jae epilogue | mov bx,[bp-2]; mov al,[bx+0x200]; inc word [bp-2];
# jmp -0x12 -> loop head | mov sp,bp; pop bp; ret
_INDEXED_LOOP = bytes.fromhex(
    "55 89 e5 83 ec 02 c7 46 fe 00 00 83 7e fe 04 73 0c "
    "8b 5e fe 8a 87 00 02 ff 46 fe eb ee 89 ec 5d c3"
)


def _project(binary: bytes = _INDEXED_LOOP) -> angr.Project:
    """Build the blob source-authority project at the loader-linear base."""
    return angr.Project(
        io.BytesIO(bytes(binary)),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": _FUNCTION_ADDR,
            "entry_point": _FUNCTION_ADDR,
        },
        auto_load_libs=False,
    )


def _artifact(
    binary: bytes = _INDEXED_LOOP,
    block_addrs: frozenset[int] = frozenset({0x1000, 0x100B, 0x1011, 0x101D}),
    entry: int = _FUNCTION_ADDR,
) -> IRFunctionArtifact:
    """Import the fixture through the real VEX importer for one block set."""
    function = SimpleNamespace(addr=entry, block_addrs_set=block_addrs, info={})
    return build_x86_16_ir_function_artifact(_project(binary), function)


def _block(
    container: IRFunctionArtifact | EntryJumpDomainApplication8616,
    addr: int,
) -> IRBlock:
    """Return the census block at one loader-linear address."""
    return next(b for b in container.blocks if b.addr == addr)


def _with_block(
    artifact: IRFunctionArtifact, addr: int, **changes: object
) -> IRFunctionArtifact:
    """Return the artifact with one census block's fields replaced."""
    return replace(artifact, blocks=tuple(
        replace(b, **changes) if b.addr == addr else b
        for b in artifact.blocks
    ))


def _swap_terminal(
    artifact: IRFunctionArtifact, **changes: object
) -> IRFunctionArtifact:
    """Return the artifact with the transfer terminal's fields replaced."""
    block = _block(artifact, _JMP_BLOCK)
    return _with_block(artifact, _JMP_BLOCK, instrs=(
        *block.instrs[:-1], replace(block.instrs[-1], **changes)
    ))


def _evidence(head: int, encoding: bytes) -> TerminalJumpEvidence8616:
    """Build the pending-selector-window carrier for exact decoded bytes."""
    decoded = decode_relative_edge(head, encoding, source="block_terminal")
    assert isinstance(decoded, DecodedRelativeEdge)
    return TerminalJumpEvidence8616(
        retain=True,
        proven_target=None,
        refusals=(),
        failure=TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED,
        stats=TerminalJumpEvidenceStats8616(1, 1, 1, 0, 1),
        decoded=decoded,
    )


def _pending() -> dict[int, TerminalJumpEvidence8616]:
    """Return the authentic pending map for the fixture's loop-back jump."""
    return {_JMP_BLOCK: _evidence(_JMP_HEAD, _JMP_ENCODING)}


def _summary(artifact: IRFunctionArtifact, key: str) -> dict[str, object]:
    """Return one typed summary record the importer must have written."""
    record = artifact.summary[key]
    assert isinstance(record, dict)
    return record


def _cs_write(artifact: IRFunctionArtifact) -> IRFunctionArtifact:
    """Append an explicit typed CS write to the reachable entry block."""
    entry = _block(artifact, _FUNCTION_ADDR)
    write = IRInstr(
        "MOV",
        IRValue(MemSpace.REG, name="cs", size=2),
        (IRValue(MemSpace.CONST, const=0x200, size=2),),
        size=2,
        addr=0x1009,
    )
    return _with_block(artifact, _FUNCTION_ADDR, instrs=(*entry.instrs, write))


def _missing_loop_head(artifact: IRFunctionArtifact) -> IRFunctionArtifact:
    """Drop the loop-head block so its incoming edge leaves the census."""
    return replace(artifact, blocks=tuple(
        b for b in artifact.blocks if b.addr != _JMP_TARGET
    ))


def _stale_tmp_capture(artifact: IRFunctionArtifact) -> IRFunctionArtifact:
    """Change only the operand's compare=False captured temporary."""
    arg = _block(artifact, _JMP_BLOCK).instrs[-1].args[0]
    assert isinstance(arg, IRValue)
    mutated = replace(arg, source_tmp=777)
    assert mutated == arg  # dataclass equality cannot see the capture
    return _swap_terminal(artifact, args=(mutated,))


class _RaisingBlockFactory:
    """Block factory whose lift always raises the supplied exception."""

    def __init__(self, error: Exception) -> None:
        self._error = error

    def block(self, *_args: object, **_kwargs: object) -> object:
        """Raise the configured exception instead of lifting."""
        raise self._error


def _raising_project(error: Exception) -> SimpleNamespace:
    """Build a source authority whose native re-lift raises the error."""
    return SimpleNamespace(arch=Arch86_16(), factory=_RaisingBlockFactory(error))


@pytest.fixture(scope="module")
def artifact() -> IRFunctionArtifact:
    """Import the indexed-loop fixture once for the whole module."""
    return _artifact()


@pytest.fixture(scope="module")
def project() -> angr.Project:
    """Build the fixture's source-authority project once per module."""
    return _project()


@pytest.fixture(scope="module")
def domain_proof(
    artifact: IRFunctionArtifact, project: angr.Project
) -> EntryJumpDomainProof8616:
    """Prove the authentic pending jump once for the whole module."""
    proof = prove_entry_jump_domains_8616(artifact, _pending(), project=project)
    assert proof.admitted and proof.stats.closed
    return proof


def test_import_discharges_indexed_loop_back_edge(
    artifact: IRFunctionArtifact,
) -> None:
    """The importer's domain proof materializes the exact decoded edge."""
    block = _block(artifact, _JMP_BLOCK)
    terminal = block.instrs[-1]
    operand = terminal.args[0]
    assert block.successor_addrs == (_JMP_TARGET,)
    assert terminal.op == "JMP" and terminal.addr == _JMP_HEAD
    assert isinstance(operand, IRValue)
    assert operand.space is MemSpace.CONST and operand.const == _JMP_TARGET
    assert not any(r.kind == _UNPROVED for r in block.refusals)
    assert not any(r.kind == _UNPROVED for r in artifact.refusals)
    application = _summary(artifact, "entry_jump_domain_application")
    assert application["status"] == _APPLIED.value
    assert application["applied"] == [
        {
            "block_addr": _JMP_BLOCK,
            "head": _JMP_HEAD,
            "target": _JMP_TARGET,
            "invocation": None,
            "invocation_scope": None,
            "call_dependencies": [],
        }
    ]
    assert _summary(artifact, "entry_jump_domain")["stats"] == {
        "raw_fact_count": len(artifact.blocks),
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
    }


def test_proof_binds_source_surface_and_admits_target(
    domain_proof: EntryJumpDomainProof8616, artifact: IRFunctionArtifact
) -> None:
    """The proof product records the exact input surface it consumed."""
    binding = domain_proof.source_binding
    assert domain_proof.function_addr == _FUNCTION_ADDR
    assert binding.function_addr == _FUNCTION_ADDR
    assert binding.block_count == len(artifact.blocks)
    assert len(binding.digest) == 64
    assert [c.block_addr for c in binding.pending] == [_JMP_BLOCK]
    assert binding.pending[0].decoded.head == _JMP_HEAD
    assert binding.pending[0].decoded.encoding == _JMP_ENCODING
    assert domain_proof.admitted == (AdmittedTerminalJump8616(
        block_addr=_JMP_BLOCK, head=_JMP_HEAD, target=_JMP_TARGET
    ),)
    assert domain_proof.stats.closed
    assert domain_proof.stats.materialized_count == 1
    assert domain_proof.stats.failure_count == 0
    assert domain_proof.terms_consumed > 0 and domain_proof.iterations >= 1


def test_apply_materializes_only_the_admitted_edge(
    artifact: IRFunctionArtifact, domain_proof: EntryJumpDomainProof8616
) -> None:
    """APPLIED binds the proved surface, not artifact object identity."""
    for supplied in (
        artifact,
        IRFunctionArtifact(
            function_addr=artifact.function_addr, blocks=artifact.blocks
        ),
    ):
        result = apply_entry_jump_domain_8616(supplied, domain_proof)
        assert result.status is _APPLIED and result.refusals == ()
        assert result.applied == domain_proof.admitted
        assert result.blocks == supplied.blocks
        assert _JMP_TARGET in _block(result, _JMP_BLOCK).successor_addrs


def test_empty_proof_returns_input_unchanged(
    artifact: IRFunctionArtifact, project: angr.Project
) -> None:
    """A proof with no candidates is an honest constant-cost non-result."""
    proof = prove_entry_jump_domains_8616(artifact, {}, project=project)
    assert proof.stats.closed and proof.terms_consumed == 0
    result = apply_entry_jump_domain_8616(artifact, proof)
    assert result.status is _Status.EMPTY
    assert result.blocks == artifact.blocks
    assert result.applied == () and result.refusals == ()


def test_isolated_entry_keeps_pending_refusal_and_empty_discharge() -> None:
    """A body-rooted function cannot fetch the loop target in-window."""
    isolated = _artifact(block_addrs=frozenset({_JMP_BLOCK}), entry=_JMP_BLOCK)
    block = _block(isolated, _JMP_BLOCK)
    assert _JMP_TARGET not in block.successor_addrs
    assert any(_UNPROVED in r.kind for r in block.refusals)
    assert any(_UNPROVED in r.kind for r in isolated.refusals)
    application = _summary(isolated, "entry_jump_domain_application")
    assert application["status"] == _Status.EMPTY.value
    proof = prove_entry_jump_domains_8616(isolated, _pending(), project=_project())
    assert not proof.admitted and proof.stats.closed
    assert [r.kind for r in proof.refusals] == [_Reason.JOINT_WINDOW_UNPROVED.value]


_Mutate = Callable[[IRFunctionArtifact], IRFunctionArtifact]
_Tamper = Callable[[EntryJumpDomainProof8616], EntryJumpDomainProof8616]
_REFUSAL_CASES: tuple[tuple[str, _Mutate, _Reason], ...] = (
    ("entry_missing", lambda a: replace(a, function_addr=0x1002), _Reason.ENTRY_BLOCK_MISSING),
    ("path_incomplete", _missing_loop_head, _Reason.PATH_INCOMPLETE),
    ("exterior_edge", lambda a: _with_block(
        a, _FUNCTION_ADDR,
        successor_addrs=(*_block(a, _FUNCTION_ADDR).successor_addrs, 0x2000)),
     _Reason.PATH_INCOMPLETE),
    ("cs_write", _cs_write, _Reason.CS_WRITE_INTERFERENCE),
    ("unknown_effect", lambda a: _with_block(a, _FUNCTION_ADDR, instrs=(
        IRInstr("DIRTY", IRValue(MemSpace.REG, name="ax", size=2), (),
                size=2, addr=_FUNCTION_ADDR),
        *_block(a, _FUNCTION_ADDR).instrs)), _Reason.UNKNOWN_EFFECT_ON_PATH),
)


@pytest.mark.parametrize(
    ("name", "mutate", "reason"), _REFUSAL_CASES, ids=[c[0] for c in _REFUSAL_CASES],
)
def test_reachable_path_violation_refuses_closed(
    artifact: IRFunctionArtifact,
    project: angr.Project,
    name: str,
    mutate: _Mutate,
    reason: _Reason,
) -> None:
    """Each typed census/path violation keeps the pending refusal."""
    proof = prove_entry_jump_domains_8616(
        mutate(artifact), _pending(), project=project
    )
    assert not proof.admitted and proof.stats.closed
    assert proof.stats.materialized_count == 0
    assert proof.stats.failure_count == len(proof.refusals)
    assert any(
        r.kind == reason.value and r.block_addr == _JMP_BLOCK
        for r in proof.refusals
    )


@pytest.mark.parametrize(
    "encoding",
    (
        b"\xeb\x00",
        b"\xe9\x00\x00",
        b"\x66\xe9\x00\x00\x00\x00",
        b"\xe8\x00\x00",
        b"\x73\xee",
    ),
    ids=("forged_in_window", "rel16_length", "rel32_width", "call", "jcc"),
)
def test_transfer_carrier_mismatch_refuses(
    artifact: IRFunctionArtifact, project: angr.Project, encoding: bytes
) -> None:
    """Forged bytes or a non-word-jump carrier refuse at the transfer stage."""
    assert isinstance(
        decode_relative_edge(_JMP_HEAD, encoding), DecodedRelativeEdge
    )
    proof = prove_entry_jump_domains_8616(
        artifact,
        {_JMP_BLOCK: _evidence(_JMP_HEAD, encoding)},
        project=project,
    )
    assert not proof.admitted and proof.stats.closed
    assert proof.stats.materialized_count == 0
    assert proof.stats.failure_count == 1
    assert proof.refusals[0].kind == _Reason.TRANSFER_FACT_MISMATCH.value


def test_forged_encoding_fails_only_at_native_byte_gate(
    artifact: IRFunctionArtifact, project: angr.Project
) -> None:
    """With the symbolic operand restored only re-lifted bytes can refuse."""
    block = _block(artifact, _JMP_BLOCK)
    terminal = block.instrs[-1]
    origin = terminal.origin
    assert origin is not None and type(origin.block_next_tmp) is int
    symbolic = replace(terminal, args=(IRValue(
        MemSpace.TMP,
        name=f"t{origin.block_next_tmp}",
        size=4,
        source_tmp=origin.block_next_tmp,
        expr=("Iop_Add32",),
    ),))
    forged = _with_block(
        artifact, _JMP_BLOCK, instrs=(*block.instrs[:-1], symbolic)
    )
    proof = prove_entry_jump_domains_8616(
        forged, {_JMP_BLOCK: _evidence(_JMP_HEAD, b"\xeb\x00")}, project=project
    )
    assert not proof.admitted and proof.stats.closed
    assert proof.stats.failure_count == 1
    assert proof.refusals[0].kind == _Reason.TRANSFER_FACT_MISMATCH.value
    assert "native terminal encoding" in proof.refusals[0].detail


@pytest.mark.parametrize(
    "source",
    (None, _raising_project(PyVEXError("forced"))),
    ids=("absent_authority", "named_decode_failure"),
)
def test_unproved_native_source_refuses_closed(
    artifact: IRFunctionArtifact, source: object
) -> None:
    """A missing authority or named decode failure is honest proof debt."""
    proof = prove_entry_jump_domains_8616(artifact, _pending(), project=source)
    assert not proof.admitted and proof.stats.closed
    assert proof.stats.materialized_count == 0
    assert proof.stats.failure_count == 1
    assert proof.refusals[0].kind == _Reason.NATIVE_SOURCE_UNPROVED.value


def test_deterministic_budget_refuses_closed(
    artifact: IRFunctionArtifact, project: angr.Project
) -> None:
    """A term budget too small for the census refuses identically twice."""
    budget = EntryJumpDomainBudget8616(max_terms=4)
    first = prove_entry_jump_domains_8616(
        artifact, _pending(), project=project, budget=budget
    )
    second = prove_entry_jump_domains_8616(
        artifact, _pending(), project=project, budget=budget
    )
    assert first.to_dict() == second.to_dict()
    assert not first.admitted and first.stats.closed
    assert first.stats.materialized_count == 0
    assert first.stats.failure_count == len(first.refusals) == 1
    assert first.refusals[0].kind in {
        _Reason.BLOCK_CENSUS_INCOMPLETE.value, _Reason.BUDGET_EXCEEDED.value,
    }


def test_unexpected_lift_error_propagates(artifact: IRFunctionArtifact) -> None:
    """An unexpected defect escapes the re-lift boundary with its cause."""
    with pytest.raises(RuntimeError, match="forced"):
        prove_entry_jump_domains_8616(
            artifact, _pending(),
            project=_raising_project(RuntimeError("forced")),
        )


_STALE_MUTATIONS: tuple[tuple[str, _Mutate, str], ...] = (
    ("opcode", lambda a: _swap_terminal(a, op="HALT"), "do not recompute"),
    ("operand", lambda a: _swap_terminal(
        a, args=(IRValue(MemSpace.CONST, const=0x100D, size=4),)),
     "do not recompute"),
    ("captured_tmp", _stale_tmp_capture, "do not recompute"),
    ("effect_elsewhere", _cs_write, "do not recompute"),
    ("missing_block", _missing_loop_head, "do not recompute"),
    ("added_block", lambda a: replace(
        a, blocks=(*a.blocks, IRBlock(addr=0x2000))), "do not recompute"),
    ("reordered_blocks", lambda a: replace(
        a, blocks=tuple(reversed(a.blocks))), "do not recompute"),
    ("successor_edges", lambda a: _with_block(
        a, _FUNCTION_ADDR, successor_addrs=()), "do not recompute"),
    ("moved_root", lambda a: replace(a, function_addr=0x2000),
     "does not match the proved function root"),
)


@pytest.mark.parametrize(
    ("name", "mutate", "detail"), _STALE_MUTATIONS, ids=[c[0] for c in _STALE_MUTATIONS],
)
def test_stale_input_refuses_without_touching_input(
    artifact: IRFunctionArtifact,
    domain_proof: EntryJumpDomainProof8616,
    name: str,
    mutate: _Mutate,
    detail: str,
) -> None:
    """Any changed proved surface is the typed STALE_INPUT non-result."""
    supplied = mutate(artifact)
    result = apply_entry_jump_domain_8616(supplied, domain_proof)
    assert result.status is _STALE
    assert result.blocks == supplied.blocks
    assert result.applied == ()
    assert [r.kind for r in result.refusals] == [_STALE_KIND]
    assert detail in result.refusals[0].detail
    assert domain_proof.stats.closed


def test_stale_root_names_both_roots(
    artifact: IRFunctionArtifact, domain_proof: EntryJumpDomainProof8616
) -> None:
    """A moved consuming root refuses and names both roots."""
    supplied = replace(artifact, function_addr=_JMP_BLOCK)
    result = apply_entry_jump_domain_8616(supplied, domain_proof)
    assert result.status is _STALE and result.blocks == supplied.blocks
    assert f"{_JMP_BLOCK:#x}" in result.refusals[0].detail
    assert f"{_FUNCTION_ADDR:#x}" in result.refusals[0].detail


_PROOF_TAMPERS: tuple[tuple[str, _Tamper, str], ...] = (
    ("materialized_count", lambda p: replace(p, stats=replace(
        p.stats, materialized_count=0)), "accounting does not close"),
    ("classified_count", lambda p: replace(p, stats=replace(
        p.stats, classified_fact_count=0)), "accounting does not close"),
    ("failure_count", lambda p: replace(p, stats=replace(
        p.stats, failure_count=1)), "accounting does not close"),
    ("admitted_target", lambda p: replace(p, admitted=tuple(
        replace(j, target=j.target + 1) for j in p.admitted)),
     "does not match its decoded entry-window"),
    ("duplicate_block", lambda p: replace(
        p, admitted=(*p.admitted, *p.admitted)), "claim the same terminal block"),
    ("unbacked_edge", lambda p: replace(p, admitted=(
        AdmittedTerminalJump8616(
            block_addr=_JMP_BLOCK, head=0x10FF, target=_FUNCTION_ADDR
        ),)), "is not backed by a recorded pending candidate"),
    ("forged_digest", lambda p: replace(p, source_binding=replace(
        p.source_binding, digest="0" * 64)), "do not recompute the proof's recorded"),
    ("moved_proof_root", lambda p: replace(p, function_addr=0x2000),
     "is inconsistent with its recorded binding"),
    ("moved_binding_root", lambda p: replace(p, source_binding=replace(
        p.source_binding, function_addr=0x2000)),
     "is inconsistent with its recorded binding"),
)


@pytest.mark.parametrize(
    ("name", "tamper", "detail"), _PROOF_TAMPERS, ids=[c[0] for c in _PROOF_TAMPERS],
)
def test_tampered_proof_product_refuses(
    artifact: IRFunctionArtifact,
    domain_proof: EntryJumpDomainProof8616,
    name: str,
    tamper: _Tamper,
    detail: str,
) -> None:
    """A proof product that does not cover the input refuses closed."""
    result = apply_entry_jump_domain_8616(artifact, tamper(domain_proof))
    assert result.status is _STALE
    assert result.blocks == artifact.blocks
    assert result.applied == ()
    assert [r.kind for r in result.refusals] == [_STALE_KIND]
    assert detail in result.refusals[0].detail
