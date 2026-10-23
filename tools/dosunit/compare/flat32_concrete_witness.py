"""Admit concrete integer counterexamples over shared scratch memory.

Layer: dosunit comparison evidence.
Responsibility: refute complete returning function slices under an explicit
shared concrete input. Agreement never proves equivalence. Execute-only code
prevents different image bytes from becoming unequal data inputs. No external
calls, code writes, undefined-flag consumers, or unmodeled register files are
admitted by this bounded instruction contract.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import capstone
from capstone import x86_const as instructions

from tools.dosunit.runtime.flat32_memory_permissions import DeclaredAccess, DeclaredRegion, MappingOrigin
from tools.dosunit.runtime.flat32_replay import replay
from tools.dosunit.runtime.flat32_replay_model import (
    MemoryRange,
    ObservationStatus,
    ReplayImage,
    ReplayResult,
    ReplayStatus,
    ReplayVector,
)

INTEGER_OUTPUTS: frozenset[str] = frozenset({'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'})
ADMITTED_INSTRUCTIONS: frozenset[int] = frozenset({
    instructions.X86_INS_MOV,
    instructions.X86_INS_MOVSX,
    instructions.X86_INS_MOVZX,
    instructions.X86_INS_LEA,
    instructions.X86_INS_ADD,
    instructions.X86_INS_SUB,
    instructions.X86_INS_INC,
    instructions.X86_INS_DEC,
    instructions.X86_INS_AND,
    instructions.X86_INS_OR,
    instructions.X86_INS_XOR,
    instructions.X86_INS_TEST,
    instructions.X86_INS_CMP,
    instructions.X86_INS_IMUL,
    instructions.X86_INS_SAR,
    instructions.X86_INS_PUSH,
    instructions.X86_INS_POP,
    instructions.X86_INS_LEAVE,
    instructions.X86_INS_NOP,
    instructions.X86_INS_RET,
    instructions.X86_INS_CALL,
    instructions.X86_INS_JMP,
    instructions.X86_INS_JA,
    instructions.X86_INS_JAE,
    instructions.X86_INS_JB,
    instructions.X86_INS_JBE,
    instructions.X86_INS_JE,
    instructions.X86_INS_JNE,
    instructions.X86_INS_JG,
    instructions.X86_INS_JGE,
    instructions.X86_INS_JL,
    instructions.X86_INS_JLE,
    instructions.X86_INS_JO,
    instructions.X86_INS_JNO,
    instructions.X86_INS_JS,
    instructions.X86_INS_JNS,
    instructions.X86_INS_JP,
    instructions.X86_INS_JNP,
    instructions.X86_INS_JECXZ,
})


@dataclass(frozen=True, slots=True)
class ConcreteFunction:
    """Exact native bytes at their actual virtual address, supplied by the loader."""

    entry: int
    code: bytes

    def image(self) -> ReplayImage:
        """Declare code executable but not readable as guest data or writable."""
        if not self.code or len(self.code) > 65536 or not 0 <= self.entry < 2**32 - len(self.code):
            raise ValueError('invalid concrete function extent')
        return ReplayImage(((self.entry, self.code),), (MemoryRange(self.entry, len(self.code)),),
                           (DeclaredRegion(self.entry, len(self.code), DeclaredAccess.EXECUTE,
                                           MappingOrigin.FILE),))


def _returned_via_ret(result: ReplayResult) -> bool:
    """Reject a direct jump to the harness trap masquerading as a function return."""
    if result.status is not ReplayStatus.RETURNED or result.last_instruction is None:
        return False
    address, raw = result.last_instruction
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    instruction = next(decoder.disasm(raw, address), None)
    return instruction is not None and instruction.id == instructions.X86_INS_RET


def _memory_mismatches(left: ReplayResult, right: ReplayResult) -> list[dict[str, Any]] | None:
    """Compare fully captured vector scratch only, excluding image and trap bytes."""
    if len(left.observations) != len(right.observations):
        return None
    differences: list[dict[str, Any]] = []
    for original, rebuilt in zip(left.observations, right.observations, strict=True):
        if (original.address, original.size) != (rebuilt.address, rebuilt.size):
            return None
        for observed in (original, rebuilt):
            if (observed.status is not ObservationStatus.CAPTURED
                    or observed.origins != (MappingOrigin.VECTOR,)
                    or len(observed.data) != observed.size):
                return None
        if original.data != rebuilt.data:
            differences.append({'memory_address': hex(original.address), 'size': original.size,
                                'oracle_bytes': original.data.hex(), 'candidate_bytes': rebuilt.data.hex()})
    return differences


def compare_concrete_witness(
    oracle: ConcreteFunction, candidate: ConcreteFunction, vector: ReplayVector,
    *, outputs: tuple[str, ...] = ('eax',), instruction_limit: int = 4096,
) -> dict[str, Any]:
    """Return a complete-function counterexample or an explicit non-result.

    The caller must bind the supplied native slices and entries to its binary
    catalog and must not reinterpret this literal shared-memory domain as a
    relocation or ABI premise. All scratch starts zero, then the same vector
    seeds both guests. A scalar mismatch needs no memory-output projection:
    observing additional effects cannot invalidate that concrete difference.
    """
    if not outputs or len(set(outputs)) != len(outputs) or not set(outputs) <= INTEGER_OUTPUTS:
        raise ValueError('concrete witness requires distinct integer register outputs')
    if not 1 <= instruction_limit <= 100000:
        raise ValueError('concrete witness instruction limit must be 1..100000')
    images = oracle.image(), candidate.image()
    left, right = (
        replay(image, function.entry, vector, instruction_limit=instruction_limit,
               allowed_instruction_ids=ADMITTED_INSTRUCTIONS)
        for image, function in zip(images, (oracle, candidate), strict=True)
    )
    execution = {
        side: {'status': result.status.value, 'detail': result.detail,
               'instructions': result.instructions, 'returned_via_ret': _returned_via_ret(result)}
        for side, result in (('oracle', left), ('candidate', right))
    }
    if not all(row['returned_via_ret'] for row in execution.values()):
        return {'status': 'refused', 'reason': 'concrete_execution_incomplete', 'execution': execution}
    lregs, rregs = dict(left.registers), dict(right.registers)
    mismatches = [{'reg': name, 'oracle_value': hex(lregs[name]), 'candidate_value': hex(rregs[name])}
                  for name in outputs if lregs[name] != rregs[name]]
    memory_mismatches = _memory_mismatches(left, right)
    if memory_mismatches is None:
        return {'status': 'refused', 'reason': 'concrete_memory_observation_not_admitted', 'execution': execution}
    mismatches.extend(memory_mismatches)
    if not mismatches:
        return {'status': 'refused', 'reason': 'concrete_agreement_is_not_proof', 'execution': execution}
    return {
        'status': 'failed',
        'reason': 'concrete_memory_counterexample' if memory_mismatches else 'concrete_register_counterexample',
        'proof_scope': 'complete_function', 'proof_method': 'bounded_integer_execution_counterexample',
        'mismatches': mismatches, 'execution': execution,
        'domain': 'shared_zero_initialized_scratch_with_identical_vector_seeds_and_execute_only_code',
        'outputs': list(outputs), 'instruction_limit': instruction_limit,
        'memory_outputs': [{'address': item.address, 'size': item.size} for item in vector.observations],
        'inputs': {'registers': dict(vector.registers),
                   'memory': [{'address': address, 'bytes': data.hex()} for address, data in vector.memory],
                   'mappings': [{'address': region.address, 'size': region.size,
                                 'access': int(region.access), 'origin': region.origin.value}
                                for region in vector.mappings]},
        'functions': {side: {'entry': function.entry, 'size': len(function.code),
                             'sha256': hashlib.sha256(function.code).hexdigest()}
                      for side, function in (('oracle', oracle), ('candidate', candidate))},
    }
