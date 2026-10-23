"""Layer: Tooling/gates.
Responsibility: freeze an explicit native call-closure request before sweep execution.

Selection uses admitted declarations and native discovery, never fixture names
or source bodies. Readiness does not claim unconditional case acceptance.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

from inertia.cli.declared_function_discovery import (
    DeclaredDiscoveryStatus8616,
    discover_declared_function_closure_8616,
)
from inertia.cli.project_loading import _build_project
from tools.compiler_toolchain.compiler_profile import FrozenCompilerContext
from tools.compiler_toolchain.conditional_case_composition import FrozenCaseCompositionInput
from tools.compiler_toolchain.msc6_function_targets import BinaryFunctionTarget
from tools.dosunit.catalog.real16_declared_input import parse_declared_real16_input_8616

if TYPE_CHECKING:
    import angr


class ConditionalCaseRequestStatus(StrEnum):
    """Pre-execution request readiness or its explicit unsupported input."""

    READY = 'ready'
    NO_FUNCTION_ENTRY = 'no_function_entry'
    MULTIPLE_ROOTS = 'multiple_roots'
    INPUT_REFUSED = 'input_refused'
    INPUT_CHANGED = 'input_changed'
    CLOSURE_REFUSED = 'closure_refused'
    CONTEXT_REFUSED = 'context_refused'


@dataclass(frozen=True, slots=True)
class PreparedConditionalCaseRequest:
    """Actual project and frozen request, retaining both input-file identities."""

    project: angr.Project
    contract: FrozenCaseCompositionInput
    binary_path: Path
    declaration_path: Path
    declaration_sha256: str

    def inputs_current(self) -> bool:
        """Reject changed source/declaration files before consuming child output."""
        try:
            return (hashlib.sha256(self.binary_path.read_bytes()).hexdigest() == self.contract.image_sha256
                    and hashlib.sha256(self.declaration_path.read_bytes()).hexdigest() == self.declaration_sha256)
        except OSError:
            return False


@dataclass(frozen=True, slots=True)
class ConditionalCaseRequest:
    """Atomic ready request or typed refusal without a partially usable contract."""

    status: ConditionalCaseRequestStatus
    prepared: PreparedConditionalCaseRequest | None = None
    detail: str = ''


def prepare_conditional_case_request(
    *, binary_path: Path, declaration_path: Path,
    compiler_context: FrozenCompilerContext, observations: bytes,
) -> ConditionalCaseRequest:
    """Freeze exactly one explicit root and its closed native call descendants.

    Re-read hashes after project loading and native intake callbacks. The
    existing loader independently authenticates source, load coordinates and
    declaration bytes; no inferred root or implicit environment is admitted.
    """
    if type(observations) is not bytes:
        return ConditionalCaseRequest(ConditionalCaseRequestStatus.INPUT_REFUSED, detail='observations must be bytes')
    try:
        source = binary_path.read_bytes()
        document = declaration_path.read_bytes()
        declaration_hash = hashlib.sha256(document).hexdigest()
        declaration = parse_declared_real16_input_8616(json.loads(document), source, declaration_hash)
    except (OSError, ValueError) as error:
        return ConditionalCaseRequest(ConditionalCaseRequestStatus.INPUT_REFUSED, detail=str(error))
    if not declaration.function_entries:
        return ConditionalCaseRequest(ConditionalCaseRequestStatus.NO_FUNCTION_ENTRY)
    if len(declaration.function_entries) != 1:
        return ConditionalCaseRequest(ConditionalCaseRequestStatus.MULTIPLE_ROOTS)
    try:
        compiler_context.resolve()
    except (OSError, ValueError) as error:
        return ConditionalCaseRequest(ConditionalCaseRequestStatus.CONTEXT_REFUSED, detail=str(error))
    boot = declaration.boot
    try:
        project = _build_project(binary_path, force_blob=False,
                                 base_addr=boot.image.load_segment, entry_point=boot.entry.linear(),
                                 real16_declared_input=declaration_path)
        discovery = discover_declared_function_closure_8616(project)
    except (OSError, ValueError) as error:
        return ConditionalCaseRequest(ConditionalCaseRequestStatus.INPUT_REFUSED, detail=str(error))
    if discovery is None or discovery.status is not DeclaredDiscoveryStatus8616.CLOSED:
        return ConditionalCaseRequest(ConditionalCaseRequestStatus.CLOSURE_REFUSED)
    spec = declaration.function_entries[0].spec
    entry_address = (spec.entry_segment << 4) + spec.entry_offset
    if discovery.roots != (entry_address,) or entry_address not in discovery.heads:
        return ConditionalCaseRequest(ConditionalCaseRequestStatus.CLOSURE_REFUSED)
    selected = tuple(BinaryFunctionTarget(f'sub_{head:x}', head) for head in discovery.heads)
    entry = next(target for target in selected if target.address == entry_address)
    contract = FrozenCaseCompositionInput(
        selected, entry, hashlib.sha256(source).hexdigest(),
        ((entry_address, json.dumps(spec.to_dict(), sort_keys=True, separators=(',', ':'))),),
        observations, compiler_context, boot.image.load_segment << 4,
    )
    prepared = PreparedConditionalCaseRequest(project, contract, binary_path.resolve(),
                                             declaration_path.resolve(), declaration_hash)
    if not prepared.inputs_current():
        return ConditionalCaseRequest(ConditionalCaseRequestStatus.INPUT_CHANGED)
    return ConditionalCaseRequest(ConditionalCaseRequestStatus.READY, prepared)
