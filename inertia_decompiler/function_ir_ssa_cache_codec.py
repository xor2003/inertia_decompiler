"""Encode exact raw IR and SSA cache payloads with bounded class ownership.

Layer: CLI/fallback/reporting orchestration.
Responsibility: serialize already-owned raw IR, rebuild its deterministic
IR-stage SSA projection, reject unsafe classes, and verify payload integrity.
No semantic recovery occurs here.
"""

from __future__ import annotations

import base64
import hashlib
import importlib
import io
import pickle
from collections.abc import Mapping
from dataclasses import dataclass, is_dataclass
from enum import Enum

from angr_platforms.X86_16.ir.function_artifact import IRFunctionArtifact
from angr_platforms.X86_16.ir.ssa_function import (
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
)

_FUNCTION_IR_SSA_CACHE_SCHEMA_8616: int = 4
_MAX_PICKLE_BYTES_8616: int = 64 * 1024 * 1024
_ALLOWED_IR_MODULE_PREFIXES_8616: tuple[str, ...] = (
    "angr_platforms.X86_16.ir.",
    "angr_platforms.angr_platforms.X86_16.ir.",
)


@dataclass(frozen=True, slots=True)
class FunctionIRSSABundle8616:
    """One coherent raw IR artifact and its exact IR-stage SSA projection."""

    ir: IRFunctionArtifact
    ssa: SSAFunctionArtifact

    @property
    def coherent(self) -> bool:
        """Return whether both artifacts describe one complete function."""
        ir_blocks = tuple(block.addr for block in self.ir.blocks)
        ssa_blocks = tuple(block.addr for block in self.ssa.blocks)
        return bool(
            self.ir.function_addr == self.ssa.function_addr
            and not self.ir.refusals
            and ir_blocks == ssa_blocks
            and self.ir.logical_memory == self.ssa.logical_memory
            and self.ir.condition_evidence == self.ssa.condition_evidence
        )


class _RestrictedIRUnpickler8616(pickle.Unpickler):
    """Allow only owned IR dataclasses and enums in cache payloads."""

    def find_class(self, module: str, name: str) -> type[object]:
        """Resolve one explicitly bounded owned class."""
        if module == "builtins" and name == "frozenset":
            return frozenset
        if not module.startswith(_ALLOWED_IR_MODULE_PREFIXES_8616):
            raise pickle.UnpicklingError(
                f"cache class outside IR ownership: {module}.{name}"
            )
        imported = importlib.import_module(module)
        # Dynamic third-party pickle boundary: the payload supplies an owned class name.
        candidate = getattr(imported, name, None)
        if not isinstance(candidate, type):
            raise pickle.UnpicklingError(
                f"cache class is unavailable: {module}.{name}"
            )
        if not is_dataclass(candidate) and not issubclass(candidate, Enum):
            raise pickle.UnpicklingError(
                f"cache class is not a dataclass or enum: {module}.{name}"
            )
        return candidate


def function_ir_ssa_bundle_record_8616(
    bundle: FunctionIRSSABundle8616,
) -> dict[str, object]:
    """Encode one coherent bundle with payload and projection digests."""
    if not bundle.coherent:
        raise ValueError("cannot persist incoherent function IR/SSA artifacts")
    payload = pickle.dumps(bundle.ir, protocol=5)
    if len(payload) > _MAX_PICKLE_BYTES_8616:
        raise ValueError("function IR/SSA cache payload is oversized")
    return {
        "schema": _FUNCTION_IR_SSA_CACHE_SCHEMA_8616,
        "function_addr": bundle.ir.function_addr,
        "payload": base64.b64encode(payload).decode("ascii"),
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }


def function_ir_ssa_bundle_from_record_8616(
    record: object,
    function_addr: int,
) -> FunctionIRSSABundle8616:
    """Decode one record after all ownership and integrity checks pass."""
    if (
        not isinstance(record, Mapping)
        or record.get("schema") != _FUNCTION_IR_SSA_CACHE_SCHEMA_8616
    ):
        raise ValueError("unsupported function IR/SSA cache schema")
    encoded = record.get("payload")
    if not isinstance(encoded, str):
        raise ValueError("function IR/SSA cache payload is missing")
    payload = base64.b64decode(encoded, validate=True)
    if len(payload) > _MAX_PICKLE_BYTES_8616:
        raise ValueError("function IR/SSA cache payload is oversized")
    if hashlib.sha256(payload).hexdigest() != record.get("payload_sha256"):
        raise ValueError("function IR/SSA cache payload digest disagrees")
    ir = _RestrictedIRUnpickler8616(io.BytesIO(payload)).load()
    if not isinstance(ir, IRFunctionArtifact):
        raise ValueError("function IR/SSA cache payload is not raw IR")
    try:
        ssa = build_x86_16_function_ssa(ir)
    except (AttributeError, KeyError, TypeError, ValueError) as ex:
        raise ValueError("function IR/SSA cache SSA rebuild failed") from ex
    bundle = FunctionIRSSABundle8616(ir, ssa)
    if not bundle.coherent or ir.function_addr != function_addr:
        raise ValueError("function IR/SSA cache artifacts are incoherent")
    return bundle


__all__ = [
    "FunctionIRSSABundle8616",
    "function_ir_ssa_bundle_from_record_8616",
    "function_ir_ssa_bundle_record_8616",
]
