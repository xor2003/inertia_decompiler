# cython: language_level=3, infer_types=True
"""Deterministic direct-address repeated-family evidence bundles.

Layer: CLI/fallback/reporting.
Responsibility: persist repeated direct-address fallback diagnostics without changing retry policy.

This module is reporting infrastructure only. It records what the direct lane
already observed when a repeated failure family stops retrying; it must not
change retry decisions, fallback selection, decompiler semantics, or timeout
budgets.
"""

from __future__ import annotations
import typing
import cython

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
import dataclasses

_UNAVAILABLE = "unavailable\n"


@dataclasses.dataclass(frozen=True, )
class DirectAddrStageBundleInput:
    """Inputs captured at a repeated direct-address family stop."""

    binary_path: Path | None
    function_addr: cython.longlong
    function_name: object
    family_label: object
    raw_asm: object = None
    cod_window: object = None
    raw_codegen: object = None
    post_callsite: object = None
    post_stack_lowering: object = None
    final_stdout: object = None
    final_stderr: object = None


@dataclasses.dataclass(frozen=True, )
class DirectAddrStageBundleResult:
    """Result of a bundle write or reuse."""

    path: Path
    reused: cython.bint


@cython.ccall
def _safe_component(value: object, *, limit: cython.longlong = 64) -> object:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value))
    text = text.strip("._-")
    if not text:
        text = "x"
    return text[:limit]


@cython.ccall
def _stable_text(value: object) -> object:
    if not isinstance(value, str) or not value.strip():
        return _UNAVAILABLE
    return value if value.endswith("\n") else value + "\n"


@cython.ccall
def _sha256_text(text: object) -> object:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


@cython.ccall
def direct_addr_stage_bundle_dir(
    request: DirectAddrStageBundleInput,
    *,
    root: Path = Path(".codex_automation/stage_debug"),
) -> Path:
    """Return the deterministic bundle directory for one function/family."""
    binary_text = str(request.binary_path.resolve() if isinstance(request.binary_path, Path) else "unknown-binary")
    binary_key = hashlib.sha256(binary_text.encode("utf-8", errors="ignore")).hexdigest()[:12]
    family_key = hashlib.sha256(request.family_label.encode("utf-8", errors="ignore")).hexdigest()[:12]
    binary_name = _safe_component(Path(binary_text).name if binary_text != "unknown-binary" else binary_text)
    function_name = _safe_component(request.function_name)
    return root / f"{binary_name}_{binary_key}" / f"{request.function_addr:#x}_{function_name}_{family_key}"


@cython.ccall
def write_direct_addr_stage_bundle(
    request: DirectAddrStageBundleInput,
    *,
    root: Path = Path(".codex_automation/stage_debug"),
) -> DirectAddrStageBundleResult:
    """Write or reuse the deterministic repeated-family evidence bundle."""
    name: object
    text: object
    bundle_dir = direct_addr_stage_bundle_dir(request, root=root)
    manifest_path = bundle_dir / "manifest.json"
    if manifest_path.exists():
        return DirectAddrStageBundleResult(path=bundle_dir, reused=True)

    bundle_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "raw_asm.txt": _stable_text(request.raw_asm),
        "cod_window.txt": _stable_text(request.cod_window),
        "raw_codegen.c": _stable_text(request.raw_codegen),
        "post_callsite.c": _stable_text(request.post_callsite),
        "post_stack_lowering.c": _stable_text(request.post_stack_lowering),
        "final_stdout.txt": _stable_text(request.final_stdout),
        "final_stderr.txt": _stable_text(request.final_stderr),
    }
    manifest_files: dict[str, dict[str, object]] = {}
    for name, text in files.items():
        path = bundle_dir / name
        path.write_text(text, encoding="utf-8")
        manifest_files[name] = {
            "bytes": len(text.encode("utf-8", errors="ignore")),
            "sha256": _sha256_text(text),
            "unavailable": text == _UNAVAILABLE,
        }

    manifest = {
        "binary_path": str(request.binary_path) if isinstance(request.binary_path, Path) else None,
        "function_addr": request.function_addr,
        "function_name": request.function_name,
        "family_label": request.family_label,
        "files": manifest_files,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return DirectAddrStageBundleResult(path=bundle_dir, reused=False)
