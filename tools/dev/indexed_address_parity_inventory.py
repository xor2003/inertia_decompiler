#!/usr/bin/env python3
"""Report sidecar-free indexed-address collector migration parity.

Layer: Tooling/gates.
Responsibility: isolate one DOS executable from local sidecars, run the
canonical non-library function discovery path, and serialize the typed
read-only IR/Alias-versus-legacy inventory. This tool does not select semantic
evidence or change decompilation output.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
import tempfile
from collections.abc import Iterator, Sequence
from dataclasses import asdict
from enum import Enum
from pathlib import Path
from typing import Protocol, cast

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inertia.cli.cli_function_discovery import _recover_fast_exe_catalog  # noqa: E402
from inertia.cli.project_loading import _build_project  # noqa: E402
from inertia.lowering.indexed_address_parity_inventory import (  # noqa: E402
    build_indexed_address_parity_inventory_8616,
)
from inertia.lowering.indexed_address_parity_inventory_contracts import (  # noqa: E402
    IndexedAddressParityInventory8616,
)

type JsonValue = bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"] | None


class _Arguments(Protocol):
    """Typed command-line arguments owned by this diagnostic."""

    binary: Path
    timeout: int
    window: int
    max_functions: int
    report_out: Path | None
    require_exact: bool


class _FunctionBoundary(Protocol):
    """Minimal dynamic angr function surface returned by discovery."""

    addr: object


def _parse_int(value: str) -> int:
    """Parse one decimal or prefixed integer command-line value."""
    return int(value, 0)


def _parser() -> argparse.ArgumentParser:
    """Build the deterministic inventory command-line contract."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--window", type=_parse_int, default=0x300)
    parser.add_argument("--max-functions", type=int, default=0)
    parser.add_argument("--report-out", type=Path)
    parser.add_argument(
        "--require-exact",
        action="store_true",
        help="return failure while any collector identity remains divergent",
    )
    return parser


def _json_value(value: object) -> JsonValue:
    """Convert dataclass output to deterministic JSON primitives."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Enum):
        return _json_value(value.value)
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    raise TypeError(f"unsupported inventory JSON value: {type(value).__name__}")


def inventory_payload_8616(inventory: IndexedAddressParityInventory8616) -> dict[str, JsonValue]:
    """Return the stable JSON representation of one closed inventory."""
    if not inventory.closed:
        raise ValueError("cannot serialize an incomplete indexed-address inventory")
    payload = _json_value(asdict(inventory))
    if not isinstance(payload, dict):
        raise TypeError("indexed-address inventory did not serialize to an object")
    payload["closed"] = True
    payload["exact"] = inventory.exact
    return payload


@contextlib.contextmanager
def _sidecar_free_binary(binary: Path) -> Iterator[Path]:
    """Return a temporary executable path with no neighboring helper files."""
    with tempfile.TemporaryDirectory(prefix="indexed-address-parity-") as directory:
        isolated = Path(directory) / binary.name
        isolated.write_bytes(binary.read_bytes())
        yield isolated


def build_sidecar_free_inventory_8616(
    binary: Path,
    *,
    timeout: int,
    window: int,
    max_functions: int,
) -> IndexedAddressParityInventory8616:
    """Discover non-library functions and build their read-only parity inventory."""
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if window <= 0:
        raise ValueError("window must be positive")
    limit = max_functions if max_functions > 0 else None
    with _sidecar_free_binary(binary) as isolated:
        project = _build_project(
            isolated,
            force_blob=False,
            base_addr=0x10000,
            entry_point=0x1000,
        )
        recovered = _recover_fast_exe_catalog(
            project,
            timeout=timeout,
            window=window,
            low_memory=False,
            limit=limit,
        )
        functions = tuple(
            function
            for _cfg, function in recovered
            if isinstance(cast(_FunctionBoundary, function).addr, int)
        )
        return build_indexed_address_parity_inventory_8616(project, functions)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the sidecar-free inventory and emit JSON only on stdout."""
    args = cast(_Arguments, _parser().parse_args(argv))
    with contextlib.redirect_stdout(sys.stderr):
        inventory = build_sidecar_free_inventory_8616(
            args.binary,
            timeout=args.timeout,
            window=args.window,
            max_functions=args.max_functions,
        )
    rendered = json.dumps(inventory_payload_8616(inventory), indent=2, sort_keys=True) + "\n"
    if args.report_out is not None:
        args.report_out.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    if args.require_exact and not inventory.exact:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
