"""Shared ``--entry-esp-range`` CLI plumbing for the staged flat32 drivers.

Layer: dosunit validation orchestration.
Responsibility: own the single argument surface through which both PE32
drivers declare a :class:`Flat32ProofDomain` premise — identical option
spelling, identical parsing and validation, identical mode and loader
restrictions, and one documented namespace boundary for programmatic callers.
The premise is never defaulted and never silently ignored: modes without a
whole-region call-composition path reject the option, and the feature is
PE32-to-PE32 only.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from tools.dosunit.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.ordered_io_environment import (
    ORDERED_IO_MODEL_IDENTITY,
    OrderedIoContract,
    parse_ordered_io_identity,
)
from tools.dosunit.proof_contracts import Architecture

# Modes whose retry path can thread a declared root-entry esp interval into
# checked direct-call composition. ``leaf`` has no composition path, so a
# declared premise there could only be ignored — it is rejected instead.
WHOLE_REGION_MODES: frozenset[str] = frozenset({"region", "auto", "matched-cfg"})


def parse_entry_esp_range(value: str) -> Flat32ProofDomain:
    """Parse ``MIN:MAX`` base-0 integers into a validated inclusive domain.

    ``Flat32ProofDomain`` validation rejects non-integer, empty and
    out-of-uint32 bounds; this parser additionally rejects every shape that is
    not exactly two integer fields.
    """
    parts = value.split(":")
    if len(parts) != 2:
        raise ValueError("entry-esp-range requires exactly MIN:MAX")
    try:
        bounds = int(parts[0], 0), int(parts[1], 0)
    except ValueError as error:
        raise ValueError(f"entry-esp-range bounds must be base-0 integers: {error}") from error
    return Flat32ProofDomain(*bounds)


def add_entry_esp_range_argument(parser: argparse.ArgumentParser) -> None:
    """Install the shared option so both drivers accept identical syntax."""
    parser.add_argument(
        "--entry-esp-range",
        type=parse_entry_esp_range,
        default=None,
        metavar="MIN:MAX",
        help=(
            "caller-declared inclusive unsigned interval for the top-level entry "
            "esp input of whole-region call proofs; verdicts relying on the "
            "premise are published conditional with the interval serialized"
        ),
    )


def entry_domain_from_args(args: argparse.Namespace) -> Flat32ProofDomain | None:
    """Return the declared domain, or None when the option is absent.

    ``argparse.Namespace`` is a third-party stdlib boundary: drivers also accept
    programmatic namespaces built before this option existed, so the attribute
    may legitimately be missing — ``getattr`` with a default is the documented
    seam. A string value is parsed and validated exactly like CLI input; any
    other wrong type fails closed instead of guessing a premise.
    """
    # Dynamic third-party boundary: older argparse namespaces omit this option.
    value = getattr(args, "entry_esp_range", None)
    if value is None:
        return None
    if isinstance(value, str):
        value = parse_entry_esp_range(value)
    if not isinstance(value, Flat32ProofDomain):
        raise ValueError("entry_esp_range must be produced by add_entry_esp_range_argument")
    return value


def check_entry_domain_mode(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Reject modes with no call-composition path rather than drop the premise."""
    if entry_domain_from_args(args) is not None and args.mode not in WHOLE_REGION_MODES:
        parser.error("--entry-esp-range requires a whole-region mode (region, auto or matched-cfg)")


def require_pe32_pair(oracle_exe: Path, candidate_exe: Path) -> None:
    """Require the DOS header, PE signature, i386 machine and PE32 magic.

    Read only fixed-size headers; the untrusted PE offset never determines an
    allocation size. CLE remains responsible for validating the full image.
    """
    for path in (oracle_exe, candidate_exe):
        with path.open("rb") as stream:
            dos_header = stream.read(64)
            valid_dos = len(dos_header) == 64 and dos_header[:2] == b"MZ"
            pe_header = b""
            if valid_dos:
                pe_offset = int.from_bytes(dos_header[0x3c:0x40], "little")
                if pe_offset >= 64:
                    stream.seek(pe_offset)
                    pe_header = stream.read(26)
            valid_pe = (
                len(pe_header) == 26
                and pe_header[:4] == b"PE\x00\x00"
                and int.from_bytes(pe_header[4:6], "little") == 0x14c
                and int.from_bytes(pe_header[20:22], "little") >= 2
                and int.from_bytes(pe_header[24:26], "little") == 0x10b
            )
            if not valid_pe:
                raise ValueError("--entry-esp-range currently requires PE32 on both sides")


def require_supported_entry_domain(args: argparse.Namespace) -> Flat32ProofDomain | None:
    """Return the declared domain after enforcing its usage restrictions.

    A declared premise on a mode without a call-composition path, or on a
    non-PE32 input pair, fails closed instead of being silently ignored.  This
    is the programmatic-caller counterpart of ``check_entry_domain_mode``.
    """
    domain = entry_domain_from_args(args)
    if domain is None:
        return None
    if args.mode not in WHOLE_REGION_MODES:
        raise ValueError("--entry-esp-range requires a whole-region mode (region, auto or matched-cfg)")
    require_pe32_pair(args.oracle_exe, args.candidate_exe)
    return domain


def add_ordered_io_argument(parser: argparse.ArgumentParser) -> None:
    """Install the shared ordered-I/O binding option on both PE32 drivers."""
    parser.add_argument(
        "--ordered-io-environment",
        default=None,
        metavar="MODEL_ID",
        help=(
            "bind the declared ordered scalar port-I/O environment contract "
            f"(model identity {ORDERED_IO_MODEL_IDENTITY}); covered decoded "
            "IN/OUT events are admitted under an explicit caller premise and "
            "every verdict consuming it is published conditional, never passed"
        ),
    )


def ordered_io_from_args(args: argparse.Namespace) -> OrderedIoContract | None:
    """Return the declared ordered-I/O contract, or None when unbound.

    ``argparse.Namespace`` is a third-party stdlib boundary: programmatic
    namespaces may legitimately omit the option, so the attribute is read
    with a documented ``getattr`` default.  A string is bound by exact model
    identity; an ``OrderedIoContract`` is bound by architecture.  Any other
    shape — wrong identity, wrong lane, malformed value — fails closed.
    """
    # Dynamic third-party boundary: programmatic namespaces may omit it.
    value = getattr(args, "ordered_io_environment", None)
    if value is None:
        return None
    try:
        if isinstance(value, OrderedIoContract):
            return value.validate_for(Architecture.FLAT32)
        return parse_ordered_io_identity(value, Architecture.FLAT32)
    except ValueError as error:
        raise ValueError(f"unsupported ordered-io environment binding: {error}") from error


def require_supported_io_domain(args: argparse.Namespace) -> OrderedIoContract | None:
    """Return the declared ordered-I/O contract after usage restrictions.

    The binding requires a whole-region mode — it admits covered scalar port
    events through the checked environment gate and call composition — and a
    PE32 pair on both sides, matching the recursive/entry-domain premises.
    It also refuses to combine with the recursive joint request, whose
    premise discipline is independent and must not silently share a scope.
    """
    contract = ordered_io_from_args(args)
    if contract is None:
        return None
    if args.mode not in WHOLE_REGION_MODES:
        raise ValueError(
            "--ordered-io-environment requires a whole-region mode (region, auto or matched-cfg)"
        )
    # Dynamic third-party argparse boundary: legacy namespaces omit this optional flag.
    if getattr(args, "recursive", False):
        raise ValueError(
            "--ordered-io-environment cannot combine with --recursive; the recursive "
            "joint proof has an independent premise scope"
        )
    require_pe32_pair(args.oracle_exe, args.candidate_exe)
    return contract


def check_ordered_io_mode(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    """Reject ordered-I/O bindings a mode or request shape cannot honor."""
    if ordered_io_from_args(args) is None:
        return
    if args.mode not in WHOLE_REGION_MODES:
        parser.error("--ordered-io-environment requires a whole-region mode (region, auto or matched-cfg)")
    # Dynamic third-party argparse boundary: legacy namespaces omit this optional flag.
    if getattr(args, "recursive", False):
        parser.error("--ordered-io-environment cannot combine with --recursive")
