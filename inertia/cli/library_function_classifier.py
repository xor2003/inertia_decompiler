# cython: language_level=3, infer_types=True
"""Classify library-like function names for reporting and filtering policy.

Layer: CLI/fallback/reporting.
Responsibility: classify optional library labels for reporting without proving function semantics.
"""

from __future__ import annotations
import typing
import cython

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from inertia.cli.lst_extract import LSTMetadata
import dataclasses


class LibraryFunctionClass(Enum):
    """Reporting-only classification for labels that may be hidden as library code."""

    USER_SOURCE_PROC = "user_source_proc"
    USER_UNCLASSIFIED = "user_unclassified"
    IMPORT_STUB = "import_stub"
    SIGNATURE_MATCH = "signature_match"
    RUNTIME_PREFIX = "runtime_prefix"
    RUNTIME_KNOWN_NAME = "runtime_known_name"
    NON_SOURCE_SIDECAR_LABEL = "non_source_sidecar_label"


_LIBRARY_CLASSES = frozenset(
    {
        LibraryFunctionClass.IMPORT_STUB,
        LibraryFunctionClass.SIGNATURE_MATCH,
        LibraryFunctionClass.RUNTIME_PREFIX,
        LibraryFunctionClass.RUNTIME_KNOWN_NAME,
        LibraryFunctionClass.NON_SOURCE_SIDECAR_LABEL,
    }
)


@dataclasses.dataclass(frozen=True)
class LibraryLabelFilterResult:
    """Filtered labels plus per-label reporting decisions."""

    labels: object
    decisions: object
    skipped_by_class: Mapping[LibraryFunctionClass, cython.longlong]

    @property
    def skipped_count(self) -> cython.longlong:
        """Return the number of labels hidden by library-filter policy."""
        return sum(self.skipped_by_class.values())


_GENERIC_C_RUNTIME_NAMES = frozenset(
    {
        "abs",
        "atoi",
        "atol",
        "clock",
        "exit",
        "fclose",
        "fflush",
        "fopen",
        "fprintf",
        "fread",
        "free",
        "fwrite",
        "getc",
        "getch",
        "getche",
        "getenv",
        "inp",
        "labs",
        "lseek",
        "malloc",
        "memcmp",
        "memcpy",
        "memset",
        "outp",
        "printf",
        "putc",
        "puts",
        "rand",
        "realloc",
        "scanf",
        "sprintf",
        "srand",
        "strcat",
        "strcmp",
        "strcpy",
        "strlen",
        "strncat",
        "strncmp",
        "strncpy",
        "time",
        "toupper",
        "write",
    }
)

_MS_C_RUNTIME_NAMES = frozenset(
    {
        "amsg_exit",
        "anldiv",
        "anlmul",
        "anchkstk",
        "astart",
        "catox",
        "cexit",
        "c_exit",
        "cintdiv",
        "cinit",
        "clearscreen",
        "clock",
        "ctermsub",
        "dataseg",
        "displaycursor",
        "dos_getdate",
        "dos_gettime",
        "dosret0",
        "dosretax",
        "dosreturn",
        "dtoxtime",
        "ff_msgbanner",
        "findlast",
        "flsbuf",
        "flushall",
        "fptrap",
        "ftime",
        "getbkcolor",
        "getbuf",
        "gettextcolor",
        "gettextcursor",
        "gettextposition",
        "getvideoconfig",
        "growseg",
        "grstatus",
        "incseg",
        "inittime",
        "isindst",
        "maperror",
        "myalloc",
        "nfree",
        "nmalloc",
        "nmsg_text",
        "nmsg_write",
        "nullcheck",
        "outmem",
        "output",
        "outtext",
        "searchseg",
        "setargv",
        "setbkcolor",
        "setenvp",
        "settextcolor",
        "settextcursor",
        "settextposition",
        "settextrows",
        "setvideomode",
        "setvideomoderows",
        "stackavail",
        "tzset",
    }
)

_RUNTIME_PREFIXES = (
    "__",
    "_ci",
    "_nci",
    "$",
    "b$",
)

_MS_HELPER_PREFIXES = (
    "an",
    "b$",
    "ff_",
    "nmsg_",
)


@cython.ccall
def normalize_library_symbol_name(name: object) -> object:
    """Normalize a symbol name for library-label comparison."""
    return (name or "").strip().lstrip("_").lower()


def classify_library_function_name(name: object) -> LibraryFunctionClass:
    """Classify one function name using reporting-only library heuristics."""
    raw = (name or "").strip()
    lowered = raw.lower()
    if (
        lowered.startswith(("sym.imp.", "fcn.imp.", "import_", "imp.")) or ".imp." in lowered
    ):
        return LibraryFunctionClass.IMPORT_STUB
    normalized = normalize_library_symbol_name(raw)
    if not normalized:
        return LibraryFunctionClass.USER_UNCLASSIFIED
    if normalized in _GENERIC_C_RUNTIME_NAMES or normalized in _MS_C_RUNTIME_NAMES:
        return LibraryFunctionClass.RUNTIME_KNOWN_NAME
    if lowered.startswith("_") and len(lowered) > 1 and lowered[1].isalpha():
        return LibraryFunctionClass.RUNTIME_PREFIX
    if any(lowered.startswith(prefix) for prefix in iter(_RUNTIME_PREFIXES)):
        return LibraryFunctionClass.RUNTIME_PREFIX
    if any(normalized.startswith(prefix) for prefix in iter(_MS_HELPER_PREFIXES)):
        return LibraryFunctionClass.RUNTIME_PREFIX
    return LibraryFunctionClass.USER_UNCLASSIFIED


@cython.ccall
def is_library_like_function_name(name: object) -> cython.bint:
    """Return whether a name belongs to a library-like reporting class."""
    return classify_library_function_name(name) in _LIBRARY_CLASSES


@cython.ccall
def classify_sidecar_function_label(
    addr: cython.longlong,
    name: object,
    metadata: object,
) -> LibraryFunctionClass:
    """Classify one sidecar label without using it as semantic proof."""
    if metadata is None:
        return classify_library_function_name(name)

    proc_addrs = metadata.function_entry_addrs or metadata.cod_proc_kinds.keys()
    if addr in proc_addrs:
        return LibraryFunctionClass.USER_SOURCE_PROC
    if addr in metadata.signature_code_addrs:
        return LibraryFunctionClass.SIGNATURE_MATCH
    if proc_addrs and "cod_listing" in metadata.source_format:
        return LibraryFunctionClass.NON_SOURCE_SIDECAR_LABEL
    return classify_library_function_name(name)


@cython.ccall
def filter_code_labels_for_library_policy(
    metadata: LSTMetadata | None,
    labels: Mapping[cython.longlong, str],
) -> LibraryLabelFilterResult:
    """Filter sidecar labels using reporting-only library policy."""
    addr: object
    name: object
    kept: dict[cython.longlong, str] = {}
    decisions: dict[cython.longlong, LibraryFunctionClass] = {}
    skipped: Counter[LibraryFunctionClass] = Counter()
    for addr, name in labels.items():
        decision = classify_sidecar_function_label(int(addr), str(name), metadata)
        decisions[int(addr)] = decision
        if decision in _LIBRARY_CLASSES:
            skipped[decision] += 1
            continue
        kept[int(addr)] = str(name)
    return LibraryLabelFilterResult(
        labels=kept,
        decisions=decisions,
        skipped_by_class=dict(skipped),
    )
