"""Explicit compiler identities and probe-verified toolchain settings.

Layer: Tooling/gates.
Responsibility: bind a manifest-declared compiler profile to typed toolchain
settings consumed by the shared compile/decompile/recompile/execute owner.
Commands for compilers other than the built-in MS C 6 lane come only from the
repo-owned executable profile registry (examples/compiler_coverage/
toolchains.json), which carries the exact commands reconciled from private
probe evidence plus SHA-256 identity pins for every tool and library. Records
that fail schema, probe-evidence, or tool-hash validation refuse rather than
silently substituting MS C 6 commands.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import re
import signal
import string
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from tools.compiler_toolchain.compiler_coverage_manifest import CoverageManifest
from tools.compiler_toolchain.msc6_memory_model import MSCMemoryModel
from tools.dev.process_metrics import process_tree_pids

MSC6_AX_PROFILE_ID: str = "msc6_ax"
MSC6_AX_TOOLCHAIN_ROOT: Path = Path("/home/xor/inertia_player/dos_compilers/Microsoft C v6ax")
DEFAULT_PROFILE_REGISTRY: Path = (
    Path(__file__).resolve().parents[2] / "examples" / "compiler_coverage" / "toolchains.json"
)


class CompilerIdentity(StrEnum):
    """The compiler families this adapter can route to a DOS toolchain."""

    MSC6_AX = "msc6_ax"
    MSC51 = "msc51"
    BORLAND31 = "borland31"


class CompileBackend(StrEnum):
    """The DOS runner selected for compiler/linker stages or program execution."""

    KVIKDOS = "kvikdos"
    DOSBOX = "dosbox"


class KvikdosDPMIMode(StrEnum):
    """Explicit host DPMI policy, independent of the DOS program's flags."""

    AUTO = "auto"
    OFF = "off"


MANIFEST_COMPILER_NAMES: dict[CompilerIdentity, str] = {
    CompilerIdentity.MSC6_AX: "Microsoft C v6ax",
    CompilerIdentity.MSC51: "Microsoft C v5.1",
    CompilerIdentity.BORLAND31: "Borland C++ 3.1",
}
_MANIFEST_IDENTITIES = {name: identity for identity, name in MANIFEST_COMPILER_NAMES.items()}

_ARGUMENT_FIELDS = frozenset({"source", "obj", "exe", "map", "cod", "extra_objs", "cod_option"})
_EXTRA_OBJECT_FIELD = "extra_obj"
_ARTIFACT_NAME = re.compile(r"^[A-Za-z0-9_.$-]+$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORMATTER = string.Formatter()

_REGISTRY_PROFILE_FIELDS = frozenset({
    "id", "probe_id", "aliases", "compiler", "memory_model", "declared_flags",
    "compile_backend", "run_backend", "toolchain_root",
    "tools", "libraries", "dependency_group",
    "compiler_path_dos", "linker_path_dos",
    "compiler_environment", "linker_environment",
    "compile_arguments", "cod_argument", "link_argument", "extra_object_format",
})
_REGISTRY_TOOL_KINDS = frozenset({"compiler", "linker"})
_REGISTRY_OPTIONAL_PROFILE_FIELDS = frozenset({"kvikdos_dpmi_mode"})
_REGISTRY_FIELDS = frozenset({"schema", "profiles", "runners", "probe_evidence", "dependencies"})
_TOOL_FIELDS = frozenset({"dos_path", "sha256"})
_PROBE_PRODUCT_MARKERS: dict[CompilerIdentity, str] = {
    CompilerIdentity.MSC51: "Microsoft C 5.1",
    CompilerIdentity.BORLAND31: "Borland C++ 3.1",
}

_DOSBOX_CONF: str = """\
# Deterministic DOSBox 0.74-3 configuration for compiler toolchain stages.
# Pinned so mutable ~/.dosbox settings cannot change compiler behavior.
[sdl]
autolock=false
[dosbox]
machine=svga_s3
memsize=16
[cpu]
core=auto
cputype=auto
cycles=auto
[autoexec]
"""


class UnsupportedCompilerProfile(ValueError):
    """A declared compiler identity/settings pair lacks verified toolchain evidence."""


def compiler_identity(compiler: str) -> CompilerIdentity:
    """Map a manifest compiler name to its typed identity; unknown names refuse."""
    identity = _MANIFEST_IDENTITIES.get(compiler)
    if identity is None:
        supported = ", ".join(sorted(_MANIFEST_IDENTITIES))
        raise UnsupportedCompilerProfile(f"Unsupported compiler {compiler!r}; supported: {supported}")
    return identity


def _template_fields(template: str) -> frozenset[str]:
    """Collect substitution names, rejecting malformed brace structure."""
    try:
        parsed = list(_FORMATTER.parse(template))
    except ValueError as error:
        raise ValueError(f"Malformed toolchain template {template!r}: {error}") from error
    return frozenset(field for _text, field, _spec, _conv in parsed if field is not None)


def _require_known_fields(template: str) -> None:
    """Reject template substitutions outside the artifact vocabulary."""
    unknown = _template_fields(template) - _ARGUMENT_FIELDS
    if unknown:
        raise ValueError(f"Toolchain template uses unsupported fields {sorted(unknown)}: {template!r}")


def _require_field(templates: tuple[str, ...], name: str) -> None:
    """Require a substitution the command renderer must be able to bind."""
    if not any(name in _template_fields(template) for template in templates):
        raise ValueError(f"Toolchain template must bind {{{name}}}")


def _require_dos_program(program: str) -> None:
    """Require an e:-mounted DOS path so the host file can be recovered."""
    _host_program_path(Path("/"), program)


def _host_program_path(toolchain_root: Path, program: str) -> Path:
    """Map an e:-mounted DOS program path back to its host toolchain file."""
    if program[:3].upper() != "E:\\":
        raise ValueError(f"Toolchain programs must live under the e: mount: {program!r}")
    parts = program[3:].split("\\")
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError(f"Toolchain program path is not a plain relative tail: {program!r}")
    return toolchain_root.joinpath(*parts)


def _require_artifact_name(name: str) -> None:
    """Reject path or template injection through artifact names."""
    if not _ARTIFACT_NAME.fullmatch(name):
        raise ValueError(f"Artifact names must be plain DOS filenames: {name!r}")


def _require_environment_name(name: str) -> None:
    """Require a well-formed DOS environment variable name."""
    if not _ENVIRONMENT_NAME.fullmatch(name):
        raise ValueError(f"Invalid DOS environment name: {name!r}")


def _file_sha256(path: Path) -> str:
    """Return the SHA-256 of one host file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class ToolIdentity:
    """One probed DOS tool or library pinned by DOS path and SHA-256.

    ``dos_path`` is the e:-mounted name embedded in commands and also the
    source of the host path, so a verified hash can never describe a file
    other than the one the profile invokes. ``sha256`` is required for
    registry profiles; the built-in MS C 6 lane carries no pin.
    """

    dos_path: str
    sha256: str | None

    def __post_init__(self) -> None:
        """Reject identities that cannot resolve to the mounted toolchain."""
        _require_dos_program(self.dos_path)
        if self.sha256 is not None and not _SHA256.fullmatch(self.sha256):
            raise ValueError(f"Tool sha256 must be 64 lowercase hex digits: {self.sha256!r}")

    def host_path(self, toolchain_root: Path) -> Path:
        """Return the host file backing this e:-mounted DOS artifact."""
        return _host_program_path(toolchain_root, self.dos_path)

    def to_dict(self) -> dict[str, object]:
        """Return the recorded identity, including the verification pin."""
        return {"dos_path": self.dos_path, "sha256": self.sha256}


@dataclass(frozen=True)
class CompilerToolchain:
    """Verified compiler/linker settings for one compiler and memory model.

    ``compile_arguments``/``link_argument``/``cod_argument``/
    ``extra_object_format`` carry ``str.format`` placeholders drawn from
    {source, obj, exe, map, cod, extra_objs, cod_option, extra_obj}; literal
    DOS paths (``c:\\``/``e:\\``) are embedded by the profile, never guessed.
    ``compile_backend`` selects the emulator hosting compiler/linker stages;
    linked 16-bit output always executes under ``run_backend``.
    ``kvikdos_dpmi_mode`` selects a measured kvikdos host policy for both
    stages and output execution; AUTO preserves the runner's default argv.
    """

    profile_id: str
    identity: CompilerIdentity
    memory_model: MSCMemoryModel
    declared_flags: tuple[str, ...]
    compile_backend: CompileBackend
    run_backend: CompileBackend
    toolchain_root: Path
    compiler_tool: ToolIdentity
    linker_tool: ToolIdentity
    libraries: tuple[ToolIdentity, ...]
    compiler_path_dos: tuple[str, ...]
    linker_path_dos: tuple[str, ...]
    compiler_environment: tuple[tuple[str, str], ...]
    linker_environment: tuple[tuple[str, str], ...]
    compile_arguments: tuple[str, ...]
    cod_argument: str | None
    link_argument: str
    extra_object_format: str
    probe_id: str | None = None
    aliases: tuple[str, ...] = ()
    dependency_group: str | None = None
    dependency_tools: tuple[ToolIdentity, ...] = ()
    dosbox_executable: Path | None = None
    dosbox_sha256: str | None = None
    dosbox_host_environment: tuple[tuple[str, str], ...] = ()
    kvikdos_executable: Path | None = None
    kvikdos_sha256: str | None = None
    kvikdos_dpmi_mode: KvikdosDPMIMode = KvikdosDPMIMode.AUTO

    def __post_init__(self) -> None:
        """Reject structural settings the shared runner cannot honor."""
        if not self.toolchain_root.is_absolute():
            raise ValueError(f"toolchain_root must be absolute: {self.toolchain_root}")
        _require_dos_program(self.compiler_program)
        _require_dos_program(self.linker_program)
        self._validate_backends()
        self._validate_templates()
        for name, _value in (
            *self.compiler_environment, *self.linker_environment, *self.dosbox_host_environment
        ):
            _require_environment_name(name)
        if self.profile_id in self.aliases:
            raise ValueError("profile aliases must not repeat the canonical id")

    @property
    def uses_dosbox(self) -> bool:
        """Return whether either selected backend requires the pinned DOSBox runner."""
        return (
            self.compile_backend is CompileBackend.DOSBOX
            or self.run_backend is CompileBackend.DOSBOX
        )

    def _validate_backends(self) -> None:
        """Require pinned runners for each explicitly selected backend."""
        if not isinstance(self.kvikdos_dpmi_mode, KvikdosDPMIMode):
            raise ValueError("kvikdos_dpmi_mode must be a typed KvikdosDPMIMode")
        if self.uses_dosbox and self.dosbox_executable is None:
            raise ValueError("DOSBox backends must declare dosbox_executable")
        if self.uses_dosbox and self.dosbox_sha256 is None:
            raise ValueError("DOSBox backends must declare a pinned dosbox_sha256")
        if self.dosbox_executable is not None and not self.dosbox_executable.is_absolute():
            raise ValueError(f"dosbox_executable must be absolute: {self.dosbox_executable}")
        if self.dosbox_sha256 is not None and not _SHA256.fullmatch(self.dosbox_sha256):
            raise ValueError(f"dosbox_sha256 must be 64 lowercase hex digits: {self.dosbox_sha256}")
        if self.kvikdos_sha256 is not None and not _SHA256.fullmatch(self.kvikdos_sha256):
            raise ValueError(f"kvikdos_sha256 must be 64 lowercase hex digits: {self.kvikdos_sha256}")
        if self.kvikdos_executable is not None and not self.kvikdos_executable.is_absolute():
            raise ValueError(f"kvikdos_executable must be absolute: {self.kvikdos_executable}")

    def _validate_templates(self) -> None:
        """Require every template placeholder the renderers must bind."""
        if not self.compile_arguments:
            raise ValueError("compile_arguments must not be empty")
        for template in (*self.compile_arguments, self.link_argument):
            _require_known_fields(template)
        _require_field(self.compile_arguments, "source")
        _require_field(self.compile_arguments, "obj")
        _require_field((self.link_argument,), "obj")
        _require_field((self.link_argument,), "exe")
        if self.cod_argument is not None:
            _require_known_fields(self.cod_argument)
            _require_field((self.cod_argument,), "cod")
        if _template_fields(self.extra_object_format) != frozenset({_EXTRA_OBJECT_FIELD}):
            raise ValueError("extra_object_format must bind exactly {extra_obj}")

    @property
    def compiler_program(self) -> str:
        """Return the e:-mounted compiler executable path."""
        return self.compiler_tool.dos_path

    @property
    def linker_program(self) -> str:
        """Return the e:-mounted linker executable path."""
        return self.linker_tool.dos_path

    @property
    def compiler_host_path(self) -> Path:
        """Return the host path of the e:-mounted compiler executable."""
        return self.compiler_tool.host_path(self.toolchain_root)

    def _fields(self, **overrides: str) -> dict[str, str]:
        """Bind every allowed template name so missing values stay explicit."""
        fields = dict.fromkeys(_ARGUMENT_FIELDS, "")
        fields.update(overrides)
        return fields

    def compile_argv(
        self, *, source_name: str, obj_name: str, cod_name: str | None = None,
    ) -> list[str]:
        """Render the verified compile arguments for plain DOS artifact names."""
        _require_artifact_name(source_name)
        _require_artifact_name(obj_name)
        if cod_name is not None:
            _require_artifact_name(cod_name)
        cod_option = ""
        if cod_name is not None and self.cod_argument is not None:
            cod_option = self.cod_argument.format(**self._fields(cod=cod_name))
        fields = self._fields(
            source=source_name, obj=obj_name, cod=cod_name or "", cod_option=cod_option,
        )
        return [arg for arg in (item.format(**fields) for item in self.compile_arguments) if arg]

    def link_argv(
        self, *, obj_name: str, exe_name: str, map_name: str,
        extra_obj_names: tuple[str, ...] = (),
    ) -> list[str]:
        """Render the verified link argument, including runner-built objects."""
        for name in (obj_name, exe_name, map_name, *extra_obj_names):
            _require_artifact_name(name)
        extra_objs = "".join(
            self.extra_object_format.format(**{_EXTRA_OBJECT_FIELD: name}) for name in extra_obj_names
        )
        fields = self._fields(obj=obj_name, exe=exe_name, map=map_name, extra_objs=extra_objs)
        return [self.link_argument.format(**fields)]

    def compile_dos_command(
        self, *, source_name: str, obj_name: str, cod_name: str | None = None,
    ) -> str:
        """Render the complete DOS compile line for a DOSBox batch."""
        return " ".join(
            [self.compiler_program, *self.compile_argv(
                source_name=source_name, obj_name=obj_name, cod_name=cod_name)]
        )

    def link_dos_command(
        self, *, obj_name: str, exe_name: str, map_name: str,
        extra_obj_names: tuple[str, ...] = (),
    ) -> str:
        """Render the complete DOS link line for a DOSBox batch."""
        return " ".join(
            [self.linker_program, *self.link_argv(
                obj_name=obj_name, exe_name=exe_name, map_name=map_name,
                extra_obj_names=extra_obj_names)]
        )

    def dosbox_conf(self) -> str:
        """Return the pinned private DOSBox config for deterministic stages."""
        return _DOSBOX_CONF

    def dosbox_batch(
        self,
        *,
        tag: str,
        command_line: str,
        out_name: str,
        ok_name: str,
        fail_name: str,
        path_dos: tuple[str, ...],
        environment: tuple[tuple[str, str], ...],
    ) -> str:
        """Render a DOS batch running one tool with ERRORLEVEL markers.

        DOSBox's own exit code only reports the launcher, and it eagerly
        creates redirect targets for skipped echoes, so success requires the
        OK marker to carry exact content while the FAIL marker stays empty.
        """
        for name in (out_name, ok_name, fail_name):
            _require_artifact_name(name)
        lines = ["@echo off"]
        if path_dos:
            lines.append(f"set PATH={';'.join(path_dos)}")
        lines.extend(f"set {name}={value}" for name, value in environment)
        lines.extend([
            f"{command_line} > c:\\{out_name}",
            f"if errorlevel 1 echo {tag}_FAIL > c:\\{fail_name}",
            f"if not errorlevel 1 echo {tag}_OK > c:\\{ok_name}",
        ])
        return "\r\n".join(lines) + "\r\n"

    @staticmethod
    def dosbox_ok_marker(tag: str) -> str:
        """Return the exact content a successful stage marker must contain."""
        return f"{tag}_OK"

    def pinned_tools(self) -> tuple[ToolIdentity, ...]:
        """Return every hash-pinned tool, library, or spawned child the profile needs."""
        return tuple(
            tool
            for tool in (
                self.compiler_tool, self.linker_tool, *self.libraries, *self.dependency_tools,
            )
            if tool.sha256 is not None
        )

    def verify_tools(self) -> None:
        """Refuse the profile when a pinned tool or library drifts.

        SHA-256 identity pins bind the executable profile to the binaries the
        probe actually measured; a missing file or hash mismatch means the
        toolchain is stale or mislabelled, not a valid substitute.
        """
        for tool in self.pinned_tools():
            expected = tool.sha256
            if expected is None:
                continue
            host_path = tool.host_path(self.toolchain_root)
            if not host_path.is_file():
                raise UnsupportedCompilerProfile(
                    f"{self.profile_id}: pinned tool missing: {host_path}"
                )
            actual = _file_sha256(host_path)
            if actual != expected:
                raise UnsupportedCompilerProfile(
                    f"{self.profile_id}: {tool.dos_path} sha256 mismatch "
                    f"(profile {expected[:12]}…, host {actual[:12]}…); "
                    "toolchain drifted from the verified probe binaries"
                )

    def to_dict(self) -> dict[str, object]:
        """Return a stable JSON form of the complete resolved toolchain."""
        return {
            "profile_id": self.profile_id,
            "compiler": MANIFEST_COMPILER_NAMES[self.identity],
            "identity": self.identity.value,
            "memory_model": self.memory_model.value,
            "declared_flags": list(self.declared_flags),
            "compile_backend": self.compile_backend.value,
            "run_backend": self.run_backend.value,
            "toolchain_root": str(self.toolchain_root),
            "compiler_program": self.compiler_program,
            "linker_program": self.linker_program,
            "tools": {
                "compiler": self.compiler_tool.to_dict(),
                "linker": self.linker_tool.to_dict(),
            },
            "libraries": [library.to_dict() for library in self.libraries],
            "compiler_path_dos": list(self.compiler_path_dos),
            "linker_path_dos": list(self.linker_path_dos),
            "compiler_environment": [list(pair) for pair in self.compiler_environment],
            "linker_environment": [list(pair) for pair in self.linker_environment],
            "compile_arguments": list(self.compile_arguments),
            "cod_argument": self.cod_argument,
            "link_argument": self.link_argument,
            "extra_object_format": self.extra_object_format,
            "probe_id": self.probe_id,
            "aliases": list(self.aliases),
            "dependency_group": self.dependency_group,
            "dependency_tools": [tool.to_dict() for tool in self.dependency_tools],
            "dosbox_executable": (
                str(self.dosbox_executable) if self.dosbox_executable is not None else None
            ),
            "dosbox_sha256": self.dosbox_sha256,
            "dosbox_host_environment": [list(pair) for pair in self.dosbox_host_environment],
            "dosbox_conf_sha256": (
                hashlib.sha256(self.dosbox_conf().encode("ascii")).hexdigest()
                if self.uses_dosbox else None
            ),
            "kvikdos_executable": (
                str(self.kvikdos_executable) if self.kvikdos_executable is not None else None
            ),
            "kvikdos_sha256": self.kvikdos_sha256,
            "kvikdos_dpmi_mode": self.kvikdos_dpmi_mode.value,
        }


@dataclass(frozen=True)
class CompilerProfileSelection:
    """Suite-to-runner routing for one verified compiler profile."""

    toolchain: CompilerToolchain
    evidence_path: Path | None

    def to_dict(self) -> dict[str, object]:
        """Return the routing identity retained in coverage reports."""
        return {
            "profile_id": self.toolchain.profile_id,
            "compiler": MANIFEST_COMPILER_NAMES[self.toolchain.identity],
            "identity": self.toolchain.identity.value,
            "memory_model": self.toolchain.memory_model.value,
            "compile_backend": self.toolchain.compile_backend.value,
            "run_backend": self.toolchain.run_backend.value,
            "toolchain_root": str(self.toolchain.toolchain_root),
            "evidence_path": str(self.evidence_path) if self.evidence_path is not None else None,
        }


def msc6_ax_toolchain(*, root: Path, memory_model: MSCMemoryModel) -> CompilerToolchain:
    """Reproduce the historically verified MS C 6 compile/link commands.

    TMP stays on the writable c: mount: host TMP is not a DOS path and the
    compiler tree may be read-only.
    """
    return CompilerToolchain(
        profile_id=MSC6_AX_PROFILE_ID,
        identity=CompilerIdentity.MSC6_AX,
        memory_model=memory_model,
        declared_flags=("/Od", memory_model.compiler_flag),
        compile_backend=CompileBackend.KVIKDOS,
        run_backend=CompileBackend.KVIKDOS,
        toolchain_root=root,
        compiler_tool=ToolIdentity(dos_path="e:\\BIN\\CL.EXE", sha256=None),
        linker_tool=ToolIdentity(dos_path="e:\\BIN\\LINK.EXE", sha256=None),
        libraries=(
            ToolIdentity(
                dos_path=f"e:\\LIB\\{memory_model.runtime_library}",
                sha256=None,
            ),
        ),
        compiler_path_dos=("e:\\BIN",),
        linker_path_dos=(),
        compiler_environment=(
            ("INCLUDE", "E:\\INCLUDE"),
            ("LIB", "E:\\LIB"),
            ("TMP", "C:\\"),
        ),
        linker_environment=(("LIB", "E:\\LIB"),),
        compile_arguments=(
            "/Ic:\\",
            "/nologo",
            "/Od",
            memory_model.compiler_flag,
            "/c",
            "/Foc:\\{obj}",
            "{cod_option}",
            "c:\\{source}",
        ),
        cod_argument="/Fcc:\\{cod}",
        link_argument=(
            f"c:\\{{obj}}{{extra_objs}},c:\\{{exe}},c:\\{{map}},E:\\LIB\\{memory_model.runtime_library};"
        ),
        extra_object_format="+c:\\{extra_obj}",
    )


def _text(value: object, label: str) -> str:
    """Require a nonempty string evidence field."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label}: expected a nonempty string")
    return value


def _strings(value: object, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    """Preserve ordered evidence settings without coercing invalid values."""
    if not isinstance(value, list):
        raise ValueError(f"{label}: expected a list")
    result = tuple(_text(item, label) for item in value)
    if not result and not allow_empty:
        raise ValueError(f"{label}: expected a nonempty list")
    return result


def _environment(value: object, label: str) -> tuple[tuple[str, str], ...]:
    """Read ordered DOS environment pairs as a tuple of name/value tuples."""
    if not isinstance(value, list):
        raise ValueError(f"{label}: expected a list of [name, value] pairs")
    pairs: list[tuple[str, str]] = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError(f"{label}: expected [name, value] pairs")
        name = _text(item[0], label)
        _require_environment_name(name)
        pairs.append((name, _text(item[1], label)))
    return tuple(pairs)


def _tool_identity(value: object, label: str) -> ToolIdentity:
    """Read one hash-pinned tool/library record; unpinned records refuse."""
    if not isinstance(value, dict) or set(value) != _TOOL_FIELDS:
        raise ValueError(f"{label}: tool records must have fields {sorted(_TOOL_FIELDS)}")
    return ToolIdentity(
        dos_path=_text(value["dos_path"], label),
        sha256=_text(value["sha256"], label),
    )


def _registry_dependencies(
    payload: dict[object, object], source: Path,
) -> dict[str, tuple[ToolIdentity, ...]]:
    """Read the shared spawned-tool/header pins keyed by probe inventory group."""
    dependencies = payload["dependencies"]
    if not isinstance(dependencies, dict):
        raise ValueError(f"{source}: dependencies must be an object of groups")
    groups: dict[str, tuple[ToolIdentity, ...]] = {}
    for group, entries in dependencies.items():
        label = f"dependencies.{_text(group, 'dependencies group name')}"
        if not isinstance(entries, dict) or not entries:
            raise ValueError(f"{source}: {label} must be a nonempty dos_path:sha256 map")
        tools = []
        for dos_path, sha256 in entries.items():
            tools.append(ToolIdentity(
                dos_path=_text(dos_path, label),
                sha256=_text(sha256, label),
            ))
        if len({tool.dos_path.casefold() for tool in tools}) != len(tools):
            raise ValueError(f"{source}: {label} duplicates a DOS path under case folding")
        groups[group] = tuple(tools)
    return groups


def _registry_toolchain(
    record: object,
    source: Path,
    dosbox: tuple[Path, str, tuple[tuple[str, str], ...]] | None,
    kvikdos: tuple[Path, str] | None,
    dependencies: dict[str, tuple[ToolIdentity, ...]],
) -> CompilerToolchain:
    """Validate one registry profile record into a typed toolchain."""
    if (
        not isinstance(record, dict)
        or not set(record) >= _REGISTRY_PROFILE_FIELDS
        or not set(record) <= _REGISTRY_PROFILE_FIELDS | _REGISTRY_OPTIONAL_PROFILE_FIELDS
    ):
        raise ValueError(
            f"{source}: profile records must have fields {sorted(_REGISTRY_PROFILE_FIELDS)} "
            f"and may include {sorted(_REGISTRY_OPTIONAL_PROFILE_FIELDS)}"
        )
    compile_backend = CompileBackend(_text(record["compile_backend"], "profile.compile_backend"))
    run_backend = CompileBackend(_text(record["run_backend"], "profile.run_backend"))
    if (
        compile_backend is CompileBackend.DOSBOX or run_backend is CompileBackend.DOSBOX
    ) and dosbox is None:
        raise ValueError(f"{source}: DOSBox profiles require a runners.dosbox record")
    tools = record["tools"]
    if not isinstance(tools, dict) or set(tools) != _REGISTRY_TOOL_KINDS:
        raise ValueError(f"{source}: tools must have kinds {sorted(_REGISTRY_TOOL_KINDS)}")
    if not isinstance(record["libraries"], list):
        raise ValueError(f"{source}: profile.libraries must be a list")
    dependency_group = _text(record["dependency_group"], "profile.dependency_group")
    if dependency_group not in dependencies:
        raise ValueError(
            f"{source}: dependency_group {dependency_group!r} has no dependencies entry"
        )
    toolchain = CompilerToolchain(
        profile_id=_text(record["id"], "profile.id"),
        identity=compiler_identity(_text(record["compiler"], "profile.compiler")),
        memory_model=MSCMemoryModel(_text(record["memory_model"], "profile.memory_model")),
        declared_flags=_strings(record["declared_flags"], "profile.declared_flags"),
        compile_backend=compile_backend,
        run_backend=run_backend,
        toolchain_root=Path(_text(record["toolchain_root"], "profile.toolchain_root")),
        compiler_tool=_tool_identity(tools["compiler"], "profile.tools.compiler"),
        linker_tool=_tool_identity(tools["linker"], "profile.tools.linker"),
        libraries=tuple(
            _tool_identity(item, "profile.libraries") for item in record["libraries"]
        ),
        compiler_path_dos=_strings(record["compiler_path_dos"], "profile.compiler_path_dos", allow_empty=True),
        linker_path_dos=_strings(record["linker_path_dos"], "profile.linker_path_dos", allow_empty=True),
        compiler_environment=_environment(record["compiler_environment"], "profile.compiler_environment"),
        linker_environment=_environment(record["linker_environment"], "profile.linker_environment"),
        compile_arguments=_strings(record["compile_arguments"], "profile.compile_arguments"),
        cod_argument=(
            None if record["cod_argument"] is None
            else _text(record["cod_argument"], "profile.cod_argument")
        ),
        link_argument=_text(record["link_argument"], "profile.link_argument"),
        extra_object_format=_text(record["extra_object_format"], "profile.extra_object_format"),
        probe_id=_text(record["probe_id"], "profile.probe_id"),
        aliases=_strings(record["aliases"], "profile.aliases", allow_empty=True),
        dependency_group=dependency_group,
        dependency_tools=dependencies[dependency_group],
        dosbox_executable=dosbox[0] if dosbox is not None else None,
        dosbox_sha256=dosbox[1] if dosbox is not None else None,
        dosbox_host_environment=dosbox[2] if dosbox is not None else (),
        kvikdos_executable=kvikdos[0] if kvikdos is not None else None,
        kvikdos_sha256=kvikdos[1] if kvikdos is not None else None,
        kvikdos_dpmi_mode=KvikdosDPMIMode(
            _text(record.get("kvikdos_dpmi_mode", "auto"), "profile.kvikdos_dpmi_mode")
        ),
    )
    if toolchain.profile_id == MSC6_AX_PROFILE_ID:
        raise ValueError(f"{source}: {MSC6_AX_PROFILE_ID!r} is reserved for the built-in profile")
    return toolchain


def _read_probe_evidence(payload: dict[object, object], source: Path) -> dict[object, object]:
    """Load and hash-pin the declared probe-evidence document.

    The pin proves the retained probe output is unmodified; per-profile
    identity checks in ``_verify_probe_profile`` prove each executable
    profile actually describes a measured configuration.
    """
    evidence = payload["probe_evidence"]
    if not isinstance(evidence, dict) or set(evidence) != {"path", "sha256"}:
        raise ValueError(f"{source}: probe_evidence must have fields ['path', 'sha256']")
    evidence_path = Path(_text(evidence["path"], "probe_evidence.path"))
    if not evidence_path.is_absolute():
        evidence_path = source.parents[2] / evidence_path
    if not evidence_path.is_file():
        raise ValueError(f"{source}: probe evidence missing: {evidence_path}")
    expected = _text(evidence["sha256"], "probe_evidence.sha256")
    if _file_sha256(evidence_path) != expected:
        raise ValueError(f"{source}: probe evidence sha256 mismatch: {evidence_path}")
    try:
        probe = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"{source}: probe evidence unreadable: {error}") from error
    if not isinstance(probe, dict) or not isinstance(probe.get("profiles"), list):
        raise ValueError(f"{source}: probe evidence must record a profiles list")
    return probe


def _probe_dependency_problems(
    toolchain: CompilerToolchain,
    probe: dict[object, object],
) -> list[str]:
    """Compare registered spawned-tool pins with the probe's measured inventory."""
    children = probe.get("toolchain_children")
    inventory = children.get(toolchain.dependency_group) if isinstance(children, dict) else None
    if not isinstance(inventory, dict):
        return [f"probe evidence lacks toolchain_children[{toolchain.dependency_group!r}]"]
    pinned = {
        tool.dos_path: tool.sha256
        for tool in (toolchain.linker_tool, *toolchain.dependency_tools)
    }
    problems = [
        f"dependency {dos_path!r} pin {pinned.get(dos_path)!r} != inventory {expected!r}"
        for dos_path, expected in inventory.items()
        if pinned.get(dos_path) != expected
    ]
    extra = {tool.dos_path for tool in toolchain.dependency_tools} - set(inventory)
    if extra:
        problems.append(f"unmeasured dependency pins {sorted(extra)!r}")
    return problems


def _verify_probe_profile(
    toolchain: CompilerToolchain, probe: dict[object, object], source: Path,
) -> None:
    """Prove the registry profile describes the measured probe record.

    The probe document hash alone cannot show arbitrary templates derive
    from the measured run, so the referenced probe profile must agree on
    compiler product, memory model, model flag, and both backends.
    """
    marker = _PROBE_PRODUCT_MARKERS.get(toolchain.identity)
    probe_profiles = probe["profiles"]
    assert isinstance(probe_profiles, list)  # Guaranteed by _read_probe_evidence.
    matches = [
        record for record in probe_profiles
        if isinstance(record, dict) and record.get("id") == toolchain.probe_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"{source}: probe evidence must contain exactly one {toolchain.probe_id!r} profile"
        )
    record = matches[0]
    compiler_record = record.get("compiler")
    compiler = compiler_record if isinstance(compiler_record, dict) else {}
    product = compiler.get("product", "")
    problems = []
    if not isinstance(product, str) or marker is None or marker not in product:
        problems.append(f"probe product {product!r} != {marker!r}")
    if record.get("model") != toolchain.memory_model.value:
        problems.append(f"probe model {record.get('model')!r} != {toolchain.memory_model.value!r}")
    if record.get("model_flag") not in toolchain.declared_flags:
        problems.append(
            f"probe model flag {record.get('model_flag')!r} not in {toolchain.declared_flags!r}"
        )
    if record.get("compile_runner") != toolchain.compile_backend.value:
        problems.append(
            f"probe compile runner {record.get('compile_runner')!r} "
            f"!= {toolchain.compile_backend.value!r}"
        )
    if record.get("run_runner") != toolchain.run_backend.value:
        problems.append(
            f"probe run runner {record.get('run_runner')!r} != {toolchain.run_backend.value!r}"
        )
    problems.extend(_probe_dependency_problems(toolchain, probe))
    if record.get("kvikdos_dpmi_mode", "auto") != toolchain.kvikdos_dpmi_mode.value:
        problems.append(
            f"probe kvikdos DPMI mode {record.get('kvikdos_dpmi_mode', 'auto')!r} "
            f"!= {toolchain.kvikdos_dpmi_mode.value!r}"
        )
    if problems:
        raise ValueError(
            f"{source}: profile {toolchain.profile_id!r} does not match probe "
            f"{toolchain.probe_id!r}: {'; '.join(problems)}"
        )


def _runner_record(payload: dict[object, object], source: Path) -> dict[object, object]:
    """Return the declared runners object, rejecting unknown runner kinds."""
    runners = payload["runners"]
    if not isinstance(runners, dict) or not set(runners) <= {"kvikdos", "dosbox"}:
        raise ValueError(f"{source}: runners must only declare kvikdos/dosbox")
    return runners


def _dosbox_runner(
    runners: dict[object, object], source: Path,
) -> tuple[Path, str, tuple[tuple[str, str], ...]] | None:
    """Verify and read the declared DOSBox runner when present."""
    record = runners.get("dosbox")
    if record is None:
        return None
    if not isinstance(record, dict) or set(record) != {"path", "sha256", "host_environment"}:
        raise ValueError(f"{source}: runners.dosbox must have path/sha256/host_environment")
    executable = Path(_text(record["path"], "runners.dosbox.path"))
    if not executable.is_file():
        raise ValueError(f"{source}: DOSBox executable missing: {executable}")
    expected = _text(record["sha256"], "runners.dosbox.sha256")
    if _file_sha256(executable) != expected:
        raise ValueError(
            f"{source}: DOSBox executable sha256 mismatch: {executable}"
        )
    environment = record["host_environment"]
    if not isinstance(environment, dict):
        raise ValueError(f"{source}: runners.dosbox.host_environment must be an object")
    return executable, expected, tuple(
        (_text(name, "runners.dosbox.host_environment"), _text(value, "runners.dosbox.host_environment"))
        for name, value in environment.items()
    )


def _kvikdos_runner(runners: dict[object, object], source: Path) -> tuple[Path, str] | None:
    """Verify and read the declared kvikdos runner when present."""
    record = runners.get("kvikdos")
    if record is None:
        return None
    if not isinstance(record, dict) or set(record) != {"path", "sha256"}:
        raise ValueError(f"{source}: runners.kvikdos must have path/sha256")
    executable = Path(_text(record["path"], "runners.kvikdos.path"))
    if not executable.is_file():
        raise ValueError(f"{source}: kvikdos executable missing: {executable}")
    expected = _text(record["sha256"], "runners.kvikdos.sha256")
    if _file_sha256(executable) != expected:
        raise ValueError(
            f"{source}: kvikdos executable sha256 mismatch: {executable}"
        )
    return executable, expected


def load_compiler_profiles(path: Path) -> tuple[CompilerToolchain, ...]:
    """Read the repo-owned toolchain registry; malformed records refuse.

    The registry must pin its probe evidence and every profile must carry
    hash-pinned tool identities; arbitrary command JSON is not evidence.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Compiler profile registry unreadable: {path}: {error}") from error
    if not isinstance(payload, dict) or set(payload) != _REGISTRY_FIELDS or payload["schema"] != 1:
        raise ValueError("Compiler profile registry: unsupported schema")
    probe = _read_probe_evidence(payload, path)
    runners = _runner_record(payload, path)
    dosbox = _dosbox_runner(runners, path)
    kvikdos = _kvikdos_runner(runners, path)
    dependencies = _registry_dependencies(payload, path)
    records = payload["profiles"]
    if not isinstance(records, list) or not records:
        raise ValueError("Compiler profile registry: profiles must be a nonempty list")
    toolchains = tuple(
        _registry_toolchain(record, path, dosbox, kvikdos, dependencies) for record in records
    )
    identifiers = [toolchain.profile_id for toolchain in toolchains]
    aliases = [alias for toolchain in toolchains for alias in toolchain.aliases]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("Compiler profile registry: duplicate profile ids")
    if len(set(aliases)) != len(aliases) or set(aliases) & set(identifiers):
        raise ValueError("Compiler profile registry: duplicate or conflicting profile aliases")
    for toolchain in toolchains:
        _verify_probe_profile(toolchain, probe, path)
    return toolchains


def profile_registry_path(evidence_path: Path | None = None) -> Path:
    """Return the explicit or default repo-owned toolchain registry."""
    return evidence_path if evidence_path is not None else DEFAULT_PROFILE_REGISTRY


def _evidence_toolchain_by_id(profile_id: str, evidence_path: Path | None) -> CompilerToolchain:
    """Select one recorded profile by id; absent or ambiguous ids refuse."""
    path = profile_registry_path(evidence_path)
    try:
        profiles = load_compiler_profiles(path)
    except ValueError as error:
        raise UnsupportedCompilerProfile(
            f"Compiler profile {profile_id!r}: registry unusable: {error}"
        ) from error
    matches = [
        toolchain for toolchain in profiles
        if toolchain.profile_id == profile_id or profile_id in toolchain.aliases
    ]
    if len(matches) != 1:
        raise UnsupportedCompilerProfile(
            f"Compiler profile registry must contain exactly one {profile_id!r} profile"
        )
    return matches[0]


def resolve_case_toolchain(
    profile_id: str = MSC6_AX_PROFILE_ID,
    *,
    memory_model: MSCMemoryModel | None = None,
    msc6_root: Path = MSC6_AX_TOOLCHAIN_ROOT,
    evidence_path: Path | None = None,
) -> CompilerToolchain:
    """Resolve the exact toolchain for one round trip; unknown ids refuse."""
    if profile_id == MSC6_AX_PROFILE_ID:
        return msc6_ax_toolchain(root=msc6_root, memory_model=memory_model or MSCMemoryModel.SMALL)
    toolchain = _evidence_toolchain_by_id(profile_id, evidence_path)
    if memory_model is not None and toolchain.memory_model is not memory_model:
        raise UnsupportedCompilerProfile(
            f"Compiler profile {profile_id!r} is {toolchain.memory_model.value}, not {memory_model.value}"
        )
    toolchain.verify_tools()
    return toolchain


def select_manifest_profile(
    manifest: CoverageManifest, *, evidence_path: Path | None = None,
) -> CompilerProfileSelection:
    """Bind a manifest's declared compiler profile to verified toolchain settings."""
    if manifest.memory_model is None:
        raise UnsupportedCompilerProfile("Adapter requires an explicit small or large memory model")
    model = MSCMemoryModel(manifest.memory_model)
    identity = compiler_identity(manifest.compiler)
    if identity is CompilerIdentity.MSC6_AX:
        toolchain = msc6_ax_toolchain(root=MSC6_AX_TOOLCHAIN_ROOT, memory_model=model)
        evidence = None
    else:
        path = profile_registry_path(evidence_path)
        try:
            profiles = load_compiler_profiles(path)
        except ValueError as error:
            raise UnsupportedCompilerProfile(
                f"{manifest.compiler}: registry unusable: {error}"
            ) from error
        candidates = [
            toolchain for toolchain in profiles
            if toolchain.identity is identity and toolchain.memory_model is model
        ]
        matches = [
            toolchain for toolchain in candidates if toolchain.declared_flags == manifest.compiler_flags
        ]
        if len(matches) != 1:
            raise UnsupportedCompilerProfile(
                f"{manifest.compiler} {model.value} has no verified profile matching "
                f"declared flags {manifest.compiler_flags!r}"
            )
        toolchain = matches[0]
        toolchain.verify_tools()
        evidence = path
    if manifest.compiler_flags != toolchain.declared_flags:
        raise UnsupportedCompilerProfile(
            f"{manifest.compiler} manifest flags {manifest.compiler_flags!r} do not match "
            f"the verified profile flags {toolchain.declared_flags!r}"
        )
    return CompilerProfileSelection(toolchain=toolchain, evidence_path=evidence)


@contextmanager
def compiler_toolchain_lock(toolchain: CompilerToolchain) -> Iterator[None]:
    """Serialize concurrent transactions on each toolchain's own compiler."""
    with toolchain.compiler_host_path.open("rb") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)


class ToolStageOutcome(StrEnum):
    """Distinguish DOS compiler evidence from launcher and artifact failures."""

    PASSED = "passed"
    COMPILE_FAILED = "compile_failed"
    LAUNCH_FAILED = "launch_failed"
    TIMED_OUT = "timed_out"
    ARTIFACT_MISSING = "artifact_missing"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class ToolStageReceipt:
    """One original tool invocation and its retained host/guest evidence."""

    outcome: ToolStageOutcome
    exit_code: int | None
    command: tuple[str, ...]
    stdout: str
    stderr: str

    @property
    def passed(self) -> bool:
        """Require compiler success and every declared output artifact."""
        return self.outcome is ToolStageOutcome.PASSED

    @property
    def signal(self) -> int | None:
        """Expose host signal termination separately from DOS compiler failure."""
        return -self.exit_code if self.exit_code is not None and self.exit_code < 0 else None


_STAGE_PROCESS_CLEANUP_GRACE_SECONDS: float = 0.5


def _kill_owned_process_group(process: subprocess.Popen[str]) -> None:
    """Kill only the isolated stage process group owned by this caller."""
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


def _kill_owned_process_tree(process: subprocess.Popen[str]) -> None:
    """Snapshot and kill this root's descendants before terminating its group."""
    descendants = process_tree_pids((process.pid,)) or (process.pid,)
    for pid in reversed(descendants):
        if pid != process.pid:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
    _kill_owned_process_group(process)


def _timeout_output_text(value: str | bytes | None) -> str | None:
    """Normalize one partial timeout stream while retaining undecodable bytes."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _combine_timeout_output(before: str | bytes | None, after: str | bytes | None) -> str | None:
    """Keep the fullest partial stream when bounded cleanup retries communicate."""
    initial = _timeout_output_text(before)
    final = _timeout_output_text(after)
    if not initial:
        return final
    if not final:
        return initial
    if final.startswith(initial):
        return final
    if initial.startswith(final):
        return initial
    return initial + final


def _run(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: int | float = 60,
    env: dict[str, str] | None = None,
    cleanup_process_group: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a command with captured output and explicit environment overrides."""
    runtime_env = os.environ.copy()
    if env is not None:
        runtime_env.update(env)
    if not cleanup_process_group:
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd is not None else None,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            env=runtime_env,
        )

    process = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
        env=runtime_env,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as failure:
        _kill_owned_process_tree(process)
        try:
            stdout, stderr = process.communicate(timeout=_STAGE_PROCESS_CLEANUP_GRACE_SECONDS)
        except subprocess.TimeoutExpired as drain_failure:
            _kill_owned_process_group(process)
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=_STAGE_PROCESS_CLEANUP_GRACE_SECONDS)
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    with contextlib.suppress(OSError):
                        stream.close()
            stdout = _combine_timeout_output(failure.output, drain_failure.output) or ""
            stderr = _combine_timeout_output(failure.stderr, drain_failure.stderr) or ""
        raise subprocess.TimeoutExpired(cmd, timeout, output=stdout, stderr=stderr) from failure
    except BaseException:
        _kill_owned_process_tree(process)
        with contextlib.suppress(subprocess.TimeoutExpired):
            process.communicate(timeout=_STAGE_PROCESS_CLEANUP_GRACE_SECONDS)
        raise
    return subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)


def _kvikdos_toolchain_command(
    kvikdos: Path,
    out_dir: Path,
    spec: CompilerToolchain,
    *,
    path_dos: tuple[str, ...],
    environment: tuple[tuple[str, str], ...],
    program: str,
) -> list[str]:
    """Assemble one emulator invocation for a verified toolchain program."""
    return [
        str(kvikdos),
        f"--mount=c:{out_dir}/",
        f"--mount=e:{spec.toolchain_root}/",
        "--drive=c",
        "--cwd-dos=c:\\",
        *(f"--path-dos={path}" for path in path_dos),
        *(f"--env={name}={value}" for name, value in environment),
        *(["--dpmi=off"] if spec.kvikdos_dpmi_mode is KvikdosDPMIMode.OFF else []),
        f"--prog={program}",
        program,
    ]


def _dos_case_file(out_dir: Path, name: str) -> Path | None:
    """Find a DOS-created file regardless of DOSBox name folding."""
    for candidate in (out_dir / name, out_dir / name.upper(), out_dir / name.lower()):
        if candidate.is_file():
            return candidate
    return None


def _run_dosbox_stage(
    spec: CompilerToolchain,
    out_dir: Path,
    *,
    tag: str,
    command_line: str,
    path_dos: tuple[str, ...],
    environment: tuple[tuple[str, str], ...],
    required: tuple[str, ...],
    timeout: int = 120,
) -> ToolStageReceipt:
    """Run one compiler/linker stage under pinned-config DOSBox.

    DOSBox's host exit code only reports the launcher, and it eagerly
    creates redirect targets even for skipped echoes, so success requires
    the exact OK marker text with an empty FAIL marker, an error-free tool
    log, and every required artifact fresh and nonempty.
    """
    batch_name = f"{tag}.BAT"
    out_name = f"{tag}.OUT"
    ok_name = f"{tag}OK.OUT"
    fail_name = f"{tag}FL.OUT"
    cleanup_error = _clear_stage_artifacts(out_dir, (batch_name, out_name, ok_name, fail_name, *required))
    if cleanup_error is not None:
        return cleanup_error
    (out_dir / batch_name).write_bytes(
        spec.dosbox_batch(
            tag=tag,
            command_line=command_line,
            out_name=out_name,
            ok_name=ok_name,
            fail_name=fail_name,
            path_dos=path_dos,
            environment=environment,
        ).encode("ascii")
    )
    conf_path = out_dir / "DOSBOX.CFG"
    conf_path.write_text(spec.dosbox_conf(), encoding="ascii")
    dosbox = spec.dosbox_executable
    if dosbox is None:
        return ToolStageReceipt(ToolStageOutcome.LAUNCH_FAILED, None, (), "", "DOSBox compile backend without a declared executable")
    command = [
        str(dosbox),
        "-noconsole",
        "-conf", str(conf_path),
        "-c", f'mount c "{out_dir}"',
        "-c", f'mount e "{spec.toolchain_root}"',
        "-c", "c:",
        "-c", f"call c:\\{batch_name}",
        "-c", "exit",
    ]
    wall_start = time.time()
    try:
        proc = _run(command, timeout=timeout, env=dict(spec.dosbox_host_environment), cleanup_process_group=True)
    except subprocess.TimeoutExpired as error:
        return ToolStageReceipt(ToolStageOutcome.TIMED_OUT, None, tuple(command),
                                _timeout_output_text(error.stdout) or "",
                                (_timeout_output_text(error.stderr) or "") + str(error))
    except OSError as error:
        return ToolStageReceipt(ToolStageOutcome.LAUNCH_FAILED, None, tuple(command), "", str(error))
    dos_log_path = _dos_case_file(out_dir, out_name)
    dos_log = dos_log_path.read_text("latin1") if dos_log_path is not None else ""
    diagnostics: list[str] = []
    if proc.returncode != 0:
        diagnostics.append(f"dosbox launcher exit {proc.returncode}")
    marker_problems = _dosbox_marker_diagnostics(spec, out_dir, tag, ok_name, fail_name)
    diagnostics.extend(marker_problems)
    error_lines = [
        line.strip() for line in dos_log.splitlines()
        if "error" in line.lower() or "fatal" in line.lower()
    ]
    diagnostics.extend(f"{out_name}: {line}" for line in error_lines[:8])
    diagnostics.extend(_dosbox_artifact_diagnostics(out_dir, required, wall_start))
    log_parts = [proc.stdout, proc.stderr, dos_log]
    log_parts.extend(diagnostic + "\n" for diagnostic in diagnostics)
    fail_marker = _dos_case_file(out_dir, fail_name)
    compiler_failed = bool(fail_marker is not None and fail_marker.read_text("latin1").strip()) or bool(error_lines)
    outcome = ToolStageOutcome.PASSED
    if proc.returncode != 0:
        outcome = ToolStageOutcome.LAUNCH_FAILED
    elif compiler_failed:
        outcome = ToolStageOutcome.COMPILE_FAILED
    elif marker_problems:
        outcome = ToolStageOutcome.INCOMPLETE
    elif diagnostics:
        outcome = ToolStageOutcome.ARTIFACT_MISSING
    return ToolStageReceipt(outcome, proc.returncode, tuple(command), "".join(log_parts), "")


def _dosbox_marker_diagnostics(
    spec: CompilerToolchain, out_dir: Path, tag: str, ok_name: str, fail_name: str,
) -> list[str]:
    """Require the exact OK marker text and an empty/absent FAIL marker."""
    problems: list[str] = []
    ok_path = _dos_case_file(out_dir, ok_name)
    if ok_path is None:
        problems.append(f"missing {ok_name} status marker")
    else:
        ok_text = ok_path.read_text("latin1").strip()
        if ok_text != spec.dosbox_ok_marker(tag):
            problems.append(f"malformed {ok_name} marker content {ok_text!r}")
    fail_path = _dos_case_file(out_dir, fail_name)
    if fail_path is not None and fail_path.read_text("latin1").strip():
        problems.append(f"{fail_name} marker records DOS ERRORLEVEL >= 1")
    return problems


def _dosbox_artifact_diagnostics(
    out_dir: Path, required: tuple[str, ...], wall_start: float,
) -> list[str]:
    """Require every declared stage artifact to be fresh and nonempty."""
    problems: list[str] = []
    for name in required:
        artifact = _dos_case_file(out_dir, name)
        if artifact is None:
            problems.append(f"missing artifact {name}")
        elif artifact.stat().st_size == 0 or artifact.stat().st_mtime < wall_start - 1.0:
            problems.append(f"stale or empty artifact {name}")
    return problems


def _run_tool_stage(
    spec: CompilerToolchain,
    out_dir: Path,
    *,
    kvikdos: Path | None,
    tag: str,
    program: str,
    argv: list[str],
    command_line: str,
    path_dos: tuple[str, ...],
    environment: tuple[tuple[str, str], ...],
    required: tuple[str, ...],
    timeout: int = 120,
) -> ToolStageReceipt:
    """Run one compile/link stage on the profile's verified compile backend."""
    if spec.compile_backend is CompileBackend.DOSBOX:
        return _run_dosbox_stage(
            spec,
            out_dir,
            tag=tag,
            command_line=command_line,
            path_dos=path_dos,
            environment=environment,
            required=required,
            timeout=timeout,
        )
    if kvikdos is None:
        return ToolStageReceipt(ToolStageOutcome.LAUNCH_FAILED, None, (), "", "selected profile has no declared kvikdos runner")
    command = _kvikdos_toolchain_command(
        kvikdos, out_dir, spec, path_dos=path_dos, environment=environment, program=program,
    ) + argv
    cleanup_error = _clear_stage_artifacts(out_dir, required)
    if cleanup_error is not None:
        return cleanup_error
    started = time.time()
    try:
        proc = _run(command, timeout=timeout, cleanup_process_group=True)
    except subprocess.TimeoutExpired as error:
        return ToolStageReceipt(ToolStageOutcome.TIMED_OUT, None, tuple(command),
                                _timeout_output_text(error.stdout) or "",
                                (_timeout_output_text(error.stderr) or "") + str(error))
    except OSError as error:
        return ToolStageReceipt(ToolStageOutcome.LAUNCH_FAILED, None, tuple(command), "", str(error))
    outcome = ToolStageOutcome.PASSED
    diagnostics = _dosbox_artifact_diagnostics(out_dir, required, started)
    if proc.returncode < 0:
        outcome = ToolStageOutcome.LAUNCH_FAILED
    elif proc.returncode != 0:
        outcome = ToolStageOutcome.COMPILE_FAILED
    elif diagnostics:
        outcome = ToolStageOutcome.ARTIFACT_MISSING
    return ToolStageReceipt(outcome, proc.returncode, tuple(command), proc.stdout,
                            proc.stderr + "\n".join(diagnostics))




TAIL_COMPILER_CONTEXT_ENV: str = "INERTIA_TAIL_COMPILER_CONTEXT"


@dataclass(frozen=True)
class FrozenCompilerContext:
    """Bind child compilation to authoritative profile bytes and resolved settings."""

    profile_id: str
    memory_model: str
    toolchain_root: str
    evidence_path: str
    evidence_sha256: str
    profile_sha256: str

    @classmethod
    def create(cls, toolchain: CompilerToolchain, evidence_path: Path | None) -> FrozenCompilerContext:
        """Freeze selection evidence without serializing executable commands."""
        path = profile_registry_path(evidence_path) if toolchain.profile_id != MSC6_AX_PROFILE_ID else None
        return cls(toolchain.profile_id, toolchain.memory_model.value, str(toolchain.toolchain_root),
                   str(path.resolve()) if path is not None else "",
                   _file_sha256(path) if path is not None else "",
                   cls._profile_hash(toolchain))

    @staticmethod
    def _profile_hash(toolchain: CompilerToolchain) -> str:
        """Fingerprint all resolved flags, backend, environment and binary pins."""
        return hashlib.sha256(json.dumps(toolchain.to_dict(), sort_keys=True).encode()).hexdigest()

    def serialize(self) -> str:
        """Return deterministic child environment and cache identity bytes."""
        return json.dumps({"profile_id": self.profile_id, "memory_model": self.memory_model,
                           "toolchain_root": self.toolchain_root, "evidence_path": self.evidence_path,
                           "evidence_sha256": self.evidence_sha256, "profile_sha256": self.profile_sha256},
                          sort_keys=True)

    @classmethod
    def parse(cls, serialized: str) -> FrozenCompilerContext:
        """Refuse malformed context rather than silently switching compiler lanes."""
        data = json.loads(serialized)
        fields = {"profile_id", "memory_model", "toolchain_root", "evidence_path", "evidence_sha256", "profile_sha256"}
        if not isinstance(data, dict) or set(data) != fields or not all(isinstance(v, str) for v in data.values()):
            raise ValueError("malformed frozen compiler context")
        return cls(data["profile_id"], data["memory_model"], data["toolchain_root"], data["evidence_path"],
                   data["evidence_sha256"], data["profile_sha256"])

    def resolve(self) -> CompilerToolchain:
        """Reverify evidence and tools before execution or any successful cache reuse."""
        path = Path(self.evidence_path) if self.evidence_path else None
        if path is not None and _file_sha256(path) != self.evidence_sha256:
            raise ValueError("frozen compiler evidence changed")
        toolchain = resolve_case_toolchain(self.profile_id, memory_model=MSCMemoryModel(self.memory_model),
                                          msc6_root=Path(self.toolchain_root), evidence_path=path)
        if toolchain.toolchain_root.resolve() != Path(self.toolchain_root).resolve():
            raise ValueError("frozen compiler toolchain root disagrees with resolved profile")
        if self._profile_hash(toolchain) != self.profile_sha256:
            raise ValueError("frozen compiler profile changed")
        toolchain.verify_tools()
        return toolchain


def compile_profile_translation_unit(toolchain: CompilerToolchain, out_dir: Path, *, timeout: int = 60) -> ToolStageReceipt:
    """Compile only GEN.C into a fresh GEN.OBJ using the selected original profile."""
    with compiler_toolchain_lock(toolchain):
        return _run_tool_stage(toolchain, out_dir, kvikdos=toolchain.kvikdos_executable,
                               tag="CC", program=toolchain.compiler_program,
                               argv=toolchain.compile_argv(source_name="GEN.C", obj_name="GEN.OBJ"),
                               command_line=toolchain.compile_dos_command(source_name="GEN.C", obj_name="GEN.OBJ"),
                               path_dos=toolchain.compiler_path_dos, environment=toolchain.compiler_environment,
                               required=("GEN.OBJ",), timeout=timeout)


def _clear_stage_artifacts(out_dir: Path, names: tuple[str, ...]) -> ToolStageReceipt | None:
    """Require removal of previous artifacts before admitting fresh stage evidence."""
    try:
        for name in names:
            for candidate in {out_dir / name, out_dir / name.upper(), out_dir / name.lower()}:
                if candidate.exists():
                    candidate.unlink()
    except OSError as error:
        return ToolStageReceipt(ToolStageOutcome.INCOMPLETE, None, (), "", str(error))
    return None
