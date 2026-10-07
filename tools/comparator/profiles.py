"""Layer: validation target profiles.

Responsibility: own explicit target successor-admission policies without changing proof rules.
"""

from __future__ import annotations

import angr

from tools.dosunit.compare import straightline_ssa as S


def declared_bounds_only(*, project: angr.Project, function_base: int, successor: int) -> bool:
    """Admit no successors beyond the declared complete function bounds."""
    return False


def executable_section_bounds(*, project: angr.Project, function_base: int, successor: int) -> bool:
    """Preserve BC5 admission of executable sections and loader-backed sectionless bytes."""
    section = project.loader.find_section_containing(successor)
    if section is not None:
        return bool(section.is_executable)
    return S._loader_bytes(project, successor, 1) is not None
