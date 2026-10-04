"""Layer: dosunit native proof loading.

Responsibility: retain real16 instruction semantics while allowing CLE to map
the complete loader-linear coordinate space, matching the DOS MZ loader.
"""
from angr_platforms.X86_16.arch_86_16 import Arch86_16


def real16_loader_arch() -> Arch86_16:
    """Create an isolated real16 architecture with a wide loader address range.

    CLE uses bits for image bounds. Register offsets, operand defaults and the
    real16 decoder stay those of Arch86_16, as in the production MZ loader.
    """
    arch = Arch86_16()
    arch.bits = max(arch.bits, 32)
    return arch
