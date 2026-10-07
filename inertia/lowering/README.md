# Types and lowering

This package owns typed storage and object materialization, argument and return
lowering, and generated C representations. Alias and widening evidence comes
from their owning layers.

Private tests live in `tests/lowering/`; shared behavior tests live in
`tests/integration/`. Historical `angr_platforms.X86_16.lowering` modules are
import aliases to these implementations.
