# Postprocess

The existing cleanup modules live here; `optimization/` retains its existing
namespace layout. This move preserves the algorithms and proof requirements.
Private tests move into `tests/postprocess/`. Historical module paths alias
these owners.

Root postprocess stage helpers remain in the historical platform package until
their move. Cleanup consumes proven facts and does not recover semantics.
