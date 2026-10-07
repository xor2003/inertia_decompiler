# Architecture adapters

`flat32_leaf.py` owns complete single-block near-return admission. It lowers
with explicit register architecture and refuses calls or conditional exits;
it neither installs global state nor treats a branch prefix as a whole leaf.
Its function owner also preserves catalog metadata, scan limits, stable IDs,
refusal accounting and lifted-block counts. Both legacy target adapters alias
that exact function rather than carrying independent implementations.
`flat32_control.py` owns leaf/closed-CFG control admission. Matched-CFG
lowering supplies its target map through the typed `IrsbFinisher` interface
and supplies register architecture explicitly, without an inner installation
scope. Legacy adapter finishers delegate here with their historical target
state. Region finishing continues to use the native engine's control owner.
Document callers select the leaf owner with
`FunctionLoweringPolicy.FLAT32_LEAF` and the native register architecture.
`SCAN` retains default scanning and legacy dispatch only for callers without
an explicit architecture. Invalid leaf architecture/source combinations fail
before loading executable bytes.
Production MSC/BC5 CLI dispatch and native proof helpers no longer install
engine globals. Legacy installation remains for compatibility tests. Dynamic
artifact-module resolution and driver package migration remain separate work.

`flat32_loader.py` owns PE/ELF image loading, inclusive PE bounds, the mapped
byte cap and the explicit PE relocation option. Target adapters retain their
public loader signatures and delegate here; BC5 can disable relocation while
MSC retains normal loader defaults.

`flat32.py` owns native i386 register offsets, partial reads/writes and integer
expression admission. `flat32_register_architecture()` returns the explicit
`RegisterArchitecture` consumed by block/function lowering, terminal walks,
call composition and independent native byte binding.

This owner defines architecture effects. Target profiles select inputs and
policies; they do not redefine these effects. Never install register globals
here. Real16 remains in its existing owner until its explicit context migrates.

`tools.dosunit.flat32_lifting` aliases this exact module for historical imports
and pickle lookup. New callers import the canonical owner. Scalar contracts
live in `../contracts/`; solver interpretation lives in `../ssa/`.

Boundary tests: `../tests/test_contract_boundaries.py`. Integration controls
include `test_symbolic_terminal.py`, `test_pe32_recursive_public.py`,
`test_flat32_model_namespaces.py` and both target drivers' tests. Preserve
honest refusals for unsupported helpers/noninteger constants and upper bits
across byte/word writes.
