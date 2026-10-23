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

`flat32_enter_lifter.py` supplies the default 32-bit ENTER instruction missing
from libVEX. It preserves ordered pushes and nesting-display reads, including
aliases with prior pushes, masks nesting to five bits, and leaves flags intact.
The loader registers this fallback through PyVEX's public interface; the VEX
cache fingerprints both the backend registry and its module bytes. Prefix
overrides and truncated encodings retain NoDecode. Native differential tests
and changed-argument proof controls live in `test_flat32_enter.py`.

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

`flat32_cfg_lifting.py` isolates REP using the decoded instruction extent;
`flat32_cfg_summary.py` admits that complete byte record through the shared
repeat contract. Neither consumer assumes REP is always two bytes. A single
operand override retains32-bit address/count state and changes word/dword
element size; address/segment overrides remain outside this contract. Closed
continuations and effects surrounding REP remain mandatory proof obligations.

`flat32_entry_inputs.py` binds completed native call-composition roots' VEX
direction step to a one-bit `x86_df` input:0 maps to+1 and1 to-1. This covers
both architectural directions and never assumes DF-clear. Binding happens
after callee substitution, preserving caller direction in nested calls, and
is serialized as `architectural_input_bindings`. Generic SSA and other proof
lanes retain their existing input models. Width/namespace conflicts refuse;
this does not constrain stack aliasing or other architectural state.

`flat32_control_word.py` decodes default-address-size, unprefixed FNSTCW and
stores all16 bits of independent `x87_control_word` into byte-addressed memory.
ModRM/SIB base, index, scale and signed displacement are retained modulo32 bits.
Call composition and the shared CFG/region/macro lowering isolate this
instruction and use its native summary before ordinary VEX lowering; they do
not enable the lossy create_fpucw helper. The explicit architecture carries
the16-bit control word on internal edges without assigning a fake VEX offset.
The current integration covers read-only CW state. FLDCW, x87 arithmetic and
indexed FPU stack state still require implementation. FWAIT in that lane now
retains an explicit pending-exception obligation, including waiting FSTCW,
in both call and CFG discovery. Leaf lowering does not yet consume this summary.

The shared call-boundary exceptional-exit check also admits signed native
IDIV byte/word/dword forms when every division-by-zero and quotient-overflow
predicate is universally false. Native width and signedness must match the
VEX DivMod operation. For signed quotient width N, unsigned magnitudes A/B
require A < B*2**(N-1) for nonnegative quotients, or
A < B*(2**(N-1)+1) for negative quotients (truncation toward zero).
The magnitude computation includes INT64_MIN; bounded products fit uint64
for these operand widths. The auxiliary proof assumes no entry domain or
normal completion. Actual division, remainder, memory and register effects
remain in the block and are compared normally. Zero divisors, overflow,
inconclusive queries and other exceptional exits retain their refusal.
Native regression owner: `../tests/test_flat32_signed_division.py`.
