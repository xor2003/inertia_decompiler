# Traversal And Storage Contract Gates

## Purpose And Ownership

Prevent skipped AST child fields and incorrect interior stack-byte associations
from silently reaching generated C. These are structural and Alias-boundary
checks, not semantic recovery in Rewrite or CLI.

Run `make decompiler-contracts PYTHON=./.venv/bin/python PYTEST_ARGS='-n 7 --tb=short --no-header'`.
The Make targets `test-pipeline`, `test-pipeline-fast`, and
`test-pipeline-expanded` require this gate before their longer pipeline recipe.
The tests also belong to the routine Python pipeline inventory.

## Traversal Coverage

Read and replacement walkers in `c_ast_utils.py` share the declared child-field
schema. Replacement preserves list/tuple/dict structure and mapping keys and
honors the child policy for both scalar and container fields.

- Reason: duplicated walker inventories missed returns and switch bodies.
- DoD: every declared child field is tested in scalar/list/tuple/dict containers;
  read and replacement agree; refused edges stay unchanged. Native SS lowering
  regressions cover returns, expressions, call arguments, switch selector/cases/
  default, and loop condition/initializer/iterator positions.
- Failure: an admitted edge is skipped, a refused edge changes, or malformed
  traversal silently looks like an absent child.

`CTraversalContractError8616` reports node type, child path and a typed reason
(`child_read`, `child_write`, `container_cycle`) at the failing operation.
For example: `C AST traversal failed at CReturn.retval[0]: container_cycle`.
Original field-access exceptions remain chained; transform exceptions propagate.

Scope: the schema matrix uses synthetic boundary containers, not every legal
native constructor combination. This does not prove all private walkers cover
every future AST class. New schema fields automatically enter the matrix.

## Storage Invariants

Alias owns the exact contained stack-range displacement. The x86-16 native
variable-recovery adapter validates it before publishing indexes or durable
read/write/reference accesses. Other architectures delegate unchanged.

- Reason: two byte references to one word were both registered at offset zero.
- DoD: exact contained ranges preserve byte address and extent, sibling uses
  survive, and published indexes/access records agree. Deliberately corrupting
  the displacement must fail before publication.
- Failure: owner base plus displacement differs from the proven requested byte
  address, or contradictory evidence is published as a valid association.

`StackReferenceInvariantError8616` includes requested `(start, size)`, owner
`(start, size)` and displacement, with a function/access exception note.
Example: `requested=(3, 1), owner=(2, 2), displacement=None`.
Unknown/noncontained ranges, SP-based associations and unproven wrapping are
not repaired or rejected as contradictions. They retain the existing association.
This is a contained BP-coordinate association invariant, not a universal proof
of every stack owner or segmented-memory operation.

## Acceptance Boundary

### Generated-C Boundary Follow-Up

The routine pipeline now includes `test_x86_16_string_corpus_anchors.py`.
It compiles the unchanged recovered function with `-Wall -Wextra -Werror -O2`,
then checks zero/nonzero counts, both DF states, every memory byte, return value,
and saved ES/DI preservation. Four deliberately corrupted controls must fail.

- Reason: `__fimemset` reported validation success while emitting an unassigned
  `local_5`; initialized machine-stack bytes do not initialize a separate C local.
- DoD: valid control passes, corrupted controls fail, actual generated C compiles
  and meets the behavioral oracle, and the routine pipeline executes this test.
- Failure: accepting a local only because its address overlaps an initialized
  parameter, compiling altered C, or removing the regression to restore green.

Status: the five oracle self-checks pass. After the byte-subview repair, actual
generated C compiles and passes memory/return checks but fails saved ES/DI
preservation. The runtime AST gate still needs distinct emitted-variable
binding/definition evidence integrated into the existing data-flow engine.
Do not claim universal emitted-variable coverage from this one compiler oracle.
Earlier wiring/oracle check: 118 passed, one corpus compile failure, 7.57s.
Scoped Ruff/MyPy/Pyright pass; global quality-fast still fails on lint debt,
with the 39-module mypyc smoke passing. Logs are
`/home/xor/.cache/live-word-gate-final.log` and `live-word-final-quality-fast.log`.

Entry-stack validation distinguishes a parameter's declared C value width from
its physical ABI slot. Padding and extra unified-owner bytes are not initialized
inputs. Missing or unknown types cannot supply entry evidence.

- Reason: a byte parameter previously concealed uninitialized adjacent reads.
- DoD: valid byte reads pass; reads into slot padding fail with stack coordinate,
  width and AST path; declared signature types override stale variable types.
- Failure: wider physical storage silently initializes bytes absent from the
  C interface, or legitimate value reads are rejected solely for slot padding.

`test_x86_16_validation_entry_stack_ranges.py` runs in the early contract gate.

These guards supplement, never replace, whole-tail validation, generated-C
compilation and behavioral testing. The reduced MOV/LES compile/run regression
passes, including nonzero SS; full `__fimemset` and Step 9 remain open.
Global lint debt must remain visible. See `SORTD_GHIDRA_PLAN.md` for the latest
gate results; focused passing tests are not a refreshed full-suite audit.

## Stack Expression Identity Follow-Up

The boundary matrix exposed another storage bug: `SimStackVariable` subclasses
`SimMemoryVariable`. Both shared and compatibility expression comparators tested
the generic memory case first, making their stack-specific comparison unreachable.
Consequently, equal-offset variables with different BP/SP bases or function
regions compared equal. New tests reproduced both incorrect equivalences.

The shared comparator now checks stack variables first, consuming their existing
offset, size, base and region. The compatibility entry point delegates to that
owner instead of retaining a second implementation. No storage is inferred from
names or rendered C, and no new semantic recovery was added to postprocess.

- Reason: equality consumers must not conflate distinct recovered stack frames.
- DoD: both entry points distinguish offset, width, base and region; unknown
  dirty payloads retain identity-only comparison and register widths survive.
- Failure: distinct stack coordinates compare equal, or compatibility callers
  use divergent comparison rules.

Verification: the compatibility-only before check had 2 failures / 8 passes.
After repair, 241 contract checks passed; routine pytest passed 4,213 tests in
253.10s and all three pipeline lanes passed, including seven MS C round trips.
Scoped MyPy/Pyright and full architecture passed. The shared AST utility and its
test module are Ruff-clean after complexity extraction. The compatibility file
still has 24 legacy Ruff findings; global `quality-fast` remains red on lint debt.
The 39-module mypyc smoke passed. A fresh focused `__fimemset` test still failed
whole-tail validation (11.59s), so neither that function nor Step 9 is closed.

Logs: `/home/xor/.cache/ast-identity-*.log`, `ast-compat-before.log`, and
`fimemset-after-identity.log`. No new full-suite total is claimed.
