# Decompiler Map

This is the short map for agents. `AGENTS.md` is the canonical rulebook;
`reference/agent-rules.md` is supplemental glossary and long-running-agent
guidance. This file exists so the correct layer is visible before editing.

## Core Order

`alias/stack_word_call_window.py` owns the block-local lifetime of a proved
constant word through the selected raw IR CALL boundary. It consumes the IR
constant receipt, requires an exact raw-to-SSA structured projection including
temporary provenance, and replays strict frame coordinates and classified
effects. STORE overlap, unknown/cross-selector addresses, SS writes, opaque
effects and earlier control transfers refuse. The retained census is conditional
on supplied IR coverage: it is not a binary coverage certificate or caller ABI
proof. Call-boundary offsets become callee entry offsets only after independent
Frontend/Semantics boundary proof. Callee-load stability and pointer extents
remain separate obligations; consumers must not bypass them.

`alias/stack_word_call_binding.py` consumes that local theorem, exact registered
raw coverage and the Semantics-owned near-CALL binary identity check. It requires
the same raw artifact and the complete two-byte envelope at SP offsets0/1 with
delta-2. Target projection uses the existing address owner and absolute loader
image bounds, without padding/name aliases. Only this bound contract exposes
callee-entry offsets and the contextual constant; neither is a global callee
bound or proof that a later bound LOAD still reads the input.

`ir/indexed_induction_write_census.py` requires the shared scalar-effect owner
to classify non-STORE instructions; absence of an explicit STORE opcode is
never memory-preservation proof. Direct literal JMP effects and backend Boolean
Xor1/And1/Or1 operations have validated shapes in `scalar_instruction_effects.py`.
These close explicit effects only, not values, CFG target association or callee
preservation. Opaque operations remain refused in generation and retained census
validation, even if their verdicts are relabeled.

```text
IR -> Alias -> Widening -> Types -> Structuring -> Rewrite
```

Semantic facts move left to right.  Do not introduce new semantics in rewrite.
If a late pass proves a fact, migrate that proof to the owning earlier layer and
leave the late pass as a temporary consumer only.

## Branch Execution Evidence

`frontend_cfg_direct_jump.py` supplies angr CFG discovery with the existing
native terminal-JMP theorem. It resolves only an exact loader-linear target
invariant across every selector capable of fetching that instruction head.
The execution VEX stays symbolic. Indirect or selector-dependent wrap targets
remain unresolved; discovering an edge proves neither callee effects nor
whole-function equivalence. Bootstrap registers only the x86-16 adapter and
preserves other resolvers.

Executable Jcc IR consumes architectural FLAGS or a proved producer in the
current lifted block. Address-only pending condition-transfer metadata may
describe another image or incoming path; it cannot replace the live FLAGS
predicate. A missing adjacent producer retains the FLAGS read. Condition
metadata for decompiler transfer and executable branch semantics have distinct
evidence requirements. Binary comparator controls must cover repeated lifts at
the same address with different bytes, both branch polarities, and preservation
of actual adjacent CMP behavior.

A direct CMP predicate does not replace CMP's FLAGS write. The following Jcc
consumes some status bits, while either successor can observe the complete
defined flag effect. Retain that effect at the cutpoint; remove earlier flag
writes only with independent overwrite-before-use evidence.

## Loader Address Projections

CLE's public `max_addr` is an absolute, inclusive loader-domain address,
including for the DOS MZ/NE blob backends. Derive an exclusive image bound as
`max_addr + 1`; do not add `linked_base` again. Object Clemory offsets are
relative: a read from offset zero uses the span `max_addr - linked_base + 1`,
not an absolute address as its byte count. Backing gaps still require checks.
Test doubles must model this contract rather than invent relative `max_addr`
semantics. These loader coordinates are not guest segment offsets and do not
justify flattening segmented program memory in recovered C.

## Validation Input Identity

Generation identity includes every function, codegen and project atom field.
Comparison may reuse tuple-pair work only after proving exact built-in immutable
value semantics; scalar or tuple subclasses retain native equality, methods and
exceptions. Keep memoization request-local with compared roots alive, preserve
builder-supported depth, and retain the original frozen field-tuple hash and
same-class protocol. A component cost fix is not end-to-end performance or
function-validation acceptance.
Preserve the installed dataclass's same-instance shortcut and direct field
comparison order: an outer tuple would skip shared scalar-subclass methods.

## Direct Clean-Worker Evidence Boundary

The direct CLI's canonicalized clean-worker lanes consume one finalized
caller-return evidence snapshot. Capture it after serial hydration, selected
target recovery and neighbor fast-probe preparation, before project transfer
and payload consumers. Preserve typed facts and UNKNOWN verdicts verbatim;
copy the mapping so later registry writes cannot change that request's payload.
An empty finalized map means no collected evidence, not permission to read
new facts from a later live registry. Earlier aborts do not consume the snapshot.
This transport boundary does not infer caller-use semantics or fix hint-free
pointer recovery; those remain with their existing semantic owners.

## Binary Caller Ranges and Signature Hints

`discovery_candidate_ranges.py` keeps signature-delimited recovery windows
separate from caller-census ranges. An optional signature address is not an
exclusive caller-body endpoint when the existing Frontend owner proves that
address belongs to the closed reachable body of the same project, entry and
bounded range. Remove only those individually proven interior delimiters;
retain every unreachable or unproven neighboring signature boundary.

The binary window is bounded by selected entries and startup/image limits.
Open reachability, foreign projects or stale extents authorize no expansion.
Library-body exclusion and candidate recovery bounds remain unchanged. This
boundary does not infer return type, signedness, pointers or argument values;
it prevents optional catalog hints from removing the binary census inputs.

## Layer Owners

`ir/indexed_induction_write_census.py` checks raw STORE effects over the
initializer-to-header preheader region and the whole loop. It binds exact
initializer/increment byte slices across earned SSA renaming, checks every
other write (including byte and unclassified writes), and refuses unknown
calls, BP/SS changes, block refusals and unproved cross-selector stores.
Frame writes are classified by architectural register-storage overlap, so a
32-bit EBP write invalidates the BP-relative lifetime just like a BP write.
Candidates retain a typed census with exact raw instructions, per-effect
verdicts, expected byte slices and checked/refused blocks. Five-counter
accounting retains every failed effect; completeness rechecks raw effects
instead of trusting a relabeled verdict. The explicit range collector and
fact completeness require this census to match the function, canonical
induction identity, exact initializer/increment byte slices and loop header/
blocks. Initializer dominance must be retained. Missing or mismatched evidence
refuses publication, including candidates supplied outside the SSA producer.
This does not establish a caller-bound address range or store disjointness.
Candidate generation also requires initialization to dominate the header.
Range completeness rejects access before the header guard and induction
loads after the latch increment; an old proven index may remain live after
the increment. No Alias storage widening or rendered-code repair occurs here.

`ir/indexed_address_range_witnesses.py` retains signed and unsigned comparison
relations separately. Zero-init/unit-step signed constant loops can publish
`[0, N)` only with an exact matching positive constant and compare width,
matching induction storage, and `N <= signed_max`. Thus the final increment
reaches the exit bound without crossing the sign bit. Dynamic, nonpositive,
width-conflicting and relabeled guards remain refusals. Pointer-relative
two-root addresses and caller-bound counts still require separate evidence;
this contract must not promote contextual counts to local constants.

`ir/memory_offset_word_value.py` binds a canonical memory operand to its exact
SSA use and composes one or two scalar-affine roots modulo 65536. Component
traces and closed evidence counts are retained and rechecked; distinct loads
are not merged merely because they name the same storage. This numeric low-word
projection proves neither full effective-address width nor segment equality,
object extent or saved-stack disjointness. Those remain consumer obligations.

`ir/direct_call_segment_context.py` retains a direct-call entry DS==SS theorem
with exact registered caller/callee coverage, decoded call index and Alias
source lineage. The segment-state solver may consume it only for that callee IR
object. Contextual state is request-local: default architectural live-ins and
project registries remain unchanged. Explicit segment writes and unproved CALLs
still replace/drop the equality. Generic segment-effect closure refuses these
contextual states rather than promoting one incoming call to a universal callee
preservation summary. Transitive propagation and caller-bound memory ranges are
separate obligations.

`segment_call_preservation_stage.py` resolves registered raw callee IR once per
target. A missing optional catalog can use closed mapped-entry Frontend bounds
and the normal IR segment-contract coverage owner; existing registry conflicts
remain refusals. Repeated calls and later refreshes reuse the retained raw
artifact rather than replacing equal-content objects and invalidating proofs.
Unproved/nested or nonreturning callees remain counted refusals, and an explicit
callee segment clobber cannot preserve caller equality.

`ir/no_effect_instructions.py` preserves native NOP instruction heads as explicit
IR evidence when their VEX mark spans contain no effects. Coverage authenticates
the mark coordinates, decoded extent, current loader bytes and fallthrough;
empty IR alone is never a no-effect proof. The scalar classifier and initialized
invocation simulator consume this evidence. Only immutable exact-byte lift facts
are cached (16 entries, at most 4096 code bytes and 2048 statement projections
per entry); live byte and provenance checks still run for every coverage query.
Larger blocks bypass caching. Unsupported or faulting empty spans remain refused.

`alias/saved_stack_store_window.py` owns the shared CFG-aware cross-selector
saved-byte lifetime guard. Both incoming-BP preservation and direct-call DS=SS
entry proof consume it. An unknown-selector store on a save-to-restore path
requires independent physical disjointness evidence; a saved SS word cannot be
treated as unchanged merely because the write is labeled DS or ES.

`alias/bp_preservation.py` owns closed-leaf incoming-BP preservation. It requires
exact registered IR/frontend coverage, consumes Alias-proven saved-byte lineage,
and propagates overlapping BP/EBP writes through every return path and loop.
Only entry-prefix saves before a BP write can restore incoming BP. A restore
address cannot authorize multiple writes; external effects, reentered entries,
unproved terminal exits and stale coverage refuse. Restore-dependent proofs also
refuse non-SS stores on CFG save-to-restore paths without cross-selector
disjointness: logical DS/ES names do not prove their runtime selectors differ
from SS. Stores outside the saved-byte lifetime are not clobbers; backedges
retain that lifetime when a later write can reach another restore. This is not a compiler ABI,
caller-target proof, stack-memory preservation or pointer representation proof.

`semantics/bp_call_preservation.py` binds that Alias result to mapped direct
near-call bytes, the exact return coordinate and the target's registered raw
IR. The Frontend may close the proven entry inside its mapped image without
optional function catalogs; open reachability still refuses. Production
caller-stack facts retain the proof/refusal, and the IR CALL target must agree
before BP preservation is projected. This authorizes only word BP transport,
not caller memory, segment equality, pointer provenance or a recovered ABI.

Near-return C operand binding is owned by
`lowering/near_return_c_ast_congruence.py`. It consumes the retained exact
modular-return IR proof and canonical stack-variable identities. A congruent
result proves only the original operand's 16-bit affine bit pattern, not native
pointer representation, pointee type, DS=SS, or a publishable C return. All
registered raw/unified variable views must agree; unknown views and unsupported
numeric operations refuse without mutation. The stored result rechecks its
callee, coefficients, storage and canonical projections. Pointer publication
must separately establish input/result segment views and atomically update
the body, declaration, prototype and caller projections.

| Layer | Owner paths | Owns |
| --- | --- | --- |
| Frontend | `angr_platforms/angr_platforms/X86_16/`, `angr_platforms/angr_platforms/X86_16/lift_86_16.py` | arch, loader/lift hooks, instruction facts |
| IR | `X86_16/ir/` | typed `Value`, `Address`, `Condition`, instruction facts |
| Semantics | `X86_16/semantics/` | instruction effects, flags, branch meaning |
| Alias | `X86_16/alias/` | storage identity, stack/global alias proof |
| Widening | `X86_16/widening/` | proven byte/word/pointer joins after alias |
| Types and Lowering | `X86_16/lowering/`, `type_*.py` | stack/global object materialization, callsite facts, segmented memory lowering |
| Structuring | `X86_16/structuring/`, `decompiler_structuring_stage.py` | CFG shape, loops, switches, structured condition lowering |
| Rewrite/Postprocess | `X86_16/postprocess/`, `decompiler_postprocess_*.py`, `decompiler_postprocess_stage.py` | formatting, cleanup, validation-gated compatibility consumers |
| Validation | `X86_16/tail_validation*.py`, `validation_*.py` | semantic equivalence checks and honest failure reporting |
| CLI | `inertia_decompiler/` | orchestration, fallback choice, reports, timeouts |

Per-module evidence, ownership, and consumer facts for each layer live in
[`decompiler-evidence-owners.md`](decompiler-evidence-owners.md); consult that
guide for the relevant semantic consumers before editing.

## Callee-Bound Modular Input Evidence

`lowering/modular_argument_type_facts.py` consumes the existing IR modular-use
proof through the registered Semantics SSA artifact. It binds a census stack
word to one proven logical read in the exact selected callee; a matching BP
offset in another callee is not evidence. The original census address retains
its segment-proof status rather than being relabeled as proven.

Only a complete five-stage proof can supply `SIGN_INSENSITIVE` scalar `VALUE`
typing when condition interpretation is absent. Pointer classification and
condition conflicts retain priority. Unknown boundaries, SSA, access identity,
or callee mismatches remain typed refusals. This evidence establishes modular
word behavior, not original C signedness, pointer provenance, segment/pointee
identity, or a return expression. The production collection owner shares one
lazy proof cache across its callee's callsites. Routine regressions live in
`test_x86_16_modular_input_type_join.py`.

## Never Fix Here

- Do not add semantic recovery to `decompiler_postprocess_jcc.py`.
- Do not add call argument/signature/body repair to postprocess or CLI.
- Do not add stack identity, global identity, or type recovery to rewrite.
- Do not add behavior to root compatibility shims such as `alias_model.py` and
  `alias_domains.py`.
- Do not recover semantics from rendered C, assembly text, or regex matches.

## Compatibility Debt

Root `decompiler_postprocess_*.py` files are guarded compatibility bridges.
Their headers say what they may consume and where their debt must move.  The
current debt is also visible through:

- `angr_platforms/angr_platforms/X86_16/decompiler_postprocess_inventory.py`
- `reference/layer-module-status.md`
- `reference/decompiler-fix-plan.md`

Adding a new semantic-looking postprocess pass must also update the inventory,
evidence counters, owner layer, and tests.  Unknown proof means keep the ugly
code and let validation report the missing fact.

## Gate Tiers

Run the fast tier while editing and before handing off ordinary decompiler
changes. The fast tier is unit-focused only; external compiler/decompiler smoke
lanes belong to the default and expanded tiers:

```bash
make check-files PYTHON=./.venv/bin/python FILES="path/to/file.py path/to/test.py"
make quality-fast PYTHON=./.venv/bin/python
make test-pipeline-fast PYTHON=./.venv/bin/python
```

Run the default tier before claiming a semantic decompiler improvement:

```bash
make test-pipeline PYTHON=./.venv/bin/python
```

Run the expanded tier for broad architecture/status audits and slower SORTDEMO
or corpus work:

```bash
make test-pipeline-expanded PYTHON=./.venv/bin/python
```

`make architecture-check PYTHON=./.venv/bin/python` is the ratchet for future
agents. It checks postprocess guard headers, protected import exceptions, root
compatibility shims, CLI imports, runtime guard entrypoints, documentation
markers, ownership manifests, and docs/types/dot-access ratchets. If it fails,
either move the work to the correct layer or explicitly update the architecture
allowlist with a documented migration reason and regression.

## Function Fix DoD
A fixed function needs all of:

- focused before/after regression evidence;
- `validation=passed`;
- no semantic call loss;
- output closer to original C/COD source when source exists;
- MS C tiny/full pipeline coverage when the case is represented there.

Passing recompilation by deleting live code is a failure, not a fix.

`frontend_cfg_direct_jobs.py` submits source-proved default native JMP and near-CALL targets as direct angr CFG jobs. The CALL adapter consumes the existing near-call target-binding theorem and binds the supplied discovery operand and producer DAG to native bytes. This preserves direct-edge function membership while retaining symbolic execution VEX and ordinary function-boundary heuristics; unsupported, selector-dependent, indirect, far and flat32 transfers keep their existing paths. The condition/register provenance cohort owns the cross-block acceptance controls.

`ir/entry_jump_domain.py` proves a narrower function-entry fetch domain for
retained word near JMPs. It requires closed reachable paths, typed effect
classification, unchanged CS identity, and native byte/next-expression binding.
The importer applies the result only to the proved root and complete block
surface, checks each admitted target and closed accounting, and clears only
the discharged selector-window refusal. Missing, stale or unsupported evidence
retains the transfer and refusal. A block-only importer has no function-entry
premise. `test_x86_16_entry_jump_domain.py` owns the routine native, mutation,
budget and exception controls; this theorem alone is not binary equivalence.

`ir/real16_invocation_domain.py` proves a numeric CS domain for one exact
near-CALL under a source-derived initialized MZ invocation. It rederives
header and relocated module bytes through the shared Frontend MZ authority,
binds every simulated IR field to native effects, joins loop/predecessor
states, and checks stores against all fetched caller/callee bytes. Unknown
effects, addresses, calls and exhausted budgets refuse with closed counts.
The call-target and segment-context consumers retain only a premise actually
used by the target proof; this local invocation does not become universal
function equality or an inferred chained-callee premise. Native MZ, register
lane, source mutation and unused-premise controls are routinely enrolled.
