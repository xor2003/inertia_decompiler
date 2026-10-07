# DOS Unit SSA Block Equality Plan

## Goal

Make SSA/Z3 comparison compositional:

1. Prove small blocks/regions first.
2. Cache those proofs as semantic facts.
3. When a caller block calls a callee already proven equal, normalize the call to the same semantic callee summary even if the call address differs.
4. Prove larger functions by composing equal blocks/regions and checking that block outputs feed successor inputs consistently.

This is intended to reduce whole-function Z3 formulas, especially for functions with many branches or calls.

## Current Implementation Status

Implemented:

- in-run semantic equality proof cache for successful SSA comparisons;
- fixed-point retry for caller blocks/functions waiting on callee proofs;
- default refusal of mapped/name-equivalent shifted direct calls until the callee is proven equal;
- direct-call normalization after callee proof, so call address drift does not become an observable mismatch;
- visible compare/report fields for callee proof facts and unproven-callee refusals;
- conservative direct-successor connectivity gate for already-paired SSA blocks;
- direct branch successor transfer metadata from VEX lowering;
- automatic `ip` observable on direct branch blocks so branch predicates are compared by SSA/Z3;
- refusal for externally supplied conditional SSA blocks that omit `ip`;
- ABI `ssa_call_policy: summary` for declared callees:
  - match direct call targets by raw/low16 address or single unambiguous summary;
  - disambiguate repeated same-target call sites by `target_ordinal`, global call ordinal, or explicit call-site entry/delta fields;
  - support indirect calls when the summary is pinned by explicit call-site entry/delta fields;
  - support recovered indirect target sets through `target_candidates` on the SSA transfer and list-valued summary selectors such as `target_low16s`;
  - capture declared register and stack arguments as ABI summary outputs;
  - apply declared return registers as symbolic call outputs;
  - apply declared clobbers/preserves;
  - model near/far return-address stack cleanup;
  - apply simple declared memory stores to concrete segmented offsets;
  - apply declared broad memory clobbers by replacing caller memory with a fresh callee-summary memory token;
  - apply declared range-limited memory clobbers only to the described segmented byte range, leaving unrelated memory comparable;
- fixed ABI input-substitution cache scope so separate output expressions cannot corrupt each other through Python object-id reuse;
- direct-successor connectivity checks:
  - verify paired successor identities;
  - refuse conditional direct-successor blocks that do not expose `ip`;
  - refuse direct edges where a successor reads state that the predecessor did not expose as an output;
  - prove exposed successor-input state with a small edge-local Z3 check and report checked edge/input counts;
- conservative raw `compare-ssa` acyclic region equality:
  - composes multi-block SSA groups into a compact function-region summary;
  - compares composed register outputs and whole memory when raw SSA has a memory output;
  - records passed region proofs as function-scope semantic equality facts;
  - lets caller blocks normalize shifted call targets through region-proven callee facts;
  - marks block-layout failures as `covered_by_region_equal` only after the composed proof passes;
  - refuses direct-successor composition when `ip` is not observed;
  - refuses loops by default unless `--max-region-loop-unroll` is raised;
  - prunes constant branch conditions only in raw region equality, where the synthetic contract makes SSA input registers symbolic;
  - refuses raw region summaries as `loop_bound_incomplete` when a symbolic path hits the loop bound;
  - exempts region-proven functions from direct block-connectivity failure, because the composed function proof is stronger than same-successor-shape matching;
- visible `report-failures` section for failed/refused function-region proofs;
- failed/refused region reports include entry addresses and an instruction preview for both sides;
- conservative CFG loop-SCC detection over paired direct-successor blocks:
  - reports cyclic SCCs separately from acyclic region equality;
  - marks SCCs passed only when every member block/edge proof already passed;
  - does not infer arbitrary loop invariants.
- conservative direct call-graph SCC detection:
  - reports recursive/mutually recursive cycles from resolved direct calls;
  - marks SCCs passed only when member results already passed;
  - reports unproven/refused member cycles without assume-guarantee inference.
- CLI switches:
  - `compare-ssa --semantic-proof-passes N`;
  - `compare-ssa --disable-callee-lemmas`;
  - `compare-ssa --disable-region-equality`;
  - `compare-ssa --max-region-loop-unroll N`.

Still planned:

- broader whole-function connectivity proof across reblocked regions and join-state equivalence;
- close the remaining F-15 `egame.exe` connectivity proof gaps from `/tmp/egame.current39.root_causes.md`:
  - classify and handle successors that leave the catalogued function range as shared tails, tail calls, or cross-function helper jumps instead of same-function CFG edges;
  - force explicit SSA target splitting for in-range branch successors that are inside the function range but were not emitted as block entries or lowering refusals;
  - improve VEX/compact-SSA coverage for REP/REPNE string-instruction blocks (`rep movs/stos`, `repne scas`) that currently produce `incomplete_block`;
  - add adaptive relift/gates for assignment-limit and block-limit targets before reporting connectivity refusal;
  - keep these as typed connectivity proof gaps until the above handling proves the edge, never as semantic failures;
- symbolic CFG loop invariant summaries;
- recursive call-graph SCC assume-guarantee proofs.

## Core Rule

A block containing a call is equal if:

- non-call instructions are binary equal, canonical SSA equal, or Z3 equivalent;
- direct call targets resolve to equivalent semantic functions through mapping/aliases/proof cache;
- call ABI summaries match:
  - argument locations and widths;
  - return registers;
  - preserved and clobbered registers;
  - stack delta;
  - declared memory effects;
- pre-call argument expressions are equal;
- post-call continuation state is equal after applying the same callee summary.

The raw call address is layout noise once the target function semantic identity is proven.

## Equality Lattice

Use the strongest cheap proof available first:

1. `binary_equal`
   - Same normalized loaded bytes.
   - Fast pass. No Z3.

2. `ssa_equal`
   - Same canonical SSA payload after:
     - temp/ref renaming normalization;
     - layout normalization;
     - direct call target normalization;
     - relocation/code-pointer normalization.

3. `z3_block_equal`
   - Same block transfer function.
   - Calls are replaced by mapped/proven callee summaries.
   - Compare declared block outputs, branch condition, memory effects, stack delta.

4. `region_equal`
   - Acyclic region composed from multiple blocks.
   - Used when CFG shape differs but the region has the same entry and exit contract.

5. `function_summary_equal`
   - Compare ABI-level function summary.
   - This remains final semantic gate when block/region facts are insufficient.

6. `refused`
   - Unknown indirect call/jump.
   - Missing callee summary for semantically relevant call.
   - Unbounded memory alias.
   - Loop/region exceeds configured bound.
   - Z3 timeout.

Never treat a refused block as equal.

## Data Model

Add an internal proof fact:

```json
{
  "kind": "semantic_equality_fact",
  "scope": "block|region|function",
  "oracle_id": "ssa-function:...",
  "candidate_id": "ssa-function:...",
  "oracle_function_id": "egame.exe:foo",
  "candidate_function_id": "egame.exe:foo",
  "proof": "binary_equal|ssa_equal|z3_block_equal|region_equal|function_summary_equal",
  "observables": {
    "regs": ["ax", "sp"],
    "memory": []
  },
  "abi": {
    "calling_convention": "msc16-near",
    "returns": ["ax"],
    "preserved": [],
    "clobbers": ["ax", "cx", "dx", "flags"],
    "stack_delta": 2
  },
  "call_summary_hash": "sha256..."
}
```

The proof cache is not a trusted input by default. It is built during the current compare run from actual successful comparisons. Later disk cache can store these facts only with executable hashes.

## Implementation Steps

### 1. Semantic Proof Cache

Add `SemanticEqualityCache` in `tools/dosunit/compare/straightline_ssa.py` or a small adjacent module if it grows.

Responsibilities:

- record successful block/function equality;
- answer whether an oracle function target and candidate function target are already proven equivalent;
- expose a stable semantic target key for call normalization;
- keep proof reason and summary details for reporting.

Cache keys:

- primary: `(oracle_function_id, candidate_function_id)`;
- aliases: `(oracle_name, candidate_name)`, mapped ids, mapped names;
- address aliases only after `_resolve_call_target` proves a unique target.

### 2. Worklist Order

Current `compare_ssa_documents` walks SSA parts in file order. Replace or augment with a staged worklist:

1. Compare leaf/non-call blocks first.
2. Record passed proofs.
3. Revisit call blocks whose callees are now proven.
4. Iterate until no new facts are added.
5. Emit remaining unresolved blocks as refused with reason:
   - `callee_not_proven`;
   - `call_target_unresolved`;
   - `call_abi_mismatch`;
   - `call_argument_mismatch`.

Do not require topological perfection. A bounded fixed-point is enough:

```text
for pass in range(max_proof_passes):
    changed = compare all unresolved blocks using current facts
    if not changed: break
```

Default `max_proof_passes`: 4.

### 3. Call Target Normalization With Proof Facts

Extend `_compare_call_targets` / `_call_targets_equivalent`:

- current behavior:
  - direct address equal;
  - mapped target equal;
  - alias equal;
  - semantic hash equal.

- new behavior:
  - if `(oracle_target_function, candidate_target_function)` is in `SemanticEqualityCache`, return equivalent with reason `callee_proven_equal`;
  - normalize call target output to a shared semantic token:

```text
call_target = semantic_call:<oracle_function_id>|<candidate_function_id>|<proof>
```

This lets all other block SSA remain byte/layout independent.

### 4. Call Summary Replacement

For proven callees, replace the call effect with a compact summary instead of expanding the callee:

- consume argument expressions;
- produce return registers;
- apply stack delta;
- preserve declared preserved regs;
- mark declared clobbers as summary outputs when observable;
- apply memory effects only when declared and modeled.

Initial scope:

- near/far stack delta;
- AX/DX return regs;
- SP canonicalization;
- declared memory effects;
- no broad arbitrary memory arrays unless already present in observables.

If the callee proof has no compatible ABI summary, refuse the caller block as `callee_summary_missing`.

### 5. Block Connectivity Check

Add an optional function-level composition check that uses block facts:

For every reachable edge:

- branch predicate in oracle and candidate is equivalent after normalization;
- successor semantic identity is equivalent:
  - same block delta, or
  - region mapping says equivalent exit, or
  - both return;
- values required by successor inputs are produced by predecessor outputs with equal expressions.

Represent as a report section:

```json
{
  "connectivity": {
    "status": "passed|refused|failed",
    "edges_checked": 12,
    "edge_failures": []
  }
}
```

Initial implementation can be conservative:

- check only direct conditional/unconditional successors;
- refuse indirect jump/call;
- skip unreachable blocks;
- do not guess block matching if mapping/delta is ambiguous.

### 6. Region Equality

Add acyclic region construction as a second phase after block proof cache exists.

Region candidates:

- single entry;
- exits are return/call-boundary/direct branch targets;
- no loop unless `max_loop_unroll > 0`;
- bounded by assignment/input/store gates.

Region proof:

- compose SSA summaries;
- normalize calls via proof cache;
- compare region outputs/branch exits via Z3.

This is the fallback when individual blocks differ but the composed region is equivalent.

### 7. Reporting

Reports must show why a block/function passed or refused:

- `proof`: `binary_equal`, `ssa_equal`, `z3_block_equal`, `callee_proven_equal`, `region_equal`, `function_summary_equal`;
- normalized call target:
  - oracle raw target;
  - candidate raw target;
  - resolved oracle callee;
  - resolved candidate callee;
  - proof fact used;
- call ABI summary;
- block/region counters:
  - assignments;
  - inputs;
  - memory stores;
  - branch merges;
  - loop cuts;
- refusal reason.

No report should say only “target differs” when the targets map to already proven equivalent functions.

### 8. CLI Gates

Implemented options on `compare-ssa`:

```text
--semantic-proof-passes N       default 4
--disable-callee-lemmas
--disable-region-equality       default off; region equality is enabled
--max-region-loop-unroll N      default 0
--max-solver-assignments N      default 128
--max-solver-inputs N           default 16
--max-solver-memory-stores N    default 15
```

Keep existing behavior available for debugging:

```text
--disable-callee-lemmas
--disable-region-equality
report-failures --show-unresolved-call-targets
```

### 9. Tests

Unit fixtures:

1. `call address shifted, callee binary equal`
   - callee bytes equal at different addresses;
   - caller block differs only by call immediate;
   - caller block passes via `callee_proven_equal`.

2. `call address shifted, callee SSA/Z3 equal`
   - callee instructions differ but SSA/Z3 proves equal;
   - caller block passes via callee lemma.

3. `call argument mismatch`
   - same proven callee;
   - caller passes different argument expression;
   - caller fails/refuses with `call_argument_mismatch` or observable mismatch.

4. `call ABI mismatch`
   - target functions equal as raw body but ABI summaries differ;
   - caller refuses `call_abi_mismatch`.

5. `unresolved call target`
   - direct target not found;
   - skipped by default if configured;
   - visible with unresolved-call flag.

6. `block connectivity`
   - all blocks individually equal;
   - one branch edge goes to different semantic successor;
   - function connectivity fails.

7. `region equal`
   - oracle and candidate have branch blocks whose successor block values are swapped by inverted conditions;
   - block-by-block proof fails;
   - composed region proof passes and covers the block-layout mismatch.

8. `region mismatch`
   - same reblocked branch fixture;
   - one terminal value is changed;
   - composed region proof fails and is visible in `report-failures`.

9. `constant bounded loop`
   - manual SSA loop with a constant trip count;
   - default loop bound refuses;
   - bounded raw region proof prunes constant branches and passes without loop cuts.

10. `symbolic bounded loop cut`
   - manual SSA loop with symbolic trip count;
   - bounded raw region proof reaches the loop cut;
   - result refuses as `loop_bound_incomplete` and is visible in `report-failures`.

11. `region-proven callee`
   - caller block calls a shifted rebuilt callee;
   - callee entry block is not block-equal but the function region is equal;
   - retry pass proves the caller through the function-scope region proof fact.

Integration fixtures:

- MS C tiny examples:
  - compare16 still all pass;
  - loops still refuse with `z3_unknown` until region/path splitting improves;
  - call fixture with shifted function addresses must pass.

## Definition Of Done

- A caller block whose only semantic difference is a shifted direct call to an already proven equal callee passes without comparing raw call addresses.
- The report explicitly says `callee_proven_equal` and shows both raw targets plus resolved function names.
- Caller blocks still fail/refuse when arguments, ABI, stack delta, or relevant memory effects differ.
- Function-level reporting can distinguish:
  - block proof success;
  - callee lemma success;
  - connectivity failure;
  - region proof success;
  - Z3 timeout.
- Existing full dosunit tests pass.
- MS C compare16 gate still proves all current functions.
- Loop-heavy symbolic functions remain honest typed refusals unless a later SCC/invariant proof handles them.

## Non-Goals For First Pass

- Recursive call-cycle proof.
- Indirect call target recovery beyond existing aliasing.
- Full memory-array equivalence for unknown callees.
- Proving arbitrary loop invariants.
- Trusting disk proof cache without executable hash validation.

## Cycle Ideas

Cycles appear in two different graphs and should be handled differently:

1. CFG cycles inside one function.
2. Call graph cycles between functions.

### CFG Cycles

Initial rule:

- never treat a cut loop path as a real function return;
- only compare paths that reach a real terminal within the unroll bound;
- report `loop_cuts`, `terminal_count`, and `z3_unknown` honestly.

Useful tricks:

- **Zero-iteration and one-iteration summaries**
  - Build separate summaries for:
    - loop not entered;
    - loop entered once;
    - loop entered up to `N`.
  - This often proves guard/setup equivalence without full invariant solving.

- **Backedge-local proof**
  - Compare only the loop body transfer:
    ```text
    loop_state_in -> loop_state_next
    ```
  - If oracle and candidate loop body have the same transfer and the same exit predicate, avoid expanding many iterations.

- **Counter/range recognition**
  - Detect common induction forms:
    ```text
    i = i + 1
    i = i - 1
    while i != 0
    while i < bound
    ```
  - Summarize as a bounded counter relation when the body is otherwise straight-line.

- **Widened loop summaries**
  - For simple accumulators, produce a symbolic summary:
    ```text
    acc_out = acc_in + k * n
    i_out = limit
    ```
  - Only when the induction variable, bound, and no-alias memory effects are proven.

- **SCC region refusal**
  - If loop has unknown memory writes, indirect control, or unmodeled calls, refuse the SCC as `loop_summary_missing`.
  - Do not let Z3 see a huge unrolled ITE tree by default.

### Call Graph Cycles

Initial rule:

- do not use a callee lemma for recursive/mutually recursive calls unless a summary fact already exists from a previous trusted run with matching executable hashes;
- otherwise refuse the cycle as `call_cycle_unproven`.

Useful tricks:

- **SCC fixed point**
  - Group functions into call-graph SCCs.
  - Prove leaf SCCs first.
  - For recursive SCCs, start with an uninterpreted summary token and refine until no observable summary changes.

- **Assume-guarantee proof**
  - Assume oracle/candidate recursive calls are equivalent under the same ABI summary.
  - Prove each function body preserves the assumption.
  - Accept only if all functions in the SCC close the proof.

- **Depth-bounded recursion**
  - Unroll recursive calls to depth `N`.
  - Treat deeper calls as cut paths, not returns.
  - Report recursion cuts separately from CFG loop cuts.

## Branch Tricks

The branch problem is usually formula growth, not instruction support. Useful tactics:

- **Predicate normalization**
  - Normalize common flag-derived branches directly:
    ```text
    cmp ax, imm; je  -> ax == imm
    cmp ax, imm; jb  -> ULT(ax, imm)
    test ax, ax; jz  -> ax == 0
    ```
  - Prefer branch predicates over individual flag materialization.

- **Edge-local proof**
  - Before composing a whole branch tree, prove corresponding edge predicates equal.
  - If predicates and successor identities match, cache the edge as equal.

- **Path splitting**
  - Instead of one huge `ite` expression for all exits, compare one exit path at a time:
    ```text
    assume path predicate
    prove observable equality on that path
    ```
  - This avoids a single giant `Or(output differs)` over all nested branches.

- **Dominated-output pruning**
  - If a branch only affects a register/memory location that is not observable and not used later, drop it from the solver slice.
  - Keep a structured `pruned_unobservable` counter.

- **Common-tail factoring**
  - If both branches rejoin at the same successor, compare branch-specific prefix first, then compose one shared tail once.
  - Do not duplicate the tail into both ITE arms.

- **Branch table canonicalization**
  - For jump tables/switches:
    - normalize case values;
    - compare target semantic identities;
    - refuse only unresolved/ambiguous cases.

- **Condition implication checks**
  - For reordered tests, prove:
    ```text
    oracle_path_condition <=> candidate_path_condition
    ```
  - Then compare bodies under that condition.

- **Early SAT counterexample**
  - Ask Z3 first for branch predicate mismatch before comparing all outputs.
  - If predicates differ, report branch mismatch immediately with concrete input.

- **Balanced branch budgets**
  - Use separate gates:
    - max branch merges;
    - max terminal paths;
    - max path predicate depth.
  - A small assignment count can still be hard if terminal paths explode.
