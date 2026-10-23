# Comparator orchestration

External-call catalog entries optionally declare `"memory_access": "none"`.
The default is `"arbitrary"`. `none` asserts that the returning external
operation does not read or write program memory beyond reading its declared
ABI argument/return slots. It does not dereference pointer arguments. Opaque
results and ordered external history depend on argument values and incoming
external history; all program bytes are preserved. This explicit stronger
environment premise is never inferred from an API name. It is not purity:
calls, call order, changed arguments and external history remain observable.
The premise is published and any proof using it remains conditional. Use of
the default arbitrary-memory model is unchanged. Final private-stack lifetime
projection remains a separate ABI premise.

The MSC8 global relocation map also includes ordinary C data names when an
original data-section definition and a decorated public in the verified MSVC
LINK map agree on the name. Both coordinates must be mapped non-executable
data, and the candidate map segment must be DATA. Conflicting original names
or candidate coordinates reject intake. This extends the existing address-label
correspondence; neither a name nor a declaration's `dd` spelling proves type,
extent or initial-memory equality. The resulting relocation remains conditional.

MSC8 leaf and matched-CFG reports include `proof_contract.global_layout_check`
for the selected global normalization map. It checks injective original-address
order and equal adjacent spacing with signed integer arithmetic. Checking the
sorted adjacent pairs establishes these properties for all mapped positions
without a quadratic pair comparison. The report retains each checked gap, a
canonical map hash, and the uniform displacement when one exists. An empty or
single-position map is `incomplete`; changed order, collapsed addresses or
changed spacing is `mismatch`. Such a mismatch is a layout fact, possibly due
to padding or a wrong mapping, not a function counterexample.

This partial scope never changes proof verdicts. `checked` does not establish
object sizes/types, coverage of unmapped globals, initial bytes/pointer values,
loader relocations or preservation through writes and external calls. Those
obligations remain listed explicitly. Existing image/map/source seals bind the
enclosing comparison report. Normalization itself remains a conditional premise.

When a table target lacks a strict proof and the report already declares global
normalization, `normalized_target_checks` separately compares its effects under
that exact map. Successful target comparisons are `conditional`; the full map
and its canonical hash remain explicit unproved premises. Strict target checks
and function verdicts stay intact. This reuses value relocation, not a derived
live-memory/alias relation, and cannot currently promote a table function.
Noninjective maps produce explicit incomplete evidence. Renamed symbols absent
from the original map are not guessed from neighboring addresses.

Automatic table discovery can also prove complete read-accessor switches under
explicit live-global premises. Every target must be exactly unprefixed i386
`MOV EAX,moffs32; RET` with matching near-return encoding. Prefixes must
preserve all memory; all existing prefix-state, index-range, default-path,
table-order and selected-root checks still apply. Each paired DWORD read adds
a published equality of its four live bytes at root entry. A union-find check
proves these equalities jointly satisfiable with both initial tables, including
overlapping ranges and transitive equalities. Unsupported effects, wraparound,
changed return pops and inconsistent premises do not earn credit. The result
is `conditional`, with method `single_switch_read_accessors`; runtime
initialization and preservation before root entry remain unproved assumptions.
The strict refused result and target evidence remain available. This proof
uses literal native addresses and does not require global constant rewriting.

The MSC8 driver accepts `--table-check-catalog FILE` to include these partial
checks directly in `compare.json`, both beside each selected function and in
the top-level `partial_table_checks` summary. The catalog schema is
`comparator.target_table_catalog.v1`; `functions` maps original listing names
to lists of entries with `original_table`, `candidate_table`, `original_count`,
`candidate_count` and `target_pairs`. Each pair has `original` and `candidate`
addresses. Optional `original_dispatch` and `candidate_dispatch` must appear
together. Addresses accept integers or `0x...` strings. Each function admits
1–32 tables, each with 1–4096 entries. Unknown function names are rejected.
Catalog and image digests are checked against the function report; changing
the catalog during the run invalidates attachment. Checks outside the selected
function set are retained and explicitly listed. By default full-function
statuses and coverage remain unchanged; `checked` describes the published
partial scope, even when the full function remains `refused`.
An entry can opt into `"check_returning_targets": true`: each unique non-null
mapped target used by the original table is compared by SSA/Z3 over equal
incoming modeled state. This admits acyclic direct and conditional paths ending in return
(at most 16 block visits, 128 decoded bytes per block and two seconds of composition
per side), observes all modeled registers,
memory and return control, and retains per-pair solver results. A mismatch is
local to that entry-state relation, not a root-function counterexample.
Conditional paths merge all output state under their exact guards, including
memory and return addresses. Effects after an early exit are not admitted.
Direct native calls are inlined within the same block-visit and wall limits.
The shared call engine's return-target lemma must prove every callee RET
reaches that CALL's fallthrough before the caller continues. All callee
register/memory effects, including the actual pushed return address, remain
observable; this does not assume ABI-private stack or normalize code pointers.
Call sites and proved return targets are retained, and return-proof failures
include the solver evidence. Recursion, indirect calls, cycles, unsupported effects and unresolved flag reasoning remain
`incomplete`. Proving that the original dispatch and rebuilt dispatch deliver
the required matching entry states remains a separate pending condition.
An entry can additionally request `"check_rooted_targets": true` with both
root entries and dispatch sites. `rooted_target_checks` composes each native
prefix into its target continuations before comparing final effects. The root
ESP domain then constrains root inputs, including in nested return proofs;
it is never reinterpreted as an interval on the shifted target-entry ESP.
This evidence is retained separately and cannot promote a function or replace
the strict target checks. Observations are restricted to the exact prefix
condition reaching dispatch; equality of that condition is itself proved.
Callee return-address checks remain unrestricted. Exact per-slot selection
guards are still pending, so a mismatch may concern another table slot. Default-path coverage, dispatch target selection and
table initialization/preservation remain explicit pending obligations.
Supplying `original_entry` and `candidate_entry` together with the dispatch
sites enables a `prefix_check`. It compares up to 128 bytes of single-block
prefix code, preserving all modeled data state and the branch decision between
dispatch and paired default edges. Only terminal control addresses are renamed
to shared edge tokens; data constants and branch conditions remain literal.
The catalog also checks the unsigned index domain on both sides: reaching the
dispatch must imply `index < declared_count`. With `check_returning_targets`,
paired default continuations are checked as returning blocks too. Each condition
is removed from the prefix's pending list only when its own check succeeds;
mismatches and incomplete obligations propagate to the partial aggregate.
The prefix also proves table-memory preservation, first attempting equality of
the whole memory array, then comparing the declared DWORD slots with exact
read-over-write reasoning. Unknown-pointer writes that may hit the table fail
this obligation; unrelated writes are allowed. This establishes preservation,
not initial contents. At report attachment the declared entries are checked
against the actual selected function coordinates in `function_ranges`.
With an explicit `"assume_initial_tables": true`, a single-table function can
become `conditional` when all of these lemmas succeed: selected root entries,
equal prefix state/control, bounded index, preserved table memory, actual
indexed JMP operands, all table targets and all default continuations. This
currently covers single-block prefixes and straight-line returning targets.
The exact original and candidate tables are published as root-entry memory
premises. Both must fit consistently in the shared input memory array; any
conflicting byte rejects composition, preventing vacuous proofs. This does
not prove actual loaded-image memory equality or runtime relocation.
The previous refusal is retained as `strict_function_result`. The conditional
result goes through normal proof accounting and contributes only to conditional
coverage. Calls, missing lemmas, changed targets and multiple table entries per
root catalog item group remain unpromoted. Catalog, binary and comparator source
identity are sealed together, including the table-lemma computation.
An existing `--entry-esp-range` premise is transported into root-prefix state,
index-domain and table-preservation proofs, and retained in the conditional
function's assumptions. It is never applied to independent target/default
entry states: the prefix may already have shifted ESP. A supplied range that
overlaps the table does not waive alias checks; an absent range adds no premise.

Partial target-table checks are available through
`python -m tools.comparator.table_check_cli --help`. Supply both PE images,
preferred-image table VAs, declared entry counts, a JSON target-pair list
(`[{"original":"0x...","candidate":"0x..."}]`) and an output path.
The tool checks exact file-backed DWORD contents, entry counts, slot order,
repeated targets and null slots against that correspondence. Numeric code
placement may differ, and explicitly mapped many-to-one targets are allowed.
Image and map hashes bind the report to the checked inputs.

Optional paired `--original-dispatch VA --candidate-dispatch VA` checks bind
the declared tables to actual executable bytes. Supported encodings are the
unprefixed seven-byte i386 near `CALL/JMP [index*scale+disp32]` forms without
a base register. The report checks each displacement against its table,
DWORD stride, transfer kind and matching index-register names. Other forms
produce explicit `incomplete` dispatch evidence. Different register names
are a structural mismatch that a future relational proof may resolve, not
a behavioral counterexample. Equal names still require equal live values.
Instruction-boundary reachability, bounds and runtime preservation remain
pending; the sites and table extents are currently declared inputs.

Outcomes are `checked`, `mismatch` and `incomplete`, never proof refusals.
They belong to the separate `declared_serialized_table` scope: no outcome
changes whole-function verdicts or earns function-proof coverage. A mismatch
may also expose an incorrect declared map, rather than a behavioral defect.
The report retains every slot and the still-pending conditions: binary-derived
extent/dispatch binding, target behavioral equivalence, index/domain equality,
bounds/default behavior, relocation/live-memory preservation and other pointer
observations. Target correspondence is declared, not a semantic certificate.
Automatic discovery, SSA integration and discharge of these conditions remain
future work; this command deliberately makes the useful partial checks runnable
before the full proof lane supports table dispatch.

The MS C tiny-example adapter is `compare_msc6_ssa_examples`. Run
`python -m tools.comparator.compare_msc6_ssa_examples --help` for its existing
report and comparison options. The historical script aliases this owner.
Compiler-header integration remains in `tests/integration/`.

`services.py` exposes typed `NativeProofOwners` through qualified imports.
It does not load backend modules until requested. Shared region, loop and
macro helpers use these owners without artifact modules or `sys.path` state.
`native.py` derives the model view from the existing SSA/architecture owners;
`abi.py` owns the unchanged shared default observation contract. Explicit
function output contracts remain caller-selected.

MSC8 `matched-cfg` accepts `--abi-observation-catalog FILE` for explicit
per-function scalar ABI premises. The JSON schema is
`{"schema":"dosunit.flat32_abi_observation.v1","functions":{"sub_401000":{"return_bits":32,"private_stack_bytes":16}}}`.
Return widths are 0 (void), 8, 16, 32 or 64 (EDX:EAX); floating and aggregate
returns are not covered. Unlisted functions retain strict observations.
The catalog is hashed and rechecked as an auxiliary proof input. The original
strict CFG result is retained as `strict_cfg_result` in each selected row.

The ABI projection currently applies only after complete acyclic call/region
composition has proved root returns. It does not relax internal loop states,
callee return checks, environment gates or incomplete lowering. Final memory
comparison excludes the shared union of explicitly written stack bytes within
the declared below-entry-ESP extent (at most 8192 bytes). Every executed load
and store remains in the original memory array, preserving aliases and effects
that reach return values, public memory or external events. Excluded cells are
assumed inaccessible after return, including through escaped pointers; this is
a published lifetime premise, not inferred non-escape evidence. Successful
projected results are always conditional. This option is not an imported-API
model and does not by itself resolve unknown calls or switch targets.

`profiles.py` owns target successor-admission policies. Both CLIs consume these
qualified policies and the native model view directly; compatibility adapters
retain aliases. Declared-bound and executable-section admission remain distinct.

`verified_pe.py` owns BC5's bounded, content-verified PE relocation cache and
uses the shared image loader. Certificates include loader implementation hashes;
the historical module aliases the exact owner, preserving cache-test injection.

`bc5_region.py` and `msc8_region.py` own the existing target region policies.
They share native model owners, retain distinct call-premise/trap behavior and
are imported by qualified name. Historical modules alias these exact owners.

`bc5_cfg.py` and `msc8_cfg.py` own target CFG comparison/report policies over
the shared `cfg.py` discovery/lowering owner. Their historical modules alias
the qualified owners; both CLIs use qualified imports.

`cfg.py` owns native CFG discovery, direct-edge admission, graph pairing and
full-state block lowering. Historical driver modules re-export these exact
owners and retain their target comparison policies. Noninteger control targets
refuse. Shared helper dispatch imports this backend owner only when needed.

`catalog.py` owns deterministic function coordinates and name-paired proof
obligations. Names select obligations; they never establish semantic equality.
Target listing, symbol and relocation policies live in separate qualified
catalog owners; they do not redefine proof semantics.

`msc8_catalog.py` owns MSC8 listing bounds, ELF symbols and verified PE LINK-map
data correspondence. Its historical artifact module aliases the exact owner;
the MSC8 CLI imports it by qualified name. `bc5_catalog.py` separately owns
BC5's broader listing forms, content-validated cache and symbol correspondence.
The BC5 CLI also uses qualified imports; its historical module aliases the owner.

`msc8_dependencies.py` admits each image's executable helper declarations
independently of root name correspondence. `--candidate-code-map PATH` can add
public and static code symbols from an image-verified MSVC LINK map. Segment
coordinates and extents must agree with loaded executable sections; the map
digest is sealed with the proof. These are dependency scan envelopes, not
assumed call summaries or new root correspondences. Data relocation remains a
separate explicit premise under `--candidate-link-map --normalize-globals`.
One-past segment markers are ignored as function entries only when their
segment-end coordinates match the loaded image. Symbol names do not authorize
this exception; unknown offsets or inconsistent image addresses still reject.
Symbols assigned to a declared non-executable DATA section are not code
dependencies, including assembler absolute aliases represented by wrapped
section offsets. Data-relocation validation remains separate.
MSC8 leaf and matched-CFG modes accept this premise. Matched-CFG results
retain the exact constant map, checked block verdicts and sealed LINK-map
identity; successful normalized induction is conditional and still requires
complete environment coverage. Region/auto modes remain literal-address
comparisons.
Before installing a matched-CFG map, the comparator checks every serialized
candidate SSA constant with the translator's actual width/low-word rewrite
policy. If the map changes none of them, it is omitted and the native CFG is
proved without a relocation premise (`normalization_used: false`). A changed
constant keeps the original conditional treatment. This does not infer a
global memory relation or promote an existing rewritten proof after the fact.
Refused normalized CFGs retry complete call composition under the identical
constant map. The caller includes each admitted helper's actual effects and
proved return target. Successful retries remain conditional. Cyclic roots
then try closed loop induction under the same map, including complete callee
effects and native return-target proofs. Every paired transition must
discharge; internal SAT models remain refused at whole-function scope.
Maps cannot rewrite the induction's control tokens. Unsupported
composition/induction retains its refusal and never switches to a different,
strict relation. Already conditional CFG proofs are retained.
Closed loop induction first tries the ordered graph pairing, then bounded
alternative branch bijections and finite covers under the same deadline and
cumulative composition limits. Every proposal requires complete transition
checks; failed proposals and their cutpoint countermodels remain in
`graph_attempts`. Structural matches alone never establish a verdict.
For each graph, identity-state induction runs first. A failed comparison may
propose an invertible register permutation or affine relation from entry SSA.
All transitions, including actual callee effects, must prove under that
relation. Entry inputs, returns and entry backedges retain identity; memory,
flags, segments and control remain observed. `relation_attempts` retains the
failed identity and proposed-relation evidence. Relocation-dependent success
still remains conditional on its exact constant map.
The compositor also admits acyclic roots without calls: it must retain
explicit `complete_function` scope, positive work counts and binary coverage
for both images. Different CFG shapes can then resolve to a complete-function
proof or counterexample instead of discarding a valid result for having no
call dependencies. Conditional root results still pass the environment gate.
For explicit last-byte listings, additional code entries and segment ends
partition coarse scan envelopes before extent admission. Native closure must
still prove every reachable instruction; exact instruction-head declarations
are not silently shortened.

`verdict.py` owns typed public verdicts and complete backend-result accounting.
It is independent of angr, VEX, Z3 and the SSA engine. Both historical target
verdict modules alias this exact owner, preserving identities and old pickles.

Proof-source seals include this package. Keep refusal, counterexample and
conditional proof distinct. A conditional result must name its assumptions.

The opt-in `--retry-block-limit 128` survives the transition from acyclic
call composition to closed loop induction. Both lanes retain the same
absolute deadline and other limits; completed loop proofs publish per-image
`block_lift_retries` receipts with the actual closure sizes.

MSC8 `--all-original` selects every function in the original listing, including
named functions and missing candidate mappings. `--all-mapped` retains its
historical `sub_*` selection. Every completed MSC8 report includes original
function coverage against the complete original listing catalog. Unselected,
missing, duplicate, failed, refused and conditional records cannot increase
unconditional coverage. The target is at least 90% unconditional proofs;
conditional coverage is published separately. This is listing-catalog coverage,
not a claim that every executable byte or undiscovered function is covered.

MSC8 `matched-cfg --match-import-thunks --candidate-code-map FILE` can fill
missing candidate root declarations from native import identities. It checks
executable six-byte JMP-IAT instructions and the loaded PE import metadata on
both sides. Original aliases may reach the JMP-IAT through a bounded chain of
effect-free rel8/rel32 JMPs; cycles, conditional branches, CALLs and instructions
with other effects do not establish correspondence. The recorded original route
remains subject to ordinary native composition. Matching requires exactly one
distinct candidate public-symbol address
for that DLL/API. LINK segment coordinates are verified against the image;
names alone do not establish a match. Aliases at one address are deduplicated,
distinct matching addresses remain ambiguous, and existing mappings keep
priority. `import_thunk_correspondence` records the intake evidence separately.
This flag supplies no external ABI model and no equivalence verdict. The normal
proof lane and explicit `--external-call-catalog` determine whether a matched
root can obtain a conditional proof; the full original coverage denominator
is retained. No edited candidate listing is required.

`--match-code-symbols` additionally proposes missing original roots from
unique LINK public names under the same `matched-cfg`/`--candidate-code-map`
requirements. It removes one C underscore and an optional decimal stdcall
suffix for matching only; this never supplies an ABI assumption. Every public
coordinate is checked against executable PE sections. Public/static entries
bound the scan envelope, private names do not create root matches, distinct
addresses with one canonical name remain ambiguous, and existing mappings
keep priority. `code_symbol_correspondence` is proposal evidence; ordinary
native comparison must still prove every admitted root. Use both flags with
`--all-original` to include these missing declarations without modifying the
candidate listing. Import-identity matches take priority over public names.

For candidate listings emitted with next-symbol-minus-one byte envelopes,
pass `--candidate-lst-end-kind last-byte`. The default describes original IDA
instruction-head bounds; decoding a synthetic last byte can create false
overlaps or leave the executable section.

Private tests are in `tests/`. Production drivers are `bc5_cli.py` and
`msc8_cli.py`, runnable with `python -m tools.comparator.bc5_cli` or
`python -m tools.comparator.msc8_cli`. Historical artifact commands remain
compatibility entry points and their module imports alias the exact owners.
CLI/package acceptance remains in progress; preserve resource limits and report
schemas without introducing a second semantic owner.

### Comparison experiments and remaining obligations

Choose bounded experiments by newly discharged original-function obligations
and solver cost. A local mismatch is not necessarily a whole-function
counterexample; an incomplete lemma does not become equality. Keep conditional
proofs outside the 90% unconditional coverage numerator.

Priorities after the table checks, with independent acceptance criteria:

1. **Compose from the root to observation boundaries.** The opt-in rooted
   target check now substitutes each real prefix state into its continuation;
   retaining dispatch guards and integrating complete coverage remain pending. This can
   tolerate different temporary state without assuming equality at cutpoints.
   A bounded C33216 diagnostic of two returning targets left only ECX unequal
   in the `sub_275D0` path, and memory plus VEX flag dependencies unequal in
   the `sub_17AA0` path. It imposed no dispatch guards and proves neither root.
   Next experiment: cover every reachable dispatch/default arm with guards;
   mutate a branch result to ensure the composed proof rejects it.
   On the two C33216 `sub_1C0F0` paths with return-stack alias counterexamples,
   root-domain transport currently reaches return-proof timeouts rather than
   completed lemmas. An isolated experiment using standard scalar preprocessing
   instead of read-over-write at the same solver limit also timed out; no
   production solver policy or proof budget was changed on that basis.
2. **Prove which outputs the caller can observe.** Use explicit ABI evidence
   or caller liveness to justify dead scratch registers and flags. Excluding
   private stack bytes additionally needs frame bounds, escape/alias checks,
   and a memory relation. Compare architectural flags where observed, rather
   than assuming different VEX lazy-flag encodings imply different flags.
   Mutation controls must cover live flags, escaped stack pointers and saved
   registers. Until those obligations are implemented, retain strict outputs.
3. **Cancel identical regions with a state relation.** Native byte identity
   can propose common regions, including REP instructions, but entry state,
   relocations, PC-relative operands, memory relation and external effects
   must justify treating them as the same transformer. REP versus an unrolled
   loop still needs an effect/loop lemma, including overlap and direction.
   Measure avoided lifting/solver work; corrupt a displacement as a control.
4. **Relate global objects instead of guessing address deltas.** Establish a
   bijection with extents, initialization, pointer relocations and alias
   relationships. Object order and recovered types are proposal evidence;
   they alone do not establish the runtime memory relation. Check table slots
   against the paired functions or internal blocks, and prove the paired
   targets' effects separately. Swapped slots and interior pointers are
   required negative controls.
5. **Reuse proved summaries and symbolic-range obligations.** The existing
   arbitrary-index table-preservation check covers all bounded slots with one
   symbolic query. Apply the same principle to other bounded regions when
   alias and overflow obligations permit. Cache only complete lemmas bound to
   both binaries, semantic source seal, entry relation and environment
   assumptions; reject reuse after any dependency changes. Measure cache
   hits and total solver time alongside coverage, never instead of coverage.

Each new route should fall back to the existing comparison when its admission
conditions fail. These are deferred experiments, not implemented proof claims.

Direct native calls to a declared `FF 25 <IAT slot>` leaf with an explicit
external contract now bypass only the inline-depth refusal. The thunk is
still lifted and composed, its live IAT target and native return are proved,
and the ordinary call-count, node and deadline budgets remain enforced.
Call-site evidence records `terminal_import_depth_exemption`; wrappers with
preceding instructions and truncated declared extents do not qualify. This
does not prove the external contract or remove its conditional status.

IAT target preservation first tries a bounded write-region proof. It checks
every store's full byte extent against the four-byte slot, admitting only
nonwrapping 32-bit constant/input/add/sub address intervals under the same
declared root constraints. Both arms of conditional memory must preserve the
slot. Unknown memory producers, aliases, wrapping addresses and exhausted
analysis budgets defer to the existing SMT equality check. Store values are
skipped only after their destination bytes are proved disjoint. External site
receipts record the proof method and number of checked stores. No initial
memory contents or extra stack/heap assumptions are introduced.

The same sufficient proof now covers complete table extents and explicit
`memory_preserve` frames. It follows the original array only if the frame
covers every queried byte; partial frames require preservation on both arrays.
Serialized SSA references are resolved on demand, so disjoint store values
are not expanded. This proves preservation, not initial table contents or
callback identities. The existing SMT path remains the fallback.

PE table reads cache immutable section metadata for at most two complete image
byte strings. The key is file content, never a path or timestamp; parser objects
are closed immediately. Every read still checks mapped extent, executable
permission when requested, raw-file bounds and current bytes. This cache does
not retain proof results or waive semantic freshness checks.

Flat32 direct and finite-indirect calls can reuse a completed generic callee
summary beyond the inline-depth boundary: substitution performs no additional
recursive descent. The call-site receipt marks cached_summary_depth_exemption.
Recursion rejection, call counts, deadlines and return-target proofs remain
mandatory. Context-bound summaries cannot be reused by entry address alone.
Fresh callee unfolding and tail transfers keep their existing depth limits.

The MSC8 `--find-return-counterexamples` option searches refused literal
matched-CFG roots for full-width EAX and explicitly observed EDX differences
at paired native returns. EDX is checked only when present in --output-regs;
the standalone API defaults to EAX. It retains exact path guards and memory
dependencies, but merges only the selected return registers,
return IP and a completion marker after paths terminate. Both returns must
target the original caller return slot. Search is bounded to four blocks per
path, no repeated address per path, 64 visits per image, 50000 expression
nodes, two seconds of composition and one second of solving. Unsupported
calls/transfers and clipped paths never contribute a witness.

Only a concrete SAT difference in a selected register changes refused to failed; the previous
result remains in strict_function_result. Bounded agreement never proves
equality. Global normalization, ABI/external catalogs, omitted EAX and
declared narrow/void returns are not eligible for this route. The current
solver receipt includes differing values and register assignments; symbolic
memory is not yet exported as a standalone executable replay vector.

Native block reads reuse the image-content section-layout cache for the
128-byte decode window. Section-tail windows use the existing short-read
path; every decoded instruction extent is checked before lowering.

Loop induction can derive a constant scratch-register invariant from actual
entry effects. It separately proves initiation and every continuing transition
under that invariant, and requires that the corresponding original register
has no dependency into retained outputs at any cut. A register observed at
any return cannot be projected. Other registers, memory, flags, control and
all terminal observations still undergo complete transition comparison.
After the unrestricted identity check, the independently verified constant
projection is attempted before dead-flag and narrow-register proposals. This
avoids spending the fixed proof budget on unrelated projections; every selected
proposal still discharges all relational obligations.
Receipts include constant_register_invariants and their individual proofs;
failed projection proposals are retained separately from the selected attempt.
This route introduces no caller-supplied premise. It handles successive
candidate constants in EAX/ECX/EDX against dead original coordinates. Each
new invariant is proved using only previously discharged projections, and
receipts retain that proof order. Registers selected as return observations
cannot be hidden. Other state relations remain deferred.

Complete SSA output comparison first discharges inequalities that exact Z3
simplification proves false. Unchanged observations therefore consume no solver
queries or repeated assertion copies. Every remaining output is checked under
the complete original caller domain and the same absolute deadline; incomplete
lemmas never supply assumptions. An expired deadline still refuses comparison.

Closed CFG, reblocked CFG and macro-step comparison now share the native
REP admission used by the existing repeat-string semantic contract. Discovery
retains the exact bytes of one isolated, default-form REP instruction, then
follows its complete-instruction continuation. Lowering preserves all summary
register/flag/memory effects and tokenizes only the validated fallthrough.
Ordinary VEX blocks keep the existing exit checks. Prefix/address/operand
overrides, absent summaries and out-of-range continuations remain refusals.
No REP-versus-unrolled-loop equivalence is inferred by this admission.

MSC8 `--global-alias-source PATH` supplies an explicit renamed-global premise
from decompiler C metadata. It requires `--candidate-link-map` and
`--normalize-globals`. A name must have an extern data declaration and an
address annotation at an actual original listing data label. The normal
LINK-map and loaded-section validation then checks its candidate counterpart.
Conflicting annotations reject; guessed types supply no type or extent proof.
The source path and SHA256 are sealed as auxiliary inputs and in the model
domain; mutation during comparison invalidates the receipt. Successful
comparisons consuming these constant pairs remain conditional. For MSC8
rebuilds, the explicit source can be the same gen/T.c passed to --candidate-src.


Loop induction also computes conservative low-bit demands for EAX/ECX/EDX
over the complete paired transition graph. Demands propagate backward through
cycles and use the union of both sides and every successor. Memory, control,
external observations, preserved registers and selected return registers retain
their dependencies. Entry backedges retain full scratch coordinates. Unknown
operators require full operands. A full-width return observation prevents
discarding high bits merely because the body often uses AL/AX or DL/DX.

This admits compiler differences such as a 16-bit sentinel held as 0xfffffffe
versus 0x0000fffe when only DX can affect retained observations. Every projected
transition must still pass the solver. The receipt publishes
narrow_register_projection with live input widths and retained output widths.
Relocatable mask literals cannot justify narrowing; projection uses truncation
and extension widths instead of synthesizing masks that could themselves be
relocated. No new ABI assumption is inferred. An explicit --output-regs eax,esp
selects a scalar return contract; the default still observes EDX as well.
Stack bytes are never excluded by this transformation.

Still deferred: automatic original/candidate ABI justification, bit demands
through shifts and general bit permutations, different register allocations and
stack-frame correspondence. Low-bit liveness cannot establish REP-versus-unrolled
loop equivalence or repair a real changed return value.


The flat32 call-loop fallback can also propose a closed relation with shared
non-entry BORING cutpoints. This covers duplicated loop-body suffixes, including
a first iteration preceded by alignment instructions. Every distinct original/
candidate region pair is a separate universal transition obligation. Connected
pairs receive one control class only when all effects and continuation classes
prove equal; return components stay separate and the initial entry remains
exclusive. Every region still executes a finite, positive number of real blocks.
Neither a repeated index nor the presence of padding grants an equality verdict.

Existing bijections and shared-return proposals run first. Shared-state search
is a subsequent bounded fallback under the same total proof deadline and
composition limits; identical layouts/pair sets reuse the exact earlier check.
Reports publish state_merges, strict_graph_search and state_merge_graph_search.
This does not infer a register/stack invariant for states at a cutpoint: if,
for example, LEAVE and POP EBP require EBP==ESP there, that invariant still
needs independent initiation and preservation proof.


Automatic entry-table discovery now also compares each returning target under
its exact selected-slot guard. Manual catalogs enable this alongside
check_rooted_targets. Both index expressions are composed through their own
root prefixes; guard equality and every selected observable effect are proved.
Repeated slots are joined, and distinct original arms may share a candidate
body without merging their selection domains. Strict target mismatches remain
in the report and are not root counterexamples by themselves.

A single-switch root can become conditional with method
single_switch_selected_slots only after all slots, prefix effects, index bounds,
default continuations, table preservation, native dispatch bindings and selected
root entries are checked. Initial table bytes remain explicit jointly satisfiable
premises. A partial guard proof alone earns no function coverage. CALL dispatch,
null targets, reordered entries, missing slots and unproved continuations do not
qualify. Per-slot guards do not mask callee return-address obligations.

Automatic discovery uses check_selected_slots to retry only when the prefix
is checked and strict target proofs are incomplete or mismatching. Otherwise
an explicit pending prerequisite is reported, without re-composing all targets.
The opt-in check_rooted_targets diagnostic still computes full rooted and
selected-slot evidence even when another whole-function obligation is missing.
No proof budgets or promotion requirements change under this scheduling gate.

Native target decoding reads bounded byte windows from the immutable PE layout
cache. Short blocks at the end of a mapped section no longer reopen PE files
for a padded128-byte read. Windows stop at virtual, raw and actual-file bounds;
executable permission and the exact decoded extent are still checked. The
two-image cache is keyed by complete immutable bytes, so changed images never
reuse stale layout facts. This removes repeated pefile.close garbage collection
without disabling GC or changing proof/search deadlines.


Completed switch comparison also accepts the existing per-function
--abi-observation-catalog. It composes each selected-slot continuation and
each default continuation from the exact original/candidate root states.
Selection guards must agree; ABI observations apply only after complete native
returns. Different intermediate register allocation therefore need not prevent
a proof. Strict prefix and arbitrary-target checks remain in the report.

Promotion uses single_switch_root_returns only when the table correspondence,
native dispatch binding, full slot/default partition, root entries, index bounds
and table preservation all check. Initial table bytes must be jointly
satisfiable and explicitly assumed. The ABI premise is separately published;
return values, preserved registers, return control and observable memory still
compare. Internal scratch dependencies, conditional guards and callee return
addresses are never projected. Unknown calls and clipped paths remain missing
evidence. No original ABI inference is claimed.

Deferred: derive original ABI from caller evidence, support multiple dispatches
and looped continuations, integrate external-effect contracts, and prove global
object relations. A scalar declaration in rebuilt source proposes an ABI
premise; it does not prove that premise for the original.

The completed-path route binds each native dispatch independently. Different
index-register names are permitted only when every root-composed selection
guard is proved equal. Strict operand-shape mismatches stay in the receipt;
register renaming alone never earns proof credit.


Returning table continuations can now revisit native addresses after a loop
traversal with at least one conditional edge and all its conditions proved
constant. Symbolic or unconditional cycles still stop immediately. Path-local
evidence prevents a sibling branch from authorizing a revisit. The same
16-visit and two-second composition limits apply. Every reachable path must actually
return before any equality is published. This admits small fully unrolled
constant-trip loops; it is not induction and does not prove unbounded loops.
A composed one-bit branch may select one arm only when exact literal SSA/Z3
simplification yields a constant for all registers and memory. No memory
initialization, relocation, root guard or sampled solver model is assumed by
this shortcut. Symbolic/oversized guards retain both arms. Constant branch
receipts retain bounded materialized SSA witnesses, avoiding expanded DAGs.

Constant-branch simplification reuses the shared fixed-selector x86 flag dependency
contract, replacing only zero-demand arguments. It inspects at most 256 original
SSA nodes and simplifies at most 32 projected nodes; exceeding either bound keeps
both edges. These are scheduling limits, never assumptions that a guard is false.
Within one paired-target check, identical image bytes and block addresses reuse
lowering; identical complete guard documents reuse simplification. Every visit
still composes its own input state and consumes the same 16-visit/time budget.

An external catalog may explicitly declare `memory_access: "returned_region"`
with a zero-based `write_size_argument`. Results depend on ordered arguments
and external history, with no additional program-memory reads. The operation
may write opaque bytes in the modular region `[EAX, EAX + size)`; zero EAX or
size writes nothing. Other memory and the ABI return slot are preserved.
This is a conditional environment premise, not an inferred HeapAlloc model.
Allocator-private state must live in external history. Freshness, nonaliasing,
success, alignment and zero initialization are not inferred. In particular,
HeapFree/HeapReAlloc and pointer-reading APIs need different contracts.

`check_global_initial_bytes` checks explicit `(original VA, candidate VA, width)`
extents (1..64 bytes each). It distinguishes serialized bytes from declared
virtual zero tails and rejects truncated raw sections rather than inventing
zero bytes. Results describe section initialization before relocations, imports
or TLS work; they cannot promote a function or establish a live null callback.
Object correspondence, types, all writes/aliases and external preservation
remain separate obligations. Existing serialized-table reads remain strictly
file-backed.

Guarded byte-region preservation can be factored into two checked implications:
`path => sufficient guard` and `sufficient guard => equal bytes`. The intermediate
guard is a proposal, never an assumed fact. Both checks share one deadline and
retain SSA witnesses. A rejected intermediate proposal is incomplete evidence,
not a root counterexample. The checker establishes neither guard feasibility
nor initialization nor whole-function equivalence. This can isolate the failure
case of a returned-region external call without assuming allocation succeeds or
that its successful result cannot overlap the observed region.

For a same-width equality guard `term == literal`, the guarded memory checker
may substitute the literal into both observed byte expressions only inside
that guard. The original guard remains unchanged, both outside observations
are the same value, and original/projected SSA witnesses are retained. Mixed
widths do not use this shortcut: narrowing a store would change its footprint.


Native-entry constant invariants can also be retried when a relocation map was
requested. Their initiation and preservation are proved from literal native
instructions; the complete paired transition comparison then uses literal
coordinates as well. No relocated comparison may consume those facts.
Reports retain native_constant_comparison_coordinates=literal and
requested_normalization_used=false. The caller's requested relocation premise
remains visible and keeps the public result conditional. Unknown or changed
memory effects still prevent the proof; all budgets remain shared with the
original comparison attempt.


An unresolved native indirect jump during call composition now carries a
structured refusal_location: declaring function, block and (when available)
last instruction address. The two-sided call wrapper additionally binds the
root entry and oracle/candidate side. Loop-lifting refusals preserve the known
local coordinates without guessing a missing side. These are stopping-site
diagnostics, not a recovered target, call chain or proof; the stable refusal
reason and all admission rules are unchanged. Group repeated failures by this
site before choosing a widely reused callee to improve.


Composed flat32 direct branches use the shared bounded constant-guard checker
before visiting both successors. Only an exact all-inputs TRUE/FALSE result
selects one arm; symbolic, unsupported or oversized guards retain both. This
can exclude an unreachable callback or loop after preceding blocks established
a constant, while keeping all prefix register and memory effects. Complete
summaries and comparison reports retain constant_branch_proofs with SSA
witnesses and native block coordinates. No initial-image byte, input-domain
assumption or sampled solver value establishes the constant; retry attempts
clear their previous branch certificates and keep the original shared deadline.


A nested unconstrained callback now qualifies for the existing single root-bound
composition retry. The innermost native call site is retained as refusal_location;
a callback at the root itself does not retry because its live state is already
available. The retry composes callees over actual caller states, checks each
return target, clears generic summaries and attempt certificates, and shares
the original time/work budgets. Unknown callbacks remain refused; PE initializer
bytes and matching callback names supply no implicit entry-memory premise.


Flat32 macro-path induction proposes additional cuts at native DFS backedge
targets. Entry and feedback cuts receive paired control tokens; path proposals
must agree on both starting and ending cuts. The checker proves complete,
disjoint guard coverage separately at every cut, full modeled state on every
selected path, and positive progress. A failed or incomplete cut cannot borrow
coverage from another cut. This admits hoisted/duplicated entry work around
internal loops without an iteration bound. Sorted feedback-head pairing remains
a proposal; differing loop shapes, unsupported calls and unresolved effects
still require other proof owners.


Macro guard equality, infeasibility and per-cut coverage use the shared exact
flag-argument demand projection before solving. Only zero-demand arguments of
fixed literal helper selectors disappear; carry-sensitive or unknown selectors
retain their dependencies. Full state observations are unchanged. A projected
guard counterexample establishes only a cutpoint predicate difference, never a
reachable function counterexample. Projection and solving share the original
absolute deadline.


Zero-count REP is an exact state identity before control advances. The shared
SSA summary now guards changed register, lazy-flag and memory expressions with
the architectural counter-equals-zero condition. It requires no pointer
validity, direction or memory-initialization premise on that branch. Nonzero
REP keeps its existing summary; no arbitrary loop is silently replaced by a
copy. PE32 MOVS/STOS/SCAS/CMPS controls compare against the instruction removed,
and changed following stores must still fail. Real16 zero STOS also proves;
the real16 prefix-to-SCAS flag handoff remains an explicit strict xfail.

Further proof work: check caller-owned object extents against private stack
writes, then publish any necessary non-alias/DF premises as conditional.
REP-versus-scalar-loop comparison needs a common checked memory-range effect,
including overlap, direction, counter and final flags. Same bytes can discharge
a block only with corresponding entry state, control targets and memory
coordinates; equality of bytes alone cannot justify relocated globals or calls.
Global/table maps must establish extents, initialized values and slot order;
mapped function names are target proposals, not target-equivalence proofs.


The bounded root refuter can execute default two-byte REPNE/REPE SCASB/SCASD
when byte observation enables its existing deeper search. Each admitted
iteration lowers the scalar native SCAS through VEX, preserving final lazy
flags and the DF-scaled index; ECX decrements exactly once. Entry ECX==0
bypasses the body, and continuation uses the new comparison result, not entry
ZF. Exact constant-guard simplification prunes only all-inputs constant edges.
Three visits per address, depth12,64 visits per image and the existing deadlines
still bound the search. Clipped scans never become completed returns.
Other nonzero REP families and prefixed width/segment overrides remain outside
this bounded route. A SAT difference must still occur on paired root returns
to the caller slot. Bounded agreement does not establish function equivalence.

The MSC8 driver also accepts `--concrete-counterexample-vectors FILE` in literal
`matched-cfg` mode with full EAX observation and no ABI/external-call catalog.
The schema is `dosunit.flat32_concrete_witnesses.v1`: `functions` maps original
function names to 1–16 vectors. Each vector requires a unique `id` and
`registers` containing `esp`; optional `memory` byte patches and data-only
`mappings` and `observations` use the `replay-flat32` format. Memory observations
must be fully captured from explicitly mapped vector scratch on both sides;
image, harness-stack and unmapped bytes cannot supply a memory counterexample.
Function entries and extents come
from the binary catalogs, never the vector file. A supplied entry-ESP premise
must contain every vector's ESP. The vector catalog is hashed before comparison,
checked again before replay, and retained in sealed `auxiliary_inputs`.

This route executes exact PE function slices with a bounded integer instruction
subset. Code pages are execute-only, so different instruction bytes cannot
supply different guest data inputs. Both executions share zero-initialized
scratch, register defaults and explicit seeds. Both must complete through a
native near RET. A differing full EAX or observed scratch byte changes only an existing `refused` row to
`failed`; `strict_function_result` preserves the refusal and
`concrete_counterexamples` retains the input, code/image hashes and observations.
Narrow return masks are ineligible. Agreement, faults, calls outside the slice,
unsupported effects and instruction-budget exhaustion cannot establish either
equivalence or a counterexample. This does not model OS execution or relocated
global-memory relations.

The concrete integer subset admits IMUL and immediate-count SAR with a
path-local defined-flag check. IMUL defines CF/OF, while SAR flag definitions
depend on the masked count and operand width. Reading an undefined flag in a
conditional branch refuses execution; a later CMP or another defining
instruction can restore admission. Variable-count SAR remains unsupported.


### Fixed output-buffer external contracts

An explicit external catalog may set `memory_access: "argument_region"`,
`write_address_argument: 0`, and `write_size_bytes: 16` (pointer arguments are
zero-based DWORD ABI arguments; supported fixed sizes are 1..65536 bytes).
This declares an output-only buffer: old program memory is not a dependency of
results or external history, but every byte outside the fixed modular buffer
remains observable. Normal return, a valid output pointer, ABI preservation,
and any requested IAT preservation remain published premises. No API behavior
is inferred from the import name. The operator identity includes pointer index
and size; distinct contracts never share an opaque function accidentally.

Small buffers (at most64 bytes) use finite stores, larger ones the existing
exact modular array-range operation. Return-address preservation is applied
separately. This is an explicit conditional environment model, not proof that
an arbitrary binary import implements it. For example, a separately supplied
GetSystemTime contract can describe its documented output SYSTEMTIME buffer:
https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtime
https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-systemtime
