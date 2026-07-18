 The right shape is a database-first, resumable translation pipeline: retain the lifted Wasm as the executable oracle, translate every block into structured semantics, assemble those semantics into functions and
  algorithms, then replace functions incrementally inside the same harness.

  ## Where the translator is now

  The existing foundation already provides most of the low-level front end:

  - d2wasm/cfg.py:157 discovers rooted basic blocks and control-flow edges.
  - d2wasm/cli.py:194 links modules, discovers CFGs, optionally writes SQLite, and then emits C/Wasm.
  - The d2wasm/debugdb.py:30 stores modules, blocks, instructions, edges, xrefs, imports, exports, strings, and roots.
  - d2wasm/debugdb.py:216 currently deletes and rebuilds that database in one pass.
  - d2wasm/codegen.py:870 translates machine instructions directly to C, without a semantic intermediate representation.
  - The native-egui/src/game.rs:76, browser host, recording/replay, diagnostics, and global-PC execution model provide a good differential-testing oracle.

  The main gaps are incremental persistence, function recovery, exhaustive xref closure, semantic IR, and hybrid original/reimplementation execution.

  ## Proposed architecture

  PE modules and assets
          │
          ▼
  Linking + exhaustive discovery
          │  persists each discovered block immediately
          ▼
  SQLite semantic workspace ───────────────┐
    blocks, functions, xrefs, work queue   │ runtime traces
          │                                │ indirect targets
          ▼                                │ observed effects
  Exact machine IR                         │
          ▼                                │
  Structured function/algorithm IR ◄───────┘
          │
          ├── English explanation
          ├── mathematical expressions/invariants
          ├── pseudocode and data models
          └── generated/reviewed implementation
                           │
                           ▼
               Hybrid differential harness
            lifted oracle ↔ reimplementation

  I would make the final core reimplementation Rust compiled for native and Wasm, because that matches both current hosts. The semantic IR should remain language-independent so that choice can change later.

  ## Milestone 1: Turn SQLite into the source of truth

  Replace the one-shot debug database with a versioned workspace that is never destroyed during normal operation.

  Add these main entities:

   Area             Tables
  ━━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Identity         projects, binary_images, analysis_runs, tool_versions
  ───────────────  ─────────────────────────────────────────────────────────────
   Machine graph    existing modules, blocks, instructions, edges, xrefs
  ───────────────  ─────────────────────────────────────────────────────────────
   Functions        functions, function_entries, function_blocks, call_graph
  ───────────────  ─────────────────────────────────────────────────────────────
   Translation      translation_attempts, block_ir, function_ir, semantic_facts
  ───────────────  ─────────────────────────────────────────────────────────────
   Knowledge        symbols, types, variables, memory_regions, algorithms
  ───────────────  ─────────────────────────────────────────────────────────────
   Execution        trace_runs, block_hits, dynamic_edges, observations
  ───────────────  ─────────────────────────────────────────────────────────────
   Validation       test_cases, equivalence_runs, mismatches, coverage
  ───────────────  ─────────────────────────────────────────────────────────────
   Scheduling       work_items, work_dependencies, leases

  Important invariants:

  - A block is inserted and committed before its translation work is queued.
  - A provisional function is inserted before any function-level analysis begins.
  - Every artifact is immutable and content-hashed.
  - Retranslation creates a new version rather than overwriting the previous result.
  - Every generated statement links back to instructions, xrefs, traces, or an explicit inference.
  - Failures are persisted as results: blocked, unsupported, ambiguous, or needs_review.
  - A killed process can resume without rediscovering or losing completed work.

  Suggested lifecycle:

  discovered → decoded → normalized → structured
             → explained → implemented → verified

  Use one SQLite transaction per block or function work item. WAL mode, prepared statements, and a single database-writer process should keep this practical at the existing graph scale.

  ## Milestone 2: Build the full static and dynamic xref graph

  Current CFG discovery is rooted and bounded. “Full xref graph” requires an iterative hybrid analysis:

  1. Seed discovery from entry points, exports, internal imports, configured roots, and relocation-derived code pointers.
  2. Recursively follow direct calls, branches, jump tables, and tail calls.
  3. Sweep remaining executable-section gaps for plausible code.
  4. Identify callbacks, vtables, function-pointer tables, switch tables, and code pointers embedded in data.
  5. Instrument the harness to record indirect calls/jumps and previously unseen PCs.
  6. Feed dynamic targets back into static discovery.
  7. Repeat until the graph reaches a fixpoint.

  Do not pretend ambiguous bytes are resolved. Classify every executable byte as:

  - confirmed code;
  - candidate code;
  - data embedded in an executable section;
  - alignment/padding;
  - unresolved.

  Function recovery should use direct-call targets, exports, entries, runtime call/return traces, prologue evidence, tail-call structure, and xref clusters. Use a many-to-many function_blocks relation because
  compiler-generated thunks and shared tails do not always fit single-owner functions.

  Exit gate: every module has an explicit byte-classification report, every direct xref is represented, and unresolved indirect edges are measurable rather than hidden.

  ## Milestone 3: Introduce the English/math/algorithm middle layer

  Use several IR levels instead of translating assembly directly into prose:

  - L0 — Machine facts: decoded instructions, exact flags, registers, 32-bit wrapping behavior, and memory accesses.
  - L1 — Exact micro-IR: typed bit-vector expressions, SSA-like temporaries, explicit loads/stores, calls, and side effects.
  - L2 — Structured algorithm IR: conditions, loops, switches, state machines, calls, data structures, and error paths.
  - L3 — Semantic specification: English description, equations, invariants, pre/postconditions, pseudocode, global-state effects, and external dependencies.
  - L4 — Reimplementation: reviewed Rust or another target language.

  The canonical representation should be structured JSON/AST, with English and Markdown rendered from it. Prose alone is too ambiguous to preserve overflow, aliasing, flags, calling conventions, and unusual edge
  cases.

  Each semantic claim should carry:

  - provenance;
  - confidence;
  - reviewer status;
  - source instruction/block range;
  - assumptions;
  - counterexamples or unresolved questions.

  Translation workers—deterministic passes, model-assisted passes, or humans—claim database work items. Persist the worker version, prompt/ruleset version, input hashes, output, validation result, and error
  details.

  ## Milestone 4: Extend the harness into an oracle

  Add a trace mode to both native and browser execution that records:

  - block and edge execution;
  - call/return spans;
  - indirect control targets;
  - API calls and results;
  - relevant memory reads/writes;
  - frame, audio, and save-state hashes;
  - virtual time, random seeds, and input sequence.

  Add snapshot/restore and a function-invocation interface based on the existing global-PC context. A test should be able to provide registers, stack, selected memory regions, and runtime state, invoke one
  function, and capture all observable effects.

  Hosts should emit trace events to an NDJSON stream or local RPC collector. A dedicated writer ingests them into SQLite; the rendering/audio threads should not write SQLite directly.

  ## Milestone 5: Support hybrid replacement

  Extend the global-PC dispatcher with an override table:

  function VA → lifted implementation | reimplemented implementation

  Initially every entry points to lifted code. As a function is reimplemented, the harness routes that function to Rust while the rest of the game continues through lifted Wasm.

  The bridge must preserve:

  - x86 calling convention and stack cleanup;
  - register results;
  - guest-memory representation;
  - global variables;
  - callbacks and function pointers;
  - Win32/DirectSound/renderer host effects.

  This makes migration incremental and keeps every replacement independently reversible.

  ## Milestone 6: Differential verification

  For each function or subsystem:

  1. RestoreThe right shape is a resumable, database-first pipeline: retain the lifted Wasm as the executable reference, insert a structured semantic layer between x86 and generated code, then replace functions
     incrementally inside the same harness.

  Today, d2wasm/cli.py:194 discovers CFGs in memory, optionally writes a database, and emits C/Wasm. The current schema already records modules, blocks, instructions, edges, and xrefs in d2wasm/debugdb.py:30, but
  d2wasm/debugdb.py:216 deletes and rebuilds the database in one pass. There are no persisted functions, semantic translations, work states, or translation history yet.

  PE corpus
     ↓
  Link manifest and address space
     ↓
  Incremental discovery ───────────────┐
     ↓                                 │ dynamic traces
  Persistent xref/function database ←──┤
     ↓                                 │
  Machine-neutral semantic IR          │
     ↓                                 │
  English + math + algorithms          │
     ↓                                 │
  Reimplementation source              │
     ↓                                 │
  Hybrid reference/replacement harness ┘
     ↓
  Differential validation and eventual full cutover

  ## Core invariants

  These should be treated as non-negotiable:

  - A block is inserted in the database before any semantic translation begins.
  - A recovered function and its block membership are inserted before function-level analysis begins.
  - Every attempt has a durable state: pending, running, complete, blocked, invalidated, or failed.
  - Translation outputs are immutable, versioned artifacts. New analysis supersedes old rows rather than overwriting them.
  - Every semantic claim links back to instructions, xrefs, traces, or reviewed annotations.
  - English prose is an explanation, not the executable source of truth. The mathematical/structured IR remains authoritative.
  - A crash or interrupted worker can resume without rebuilding completed work.

  ## Milestone 1: Turn the debug database into a project database

  Replace the one-shot writer with migrations and a persistent TranslationStore. Use SQLite WAL initially; the present codebase size is suitable for a single database writer with multiple analysis workers.

  Retain the existing tables and add:

   Area            Tables
  ━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   Versioning      projects, binary_versions, analysis_runs, tool_versions
  ──────────────  ────────────────────────────────────────────────────────────────────────────
   Work queue      work_items, work_dependencies, attempts, leases
  ──────────────  ────────────────────────────────────────────────────────────────────────────
   Functions       functions, function_entries, function_blocks, function_aliases
  ──────────────  ────────────────────────────────────────────────────────────────────────────
   Semantics       block_ir, function_ir, semantic_facts, expressions, algorithms, invariants
  ──────────────  ────────────────────────────────────────────────────────────────────────────
   Types/state     types, fields, variables, memory_regions, global_symbols
  ──────────────  ────────────────────────────────────────────────────────────────────────────
   Evidence        provenance, dynamic_edges, runtime_observations, review_decisions
  ──────────────  ────────────────────────────────────────────────────────────────────────────
   Generation      implementation_artifacts, source_mappings, replacement_bindings
  ──────────────  ────────────────────────────────────────────────────────────────────────────
   Verification    test_cases, validation_runs, equivalence_results, coverage

  Stable identities should be derived from the binary hash, module, and RVA—not database sequence numbers. Each IR row should include its input hash, translator version, confidence, timestamps, and provenance.

  Persistence sequence for each block:

  1. Decode the block.
  2. Transactionally insert its bytes, instructions, static edges, xrefs, and discovery state.
  3. Commit.
  4. Enqueue its next analysis stage.

  Do the equivalent for each function. This gives strict block/function-level crash recovery.

  ## Milestone 2: Build the complete static and dynamic xref graph

  The current d2wasm/cfg.py:157 follows roots and is bounded by max_blocks. Extend it into an iterative graph-discovery service.

  Discovery sources should include:

  - PE entry points and exports.
  - Internal import bindings.
  - Direct call and branch targets.
  - Relocation-derived code pointers.
  - Jump tables and switch tables.
  - Vtables, callback arrays, and stored function pointers.
  - Executable-section linear sweep for regions not reached recursively.
  - Runtime-observed PCs, indirect targets, callbacks, and return addresses.
  - Manually confirmed roots and function boundaries.

  Keep candidate and confirmed edges distinct. An address found by speculative linear sweep must not silently become equivalent to a dynamically observed call target.

  Run discovery to a fixpoint:

  1. Persist newly found targets.
  2. Decode and classify them.
  3. Recompute indirect-target and data-flow facts.
  4. Recover or revise functions.
  5. Repeat until no new confirmed targets appear.

  The graph-completeness report should classify every executable byte as:

  - Confirmed instruction.
  - Probable instruction.
  - Embedded data or padding.
  - Unresolved/ambiguous.

  “Full graph” should mean there are no invisible gaps; ambiguous regions may remain, but they must be explicit database records.

  ## Milestone 3: Recover functions without forcing false boundaries

  Function recovery should start from exports, entry points, direct-call targets, runtime call targets, known callbacks, and relocation roots.

  Use many-to-many block membership because optimized binaries can contain shared tails, thunks, multiple entry points, and function chunks:

  - functions: stable logical identity and confidence.
  - function_entries: one or more entry VAs.
  - function_blocks: membership plus roles such as entry, body, shared_tail, thunk.
  - function_xrefs: calls, tail calls, callbacks, data dependencies, and global-state dependencies.

  Boundary changes should create a new recovery version and invalidate only dependent semantic artifacts.

  ## Milestone 4: Introduce the English/math/algorithm middle layer

  Do not translate directly from assembly to prose or final Rust/C++. Use four explicit levels:

  - L0 — Machine facts: decoded x86, flags, exact 32-bit wrapping, x87 behavior, memory accesses, CFG.
  - L1 — Normalized micro-IR: typed bit-vector expressions, SSA-like temporaries, explicit flags, loads/stores, calls, and side effects.
  - L2 — Structured algorithm IR: loops, conditions, switches, state machines, calls, inferred parameters, returns, globals, and data structures.
  - L3 — Semantic specification: English explanation, equations, pseudocode, preconditions, postconditions, invariants, failure cases, and external effects.
  - L4 — Reimplementation: target-language source linked back to the semantic specification.

  For example, an L3 function record should contain:

  - One-sentence purpose.
  - Inputs, outputs, and calling convention.
  - Reads and writes by memory region.
  - Mathematical expressions with explicit widths and overflow rules.
  - Structured pseudocode.
  - Called functions and external APIs.
  - Loop invariants and termination conditions.
  - Known uncertainty.
  - Instruction/block provenance for every section.

  Persist canonical JSON ASTs for L1–L3 and render Markdown from them. This makes semantic output queryable and regenerable instead of burying the analysis in prose.

  ## Milestone 5: Extend the harness into a behavioral oracle

  The native runner already has gameplay replay, runtime diagnostics, and retained trace support around native-egui/src/game.rs:76. Extend both native and browser hosts with a common trace protocol:

  - Block and edge execution.
  - Call, return, and indirect-target observations.
  - Register snapshots at function boundaries.
  - Memory-region reads/writes or page digests.
  - Win32/API calls and returned values.
  - Filesystem mutations.
  - Renderer, audio, input, timer, and RNG events.
  - Save-game and frame checkpoints.

  Hosts should stream NDJSON or binary trace events to a database-ingestion process; they should not each write SQLite directly.

  Add snapshot/restore and a function-invocation RPC capable of executing a global PC with controlled registers, stack, memory, time, and RNG. This turns the lifted game into a function-level test oracle.

  ## Milestone 6: Support hybrid execution

  Extend the dispatcher around d2wasm/codegen.py:870 with a replacement table keyed by function entry VA.

  Initially:

  - Every function runs lifted code.
  - A replacement can be enabled for one function.
  - Calls crossing the boundary preserve the existing x86 ABI and guest memory model.
  - Replacement code can still call untranslated lifted functions.
  - A runtime flag can switch each function between reference and replacement.

  I would target a Rust core compiled for both native and Wasm, while keeping the semantic IR language-neutral. Pure functions should be migrated first; platform APIs can continue using the existing runtime
  adapters.

  ## Milestone 7: Differential verification

  For each replacement, run the lifted and reimplemented versions from identical snapshots and compare:

  - Return registers and flags.
  - Declared memory effects.
  - Global-state changes.
  - API/event sequences.
  - Filesystem and save outputs.
  - Framebuffer and audio hashes where applicable.
  - Result after several subsequent frames, not only immediately after return.

  Store every comparison in equivalence_results, including the input snapshot, observed differences, translator revision, and implementation commit.

  Promote functions through:

  explained → implemented → locally equivalent → scenario equivalent → accepted

  A failure should automatically return the function to the translation queue with the counterexample attached.

  ## Milestone 8: Migrate subsystem slices

  Recommended order:

  1. Pure leaf math, bit manipulation, comparisons, and utility routines.
  2. Strings, containers, allocators, and data-table access.
  3. File/archive parsing and serialization.
  4. RNG and deterministic simulation helpers.
  5. Game-state transitions, entities, inventory, skills, and combat rules.
  6. UI state and input handling.
  7. Rendering and audio command generation.
  8. Networking or multiplayer behavior, if in scope.
  9. Startup, orchestration, and remaining glue.

  Choose slices using the xref graph: prefer cohesive function clusters with few outgoing dependencies and strong replay coverage.

  ## Completion gates

  The final cutover should require:

  - Every discovered block and function has a durable database state.
  - Every executable byte is classified or explicitly unresolved.
  - Every function has an L3 specification or a recorded blocker.
  - Every accepted implementation has provenance and differential results.
  - Golden gameplay recordings replay identically within defined tolerances.
  - Full scenarios execute without entering lifted x86 blocks.
  - The original lifted build remains runnable as a regression oracle.

  The best first implementation increment is Milestones 1–2: schema v2, migrations, resumable work items, incremental block persistence, and exhaustive graph accounting. Everything else depends on being able to
  trust and resume that database.
