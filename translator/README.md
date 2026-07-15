# d2wasm AOT translator harness

This directory is the direct-translation path for the Diablo II demo.  It does
not execute an x86 decoder or instruction interpreter at runtime.  The build
harness decodes PE32/i386 files ahead of time, forms basic blocks, emits C for
those already-decoded blocks, and lets Clang lower that code to WebAssembly.
A BoxedWine bundle may be retained locally in `../wasm` as a behavioral oracle;
it is not required by the translator or committed to this repository.

The generated module uses one dispatch per translated **basic block** so that
irreducible and indirect PE control flow can be admitted incrementally.  x86
instructions themselves become Wasm arithmetic, loads, stores, and branches;
there is no runtime fetch/decode/execute loop.

## Quick start with the verified checkout

If `../extracted` and `build/diablo-linked-gameplay` are already present, run
the deterministic title-menu-to-gameplay replay directly:

```sh
./run-gameplay-demo.sh
```

The runner writes the final 800x600 software framebuffer to
`build/diablo-gameplay.ppm`. It is a Node.js host today; it does not invoke
Wine or BoxedWine, and it is not yet packaged as a Chrome application.

## Clean build from the shareware demo

### Requirements

- Python 3.10 or newer and the packages in `requirements.txt`
- Node.js 20 or newer
- Clang with the `wasm32-unknown-unknown` target and `wasm-ld`
- `lld-link` for the hermetic smoke tests

One setup option is:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
```

### 1. Supply the demo objects

The original Diablo II shareware/demo installer was publicly distributed and
is readily available from software archives. It is intentionally not copied
into this repository. Extract its embedded objects into an `extracted`
directory next to `translator`:

```text
d2/
├── extracted/
│   ├── File00000023.mpq
│   ├── File00000025.mpq
│   ├── File00000137.exe
│   └── ...
└── translator/
```

The verified installer object is 138,309,685 bytes with SHA-256
`89352716523e474514553e2092a1ae9349c5c7ff9e79c7861dd65fe19be88b61`.
The translator repository contains no Blizzard executable or archive data.

### 2. Prepare the runtime filesystem

Map the anonymous installer object names to the names expected under
`C:\Diablo II`. The preparation script reads `filename-map.json`, adds the six
known MPQ mappings, verifies every input before writing, and accepts
already-named files as well:

```sh
./prepare-runtime-files.py
```

Its defaults are equivalent to:

```sh
./prepare-runtime-files.py \
  --source-dir ../extracted \
  --output-dir build/runtime-files/diablo2 \
  --filename-map filename-map.json
```

### 3. Plan the linked PE address space

Create the deterministic multi-module load map and resolve Diablo DLL imports:

```sh
mkdir -p build
./d2wasm.py link ../extracted \
  --filename-map filename-map.json \
  --entry-module "Diablo II.exe" \
  --output build/diablo-link-compact.json
```

The verified input set plans 17 modules, relocates 16, resolves 760 internal
bindings, and leaves zero unresolved internal imports.

### 4. Translate the linked modules

Build the complete gameplay artifact:

```sh
./d2wasm.py link-translate ../extracted \
  --link-manifest build/diablo-link-compact.json \
  --output-dir build/diablo-linked-gameplay \
  --max-blocks-per-module 200000 \
  --relocation-roots \
  --roots-file diablo-roots.json \
  --emit-partial \
  --api-spec api-spec.json \
  --opt-level 0
```

An exit status of 2 is expected for this `--emit-partial` build: explicit
diagnostic sites remain in unexercised branches, while `linked.wasm` is still
successfully generated. Any other nonzero status is a build failure.

`-O0` is intentional for this artifact. It preserves page-sized translated
functions instead of letting LLVM fold the dispatcher into a function larger
than V8's per-function limit.

### 5. Run the deterministic gameplay path

```sh
./run-gameplay-demo.sh
```

The default schedule selects the Barbarian, creates a character, and reaches
the rainy Rogue Encampment. The script writes `build/diablo-gameplay.ppm`.
Application status 1 at the end means the configured execution-fuel boundary
was reached and the machine is resumable; it is not a crash.

Override the replay inputs or output path with `D2_AUTO_CLICKS`, `D2_AUTO_TEXT`,
`D2_MAIN_ROUNDS`, and `D2_FRAMEBUFFER_PPM`.

## Other commands

```sh
# Inventory the real module set and write a machine-readable coverage report.
./d2wasm.py inventory ../extracted --filename-map filename-map.json \
  --output build/inventory.json

# Lift a PE entry point, compile it, and emit translation diagnostics.
./d2wasm.py translate some-i386.exe --output-dir build/some-i386

# Run the hermetic PE -> Wasm behavioral smoke test.
./tests/smoke.sh
```

To produce and execute a diagnostic Diablo entry-point artifact:

```sh
./d2wasm.py translate ../extracted/File00000137.exe \
  --output-dir build/diablo-entry --emit-partial
node runtime/run-translated.mjs \
  build/diablo-entry/lifted.wasm \
  build/diablo-entry/translation.json \
  ../extracted/File00000137.exe
```

Use `--relocation-roots` for a conservative callback/vtable pass. It seeds
every executable address stored in a PE base-relocation slot, rather than
guessing pointers from arbitrary data. Repeatable `--root RVA` values are
useful for tight runtime-guided iterations.

`inventory.json` is intended to drive the long-running port: it records hashes,
sections, imports (including ordinal imports), exports, relocations, and a
linear instruction histogram for every mapped module.  `translation.json`
records reachable blocks, lifted instructions, and exact unsupported sites.
An unsupported opcode is a build result to triage, never an implicit fallback
to emulation.

## Host API boundary

Calls through a PE import-address-table slot are resolved at build time.  The
eventual generated call imports the corresponding implementation from a Wasm
module such as `win32.kernel32.dll`; it must be implemented by the direct host
runtime.  The translator will not load Wine.  The initial slice inventories
all such calls and rejects reachable imported calls until their typed adapters
are registered.

## Current measured gameplay baseline

The current generated reports establish these concrete bounds:

- The linked artifact contains 16 translated PE modules, 223,392 basic blocks,
  and 912,528 lifted x86 instructions. It is approximately 102 MB of Wasm.
- Internal Diablo DLL ordinal/name imports are linked ahead of time. Win32,
  User32, GDI, file/registry, timing, threading, and DirectSound calls cross a
  direct JavaScript host-API boundary; Wine is not loaded by the runtime.
- Cooperative translated thread contexts, synchronous translated WndProc
  callbacks, dynamic function pointers, jump tables, PE stack conventions,
  FS-relative TLS/SEH, integer flags, string operations, and the exercised x87
  surface (including `fsin`/`fcos`) execute as generated Wasm semantics.
- The software-rendered title menu, hero selection, character creation, save
  path, loading transition, and rainy Rogue Encampment gameplay have been
  verified. A 400-round replay produced 843 screen presentations, no assertion
  message boxes, and remained resumable at its fuel boundary.
- Runtime diagnostics include PC/ESP traces, cooperative-context watchpoints,
  pre-dispatch stop/skip controls, callback records, framebuffer checksums, and
  optional PC hit counters. Unsupported or missing translated blocks remain
  explicit status results; there is no fallback x86 interpreter.
