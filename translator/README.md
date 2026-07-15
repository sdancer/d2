# d2wasm AOT translator harness

This directory is the direct-translation path for the Diablo II demo.  It does
not execute an x86 decoder or instruction interpreter at runtime.  The build
harness decodes PE32/i386 files ahead of time, forms basic blocks, emits C for
those already-decoded blocks, and lets Clang lower that code to WebAssembly.
The existing BoxedWine bundle in `../wasm` is retained only as a behavioral
oracle.

The generated module uses one dispatch per translated **basic block** so that
irreducible and indirect PE control flow can be admitted incrementally.  x86
instructions themselves become Wasm arithmetic, loads, stores, and branches;
there is no runtime fetch/decode/execute loop.

## Commands

```sh
# Inventory the real module set and write a machine-readable coverage report.
./d2wasm.py inventory ../extracted --filename-map filename-map.json \
  --output build/inventory.json

# Lift a PE entry point, compile it, and emit translation diagnostics.
./d2wasm.py translate some-i386.exe --output-dir build/some-i386

# Run the hermetic PE -> Wasm behavioral smoke test (expects clang/lld-link/node).
./tests/smoke.sh
```

To build the full linked gameplay artifact (the partial exit status is expected
while untranslated, unreachable diagnostic sites remain in the report):

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

`-O0` is intentional for this artifact: it preserves page-sized translated
functions instead of letting LLVM fold the whole dispatcher into a single
function larger than V8's per-function limit.

Run the deterministic title-menu-to-gameplay replay with:

```sh
./run-gameplay-demo.sh
```

The script writes `build/diablo-gameplay.ppm`. Its click/text schedule and
round budget can be overridden with `D2_AUTO_CLICKS`, `D2_AUTO_TEXT`, and
`D2_MAIN_ROUNDS`.

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
