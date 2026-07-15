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
`build/diablo-gameplay.ppm`. That deterministic replay uses the Node.js host;
the native egui host below provides a visible, interactive window. Neither
host invokes Wine or BoxedWine.

To run the same translated artifact in a visible native window:

```sh
./run-gameplay-egui.sh
```

The first launch compiles the large linked WASM module with Wasmtime and can
take a minute or two. Mouse and keyboard events over the scaled game surface
are forwarded to Diablo as Win32 messages. The runner has no round or time
limit; status 1 is a resumable fuel boundary and execution continues.

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

## Native egui host

The Rust host in `native-egui` replaces Node with Wasmtime, eframe/egui, and a
native Win32 compatibility boundary. It maps the linked PE images, runs the
cooperative translated thread contexts, keeps an 800x600 presentation surface
(scaling the shareware game's 640x480 in-game renderer), forwards input in the
active guest coordinate space, and sends DirectSound PCM buffers to the native
audio device.

`run-gameplay-egui.sh` forwards runner options directly:

```sh
./run-gameplay-egui.sh \
  --wasm build/diablo-linked-gameplay/linked.wasm \
  --manifest build/diablo-link-compact.json \
  --source-dir ../extracted \
  --host-root build/runtime-files/diablo2
```

Cargo and Wasmtime build artifacts are large. Set `CARGO_TARGET_DIR` to a
filesystem with several GiB free when necessary. An optional trusted Wasmtime
module cache avoids the cold compile on later launches:

```sh
CARGO_TARGET_DIR=/dev/shm/d2-egui-target \
D2_EGUI_MODULE_CACHE=/dev/shm/d2-linked.cwasm \
./run-gameplay-egui.sh
```

For deterministic UI diagnostics, `D2_AUTO_CLICKS` uses the same
`x,y,presentation` schedule syntax as the Node replay.
`D2_AUTO_KEYS` accepts `virtual-key,presentation` entries separated by
semicolons, for example `D2_AUTO_KEYS='67,1500'` to press `C` at presentation
1500.
Set `D2_WATCH_PC` to a lifted basic-block address and
`D2_STOP_ON_WATCH=1` to yield with its guest registers and stack intact.

The native host cooperatively schedules translated thread contexts at Win32
waits and periodically at main-thread `Sleep(0)` calls. The default batches 256
zero-sleeps per handoff so polling loops cannot starve wait-ready worker
threads without scheduling a worker on every poll. Set
`D2_COOPERATIVE_POLL_INTERVAL` to tune that batch size. Nonzero sleeps use wall
time, while sleeping and waiting worker contexts remain blocked until their
deadline or event is ready.
`GetTickCount` and `timeGetTime` retain millisecond wall-clock semantics;
`QueryPerformanceCounter` uses a matching nanosecond-resolution monotonic
frequency so sub-millisecond guest work is still measurable.

### Record and replay native gameplay

Record mouse, keyboard, and window-close input together with a verification
checkpoint for every presented framebuffer:

```sh
./run-gameplay-egui.sh --record build/replays/barbarian.jsonl
```

Replay the exact input stream at the original presentation boundaries:

```sh
./run-gameplay-egui.sh --replay build/replays/barbarian.jsonl
```

The journal is line-delimited JSON. Its header fingerprints the linked Wasm,
link manifest, mapped PE source images, and MPQ/LNG game data. Input records
contain the presentation number and a strict sequence number; frame records
contain the virtual Win32 clock and an FNV-1a checksum of the 800x600 RGBA
framebuffer. Replay validation and recorded input stop at the first divergent
presentation; the same guest and window remain running and immediately accept
live input, with the mismatch preserved in the host diagnostics.

Recording also creates `barbarian.jsonl.state`, a snapshot of the initial
`Save` directory. Replay runs from a private temporary copy of that snapshot,
so it neither depends on nor modifies the live character saves. Live gameplay
input is ignored during replay except for closing the window.

## Chrome host

The browser harness runs the same linked Wasm and JavaScript Win32 boundary in
a module Web Worker, keeps an 800x600 `OffscreenCanvas` while scaling the
640x480 in-game renderer, forwards mouse, wheel, character, and keyboard input,
and plays guest DirectSound PCM buffers through Web Audio.
Game data and initial saves are fetched into a synchronous in-memory filesystem
before execution begins; browser writes are currently session-local.

Start the local server and open Chrome:

```sh
./run-gameplay-web.sh --open
```

Then click **Load game**. Loading the translated module, PE images, and runtime
data transfers roughly 180 MB on the local connection. The optional autoplay
checkbox selects an existing saved character when one is available, otherwise
it follows the deterministic Barbarian character-creation path.

The server defaults to `http://127.0.0.1:8080/` and accepts explicit input
locations when the build lives elsewhere:

```sh
./run-gameplay-web.sh \
  --port 8080 \
  --artifact-dir build/diablo-linked-gameplay \
  --source-dir ../extracted \
  --host-root build/runtime-files/diablo2 \
  --manifest build/diablo-link-compact.json
```

Chrome requires `OffscreenCanvas`; current Chromium/Chrome releases provide it.
The included server also supplies the cross-origin isolation and Wasm MIME
headers expected by the worker.

## SQLite lifted-code debug database

`link-translate` can materialize the complete discovered program graph without
regenerating or compiling the large Wasm artifact:

```sh
./d2wasm.py link-translate ../extracted \
  --link-manifest build/diablo-link-compact.json \
  --output-dir build/diablo-linked-gameplay \
  --max-blocks-per-module 200000 \
  --relocation-roots \
  --roots-file diablo-roots.json \
  --debug-db build/diablo-debug.sqlite \
  --debug-db-only
```

The SQLite sidecar contains modules, sections, roots, blocks, every lifted
instruction, CFG/call edges, resolved code and data xrefs, imports, exports,
and extracted ASCII/UTF-16 strings. Indexed `call_xrefs` and `string_xrefs`
views make common debugging queries short. For example:

```sql
SELECT source_module, printf('0x%08x', source_va),
       printf('0x%08x', target_va), value
FROM string_xrefs
WHERE value = 'top >= 0';

SELECT printf('0x%08x', source_instruction_va), kind,
       printf('0x%08x', target_block_va)
FROM edges
WHERE target_block_va = 0x010651a0;
```

On the verified full build the database contains 16 modules, 223,392 blocks,
912,528 instruction rows, 355,518 CFG edges, and 237,106 xrefs.

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
