#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
build="$(mktemp -d)"
trap 'rm -rf "$build"' EXIT

node "$here/win32-runtime.mjs"

clang --target=i686-pc-windows-msvc -c "$here/smoke.s" -o "$build/smoke.obj"
lld-link /entry:entry /subsystem:console /machine:x86 /nodefaultlib /fixed /safeseh:no \
  "/out:$build/smoke.exe" "$build/smoke.obj"

"$root/d2wasm.py" translate "$build/smoke.exe" --output-dir "$build/lifted"

node - "$build/lifted/lifted.wasm" <<'JS'
const fs = require("node:fs");
const path = process.argv[2];
(async () => {
  const { instance } = await WebAssembly.instantiate(fs.readFileSync(path), {});
  instance.exports.d2_set_count_pc(0x1000);
  instance.exports.d2_run(0x1000, 0x100000, 1);
  const partialStatus = instance.exports.d2_last_status();
  const countedBlocks = instance.exports.d2_count_hits();
  if (partialStatus !== 1 || countedBlocks !== 1) {
    throw new Error(`one-block run returned status ${partialStatus}, count ${countedBlocks}`);
  }
  const result = instance.exports.d2_run(0x1000, 0x100000, 100);
  const status = instance.exports.d2_last_status();
  if (result !== 42 || status !== 0) {
    throw new Error(`translated PE returned ${result}, status ${status}`);
  }

  const context = 0x80000;
  new Uint8Array(instance.exports.memory.buffer, context, 256).fill(0);
  let resumedResult = 0;
  let rounds = 0;
  while (!instance.exports.d2_context_finished(context) && rounds < 100) {
    resumedResult = instance.exports.d2_run_context(context, 0x1000, 0x100000, 1);
    const resumedStatus = instance.exports.d2_context_status(context);
    if (!instance.exports.d2_context_finished(context) && resumedStatus !== 1) {
      throw new Error(`resumed run stopped early with status ${resumedStatus}`);
    }
    rounds++;
  }
  const resumedStatus = instance.exports.d2_context_status(context);
  if (resumedResult !== 42 || resumedStatus !== 0 || rounds < 2 || rounds >= 100) {
    throw new Error(
      `resumed translated PE returned ${resumedResult}, status ${resumedStatus}, rounds ${rounds}`,
    );
  }
  console.log(
    `translated PE returned ${result}, status ${status}; resumed in ${rounds} one-block rounds`,
  );
})().catch((error) => { console.error(error); process.exit(1); });
JS

clang --target=i686-pc-windows-msvc -c "$here/smoke-integer.s" -o "$build/smoke-integer.obj"
lld-link /entry:entry /subsystem:console /machine:x86 /nodefaultlib /fixed /safeseh:no \
  "/out:$build/smoke-integer.exe" "$build/smoke-integer.obj"
"$root/d2wasm.py" translate "$build/smoke-integer.exe" --output-dir "$build/lifted-integer"
node - "$build/lifted-integer/lifted.wasm" <<'JS'
const fs = require("node:fs");
(async () => {
  const { instance } = await WebAssembly.instantiate(fs.readFileSync(process.argv[2]), {});
  const result = instance.exports.d2_run(0x1000, 0x100000, 10000);
  if (result !== 42 || instance.exports.d2_last_status() !== 0) {
    throw new Error(`translated integer PE returned ${result}, status ${instance.exports.d2_last_status()}`);
  }
  console.log(`translated integer PE returned ${result}, status ${instance.exports.d2_last_status()}`);
})().catch((error) => { console.error(error); process.exit(1); });
JS

clang --target=i686-pc-windows-msvc -c "$here/smoke-x87.s" -o "$build/smoke-x87.obj"
lld-link /entry:entry /subsystem:console /machine:x86 /nodefaultlib /fixed /safeseh:no \
  "/out:$build/smoke-x87.exe" "$build/smoke-x87.obj"
"$root/d2wasm.py" translate "$build/smoke-x87.exe" --output-dir "$build/lifted-x87"
node - "$build/lifted-x87/lifted.wasm" <<'JS'
const fs = require("node:fs");
(async () => {
  const { instance } = await WebAssembly.instantiate(fs.readFileSync(process.argv[2]), {});
  const result = instance.exports.d2_run(0x1000, 0x100000, 100);
  if (result !== 42 || instance.exports.d2_last_status() !== 0) {
    throw new Error(`translated x87 PE returned ${result}`);
  }
  console.log(`translated x87 PE returned ${result}`);
})().catch((error) => { console.error(error); process.exit(1); });
JS

llvm_dlltool="${LLVM_DLLTOOL:-$(command -v llvm-dlltool-20 || command -v llvm-dlltool)}"
"$llvm_dlltool" -m i386 -d "$here/smoke-api.def" -l "$build/test.lib"
clang --target=i686-pc-windows-msvc -c "$here/smoke-api.s" -o "$build/smoke-api.obj"
lld-link /entry:entry /subsystem:console /machine:x86 /nodefaultlib /fixed /safeseh:no \
  "/out:$build/smoke-api.exe" "$build/smoke-api.obj" "$build/test.lib"

"$root/d2wasm.py" translate "$build/smoke-api.exe" \
  --api-spec "$here/smoke-api.json" --opt-level 1 --output-dir "$build/lifted-api"

node - "$build/lifted-api/lifted.wasm" <<'JS'
const fs = require("node:fs");
const path = process.argv[2];
let memory;
let instance;
let hostCalls = 0;
const imports = {
  "win32.test.dll": {
      HostAdd(stackPointer) {
        const view = new DataView(memory.buffer);
        hostCalls++;
        if (hostCalls === 2) instance.exports.d2_request_yield();
      return view.getUint32(stackPointer, true) + view.getUint32(stackPointer + 4, true);
    },
  },
};
(async () => {
  ({ instance } = await WebAssembly.instantiate(fs.readFileSync(path), imports));
  memory = instance.exports.memory;
  const context = 0x80000;
  new Uint8Array(memory.buffer, context, 256).fill(0);
  let result = instance.exports.d2_run_context(context, 0x1000, 0x100000, 100);
  let status = instance.exports.d2_context_status(context);
  if (status !== 5 || instance.exports.d2_context_finished(context) !== 0 || hostCalls !== 2) {
    throw new Error(
      `translated PE/API did not yield: result ${result}, status ${status}, calls ${hostCalls}`,
    );
  }
  result = instance.exports.d2_run_context(context, 0x1000, 0x100000, 100);
  status = instance.exports.d2_context_status(context);
  if (result !== 42 || status !== 0 || instance.exports.d2_context_finished(context) !== 1) {
    throw new Error(`resumed PE/API returned ${result}, status ${status}`);
  }
  console.log(`translated PE/API yielded and resumed with ${result}, status ${status}`);
})().catch((error) => { console.error(error); process.exit(1); });
JS

clang --target=i686-pc-windows-msvc -O1 -ffreestanding -fno-stack-protector \
  -c "$here/smoke-reloc.c" -o "$build/smoke-reloc.obj"
lld-link /entry:entry /subsystem:console /machine:x86 /nodefaultlib /safeseh:no \
  /base:0x10000000 /fixed:no "/out:$build/smoke-reloc.exe" "$build/smoke-reloc.obj"
"$root/d2wasm.py" translate "$build/smoke-reloc.exe" \
  --load-base 0x01000000 --global-pc --output-dir "$build/lifted-reloc"
node "$here/smoke-reloc.mjs" \
  "$build/lifted-reloc/lifted.wasm" \
  "$build/lifted-reloc/translation.json" \
  "$build/smoke-reloc.exe"

clang --target=i686-pc-windows-msvc -c "$here/smoke-api.s" -o "$build/caller.obj"
lld-link /entry:entry /subsystem:console /machine:x86 /nodefaultlib /fixed /safeseh:no \
  "/out:$build/caller.exe" "$build/caller.obj" "$build/test.lib"
clang --target=i686-pc-windows-msvc -O1 -ffreestanding -fno-stack-protector \
  -c "$here/smoke-linked.c" -o "$build/test.obj"
lld-link /dll /noentry /machine:x86 /nodefaultlib /safeseh:no /base:0x10000000 \
  "/def:$here/smoke-linked.def" "/out:$build/test.dll" "$build/test.obj"
"$root/d2wasm.py" link "$build" \
  --filename-map "$here/smoke-linked-map.json" \
  --entry-module caller.exe \
  --output "$build/smoke-linked.json"
"$root/d2wasm.py" link-translate "$build" \
  --link-manifest "$build/smoke-linked.json" \
  --output-dir "$build/lifted-linked"
linked_output="$(node "$root/runtime/run-linked.mjs" \
  "$build/lifted-linked/linked.wasm" \
  "$build/lifted-linked/linked-translation.json" \
  "$build/smoke-linked.json" \
  "$build")"
node - "$linked_output" <<'JS'
const output = JSON.parse(process.argv[2]);
if (output.result !== 42 || output.status !== 0) {
  throw new Error(`linked translated PEs returned ${output.result}, status ${output.status}`);
}
console.log(`linked translated PEs returned ${output.result}, status ${output.status}`);
JS

"$root/d2wasm.py" link "$root/../extracted" \
  --filename-map "$root/filename-map.json" \
  --entry-module "Diablo II.exe" \
  --output "$build/diablo-link.json"
node "$here/link-manifest.mjs" "$build/diablo-link.json" "$root/../extracted"
