#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { mapLinkedImages } from "./load-pe.mjs";
import { Win32Runtime } from "./win32.mjs";

const [wasmPath, translationPath, manifestPath, sourceDir, hostRoot, watchText] = process.argv.slice(2);
if (!wasmPath || !translationPath || !manifestPath || !sourceDir) {
  console.error("usage: run-linked.mjs linked.wasm linked-translation.json link.json PE_DIR [HOST_ROOT] [WATCH_VA]");
  process.exit(64);
}
const translation = JSON.parse(fs.readFileSync(translationPath, "utf8"));
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const heapBase = (Number(manifest.summary.highest_mapped_address) + 0xffff) & ~0xffff;
const runtime = new Win32Runtime({
  hostRoot,
  heapBase,
  commandLine: process.env.D2_COMMAND_LINE,
});
runtime.registerLinkedModules(manifest);
const module = await WebAssembly.compile(fs.readFileSync(wasmPath));
const imports = runtime.imports();
for (const item of WebAssembly.Module.imports(module)) {
  imports[item.module] ??= {};
  imports[item.module][item.name] ??= () => {
    throw new Error(`direct host API is not implemented: ${item.module}.${item.name}`);
  };
}
const instance = await WebAssembly.instantiate(module, imports);
const stackTop = 0x10000000;
runtime.reserve(stackTop - 0x00100000, stackTop + 0x00010000);
runtime.attach(instance.exports.memory, instance.exports);
runtime.ensure(stackTop + 0x100);
mapLinkedImages(instance.exports.memory, manifest, (pe) =>
  new Uint8Array(fs.readFileSync(path.join(sourceDir, pe.source))),
);
const fsBase = 0x00700000;
new DataView(instance.exports.memory.buffer).setUint32(fsBase, 0xffffffff, true);
instance.exports.d2_set_fs_base(fsBase);
if (process.env.D2_DIAGNOSTICS) instance.exports.d2_set_diagnostics?.(1);
if (watchText && !process.env.D2_ARCHIVE_PROBE) {
  if (process.env.D2_WATCH_AFTER_PRESENTATION) {
    runtime.delayedWatchPc = Number.parseInt(watchText, 0) >>> 0;
    runtime.delayedWatchPresentation = Number(process.env.D2_WATCH_AFTER_PRESENTATION);
  } else {
    instance.exports.d2_set_watch_pc(Number.parseInt(watchText, 0));
  }
}
const moduleByName = new Map(manifest.modules.map((item) => [item.runtime_name.toLowerCase(), item]));
const dependencies = new Map();
for (const binding of manifest.internal_bindings) {
  const importer = binding.importer.toLowerCase(), target = binding.target_module.toLowerCase();
  if (importer === target) continue;
  if (!dependencies.has(importer)) dependencies.set(importer, new Set());
  dependencies.get(importer).add(target);
}
const initializationOrder = [], visited = new Set(), visiting = new Set();
const visit = (name) => {
  if (visited.has(name) || visiting.has(name)) return;
  visiting.add(name);
  for (const dependency of dependencies.get(name) ?? []) visit(dependency);
  visiting.delete(name); visited.add(name);
  if (name !== manifest.entry_module.toLowerCase()) initializationOrder.push(name);
};
visit(manifest.entry_module.toLowerCase());

const dllInitialization = [];
let initializationFailure = null;
const memoryView = new Proxy({}, {
  get(_target, property) {
    const view = new DataView(instance.exports.memory.buffer);
    const value = Reflect.get(view, property, view);
    return typeof value === "function" ? value.bind(view) : value;
  },
});
for (const name of initializationOrder) {
  const item = moduleByName.get(name);
  if (!item?.entry_rva) continue;
  memoryView.setUint32(stackTop, item.load_base, true);
  memoryView.setUint32(stackTop + 4, 1, true);
  // These dependencies are statically imported by the process. Windows uses
  // a non-null lpReserved for DLL_PROCESS_ATTACH during process startup.
  memoryView.setUint32(stackTop + 8, 1, true);
  const result = instance.exports.d2_run((item.load_base + item.entry_rva) >>> 0, stackTop, 1_000_000);
  const status = instance.exports.d2_last_status();
  const record = { module: item.runtime_name, result, status };
  if (instance.exports.d2_watch_hit()) {
    const names = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
    record.watch = Object.fromEntries(names.map((register, index) => [register, instance.exports.d2_watch_register(index) >>> 0]));
  }
  if (process.env.D2_TRACK_CRYPT_TABLE) {
    const storm = moduleByName.get("storm.dll");
    const cryptTablePointer = memoryView.getUint32((storm.load_base + 0x399a4) >>> 0, true);
    record.cryptTablePointer = cryptTablePointer;
    record.cryptTableD0 = cryptTablePointer ? memoryView.getUint32(cryptTablePointer + 0x110, true) : 0;
  }
  dllInitialization.push(record);
  if (status !== 0 || result === 0) { initializationFailure = record; break; }
}

let archiveProbe = null;
const runArchiveProbe = () => {
  if (watchText) instance.exports.d2_set_watch_pc(Number.parseInt(watchText, 0));
  const storm = moduleByName.get("storm.dll");
  const openFile = storm?.exports?.find((item) => item.ordinal === 267);
  if (openFile) {
    const filename = runtime.allocCString(process.env.D2_ARCHIVE_PROBE);
    const outputPointer = runtime.alloc(4);
    const beforeCryptTablePointer = memoryView.getUint32((storm.load_base + 0x399a4) >>> 0, true);
    const beforeCryptTableD0 = beforeCryptTablePointer ? memoryView.getUint32(beforeCryptTablePointer + 0x110, true) : 0;
    memoryView.setUint32(stackTop, filename, true);
    memoryView.setUint32(stackTop + 4, outputPointer, true);
    const probeResult = instance.exports.d2_run((storm.load_base + openFile.rva) >>> 0, stackTop, 1_000_000);
    const fileHandle = memoryView.getUint32(outputPointer, true);
    let fileSize = 0, readResult = 0, bytesRead = 0, preview = [];
    if (probeResult && fileHandle) {
      const getFileSize = storm.exports.find((item) => item.ordinal === 265);
      const readFile = storm.exports.find((item) => item.ordinal === 289);
      const highSize = runtime.alloc(4);
      memoryView.setUint32(stackTop, fileHandle, true);
      memoryView.setUint32(stackTop + 4, highSize, true);
      fileSize = instance.exports.d2_run((storm.load_base + getFileSize.rva) >>> 0, stackTop, 1_000_000) >>> 0;
      if (fileSize && fileSize < 16 * 1024 * 1024) {
        const buffer = runtime.alloc(fileSize);
        const bytesReadPointer = runtime.alloc(4);
        const args = [fileHandle, buffer, fileSize, bytesReadPointer, 0, 0, 0];
        args.forEach((value, index) => memoryView.setUint32(stackTop + index * 4, value, true));
        readResult = instance.exports.d2_run((storm.load_base + readFile.rva) >>> 0, stackTop, 1_000_000);
        bytesRead = memoryView.getUint32(bytesReadPointer, true);
        preview = Array.from(new Uint8Array(instance.exports.memory.buffer, buffer, Math.min(bytesRead, 32)));
        if (bytesRead && process.env.D2_ARCHIVE_PROBE_OUTPUT) {
          const outputPath = path.resolve(process.env.D2_ARCHIVE_PROBE_OUTPUT);
          fs.mkdirSync(path.dirname(outputPath), { recursive: true });
          fs.writeFileSync(outputPath, new Uint8Array(instance.exports.memory.buffer, buffer, bytesRead));
        }
      }
    }
    const cryptTablePointer = memoryView.getUint32((storm.load_base + 0x399a4) >>> 0, true);
    return {
      filename: process.env.D2_ARCHIVE_PROBE,
      result: probeResult,
      status: instance.exports.d2_last_status(),
      output: memoryView.getUint32(outputPointer, true),
      fileSize,
      readResult,
      bytesRead,
      preview,
      beforeCryptTablePointer,
      beforeCryptTableD0,
      cryptTablePointer,
      cryptTableD: [0, 1, 2, 3, 4].map((type) => memoryView.getUint32(cryptTablePointer + (type * 256 + 0x44) * 4, true)),
      threads: Array.from(runtime.handles.values())
        .filter((item) => item.type === "thread")
        .map(({ handle, start, status, finished, exitCode, context }) => ({
          handle, start, status, finished, exitCode,
          nextPc: memoryView.getUint32(context + 12, true),
          lastPc: memoryView.getUint32(context + 16, true),
          previousPc: memoryView.getUint32(context + 20, true),
        })),
      schedulerEvents: runtime.schedulerEvents.slice(-32),
      fileIoEvents: runtime.fileIoEvents.slice(-32),
      apiCounts: Object.fromEntries(Array.from(runtime.apiCounts.entries()).sort((left, right) => right[1] - left[1]).slice(0, 64)),
      recentApis: runtime.recentApis.slice(-32),
    };
  }
  return null;
};
if (!initializationFailure && process.env.D2_ARCHIVE_PROBE && !process.env.D2_ARCHIVE_PROBE_AFTER_MAIN) {
  archiveProbe = runArchiveProbe();
}

let applicationRun = null;
if (process.env.D2_STOP_ON_WATCH) instance.exports.d2_set_stop_on_watch?.(1);
if (process.env.D2_WATCH_SKIP) instance.exports.d2_set_watch_skip?.(Number(process.env.D2_WATCH_SKIP));
if (process.env.D2_COUNT_PC) instance.exports.d2_set_count_pc?.(Number.parseInt(process.env.D2_COUNT_PC, 0));
let result = initializationFailure ? initializationFailure.result
  : process.env.D2_DLL_INIT_ONLY ? 0
  : process.env.D2_ARCHIVE_PROBE_ONLY ? archiveProbe?.result ?? 0
  : 0;
if (!initializationFailure && !process.env.D2_DLL_INIT_ONLY && !process.env.D2_ARCHIVE_PROBE_ONLY) {
  const context = runtime.alloc(256, 8);
  const fuel = Number(process.env.D2_MAIN_FUEL ?? 1_000_000);
  const maximumRounds = Number(process.env.D2_MAIN_ROUNDS ?? 8);
  let rounds = 0, status = 1;
  let capturedWatch = null;
  while (rounds < maximumRounds && status === 1) {
    result = instance.exports.d2_run_context(context, translation.entry_va, stackTop, fuel);
    runtime.runPendingThreads(Math.min(fuel, 50_000));
    status = instance.exports.d2_context_status(context) >>> 0;
    rounds++;
    if (instance.exports.d2_context_watch_hit(context)) {
      const names = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
      const registers = Object.fromEntries(names.map((name, index) => [name, instance.exports.d2_context_watch_register(context, index) >>> 0]));
      const preview = (pointer) => pointer && pointer < instance.exports.memory.buffer.byteLength
        ? Array.from(new Uint8Array(instance.exports.memory.buffer, pointer, Math.min(64, instance.exports.memory.buffer.byteLength - pointer)))
        : [];
      capturedWatch = {
        round: rounds,
        ...registers,
        pointers: Object.fromEntries(names.map((name) => [name, preview(registers[name])]).filter(([, bytes]) => bytes.length)),
        stack: Array.from({ length: 32 }, (_, index) => memoryView.getUint32(registers.esp + index * 4, true)),
        deepStack: Object.fromEntries(
          [0x21c, 0x220, 0x224, 0x228, 0x22c, 0x230, 0x234, 0x238, 0x23c]
            .map((offset) => [`0x${offset.toString(16)}`, memoryView.getUint32(registers.esp + offset, true)]),
        ),
      };
      if (process.env.D2_WATCH_WORDS) {
        capturedWatch.memoryWords = Object.fromEntries(process.env.D2_WATCH_WORDS.split(",").map((text) => {
          const address = Number.parseInt(text.trim(), 0) >>> 0;
          return [`0x${address.toString(16).padStart(8, "0")}`, memoryView.getUint32(address, true)];
        }));
      }
      if (process.env.D2_STOP_ON_WATCH) break;
    }
  }
  applicationRun = {
    result,
    status,
    finished: Boolean(instance.exports.d2_context_finished(context)),
    rounds,
    lastVa: memoryView.getUint32(context + 16, true),
    previousVa: memoryView.getUint32(context + 20, true),
    nextVa: memoryView.getUint32(context + 12, true),
  };
  if (process.env.D2_WATCH_WORDS) {
    applicationRun.memoryWords = Object.fromEntries(process.env.D2_WATCH_WORDS.split(",").map((text) => {
      const address = Number.parseInt(text.trim(), 0) >>> 0;
      return [`0x${address.toString(16).padStart(8, "0")}`, memoryView.getUint32(address, true)];
    }));
  }
  if (capturedWatch) applicationRun.watch = capturedWatch;
}
if (!initializationFailure && process.env.D2_ARCHIVE_PROBE_AFTER_MAIN) {
  archiveProbe = runArchiveProbe();
  result = archiveProbe?.result ?? result;
}
const traceCount = instance.exports.d2_trace_count();
const trace = Array.from({ length: Math.min(traceCount, 16) }, (_, back) => ({
  va: `0x${instance.exports.d2_trace_pc(back).toString(16).padStart(8, "0")}`,
  esp: `0x${instance.exports.d2_trace_esp(back).toString(16).padStart(8, "0")}`,
}));
const messageBox = runtime.events.findLast((event) => event.type === "message-box");
const compactEvents = runtime.events.slice(-16).map(({ trace: _trace, ...event }) => event);
const compactProbeOutput = Boolean(process.env.D2_ARCHIVE_PROBE);
const screen = runtime.handles.get(runtime.screenBitmapHandle);
let screenSummary = null;
if (screen) {
  const bytes = new Uint8Array(instance.exports.memory.buffer, screen.bits, screen.size);
  let checksum = 2166136261;
  for (const value of bytes) checksum = Math.imul(checksum ^ value, 16777619) >>> 0;
  screenSummary = {
    width: screen.width, height: screen.height, bitsPerPixel: screen.bitsPerPixel,
    bits: screen.bits, presentations: runtime.screenPresentations, checksum,
  };
}
const output = {
  result,
  status: instance.exports.d2_last_status(),
  lastVa: `0x${instance.exports.d2_last_rva().toString(16).padStart(8, "0")}`,
  previousVa: `0x${instance.exports.d2_previous_rva().toString(16).padStart(8, "0")}`,
  exitCode: runtime.exitCode,
  dllInitialization,
  initializationFailure,
  applicationRun,
  archiveProbe,
  callbackWatch: runtime.callbackWatch ?? null,
  countHits: instance.exports.d2_count_hits?.() ?? null,
  callbacks: runtime.callbackEvents?.slice(-32) ?? [],
  threadWatches: Array.from(runtime.handles.values())
    .filter((item) => item.type === "thread" && item.context
      && instance.exports.d2_context_watch_hit(item.context))
    .map((item) => ({
      handle: item.handle,
      start: item.start,
      status: item.status,
      finished: item.finished,
      registers: Object.fromEntries(
        ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]
          .map((name, index) => [name, instance.exports.d2_context_watch_register(item.context, index) >>> 0]),
      ),
    })),
  threadWatchEvents: runtime.threadWatchEvents ?? [],
  screen: screenSummary,
  events: compactProbeOutput ? [] : compactEvents,
  messageBoxTrace: compactProbeOutput ? [] : messageBox?.trace?.map(({ va, esp }) => ({
    va: `0x${va.toString(16).padStart(8, "0")}`,
    esp: `0x${esp.toString(16).padStart(8, "0")}`,
  })) ?? [],
  messageBoxStack: compactProbeOutput ? [] : messageBox?.stackCodePointers?.map(({ stack, va }) => ({
    stack: `0x${stack.toString(16).padStart(8, "0")}`,
    va: `0x${va.toString(16).padStart(8, "0")}`,
  })) ?? [],
  fileEvents: compactProbeOutput ? [] : runtime.events.filter((event) => event.type === "open" || event.type === "open-error" || event.type === "read-error").slice(-32),
  trace,
};
if (screen && process.env.D2_FRAMEBUFFER_PPM) {
  const header = Buffer.from(`P6\n${screen.width} ${screen.height}\n255\n`);
  const pixels = Buffer.alloc(screen.width * screen.height * 3);
  const source = new Uint8Array(instance.exports.memory.buffer, screen.bits, screen.size);
  for (let index = 0; index < screen.width * screen.height; index++) {
    pixels[index * 3] = source[index * 4 + 2];
    pixels[index * 3 + 1] = source[index * 4 + 1];
    pixels[index * 3 + 2] = source[index * 4];
  }
  fs.writeFileSync(process.env.D2_FRAMEBUFFER_PPM, Buffer.concat([header, pixels]));
  output.framebufferPath = path.resolve(process.env.D2_FRAMEBUFFER_PPM);
}
if (instance.exports.d2_watch_hit()) {
  const names = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
  output.watch = Object.fromEntries(names.map((name, index) => [name, instance.exports.d2_watch_register(index) >>> 0]));
  const watchView = new DataView(instance.exports.memory.buffer);
  output.watch.stack = Array.from({ length: 16 }, (_, index) => watchView.getUint32(output.watch.esp + index * 4, true));
}
console.log(JSON.stringify(output));
