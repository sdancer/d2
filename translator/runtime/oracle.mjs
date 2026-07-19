#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { mapLinkedImages } from "./load-pe.mjs";
import { Win32Runtime } from "./win32.mjs";

const comparableTrace = (trace) => trace
  .filter((event) => !["block", "edge", "replacement"].includes(event.kind))
  .map(({ sequence: _sequence, ...event }) => event);

const stable = (value) => JSON.stringify(value);

export async function loadOracle(wasmPath, translationPath, manifestPath, sourceDir, hostRoot = null) {
  const translation = JSON.parse(fs.readFileSync(translationPath, "utf8"));
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const heapBase = (Number(manifest.summary.highest_mapped_address) + 0xffff) & ~0xffff;
  const runtime = new Win32Runtime({ hostRoot, heapBase });
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
    new Uint8Array(fs.readFileSync(path.join(sourceDir, pe.source))));
  const fsBase = 0x00700000;
  new DataView(instance.exports.memory.buffer).setUint32(fsBase, 0xffffffff, true);
  instance.exports.d2_set_fs_base(fsBase);
  return { runtime, instance, manifest, translation, stackTop };
}

export async function executeOracle(config) {
  const oracle = await loadOracle(
    config.wasm, config.translation, config.manifest, config.sourceDir, config.hostRoot,
  );
  const { runtime, stackTop } = oracle;
  const invoke = (request) => runtime.invokeFunction({ stackTop, ...request });
  if (config.operation === "invoke") return invoke(config.request);
  if (config.operation === "snapshot") return runtime.snapshot(config.ranges ?? []);
  if (config.operation === "differential") {
    const snapshot = runtime.snapshot(config.request.ranges ?? []);
    const reference = invoke(config.request);
    runtime.restoreSnapshot(snapshot);
    runtime.clearReplacements();
    if (!runtime.setReplacement(
      config.replacement.entry,
      config.replacement.kind,
      config.replacement.value ?? 0,
      config.replacement.stackCleanup ?? 0,
    )) throw new Error("replacement table is full");
    const replacement = invoke(config.request);
    runtime.clearReplacements();
    const registerDiff = {};
    for (const name of Object.keys(reference.registers)) {
      if (reference.registers[name] !== replacement.registers[name]) {
        registerDiff[name] = { reference: reference.registers[name], replacement: replacement.registers[name] };
      }
    }
    const memoryDiff = stable(reference.memory) === stable(replacement.memory) ? [] : [
      { reference: reference.memory, replacement: replacement.memory },
    ];
    const referenceEvents = comparableTrace(reference.trace);
    const replacementEvents = comparableTrace(replacement.trace);
    const eventDiff = stable(referenceEvents) === stable(replacementEvents) ? [] : [
      { reference: referenceEvents, replacement: replacementEvents },
    ];
    return {
      equivalent: reference.result === replacement.result
        && reference.status === replacement.status
        && Object.keys(registerDiff).length === 0
        && memoryDiff.length === 0
        && eventDiff.length === 0,
      reference,
      replacement,
      registerDiff,
      memoryDiff,
      eventDiff,
      snapshot,
    };
  }
  throw new Error(`unknown oracle operation: ${config.operation}`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const configPath = process.argv[2];
  if (!configPath) {
    console.error("usage: oracle.mjs CONFIG.json");
    process.exit(64);
  }
  try {
    const result = await executeOracle(JSON.parse(fs.readFileSync(configPath, "utf8")));
    if (process.env.D2_TRACE_NDJSON && result.reference?.trace) {
      for (const event of result.reference.trace) console.error(JSON.stringify({ stream: "reference", ...event }));
      for (const event of result.replacement?.trace ?? []) console.error(JSON.stringify({ stream: "replacement", ...event }));
    }
    console.log(JSON.stringify(result));
  } catch (error) {
    console.error(error.stack ?? String(error));
    process.exit(1);
  }
}
