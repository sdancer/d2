#!/usr/bin/env node
import fs from "node:fs";
import { mapPeImage, readPe } from "./load-pe.mjs";
import { Win32Runtime } from "./win32.mjs";

const [wasmPath, reportPath, pePath] = process.argv.slice(2);
if (!wasmPath || !reportPath || !pePath) {
  console.error("usage: run-translated.mjs LIFTED.wasm translation.json INPUT.exe");
  process.exit(64);
}

const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
const runtime = new Win32Runtime();
const module = await WebAssembly.compile(fs.readFileSync(wasmPath));
const required = WebAssembly.Module.imports(module);
const available = runtime.imports();
for (const item of required) {
  if (!available[item.module]?.[item.name]) {
    available[item.module] ??= {};
    available[item.module][item.name] = () => {
      throw new Error(`direct host API is not implemented: ${item.module}.${item.name}`);
    };
  }
}
const instance = await WebAssembly.instantiate(module, available);
runtime.attach(instance.exports.memory);
mapPeImage(instance.exports.memory, readPe(pePath), report.source);

const fsBase = 0x00700000;
new DataView(instance.exports.memory.buffer).setUint32(fsBase, 0xffffffff, true);
instance.exports.d2_set_fs_base(fsBase);
const stackTop = 0x10000000;
runtime.ensure(stackTop);
const result = instance.exports.d2_run(report.roots[0], stackTop, 1_000_000);
const trace = [];
for (let back = Math.min(instance.exports.d2_trace_count(), 16) - 1; back >= 0; back--) {
  trace.push({
    rva: `0x${instance.exports.d2_trace_pc(back).toString(16).padStart(8, "0")}`,
    esp: `0x${instance.exports.d2_trace_esp(back).toString(16).padStart(8, "0")}`,
  });
}
const stackWords = [];
const memoryView = new DataView(instance.exports.memory.buffer);
for (let address = stackTop - 0x100; address < stackTop - 0xa0; address += 4) {
  stackWords.push({
    address: `0x${address.toString(16)}`,
    value: `0x${memoryView.getUint32(address, true).toString(16).padStart(8, "0")}`,
  });
}
console.log(JSON.stringify({
  result,
  status: instance.exports.d2_last_status(),
  lastRva: `0x${instance.exports.d2_last_rva().toString(16).padStart(8, "0")}`,
  previousRva: `0x${instance.exports.d2_previous_rva().toString(16).padStart(8, "0")}`,
  exitCode: runtime.exitCode,
  trace,
  stackWords,
  runtimeEvents: runtime.events.slice(-20).map((event) => ({
    ...event,
    start: `0x${event.start.toString(16)}`,
  })),
}));
