import { installMemoryFiles } from "/runtime/host-platform.mjs";
import { mapLinkedImages } from "/runtime/load-pe.mjs";
import { Win32Runtime } from "/runtime/win32.mjs";

const STACK_TOP = 0x10000000;
const FS_BASE = 0x00700000;
const FUEL_PER_ROUND = 1_000_000;

let runtime;
let instance;
let context;
let running = false;
let paused = false;
let rounds = 0;
let eventIndex = 0;
let surface;
let surfaceContext;
let stagingSurface;
let stagingContext;
let frame;

const send = (type, detail = {}) => postMessage({ type, ...detail });
const delay = () => new Promise((resolve) => setTimeout(resolve, 0));

async function fetchBytes(url, onProgress = null) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`HTTP ${response.status} while fetching ${url}`);
  if (!response.body || !onProgress) return new Uint8Array(await response.arrayBuffer());
  const chunks = [];
  let length = 0;
  const reader = response.body.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    length += value.byteLength;
    onProgress(length);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function render(bitmap, presentation, viewport = bitmap) {
  if (!surfaceContext || !runtime?.memory) return;
  const width = viewport.width;
  const height = viewport.height;
  if (!frame || frame.width !== width || frame.height !== height) {
    stagingSurface = new OffscreenCanvas(width, height);
    stagingContext = stagingSurface.getContext("2d", { alpha: false });
    frame = surfaceContext.createImageData(width, height);
    send("frame-size", { width, height });
  }
  const source = new Uint8Array(runtime.memory.buffer, bitmap.bits, bitmap.size);
  const output = frame.data;
  for (let y = 0; y < height; y++) {
    const sourceRow = bitmap.topDown ? y : bitmap.height - 1 - y;
    for (let x = 0; x < width; x++) {
      const input = sourceRow * bitmap.stride + x * 4;
      const index = (y * width + x) * 4;
      output[index] = source[input + 2];
      output[index + 1] = source[input + 1];
      output[index + 2] = source[input];
      output[index + 3] = 0xff;
    }
  }
  stagingContext.putImageData(frame, 0, 0);
  surfaceContext.imageSmoothingEnabled = false;
  surfaceContext.clearRect(0, 0, surface.width, surface.height);
  surfaceContext.drawImage(stagingSurface, 0, 0, surface.width, surface.height);
  if (presentation % 10 === 0) {
    send("state", { message: `Running · round ${rounds} · presentation ${presentation}` });
  }
}

function initializationOrder(manifest) {
  const dependencies = new Map();
  for (const binding of manifest.internal_bindings) {
    const importer = binding.importer.toLowerCase();
    const target = binding.target_module.toLowerCase();
    if (importer === target) continue;
    if (!dependencies.has(importer)) dependencies.set(importer, new Set());
    dependencies.get(importer).add(target);
  }
  const order = [];
  const visited = new Set();
  const visiting = new Set();
  const visit = (name) => {
    if (visited.has(name) || visiting.has(name)) return;
    visiting.add(name);
    for (const dependency of dependencies.get(name) ?? []) visit(dependency);
    visiting.delete(name);
    visited.add(name);
    if (name !== manifest.entry_module.toLowerCase()) order.push(name);
  };
  visit(manifest.entry_module.toLowerCase());
  return order;
}

function drainEvents() {
  while (eventIndex < runtime.events.length) {
    const event = runtime.events[eventIndex++];
    if (event.type === "message-box") {
      send("message-box", { caption: event.caption, text: event.text });
    } else if (event.type === "direct-sound-created") {
      send("log", { message: "DirectSound device created" });
    } else if (event.type === "direct-sound-playback") {
      send("log", { message: "DirectSound PCM playback active" });
    } else if (event.type.endsWith("error")) {
      send("log", { message: `${event.type}: ${event.requested ?? event.path ?? ""} ${event.error ?? ""}`.trim() });
    }
  }
}

async function initialize(canvas, demo) {
  surface = canvas;
  surface.width = 800;
  surface.height = 600;
  surfaceContext = surface.getContext("2d", { alpha: false, desynchronized: true });
  send("progress", { title: "Reading web configuration…", detail: "" });
  const configResponse = await fetch("/api/config");
  if (!configResponse.ok) throw new Error(await configResponse.text());
  const config = await configResponse.json();

  const [manifest, translation] = await Promise.all([
    fetch(config.manifest).then((response) => response.json()),
    fetch(config.translation).then((response) => response.json()),
  ]);
  const compile = WebAssembly.compileStreaming(fetch(config.wasm));

  let loaded = 0;
  const memoryEntries = [];
  for (let index = 0; index < config.gameFiles.length; index++) {
    const item = config.gameFiles[index];
    const before = loaded;
    const bytes = await fetchBytes(item.url, (current) => {
      const total = before + current;
      send("progress", {
        title: `Loading game data ${index + 1}/${config.gameFiles.length}`,
        detail: `${(total / 1048576).toFixed(1)} / ${(config.gameBytes / 1048576).toFixed(1)} MB · ${item.path}`,
      });
    });
    loaded += bytes.byteLength;
    memoryEntries.push([`/d2/${item.path}`, bytes]);
  }
  installMemoryFiles(memoryEntries);

  send("progress", { title: "Loading PE images…", detail: "Preparing the linked Windows address space." });
  const peBytes = new Map();
  for (let index = 0; index < manifest.modules.length; index++) {
    const module = manifest.modules[index];
    peBytes.set(module.source, await fetchBytes(`${config.peBase}${encodeURIComponent(module.source)}`));
    send("progress", {
      title: `Loading PE images ${index + 1}/${manifest.modules.length}`,
      detail: module.runtime_name,
    });
  }

  const wasmModule = await compile;
  const heapBase = (Number(manifest.summary.highest_mapped_address) + 0xffff) & ~0xffff;
  let environment = {};
  if (demo && config.savedCharacters.length) {
    environment = {
      D2_AUTO_CLICKS: "400,208,350;550,180,600;400,555,750",
    };
  } else if (demo) {
    environment = {
      D2_AUTO_CLICKS: "400,208,350;400,280,600;690,555,850;250,290,900",
      D2_AUTO_TEXT: `Chrome${Date.now().toString().slice(-5)},750`,
    };
  }
  runtime = new Win32Runtime({
    hostRoot: "/d2",
    heapBase,
    environment,
    stdout: (text) => send("log", { message: text }),
    onPresent: render,
    onAudio: (event) => {
      if (event.type === "play") {
        postMessage({ type: "audio-play", ...event, bytes: event.bytes.buffer }, [event.bytes.buffer]);
      } else {
        send("audio-stop", { id: event.id });
      }
    },
  });
  runtime.registerLinkedModules(manifest);
  const imports = runtime.imports();
  for (const item of WebAssembly.Module.imports(wasmModule)) {
    imports[item.module] ??= {};
    imports[item.module][item.name] ??= () => {
      throw new Error(`direct host API is not implemented: ${item.module}.${item.name}`);
    };
  }

  send("progress", { title: "Instantiating translated game…", detail: "Mapping modules and initializing Diablo DLLs." });
  instance = await WebAssembly.instantiate(wasmModule, imports);
  runtime.reserve(STACK_TOP - 0x00100000, STACK_TOP + 0x00010000);
  runtime.attach(instance.exports.memory, instance.exports);
  runtime.ensure(STACK_TOP + 0x100);
  mapLinkedImages(instance.exports.memory, manifest, (module) => peBytes.get(module.source));
  new DataView(instance.exports.memory.buffer).setUint32(FS_BASE, 0xffffffff, true);
  instance.exports.d2_set_fs_base(FS_BASE);

  const moduleByName = new Map(manifest.modules.map((item) => [item.runtime_name.toLowerCase(), item]));
  const view = new DataView(instance.exports.memory.buffer);
  for (const name of initializationOrder(manifest)) {
    const module = moduleByName.get(name);
    if (!module?.entry_rva) continue;
    view.setUint32(STACK_TOP, module.load_base, true);
    view.setUint32(STACK_TOP + 4, 1, true);
    view.setUint32(STACK_TOP + 8, 1, true);
    const result = instance.exports.d2_run((module.load_base + module.entry_rva) >>> 0, STACK_TOP, FUEL_PER_ROUND) >>> 0;
    const status = instance.exports.d2_last_status() >>> 0;
    send("log", { message: `${module.runtime_name} initialization: result=${result}, status=${status}` });
    if (!result || status !== 0) throw new Error(`${module.runtime_name} initialization failed`);
  }

  context = runtime.alloc(256, 8);
  running = true;
  send("ready", { message: "Browser host initialized; mouse and keyboard input are live." });
  await run(translation.entry_va);
}

async function run(entry) {
  let status = 1;
  while (running && status === 1) {
    if (paused) {
      await new Promise((resolve) => setTimeout(resolve, 20));
      continue;
    }
    const result = instance.exports.d2_run_context(context, entry, STACK_TOP, FUEL_PER_ROUND) >>> 0;
    status = instance.exports.d2_context_status(context) >>> 0;
    rounds++;
    drainEvents();
    if (rounds % 10 === 0) send("state", { message: `Running · round ${rounds} · status ${status}` });
    if (instance.exports.d2_context_finished(context) || status !== 1) {
      const view = new DataView(instance.exports.memory.buffer);
      const next = view.getUint32(context + 12, true).toString(16).padStart(8, "0");
      running = false;
      send("stopped", { message: `result=0x${result.toString(16)}, status=${status}, next=0x${next}` });
      break;
    }
    await delay();
  }
}

function pointerMessage(kind, button) {
  if (kind === "move") return 0x0200;
  if (button === 2) return kind === "down" ? 0x0204 : 0x0205;
  return kind === "down" ? 0x0201 : 0x0202;
}

self.addEventListener("message", ({ data }) => {
  if (data.type === "start") {
    initialize(data.canvas, data.demo).catch((error) => {
      running = false;
      send("error", { message: error.message, stack: error.stack });
    });
  } else if (data.type === "pause") {
    paused = true;
  } else if (data.type === "resume") {
    paused = false;
  } else if (data.type === "pointer" && runtime) {
    const message = pointerMessage(data.kind, data.button);
    const wParam = data.kind === "down" ? (data.button === 2 ? 2 : 1) : 0;
    runtime.enqueuePointer(message, data.x, data.y, wParam);
  } else if (data.type === "wheel" && runtime) {
    const wParam = ((data.delta & 0xffff) << 16) >>> 0;
    runtime.enqueuePointer(0x020a, data.x, data.y, wParam);
  } else if (data.type === "key" && runtime) {
    runtime.enqueueKey(data.virtualKey, data.down);
  } else if (data.type === "character" && runtime) {
    runtime.enqueueCharacter(data.codePoint);
  }
});
