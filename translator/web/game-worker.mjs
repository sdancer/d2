import { installMemoryFiles } from "/runtime/host-platform.mjs";
import { mapLinkedImages } from "/runtime/load-pe.mjs";
import { Win32Runtime } from "/runtime/win32.mjs";
import { GlideWebGlRenderer } from "/glide-renderer.mjs";

const STACK_TOP = 0x10000000;
const FS_BASE = 0x00700000;
// Give the game most of the translated execution budget while still servicing
// the cooperative DirectSound threads once per browser turn.
const MAIN_FUEL_PER_ROUND = 1_000_000;
const THREAD_FUEL_PER_ROUND = 50_000;

let runtime;
let instance;
let context;
let running = false;
let paused = false;
let rounds = 0;
let eventIndex = 0;
let surface;
let surfaceContext;
let webgl;
let glideRenderer;
let stagingSurface;
let stagingContext;
let frame;
let lastRenderAt = -Infinity;

const send = (type, detail = {}) => postMessage({ type, ...detail });
const delay = () => new Promise((resolve) => setTimeout(resolve, 0));
const hex = (value) => `0x${(value >>> 0).toString(16).padStart(8, "0")}`;

function createWebGlPresenter(canvas) {
  const gl = canvas.getContext("webgl2", {
    alpha: false,
    antialias: false,
    depth: false,
    desynchronized: true,
    preserveDrawingBuffer: false,
  });
  if (!gl) return null;
  const shader = (type, source) => {
    const value = gl.createShader(type);
    gl.shaderSource(value, source);
    gl.compileShader(value);
    if (!gl.getShaderParameter(value, gl.COMPILE_STATUS)) {
      throw new Error(`WebGL shader compilation failed: ${gl.getShaderInfoLog(value)}`);
    }
    return value;
  };
  const program = gl.createProgram();
  gl.attachShader(program, shader(gl.VERTEX_SHADER, `#version 300 es
    in vec2 a_position;
    uniform vec2 u_scale;
    uniform bool u_top_down;
    out vec2 v_uv;
    void main() {
      gl_Position = vec4(a_position, 0.0, 1.0);
      vec2 point = a_position * 0.5 + 0.5;
      float v = u_top_down ? (1.0 - point.y) * u_scale.y : point.y * u_scale.y;
      v_uv = vec2(point.x * u_scale.x, v);
    }
  `));
  gl.attachShader(program, shader(gl.FRAGMENT_SHADER, `#version 300 es
    precision mediump float;
    uniform sampler2D u_frame;
    in vec2 v_uv;
    out vec4 color;
    void main() { color = texture(u_frame, v_uv).bgra; }
  `));
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    throw new Error(`WebGL program linking failed: ${gl.getProgramInfoLog(program)}`);
  }
  const vao = gl.createVertexArray();
  gl.bindVertexArray(vao);
  const vertices = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, vertices);
  gl.bufferData(
    gl.ARRAY_BUFFER,
    new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]),
    gl.STATIC_DRAW,
  );
  const position = gl.getAttribLocation(program, "a_position");
  gl.enableVertexAttribArray(position);
  gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0);
  const texture = gl.createTexture();
  gl.bindTexture(gl.TEXTURE_2D, texture);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
  gl.pixelStorei(gl.UNPACK_ALIGNMENT, 4);
  gl.useProgram(program);
  gl.uniform1i(gl.getUniformLocation(program, "u_frame"), 0);
  return {
    gl,
    program,
    vao,
    texture,
    scale: gl.getUniformLocation(program, "u_scale"),
    topDown: gl.getUniformLocation(program, "u_top_down"),
    textureWidth: 0,
    textureHeight: 0,
  };
}

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
  if ((!webgl && !surfaceContext) || !runtime?.memory) return false;
  const width = viewport.width;
  const height = viewport.height;
  if (!webgl && (!frame || frame.width !== width || frame.height !== height)) {
    stagingSurface = new OffscreenCanvas(width, height);
    stagingContext = stagingSurface.getContext("2d", { alpha: false });
    frame = surfaceContext.createImageData(width, height);
    send("frame-size", { width, height });
  } else if (webgl && (frame?.width !== width || frame?.height !== height)) {
    frame = { width, height };
    send("frame-size", { width, height });
  }
  const now = performance.now();
  if (now - lastRenderAt < 1000 / 30) return false;
  lastRenderAt = now;
  if (webgl && bitmap.bitsPerPixel === 32 && bitmap.stride === bitmap.width * 4) {
    const { gl } = webgl;
    const source = new Uint8Array(runtime.memory.buffer, bitmap.bits, bitmap.size);
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, webgl.texture);
    if (webgl.textureWidth !== bitmap.width || webgl.textureHeight !== bitmap.height) {
      gl.texImage2D(
        gl.TEXTURE_2D,
        0,
        gl.RGBA8,
        bitmap.width,
        bitmap.height,
        0,
        gl.RGBA,
        gl.UNSIGNED_BYTE,
        source,
      );
      webgl.textureWidth = bitmap.width;
      webgl.textureHeight = bitmap.height;
    } else {
      gl.texSubImage2D(
        gl.TEXTURE_2D,
        0,
        0,
        0,
        bitmap.width,
        bitmap.height,
        gl.RGBA,
        gl.UNSIGNED_BYTE,
        source,
      );
    }
    gl.useProgram(webgl.program);
    gl.bindVertexArray(webgl.vao);
    gl.uniform2f(webgl.scale, width / bitmap.width, height / bitmap.height);
    gl.uniform1i(webgl.topDown, bitmap.topDown ? 1 : 0);
    gl.viewport(0, 0, surface.width, surface.height);
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    return true;
  }
  const source = new Uint32Array(runtime.memory.buffer, bitmap.bits, bitmap.size >>> 2);
  const output = new Uint32Array(frame.data.buffer, frame.data.byteOffset, width * height);
  let index = 0;
  for (let y = 0; y < height; y++) {
    const sourceRow = bitmap.topDown ? y : bitmap.height - 1 - y;
    const input = sourceRow * (bitmap.stride >>> 2);
    for (let x = 0; x < width; x++) {
      const pixel = source[input + x];
      output[index++] = (0xff000000
        | (pixel & 0x0000ff00)
        | (pixel & 0x000000ff) << 16
        | (pixel & 0x00ff0000) >>> 16) >>> 0;
    }
  }
  stagingContext.putImageData(frame, 0, 0);
  surfaceContext.drawImage(stagingSurface, 0, 0, surface.width, surface.height);
  if (presentation % 10 === 0) {
    send("state", { message: `Running · round ${rounds} · presentation ${presentation}` });
  }
  return true;
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
      send("log", {
        message: `DirectSoundCreate: output=${hex(event.output)}, object=${hex(event.object)}, `
          + `vtable=${hex(event.vtable)}, result=${hex(event.result)}`,
      });
    } else if (event.type === "direct-sound-call") {
      const args = event.args.map(hex).join(", ");
      const suffix = event.error ? ` error=${event.error}` : "";
      send("log", {
        message: `DirectSound #${event.sequence} ${event.name}: object=${hex(event.object)}, `
          + `sp=${hex(event.sp)}, args=[${args}], result=${hex(event.result)}${suffix}`,
      });
    } else if (event.type === "direct-sound-playback") {
      send("log", { message: "DirectSound PCM playback active" });
    } else if (event.type.endsWith("error")) {
      send("log", { message: `${event.type}: ${event.requested ?? event.path ?? ""} ${event.error ?? ""}`.trim() });
    }
  }
}

async function initialize(canvas, demo, diagnostics = false, requestedRenderer = "glide", soundEnabled = false) {
  surface = canvas;
  surface.width = 800;
  surface.height = 600;
  webgl = createWebGlPresenter(surface);
  const renderer = requestedRenderer === "glide" && webgl ? "glide" : "gdi";
  if (renderer === "glide") {
    glideRenderer = new GlideWebGlRenderer(webgl.gl, surface, (width, height) => {
      send("frame-size", { width, height });
    });
  }
  if (!webgl) {
    surfaceContext = surface.getContext("2d", { alpha: false, desynchronized: true });
    surfaceContext.imageSmoothingEnabled = false;
  }
  send("log", {
    message: renderer === "glide"
      ? "D2Glide WebGL2 renderer active"
      : webgl
        ? "D2Gdi WebGL2 framebuffer presenter active"
        : "D2Gdi Canvas2D framebuffer fallback active",
  });
  if (!soundEnabled) send("log", { message: "DirectSound disabled by browser configuration" });
  if (requestedRenderer === "glide" && renderer !== "glide") {
    send("log", { message: "WebGL2 is unavailable; falling back to D2Gdi." });
  }
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
      D2_AUTO_CLICKS: renderer === "glide"
        ? "400,208,500;550,300,800;420,560,1100"
        : "400,208,700;550,300,1600;420,560,2600",
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
    diagnostics,
    soundEnabled,
    commandLine: renderer === "glide"
      ? '"C:\\Diablo II\\Diablo II.exe" -w -3dfx'
      : '"C:\\Diablo II\\Diablo II.exe" -w',
    cooperativeTiming: true,
    yieldOnPresent: true,
    stdout: (text) => send("log", { message: text }),
    onPresent: render,
    onGlide: (event) => glideRenderer?.handle(event, runtime.memory),
    onAudio: (event) => {
      if (event.type === "play" || event.type === "write") {
        const type = event.type === "play" ? "audio-play" : "audio-write";
        postMessage({ ...event, type, bytes: event.bytes.buffer }, [event.bytes.buffer]);
      } else if (event.type === "control") {
        postMessage({ ...event, type: "audio-control" });
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
  instance.exports.d2_set_diagnostics?.(diagnostics ? 1 : 0);

  const moduleByName = new Map(manifest.modules.map((item) => [item.runtime_name.toLowerCase(), item]));
  const view = new DataView(instance.exports.memory.buffer);
  for (const name of initializationOrder(manifest)) {
    const module = moduleByName.get(name);
    if (!module?.entry_rva) continue;
    view.setUint32(STACK_TOP, module.load_base, true);
    view.setUint32(STACK_TOP + 4, 1, true);
    view.setUint32(STACK_TOP + 8, 1, true);
    const result = instance.exports.d2_run(
      (module.load_base + module.entry_rva) >>> 0,
      STACK_TOP,
      MAIN_FUEL_PER_ROUND,
    ) >>> 0;
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
  while (running && (status === 1 || status === 5)) {
    if (paused) {
      await new Promise((resolve) => setTimeout(resolve, 20));
      continue;
    }
    const wait = runtime.mainResumeAt - runtime.clockNow();
    if (wait > 0) {
      await new Promise((resolve) => setTimeout(resolve, Math.min(wait, 20)));
      continue;
    }
    runtime.mainResumeAt = 0;
    const result = instance.exports.d2_run_context(
      context,
      entry,
      STACK_TOP,
      MAIN_FUEL_PER_ROUND,
    ) >>> 0;
    runtime.runPendingThreads(THREAD_FUEL_PER_ROUND);
    status = instance.exports.d2_context_status(context) >>> 0;
    rounds++;
    drainEvents();
    if (rounds % 10 === 0) {
      const view = new DataView(instance.exports.memory.buffer);
      const next = view.getUint32(context + 12, true);
      const last = view.getUint32(context + 16, true);
      const esp = view.getUint32(context + 92, true);
      const tick = esp + 0x44 <= view.byteLength - 4 ? view.getUint32(esp + 0x44, true) : 0;
      const pendingThreads = Array.from(runtime.handles.values())
        .filter((item) => item.type === "thread" && !item.finished);
      const thread = pendingThreads[0];
      const threadNext = thread?.context && thread.context + 12 <= view.byteLength - 4
        ? view.getUint32(thread.context + 12, true)
        : 0;
      send("state", {
        message: `Running · round ${rounds} · presentation ${runtime.screenPresentations} · `
          + `input ${runtime.autoClickIndex} · queue ${runtime.messageQueue.length} · `
          + `threads ${pendingThreads.length}`
          + (thread ? ` (${hex(thread.start)} → ${hex(threadNext)})` : "")
          + ` · next ${hex(next)} · last ${hex(last)} · tick ${hex(tick)} · `
          + `status ${status}`,
      });
    }
    const finished = Boolean(instance.exports.d2_context_finished(context));
    if (finished || status !== 1 && status !== 5) {
      const view = new DataView(instance.exports.memory.buffer);
      const read = (address) => address <= view.byteLength - 4
        ? view.getUint32(address, true)
        : 0;
      const next = read(context + 12);
      const last = read(context + 16);
      const previous = read(context + 20);
      const esp = read(context + 92);
      const stackStart = esp >= 32 ? esp - 32 : 0xffffffff;
      const stack = Array.from(
        { length: 12 },
        (_value, index) => read((stackStart + index * 4) >>> 0),
      );
      send("log", {
        message: `Stopped context: finished=${finished}, next=${hex(next)}, last=${hex(last)}, `
          + `previous=${hex(previous)}, esp=${hex(esp)}`,
      });
      send("log", { message: `Stopped stack[-32..+16]: ${stack.map(hex).join(" ")}` });
      const soundCalls = runtime.directSoundCalls.slice(-16);
      if (soundCalls.length) {
        send("log", {
          message: "Recent DirectSound calls:\n" + soundCalls.map((call) =>
            `  #${call.sequence} ${call.name} object=${hex(call.object)} result=${hex(call.result)}`
          ).join("\n"),
        });
      }
      const callbacks = (runtime.callbackEvents ?? []).slice(-8);
      if (callbacks.length) {
        send("log", {
          message: "Recent translated callbacks:\n" + callbacks.map((callback) =>
            `  ${hex(callback.address)} status=${callback.status} result=${hex(callback.result)} `
              + `args=[${callback.args.map(hex).join(", ")}]`
          ).join("\n"),
        });
      }
      running = false;
      send("stopped", {
        message: `result=${hex(result)}, status=${status}, finished=${finished}, next=${hex(next)}, `
          + `last=${hex(last)}, previous=${hex(previous)}, esp=${hex(esp)}`,
      });
      break;
    }
    await delay();
  }
}

function diagnosticSnapshot() {
  if (!runtime?.memory || !context) return null;
  const view = new DataView(runtime.memory.buffer);
  const read = (address) => address <= view.byteLength - 4 ? view.getUint32(address, true) : 0;
  const esp = read(context + 92);
  const d2win = runtime.moduleHandles.get("d2win.dll") ?? 0;
  const windows = [];
  const seen = new Set();
  for (let node = read(d2win + 0x5bcf8); node && windows.length < 32 && !seen.has(node); node = read(node + 0x3c)) {
    seen.add(node);
    windows.push({ node, callback: read(node + 0x20), next: read(node + 0x3c) });
  }
  const threads = Array.from(runtime.handles.values())
    .filter((item) => item.type === "thread")
    .map((item) => ({
      handle: item.handle,
      start: item.start,
      next: read(item.context + 12),
      last: read(item.context + 16),
      status: item.status,
      finished: item.finished,
    }));
  const sounds = Array.from(runtime.soundBuffers.values()).map((buffer) => ({
    id: buffer.id,
    object: buffer.object,
    size: buffer.size,
    frequency: buffer.frequency,
    playing: buffer.playing,
    playFlags: buffer.playFlags,
    playStarted: buffer.playStarted,
  }));
  return {
    rounds,
    presentations: runtime.screenPresentations,
    autoClickIndex: runtime.autoClickIndex,
    queue: runtime.messageQueue.slice(),
    context: {
      next: read(context + 12),
      last: read(context + 16),
      previous: read(context + 20),
      esp,
      stack: Array.from({ length: 32 }, (_value, index) => read(esp + index * 4)),
    },
    windows,
    threads,
    sounds,
    glide: glideRenderer?.snapshot() ?? null,
    recentApis: runtime.recentApis.slice(-32),
    schedulerEvents: runtime.schedulerEvents.slice(-32),
  };
}

function pointerMessage(kind, button) {
  if (kind === "move") return 0x0200;
  if (button === 2) return kind === "down" ? 0x0204 : 0x0205;
  return kind === "down" ? 0x0201 : 0x0202;
}

self.addEventListener("message", ({ data }) => {
  if (data.type === "start") {
    initialize(data.canvas, data.demo, data.diagnostics, data.renderer, data.soundEnabled).catch((error) => {
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
  } else if (data.type === "inspect") {
    send("inspect", { snapshot: diagnosticSnapshot() });
  }
});
