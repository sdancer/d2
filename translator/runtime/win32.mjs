import { hostFs as fs, hostPath as path, isNodeHost } from "./host-platform.mjs";

const PAGE_SIZE = 64 * 1024;

export class Win32Runtime {
  constructor(options = {}) {
    this.memory = null;
    this.lastError = 0;
    this.exitCode = null;
    this.stdout = options.stdout ?? ((text) => isNodeHost ? process.stdout.write(text) : console.log(text));
    this.environment = options.environment ?? (isNodeHost ? process.env : {});
    this.diagnostics = options.diagnostics
      ?? ["1", "true"].includes(String(this.environment.D2_DIAGNOSTICS ?? "").toLowerCase());
    this.cooperativeTiming = options.cooperativeTiming ?? false;
    this.yieldOnPresent = options.yieldOnPresent ?? false;
    this.mainResumeAt = 0;
    this.commandLine = options.commandLine ?? '"C:\\Diablo II\\Diablo II.exe" -w';
    this.moduleFilename = options.moduleFilename ?? "C:\\Diablo II\\Diablo II.exe";
    this.heapCursor = options.heapBase ?? 0x00800000;
    this.reservedRanges = [];
    this.allocations = new Map();
    this.tls = new Map();
    this.nextTls = 0;
    this.moduleHandles = new Map([["<main>", 0x00400000]]);
    this.moduleExports = new Map();
    this.codeRanges = [];
    this.mainModuleHandle = 0x00400000;
    this.nextModuleHandle = 0x10000;
    this.virtualTime = options.virtualTime ?? 0;
    this.clock = options.clock ?? (() => performance.now());
    this.clockOrigin = this.clock();
    this.clockOffset = this.virtualTime;
    this.epochMilliseconds = options.epochMilliseconds ?? Date.UTC(2000, 0, 1);
    this.showCursorCount = 0;
    this.currentDirectory = options.currentDirectory ?? "C:\\Diablo II";
    this.hostRoot = options.hostRoot ? path.resolve(options.hostRoot) : null;
    this.errorMode = 0;
    this.unhandledExceptionFilter = 0;
    this.nextHandle = 0x100;
    this.handles = new Map();
    this.currentThread = null;
    this.schedulerEvents = [];
    this.fileIoEvents = [];
    this.apiCounts = new Map();
    this.recentApis = [];
    this.screenBitmapHandle = 0;
    this.screenPresentations = 0;
    this.presentationWidth = 800;
    this.presentationHeight = 600;
    this.windowClasses = new Map();
    this.nextWindowAtom = 1;
    this.activeWindow = 0;
    this.messageQueue = [];
    this.onPresent = options.onPresent ?? null;
    this.onAudio = options.onAudio ?? null;
    this.soundEnabled = options.soundEnabled ?? true;
    this.onGlide = options.onGlide ?? null;
    this.glideWidth = 640;
    this.glideHeight = 480;
    this.glideLfbPointer = 0;
    this.glideLfbStride = 0;
    this.glideStrings = new Map();
    this.cursorX = 0;
    this.cursorY = 0;
    this.autoClickIndex = 0;
    this.autoClickRelease = null;
    this.autoTextQueued = false;
    this.registryValues = new Map([
      ["installpath", "C:\\Diablo II"],
      ["install path", "C:\\Diablo II"],
      ["diabloiifolder", "C:\\Diablo II"],
      ["program", "C:\\Diablo II\\Diablo II.exe"],
      ["save path", "C:\\Diablo II\\save"],
      ["newsavepath", "C:\\Diablo II\\save"],
    ]);
    this.virtualDirectories = new Set();
    this.clipboard = new Map();
    this.events = [];
    this.directSoundObjects = new Set();
    this.soundBuffers = new Map();
    this.nextSoundId = 1;
    this.directSoundCreatedReported = false;
    this.directSoundPlaybackReported = false;
    this.directSoundCalls = [];
    this.directSoundCallCount = 0;
  }

  attach(memory, exports = null) {
    this.memory = memory;
    this.exports = exports;
    this.commandLinePointer = this.allocCString(this.commandLine);
  }

  captureTrace(limit = 1024) {
    if (!this.exports?.d2_trace_count) return [];
    const count = Math.min(this.exports.d2_trace_count(), limit);
    return Array.from({ length: count }, (_, back) => ({
      va: this.exports.d2_trace_pc(back) >>> 0,
      esp: this.exports.d2_trace_esp(back) >>> 0,
    }));
  }

  captureCodePointers(stackPointer, dwordLimit = 2048) {
    const view = this.view();
    const end = Math.min(view.byteLength, stackPointer + dwordLimit * 4);
    const result = [];
    for (let address = stackPointer; address + 4 <= end; address += 4) {
      const value = view.getUint32(address, true);
      if (this.codeRanges.some(({ start, end: rangeEnd }) => value >= start && value < rangeEnd)) {
        result.push({ stack: address >>> 0, va: value >>> 0 });
      }
    }
    return result.slice(0, 256);
  }

  registerLinkedModules(manifest) {
    this.moduleHandles.clear();
    this.moduleExports.clear();
    this.codeRanges = [];
    for (const module of manifest.modules) {
      const handle = module.load_base >>> 0;
      this.moduleHandles.set(module.runtime_name.toLowerCase(), handle);
      const names = new Map(), ordinals = new Map();
      for (const entry of module.exports ?? []) {
        const address = (handle + entry.rva) >>> 0;
        if (entry.name) names.set(entry.name, address);
        ordinals.set(entry.ordinal, address);
      }
      this.moduleExports.set(handle, { names, ordinals });
      for (const section of module.sections ?? []) {
        if (!section.executable) continue;
        const start = (handle + section.rva) >>> 0;
        const size = Math.max(section.virtual_size ?? 0, section.file_size ?? 0);
        this.codeRanges.push({ start, end: (start + size) >>> 0 });
      }
      if (module.runtime_name.toLowerCase() === manifest.entry_module.toLowerCase()) {
        this.mainModuleHandle = handle;
      }
    }
    this.moduleHandles.set("<main>", this.mainModuleHandle);
  }

  ensure(end) {
    if (!this.memory) throw new Error("Win32Runtime is not attached to Wasm memory");
    const missing = end - this.memory.buffer.byteLength;
    if (missing > 0) this.memory.grow(Math.ceil(missing / PAGE_SIZE));
  }

  view() {
    return new DataView(this.memory.buffer);
  }

  arg(stackPointer, index) {
    return this.view().getUint32(stackPointer + index * 4, true);
  }

  alloc(size, alignment = 16) {
    const actualSize = Math.max(size >>> 0, 1);
    let start = (this.heapCursor + alignment - 1) & -alignment;
    for (const range of this.reservedRanges) {
      if (start < range.end && start + actualSize > range.start) {
        start = (range.end + alignment - 1) & -alignment;
      }
    }
    this.heapCursor = start + actualSize;
    this.ensure(this.heapCursor);
    new Uint8Array(this.memory.buffer, start, actualSize).fill(0);
    this.allocations.set(start, actualSize);
    this.events.push({ type: "alloc", start, size: actualSize, alignment });
    if (this.events.length > 256) this.events.shift();
    return start;
  }

  reserve(start, end) {
    start >>>= 0; end >>>= 0;
    if (end <= start) throw new Error("reserved memory range must be non-empty");
    this.reservedRanges.push({ start, end });
    this.reservedRanges.sort((left, right) => left.start - right.start);
  }

  allocCString(text) {
    const bytes = new TextEncoder().encode(text + "\0");
    const pointer = this.alloc(bytes.length, 1);
    new Uint8Array(this.memory.buffer, pointer, bytes.length).set(bytes);
    return pointer;
  }

  readCString(pointer) {
    if (!pointer) return "";
    const bytes = new Uint8Array(this.memory.buffer);
    let end = pointer;
    while (end < bytes.length && bytes[end]) end++;
    return new TextDecoder().decode(bytes.subarray(pointer, end));
  }

  writeCString(pointer, capacity, text) {
    const encoded = new TextEncoder().encode(text);
    const count = Math.min(encoded.length, Math.max(0, capacity - 1));
    this.ensure(pointer + Math.max(capacity, 1));
    const bytes = new Uint8Array(this.memory.buffer);
    bytes.set(encoded.subarray(0, count), pointer);
    if (capacity) bytes[pointer + count] = 0;
    return count;
  }

  clockNow() {
    const elapsed = Math.max(0, Math.trunc(this.clock() - this.clockOrigin));
    this.virtualTime = (this.clockOffset + elapsed) >>> 0;
    return this.virtualTime;
  }

  advanceClock(milliseconds = 0) {
    this.clockOffset = (this.clockNow() + (milliseconds >>> 0)) >>> 0;
    this.clockOrigin = this.clock();
    this.virtualTime = this.clockOffset;
    return this.virtualTime;
  }

  createComObject(methodBase, methodCount) {
    const vtable = this.alloc(methodCount * 4, 4);
    for (let method = 0; method < methodCount; method++) {
      this.view().setUint32(vtable + method * 4, (0xfffe0000 + (methodBase + method) * 4) >>> 0, true);
    }
    const object = this.alloc(4, 4);
    this.view().setUint32(object, vtable, true);
    return object;
  }

  readWaveFormat(pointer) {
    if (!pointer) return { formatTag: 1, channels: 2, samplesPerSec: 22050, avgBytesPerSec: 88200, blockAlign: 4, bitsPerSample: 16 };
    const view = this.view();
    return {
      formatTag: view.getUint16(pointer, true),
      channels: view.getUint16(pointer + 2, true),
      samplesPerSec: view.getUint32(pointer + 4, true),
      avgBytesPerSec: view.getUint32(pointer + 8, true),
      blockAlign: view.getUint16(pointer + 12, true),
      bitsPerSample: view.getUint16(pointer + 14, true),
    };
  }

  writeWaveFormat(pointer, format) {
    const view = this.view();
    view.setUint16(pointer, format.formatTag, true);
    view.setUint16(pointer + 2, format.channels, true);
    view.setUint32(pointer + 4, format.samplesPerSec, true);
    view.setUint32(pointer + 8, format.avgBytesPerSec, true);
    view.setUint16(pointer + 12, format.blockAlign, true);
    view.setUint16(pointer + 14, format.bitsPerSample, true);
    view.setUint16(pointer + 16, 0, true);
  }

  emitSound(buffer) {
    if (!this.onAudio || buffer.primary || !buffer.bytes) return;
    const bytes = new Uint8Array(this.memory.buffer, buffer.bytes, buffer.size).slice();
    this.onAudio({
      type: "play",
      id: buffer.id,
      bytes,
      format: buffer.format,
      loop: Boolean(buffer.playFlags & 1),
      volume: buffer.volume,
      pan: buffer.pan,
      frequency: buffer.frequency || buffer.format.samplesPerSec,
      cursor: buffer.currentPosition || 0,
    });
    if (!this.directSoundPlaybackReported) {
      this.directSoundPlaybackReported = true;
      this.events.push({ type: "direct-sound-playback" });
    }
  }

  emitSoundWrite(buffer, pointer, size) {
    if (!this.onAudio || !buffer.playing || !pointer || !size) return;
    const offset = pointer - buffer.bytes;
    if (offset < 0 || offset >= buffer.size) return;
    const count = Math.min(size, buffer.size - offset);
    const bytes = new Uint8Array(this.memory.buffer, pointer, count).slice();
    this.onAudio({ type: "write", id: buffer.id, offset, bytes });
  }

  emitSoundControl(buffer, detail) {
    if (this.onAudio && buffer.playing) {
      this.onAudio({ type: "control", id: buffer.id, ...detail });
    }
  }

  directSoundMethodName(method) {
    const device = [
      "QueryInterface", "AddRef", "Release", "CreateSoundBuffer", "GetCaps",
      "DuplicateSoundBuffer", "SetCooperativeLevel", "Compact", "GetSpeakerConfig",
      "SetSpeakerConfig", "Initialize",
    ];
    const buffer = [
      "QueryInterface", "AddRef", "Release", "GetCaps", "GetCurrentPosition",
      "GetFormat", "GetVolume", "GetPan", "GetFrequency", "GetStatus", "Initialize",
      "Lock", "Play", "SetCurrentPosition", "SetFormat", "SetVolume", "SetPan",
      "SetFrequency", "Stop", "Unlock", "Restore",
    ];
    if (method < device.length) return `IDirectSound::${device[method]}`;
    if (method >= 32 && method - 32 < buffer.length) {
      return `IDirectSoundBuffer::${buffer[method - 32]}`;
    }
    return `DirectSound method ${method}`;
  }

  recordDirectSoundCall(method, sp, args, result, error = null) {
    const call = {
      sequence: ++this.directSoundCallCount,
      method,
      name: this.directSoundMethodName(method),
      sp: sp >>> 0,
      object: args[0] ?? 0,
      args,
      result: result >>> 0,
      error,
    };
    this.directSoundCalls.push(call);
    if (this.directSoundCalls.length > 64) this.directSoundCalls.shift();
    if (call.sequence <= 64) this.events.push({ type: "direct-sound-call", ...call });
  }

  soundBytesPerSecond(buffer) {
    const baseRate = Math.max(1, buffer.format.samplesPerSec);
    return Math.max(1, Math.floor(
      buffer.format.avgBytesPerSec * Math.max(1, buffer.frequency) / baseRate,
    ));
  }

  refreshSoundPlayback(buffer, now = this.clockNow()) {
    if (!buffer.playing || buffer.playFlags & 1 || !buffer.size) return;
    const elapsed = Math.max(0, now - buffer.playStarted);
    if (elapsed * this.soundBytesPerSecond(buffer) >= buffer.size * 1000) {
      buffer.playing = false;
    }
  }

  dispatchDirectSound(method, sp) {
    if (!this.diagnostics) return this.dispatchDirectSoundMethod(method, sp) >>> 0;
    const deviceBytes = [12, 4, 4, 16, 8, 12, 12, 4, 8, 8, 8];
    const bufferBytes = [12, 4, 4, 8, 12, 16, 8, 8, 8, 8, 12, 32, 16, 8, 8, 8, 8, 8, 4, 20, 4];
    const argumentBytes = method < deviceBytes.length
      ? deviceBytes[method]
      : method >= 32 && method - 32 < bufferBytes.length
        ? bufferBytes[method - 32]
        : 4;
    const args = Array.from(
      { length: argumentBytes / 4 },
      (_value, index) => this.arg(sp, index),
    );
    try {
      const result = this.dispatchDirectSoundMethod(method, sp) >>> 0;
      this.recordDirectSoundCall(method, sp, args, result);
      return result;
    } catch (error) {
      this.recordDirectSoundCall(method, sp, args, 0xffffffff, error.message);
      throw error;
    }
  }

  dispatchDirectSoundMethod(method, sp) {
    const view = this.view();
    const object = this.arg(sp, 0);
    if (method <= 2 || (method >= 32 && method <= 34)) {
      const relative = method >= 32 ? method - 32 : method;
      if (relative === 0) {
        const output = this.arg(sp, 2);
        if (output) view.setUint32(output, object, true);
        return 0;
      }
      return relative === 1 ? 2 : 1;
    }
    if (method < 32) {
      if (!this.directSoundObjects.has(object)) return 0x88780032;
      if (method === 3) {
        const descriptor = this.arg(sp, 1), output = this.arg(sp, 2);
        if (!descriptor || !output) return 0x80070057;
        const flags = view.getUint32(descriptor + 4, true);
        const primary = Boolean(flags & 1);
        const size = primary ? 0 : view.getUint32(descriptor + 8, true);
        const formatPointer = view.getUint32(descriptor + 16, true);
        const format = this.readWaveFormat(formatPointer);
        const bufferObject = this.createComObject(32, 21);
        const buffer = {
          id: this.nextSoundId++, object: bufferObject, primary, flags, size,
          bytes: primary || !size ? 0 : this.alloc(size, 16), format,
          volume: 0, pan: 0, frequency: format.samplesPerSec,
          playing: false, playFlags: 0, playStarted: 0, currentPosition: 0,
        };
        this.soundBuffers.set(bufferObject, buffer);
        this.view().setUint32(output, bufferObject, true);
        return 0;
      }
      if (method === 4) {
        const output = this.arg(sp, 1);
        if (output) {
          const size = view.getUint32(output, true);
          new Uint8Array(this.memory.buffer, output + 4, Math.max(0, Math.min(size, 96) - 4)).fill(0);
          if (size >= 8) view.setUint32(output + 4, 0x3f, true);
        }
        return 0;
      }
      if (method === 8) {
        const output = this.arg(sp, 1);
        if (output) view.setUint32(output, 4, true);
        return 0;
      }
      return 0;
    }
    const buffer = this.soundBuffers.get(object);
    if (!buffer) return 0x88780032;
    const relative = method - 32;
    if (relative === 3) {
      const output = this.arg(sp, 1);
      if (output) {
        const size = view.getUint32(output, true);
        new Uint8Array(this.memory.buffer, output + 4, Math.max(0, Math.min(size, 32) - 4)).fill(0);
        if (size >= 8) view.setUint32(output + 4, buffer.flags, true);
        if (size >= 12) view.setUint32(output + 8, buffer.size, true);
      }
    } else if (relative === 4) {
      const now = this.clockNow();
      const elapsed = buffer.playing ? Math.max(0, now - buffer.playStarted) : 0;
      const played = Math.floor(elapsed * this.soundBytesPerSecond(buffer) / 1000);
      this.refreshSoundPlayback(buffer, now);
      const cursor = buffer.size
        ? buffer.playFlags & 1 ? played % buffer.size : Math.min(played, buffer.size - 1)
        : 0;
      const play = this.arg(sp, 1), write = this.arg(sp, 2);
      if (play) view.setUint32(play, cursor, true);
      if (write) view.setUint32(write, buffer.size ? (cursor + buffer.format.blockAlign * 4) % buffer.size : 0, true);
    } else if (relative === 5) {
      const output = this.arg(sp, 1), size = this.arg(sp, 2), written = this.arg(sp, 3);
      if (output && size) this.writeWaveFormat(output, buffer.format);
      if (written) view.setUint32(written, 18, true);
    } else if (relative === 6) {
      const output = this.arg(sp, 1); if (output) view.setInt32(output, buffer.volume, true);
    } else if (relative === 7) {
      const output = this.arg(sp, 1); if (output) view.setInt32(output, buffer.pan, true);
    } else if (relative === 8) {
      const output = this.arg(sp, 1); if (output) view.setUint32(output, buffer.frequency, true);
    } else if (relative === 9) {
      this.refreshSoundPlayback(buffer);
      const output = this.arg(sp, 1); if (output) view.setUint32(output, buffer.playing ? 1 | (buffer.playFlags & 1 ? 4 : 0) : 0, true);
    } else if (relative === 11) {
      if (!buffer.bytes || !buffer.size) return 0x88780032;
      let offset = this.arg(sp, 1) % buffer.size;
      let count = this.arg(sp, 2);
      if ((this.arg(sp, 7) & 2) || !count) count = buffer.size;
      count = Math.min(count, buffer.size);
      const first = Math.min(count, buffer.size - offset), second = count - first;
      view.setUint32(this.arg(sp, 3), buffer.bytes + offset, true);
      view.setUint32(this.arg(sp, 4), first, true);
      if (this.arg(sp, 5)) view.setUint32(this.arg(sp, 5), second ? buffer.bytes : 0, true);
      if (this.arg(sp, 6)) view.setUint32(this.arg(sp, 6), second, true);
    } else if (relative === 12) {
      buffer.playFlags = this.arg(sp, 3);
      buffer.playing = true;
      buffer.playStarted = this.clockNow()
        - Math.floor(buffer.currentPosition * 1000 / this.soundBytesPerSecond(buffer));
      this.emitSound(buffer);
    } else if (relative === 13) {
      buffer.currentPosition = buffer.size ? this.arg(sp, 1) % buffer.size : 0;
      buffer.playStarted = this.clockNow()
        - Math.floor(buffer.currentPosition * 1000 / this.soundBytesPerSecond(buffer));
      this.emitSoundControl(buffer, { cursor: buffer.currentPosition });
    } else if (relative === 14) {
      buffer.format = this.readWaveFormat(this.arg(sp, 1));
    } else if (relative === 15) {
      buffer.volume = this.arg(sp, 1) | 0;
      this.emitSoundControl(buffer, { volume: buffer.volume });
    } else if (relative === 16) {
      buffer.pan = this.arg(sp, 1) | 0;
      this.emitSoundControl(buffer, { pan: buffer.pan });
    } else if (relative === 17) {
      buffer.frequency = this.arg(sp, 1);
      this.emitSoundControl(buffer, { frequency: buffer.frequency });
    } else if (relative === 18) {
      if (buffer.playing && buffer.size) {
        const elapsed = Math.max(0, this.clockNow() - buffer.playStarted);
        const played = Math.floor(elapsed * this.soundBytesPerSecond(buffer) / 1000);
        buffer.currentPosition = buffer.playFlags & 1
          ? played % buffer.size
          : Math.min(played, buffer.size - 1);
      }
      buffer.playing = false;
      this.onAudio?.({ type: "stop", id: buffer.id });
    } else if (relative === 19) {
      this.emitSoundWrite(buffer, this.arg(sp, 1), this.arg(sp, 2));
      this.emitSoundWrite(buffer, this.arg(sp, 3), this.arg(sp, 4));
    }
    return 0;
  }

  formatAnsi(formatPointer, argumentsPointer) {
    const format = this.readCString(formatPointer);
    let argument = argumentsPointer, output = "";
    for (let index = 0; index < format.length; index++) {
      if (format[index] !== "%") { output += format[index]; continue; }
      index++;
      if (format[index] === "%") { output += "%"; continue; }
      let zero = false, widthText = "";
      if (format[index] === "0") { zero = true; index++; }
      while (index < format.length && /[0-9]/.test(format[index])) widthText += format[index++];
      while (format[index] === "l" || format[index] === "h") index++;
      const kind = format[index], value = this.view().getUint32(argument, true);
      argument += 4;
      let text;
      if (kind === "s" || kind === "S") text = this.readCString(value);
      else if (kind === "d" || kind === "i") text = String(value | 0);
      else if (kind === "u") text = String(value >>> 0);
      else if (kind === "x" || kind === "X" || kind === "p") {
        text = (value >>> 0).toString(16);
        if (kind === "X") text = text.toUpperCase();
      } else if (kind === "c") text = String.fromCharCode(value & 0xff);
      else { output += `%${kind ?? ""}`; continue; }
      const width = Number(widthText || 0);
      if (width > text.length) text = text.padStart(width, zero ? "0" : " ");
      output += text;
    }
    return output;
  }

  hostPath(windowsPath) {
    if (!this.hostRoot) return null;
    let relative = windowsPath.replaceAll("\\", "/");
    const current = this.currentDirectory.replaceAll("\\", "/");
    if (relative.toLowerCase() === current.toLowerCase()) relative = "";
    else if (relative.toLowerCase().startsWith(current.toLowerCase() + "/")) relative = relative.slice(current.length + 1);
    relative = relative.replace(/^[a-zA-Z]:/, "").replace(/^\/+/, "");
    const candidate = path.resolve(this.hostRoot, relative);
    if (candidate !== this.hostRoot && !candidate.startsWith(this.hostRoot + path.sep)) return null;
    if (fs.existsSync(candidate)) return candidate;
    let resolved = this.hostRoot;
    for (const segment of relative.split("/").filter(Boolean)) {
      try {
        const match = fs.readdirSync(resolved).find((name) => name.toLowerCase() === segment.toLowerCase());
        if (!match) return candidate;
        resolved = path.join(resolved, match);
      } catch { return candidate; }
    }
    return resolved;
  }

  writeFindData(pointer, name, stats) {
    new Uint8Array(this.memory.buffer, pointer, 320).fill(0);
    const view = this.view();
    view.setUint32(pointer, stats.isDirectory() ? 0x10 : 0x80, true);
    view.setUint32(pointer + 28, Math.floor(stats.size / 0x100000000), true);
    view.setUint32(pointer + 32, stats.size >>> 0, true);
    this.writeCString(pointer + 44, 260, name);
  }

  ensureScreenBitmap() {
    if (this.screenBitmapHandle) return this.screenBitmapHandle;
    const width = 800, height = 600, bitsPerPixel = 32;
    const stride = width * 4, size = stride * height, bits = this.alloc(size, 4);
    const handle = this.nextHandle++;
    this.handles.set(handle, {
      type: "gdi-bitmap", screen: true, width, height, bitsPerPixel,
      stride, size, bits, topDown: true, palette: null,
    });
    this.screenBitmapHandle = handle;
    return handle;
  }

  enqueueMessage(hwnd, message, wParam = 0, lParam = 0) {
    this.messageQueue.push({ hwnd: hwnd >>> 0, message: message >>> 0, wParam: wParam >>> 0, lParam: lParam >>> 0 });
  }

  enqueuePointer(message, x, y, wParam = 0) {
    this.cursorX = Math.max(0, Math.min(this.presentationWidth - 1, Math.trunc(x)));
    this.cursorY = Math.max(0, Math.min(this.presentationHeight - 1, Math.trunc(y)));
    const lParam = ((this.cursorY & 0xffff) << 16 | this.cursorX & 0xffff) >>> 0;
    this.enqueueMessage(this.activeWindow, 0x0200, 0, lParam);
    if (message !== 0x0200) this.enqueueMessage(this.activeWindow, message, wParam, lParam);
  }

  enqueueKey(virtualKey, down) {
    this.enqueueMessage(this.activeWindow, down ? 0x0100 : 0x0101, virtualKey, 1);
  }

  enqueueCharacter(codePoint) {
    this.enqueueMessage(this.activeWindow, 0x0102, codePoint, 1);
  }

  runPresentationAutomation() {
    const clickSchedule = this.environment.D2_AUTO_CLICKS ?? this.environment.D2_AUTO_CLICK;
    if (clickSchedule) {
      const clicks = clickSchedule.split(";").filter(Boolean);
      if (this.autoClickRelease
          && this.screenPresentations >= this.autoClickRelease.presentation) {
        const { hwnd, lParam } = this.autoClickRelease;
        this.enqueueMessage(hwnd, 0x202, 0, lParam);
        this.autoClickRelease = null;
        this.autoClickIndex++;
      } else if (!this.autoClickRelease && this.autoClickIndex < clicks.length) {
        const [xText, yText, presentationText] = clicks[this.autoClickIndex].split(",");
        const presentation = Number(presentationText || 350);
        if (this.screenPresentations >= presentation) {
          this.cursorX = Number(xText || 400);
          this.cursorY = Number(yText || 208);
          const hwnd = this.activeWindow;
          const lParam = ((this.cursorY & 0xffff) << 16 | this.cursorX & 0xffff) >>> 0;
          this.enqueueMessage(hwnd, 0x200, 0, lParam);
          this.enqueueMessage(hwnd, 0x201, 1, lParam);
          this.autoClickRelease = {
            hwnd,
            lParam,
            presentation: this.screenPresentations + 10,
          };
        }
      }
    }
    if (!this.autoTextQueued && this.environment.D2_AUTO_TEXT) {
      const separator = this.environment.D2_AUTO_TEXT.lastIndexOf(",");
      const text = separator < 0
        ? this.environment.D2_AUTO_TEXT
        : this.environment.D2_AUTO_TEXT.slice(0, separator);
      const presentation = Number(
        separator < 0 ? 600 : this.environment.D2_AUTO_TEXT.slice(separator + 1),
      );
      if (this.screenPresentations >= presentation) {
        for (const character of text) {
          const code = character.codePointAt(0);
          const virtualKey = code >= 0x61 && code <= 0x7a ? code - 0x20 : code;
          this.enqueueMessage(this.activeWindow, 0x100, virtualKey, 1);
          this.enqueueMessage(this.activeWindow, 0x102, code, 1);
          this.enqueueMessage(this.activeWindow, 0x101, virtualKey, 1);
        }
        this.autoTextQueued = true;
      }
    }
  }

  completePresentation(width, height, render) {
    this.screenPresentations++;
    this.presentationWidth = Math.max(1, width | 0);
    this.presentationHeight = Math.max(1, height | 0);
    if (this.delayedWatchPc !== undefined
        && this.screenPresentations >= this.delayedWatchPresentation) {
      this.exports?.d2_set_watch_pc?.(this.delayedWatchPc);
      this.delayedWatchPc = undefined;
    }
    this.runPresentationAutomation();
    const presented = render?.(this.screenPresentations);
    if (this.yieldOnPresent && presented !== false) this.exports?.d2_request_yield?.();
    return presented;
  }

  writeMessage(pointer, message) {
    const view = this.view();
    view.setUint32(pointer, message.hwnd, true);
    view.setUint32(pointer + 4, message.message, true);
    view.setUint32(pointer + 8, message.wParam, true);
    view.setUint32(pointer + 12, message.lParam, true);
    view.setUint32(pointer + 16, this.clockNow(), true);
    view.setInt32(pointer + 20, this.cursorX, true);
    view.setInt32(pointer + 24, this.cursorY, true);
  }

  invokeTranslated(address, args, fuel = 1_000_000) {
    if (!address || !this.exports?.d2_run_context) return 0;
    if (this.exports.d2_invoke_current) {
      this.callbackArguments ??= this.alloc(64, 4);
      const view = this.view();
      args.forEach((value, index) => view.setUint32(this.callbackArguments + index * 4, value >>> 0, true));
      const result = this.exports.d2_invoke_current(address, this.callbackArguments, args.length, fuel) >>> 0;
      const status = this.exports.d2_invoke_status() >>> 0;
      if (this.exports.d2_watch_hit()) {
        const names = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
        this.callbackWatch = {
          callback: address,
          args,
          currentStack: true,
          registers: Object.fromEntries(
            names.map((name, index) => [name, this.exports.d2_watch_register(index) >>> 0]),
          ),
        };
      }
      if (this.diagnostics) {
        const event = { type: "callback", address, args, result, status, currentStack: true };
        this.schedulerEvents.push(event);
        this.callbackEvents ??= [];
        this.callbackEvents.push(event);
        if (this.callbackEvents.length > 64) this.callbackEvents.shift();
      }
      return result;
    }
    const stackSize = 0x10000;
    this.callbackStacks ??= [];
    this.callbackDepth ??= 0;
    const depth = this.callbackDepth++;
    const stackBase = this.callbackStacks[depth] ??= this.alloc(stackSize, 16);
    const stackTop = (stackBase + stackSize - 0x100) & ~15, context = this.alloc(256, 8);
    const view = this.view();
    args.forEach((value, index) => view.setUint32(stackTop + index * 4, value >>> 0, true));
    let result = 0, status = 1;
    try {
      for (let round = 0; round < 8 && status === 1; round++) {
        result = this.exports.d2_run_context(context, address, stackTop, fuel) >>> 0;
        status = this.exports.d2_context_status(context) >>> 0;
        if (this.exports.d2_context_watch_hit(context)) {
          const names = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
          this.callbackWatch = {
            callback: address,
            args,
            round: round + 1,
            registers: Object.fromEntries(names.map((name, index) => [name, this.exports.d2_context_watch_register(context, index) >>> 0])),
          };
        }
      }
    } finally {
      this.callbackDepth--;
    }
    if (this.diagnostics) {
      const event = { type: "callback", address, args, result, status };
      this.schedulerEvents.push(event);
      this.callbackEvents ??= [];
      this.callbackEvents.push(event);
      if (this.callbackEvents.length > 64) this.callbackEvents.shift();
    }
    return result;
  }

  runThread(thread, fuel = 1_000_000) {
    if (thread.finished || !this.exports?.d2_run_context) return;
    const previous = this.currentThread;
    this.currentThread = thread;
    try {
      thread.exitCode = this.exports.d2_run_context(
        thread.context,
        thread.start,
        thread.stackTop,
        fuel,
      ) >>> 0;
      thread.status = this.exports.d2_context_status(thread.context) >>> 0;
      thread.finished = Boolean(this.exports.d2_context_finished(thread.context));
      if (this.exports.d2_context_watch_hit(thread.context)) {
        const names = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
        this.threadWatchEvents ??= [];
        this.threadWatchEvents.push({
          handle: thread.handle,
          start: thread.start,
          registers: Object.fromEntries(
            names.map((name, index) => [name, this.exports.d2_context_watch_register(thread.context, index) >>> 0]),
          ),
        });
      }
      if (this.diagnostics) {
        this.schedulerEvents.push({
          type: "thread-run", handle: thread.handle, start: thread.start,
          status: thread.status, finished: thread.finished, exitCode: thread.exitCode,
        });
        if (this.schedulerEvents.length > 128) this.schedulerEvents.shift();
      }
    } finally {
      this.currentThread = previous;
    }
  }

  runPendingThreads(fuel = 50_000) {
    const now = this.clockNow();
    const pending = Array.from(this.handles.values())
      .filter((item) => item.type === "thread" && !item.finished)
      .filter((thread) => {
        if (!this.cooperativeTiming || !thread.resumeAt || thread.resumeAt <= now) return true;
        return thread.waitHandle && this.handles.get(thread.waitHandle)?.signaled;
      });
    for (const thread of pending) {
      thread.resumeAt = 0;
      thread.waitHandle = 0;
      this.runThread(thread, fuel);
    }
  }

  sleep(milliseconds) {
    if (!this.cooperativeTiming) {
      this.advanceClock(milliseconds);
      return 0;
    }
    if (!milliseconds) {
      // The game's main loop calls Sleep(0) twice per iteration. A browser
      // timer here clamps the loop to a few frames per second; presentation
      // itself is already the cooperative compositor boundary.
      if (this.currentThread) this.exports?.d2_request_yield?.();
      return 0;
    }
    const resumeAt = this.clockNow() + (milliseconds >>> 0);
    if (this.currentThread) this.currentThread.resumeAt = resumeAt;
    else this.mainResumeAt = resumeAt;
    this.exports?.d2_request_yield?.();
    return 0;
  }

  waitForSingleObject(handle, timeout) {
    const target = this.handles.get(handle);
    if (this.diagnostics) {
      this.schedulerEvents.push({
        type: "wait", handle, timeout, targetType: target?.type ?? null,
        signaled: target?.signaled ?? null, currentThread: this.currentThread?.handle ?? null,
      });
      if (this.schedulerEvents.length > 128) this.schedulerEvents.shift();
    }
    const consumeSignal = () => {
      if (!target?.signaled) return false;
      if (target.type === "event" && !target.manualReset) target.signaled = false;
      return true;
    };
    if (consumeSignal() || target?.type === "thread" && target.finished) return 0;
    if (timeout === 0) return 258;
    if (this.currentThread && timeout !== 0) {
      this.currentThread.waitHandle = handle;
      this.currentThread.resumeAt = timeout === 0xffffffff
        ? Infinity
        : this.clockNow() + (timeout >>> 0);
      this.exports?.d2_request_yield?.();
      return timeout === 0xffffffff ? 0 : 258;
    }
    const threads = target?.type === "thread"
      ? [target]
      : Array.from(this.handles.values()).filter((item) => item.type === "thread" && !item.finished);
    for (let round = 0; round < 32 && threads.length; round++) {
      for (const thread of threads) {
        this.runThread(thread);
        if (consumeSignal() || target?.type === "thread" && target.finished) return 0;
      }
    }
    return timeout === 0 ? 258 : 0;
  }

  kernel32() {
    return {
      GetLastError: () => this.lastError,
      SetLastError: (sp) => { this.lastError = this.arg(sp, 0); return 0; },
      GetCurrentProcess: () => 0xffffffff,
      GetCurrentProcessId: () => 1,
      GetCurrentThread: () => 0xfffffffe,
      GetCurrentThreadId: () => this.currentThread?.handle ?? 1,
      SetThreadPriority: () => 1,
      GetExitCodeProcess: (sp) => {
        const item = this.handles.get(this.arg(sp, 0));
        this.view().setUint32(this.arg(sp, 1), item?.type === "thread" ? item.exitCode : 259, true);
        return 1;
      },
      TerminateProcess: (sp) => { this.exitCode = this.arg(sp, 1); return 1; },
      ExitProcess: (sp) => { this.exitCode = this.arg(sp, 0); return this.exitCode; },
      GetVersion: () => 0x00000004,
      GetVersionExA: (sp) => {
        const pointer = this.arg(sp, 0), view = this.view();
        const size = view.getUint32(pointer, true);
        if (size < 148) { this.lastError = 122; return 0; }
        view.setUint32(pointer + 4, 4, true);
        view.setUint32(pointer + 8, 0, true);
        view.setUint32(pointer + 12, 950, true);
        view.setUint32(pointer + 16, 2, true);
        new Uint8Array(this.memory.buffer, pointer + 20, 128).fill(0);
        return 1;
      },
      GetCommandLineA: () => this.commandLinePointer,
      GetCurrentDirectoryA: (sp) => {
        const required = new TextEncoder().encode(this.currentDirectory).length;
        if (this.arg(sp, 0) <= required) return required + 1;
        this.writeCString(this.arg(sp, 1), this.arg(sp, 0), this.currentDirectory);
        return required;
      },
      SetCurrentDirectoryA: (sp) => { this.currentDirectory = this.readCString(this.arg(sp, 0)); return 1; },
      GetStartupInfoA: (sp) => {
        const pointer = this.arg(sp, 0);
        this.ensure(pointer + 68);
        new Uint8Array(this.memory.buffer, pointer, 68).fill(0);
        this.view().setUint32(pointer, 68, true);
        return 0;
      },
      GetModuleHandleA: (sp) => {
        const pointer = this.arg(sp, 0);
        if (!pointer) return this.mainModuleHandle;
        return this.moduleHandles.get(this.readCString(pointer).toLowerCase()) ?? 0;
      },
      GetModuleFileNameA: (sp) => this.writeCString(this.arg(sp, 1), this.arg(sp, 2), this.moduleFilename),
      InterlockedIncrement: (sp) => {
        const pointer = this.arg(sp, 0), value = (this.view().getInt32(pointer, true) + 1) | 0;
        this.view().setInt32(pointer, value, true); return value;
      },
      InterlockedDecrement: (sp) => {
        const pointer = this.arg(sp, 0), value = (this.view().getInt32(pointer, true) - 1) | 0;
        this.view().setInt32(pointer, value, true); return value;
      },
      InitializeCriticalSection: () => 0,
      DeleteCriticalSection: () => 0,
      EnterCriticalSection: () => 0,
      LeaveCriticalSection: () => 0,
      TlsAlloc: () => this.nextTls++,
      TlsFree: (sp) => { this.tls.delete(this.arg(sp, 0)); return 1; },
      TlsSetValue: (sp) => { this.tls.set(this.arg(sp, 0), this.arg(sp, 1)); return 1; },
      TlsGetValue: (sp) => this.tls.get(this.arg(sp, 0)) ?? 0,
      GetTickCount: () => this.clockNow(),
      Sleep: (sp) => this.sleep(this.arg(sp, 0)),
      WaitForSingleObject: (sp) => this.waitForSingleObject(this.arg(sp, 0), this.arg(sp, 1)),
      WaitForMultipleObjects: () => 0,
      CloseHandle: (sp) => {
        const handle = this.arg(sp, 0), item = this.handles.get(handle);
        if (item?.type === "file") fs.closeSync(item.fd);
        this.handles.delete(handle);
        return 1;
      },
      FreeLibrary: () => 1,
      OpenEventA: () => 0,
      CreateEventA: (sp) => {
        const handle = this.nextHandle++;
        this.handles.set(handle, {
          type: "event",
          manualReset: Boolean(this.arg(sp, 1)),
          signaled: Boolean(this.arg(sp, 2)),
        });
        return handle;
      },
      SetEvent: (sp) => {
        const handle = this.arg(sp, 0), event = this.handles.get(handle);
        if (event) {
          event.signaled = true;
          for (const thread of this.handles.values()) {
            if (thread.type === "thread" && thread.waitHandle === handle) thread.resumeAt = 0;
          }
        }
        return event ? 1 : 0;
      },
      ResetEvent: (sp) => { const event = this.handles.get(this.arg(sp, 0)); if (event) event.signaled = false; return event ? 1 : 0; },
      SetUnhandledExceptionFilter: (sp) => {
        const previous = this.unhandledExceptionFilter;
        this.unhandledExceptionFilter = this.arg(sp, 0);
        return previous;
      },
      IsBadCodePtr: () => 0,
      IsBadReadPtr: () => 0,
      IsBadWritePtr: () => 0,
      GetProcessHeap: () => 1,
      SetErrorMode: (sp) => { const previous = this.errorMode; this.errorMode = this.arg(sp, 0); return previous; },
      QueryPerformanceFrequency: (sp) => { this.view().setBigUint64(this.arg(sp, 0), 1000000n, true); return 1; },
      QueryPerformanceCounter: (sp) => { this.view().setBigUint64(this.arg(sp, 0), BigInt(this.clockNow()) * 1000n, true); return 1; },
      OutputDebugStringA: (sp) => {
        this.events.push({ type: "debug", text: this.readCString(this.arg(sp, 0)), trace: this.captureTrace(32) });
        if (this.events.length > 256) this.events.shift();
        return 0;
      },
      GetLocalTime: (sp) => {
        const date = new Date(this.epochMilliseconds + this.clockNow()), pointer = this.arg(sp, 0), view = this.view();
        const values = [date.getUTCFullYear(), date.getUTCMonth() + 1, date.getUTCDay(), date.getUTCDate(), date.getUTCHours(), date.getUTCMinutes(), date.getUTCSeconds(), date.getUTCMilliseconds()];
        for (let index = 0; index < values.length; index++) view.setUint16(pointer + index * 2, values[index], true);
        return 0;
      },
      GetSystemTime: (sp) => {
        const localTime = this.kernel32().GetLocalTime;
        return localTime(sp);
      },
      GetTimeZoneInformation: (sp) => {
        new Uint8Array(this.memory.buffer, this.arg(sp, 0), 172).fill(0);
        return 1;
      },
      GetSystemInfo: (sp) => {
        const pointer = this.arg(sp, 0), view = this.view();
        new Uint8Array(this.memory.buffer, pointer, 36).fill(0);
        view.setUint16(pointer, 0, true);
        view.setUint32(pointer + 4, PAGE_SIZE, true);
        view.setUint32(pointer + 8, 0x00010000, true);
        view.setUint32(pointer + 12, 0x7ffeffff, true);
        view.setUint32(pointer + 20, 1, true);
        view.setUint32(pointer + 24, 1, true);
        view.setUint16(pointer + 32, 5, true);
        return 0;
      },
      FormatMessageA: (sp) => {
        const flags = this.arg(sp, 0), messageId = this.arg(sp, 2), destinationArgument = this.arg(sp, 4), capacity = this.arg(sp, 5);
        const text = `Win32 error ${messageId}`;
        if (flags & 0x100) {
          const pointer = this.allocCString(text);
          this.view().setUint32(destinationArgument, pointer, true);
        } else this.writeCString(destinationArgument, capacity, text);
        return text.length;
      },
      CompareStringA: (sp) => {
        const leftPointer = this.arg(sp, 2), leftCount = this.arg(sp, 3) | 0, rightPointer = this.arg(sp, 4), rightCount = this.arg(sp, 5) | 0;
        let left = leftCount < 0 ? this.readCString(leftPointer) : new TextDecoder().decode(new Uint8Array(this.memory.buffer, leftPointer, leftCount));
        let right = rightCount < 0 ? this.readCString(rightPointer) : new TextDecoder().decode(new Uint8Array(this.memory.buffer, rightPointer, rightCount));
        if (this.arg(sp, 1) & 1) { left = left.toLowerCase(); right = right.toLowerCase(); }
        return left < right ? 1 : left > right ? 3 : 2;
      },
      CompareStringW: (sp) => {
        const read = (pointer, count) => {
          const view = this.view(), values = [];
          for (let index = 0; count < 0 ? view.getUint16(pointer + index * 2, true) : index < count; index++) values.push(view.getUint16(pointer + index * 2, true));
          return String.fromCharCode(...values);
        };
        let left = read(this.arg(sp, 2), this.arg(sp, 3) | 0), right = read(this.arg(sp, 4), this.arg(sp, 5) | 0);
        if (this.arg(sp, 1) & 1) { left = left.toLowerCase(); right = right.toLowerCase(); }
        return left < right ? 1 : left > right ? 3 : 2;
      },
      CreateThread: (sp) => {
        const handle = this.nextHandle++;
        const requestedStackSize = this.arg(sp, 1);
        const stackSize = Math.min(Math.max(requestedStackSize || 0x40000, 0x10000), 0x100000);
        const stackBase = this.alloc(stackSize, 16), stackTop = (stackBase + stackSize - 0x100) & ~15;
        const context = this.alloc(256, 8), parameter = this.arg(sp, 3);
        this.view().setUint32(stackTop, parameter, true);
        const thread = {
          type: "thread", handle, start: this.arg(sp, 2), parameter,
          stackBase, stackTop, context, exitCode: 259, status: 0, finished: false,
        };
        this.handles.set(handle, thread);
        const threadId = this.arg(sp, 5); if (threadId) this.view().setUint32(threadId, handle, true);
        this.events.push({ type: "thread-created", handle, start: thread.start, parameter, stackTop, context });
        return handle;
      },
      DisableThreadLibraryCalls: () => 1,
      UnhandledExceptionFilter: () => 0,
      GetStdHandle: (sp) => this.arg(sp, 0),
      GetFileType: () => 2,
      SetHandleCount: (sp) => this.arg(sp, 0),
      GetEnvironmentVariableA: (sp) => {
        const name = this.readCString(this.arg(sp, 0));
        const value = this.environment[name];
        if (value === undefined) { this.lastError = 203; return 0; }
        const capacity = this.arg(sp, 2), required = new TextEncoder().encode(value).length;
        if (capacity <= required) return required + 1;
        this.writeCString(this.arg(sp, 1), capacity, value);
        return required;
      },
      SetEnvironmentVariableA: (sp) => {
        const name = this.readCString(this.arg(sp, 0)), valuePointer = this.arg(sp, 1);
        if (valuePointer) this.environment[name] = this.readCString(valuePointer); else delete this.environment[name];
        return 1;
      },
      GetSystemDefaultLangID: () => 0x0409,
      GetPrivateProfileIntA: (sp) => this.arg(sp, 2),
      GetPrivateProfileStringA: (sp) => {
        const output = this.arg(sp, 3), capacity = this.arg(sp, 4), fallback = this.readCString(this.arg(sp, 2));
        return this.writeCString(output, capacity, fallback);
      },
      GetDiskFreeSpaceA: (sp) => {
        // Keep the reported capacity below 4 GiB: this 32-bit client multiplies
        // the legacy fields without widening and treats an exact 4 GiB wrap as zero.
        const view = this.view(), values = [8, 512, 0x40000, 0x80000];
        for (let index = 0; index < 4; index++) if (this.arg(sp, index + 1)) view.setUint32(this.arg(sp, index + 1), values[index], true);
        return 1;
      },
      GetVolumeInformationA: (sp) => {
        const volume = this.arg(sp, 1), volumeCapacity = this.arg(sp, 2), serial = this.arg(sp, 3);
        const maximumComponent = this.arg(sp, 4), flags = this.arg(sp, 5), filesystem = this.arg(sp, 6), filesystemCapacity = this.arg(sp, 7), view = this.view();
        if (volume && volumeCapacity) this.writeCString(volume, volumeCapacity, "D2WASM");
        if (serial) view.setUint32(serial, 0xd2000101, true);
        if (maximumComponent) view.setUint32(maximumComponent, 255, true);
        if (flags) view.setUint32(flags, 3, true);
        if (filesystem && filesystemCapacity) this.writeCString(filesystem, filesystemCapacity, "FAT32");
        return 1;
      },
      GlobalMemoryStatus: (sp) => {
        const pointer = this.arg(sp, 0), view = this.view();
        view.setUint32(pointer, 32, true); view.setUint32(pointer + 4, 50, true);
        for (let offset = 8; offset < 32; offset += 4) view.setUint32(pointer + offset, 0x20000000, true);
        return 0;
      },
      GetEnvironmentStrings: () => this.allocCString(""),
      GetEnvironmentStringsA: () => this.allocCString(""),
      GetEnvironmentStringsW: () => {
        const pointer = this.alloc(4, 2);
        this.view().setUint32(pointer, 0, true);
        return pointer;
      },
      FreeEnvironmentStringsA: () => 1,
      FreeEnvironmentStringsW: () => 1,
      HeapCreate: () => 1,
      HeapDestroy: () => 1,
      HeapSize: (sp) => this.allocations.get(this.arg(sp, 2)) ?? 0xffffffff,
      CreateDirectoryA: (sp) => {
        const requested = this.readCString(this.arg(sp, 0));
        this.virtualDirectories.add(requested.replaceAll("/", "\\").replace(/\\+$/, "").toLowerCase());
        const hostPath = this.hostPath(requested);
        if (hostPath) fs.mkdirSync(hostPath, { recursive: true });
        this.events.push({ type: "mkdir", requested });
        return 1;
      },
      RemoveDirectoryA: (sp) => {
        const requested = this.readCString(this.arg(sp, 0));
        this.virtualDirectories.delete(requested.replaceAll("/", "\\").replace(/\\+$/, "").toLowerCase());
        const hostPath = this.hostPath(requested);
        try { if (hostPath) fs.rmdirSync(hostPath); } catch { return 0; }
        return 1;
      },
      MoveFileA: (sp) => {
        const source = this.hostPath(this.readCString(this.arg(sp, 0)));
        const destination = this.hostPath(this.readCString(this.arg(sp, 1)));
        try { if (!source || !destination) throw new Error("no host path"); fs.renameSync(source, destination); return 1; }
        catch { return 0; }
      },
      DuplicateHandle: (sp) => {
        const source = this.arg(sp, 1), output = this.arg(sp, 3), handle = this.nextHandle++;
        this.handles.set(handle, this.handles.get(source) ?? { type: "duplicate", source });
        if (output) this.view().setUint32(output, handle, true);
        return 1;
      },
      SuspendThread: () => 0,
      ResumeThread: () => 0,
      GetThreadContext: () => 0,
      CreateIoCompletionPort: () => {
        const handle = this.nextHandle++;
        this.handles.set(handle, { type: "completion-port" });
        return handle;
      },
      GetQueuedCompletionStatus: () => 0,
      GetComputerNameA: (sp) => {
        const output = this.arg(sp, 0), sizePointer = this.arg(sp, 1), view = this.view(), capacity = view.getUint32(sizePointer, true);
        if (capacity < 7) { view.setUint32(sizePointer, 7, true); return 0; }
        this.writeCString(output, capacity, "D2WASM"); view.setUint32(sizePointer, 6, true); return 1;
      },
      CreateFileA: (sp) => {
        const requested = this.readCString(this.arg(sp, 0)), hostPath = this.hostPath(requested);
        const access = this.arg(sp, 1), disposition = this.arg(sp, 4), writable = Boolean(access & 0x40000000);
        try {
          if (!hostPath) throw new Error("no host root");
          let mode = "r";
          if (writable) {
            if (disposition === 1) mode = "wx+";
            else if (disposition === 2) mode = "w+";
            else if (disposition === 4) mode = fs.existsSync(hostPath) ? "r+" : "w+";
            else mode = "r+";
          }
          const fd = fs.openSync(hostPath, mode), handle = this.nextHandle++;
          if (writable && disposition === 5) fs.ftruncateSync(fd, 0);
          this.handles.set(handle, { type: "file", fd, position: 0, path: hostPath, writable });
          this.events.push({ type: "open", requested, hostPath, handle });
          return handle;
        } catch (error) { this.events.push({ type: "open-error", requested, hostPath, error: error.message }); this.lastError = 2; return 0xffffffff; }
      },
      ReadFile: (sp) => {
        const item = this.handles.get(this.arg(sp, 0)), buffer = this.arg(sp, 1), count = this.arg(sp, 2), written = this.arg(sp, 3);
        if (item?.type !== "file") { this.lastError = 6; return 0; }
        try {
          this.ensure(buffer + count);
          const bytes = new Uint8Array(this.memory.buffer, buffer, count);
          const actual = fs.readSync(item.fd, bytes, 0, count, item.position);
          this.fileIoEvents.push({ path: item.path, position: item.position, requested: count, actual });
          if (this.fileIoEvents.length > 128) this.fileIoEvents.shift();
          item.position += actual;
          if (written) this.view().setUint32(written, actual, true);
          return 1;
        } catch (error) {
          if (written) this.view().setUint32(written, 0, true);
          this.lastError = error.code === "EISDIR" ? 5 : 30;
          this.events.push({ type: "read-error", path: item.path, error: error.message });
          return 0;
        }
      },
      SetFilePointer: (sp) => {
        const item = this.handles.get(this.arg(sp, 0));
        if (item?.type !== "file") { this.lastError = 6; return 0xffffffff; }
        const distance = this.arg(sp, 1) | 0, origin = this.arg(sp, 3);
        const base = origin === 1 ? item.position : origin === 2 ? fs.fstatSync(item.fd).size : 0;
        item.position = Math.max(0, base + distance);
        return item.position >>> 0;
      },
      GetFileSize: (sp) => {
        const item = this.handles.get(this.arg(sp, 0));
        if (item?.type !== "file") { this.lastError = 6; return 0xffffffff; }
        const size = fs.fstatSync(item.fd).size, high = this.arg(sp, 1);
        if (high) this.view().setUint32(high, Math.floor(size / 0x100000000), true);
        return size >>> 0;
      },
      FlushFileBuffers: (sp) => { const item = this.handles.get(this.arg(sp, 0)); if (item?.type === "file" && item.writable) fs.fsyncSync(item.fd); return 1; },
      SetEndOfFile: (sp) => {
        const item = this.handles.get(this.arg(sp, 0));
        if (item?.type !== "file" || !item.writable) return 0;
        fs.ftruncateSync(item.fd, item.position); return 1;
      },
      DeleteFileA: (sp) => {
        const hostPath = this.hostPath(this.readCString(this.arg(sp, 0)));
        try { if (!hostPath) throw new Error("no host path"); fs.unlinkSync(hostPath); return 1; }
        catch { this.lastError = 2; return 0; }
      },
      CreateProcessA: () => { this.lastError = 2; return 0; },
      FindFirstFileA: (sp) => {
        const requested = this.readCString(this.arg(sp, 0)).replaceAll("\\", "/");
        const slash = requested.lastIndexOf("/"), directoryText = slash >= 0 ? requested.slice(0, slash) : "", pattern = requested.slice(slash + 1);
        const directory = this.hostPath(directoryText || ".");
        try {
          if (!directory) throw new Error("no host root");
          const expression = new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*").replaceAll("?", ".")}$`, "i");
          const names = fs.readdirSync(directory).filter((name) => expression.test(name));
          if (!names.length) throw new Error("no match");
          const handle = this.nextHandle++, item = { type: "find", directory, names, index: 0 };
          this.handles.set(handle, item);
          this.writeFindData(this.arg(sp, 1), names[0], fs.statSync(path.join(directory, names[0])));
          this.events.push({ type: "find", requested, directory, count: names.length });
          return handle;
        } catch (error) { this.events.push({ type: "find-error", requested, directory, error: error.message }); this.lastError = 2; return 0xffffffff; }
      },
      FindNextFileA: (sp) => {
        const item = this.handles.get(this.arg(sp, 0));
        if (item?.type !== "find" || ++item.index >= item.names.length) { this.lastError = 18; return 0; }
        const name = item.names[item.index];
        this.writeFindData(this.arg(sp, 1), name, fs.statSync(path.join(item.directory, name)));
        return 1;
      },
      FindClose: (sp) => { this.handles.delete(this.arg(sp, 0)); return 1; },
      WriteFile: (sp) => {
        const item = this.handles.get(this.arg(sp, 0)), buffer = this.arg(sp, 1), count = this.arg(sp, 2), written = this.arg(sp, 3);
        if (item?.type === "file" && item.writable) {
          try {
            const bytes = new Uint8Array(this.memory.buffer, buffer, count);
            const actual = fs.writeSync(item.fd, bytes, 0, count, item.position);
            item.position += actual;
            if (written) this.view().setUint32(written, actual, true);
            return 1;
          } catch { if (written) this.view().setUint32(written, 0, true); return 0; }
        }
        if (item?.type === "file") {
          if (written) this.view().setUint32(written, 0, true);
          this.lastError = 5;
          return 0;
        }
        const text = new TextDecoder().decode(new Uint8Array(this.memory.buffer, buffer, count));
        this.stdout(text);
        if (written) this.view().setUint32(written, count, true);
        return 1;
      },
      HeapAlloc: (sp) => this.alloc(this.arg(sp, 2)),
      HeapFree: (sp) => { this.allocations.delete(this.arg(sp, 2)); return 1; },
      HeapReAlloc: (sp) => {
        const oldPointer = this.arg(sp, 2), size = this.arg(sp, 3), pointer = this.alloc(size);
        const oldSize = this.allocations.get(oldPointer) ?? 0;
        if (oldPointer && oldSize) {
          const oldBytes = new Uint8Array(this.memory.buffer, oldPointer, Math.min(oldSize, size)).slice();
          new Uint8Array(this.memory.buffer, pointer, oldBytes.length).set(oldBytes);
          this.allocations.delete(oldPointer);
        }
        return pointer;
      },
      VirtualAlloc: (sp) => {
        const requested = this.arg(sp, 0), size = this.arg(sp, 1);
        if (!requested) return this.alloc(size, PAGE_SIZE);
        this.ensure(requested + size);
        return requested;
      },
      VirtualFree: () => 1,
      VirtualUnlock: () => 1,
      VirtualQuery: (sp) => {
        const address = this.arg(sp, 0), output = this.arg(sp, 1), length = this.arg(sp, 2), view = this.view();
        if (!output || length < 28) return 0;
        view.setUint32(output, address & 0xffff0000, true); view.setUint32(output + 4, address & 0xffff0000, true);
        view.setUint32(output + 8, 0x04, true); view.setUint32(output + 12, 0x10000, true);
        view.setUint32(output + 16, 0x1000, true); view.setUint32(output + 20, 0x04, true); view.setUint32(output + 24, 0x20000, true);
        return 28;
      },
      VirtualQueryEx: (sp) => {
        const address = this.arg(sp, 1), output = this.arg(sp, 2), length = this.arg(sp, 3), view = this.view();
        if (!output || length < 28) return 0;
        view.setUint32(output, address & 0xffff0000, true); view.setUint32(output + 4, address & 0xffff0000, true);
        view.setUint32(output + 8, 0x04, true); view.setUint32(output + 12, 0x10000, true);
        view.setUint32(output + 16, 0x1000, true); view.setUint32(output + 20, 0x04, true); view.setUint32(output + 24, 0x20000, true);
        return 28;
      },
      LocalAlloc: (sp) => this.alloc(this.arg(sp, 1)),
      LocalFree: (sp) => { this.allocations.delete(this.arg(sp, 0)); return 0; },
      GlobalAlloc: (sp) => this.alloc(this.arg(sp, 1)),
      GlobalFree: (sp) => { this.allocations.delete(this.arg(sp, 0)); return 0; },
      GlobalLock: (sp) => this.arg(sp, 0),
      GlobalUnlock: () => 1,
      GetFileAttributesA: (sp) => {
        const requested = this.readCString(this.arg(sp, 0));
        const key = requested.replaceAll("/", "\\").replace(/\\+$/, "").toLowerCase();
        if (this.virtualDirectories.has(key)) return 0x10;
        try { return fs.statSync(this.hostPath(requested)).isDirectory() ? 0x10 : 0x80; }
        catch { this.lastError = 2; return 0xffffffff; }
      },
      GetDriveTypeA: () => 3,
      GetLogicalDriveStringsA: (sp) => {
        const capacity = this.arg(sp, 0), output = this.arg(sp, 1), required = 5;
        if (!output || capacity < required) return required;
        new Uint8Array(this.memory.buffer, output, required).set([0x43, 0x3a, 0x5c, 0, 0]);
        return 4;
      },
      GetWindowsDirectoryA: (sp) => this.writeCString(this.arg(sp, 0), this.arg(sp, 1), "C:\\Windows"),
      GetSystemDirectoryA: (sp) => this.writeCString(this.arg(sp, 0), this.arg(sp, 1), "C:\\Windows\\System"),
      SetStdHandle: () => 1,
      lstrcpyA: (sp) => {
        const destination = this.arg(sp, 0), text = this.readCString(this.arg(sp, 1));
        this.writeCString(destination, new TextEncoder().encode(text).length + 1, text); return destination;
      },
      lstrcpynA: (sp) => { this.writeCString(this.arg(sp, 0), this.arg(sp, 2), this.readCString(this.arg(sp, 1))); return this.arg(sp, 0); },
      lstrcatA: (sp) => {
        const destination = this.arg(sp, 0), text = this.readCString(destination) + this.readCString(this.arg(sp, 1));
        this.writeCString(destination, new TextEncoder().encode(text).length + 1, text); return destination;
      },
      GetACP: () => 1252,
      GetOEMCP: () => 437,
      GetCPInfo: (sp) => {
        const pointer = this.arg(sp, 1), view = this.view();
        new Uint8Array(this.memory.buffer, pointer, 20).fill(0);
        view.setUint32(pointer, 1, true);
        view.setUint8(pointer + 4, 0x3f);
        return 1;
      },
      GetStringTypeW: (sp) => {
        const count = this.arg(sp, 2), output = this.arg(sp, 3), view = this.view();
        for (let index = 0; index < count; index++) view.setUint16(output + index * 2, 0, true);
        return 1;
      },
      GetStringTypeA: (sp) => {
        const count = this.arg(sp, 3), output = this.arg(sp, 4), view = this.view();
        for (let index = 0; index < count; index++) view.setUint16(output + index * 2, 0, true);
        return 1;
      },
      LCMapStringA: (sp) => {
        const flags = this.arg(sp, 1), source = this.arg(sp, 2), rawCount = this.arg(sp, 3) | 0;
        const destination = this.arg(sp, 4), capacity = this.arg(sp, 5);
        let count = rawCount < 0 ? this.readCString(source).length + 1 : rawCount;
        if (!destination || !capacity) return count;
        const bytes = new Uint8Array(this.memory.buffer), written = Math.min(count, capacity);
        for (let index = 0; index < written; index++) {
          let value = bytes[source + index];
          if ((flags & 0x100) && value >= 65 && value <= 90) value += 32;
          if ((flags & 0x200) && value >= 97 && value <= 122) value -= 32;
          bytes[destination + index] = value;
        }
        return written;
      },
      LCMapStringW: (sp) => {
        const flags = this.arg(sp, 1), source = this.arg(sp, 2), rawCount = this.arg(sp, 3) | 0;
        const destination = this.arg(sp, 4), capacity = this.arg(sp, 5), view = this.view();
        let count = rawCount;
        if (count < 0) { count = 0; while (view.getUint16(source + count * 2, true)) count++; count++; }
        if (!destination || !capacity) return count;
        const written = Math.min(count, capacity);
        for (let index = 0; index < written; index++) {
          let value = view.getUint16(source + index * 2, true);
          if ((flags & 0x100) && value >= 65 && value <= 90) value += 32;
          if ((flags & 0x200) && value >= 97 && value <= 122) value -= 32;
          view.setUint16(destination + index * 2, value, true);
        }
        return written;
      },
      MultiByteToWideChar: (sp) => {
        const input = this.arg(sp, 2), rawCount = this.arg(sp, 3) | 0;
        const output = this.arg(sp, 4), capacity = this.arg(sp, 5);
        let text;
        if (rawCount < 0) text = this.readCString(input) + "\0";
        else text = new TextDecoder().decode(new Uint8Array(this.memory.buffer, input, rawCount));
        if (!output || !capacity) return text.length;
        const count = Math.min(text.length, capacity), view = this.view();
        for (let index = 0; index < count; index++) view.setUint16(output + index * 2, text.charCodeAt(index), true);
        return count;
      },
      WideCharToMultiByte: (sp) => {
        const input = this.arg(sp, 2), rawCount = this.arg(sp, 3) | 0;
        const output = this.arg(sp, 4), capacity = this.arg(sp, 5), view = this.view();
        let count = rawCount;
        if (count < 0) {
          count = 0;
          while (view.getUint16(input + count * 2, true)) count++;
          count++;
        }
        if (!output || !capacity) return count;
        const written = Math.min(count, capacity), bytes = new Uint8Array(this.memory.buffer);
        for (let index = 0; index < written; index++) bytes[output + index] = view.getUint16(input + index * 2, true) & 0xff;
        return written;
      },
      LoadLibraryA: (sp) => {
        const name = this.readCString(this.arg(sp, 0)).toLowerCase();
        if (!this.moduleHandles.has(name)) this.moduleHandles.set(name, this.nextModuleHandle++);
        return this.moduleHandles.get(name);
      },
      LoadLibraryExA: (sp) => {
        const name = this.readCString(this.arg(sp, 0)).toLowerCase();
        if (!this.moduleHandles.has(name)) this.moduleHandles.set(name, this.nextModuleHandle++);
        return this.moduleHandles.get(name);
      },
      GetProcAddress: (sp) => {
        const handle = this.arg(sp, 0), symbolPointer = this.arg(sp, 1);
        const exports = this.moduleExports.get(handle);
        if (!exports) { this.lastError = 126; return 0; }
        const address = symbolPointer <= 0xffff
          ? exports.ordinals.get(symbolPointer)
          : exports.names.get(this.readCString(symbolPointer));
        if (address === undefined) { this.lastError = 127; return 0; }
        return address;
      },
    };
  }

  user32() {
    return {
      MessageBoxA: (sp) => {
        const event = { type: "message-box", text: this.readCString(this.arg(sp, 1)), caption: this.readCString(this.arg(sp, 2)), trace: this.captureTrace(128), stackCodePointers: this.captureCodePointers(sp) };
        if (this.environment.D2_WATCH_WORDS) {
          event.memoryWords = Object.fromEntries(this.environment.D2_WATCH_WORDS.split(",").map((text) => {
            const address = Number.parseInt(text.trim(), 0) >>> 0;
            return [`0x${address.toString(16).padStart(8, "0")}`, this.view().getUint32(address, true)];
          }));
        }
        this.events.push(event);
        return 1;
      },
      LoadStringA: (sp) => {
        const module = this.arg(sp, 0), id = this.arg(sp, 1), output = this.arg(sp, 2), capacity = this.arg(sp, 3);
        this.events.push({ type: "load-string", module, id, capacity });
        if (output && capacity) this.view().setUint8(output, 0);
        return 0;
      },
      GetSystemMetrics: (sp) => ({ 0: 800, 1: 600, 32: 8, 33: 8 }[this.arg(sp, 0)] ?? 0),
      GetDesktopWindow: () => 1,
      GetDC: () => {
        const handle = this.nextHandle++;
        this.handles.set(handle, { type: "gdi-dc", selected: this.ensureScreenBitmap() });
        return handle;
      },
      ReleaseDC: (sp) => { this.handles.delete(this.arg(sp, 1)); return 1; },
      DrawTextA: () => 16,
      GetActiveWindow: () => this.activeWindow || 1,
      IsWindow: () => 1,
      IsWindowVisible: () => 1,
      ShowWindow: () => 1,
      UpdateWindow: () => 1,
      DestroyWindow: (sp) => { this.handles.delete(this.arg(sp, 0)); return 1; },
      SetFocus: (sp) => { const previous = this.activeWindow; this.activeWindow = this.arg(sp, 0); return previous; },
      SetWindowPos: () => 1,
      GetWindowLongA: () => 0,
      GetWindowThreadProcessId: (sp) => { const process = this.arg(sp, 1); if (process) this.view().setUint32(process, 1, true); return 1; },
      SetRect: (sp) => {
        const pointer = this.arg(sp, 0), view = this.view();
        for (let index = 0; index < 4; index++) view.setInt32(pointer + index * 4, this.arg(sp, index + 1) | 0, true);
        return 1;
      },
      GetClientRect: (sp) => {
        const pointer = this.arg(sp, 1), view = this.view();
        view.setInt32(pointer, 0, true); view.setInt32(pointer + 4, 0, true);
        view.setInt32(pointer + 8, 800, true); view.setInt32(pointer + 12, 600, true); return 1;
      },
      GetWindowRect: (sp) => this.user32().GetClientRect(sp),
      AdjustWindowRectEx: () => 1,
      GetWindowPlacement: (sp) => {
        const pointer = this.arg(sp, 1), view = this.view();
        new Uint8Array(this.memory.buffer, pointer, 44).fill(0); view.setUint32(pointer, 44, true); view.setUint32(pointer + 8, 1, true);
        view.setInt32(pointer + 36, 800, true); view.setInt32(pointer + 40, 600, true); return 1;
      },
      IsIconic: () => 0,
      PtInRect: (sp) => {
        const pointer = this.arg(sp, 0), x = this.arg(sp, 1) | 0, y = this.arg(sp, 2) | 0, view = this.view();
        return x >= view.getInt32(pointer, true) && x < view.getInt32(pointer + 8, true) && y >= view.getInt32(pointer + 4, true) && y < view.getInt32(pointer + 12, true) ? 1 : 0;
      },
      GetCursorPos: (sp) => {
        const pointer = this.arg(sp, 0), view = this.view();
        view.setInt32(pointer, this.cursorX, true); view.setInt32(pointer + 4, this.cursorY, true); return 1;
      },
      ScreenToClient: () => 1,
      InvalidateRect: () => 1,
      LoadCursorA: () => 1,
      LoadImageA: () => 1,
      RegisterClassA: (sp) => {
        const definition = this.arg(sp, 0), view = this.view();
        const namePointer = view.getUint32(definition + 36, true);
        const name = namePointer <= 0xffff ? `#${namePointer}` : this.readCString(namePointer).toLowerCase();
        const atom = this.nextWindowAtom++;
        const item = { atom, name, wndProc: view.getUint32(definition + 4, true), instance: view.getUint32(definition + 16, true) };
        this.windowClasses.set(name, item); this.windowClasses.set(`#${atom}`, item);
        return atom;
      },
      UnregisterClassA: () => 1,
      CreateWindowExA: (sp) => {
        const classPointer = this.arg(sp, 1);
        const className = classPointer <= 0xffff ? `#${classPointer}` : this.readCString(classPointer).toLowerCase();
        const definition = this.windowClasses.get(className), handle = this.nextHandle++;
        this.handles.set(handle, {
          type: "window", className, wndProc: definition?.wndProc ?? 0,
          width: this.arg(sp, 6) | 0, height: this.arg(sp, 7) | 0,
        });
        this.activeWindow = handle;
        this.events.push({ type: "window-created", handle, className, wndProc: definition?.wndProc ?? 0 });
        return handle;
      },
      PeekMessageA: (sp) => {
        const output = this.arg(sp, 0), hwnd = this.arg(sp, 1), minimum = this.arg(sp, 2), maximum = this.arg(sp, 3), remove = this.arg(sp, 4);
        const index = this.messageQueue.findIndex((item) => (!hwnd || item.hwnd === hwnd) && (!minimum && !maximum || item.message >= minimum && item.message <= maximum));
        if (index < 0) return 0;
        const message = this.messageQueue[index];
        this.writeMessage(output, message);
        if (remove & 1) this.messageQueue.splice(index, 1);
        return 1;
      },
      GetMessageA: (sp) => {
        const output = this.arg(sp, 0), hwnd = this.arg(sp, 1), minimum = this.arg(sp, 2), maximum = this.arg(sp, 3);
        const index = this.messageQueue.findIndex((item) => (!hwnd || item.hwnd === hwnd) && (!minimum && !maximum || item.message >= minimum && item.message <= maximum));
        if (index < 0) return 0;
        const [message] = this.messageQueue.splice(index, 1);
        this.writeMessage(output, message);
        return message.message === 0x12 ? 0 : 1;
      },
      TranslateMessage: () => 1,
      DispatchMessageA: (sp) => {
        const messagePointer = this.arg(sp, 0), view = this.view();
        const hwnd = view.getUint32(messagePointer, true), window = this.handles.get(hwnd);
        return this.invokeTranslated(window?.wndProc, [hwnd, view.getUint32(messagePointer + 4, true), view.getUint32(messagePointer + 8, true), view.getUint32(messagePointer + 12, true)]);
      },
      SendMessageA: (sp) => {
        const hwnd = this.arg(sp, 0), window = this.handles.get(hwnd);
        return this.invokeTranslated(window?.wndProc, [hwnd, this.arg(sp, 1), this.arg(sp, 2), this.arg(sp, 3)]);
      },
      CopyRect: (sp) => {
        new Uint8Array(this.memory.buffer, this.arg(sp, 0), 16).set(new Uint8Array(this.memory.buffer, this.arg(sp, 1), 16));
        return 1;
      },
      IntersectRect: (sp) => {
        const output = this.arg(sp, 0), left = this.arg(sp, 1), right = this.arg(sp, 2), view = this.view();
        const values = [Math.max(view.getInt32(left, true), view.getInt32(right, true)), Math.max(view.getInt32(left + 4, true), view.getInt32(right + 4, true)), Math.min(view.getInt32(left + 8, true), view.getInt32(right + 8, true)), Math.min(view.getInt32(left + 12, true), view.getInt32(right + 12, true))];
        for (let index = 0; index < 4; index++) view.setInt32(output + index * 4, values[index], true);
        return values[0] < values[2] && values[1] < values[3] ? 1 : 0;
      },
      SetCursorPos: (sp) => { this.cursorX = this.arg(sp, 0) | 0; this.cursorY = this.arg(sp, 1) | 0; return 1; },
      GetKeyboardLayout: () => 0x04090409,
      GetKeyState: () => 0,
      GetAsyncKeyState: () => 0,
      LoadAcceleratorsA: () => 1,
      TranslateAcceleratorA: () => 0,
      DefWindowProcA: () => 0,
      SetTimer: (sp) => this.arg(sp, 2) || 1,
      KillTimer: () => 1,
      SetForegroundWindow: () => 1,
      RegisterWindowMessageA: () => 0xc000,
      PostQuitMessage: () => 0,
      FindWindowA: () => 0,
      OpenClipboard: () => 1,
      CloseClipboard: () => 1,
      EmptyClipboard: () => { this.clipboard.clear(); return 1; },
      SetClipboardData: (sp) => { this.clipboard.set(this.arg(sp, 0), this.arg(sp, 1)); return this.arg(sp, 1); },
      GetClipboardData: (sp) => this.clipboard.get(this.arg(sp, 0)) ?? 0,
      IsClipboardFormatAvailable: (sp) => this.clipboard.has(this.arg(sp, 0)) ? 1 : 0,
      ShowCursor: (sp) => {
        this.showCursorCount += this.arg(sp, 0) ? 1 : -1;
        return this.showCursorCount;
      },
      wsprintfA: (sp) => {
        const destination = this.arg(sp, 0);
        const text = this.formatAnsi(this.arg(sp, 1), sp + 8);
        this.writeCString(destination, new TextEncoder().encode(text).length + 1, text);
        return text.length;
      },
      wvsprintfA: (sp) => {
        const destination = this.arg(sp, 0);
        const text = this.formatAnsi(this.arg(sp, 1), this.arg(sp, 2));
        this.writeCString(destination, new TextEncoder().encode(text).length + 1, text);
        return text.length;
      },
    };
  }

  advapi32() {
    const predefinedKeys = new Map([
      [0x80000000, "HKEY_CLASSES_ROOT"],
      [0x80000001, "HKEY_CURRENT_USER"],
      [0x80000002, "HKEY_LOCAL_MACHINE"],
      [0x80000003, "HKEY_USERS"],
      [0x80000005, "HKEY_CURRENT_CONFIG"],
    ]);
    const keyPath = (handle) => {
      handle >>>= 0;
      return predefinedKeys.get(handle) ?? this.handles.get(handle)?.path ?? `HKEY_${handle.toString(16)}`;
    };
    const openKey = (sp, extended = false) => {
      const parent = this.arg(sp, 0) >>> 0;
      const subkey = this.readCString(this.arg(sp, 1));
      const resultPointer = this.arg(sp, extended ? 4 : 2);
      if (!resultPointer) return 87;
      const handle = this.nextHandle++;
      const path = [keyPath(parent), subkey].filter(Boolean).join("\\");
      this.handles.set(handle, { type: "registry", path });
      this.view().setUint32(resultPointer, handle, true);
      this.events.push({ type: "registry-open", path });
      return 0;
    };
    return {
      RegOpenKeyA: (sp) => openKey(sp),
      RegOpenKeyExA: (sp) => openKey(sp, true),
      RegCreateKeyA: (sp) => openKey(sp),
      RegCreateKeyExA: (sp) => {
        const parent = this.arg(sp, 0) >>> 0, subkey = this.readCString(this.arg(sp, 1));
        const resultPointer = this.arg(sp, 7), dispositionPointer = this.arg(sp, 8);
        if (!resultPointer) return 87;
        const handle = this.nextHandle++, path = [keyPath(parent), subkey].filter(Boolean).join("\\");
        this.handles.set(handle, { type: "registry", path });
        const view = this.view();
        view.setUint32(resultPointer, handle, true);
        if (dispositionPointer) view.setUint32(dispositionPointer, 1, true);
        this.events.push({ type: "registry-create", path });
        return 0;
      },
      RegDeleteKeyA: (sp) => {
        const path = [keyPath(this.arg(sp, 0)), this.readCString(this.arg(sp, 1))].filter(Boolean).join("\\");
        this.events.push({ type: "registry-delete", path });
        return 0;
      },
      RegDeleteValueA: (sp) => { this.registryValues.delete(this.readCString(this.arg(sp, 1)).toLowerCase()); return 0; },
      RegEnumValueA: () => 259,
      RegFlushKey: () => 0,
      RegQueryValueExA: (sp) => {
        const handle = this.arg(sp, 0) >>> 0;
        const name = this.readCString(this.arg(sp, 1));
        const typePointer = this.arg(sp, 3);
        const dataPointer = this.arg(sp, 4);
        const sizePointer = this.arg(sp, 5);
        const value = this.registryValues.get(name.toLowerCase());
        this.events.push({ type: "registry-query", path: keyPath(handle), name, found: value !== undefined });
        if (value === undefined) return 2;
        if (!sizePointer) return 87;
        const bytes = new TextEncoder().encode(`${value}\0`);
        const view = this.view();
        const capacity = view.getUint32(sizePointer, true);
        view.setUint32(sizePointer, bytes.length, true);
        if (typePointer) view.setUint32(typePointer, 1, true);
        if (!dataPointer) return 0;
        if (capacity < bytes.length) return 234;
        new Uint8Array(this.memory.buffer, dataPointer, bytes.length).set(bytes);
        return 0;
      },
      RegSetValueExA: (sp) => {
        const name = this.readCString(this.arg(sp, 1)), type = this.arg(sp, 3);
        const data = this.arg(sp, 4), size = this.arg(sp, 5);
        if (type === 1 && data) this.registryValues.set(name.toLowerCase(), this.readCString(data, size));
        this.events.push({ type: "registry-set", path: keyPath(this.arg(sp, 0)), name, registryType: type, size });
        return 0;
      },
      RegCloseKey: (sp) => { this.handles.delete(this.arg(sp, 0)); return 0; },
      GetUserNameA: (sp) => {
        const output = this.arg(sp, 0), sizePointer = this.arg(sp, 1);
        if (!sizePointer) return 0;
        const view = this.view(), capacity = view.getUint32(sizePointer, true), required = 7;
        view.setUint32(sizePointer, required, true);
        if (!output || capacity < required) { this.lastError = 122; return 0; }
        this.writeCString(output, capacity, "Player");
        return 1;
      },
      OpenSCManagerA: () => {
        const handle = this.nextHandle++;
        this.handles.set(handle, { type: "service-manager" });
        return handle;
      },
      OpenServiceA: () => { this.lastError = 1060; return 0; },
      CloseServiceHandle: (sp) => { this.handles.delete(this.arg(sp, 0)); return 1; },
      RegisterServiceCtrlHandlerA: () => {
        const handle = this.nextHandle++;
        this.handles.set(handle, { type: "service-status" });
        return handle;
      },
      SetServiceStatus: () => 1,
      StartServiceCtrlDispatcherA: () => 0,
      CreateServiceA: () => {
        const handle = this.nextHandle++;
        this.handles.set(handle, { type: "service" });
        return handle;
      },
    };
  }

  crtdll() {
    const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
    const parseInteger = (sp, unsigned) => {
      const input = this.arg(sp, 0);
      const text = this.readCString(input);
      const endPointer = this.arg(sp, 1);
      let base = this.arg(sp, 2) | 0;
      if (!base) base = /^\s*[+-]?0x/i.test(text) ? 16 : /^\s*[+-]?0[0-7]/.test(text) ? 8 : 10;
      const pattern = base === 16 ? /^\s*[+-]?(?:0x)?[0-9a-f]+/i : base === 8 ? /^\s*[+-]?[0-7]+/ : /^\s*[+-]?[0-9]+/;
      const token = text.match(pattern)?.[0] ?? "";
      if (endPointer) this.view().setUint32(endPointer, input + new TextEncoder().encode(token).length, true);
      if (!token) return 0;
      const value = Number.parseInt(token, base);
      return unsigned ? value >>> 0 : value | 0;
    };
    return {
      _fullpath: (sp) => {
        let destination = this.arg(sp, 0);
        const source = this.readCString(this.arg(sp, 1)).replaceAll("/", "\\");
        const capacity = this.arg(sp, 2);
        const absolute = /^[A-Za-z]:\\/.test(source) ? source : `${this.currentDirectory}\\${source}`;
        if (!destination) destination = this.alloc(new TextEncoder().encode(absolute).length + 1);
        if (!destination || !capacity && this.arg(sp, 0)) return 0;
        this.writeCString(destination, this.arg(sp, 0) ? capacity : new TextEncoder().encode(absolute).length + 1, absolute);
        return destination;
      },
      _stricmp: (sp) => compare(this.readCString(this.arg(sp, 0)).toLowerCase(), this.readCString(this.arg(sp, 1)).toLowerCase()),
      _strnicmp: (sp) => {
        const count = this.arg(sp, 2);
        return compare(this.readCString(this.arg(sp, 0)).slice(0, count).toLowerCase(), this.readCString(this.arg(sp, 1)).slice(0, count).toLowerCase());
      },
      _strupr: (sp) => {
        const pointer = this.arg(sp, 0);
        const text = this.readCString(pointer).toUpperCase();
        this.writeCString(pointer, new TextEncoder().encode(text).length + 1, text);
        return pointer;
      },
      _vsnprintf: (sp) => {
        const destination = this.arg(sp, 0), capacity = this.arg(sp, 1);
        const text = this.formatAnsi(this.arg(sp, 2), this.arg(sp, 3));
        this.writeCString(destination, capacity, text);
        return text.length;
      },
      memmove: (sp) => {
        const destination = this.arg(sp, 0), source = this.arg(sp, 1), count = this.arg(sp, 2);
        new Uint8Array(this.memory.buffer, destination, count).set(new Uint8Array(this.memory.buffer, source, count).slice());
        return destination;
      },
      setlocale: () => this.allocCString("C"),
      strncmp: (sp) => compare(this.readCString(this.arg(sp, 0)).slice(0, this.arg(sp, 2)), this.readCString(this.arg(sp, 1)).slice(0, this.arg(sp, 2))),
      strpbrk: (sp) => {
        const pointer = this.arg(sp, 0), text = this.readCString(pointer), accepted = new Set(this.readCString(this.arg(sp, 1)));
        const index = [...text].findIndex(character => accepted.has(character));
        return index < 0 ? 0 : pointer + index;
      },
      strstr: (sp) => {
        const pointer = this.arg(sp, 0), index = this.readCString(pointer).indexOf(this.readCString(this.arg(sp, 1)));
        return index < 0 ? 0 : pointer + index;
      },
      strtol: (sp) => parseInteger(sp, false),
      strtoul: (sp) => parseInteger(sp, true),
      toupper: (sp) => {
        const value = this.arg(sp, 0) | 0;
        return value >= 0x61 && value <= 0x7a ? value - 0x20 : value;
      },
      vsprintf: (sp) => {
        const destination = this.arg(sp, 0);
        const text = this.formatAnsi(this.arg(sp, 1), this.arg(sp, 2));
        this.writeCString(destination, new TextEncoder().encode(text).length + 1, text);
        return text.length;
      },
      wcslen: (sp) => {
        const pointer = this.arg(sp, 0), view = this.view();
        let length = 0;
        while (view.getUint16(pointer + length * 2, true)) length++;
        return length;
      },
      wcstombs: (sp) => {
        const destination = this.arg(sp, 0), source = this.arg(sp, 1), capacity = this.arg(sp, 2), view = this.view();
        let text = "";
        for (let index = 0, code; (code = view.getUint16(source + index * 2, true)); index++) text += String.fromCharCode(code <= 0xff ? code : 0x3f);
        if (destination && capacity) this.writeCString(destination, capacity, text);
        return text.length;
      },
    };
  }

  version() {
    return {
      GetFileVersionInfoSizeA: (sp) => {
        const ignoredHandle = this.arg(sp, 1);
        if (ignoredHandle) this.view().setUint32(ignoredHandle, 0, true);
        this.events.push({ type: "version-info-size", path: this.readCString(this.arg(sp, 0)), available: true });
        return 512;
      },
      GetFileVersionInfoA: (sp) => {
        const capacity = this.arg(sp, 2), block = this.arg(sp, 3);
        if (!block || capacity < 256) return 0;
        const bytes = new Uint8Array(this.memory.buffer, block, capacity);
        bytes.fill(0);
        const view = this.view();
        view.setUint32(block, 0xfeef04bd, true);
        view.setUint32(block + 4, 0x00010000, true);
        view.setUint32(block + 8, 0x00010001, true);
        view.setUint32(block + 12, 0x00020010, true);
        view.setUint32(block + 16, 0x00010001, true);
        view.setUint32(block + 20, 0x00020010, true);
        this.writeCString(block + 0x80, capacity - 0x80, "1.1.2.16");
        this.writeCString(block + 0xc0, capacity - 0xc0, "ijl11.dll");
        return 1;
      },
      VerQueryValueA: (sp) => {
        const block = this.arg(sp, 0), query = this.readCString(this.arg(sp, 1)).toLowerCase();
        const valuePointer = this.arg(sp, 2), lengthPointer = this.arg(sp, 3);
        if (!block || !valuePointer || !lengthPointer) return 0;
        let value = block, length = 52;
        if (query.includes("productversion")) { value = block + 0x80; length = 9; }
        else if (query.includes("originalfilename")) { value = block + 0xc0; length = 10; }
        else if (query !== "\\") return 0;
        const view = this.view();
        view.setUint32(valuePointer, value, true);
        view.setUint32(lengthPointer, length, true);
        return 1;
      },
    };
  }

  gdi32() {
    const create = (item) => { const handle = this.nextHandle++; this.handles.set(handle, item); return handle; };
    const bitmapForDc = (handle) => {
      const dc = this.handles.get(handle);
      return this.handles.get(dc?.selected ?? 0);
    };
    const createBitmap = (width, height, bitsPerPixel = 32, source = 0) => {
      const topDown = (height | 0) < 0;
      width = Math.max(1, width | 0); height = Math.max(1, Math.abs(height | 0));
      const stride = ((width * bitsPerPixel + 31) >>> 5) << 2, size = stride * height, bits = this.alloc(size, 4);
      new Uint8Array(this.memory.buffer, bits, size).fill(0);
      if (source) new Uint8Array(this.memory.buffer, bits, size).set(new Uint8Array(this.memory.buffer, source, size));
      return create({ type: "gdi-bitmap", width, height, bitsPerPixel, stride, size, bits, topDown, palette: null });
    };
    return {
      GetStockObject: (sp) => 0x70000000 | this.arg(sp, 0),
      DeleteObject: (sp) => { this.handles.delete(this.arg(sp, 0)); return 1; },
      DeleteDC: (sp) => { this.handles.delete(this.arg(sp, 0)); return 1; },
      CreateCompatibleDC: () => create({ type: "gdi-dc", selected: 0 }),
      CreateDCA: () => create({ type: "gdi-dc", selected: 0 }),
      SelectObject: (sp) => {
        const dc = this.handles.get(this.arg(sp, 0)); if (!dc) return 0;
        const previous = dc.selected ?? 0; dc.selected = this.arg(sp, 1); return previous;
      },
      GetCurrentObject: (sp) => this.handles.get(this.arg(sp, 0))?.selected ?? 0,
      SetTextColor: () => 0,
      SetBkColor: () => 0,
      SetBkMode: (sp) => this.arg(sp, 1),
      SetTextAlign: (sp) => this.arg(sp, 1),
      GetDeviceCaps: (sp) => ({ 8: 800, 10: 600, 12: 32, 14: 1, 88: 96, 90: 96, 104: 256 }[this.arg(sp, 1)] ?? 0),
      CreateRectRgn: (sp) => create({ type: "gdi-region", rect: [this.arg(sp, 0) | 0, this.arg(sp, 1) | 0, this.arg(sp, 2) | 0, this.arg(sp, 3) | 0] }),
      CombineRgn: () => 1,
      RectInRegion: () => 1,
      GetRegionData: (sp) => {
        const capacity = this.arg(sp, 1), output = this.arg(sp, 2); if (!output || capacity < 32) return 32;
        new Uint8Array(this.memory.buffer, output, 32).fill(0); const view = this.view();
        view.setUint32(output, 32, true); view.setUint32(output + 4, 1, true); view.setUint32(output + 8, 1, true); view.setUint32(output + 12, 16, true); return 32;
      },
      CreatePalette: () => create({ type: "gdi-palette" }),
      SelectPalette: (sp) => { const dc = this.handles.get(this.arg(sp, 0)); if (dc) dc.palette = this.arg(sp, 1); return 0; },
      RealizePalette: () => 256,
      SetPaletteEntries: (sp) => this.arg(sp, 2),
      GetSystemPaletteEntries: (sp) => {
        const count = this.arg(sp, 2), output = this.arg(sp, 3); if (output) new Uint8Array(this.memory.buffer, output, count * 4).fill(0); return count;
      },
      CreateFontA: () => create({ type: "gdi-font" }),
      GetCharWidthA: (sp) => {
        const first = this.arg(sp, 1), last = this.arg(sp, 2), output = this.arg(sp, 3), view = this.view();
        for (let value = first; value <= last; value++) view.setUint32(output + (value - first) * 4, 8, true); return 1;
      },
      GetCharABCWidthsA: (sp) => {
        const first = this.arg(sp, 1), last = this.arg(sp, 2), output = this.arg(sp, 3), view = this.view();
        for (let value = first; value <= last; value++) { const pointer = output + (value - first) * 12; view.setInt32(pointer, 0, true); view.setUint32(pointer + 4, 8, true); view.setInt32(pointer + 8, 0, true); } return 1;
      },
      GetTextExtentPoint32A: (sp) => { const output = this.arg(sp, 3), view = this.view(); view.setInt32(output, this.arg(sp, 2) * 8, true); view.setInt32(output + 4, 16, true); return 1; },
      CreateBitmap: (sp) => createBitmap(this.arg(sp, 0), this.arg(sp, 1), Math.max(1, this.arg(sp, 2) * this.arg(sp, 3)), this.arg(sp, 4)),
      CreateCompatibleBitmap: (sp) => createBitmap(this.arg(sp, 1), this.arg(sp, 2)),
      CreateDIBSection: (sp) => {
        const info = this.arg(sp, 1), view = this.view(), width = view.getInt32(info + 4, true), height = view.getInt32(info + 8, true), bitsPerPixel = view.getUint16(info + 14, true) || 32;
        const handle = createBitmap(width, height, bitsPerPixel), bitmap = this.handles.get(handle), bitsPointer = this.arg(sp, 3);
        if (bitsPointer) view.setUint32(bitsPointer, bitmap.bits, true); return handle;
      },
      GetDIBits: (sp) => {
        const bitmap = this.handles.get(this.arg(sp, 1)), output = this.arg(sp, 4); if (!bitmap || bitmap.type !== "gdi-bitmap") return 0;
        if (output) new Uint8Array(this.memory.buffer, output, bitmap.size).set(new Uint8Array(this.memory.buffer, bitmap.bits, bitmap.size)); return this.arg(sp, 3);
      },
      SetDIBColorTable: (sp) => {
        const bitmap = bitmapForDc(this.arg(sp, 0)), start = this.arg(sp, 1), count = this.arg(sp, 2), entries = this.arg(sp, 3);
        if (!bitmap || bitmap.type !== "gdi-bitmap" || !entries) return 0;
        bitmap.palette ??= new Uint32Array(256);
        const bytes = new Uint8Array(this.memory.buffer);
        for (let index = 0; index < count && start + index < 256; index++) {
          const pointer = entries + index * 4;
          bitmap.palette[start + index] = (bytes[pointer] | bytes[pointer + 1] << 8 | bytes[pointer + 2] << 16 | 0xff000000) >>> 0;
        }
        return count;
      },
      GetPixel: (sp) => {
        const bitmap = bitmapForDc(this.arg(sp, 0)); if (!bitmap || bitmap.bitsPerPixel !== 32) return 0xffffffff;
        const x = this.arg(sp, 1) | 0, y = this.arg(sp, 2) | 0; if (x < 0 || y < 0 || x >= bitmap.width || y >= bitmap.height) return 0xffffffff;
        return this.view().getUint32(bitmap.bits + y * bitmap.stride + x * 4, true) & 0xffffff;
      },
      SetPixel: (sp) => {
        const bitmap = bitmapForDc(this.arg(sp, 0)); if (!bitmap || bitmap.bitsPerPixel !== 32) return 0xffffffff;
        const x = this.arg(sp, 1) | 0, y = this.arg(sp, 2) | 0, color = this.arg(sp, 3); if (x < 0 || y < 0 || x >= bitmap.width || y >= bitmap.height) return 0xffffffff;
        this.view().setUint32(bitmap.bits + y * bitmap.stride + x * 4, color, true); return color;
      },
      BitBlt: (sp) => {
        const destination = bitmapForDc(this.arg(sp, 0)), source = bitmapForDc(this.arg(sp, 5));
        if (!destination || !source) return 1;
        const dx = this.arg(sp, 1) | 0, dy = this.arg(sp, 2) | 0, width = this.arg(sp, 3) | 0, height = this.arg(sp, 4) | 0, sx = this.arg(sp, 6) | 0, sy = this.arg(sp, 7) | 0;
        for (let row = 0; row < height; row++) if (dy + row >= 0 && dy + row < destination.height && sy + row >= 0 && sy + row < source.height) {
          const count = Math.max(0, Math.min(width, destination.width - dx, source.width - sx)); if (!count) continue;
          const sourceRow = source.topDown ? sy + row : source.height - 1 - sy - row;
          const destinationRow = destination.topDown ? dy + row : destination.height - 1 - dy - row;
          if (destination.bitsPerPixel === 32 && source.bitsPerPixel === 32) {
            const bytes = new Uint8Array(this.memory.buffer, source.bits + sourceRow * source.stride + sx * 4, count * 4);
            new Uint8Array(this.memory.buffer, destination.bits + destinationRow * destination.stride + dx * 4, count * 4).set(bytes);
          } else if (destination.bitsPerPixel === 32 && source.bitsPerPixel === 8) {
            const input = new Uint8Array(this.memory.buffer, source.bits + sourceRow * source.stride + sx, count);
            const output = new DataView(this.memory.buffer, destination.bits + destinationRow * destination.stride + dx * 4, count * 4);
            for (let column = 0; column < count; column++) output.setUint32(column * 4, source.palette?.[input[column]] ?? 0xff000000, true);
          } else if (destination.bitsPerPixel === 8 && source.bitsPerPixel === 8) {
            const bytes = new Uint8Array(this.memory.buffer, source.bits + sourceRow * source.stride + sx, count);
            new Uint8Array(this.memory.buffer, destination.bits + destinationRow * destination.stride + dx, count).set(bytes);
          }
        }
        if (destination.screen) {
          const presentationWidth = Math.max(1, Math.min(
            destination.width - Math.max(dx, 0),
            source.width - Math.max(sx, 0),
            width,
          ));
          const presentationHeight = Math.max(1, Math.min(
            destination.height - Math.max(dy, 0),
            source.height - Math.max(sy, 0),
            height,
          ));
          this.completePresentation(presentationWidth, presentationHeight, (presentation) =>
            this.onPresent?.(destination, presentation, {
              width: presentationWidth,
              height: presentationHeight,
            })
          );
        }
        return 1;
      },
      GdiFlush: () => 1,
      GdiSetBatchLimit: () => 1,
    };
  }

  glide3x() {
    const emit = (type, detail = {}) => this.onGlide?.({ type, ...detail });
    const textureInfo = (pointer) => {
      const view = this.view();
      const smallLod = view.getInt32(pointer, true);
      const largeLod = view.getInt32(pointer + 4, true);
      const aspect = view.getInt32(pointer + 8, true);
      const maxDimension = 1 << Math.max(0, Math.min(12, largeLod));
      const width = aspect >= 0 ? maxDimension : maxDimension >> -aspect;
      const height = aspect <= 0 ? maxDimension : maxDimension >> aspect;
      return {
        pointer,
        smallLod,
        largeLod,
        aspect,
        format: view.getUint32(pointer + 12, true),
        data: view.getUint32(pointer + 16, true),
        width: Math.max(1, width),
        height: Math.max(1, height),
      };
    };
    const draw = (type, sp, detail = {}) => {
      emit("draw", { drawType: type, ...detail });
      return 0;
    };
    const state = (type, names) => (sp) => {
      emit(type, Object.fromEntries(names.map((name, index) => [name, this.arg(sp, index)])));
      return 0;
    };
    const getValues = new Map([
      [0x05, 256], // GR_GAMMA_TABLE_ENTRIES
      [0x0a, 256], // GR_MAX_TEXTURE_SIZE
      [0x0b, 3],   // GR_MAX_TEXTURE_ASPECT_RATIO
      [0x0e, 0],   // GR_MEMORY_UMA
      [0x0f, 1],   // GR_NUM_BOARDS
      [0x11, 1],   // GR_NUM_FB
      [0x13, 1],   // GR_NUM_TMU
      [0x24, 256], // GR_TEXTURE_ALIGN
      [0x2a, 8],   // GR_BITS_GAMMA
    ]);
    const strings = new Map([
      [0xa0, " "],
      [0xa1, "Voodoo2"],
      [0xa2, "d2wasm WebGL2 Glide"],
      [0xa3, "3Dfx Interactive"],
      [0xa4, "3.0"],
    ]);
    return {
      "_grGlideInit@0": () => { emit("init"); return 0; },
      "_grGlideShutdown@0": () => { emit("shutdown"); return 0; },
      "_grSstSelect@4": state("select", ["board"]),
      "_grSstWinOpen@28": (sp) => {
        const resolution = this.arg(sp, 1);
        const dimensions = new Map([
          [0x7, [640, 480]],
          [0x8, [800, 600]],
          [0xc, [1024, 768]],
        ]).get(resolution) ?? [640, 480];
        [this.glideWidth, this.glideHeight] = dimensions;
        emit("open", {
          window: this.arg(sp, 0),
          resolution,
          width: this.glideWidth,
          height: this.glideHeight,
          refresh: this.arg(sp, 2),
          colorFormat: this.arg(sp, 3),
          origin: this.arg(sp, 4),
          colorBuffers: this.arg(sp, 5),
          auxiliaryBuffers: this.arg(sp, 6),
        });
        return 1;
      },
      "_grSstWinClose@4": (sp) => { emit("close", { context: this.arg(sp, 0) }); return 1; },
      "_grGet@12": (sp) => {
        const parameter = this.arg(sp, 0);
        const length = this.arg(sp, 1);
        const output = this.arg(sp, 2);
        if (!output || length < 4 || !getValues.has(parameter)) return 0;
        this.view().setInt32(output, getValues.get(parameter), true);
        return 4;
      },
      "_grGetString@4": (sp) => {
        const parameter = this.arg(sp, 0);
        const value = strings.get(parameter);
        if (value === undefined) return 0;
        if (!this.glideStrings.has(parameter)) this.glideStrings.set(parameter, this.allocCString(value));
        return this.glideStrings.get(parameter);
      },
      "_grTexMinAddress@4": () => 0,
      "_grTexMaxAddress@4": () => 16 * 1024 * 1024 - 512,
      "_grVertexLayout@12": state("vertex-layout", ["parameter", "offset", "mode"]),
      "_grTexDownloadMipMap@16": (sp) => {
        const info = textureInfo(this.arg(sp, 3));
        emit("texture-download", {
          tmu: this.arg(sp, 0),
          address: this.arg(sp, 1),
          evenOdd: this.arg(sp, 2),
          ...info,
        });
        return 0;
      },
      "_grTexSource@16": (sp) => {
        const info = textureInfo(this.arg(sp, 3));
        emit("texture-source", {
          tmu: this.arg(sp, 0),
          address: this.arg(sp, 1),
          evenOdd: this.arg(sp, 2),
          ...info,
        });
        return 0;
      },
      "_grTexDownloadTable@8": state("palette", ["table", "data"]),
      "_grTexCombine@28": state("texture-combine", [
        "tmu", "rgbFunction", "rgbFactor", "alphaFunction", "alphaFactor", "rgbInvert", "alphaInvert",
      ]),
      "_grTexFilterMode@12": state("texture-filter", ["tmu", "minification", "magnification"]),
      "_grColorCombine@20": state("color-combine", ["function", "factor", "local", "other", "invert"]),
      "_grAlphaCombine@20": state("alpha-combine", ["function", "factor", "local", "other", "invert"]),
      "_grAlphaBlendFunction@16": state("alpha-blend", ["rgbSource", "rgbDestination", "alphaSource", "alphaDestination"]),
      "_grConstantColorValue@4": state("constant-color", ["color"]),
      "_grChromakeyMode@4": state("chroma-mode", ["mode"]),
      "_grChromakeyValue@4": state("chroma-value", ["color"]),
      "_grColorMask@8": state("color-mask", ["rgb", "alpha"]),
      "_grDepthMask@4": state("depth-mask", ["enabled"]),
      "_grDitherMode@4": state("dither", ["mode"]),
      "_grCoordinateSpace@4": state("coordinate-space", ["mode"]),
      "_grLoadGammaTable@16": state("gamma-table", ["entries", "red", "green", "blue"]),
      "_guGammaCorrectionRGB@12": state("gamma", ["red", "green", "blue"]),
      "_grDrawPoint@4": (sp) => draw("point", sp, { vertices: this.arg(sp, 0), count: 1, stride: 28 }),
      "_grDrawLine@8": (sp) => draw("line", sp, {
        vertices: [this.arg(sp, 0), this.arg(sp, 1)],
        count: 2,
        stride: 28,
      }),
      "_grDrawVertexArray@12": (sp) => draw("array", sp, {
        mode: this.arg(sp, 0),
        count: this.arg(sp, 1),
        pointers: this.arg(sp, 2),
        stride: 28,
      }),
      "_grDrawVertexArrayContiguous@16": (sp) => draw("contiguous", sp, {
        mode: this.arg(sp, 0),
        count: this.arg(sp, 1),
        vertices: this.arg(sp, 2),
        stride: this.arg(sp, 3),
      }),
      "_grBufferClear@12": state("clear", ["color", "alpha", "depth"]),
      "_grBufferSwap@4": (sp) => {
        this.completePresentation(this.glideWidth, this.glideHeight, () =>
          emit("swap", { interval: this.arg(sp, 0), width: this.glideWidth, height: this.glideHeight })
        );
        return 0;
      },
      "_grFinish@0": () => { emit("finish"); return 0; },
      "_grLfbLock@24": (sp) => {
        const info = this.arg(sp, 5);
        if (!info) return 0;
        const required = this.glideWidth * this.glideHeight * 4;
        if (!this.glideLfbPointer || this.glideLfbSize < required) {
          this.glideLfbPointer = this.alloc(required, 16);
          this.glideLfbSize = required;
        }
        this.glideLfbStride = this.glideWidth * 4;
        const view = this.view();
        view.setUint32(info + 4, this.glideLfbPointer, true);
        view.setUint32(info + 8, this.glideLfbStride, true);
        view.setUint32(info + 12, this.arg(sp, 2), true);
        view.setUint32(info + 16, this.arg(sp, 3), true);
        emit("lfb-lock", {
          lockType: this.arg(sp, 0),
          buffer: this.arg(sp, 1),
          writeMode: this.arg(sp, 2),
          origin: this.arg(sp, 3),
          pixelPipeline: this.arg(sp, 4),
          info,
          data: this.glideLfbPointer,
          stride: this.glideLfbStride,
          width: this.glideWidth,
          height: this.glideHeight,
        });
        return 1;
      },
      "_grLfbUnlock@8": (sp) => {
        this.completePresentation(this.glideWidth, this.glideHeight, () => emit("lfb-unlock", {
          lockType: this.arg(sp, 0),
          buffer: this.arg(sp, 1),
          data: this.glideLfbPointer,
          stride: this.glideLfbStride,
          width: this.glideWidth,
          height: this.glideHeight,
        }));
        return 1;
      },
    };
  }

  winmm() {
    return { timeGetTime: () => this.clockNow() };
  }

  imm32() {
    return {
      ImmGetContext: () => 1,
      ImmReleaseContext: () => 1,
      ImmIsIME: () => 0,
      ImmGetOpenStatus: () => 0,
      ImmSetOpenStatus: () => 1,
      ImmGetConversionStatus: (sp) => {
        if (this.arg(sp, 1)) this.view().setUint32(this.arg(sp, 1), 0, true);
        if (this.arg(sp, 2)) this.view().setUint32(this.arg(sp, 2), 0, true);
        return 1;
      },
      ImmSetConversionStatus: () => 1,
      ImmGetCompositionStringA: () => 0,
      ImmGetCandidateListCountA: (sp) => { if (this.arg(sp, 1)) this.view().setUint32(this.arg(sp, 1), 0, true); return 0; },
      ImmGetCandidateListA: () => 0,
      ImmSimulateHotKey: () => 0,
    };
  }

  wsock32() {
    const socket = () => {
      const handle = this.nextHandle++;
      this.handles.set(handle, { type: "socket", address: 0x0100007f });
      return handle;
    };
    const socketAddress = (pointer, sizePointer = 0) => {
      if (!pointer) return;
      const view = this.view();
      view.setUint16(pointer, 2, true); view.setUint16(pointer + 2, 0, true); view.setUint32(pointer + 4, 0x0100007f, true);
      if (sizePointer) view.setUint32(sizePointer, 16, true);
    };
    return {
      "#1": () => { this.lastError = 10035; return 0xffffffff; },
      "#2": () => 0,
      "#3": (sp) => { this.handles.delete(this.arg(sp, 0)); return 0; },
      "#4": () => { this.lastError = 10061; return 0xffffffff; },
      "#6": (sp) => { socketAddress(this.arg(sp, 1), this.arg(sp, 2)); return 0; },
      "#9": (sp) => { const value = this.arg(sp, 0); return ((value & 0xff) << 8) | ((value >>> 8) & 0xff); },
      "#10": (sp) => {
        const parts = this.readCString(this.arg(sp, 0)).split(".").map(Number);
        if (parts.length !== 4 || parts.some(value => !Number.isInteger(value) || value < 0 || value > 255)) return 0xffffffff;
        return (parts[0] | parts[1] << 8 | parts[2] << 16 | parts[3] << 24) >>> 0;
      },
      "#11": (sp) => {
        const value = this.arg(sp, 0), text = `${value & 0xff}.${value >>> 8 & 0xff}.${value >>> 16 & 0xff}.${value >>> 24 & 0xff}`;
        return this.allocCString(text);
      },
      "#12": () => 0,
      "#13": () => 0,
      "#16": () => { this.lastError = 10035; return 0xffffffff; },
      "#18": () => 0,
      "#19": () => { this.lastError = 10035; return 0xffffffff; },
      "#21": () => 0,
      "#23": () => socket(),
      "#52": (sp) => {
        const name = this.readCString(this.arg(sp, 0)) || "d2wasm";
        const hostent = this.alloc(32, 4), namePointer = this.allocCString(name), address = this.alloc(4, 4), list = this.alloc(8, 4), view = this.view();
        view.setUint32(address, 0x0100007f, true); view.setUint32(list, address, true); view.setUint32(list + 4, 0, true);
        view.setUint32(hostent, namePointer, true); view.setUint32(hostent + 4, 0, true);
        view.setUint16(hostent + 8, 2, true); view.setUint16(hostent + 10, 4, true); view.setUint32(hostent + 12, list, true);
        return hostent;
      },
      "#57": (sp) => { this.writeCString(this.arg(sp, 0), this.arg(sp, 1), "d2wasm"); return 0; },
      "#111": () => this.lastError,
      "#112": (sp) => { this.lastError = this.arg(sp, 0); return 0; },
      "#115": (sp) => {
        const data = this.arg(sp, 1), view = this.view();
        new Uint8Array(this.memory.buffer, data, 400).fill(0);
        view.setUint16(data, 0x0101, true); view.setUint16(data + 2, 0x0101, true);
        this.writeCString(data + 4, 257, "D2Wasm Winsock 1.1"); this.writeCString(data + 261, 129, "Running");
        view.setUint16(data + 390, 64, true); view.setUint16(data + 392, 64, true);
        return 0;
      },
      "#116": () => 0,
      "#151": () => 0,
    };
  }

  dsound() {
    return {
      "#1": (sp) => {
        const output = this.arg(sp, 1);
        if (!output) return 0x80070057;
        if (!this.soundEnabled) {
          this.view().setUint32(output, 0, true);
          return 0x88780078;
        }
        const object = this.createComObject(0, 11);
        this.directSoundObjects.add(object);
        this.view().setUint32(output, object, true);
        if (!this.directSoundCreatedReported) {
          this.directSoundCreatedReported = true;
          this.events.push({
            type: "direct-sound-created",
            output,
            object,
            vtable: this.view().getUint32(object, true),
            result: 0,
          });
        }
        return 0;
      },
      "__dispatch": (method, sp) => this.dispatchDirectSound(method >>> 0, sp >>> 0),
    };
  }

  imports() {
    const libraries = {
      "win32.kernel32.dll": this.kernel32(),
      "win32.user32.dll": this.user32(),
      "win32.advapi32.dll": this.advapi32(),
      "win32.crtdll.dll": this.crtdll(),
      "win32.version.dll": this.version(),
      "win32.gdi32.dll": this.gdi32(),
      "win32.glide3x.dll": this.glide3x(),
      "win32.winmm.dll": this.winmm(),
      "win32.imm32.dll": this.imm32(),
      "win32.wsock32.dll": this.wsock32(),
      "win32.dsound.dll": this.dsound(),
    };
    if (!this.diagnostics) return libraries;
    for (const [library, functions] of Object.entries(libraries)) {
      for (const [name, implementation] of Object.entries(functions)) {
        functions[name] = (...args) => {
          const key = `${library}!${name}`;
          this.apiCounts.set(key, (this.apiCounts.get(key) ?? 0) + 1);
          this.recentApis.push(key);
          if (this.recentApis.length > 128) this.recentApis.shift();
          return implementation(...args);
        };
      }
    }
    return libraries;
  }
}
