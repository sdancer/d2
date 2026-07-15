const canvas = document.querySelector("#game");
const startButton = document.querySelector("#start");
const pauseButton = document.querySelector("#pause");
const demoToggle = document.querySelector("#demo");
const curtain = document.querySelector("#curtain");
const status = document.querySelector("#status");
const progress = document.querySelector("#progress");
const runtimeStatus = document.querySelector("#runtime");
const log = document.querySelector("#log");

let worker;
let paused = false;
let surfaceWidth = 800;
let surfaceHeight = 600;
let audioContext;
const playingSounds = new Map();
const logLines = [];

function playSound(data) {
  if (!audioContext || audioContext.state === "closed") return;
  const format = data.format;
  const channels = Math.max(1, Math.min(2, format.channels));
  const bytes = new Uint8Array(data.bytes);
  const bytesPerSample = Math.max(1, format.bitsPerSample >> 3);
  const frames = Math.floor(bytes.byteLength / Math.max(1, channels * bytesPerSample));
  if (!frames || (format.bitsPerSample !== 8 && format.bitsPerSample !== 16)) return;
  const sampleRate = Math.max(8000, data.frequency || format.samplesPerSec);
  const buffer = audioContext.createBuffer(channels, frames, sampleRate);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let channel = 0; channel < channels; channel++) {
    const output = buffer.getChannelData(channel);
    for (let frame = 0; frame < frames; frame++) {
      const offset = (frame * channels + channel) * bytesPerSample;
      output[frame] = format.bitsPerSample === 8
        ? (bytes[offset] - 128) / 128
        : view.getInt16(offset, true) / 32768;
    }
  }
  try { playingSounds.get(data.id)?.stop(); } catch {}
  const source = audioContext.createBufferSource();
  const gain = audioContext.createGain();
  gain.gain.value = Math.max(0, Math.min(1, Math.pow(10, data.volume / 2000)));
  source.buffer = buffer;
  source.loop = data.loop;
  if (audioContext.createStereoPanner) {
    const panner = audioContext.createStereoPanner();
    panner.pan.value = Math.max(-1, Math.min(1, data.pan / 10000));
    source.connect(gain).connect(panner).connect(audioContext.destination);
  } else {
    source.connect(gain).connect(audioContext.destination);
  }
  source.addEventListener("ended", () => {
    if (playingSounds.get(data.id) === source) playingSounds.delete(data.id);
  });
  playingSounds.set(data.id, source);
  source.start();
}

function stopSound(id) {
  const source = playingSounds.get(id);
  if (!source) return;
  playingSounds.delete(id);
  try { source.stop(); } catch {}
}

function appendLog(message) {
  const stamp = new Date().toLocaleTimeString();
  logLines.push(`[${stamp}] ${message}`);
  if (logLines.length > 200) logLines.splice(0, logLines.length - 200);
  log.textContent = logLines.join("\n");
  log.scrollTop = log.scrollHeight;
}

function setStatus(title, detail = "") {
  status.textContent = title;
  progress.textContent = detail;
}

function virtualKey(event) {
  if (event.key.length === 1) {
    const upper = event.key.toUpperCase().codePointAt(0);
    if (upper <= 0x7f) return upper;
  }
  const keys = {
    Backspace: 0x08, Tab: 0x09, Enter: 0x0d, Shift: 0x10, Control: 0x11,
    Alt: 0x12, Pause: 0x13, CapsLock: 0x14, Escape: 0x1b, " ": 0x20,
    PageUp: 0x21, PageDown: 0x22, End: 0x23, Home: 0x24, ArrowLeft: 0x25,
    ArrowUp: 0x26, ArrowRight: 0x27, ArrowDown: 0x28, Insert: 0x2d,
    Delete: 0x2e, F1: 0x70, F2: 0x71, F3: 0x72, F4: 0x73, F5: 0x74,
    F6: 0x75, F7: 0x76, F8: 0x77, F9: 0x78, F10: 0x79, F11: 0x7a,
    F12: 0x7b,
  };
  return keys[event.key] ?? null;
}

function gamePoint(event) {
  const bounds = canvas.getBoundingClientRect();
  return {
    x: Math.max(0, Math.min(surfaceWidth - 1, Math.floor((event.clientX - bounds.left) * surfaceWidth / bounds.width))),
    y: Math.max(0, Math.min(surfaceHeight - 1, Math.floor((event.clientY - bounds.top) * surfaceHeight / bounds.height))),
  };
}

function sendPointer(event, kind) {
  if (!worker) return;
  const point = gamePoint(event);
  worker.postMessage({ type: "pointer", kind, button: event.button, ...point });
}

canvas.addEventListener("pointermove", (event) => sendPointer(event, "move"));
canvas.addEventListener("pointerdown", (event) => {
  canvas.focus();
  canvas.setPointerCapture(event.pointerId);
  sendPointer(event, "down");
  event.preventDefault();
});
canvas.addEventListener("pointerup", (event) => {
  sendPointer(event, "up");
  event.preventDefault();
});
canvas.addEventListener("contextmenu", (event) => event.preventDefault());
canvas.addEventListener("wheel", (event) => {
  if (!worker) return;
  const point = gamePoint(event);
  worker.postMessage({ type: "wheel", delta: Math.sign(-event.deltaY) * 120, ...point });
  event.preventDefault();
}, { passive: false });

canvas.addEventListener("keydown", (event) => {
  if (!worker || event.repeat) return;
  const key = virtualKey(event);
  if (key === null) return;
  worker.postMessage({ type: "key", virtualKey: key, down: true });
  if (event.key.length === 1 && !event.ctrlKey && !event.altKey && !event.metaKey) {
    worker.postMessage({ type: "character", codePoint: event.key.codePointAt(0) });
  }
  event.preventDefault();
});
canvas.addEventListener("keyup", (event) => {
  if (!worker) return;
  const key = virtualKey(event);
  if (key === null) return;
  worker.postMessage({ type: "key", virtualKey: key, down: false });
  event.preventDefault();
});

startButton.addEventListener("click", () => {
  if (worker) return;
  const Audio = window.AudioContext || window.webkitAudioContext;
  if (Audio) {
    audioContext = new Audio();
    audioContext.resume();
  }
  worker = new Worker("/game-worker.mjs", { type: "module" });
  worker.addEventListener("message", ({ data }) => {
    if (data.type === "progress") {
      setStatus(data.title, data.detail);
    } else if (data.type === "ready") {
      curtain.classList.add("hidden");
      pauseButton.disabled = false;
      runtimeStatus.textContent = "Running";
      canvas.focus();
      appendLog(data.message);
    } else if (data.type === "state") {
      runtimeStatus.textContent = data.message;
    } else if (data.type === "frame-size") {
      surfaceWidth = data.width;
      surfaceHeight = data.height;
    } else if (data.type === "audio-play") {
      playSound(data);
    } else if (data.type === "audio-stop") {
      stopSound(data.id);
    } else if (data.type === "log") {
      appendLog(data.message);
    } else if (data.type === "message-box") {
      appendLog(`MessageBoxA: ${data.caption}: ${data.text}`);
    } else if (data.type === "stopped") {
      setStatus("Guest stopped", data.message);
      curtain.classList.remove("hidden");
      runtimeStatus.textContent = "Stopped";
      pauseButton.disabled = true;
      appendLog(data.message);
    } else if (data.type === "error") {
      setStatus("Browser host failed", data.message);
      runtimeStatus.textContent = "Error";
      appendLog(data.stack || data.message);
    }
  });
  const surface = canvas.transferControlToOffscreen();
  worker.postMessage({ type: "start", canvas: surface, demo: demoToggle.checked }, [surface]);
  startButton.disabled = true;
  demoToggle.disabled = true;
  setStatus("Starting browser host…", "Fetching configuration and translated Wasm.");
});

pauseButton.addEventListener("click", () => {
  if (!worker) return;
  paused = !paused;
  worker.postMessage({ type: paused ? "pause" : "resume" });
  pauseButton.textContent = paused ? "Resume" : "Pause";
  runtimeStatus.textContent = paused ? "Paused" : "Running";
});

window.addEventListener("beforeunload", () => worker?.terminate());
