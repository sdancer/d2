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
const audioDiagnostics = {
  state: "unavailable",
  playCount: 0,
  nonSilentPlayCount: 0,
  writeCount: 0,
  lastSound: null,
};
const logLines = [];

function updateAudioDiagnostics() {
  audioDiagnostics.state = audioContext?.state ?? "unavailable";
  globalThis.d2Audio = { ...audioDiagnostics, activeSources: playingSounds.size };
}

async function resumeAudio() {
  if (!audioContext || audioContext.state === "closed") return false;
  try {
    if (audioContext.state !== "running") await audioContext.resume();
  } catch (error) {
    appendLog(`Web Audio resume failed: ${error.message}`);
  }
  updateAudioDiagnostics();
  return audioContext.state === "running";
}

function gainForVolume(volume) {
  return Math.max(0, Math.min(1, Math.pow(10, volume / 2000)));
}

function decodePcm(sound, bytes, byteOffset = 0) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let peak = 0;
  for (let offset = 0; offset + sound.bytesPerSample <= bytes.byteLength; offset += sound.bytesPerSample) {
    const sample = Math.floor((byteOffset + offset) / sound.bytesPerSample);
    const channel = sample % sound.channels;
    const frame = Math.floor(sample / sound.channels) % sound.frames;
    const value = sound.bitsPerSample === 8
      ? (bytes[offset] - 128) / 128
      : view.getInt16(offset, true) / 32768;
    sound.channelData[channel][frame] = value;
    peak = Math.max(peak, Math.abs(value));
  }
  return peak;
}

function disconnectSound(sound) {
  sound.playing = false;
  if (sound.processor) sound.processor.onaudioprocess = null;
  try { sound.source?.stop(); } catch {}
  try { sound.node?.disconnect(); } catch {}
  try { sound.gain?.disconnect(); } catch {}
  try { sound.panner?.disconnect(); } catch {}
}

function connectSound(sound) {
  sound.gain = audioContext.createGain();
  sound.gain.gain.value = gainForVolume(sound.volume);
  sound.node.connect(sound.gain);
  if (audioContext.createStereoPanner) {
    sound.panner = audioContext.createStereoPanner();
    sound.panner.pan.value = Math.max(-1, Math.min(1, sound.pan / 10000));
    sound.gain.connect(sound.panner).connect(audioContext.destination);
  } else {
    sound.gain.connect(audioContext.destination);
  }
}

function playSound(data) {
  if (!audioContext || audioContext.state === "closed") return;
  void resumeAudio();
  const format = data.format;
  const channels = Math.max(1, Math.min(2, format.channels));
  const bytes = new Uint8Array(data.bytes);
  const bytesPerSample = Math.max(1, format.bitsPerSample >> 3);
  const blockAlign = Math.max(bytesPerSample * channels, format.blockAlign);
  const frames = Math.floor(bytes.byteLength / blockAlign);
  if (!frames || (format.bitsPerSample !== 8 && format.bitsPerSample !== 16)) return;
  const previous = playingSounds.get(data.id);
  if (previous) disconnectSound(previous);
  const sound = {
    id: data.id,
    channels,
    frames,
    bytesPerSample,
    blockAlign,
    bitsPerSample: format.bitsPerSample,
    frequency: data.frequency || format.samplesPerSec,
    volume: data.volume,
    pan: data.pan,
    loop: data.loop,
    playing: true,
    cursor: (data.cursor || 0) / blockAlign,
    channelData: Array.from({ length: channels }, () => new Float32Array(frames)),
  };
  const peak = decodePcm(sound, bytes);
  if (sound.loop) {
    sound.processor = audioContext.createScriptProcessor(2048, 0, channels);
    sound.node = sound.processor;
    sound.processor.onaudioprocess = (event) => {
      const length = event.outputBuffer.length;
      const step = Math.max(1, sound.frequency) / audioContext.sampleRate;
      const outputs = Array.from(
        { length: sound.channels },
        (_value, channel) => event.outputBuffer.getChannelData(channel),
      );
      for (let index = 0; index < length; index++) {
        const frame = Math.floor(sound.cursor) % sound.frames;
        for (let channel = 0; channel < sound.channels; channel++) {
          outputs[channel][index] = sound.channelData[channel][frame];
        }
        sound.cursor += step;
        if (sound.cursor >= sound.frames) sound.cursor %= sound.frames;
      }
    };
  } else {
    const buffer = audioContext.createBuffer(channels, frames, Math.max(8000, sound.frequency));
    for (let channel = 0; channel < channels; channel++) {
      buffer.copyToChannel(sound.channelData[channel], channel);
    }
    sound.source = audioContext.createBufferSource();
    sound.source.buffer = buffer;
    sound.node = sound.source;
    sound.source.addEventListener("ended", () => {
      if (playingSounds.get(data.id) === sound) {
        playingSounds.delete(data.id);
        disconnectSound(sound);
        updateAudioDiagnostics();
      }
    });
  }
  connectSound(sound);
  playingSounds.set(data.id, sound);
  sound.source?.start(
    0,
    Math.min(sound.cursor / Math.max(1, sound.frequency), sound.frames / Math.max(1, sound.frequency)),
  );
  audioDiagnostics.playCount++;
  if (peak > 0) audioDiagnostics.nonSilentPlayCount++;
  audioDiagnostics.lastSound = {
    id: data.id,
    channels,
    frames,
    sampleRate: sound.frequency,
    bitsPerSample: format.bitsPerSample,
    volume: data.volume,
    peak,
  };
  updateAudioDiagnostics();
  if (audioDiagnostics.playCount === 1) {
    appendLog(
      `Web Audio PCM: ${channels}ch ${sound.frequency}Hz ${format.bitsPerSample}-bit, `
        + `${frames} frames, peak=${peak.toFixed(3)}, context=${audioContext.state}`,
    );
  }
}

function writeSound(data) {
  const sound = playingSounds.get(data.id);
  if (!sound?.loop) return;
  decodePcm(sound, new Uint8Array(data.bytes), data.offset);
  audioDiagnostics.writeCount++;
  updateAudioDiagnostics();
}

function controlSound(data) {
  const sound = playingSounds.get(data.id);
  if (!sound) return;
  if (data.volume !== undefined) {
    sound.volume = data.volume;
    sound.gain.gain.value = gainForVolume(data.volume);
  }
  if (data.pan !== undefined && sound.panner) {
    sound.pan = data.pan;
    sound.panner.pan.value = Math.max(-1, Math.min(1, data.pan / 10000));
  }
  if (data.frequency !== undefined) sound.frequency = data.frequency;
  if (data.cursor !== undefined) sound.cursor = data.cursor / sound.blockAlign;
}

function stopSound(id) {
  const sound = playingSounds.get(id);
  if (!sound) return;
  playingSounds.delete(id);
  disconnectSound(sound);
  updateAudioDiagnostics();
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
  void resumeAudio();
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
  void resumeAudio();
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

startButton.addEventListener("click", async () => {
  if (worker) return;
  const parameters = new URLSearchParams(location.search);
  const soundEnabled = parameters.get("sound") === "1";
  const Audio = window.AudioContext || window.webkitAudioContext;
  if (soundEnabled && Audio) {
    audioContext = new Audio({ latencyHint: "interactive" });
    audioContext.addEventListener("statechange", updateAudioDiagnostics);
    const running = await resumeAudio();
    appendLog(
      `Web Audio ${running ? "ready" : "not running"}: state=${audioContext.state}, `
        + `sampleRate=${audioContext.sampleRate}`,
    );
  } else if (soundEnabled) {
    updateAudioDiagnostics();
    appendLog("Web Audio is unavailable in this browser");
  } else {
    audioDiagnostics.state = "disabled";
    globalThis.d2Audio = { ...audioDiagnostics, activeSources: 0 };
    appendLog("Audio disabled (use ?sound=1 to enable)");
  }
  worker = new Worker("/game-worker.mjs", { type: "module" });
  globalThis.d2Worker = worker;
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
    } else if (data.type === "audio-write") {
      writeSound(data);
    } else if (data.type === "audio-control") {
      controlSound(data);
    } else if (data.type === "audio-stop") {
      stopSound(data.id);
    } else if (data.type === "inspect") {
      globalThis.d2Inspect = data.snapshot;
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
  const diagnostics = parameters.get("diagnostics") === "1";
  const renderer = parameters.get("renderer") === "glide" ? "glide" : "gdi";
  worker.postMessage({
    type: "start",
    canvas: surface,
    demo: demoToggle.checked,
    diagnostics,
    renderer,
    soundEnabled,
  }, [surface]);
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
