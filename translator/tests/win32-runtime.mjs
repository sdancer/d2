import { fileURLToPath } from "node:url";
import { Win32Runtime } from "../runtime/win32.mjs";

const memory = new WebAssembly.Memory({ initial: 1 });
let now = 0;
const runtime = new Win32Runtime({ hostRoot: fileURLToPath(new URL(".", import.meta.url)), clock: () => now });
runtime.attach(memory);
const reservedStart = runtime.heapCursor + 0x100;
runtime.reserve(reservedStart, reservedStart + 0x100);
const allocationAfterReservation = runtime.alloc(0x180, 16);
if (allocationAfterReservation !== reservedStart + 0x100) {
  throw new Error("allocator did not skip a reserved memory range");
}
const imports = runtime.imports();
const kernel32 = imports["win32.kernel32.dll"];
const user32 = imports["win32.user32.dll"];
const winmm = imports["win32.winmm.dll"];
const gdi32 = imports["win32.gdi32.dll"];
const dsound = imports["win32.dsound.dll"];
const stack = 0x1000;
const view = () => new DataView(memory.buffer);
const setArgs = (...values) => values.forEach((value, index) => view().setUint32(stack + index * 4, value >>> 0, true));

if (kernel32.GetTickCount() !== 0 || winmm.timeGetTime() !== 0) throw new Error("clock reads must not advance time");
now = 16;
if (kernel32.GetTickCount() !== 16 || winmm.timeGetTime() !== 16) throw new Error("clock did not follow elapsed host time");
setArgs(100);
kernel32.Sleep(stack);
if (kernel32.GetTickCount() !== 116) throw new Error("Sleep did not advance virtual time");

const format = runtime.allocCString("value=%04d %s");
const word = runtime.allocCString("ok");
const output = runtime.alloc(64, 1);
setArgs(output, format, 42, word);
if (user32.wsprintfA(stack) !== 13 || runtime.readCString(output) !== "value=0042 ok") {
  throw new Error(`wsprintfA produced ${JSON.stringify(runtime.readCString(output))}`);
}

setArgs(1);
if (user32.ShowCursor(stack) !== 1) throw new Error("ShowCursor(TRUE) failed");
setArgs(0);
if (user32.ShowCursor(stack) !== 0) throw new Error("ShowCursor(FALSE) failed");

const systemTime = runtime.alloc(16, 2);
setArgs(systemTime);
kernel32.GetLocalTime(stack);
if (view().getUint16(systemTime, true) !== 2000) throw new Error("GetLocalTime epoch is not deterministic");

const filename = runtime.allocCString("smoke.s");
const fileBuffer = runtime.alloc(16, 1);
const bytesRead = runtime.alloc(4, 4);
setArgs(filename, 0x80000000, 1, 0, 3, 0, 0);
const file = kernel32.CreateFileA(stack);
if (file === 0xffffffff) throw new Error("CreateFileA did not open a host-root file");
setArgs(file, fileBuffer, 16, bytesRead, 0);
if (!kernel32.ReadFile(stack) || view().getUint32(bytesRead, true) !== 16) throw new Error("ReadFile failed");
setArgs(file);
kernel32.CloseHandle(stack);

runtime.activeWindow = 0x123;
runtime.enqueuePointer(0x0201, 321, 222, 1);
runtime.enqueueKey(0x49, true);
runtime.enqueueCharacter(0x69);
runtime.enqueueKey(0x49, false);
const inputMessages = runtime.messageQueue.map(({ hwnd, message, wParam }) => [hwnd, message, wParam]);
const expectedMessages = [
  [0x123, 0x0200, 0],
  [0x123, 0x0201, 1],
  [0x123, 0x0100, 0x49],
  [0x123, 0x0102, 0x69],
  [0x123, 0x0101, 0x49],
];
if (JSON.stringify(inputMessages) !== JSON.stringify(expectedMessages)) {
  throw new Error(`browser input messages differ: ${JSON.stringify(inputMessages)}`);
}

let presented;
runtime.onPresent = (bitmap, presentation, viewport) => { presented = { bitmap, presentation, viewport }; };
setArgs(runtime.activeWindow);
const screenDc = user32.GetDC(stack);
const sourceDc = gdi32.CreateCompatibleDC(stack);
setArgs(sourceDc, 640, 480);
const sourceBitmap = gdi32.CreateCompatibleBitmap(stack);
setArgs(sourceDc, sourceBitmap);
gdi32.SelectObject(stack);
setArgs(screenDc, 0, 0, 640, 480, sourceDc, 0, 0, 0x00cc0020);
gdi32.BitBlt(stack);
if (presented?.viewport.width !== 640 || presented?.viewport.height !== 480) {
  throw new Error(`active presentation size differs: ${JSON.stringify(presented?.viewport)}`);
}
runtime.enqueuePointer(0x0200, 700, 500);
if (runtime.cursorX !== 639 || runtime.cursorY !== 479) throw new Error("input was not clamped to the active presentation");

let audioEvent;
runtime.onAudio = (event) => { audioEvent = event; };
const directSoundOutput = runtime.alloc(4, 4);
setArgs(0, directSoundOutput, 0);
if (dsound["#1"](stack) !== 0) throw new Error("DirectSoundCreate failed");
const directSound = view().getUint32(directSoundOutput, true);
const waveFormat = runtime.alloc(18, 2);
view().setUint16(waveFormat, 1, true);
view().setUint16(waveFormat + 2, 1, true);
view().setUint32(waveFormat + 4, 8000, true);
view().setUint32(waveFormat + 8, 8000, true);
view().setUint16(waveFormat + 12, 1, true);
view().setUint16(waveFormat + 14, 8, true);
const descriptor = runtime.alloc(20, 4);
view().setUint32(descriptor, 20, true);
view().setUint32(descriptor + 8, 8, true);
view().setUint32(descriptor + 16, waveFormat, true);
const soundBufferOutput = runtime.alloc(4, 4);
setArgs(directSound, descriptor, soundBufferOutput, 0);
if (dsound.__dispatch(3, stack) !== 0) throw new Error("CreateSoundBuffer failed");
const soundBuffer = view().getUint32(soundBufferOutput, true);
const audioPointer = runtime.soundBuffers.get(soundBuffer).bytes;
new Uint8Array(memory.buffer, audioPointer, 8).set([128, 144, 160, 176, 160, 144, 128, 112]);
setArgs(soundBuffer, 0, 0, 0);
if (dsound.__dispatch(44, stack) !== 0 || audioEvent?.type !== "play" || audioEvent.bytes.length !== 8) {
  throw new Error("DirectSound PCM playback was not emitted");
}

console.log("direct Win32 runtime clock, viewport, audio, formatting, cursor, file, and browser input adapters passed");
