import { fileURLToPath } from "node:url";
import { Win32Runtime } from "../runtime/win32.mjs";

const memory = new WebAssembly.Memory({ initial: 1 });
const runtime = new Win32Runtime({ hostRoot: fileURLToPath(new URL(".", import.meta.url)) });
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
const stack = 0x1000;
const view = () => new DataView(memory.buffer);
const setArgs = (...values) => values.forEach((value, index) => view().setUint32(stack + index * 4, value >>> 0, true));

if (kernel32.GetTickCount() !== 16 || winmm.timeGetTime() !== 32) throw new Error("virtual clock did not advance");
setArgs(100);
kernel32.Sleep(stack);
if (kernel32.GetTickCount() !== 148) throw new Error("Sleep did not advance virtual time");

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

console.log("direct Win32 runtime clock, formatting, cursor, time, and file adapters passed");
