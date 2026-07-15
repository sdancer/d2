import fs from "node:fs";
import { mapPeImage } from "../runtime/load-pe.mjs";

const [wasmPath, reportPath, pePath] = process.argv.slice(2);
const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
const { instance } = await WebAssembly.instantiate(fs.readFileSync(wasmPath), {});
mapPeImage(instance.exports.memory, new Uint8Array(fs.readFileSync(pePath)), report.source);
const result = instance.exports.d2_run(report.root_pcs[0], 0x00f00000, 100);
if (result !== 42 || instance.exports.d2_last_status() !== 0) {
  throw new Error(`relocated translated PE returned ${result}`);
}
console.log(`relocated translated PE returned ${result}`);

