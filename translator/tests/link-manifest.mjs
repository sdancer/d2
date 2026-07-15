import fs from "node:fs";
import path from "node:path";
import { mapLinkedImages } from "../runtime/load-pe.mjs";

const [manifestPath, sourceDir] = process.argv.slice(2);
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const pages = Math.ceil(manifest.summary.highest_mapped_address / 65536) + 1;
const memory = new WebAssembly.Memory({ initial: pages, maximum: 32768 });
mapLinkedImages(memory, manifest, (module) =>
  new Uint8Array(fs.readFileSync(path.join(sourceDir, module.source))),
);
const view = new DataView(memory.buffer);

for (const module of manifest.modules) {
  const peHeader = view.getUint32(module.load_base + 0x3c, true);
  const mappedBase = view.getUint32(module.load_base + peHeader + 52, true);
  if (mappedBase !== module.load_base) {
    throw new Error(`${module.runtime_name}: mapped PE header has base 0x${mappedBase.toString(16)}`);
  }
  const relocation = module.relocation_entries.find((entry) => entry.type === 3);
  if (relocation && module.relocation_delta) {
    const section = module.sections.find(
      (candidate) => relocation.rva >= candidate.rva && relocation.rva + 4 <= candidate.rva + candidate.file_size,
    );
    if (!section) throw new Error(`${module.runtime_name}: relocation is not file-backed`);
    const file = fs.readFileSync(path.join(sourceDir, module.source));
    const rawOffset = section.file_offset + relocation.rva - section.rva;
    const original = file.readUInt32LE(rawOffset);
    const expected = (original + module.relocation_delta) >>> 0;
    const actual = view.getUint32(module.load_base + relocation.rva, true);
    if (actual !== expected) {
      throw new Error(`${module.runtime_name}: HIGHLOW relocation mismatch`);
    }
  }
}

const modules = new Map(manifest.modules.map((module) => [module.runtime_name.toLowerCase(), module]));
for (const binding of manifest.internal_bindings) {
  const importer = modules.get(binding.importer.toLowerCase());
  const actual = view.getUint32(importer.load_base + binding.iat_rva, true);
  if (actual !== binding.target_va) {
    throw new Error(`${binding.importer}: IAT binding mismatch for ${binding.library}`);
  }
}

console.log(
  `linked ${manifest.modules.length} PEs, verified ${manifest.internal_bindings.length} internal IAT bindings`,
);

