import fs from "node:fs";

export function mapPeImage(memory, peBytes, inventory) {
  const loadBase = inventory.load_base ?? inventory.image_base;
  const destination = new Uint8Array(memory.buffer);
  destination.set(
    peBytes.subarray(0, inventory.headers_size),
    loadBase,
  );
  for (const section of inventory.sections) {
    if (!section.file_size) continue;
    const source = peBytes.subarray(
      section.file_offset,
      section.file_offset + section.file_size,
    );
    destination.set(source, loadBase + section.rva);
  }

  const view = new DataView(memory.buffer);
  const delta = inventory.relocation_delta ?? 0;
  for (const relocation of inventory.relocation_entries ?? []) {
    if (relocation.type !== 3) {
      throw new Error(`unsupported PE relocation type ${relocation.type} in ${inventory.runtime_name}`);
    }
    const address = loadBase + relocation.rva;
    view.setUint32(address, (view.getUint32(address, true) + delta) >>> 0, true);
  }

  // Keep GetModuleHandle/PE-header consumers consistent with the relocated map.
  const peHeader = view.getUint32(loadBase + 0x3c, true);
  view.setUint32(loadBase + peHeader + 52, loadBase, true);
}

export function mapLinkedImages(memory, manifest, loadModuleBytes) {
  const modules = new Map();
  for (const module of manifest.modules) {
    mapPeImage(memory, loadModuleBytes(module), module);
    modules.set(module.runtime_name.toLowerCase(), module);
  }
  const view = new DataView(memory.buffer);
  for (const binding of manifest.internal_bindings) {
    const importer = modules.get(binding.importer.toLowerCase());
    if (!importer) throw new Error(`missing importer in link manifest: ${binding.importer}`);
    view.setUint32(importer.load_base + binding.iat_rva, binding.target_va, true);
  }
}

export function readPe(path) {
  return new Uint8Array(fs.readFileSync(path));
}
