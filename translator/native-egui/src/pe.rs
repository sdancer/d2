use crate::manifest::Manifest;
use anyhow::{Context, Result, bail};
use std::{fs, path::Path};

pub fn map_linked_images(memory: &mut [u8], manifest: &Manifest, source_dir: &Path) -> Result<()> {
    for module in &manifest.modules {
        let path = source_dir.join(&module.source);
        let pe = fs::read(&path)
            .with_context(|| format!("failed to read PE image {}", path.display()))?;
        let base = module.load_base as usize;
        copy(
            memory,
            base,
            &pe[..module.headers_size as usize],
            &module.runtime_name,
        )?;
        for section in &module.sections {
            if section.file_size == 0 {
                continue;
            }
            let start = section.file_offset as usize;
            let end = start + section.file_size as usize;
            let source = pe.get(start..end).with_context(|| {
                format!("section exceeds source image for {}", module.runtime_name)
            })?;
            copy(
                memory,
                base + section.rva as usize,
                source,
                &module.runtime_name,
            )?;
        }
        for relocation in &module.relocation_entries {
            if relocation.kind != 3 {
                bail!(
                    "unsupported PE relocation type {} in {}",
                    relocation.kind,
                    module.runtime_name
                );
            }
            let address = base + relocation.rva as usize;
            let value = read_u32(memory, address)?;
            write_u32(
                memory,
                address,
                value.wrapping_add(module.relocation_delta as u32),
            )?;
        }

        let pe_header = read_u32(memory, base + 0x3c)? as usize;
        write_u32(memory, base + pe_header + 52, module.load_base)?;
    }

    for binding in &manifest.internal_bindings {
        let importer = manifest
            .modules
            .iter()
            .find(|module| module.runtime_name.eq_ignore_ascii_case(&binding.importer))
            .with_context(|| format!("missing importer {}", binding.importer))?;
        write_u32(
            memory,
            importer.load_base as usize + binding.iat_rva as usize,
            binding.target_va,
        )?;
    }
    Ok(())
}

fn copy(memory: &mut [u8], address: usize, source: &[u8], module: &str) -> Result<()> {
    let destination = memory
        .get_mut(address..address + source.len())
        .with_context(|| format!("mapped image exceeds Wasm memory for {module}"))?;
    destination.copy_from_slice(source);
    Ok(())
}

fn read_u32(memory: &[u8], address: usize) -> Result<u32> {
    let bytes: [u8; 4] = memory
        .get(address..address + 4)
        .context("read outside Wasm memory")?
        .try_into()
        .expect("four-byte range");
    Ok(u32::from_le_bytes(bytes))
}

fn write_u32(memory: &mut [u8], address: usize, value: u32) -> Result<()> {
    memory
        .get_mut(address..address + 4)
        .context("write outside Wasm memory")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}
