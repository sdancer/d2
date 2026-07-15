use anyhow::{Context, Result};
use serde::Deserialize;
use std::{collections::HashMap, fs, path::Path};

#[derive(Clone, Debug, Deserialize)]
pub struct Manifest {
    pub entry_module: String,
    pub entry_va: u32,
    pub summary: Summary,
    pub modules: Vec<Module>,
    pub internal_bindings: Vec<InternalBinding>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Summary {
    pub highest_mapped_address: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Module {
    pub runtime_name: String,
    pub source: String,
    pub load_base: u32,
    pub entry_rva: u32,
    pub headers_size: u32,
    pub sections: Vec<Section>,
    #[serde(default)]
    pub relocation_delta: i64,
    #[serde(default)]
    pub relocation_entries: Vec<Relocation>,
    #[serde(default)]
    pub exports: Vec<Export>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Section {
    pub rva: u32,
    pub file_offset: u32,
    pub file_size: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Relocation {
    pub rva: u32,
    #[serde(rename = "type")]
    pub kind: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Export {
    pub rva: u32,
    pub name: Option<String>,
    pub ordinal: u32,
}

#[derive(Clone, Debug, Deserialize)]
pub struct InternalBinding {
    pub importer: String,
    pub iat_rva: u32,
    pub target_module: String,
    pub target_va: u32,
}

impl Manifest {
    pub fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("failed to read link manifest {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse link manifest {}", path.display()))
    }

    pub fn initialization_order(&self) -> Vec<&Module> {
        let modules = self
            .modules
            .iter()
            .map(|module| (module.runtime_name.to_ascii_lowercase(), module))
            .collect::<HashMap<_, _>>();
        let mut dependencies = HashMap::<String, Vec<String>>::new();
        for binding in &self.internal_bindings {
            let importer = binding.importer.to_ascii_lowercase();
            let target = binding.target_module.to_ascii_lowercase();
            if importer != target {
                dependencies.entry(importer).or_default().push(target);
            }
        }

        fn visit(
            name: &str,
            dependencies: &HashMap<String, Vec<String>>,
            visiting: &mut Vec<String>,
            visited: &mut Vec<String>,
            output: &mut Vec<String>,
            entry: &str,
        ) {
            if visited.iter().any(|item| item == name) || visiting.iter().any(|item| item == name) {
                return;
            }
            visiting.push(name.to_owned());
            for dependency in dependencies.get(name).into_iter().flatten() {
                visit(dependency, dependencies, visiting, visited, output, entry);
            }
            visiting.retain(|item| item != name);
            visited.push(name.to_owned());
            if name != entry {
                output.push(name.to_owned());
            }
        }

        let entry = self.entry_module.to_ascii_lowercase();
        let mut names = Vec::new();
        visit(
            &entry,
            &dependencies,
            &mut Vec::new(),
            &mut Vec::new(),
            &mut names,
            &entry,
        );
        names
            .into_iter()
            .filter_map(|name| modules.get(&name).copied())
            .collect()
    }
}
