use crate::protocol::InputEvent;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

const SCHEMA_VERSION: u32 = 2;
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Fingerprint {
    wasm_fnv1a64: String,
    manifest_fnv1a64: String,
    source_images_fnv1a64: String,
    game_data_fnv1a64: String,
    save_state_fnv1a64: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JournalLine {
    Header {
        schema_version: u32,
        fingerprint: Fingerprint,
    },
    Input {
        presentation: u64,
        sequence: u64,
        event: InputEvent,
    },
    Frame {
        presentation: u64,
        virtual_time: u32,
        width: u32,
        height: u32,
        framebuffer_fnv1a64: String,
    },
}

#[derive(Clone, Debug)]
struct ReplayInput {
    presentation: u64,
    sequence: u64,
    event: InputEvent,
}

#[derive(Clone, Debug)]
struct ReplayFrame {
    presentation: u64,
    virtual_time: u32,
    width: u32,
    height: u32,
    framebuffer_fnv1a64: String,
}

enum Journal {
    Disabled,
    Record {
        writer: BufWriter<File>,
        sequence: u64,
    },
    Replay {
        events: VecDeque<ReplayInput>,
        frames: VecDeque<ReplayFrame>,
    },
}

pub struct GameplaySession {
    journal: Journal,
    save_root: Option<PathBuf>,
    cleanup_root: Option<PathBuf>,
    description: String,
}

impl GameplaySession {
    pub fn prepare(
        record: Option<&Path>,
        replay: Option<&Path>,
        wasm: &Path,
        manifest: &Path,
        source_dir: &Path,
        host_root: &Path,
    ) -> Result<Self> {
        if record.is_some() && replay.is_some() {
            bail!("--record and --replay are mutually exclusive");
        }
        let wasm_hash = hash_file(wasm)?;
        let manifest_hash = hash_file(manifest)?;
        let source_images_hash = hash_filtered_tree(source_dir, is_source_image)?;
        let game_data_hash = hash_filtered_tree(host_root, is_game_data)?;
        if let Some(path) = record {
            let state_root = state_path(path);
            if state_root.exists() {
                fs::remove_dir_all(&state_root).with_context(|| {
                    format!("removing old replay state {}", state_root.display())
                })?;
            }
            copy_tree(&find_save_dir(host_root), &state_root)?;
            let fingerprint = Fingerprint {
                wasm_fnv1a64: wasm_hash,
                manifest_fnv1a64: manifest_hash,
                source_images_fnv1a64: source_images_hash,
                game_data_fnv1a64: game_data_hash,
                save_state_fnv1a64: hash_tree(&state_root, false)?,
            };
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)?;
            }
            let file = File::create(path)
                .with_context(|| format!("creating gameplay journal {}", path.display()))?;
            let mut writer = BufWriter::new(file);
            write_line(
                &mut writer,
                &JournalLine::Header {
                    schema_version: SCHEMA_VERSION,
                    fingerprint,
                },
            )?;
            return Ok(Self {
                journal: Journal::Record {
                    writer,
                    sequence: 0,
                },
                save_root: None,
                cleanup_root: None,
                description: format!("Recording deterministic gameplay to {}", path.display()),
            });
        }
        if let Some(path) = replay {
            let (expected, events, frames) = read_journal(path)?;
            let state_root = state_path(path);
            let actual = Fingerprint {
                wasm_fnv1a64: wasm_hash,
                manifest_fnv1a64: manifest_hash,
                source_images_fnv1a64: source_images_hash,
                game_data_fnv1a64: game_data_hash,
                save_state_fnv1a64: hash_tree(&state_root, false)?,
            };
            validate_fingerprint(&expected, &actual)?;
            let replay_root =
                std::env::temp_dir().join(format!("d2-egui-replay-{}", std::process::id()));
            if replay_root.exists() {
                fs::remove_dir_all(&replay_root)?;
            }
            copy_tree(&state_root, &replay_root)?;
            return Ok(Self {
                journal: Journal::Replay { events, frames },
                save_root: Some(replay_root.clone()),
                cleanup_root: Some(replay_root),
                description: format!("Replaying deterministic gameplay from {}", path.display()),
            });
        }
        Ok(Self {
            journal: Journal::Disabled,
            save_root: None,
            cleanup_root: None,
            description: String::from("Gameplay recording disabled"),
        })
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn is_replay(&self) -> bool {
        matches!(self.journal, Journal::Replay { .. })
    }

    pub fn save_root(&self) -> Option<&Path> {
        self.save_root.as_deref()
    }

    pub fn process_inputs(
        &mut self,
        presentation: u64,
        live: Vec<InputEvent>,
    ) -> Result<Vec<InputEvent>> {
        match &mut self.journal {
            Journal::Disabled => Ok(live),
            Journal::Record { writer, sequence } => {
                for event in &live {
                    write_line(
                        writer,
                        &JournalLine::Input {
                            presentation,
                            sequence: *sequence,
                            event: event.clone(),
                        },
                    )?;
                    *sequence += 1;
                }
                Ok(live)
            }
            Journal::Replay { events, .. } => {
                if live.iter().any(|event| matches!(event, InputEvent::Quit)) {
                    return Ok(vec![InputEvent::Quit]);
                }
                if let Some(event) = events.front()
                    && event.presentation < presentation
                {
                    bail!(
                        "replay diverged: input sequence {} was due at presentation {}, current presentation is {}",
                        event.sequence,
                        event.presentation,
                        presentation
                    );
                }
                let mut output = Vec::new();
                while events
                    .front()
                    .is_some_and(|event| event.presentation == presentation)
                {
                    output.push(events.pop_front().expect("front event exists").event);
                }
                Ok(output)
            }
        }
    }

    pub fn checkpoint(
        &mut self,
        presentation: u64,
        virtual_time: u32,
        width: usize,
        height: usize,
        framebuffer: &[u8],
    ) -> Result<()> {
        let framebuffer_fnv1a64 = hash_bytes(framebuffer);
        match &mut self.journal {
            Journal::Disabled => Ok(()),
            Journal::Record { writer, .. } => write_line(
                writer,
                &JournalLine::Frame {
                    presentation,
                    virtual_time,
                    width: width as u32,
                    height: height as u32,
                    framebuffer_fnv1a64,
                },
            ),
            Journal::Replay { frames, .. } => {
                let expected = frames
                    .pop_front()
                    .context("replay produced more frames than the recording")?;
                if expected.presentation != presentation {
                    bail!(
                        "replay frame sequence diverged: expected presentation {}, got {}",
                        expected.presentation,
                        presentation
                    );
                }
                if expected.virtual_time != virtual_time {
                    bail!(
                        "replay clock diverged at presentation {presentation}: expected {}, got {}",
                        expected.virtual_time,
                        virtual_time
                    );
                }
                if expected.width != width as u32 || expected.height != height as u32 {
                    bail!(
                        "replay frame size diverged at presentation {presentation}: expected {}x{}, got {width}x{height}",
                        expected.width,
                        expected.height
                    );
                }
                if expected.framebuffer_fnv1a64 != framebuffer_fnv1a64 {
                    bail!(
                        "replay framebuffer diverged at presentation {presentation}: expected {}, got {}",
                        expected.framebuffer_fnv1a64,
                        framebuffer_fnv1a64
                    );
                }
                Ok(())
            }
        }
    }
}

impl Drop for GameplaySession {
    fn drop(&mut self) {
        if let Some(path) = self.cleanup_root.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

fn write_line(writer: &mut BufWriter<File>, line: &JournalLine) -> Result<()> {
    serde_json::to_writer(&mut *writer, line)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn read_journal(
    path: &Path,
) -> Result<(Fingerprint, VecDeque<ReplayInput>, VecDeque<ReplayFrame>)> {
    let file =
        File::open(path).with_context(|| format!("opening gameplay journal {}", path.display()))?;
    let mut lines = BufReader::new(file).lines();
    let first = lines.next().context("gameplay journal is empty")??;
    let JournalLine::Header {
        schema_version,
        fingerprint,
    } = serde_json::from_str(&first)?
    else {
        bail!("gameplay journal does not start with a header");
    };
    if schema_version != SCHEMA_VERSION {
        bail!("unsupported gameplay journal schema {schema_version}; expected {SCHEMA_VERSION}");
    }
    let mut events = VecDeque::new();
    let mut frames = VecDeque::new();
    let mut previous_input = None;
    let mut previous_frame = None;
    for line in lines {
        match serde_json::from_str(&line?)? {
            JournalLine::Header { .. } => bail!("gameplay journal contains a second header"),
            JournalLine::Input {
                presentation,
                sequence,
                event,
            } => {
                if previous_input.is_some_and(|value| sequence <= value) {
                    bail!("gameplay journal input sequence is not strictly increasing");
                }
                previous_input = Some(sequence);
                events.push_back(ReplayInput {
                    presentation,
                    sequence,
                    event,
                });
            }
            JournalLine::Frame {
                presentation,
                virtual_time,
                width,
                height,
                framebuffer_fnv1a64,
            } => {
                if previous_frame.is_some_and(|value| presentation <= value) {
                    bail!("gameplay journal frame presentations are not strictly increasing");
                }
                previous_frame = Some(presentation);
                frames.push_back(ReplayFrame {
                    presentation,
                    virtual_time,
                    width,
                    height,
                    framebuffer_fnv1a64,
                });
            }
        }
    }
    Ok((fingerprint, events, frames))
}

fn validate_fingerprint(expected: &Fingerprint, actual: &Fingerprint) -> Result<()> {
    if expected.wasm_fnv1a64 != actual.wasm_fnv1a64 {
        bail!("replay WASM hash does not match the recorded artifact");
    }
    if expected.manifest_fnv1a64 != actual.manifest_fnv1a64 {
        bail!("replay manifest hash does not match the recorded manifest");
    }
    if expected.source_images_fnv1a64 != actual.source_images_fnv1a64 {
        bail!("replay source-image hash does not match the recorded PE images");
    }
    if expected.game_data_fnv1a64 != actual.game_data_fnv1a64 {
        bail!("replay game-data hash does not match the recorded runtime files");
    }
    if expected.save_state_fnv1a64 != actual.save_state_fnv1a64 {
        bail!("replay save-state snapshot is missing or does not match the journal");
    }
    Ok(())
}

fn state_path(journal: &Path) -> PathBuf {
    PathBuf::from(format!("{}.state", journal.display()))
}

fn find_save_dir(host_root: &Path) -> PathBuf {
    fs::read_dir(host_root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .find(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .eq_ignore_ascii_case("save")
        })
        .map(|entry| entry.path())
        .unwrap_or_else(|| host_root.join("Save"))
}

fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    fs::create_dir_all(destination)?;
    if !source.exists() {
        return Ok(());
    }
    let mut entries = fs::read_dir(source)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let target = destination.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else if entry.file_type()?.is_file() {
            fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String> {
    let mut hash = FNV_OFFSET;
    hash_file_into(path, &mut hash)?;
    Ok(format!("{hash:016x}"))
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hash = FNV_OFFSET;
    update_hash(&mut hash, bytes);
    format!("{hash:016x}")
}

fn is_source_image(path: &Path) -> bool {
    path.extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("exe"))
}

fn is_game_data(path: &Path) -> bool {
    path.extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("mpq") || extension.eq_ignore_ascii_case("lng")
    })
}

fn hash_filtered_tree(path: &Path, include: fn(&Path) -> bool) -> Result<String> {
    let mut hash = FNV_OFFSET;
    hash_filtered_tree_into(path, path, include, &mut hash)?;
    Ok(format!("{hash:016x}"))
}

fn hash_filtered_tree_into(
    root: &Path,
    path: &Path,
    include: fn(&Path) -> bool,
    hash: &mut u64,
) -> Result<()> {
    if !path.exists() {
        update_hash(hash, b"<missing>");
        return Ok(());
    }
    let mut entries = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if entry.file_type()?.is_dir() {
            hash_filtered_tree_into(root, &entry.path(), include, hash)?;
        } else if entry.file_type()?.is_file() && include(&entry.path()) {
            let relative = entry
                .path()
                .strip_prefix(root)?
                .to_string_lossy()
                .into_owned();
            update_hash(hash, relative.as_bytes());
            update_hash(hash, b"F");
            hash_file_into(&entry.path(), hash)?;
        }
    }
    Ok(())
}

fn hash_tree(path: &Path, exclude_save: bool) -> Result<String> {
    let mut hash = FNV_OFFSET;
    hash_tree_into(path, path, exclude_save, &mut hash)?;
    Ok(format!("{hash:016x}"))
}

fn hash_tree_into(root: &Path, path: &Path, exclude_save: bool, hash: &mut u64) -> Result<()> {
    if !path.exists() {
        update_hash(hash, b"<missing>");
        return Ok(());
    }
    let mut entries = fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if exclude_save
            && entry.path().parent() == Some(root)
            && entry
                .file_name()
                .to_string_lossy()
                .eq_ignore_ascii_case("save")
        {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)?
            .to_string_lossy()
            .into_owned();
        update_hash(hash, relative.as_bytes());
        if entry.file_type()?.is_dir() {
            update_hash(hash, b"D");
            hash_tree_into(root, &entry.path(), false, hash)?;
        } else if entry.file_type()?.is_file() {
            update_hash(hash, b"F");
            hash_file_into(&entry.path(), hash)?;
        }
    }
    Ok(())
}

fn hash_file_into(path: &Path, hash: &mut u64) -> Result<()> {
    let mut file = File::open(path).with_context(|| format!("hashing {}", path.display()))?;
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        update_hash(hash, &buffer[..count]);
    }
    Ok(())
}

fn update_hash(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(FNV_PRIME);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_replays_at_the_same_presentation() -> Result<()> {
        let root = std::env::temp_dir().join(format!("d2-gameplay-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("game/Save"))?;
        fs::write(root.join("game/data.mpq"), b"data")?;
        fs::write(root.join("game/D2000101.txt"), b"runtime log before")?;
        fs::write(root.join("game/Save/Hero.d2s"), b"save")?;
        fs::create_dir_all(root.join("images"))?;
        fs::write(root.join("images/game.exe"), b"image")?;
        fs::write(root.join("linked.wasm"), b"wasm")?;
        fs::write(root.join("manifest.json"), b"manifest")?;
        let journal = root.join("run.jsonl");
        {
            let mut session = GameplaySession::prepare(
                Some(&journal),
                None,
                &root.join("linked.wasm"),
                &root.join("manifest.json"),
                &root.join("images"),
                &root.join("game"),
            )?;
            let event = InputEvent::MouseButton {
                x: 10,
                y: 20,
                down: true,
            };
            assert_eq!(session.process_inputs(7, vec![event.clone()])?, vec![event]);
            session.checkpoint(7, 112, 1, 1, &[1, 2, 3, 0xff])?;
        }
        fs::write(root.join("game/D2000101.txt"), b"runtime log after")?;
        let mut replay = GameplaySession::prepare(
            None,
            Some(&journal),
            &root.join("linked.wasm"),
            &root.join("manifest.json"),
            &root.join("images"),
            &root.join("game"),
        )?;
        assert!(replay.process_inputs(6, Vec::new())?.is_empty());
        assert_eq!(
            replay.process_inputs(7, Vec::new())?,
            vec![InputEvent::MouseButton {
                x: 10,
                y: 20,
                down: true,
            }]
        );
        replay.checkpoint(7, 112, 1, 1, &[1, 2, 3, 0xff])?;
        assert!(
            replay
                .save_root()
                .expect("replay save root")
                .join("Hero.d2s")
                .exists()
        );
        drop(replay);

        let mut divergent = GameplaySession::prepare(
            None,
            Some(&journal),
            &root.join("linked.wasm"),
            &root.join("manifest.json"),
            &root.join("images"),
            &root.join("game"),
        )?;
        let error = divergent
            .checkpoint(7, 112, 1, 1, &[4, 3, 2, 0xff])
            .expect_err("different framebuffer must be rejected");
        assert!(error.to_string().contains("framebuffer diverged"));
        drop(divergent);
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
