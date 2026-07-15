use crate::{
    gameplay::GameplaySession,
    manifest::Manifest,
    pe::map_linked_images,
    protocol::{HostEvent, InputEvent},
    runtime::{DispatchResult, Runtime, ThreadRun, WaitRequest},
};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashSet,
    fs,
    path::PathBuf,
    sync::mpsc::{Receiver, SyncSender},
};
use wasmtime::{
    Caller, Engine, Error as WasmtimeError, Extern, ExternType, Linker, Memory, Module, Store, Val,
};

const STACK_TOP: u32 = 0x1000_0000;
const FS_BASE: u32 = 0x0070_0000;
const FUEL_PER_ROUND: u32 = 1_000_000;
const MEMORY_ARENA_END: usize = 0x2000_0000;

#[derive(Clone, Debug)]
pub struct RunnerOptions {
    pub wasm: PathBuf,
    pub manifest: PathBuf,
    pub source_dir: PathBuf,
    pub host_root: PathBuf,
    pub record: Option<PathBuf>,
    pub replay: Option<PathBuf>,
}

impl RunnerOptions {
    pub fn from_args() -> Result<Self> {
        let mut options = Self {
            wasm: PathBuf::from("build/diablo-linked-gameplay/linked.wasm"),
            manifest: PathBuf::from("build/diablo-link-compact.json"),
            source_dir: PathBuf::from("../extracted"),
            host_root: PathBuf::from("build/runtime-files/diablo2"),
            record: None,
            replay: None,
        };
        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            let value = arguments
                .next()
                .with_context(|| format!("missing value after {argument}"))?;
            match argument.as_str() {
                "--wasm" => options.wasm = value.into(),
                "--manifest" => options.manifest = value.into(),
                "--source-dir" => options.source_dir = value.into(),
                "--host-root" => options.host_root = value.into(),
                "--record" => options.record = Some(value.into()),
                "--replay" => options.replay = Some(value.into()),
                _ => bail!("unknown argument {argument}"),
            }
        }
        if options.record.is_some() && options.replay.is_some() {
            bail!("--record and --replay are mutually exclusive");
        }
        Ok(options)
    }
}

struct HostState {
    runtime: Runtime,
}

pub fn run(
    options: RunnerOptions,
    event_tx: SyncSender<HostEvent>,
    input_rx: Receiver<InputEvent>,
) -> Result<()> {
    send(
        &event_tx,
        HostEvent::Status(String::from("Compiling translated WASM…")),
    );
    let manifest = Manifest::read(&options.manifest)?;
    let gameplay = GameplaySession::prepare(
        options.record.as_deref(),
        options.replay.as_deref(),
        &options.wasm,
        &options.manifest,
        &options.source_dir,
        &options.host_root,
    )?;
    send(&event_tx, HostEvent::Log(gameplay.description().to_owned()));
    let engine = Engine::default();
    let module = load_module(&engine, &options.wasm, &event_tx)?;
    let heap_base = manifest
        .summary
        .highest_mapped_address
        .saturating_add(0xffff)
        & !0xffff;
    let mut runtime = Runtime::new(
        heap_base,
        options.host_root.clone(),
        event_tx.clone(),
        input_rx,
        gameplay,
    );
    runtime.reserve(STACK_TOP - 0x0010_0000, STACK_TOP + 0x0001_0000)?;
    runtime.register_manifest(&manifest);
    let mut store = Store::new(&engine, HostState { runtime });
    let mut linker = Linker::new(&engine);
    register_imports(&module, &mut linker)?;

    send(
        &event_tx,
        HostEvent::Status(String::from("Instantiating native host…")),
    );
    let instance = wt(linker.instantiate(&mut store, &module))?;
    let memory = instance
        .get_memory(&mut store, "memory")
        .context("translated module does not export memory")?;
    ensure_memory(&memory, &mut store, MEMORY_ARENA_END)?;
    map_linked_images(memory.data_mut(&mut store), &manifest, &options.source_dir)?;
    write_u32(memory.data_mut(&mut store), FS_BASE, u32::MAX)?;

    let set_fs_base = wt(instance.get_typed_func::<u32, ()>(&mut store, "d2_set_fs_base"))?;
    wt(set_fs_base.call(&mut store, FS_BASE))?;
    let run = wt(instance.get_typed_func::<(u32, u32, u32), u32>(&mut store, "d2_run"))?;
    let last_status = wt(instance.get_typed_func::<(), u32>(&mut store, "d2_last_status"))?;

    send(
        &event_tx,
        HostEvent::Status(String::from("Initializing Diablo DLLs…")),
    );
    for module in manifest.initialization_order() {
        if module.entry_rva == 0 {
            continue;
        }
        {
            let bytes = memory.data_mut(&mut store);
            write_u32(bytes, STACK_TOP, module.load_base)?;
            write_u32(bytes, STACK_TOP + 4, 1)?;
            write_u32(bytes, STACK_TOP + 8, 1)?;
        }
        let address = module.load_base.wrapping_add(module.entry_rva);
        let result = wt(run.call(&mut store, (address, STACK_TOP, FUEL_PER_ROUND)))?;
        let status = wt(last_status.call(&mut store, ()))?;
        send(
            &event_tx,
            HostEvent::Log(format!(
                "{} initialization: result={result}, status={status}",
                module.runtime_name
            )),
        );
        if result == 0 || status != 0 {
            bail!(
                "{} initialization failed: result={result}, status={status}",
                module.runtime_name
            );
        }
    }

    let context = {
        let (bytes, state) = memory.data_and_store_mut(&mut store);
        state.runtime.alloc(bytes, 256, 8)?
    };
    let run_context =
        wt(instance.get_typed_func::<(u32, u32, u32, u32), u32>(&mut store, "d2_run_context"))?;
    let context_status = wt(instance.get_typed_func::<u32, u32>(&mut store, "d2_context_status"))?;
    let context_finished =
        wt(instance.get_typed_func::<u32, u32>(&mut store, "d2_context_finished"))?;
    let watch_pc = environment_u32("D2_WATCH_PC")?;
    let count_pc = environment_u32("D2_COUNT_PC")?;
    let count_hits = instance
        .get_typed_func::<(), u32>(&mut store, "d2_count_hits")
        .ok();
    if let Some(value) = watch_pc {
        let set_watch_pc = wt(instance.get_typed_func::<u32, ()>(&mut store, "d2_set_watch_pc"))?;
        wt(set_watch_pc.call(&mut store, value))?;
        if let Some(skip) = environment_u32("D2_WATCH_SKIP")? {
            let set_watch_skip =
                wt(instance.get_typed_func::<u32, ()>(&mut store, "d2_set_watch_skip"))?;
            wt(set_watch_skip.call(&mut store, skip))?;
        }
        send(
            &event_tx,
            HostEvent::Log(format!("Watching translated PC {value:#010x}")),
        );
    }
    if let Some(value) = count_pc {
        let set_count_pc = wt(instance.get_typed_func::<u32, ()>(&mut store, "d2_set_count_pc"))?;
        wt(set_count_pc.call(&mut store, value))?;
        send(
            &event_tx,
            HostEvent::Log(format!("Counting translated PC {value:#010x}")),
        );
    }
    send(
        &event_tx,
        HostEvent::Status(String::from("Running — click the game surface to interact")),
    );

    let mut rounds = 0u64;
    let mut reported_watch_contexts = HashSet::new();
    loop {
        let result = wt(run_context.call(
            &mut store,
            (context, manifest.entry_va, STACK_TOP, FUEL_PER_ROUND),
        ))?;
        rounds += 1;
        let status = wt(context_status.call(&mut store, context))?;
        let finished = wt(context_finished.call(&mut store, context))? != 0;
        if watch_pc.is_some() {
            let mut contexts = vec![(1, context)];
            contexts.extend(store.data().runtime.thread_contexts());
            let bytes = memory.data(&store);
            for (thread, watched_context) in contexts {
                if reported_watch_contexts.contains(&watched_context) {
                    continue;
                }
                if let Some(report) = context_watch_report(bytes, thread, watched_context) {
                    eprintln!("{report}");
                    send(&event_tx, HostEvent::Log(report));
                    reported_watch_contexts.insert(watched_context);
                }
            }
        }
        if rounds % 10 == 0 {
            send(
                &event_tx,
                HostEvent::Status(format!(
                    "Running — round {rounds}, result={result:#x}, status={status}"
                )),
            );
        }
        if store.data().runtime.quit_requested() {
            break;
        }
        if finished || status != 1 {
            let bytes = memory.data(&store);
            let next_pc = read_u32(bytes, context + 12).unwrap_or(0);
            let last_pc = read_u32(bytes, context + 16).unwrap_or(0);
            let previous_pc = read_u32(bytes, context + 20).unwrap_or(0);
            let esp = read_u32(bytes, context + 92).unwrap_or(0);
            let stack = (0..12)
                .map(|index| read_u32(bytes, esp.wrapping_sub(32) + index * 4).unwrap_or(0))
                .map(|value| format!("{value:08x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let unknown_apis = store.data().runtime.unknown_api_summary();
            if let (Some(address), Some(counter)) = (count_pc, count_hits.as_ref()) {
                let hits = wt(counter.call(&mut store, ()))?;
                let report = format!("Translated PC {address:#010x} executed {hits} times");
                eprintln!("{report}");
                send(&event_tx, HostEvent::Log(report));
            }
            send(
                &event_tx,
                HostEvent::Log(format!(
                    "Stopped context: esp={esp:#010x}, stack[-32..+16]={stack}"
                )),
            );
            send(&event_tx, HostEvent::Log(unknown_apis));
            let stopped = format!(
                "Guest stopped after {rounds} rounds: result={result:#x}, status={status}, \
                 finished={finished}, next={next_pc:#010x}, last={last_pc:#010x}, \
                 previous={previous_pc:#010x}"
            );
            eprintln!("{stopped}");
            send(&event_tx, HostEvent::Stopped(stopped));
            break;
        }
    }
    Ok(())
}

fn environment_u32(name: &str) -> Result<Option<u32>> {
    let Ok(value) = std::env::var(name) else {
        return Ok(None);
    };
    let value = value.trim();
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16)
    } else {
        value.parse()
    };
    Ok(Some(parsed.with_context(|| {
        format!("invalid {name} value {value:?}")
    })?))
}

fn context_watch_report(memory: &[u8], thread: u32, context: u32) -> Option<String> {
    if read_u32(memory, context + 24).ok()? == 0 {
        return None;
    }
    let names = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
    let registers = (0..8)
        .map(|index| read_u32(memory, context + 28 + index * 4).unwrap_or(0))
        .collect::<Vec<_>>();
    let register_text = names
        .iter()
        .zip(&registers)
        .map(|(name, value)| format!("{name}={value:#010x}"))
        .collect::<Vec<_>>()
        .join(" ");
    let eax = registers[0];
    let esp = registers[7];
    let signed = |value: u32| value as i32;
    let object = [-0x20i32, -0x1c, -0x18, -4, 0, 4]
        .into_iter()
        .map(|offset| {
            let address = eax.wrapping_add(offset as u32);
            let value = read_u32(memory, address).unwrap_or(0);
            format!("[eax{offset:+#x}]={value:#010x}({})", signed(value))
        })
        .collect::<Vec<_>>()
        .join(" ");
    let arguments = [0x88u32, 0x8c]
        .into_iter()
        .map(|offset| {
            let value = read_u32(memory, esp.wrapping_add(offset)).unwrap_or(0);
            format!("[esp+{offset:#x}]={value:#010x}({})", signed(value))
        })
        .collect::<Vec<_>>()
        .join(" ");
    Some(format!(
        "Translated watch hit: thread={thread:#x}, context={context:#010x}\n  {register_text}\n  {object}\n  {arguments}"
    ))
}

fn load_module(
    engine: &Engine,
    wasm: &PathBuf,
    event_tx: &SyncSender<HostEvent>,
) -> Result<Module> {
    if let Ok(cache) = std::env::var("D2_EGUI_MODULE_CACHE") {
        let cache = PathBuf::from(cache);
        if cache.is_file() {
            send(
                event_tx,
                HostEvent::Status(String::from("Loading cached native WASM module…")),
            );
            // The cache is explicitly supplied by the user and was produced by this host.
            return unsafe { Module::deserialize_file(engine, &cache) }
                .map_err(|error| anyhow::anyhow!(error.to_string()))
                .with_context(|| format!("failed to load module cache {}", cache.display()));
        }
        let module = wt(Module::from_file(engine, wasm))
            .with_context(|| format!("failed to compile {}", wasm.display()))?;
        if let Some(parent) = cache.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&cache, wt(module.serialize())?)
            .with_context(|| format!("failed to write module cache {}", cache.display()))?;
        return Ok(module);
    }
    wt(Module::from_file(engine, wasm))
        .with_context(|| format!("failed to compile {}", wasm.display()))
}

fn register_imports(module: &Module, linker: &mut Linker<HostState>) -> Result<()> {
    let imports = module
        .imports()
        .map(|import| {
            let ExternType::Func(function_type) = import.ty() else {
                bail!(
                    "unsupported non-function import {}!{}",
                    import.module(),
                    import.name()
                );
            };
            Ok((
                import.module().to_owned(),
                import.name().to_owned(),
                function_type,
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    for (library, name, function_type) in imports {
        let callback_library = library.clone();
        let callback_name = name.clone();
        wt(linker.func_new(
            &library,
            &name,
            function_type,
            move |mut caller: Caller<'_, HostState>, parameters, results| {
                if parameters.len() != 1 || results.len() != 1 {
                    return Err(WasmtimeError::msg(format!(
                        "unexpected host signature for {}!{}",
                        callback_library, callback_name
                    )));
                }
                let sp = match parameters[0] {
                    Val::I32(value) => value as u32,
                    _ => return Err(WasmtimeError::msg("host stack pointer is not i32")),
                };
                let memory = exported_memory(&mut caller)?;
                let outcome = {
                    let (bytes, state) = memory.data_and_store_mut(&mut caller);
                    state
                        .runtime
                        .dispatch(&callback_library, &callback_name, sp, bytes)
                        .map_err(|error| WasmtimeError::msg(format!("{error:#}")))?
                };
                if callback_library == "win32.user32.dll" && callback_name == "MessageBoxA" {
                    let trace = capture_assertion_trace(&mut caller)?;
                    eprintln!("MessageBoxA translated trace:\n{trace}");
                    caller
                        .data()
                        .runtime
                        .log(format!("MessageBoxA translated trace:\n{trace}"));
                }
                let value = match outcome {
                    DispatchResult::Value(value) => value,
                    DispatchResult::Invoke(request) => {
                        let (address, arguments, count) = {
                            let (bytes, state) = memory.data_and_store_mut(&mut caller);
                            state
                                .runtime
                                .prepare_invoke(bytes, request)
                                .map_err(|error| WasmtimeError::msg(format!("{error:#}")))?
                        };
                        let function = caller
                            .get_export("d2_invoke_current")
                            .and_then(Extern::into_func)
                            .ok_or_else(|| {
                                WasmtimeError::msg("d2_invoke_current export is unavailable")
                            })?;
                        let mut callback_result = [Val::I32(0)];
                        function.call(
                            &mut caller,
                            &[
                                Val::I32(address as i32),
                                Val::I32(arguments as i32),
                                Val::I32(count as i32),
                                Val::I32(FUEL_PER_ROUND as i32),
                            ],
                            &mut callback_result,
                        )?;
                        callback_result[0].unwrap_i32() as u32
                    }
                    DispatchResult::Wait(request) => run_wait(&mut caller, request)?,
                };
                results[0] = Val::I32(value as i32);
                Ok(())
            },
        ))?;
    }
    Ok(())
}

fn capture_assertion_trace(caller: &mut Caller<'_, HostState>) -> Result<String, WasmtimeError> {
    let count = call_export_u32(caller, "d2_trace_count", &[])?.min(16_384);
    let mut entries = Vec::with_capacity(count as usize);
    for back in 0..count {
        let pc = call_export_u32(caller, "d2_trace_pc", &[Val::I32(back as i32)])?;
        let esp = call_export_u32(caller, "d2_trace_esp", &[Val::I32(back as i32)])?;
        entries.push((back, pc, esp));
    }
    let module_name = |pc: u32| match pc {
        0x0106_0000..0x0117_0000 => "D2CMP",
        0x0135_0000..0x013a_0000 => "Fog",
        0x013f_0000..0x0144_0000 => "Storm",
        _ => "other",
    };
    let mut selected = (0..entries.len().min(16)).collect::<Vec<_>>();
    let mut transition_count = 0usize;
    for index in 1..entries.len() {
        if transition_count < 8
            && module_name(entries[index - 1].1) != module_name(entries[index].1)
        {
            selected.extend(index.saturating_sub(4)..(index + 12).min(entries.len()));
            transition_count += 1;
        }
    }
    selected.extend(entries.len().saturating_sub(16)..entries.len());
    selected.sort_unstable();
    selected.dedup();
    let lines = selected
        .into_iter()
        .map(|index| {
            let (back, pc, esp) = entries[index];
            format!(
                "  {back:04}: pc={pc:#010x} esp={esp:#010x} {}",
                module_name(pc)
            )
        })
        .collect::<Vec<_>>();
    let mut output = lines;
    if let Some((_, _, current_esp)) = entries.first().copied() {
        let memory = exported_memory(caller)?;
        let bytes = memory.data(&*caller);
        let start = current_esp.saturating_sub(0x4000) & !3;
        let end = current_esp.saturating_add(0x8000).min(bytes.len() as u32) & !3;
        let mut hits = 0usize;
        for address in (start..end).step_by(4) {
            let value = read_u32(bytes, address).unwrap_or(0);
            if (0x0106_0000..0x0117_0000).contains(&value) {
                if hits == 0 {
                    output.push(String::from("  D2CMP stack candidates:"));
                }
                output.push(format!("    [{address:#010x}] = {value:#010x}"));
                hits += 1;
                if hits == 128 {
                    output.push(String::from("    ... candidate list truncated"));
                    break;
                }
            }
        }
    }
    Ok(output.join("\n"))
}

fn run_wait(
    caller: &mut Caller<'_, HostState>,
    request: WaitRequest,
) -> Result<u32, WasmtimeError> {
    if caller.data().runtime.background_critical_owner().is_none()
        && caller.data_mut().runtime.wait_immediate(request.handle)
    {
        return Ok(0);
    }
    if caller.data().runtime.is_running_thread() {
        call_export_void(caller, "d2_request_yield")?;
        return Ok(if request.timeout == u32::MAX { 0 } else { 258 });
    }

    for round in 0..4096 {
        let owner = caller.data().runtime.background_critical_owner();
        if round >= 32 && owner.is_none() {
            break;
        }
        let threads = caller.data().runtime.wait_threads(request.handle);
        if threads.is_empty() {
            if let Some(owner) = owner {
                return Err(WasmtimeError::msg(format!(
                    "thread {owner:#x} stopped while owning a critical section"
                )));
            }
            break;
        }
        for handle in &threads {
            let Some(run) = caller.data_mut().runtime.begin_thread_run(*handle) else {
                continue;
            };
            let outcome = run_thread(caller, &run);
            match outcome {
                Ok((exit_code, status, finished)) => caller
                    .data_mut()
                    .runtime
                    .finish_thread_run(&run, exit_code, status, finished),
                Err(error) => {
                    caller.data_mut().runtime.abort_thread_run(&run);
                    return Err(error);
                }
            }
            if caller.data().runtime.background_critical_owner().is_none()
                && caller.data_mut().runtime.wait_immediate(request.handle)
            {
                return Ok(0);
            }
        }
    }
    if let Some(owner) = caller.data().runtime.background_critical_owner() {
        return Err(WasmtimeError::msg(format!(
            "critical section owner {owner:#x} did not release after 4096 scheduler rounds"
        )));
    }
    Ok(if request.timeout == 0 { 258 } else { 0 })
}

fn run_thread(
    caller: &mut Caller<'_, HostState>,
    run: &ThreadRun,
) -> Result<(u32, u32, bool), WasmtimeError> {
    let exit_code = call_export_u32(
        caller,
        "d2_run_context",
        &[
            Val::I32(run.context as i32),
            Val::I32(run.start as i32),
            Val::I32(run.stack_top as i32),
            Val::I32(FUEL_PER_ROUND as i32),
        ],
    )?;
    let status = call_export_u32(caller, "d2_context_status", &[Val::I32(run.context as i32)])?;
    let finished = call_export_u32(
        caller,
        "d2_context_finished",
        &[Val::I32(run.context as i32)],
    )? != 0;
    Ok((exit_code, status, finished))
}

fn call_export_u32(
    caller: &mut Caller<'_, HostState>,
    name: &str,
    parameters: &[Val],
) -> Result<u32, WasmtimeError> {
    let function = caller
        .get_export(name)
        .and_then(Extern::into_func)
        .ok_or_else(|| WasmtimeError::msg(format!("{name} export is unavailable")))?;
    let mut results = [Val::I32(0)];
    function.call(caller, parameters, &mut results)?;
    Ok(results[0].unwrap_i32() as u32)
}

fn call_export_void(caller: &mut Caller<'_, HostState>, name: &str) -> Result<(), WasmtimeError> {
    let function = caller
        .get_export(name)
        .and_then(Extern::into_func)
        .ok_or_else(|| WasmtimeError::msg(format!("{name} export is unavailable")))?;
    function.call(caller, &[], &mut [])
}

fn exported_memory(caller: &mut Caller<'_, HostState>) -> wasmtime::Result<Memory> {
    caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| WasmtimeError::msg("translated module memory is unavailable"))
}

fn ensure_memory(memory: &Memory, store: &mut Store<HostState>, required: usize) -> Result<()> {
    let current = memory.data_size(&*store);
    if required > current {
        let pages = (required - current).div_ceil(65_536) as u64;
        wt(memory.grow(store, pages))?;
    }
    Ok(())
}

fn write_u32(memory: &mut [u8], address: u32, value: u32) -> Result<()> {
    memory
        .get_mut(address as usize..address as usize + 4)
        .context("write outside translated memory")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn read_u32(memory: &[u8], address: u32) -> Result<u32> {
    let bytes: [u8; 4] = memory
        .get(address as usize..address as usize + 4)
        .context("read outside translated memory")?
        .try_into()
        .expect("four-byte memory range");
    Ok(u32::from_le_bytes(bytes))
}

fn send(sender: &SyncSender<HostEvent>, event: HostEvent) {
    let _ = sender.try_send(event);
}

fn wt<T>(result: wasmtime::Result<T>) -> Result<T> {
    result.map_err(|error| anyhow::anyhow!(format!("{error:#}")))
}
