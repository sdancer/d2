use crate::{
    gameplay::GameplaySession,
    manifest::Manifest,
    protocol::{HostEvent, InputEvent},
};
use anyhow::{Context, Result, bail};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::File,
    path::{Component, Path, PathBuf},
    sync::mpsc::{Receiver, SyncSender, TryRecvError},
    time::Instant,
};

const SCREEN_WIDTH: usize = 800;
const SCREEN_HEIGHT: usize = 600;

#[derive(Clone, Debug)]
pub struct InvokeRequest {
    pub address: u32,
    pub arguments: Vec<u32>,
}

#[derive(Clone, Debug)]
pub enum DispatchResult {
    Value(u32),
    Invoke(InvokeRequest),
    Wait(WaitRequest),
}

#[derive(Clone, Debug)]
pub struct WaitRequest {
    pub handle: u32,
    pub timeout: u32,
}

#[derive(Clone, Debug)]
pub struct ThreadRun {
    pub handle: u32,
    pub context: u32,
    pub start: u32,
    pub stack_top: u32,
    previous_thread: Option<u32>,
}

#[derive(Clone, Debug)]
struct Bitmap {
    width: i32,
    height: i32,
    bits_per_pixel: u32,
    stride: usize,
    size: usize,
    bits: u32,
    top_down: bool,
    screen: bool,
    palette: Option<Vec<u32>>,
}

#[derive(Debug)]
enum Handle {
    Dc {
        selected: u32,
        palette: u32,
    },
    Bitmap(Bitmap),
    Window {
        wnd_proc: u32,
        width: i32,
        height: i32,
    },
    File(FileHandle),
    Find(FindState),
    Event {
        manual_reset: bool,
        signaled: bool,
    },
    Thread(ThreadState),
    Socket,
    Registry(String),
    Generic,
}

#[derive(Clone, Debug)]
struct WindowClass {
    atom: u32,
    wnd_proc: u32,
}

#[derive(Clone, Debug)]
struct Message {
    hwnd: u32,
    message: u32,
    w_param: u32,
    l_param: u32,
}

#[derive(Debug)]
struct FileHandle {
    file: File,
    path: PathBuf,
    position: u64,
    writable: bool,
}

#[derive(Debug)]
struct ThreadState {
    start: u32,
    stack_top: u32,
    context: u32,
    exit_code: u32,
    status: u32,
    finished: bool,
}

#[derive(Clone, Debug, Default)]
struct CriticalSectionState {
    owner: u32,
    recursion: u32,
}

impl CriticalSectionState {
    fn try_enter(&mut self, thread: u32) -> bool {
        if self.owner == 0 {
            self.owner = thread;
            self.recursion = 1;
            true
        } else if self.owner == thread {
            self.recursion += 1;
            true
        } else {
            false
        }
    }

    fn leave(&mut self, thread: u32) -> Result<()> {
        if self.owner != thread || self.recursion == 0 {
            bail!(
                "critical section leave by thread {thread:#x}, owner is {:#x} with recursion {}",
                self.owner,
                self.recursion
            );
        }
        self.recursion -= 1;
        if self.recursion == 0 {
            self.owner = 0;
        }
        Ok(())
    }

    fn may_delete(&self, thread: u32) -> bool {
        self.owner == 0 || self.owner == thread
    }
}

#[derive(Debug)]
struct FindState {
    directory: PathBuf,
    names: Vec<String>,
    index: usize,
}

pub struct Runtime {
    pub last_error: u32,
    heap_cursor: u32,
    next_handle: u32,
    next_tls: u32,
    tls: HashMap<u32, u32>,
    handles: HashMap<u32, Handle>,
    current_thread: Option<u32>,
    critical_sections: HashMap<u32, CriticalSectionState>,
    message_box_counts: HashMap<(String, String), u64>,
    message_box_trace_pending: bool,
    allocations: HashMap<u32, u32>,
    reserved_ranges: Vec<(u32, u32)>,
    module_handles: HashMap<String, u32>,
    module_exports: HashMap<(u32, String), u32>,
    current_directory: String,
    host_root: PathBuf,
    gameplay: GameplaySession,
    command_line: String,
    command_line_pointer: u32,
    registry_values: HashMap<String, String>,
    clipboard: HashMap<u32, u32>,
    screen_bitmap_handle: u32,
    screen_presentations: u64,
    next_window_atom: u32,
    window_classes: HashMap<String, WindowClass>,
    active_window: u32,
    messages: VecDeque<Message>,
    cursor_x: i32,
    cursor_y: i32,
    auto_clicks: VecDeque<(i32, i32, u64)>,
    auto_keys: VecDeque<(u32, u64)>,
    show_cursor_count: i32,
    virtual_time: u32,
    clock_origin: Instant,
    clock_offset: u32,
    unknown_apis: HashSet<String>,
    event_tx: SyncSender<HostEvent>,
    input_rx: Receiver<InputEvent>,
    quit_requested: bool,
}

impl Runtime {
    pub fn new(
        heap_base: u32,
        host_root: PathBuf,
        event_tx: SyncSender<HostEvent>,
        input_rx: Receiver<InputEvent>,
        gameplay: GameplaySession,
    ) -> Self {
        let auto_clicks = (!gameplay.is_replay())
            .then(|| std::env::var("D2_AUTO_CLICKS").ok())
            .flatten()
            .into_iter()
            .flat_map(|schedule| {
                schedule
                    .split(';')
                    .filter_map(|item| {
                        let mut fields = item.split(',');
                        Some((
                            fields.next()?.parse().ok()?,
                            fields.next()?.parse().ok()?,
                            fields.next()?.parse().ok()?,
                        ))
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let auto_keys = std::env::var("D2_AUTO_KEYS")
            .ok()
            .into_iter()
            .flat_map(|schedule| {
                schedule
                    .split(';')
                    .filter_map(|item| {
                        let mut fields = item.split(',');
                        Some((fields.next()?.parse().ok()?, fields.next()?.parse().ok()?))
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        Self {
            last_error: 0,
            heap_cursor: heap_base,
            next_handle: 0x100,
            next_tls: 0,
            tls: HashMap::new(),
            handles: HashMap::new(),
            current_thread: None,
            critical_sections: HashMap::new(),
            message_box_counts: HashMap::new(),
            message_box_trace_pending: false,
            allocations: HashMap::new(),
            reserved_ranges: Vec::new(),
            module_handles: HashMap::from([(String::from("<main>"), 0x0040_0000)]),
            module_exports: HashMap::new(),
            current_directory: String::from("C:\\Diablo II"),
            host_root,
            gameplay,
            command_line: String::from("\"C:\\Diablo II\\Diablo II.exe\" -w"),
            command_line_pointer: 0,
            registry_values: HashMap::from([
                (String::from("installpath"), String::from("C:\\Diablo II")),
                (String::from("install path"), String::from("C:\\Diablo II")),
                (
                    String::from("diabloiifolder"),
                    String::from("C:\\Diablo II"),
                ),
                (
                    String::from("program"),
                    String::from("C:\\Diablo II\\Diablo II.exe"),
                ),
                (
                    String::from("save path"),
                    String::from("C:\\Diablo II\\save"),
                ),
                (
                    String::from("newsavepath"),
                    String::from("C:\\Diablo II\\save"),
                ),
            ]),
            clipboard: HashMap::new(),
            screen_bitmap_handle: 0,
            screen_presentations: 0,
            next_window_atom: 1,
            window_classes: HashMap::new(),
            active_window: 0,
            messages: VecDeque::new(),
            cursor_x: 0,
            cursor_y: 0,
            auto_clicks,
            auto_keys,
            show_cursor_count: 0,
            virtual_time: 0,
            clock_origin: Instant::now(),
            clock_offset: 0,
            unknown_apis: HashSet::new(),
            event_tx,
            input_rx,
            quit_requested: false,
        }
    }

    pub fn register_manifest(&mut self, manifest: &Manifest) {
        for module in &manifest.modules {
            let name = module.runtime_name.to_ascii_lowercase();
            self.module_handles.insert(name, module.load_base);
            for export in &module.exports {
                let address = module.load_base.wrapping_add(export.rva);
                self.module_exports
                    .insert((module.load_base, format!("#{}", export.ordinal)), address);
                if let Some(name) = &export.name {
                    self.module_exports
                        .insert((module.load_base, name.to_ascii_lowercase()), address);
                }
            }
        }
        if let Some(main) = manifest.modules.iter().find(|module| {
            module
                .runtime_name
                .eq_ignore_ascii_case(&manifest.entry_module)
        }) {
            self.module_handles
                .insert(String::from("<main>"), main.load_base);
        }
    }

    pub fn alloc(&mut self, memory: &mut [u8], size: u32, alignment: u32) -> Result<u32> {
        let size = size.max(1);
        let alignment = alignment.max(1);
        let mut start = self
            .heap_cursor
            .checked_add(alignment - 1)
            .map(|value| value & !(alignment - 1))
            .context("host allocation overflow")?;
        for &(reserved_start, reserved_end) in &self.reserved_ranges {
            let end = start
                .checked_add(size)
                .context("host allocation overflow")?;
            if start < reserved_end && end > reserved_start {
                start = reserved_end
                    .checked_add(alignment - 1)
                    .map(|value| value & !(alignment - 1))
                    .context("host allocation overflow")?;
            }
        }
        let end = start
            .checked_add(size)
            .context("host allocation overflow")?;
        if end as usize > memory.len() {
            bail!("host allocation exceeds pre-grown Wasm memory: {end:#x}");
        }
        memory[start as usize..end as usize].fill(0);
        self.heap_cursor = end;
        self.allocations.insert(start, size);
        Ok(start)
    }

    pub fn reserve(&mut self, start: u32, end: u32) -> Result<()> {
        if end <= start {
            bail!("reserved memory range must be non-empty");
        }
        self.reserved_ranges.push((start, end));
        self.reserved_ranges.sort_by_key(|range| range.0);
        Ok(())
    }

    pub fn dispatch(
        &mut self,
        library: &str,
        name: &str,
        sp: u32,
        memory: &mut [u8],
    ) -> Result<DispatchResult> {
        if library == "win32.kernel32.dll" && name == "WaitForSingleObject" {
            return Ok(DispatchResult::Wait(WaitRequest {
                handle: arg(memory, sp, 0),
                timeout: arg(memory, sp, 1),
            }));
        }
        let value = match library {
            "win32.kernel32.dll" => self.kernel32(name, sp, memory)?,
            "win32.user32.dll" => return self.user32(name, sp, memory),
            "win32.gdi32.dll" => self.gdi32(name, sp, memory)?,
            "win32.advapi32.dll" => self.advapi32(name, sp, memory)?,
            "win32.crtdll.dll" => self.crtdll(name, sp, memory)?,
            "win32.version.dll" => self.version(name, sp, memory)?,
            "win32.imm32.dll" => self.imm32(name, sp, memory)?,
            "win32.wsock32.dll" => self.wsock32(name, sp, memory)?,
            "win32.dsound.dll" => {
                let output = arg(memory, sp, 1);
                if output != 0 {
                    write_u32(memory, output, 0)?;
                }
                0x8878_0078
            }
            "win32.winmm.dll" => self.clock_now(),
            _ => self.unknown(library, name, 0),
        };
        Ok(DispatchResult::Value(value))
    }

    fn unknown(&mut self, library: &str, name: &str, fallback: u32) -> u32 {
        let key = format!("{library}!{name}");
        if self.unknown_apis.insert(key.clone()) {
            let _ = self.event_tx.try_send(HostEvent::Log(format!(
                "unimplemented host API {key}; returning {fallback:#x}"
            )));
        }
        fallback
    }

    fn clock_now(&mut self) -> u32 {
        let elapsed = self
            .clock_origin
            .elapsed()
            .as_millis()
            .min(u128::from(u32::MAX)) as u32;
        self.virtual_time = self.clock_offset.wrapping_add(elapsed);
        self.virtual_time
    }

    fn advance_clock(&mut self, delta: u32) -> u32 {
        let now = self.clock_now();
        if delta == 0 {
            return now;
        }
        self.clock_offset = now.wrapping_add(delta);
        self.clock_origin = Instant::now();
        self.virtual_time = self.clock_offset;
        self.virtual_time
    }

    fn poll_input(&mut self) {
        let mut live = Vec::new();
        loop {
            match self.input_rx.try_recv() {
                Ok(event) => live.push(event),
                Err(TryRecvError::Empty | TryRecvError::Disconnected) => break,
            }
        }
        let inputs = match self
            .gameplay
            .process_inputs(self.screen_presentations, live)
        {
            Ok(inputs) => inputs,
            Err(error) => {
                self.handle_gameplay_error(error);
                return;
            }
        };
        for event in inputs {
            self.apply_input(event);
        }
    }

    fn apply_input(&mut self, event: InputEvent) {
        match event {
            InputEvent::PointerMoved { x, y } => {
                self.cursor_x = x;
                self.cursor_y = y;
                self.enqueue(0x0200, 0, point_lparam(x, y));
            }
            InputEvent::MouseButton { x, y, down } => {
                self.cursor_x = x;
                self.cursor_y = y;
                self.enqueue(0x0200, 0, point_lparam(x, y));
                self.enqueue(
                    if down { 0x0201 } else { 0x0202 },
                    u32::from(down),
                    point_lparam(x, y),
                );
            }
            InputEvent::Character(character) => {
                self.enqueue(0x0102, character as u32, 1);
            }
            InputEvent::Key { virtual_key, down } => {
                self.enqueue(if down { 0x0100 } else { 0x0101 }, virtual_key, 1);
            }
            InputEvent::Quit => {
                self.quit_requested = true;
            }
        }
    }

    pub fn quit_requested(&self) -> bool {
        self.quit_requested
    }

    pub fn timing_counters(&self) -> (u64, u32) {
        (self.screen_presentations, self.virtual_time)
    }

    pub fn prepare_invoke(
        &mut self,
        memory: &mut [u8],
        request: InvokeRequest,
    ) -> Result<(u32, u32, u32)> {
        let pointer = self.alloc(memory, request.arguments.len() as u32 * 4, 4)?;
        for (index, value) in request.arguments.iter().enumerate() {
            write_u32(memory, pointer + index as u32 * 4, *value)?;
        }
        Ok((request.address, pointer, request.arguments.len() as u32))
    }

    pub fn current_thread_id(&self) -> u32 {
        self.current_thread.unwrap_or(1)
    }

    pub fn is_running_thread(&self) -> bool {
        self.current_thread.is_some()
    }

    fn handle_gameplay_error(&mut self, error: anyhow::Error) {
        if self.gameplay.is_replay() {
            self.log(format!(
                "Replay stopped at first divergence; guest remains live: {error:#}"
            ));
            self.gameplay.stop_replay();
        } else {
            self.log(format!("Gameplay recording failed: {error:#}"));
            self.quit_requested = true;
        }
    }

    pub(super) fn initialize_critical_section(
        &mut self,
        pointer: u32,
        memory: &mut [u8],
    ) -> Result<()> {
        self.critical_sections
            .insert(pointer, CriticalSectionState::default());
        let start = pointer as usize;
        let section = memory
            .get_mut(start..start + 24)
            .with_context(|| format!("critical section {pointer:#010x} is outside guest memory"))?;
        section.fill(0);
        write_i32(memory, pointer + 4, -1)?;
        Ok(())
    }

    pub(super) fn delete_critical_section(
        &mut self,
        pointer: u32,
        memory: &mut [u8],
    ) -> Result<()> {
        let thread = self.current_thread_id();
        if let Some(section) = self.critical_sections.get(&pointer)
            && !section.may_delete(thread)
        {
            bail!(
                "critical section {pointer:#010x} deleted by thread {thread:#x} while owned by {:#x} (recursion {})",
                section.owner,
                section.recursion
            );
        }
        self.critical_sections.remove(&pointer);
        if let Some(section) = memory.get_mut(pointer as usize..pointer as usize + 24) {
            section.fill(0);
        }
        Ok(())
    }

    pub(super) fn enter_critical_section(&mut self, pointer: u32, memory: &mut [u8]) -> Result<()> {
        let thread = self.current_thread_id();
        let section = self.critical_sections.entry(pointer).or_default();
        if !section.try_enter(thread) {
            let message = format!(
                "critical section contention at {pointer:#010x}: thread {thread:#x} entered while owned by {:#x}",
                section.owner
            );
            eprintln!("{message}");
            self.log(&message);
            bail!(message);
        }
        write_i32(memory, pointer + 4, 0)?;
        write_u32(memory, pointer + 8, section.recursion)?;
        write_u32(memory, pointer + 12, section.owner)?;
        Ok(())
    }

    pub(super) fn leave_critical_section(&mut self, pointer: u32, memory: &mut [u8]) -> Result<()> {
        let thread = self.current_thread_id();
        let section = self
            .critical_sections
            .get_mut(&pointer)
            .with_context(|| format!("leaving uninitialized critical section {pointer:#010x}"))?;
        section.leave(thread)?;
        if section.owner == 0 {
            write_i32(memory, pointer + 4, -1)?;
            write_u32(memory, pointer + 8, 0)?;
            write_u32(memory, pointer + 12, 0)?;
        } else {
            write_i32(memory, pointer + 4, 0)?;
            write_u32(memory, pointer + 8, section.recursion)?;
            write_u32(memory, pointer + 12, section.owner)?;
        }
        Ok(())
    }

    pub fn background_critical_owner(&self) -> Option<u32> {
        self.critical_sections
            .values()
            .filter_map(|section| (section.owner > 1).then_some(section.owner))
            .min()
    }

    pub fn wait_immediate(&mut self, handle: u32) -> bool {
        match self.handles.get_mut(&handle) {
            Some(Handle::Event {
                manual_reset,
                signaled,
            }) if *signaled => {
                if !*manual_reset {
                    *signaled = false;
                }
                true
            }
            Some(Handle::Thread(thread)) => thread.finished,
            _ => false,
        }
    }

    pub fn wait_threads(&self, target: u32) -> Vec<u32> {
        if let Some(owner) = self.background_critical_owner() {
            return match self.handles.get(&owner) {
                Some(Handle::Thread(thread)) if !thread.finished => vec![owner],
                _ => Vec::new(),
            };
        }
        if let Some(Handle::Thread(thread)) = self.handles.get(&target) {
            return if thread.finished {
                Vec::new()
            } else {
                vec![target]
            };
        }
        let mut handles = self
            .handles
            .iter()
            .filter_map(|(handle, item)| match item {
                Handle::Thread(thread) if !thread.finished => Some(*handle),
                _ => None,
            })
            .collect::<Vec<_>>();
        handles.sort_unstable();
        handles
    }

    pub fn thread_contexts(&self) -> Vec<(u32, u32)> {
        let mut contexts = self
            .handles
            .iter()
            .filter_map(|(handle, item)| match item {
                Handle::Thread(thread) => Some((*handle, thread.context)),
                _ => None,
            })
            .collect::<Vec<_>>();
        contexts.sort_unstable();
        contexts
    }

    pub fn begin_thread_run(&mut self, handle: u32) -> Option<ThreadRun> {
        if let Some(owner) = self.background_critical_owner()
            && owner != handle
        {
            return None;
        }
        let Handle::Thread(thread) = self.handles.get(&handle)? else {
            return None;
        };
        if thread.finished {
            return None;
        }
        let run = ThreadRun {
            handle,
            context: thread.context,
            start: thread.start,
            stack_top: thread.stack_top,
            previous_thread: self.current_thread,
        };
        self.current_thread = Some(handle);
        Some(run)
    }

    pub fn finish_thread_run(
        &mut self,
        run: &ThreadRun,
        exit_code: u32,
        status: u32,
        finished: bool,
    ) {
        if let Some(Handle::Thread(thread)) = self.handles.get_mut(&run.handle) {
            thread.exit_code = exit_code;
            thread.status = status;
            thread.finished = finished;
        }
        self.current_thread = run.previous_thread;
    }

    pub fn abort_thread_run(&mut self, run: &ThreadRun) {
        self.current_thread = run.previous_thread;
    }

    pub fn unknown_api_summary(&self) -> String {
        let mut names = self.unknown_apis.iter().cloned().collect::<Vec<_>>();
        names.sort();
        if names.is_empty() {
            String::from("No unimplemented host APIs were called")
        } else {
            format!("Unimplemented host APIs called: {}", names.join(", "))
        }
    }

    pub fn log(&self, message: impl Into<String>) {
        let _ = self.event_tx.try_send(HostEvent::Log(message.into()));
    }

    pub(super) fn message_box(&mut self, caption: String, text: String) {
        let count = {
            let count = self
                .message_box_counts
                .entry((caption.clone(), text.clone()))
                .or_default();
            *count += 1;
            *count
        };
        if count == 1 {
            self.message_box_trace_pending = true;
            self.log(format!("MessageBoxA: {caption}: {text}"));
        } else if count.is_power_of_two() {
            self.log(format!(
                "MessageBoxA duplicate #{count} (trace suppressed): {caption}: {text}"
            ));
        }
    }

    pub fn take_message_box_trace_request(&mut self) -> bool {
        std::mem::take(&mut self.message_box_trace_pending)
    }

    fn enqueue(&mut self, message: u32, w_param: u32, l_param: u32) {
        self.messages.push_back(Message {
            hwnd: self.active_window,
            message,
            w_param,
            l_param,
        });
    }

    fn present(&mut self, memory: &[u8], bitmap: &Bitmap, width: usize, height: usize) {
        self.screen_presentations += 1;
        self.poll_input();
        if self.quit_requested {
            return;
        }
        if let Some(&(x, y, presentation)) = self.auto_clicks.front()
            && self.screen_presentations >= presentation
        {
            self.auto_clicks.pop_front();
            let generated = vec![
                InputEvent::PointerMoved { x, y },
                InputEvent::MouseButton { x, y, down: true },
                InputEvent::MouseButton { x, y, down: false },
            ];
            match self
                .gameplay
                .process_inputs(self.screen_presentations, generated)
            {
                Ok(inputs) => {
                    for event in inputs {
                        self.apply_input(event);
                    }
                }
                Err(error) => {
                    self.handle_gameplay_error(error);
                }
            }
            let _ = self.event_tx.try_send(HostEvent::Log(format!(
                "Auto-clicked ({x},{y}) at presentation {}",
                self.screen_presentations
            )));
        }
        if let Some(&(virtual_key, presentation)) = self.auto_keys.front()
            && self.screen_presentations >= presentation
        {
            self.auto_keys.pop_front();
            let generated = vec![
                InputEvent::Key {
                    virtual_key,
                    down: true,
                },
                InputEvent::Key {
                    virtual_key,
                    down: false,
                },
            ];
            match self
                .gameplay
                .process_inputs(self.screen_presentations, generated)
            {
                Ok(inputs) => {
                    for event in inputs {
                        self.apply_input(event);
                    }
                }
                Err(error) => self.handle_gameplay_error(error),
            }
            self.log(format!(
                "Auto-pressed virtual key {virtual_key:#x} at presentation {}",
                self.screen_presentations
            ));
        }
        let source_width = width.max(1).min(bitmap.width.max(1) as usize);
        let source_height = height.max(1).min(bitmap.height.max(1) as usize);
        let width = SCREEN_WIDTH;
        let height = SCREEN_HEIGHT;
        let Some(source) = memory.get(bitmap.bits as usize..bitmap.bits as usize + bitmap.size)
        else {
            return;
        };
        let mut rgba = vec![0; width * height * 4];
        for y in 0..height {
            let scaled_y = y * source_height / height;
            let source_y = if bitmap.top_down {
                scaled_y
            } else {
                bitmap.height as usize - 1 - scaled_y
            };
            for x in 0..width {
                let scaled_x = x * source_width / width;
                let input = source_y * bitmap.stride + scaled_x * 4;
                let output = (y * width + x) * 4;
                rgba[output] = source[input + 2];
                rgba[output + 1] = source[input + 1];
                rgba[output + 2] = source[input];
                rgba[output + 3] = 0xff;
            }
        }
        let virtual_time = self.clock_now();
        if let Err(error) = self.gameplay.checkpoint(
            self.screen_presentations,
            virtual_time,
            width,
            height,
            &rgba,
        ) {
            self.handle_gameplay_error(error);
        }
        let _ = self.event_tx.try_send(HostEvent::Frame {
            width,
            height,
            input_width: source_width,
            input_height: source_height,
            rgba,
            presentation: self.screen_presentations,
        });
    }

    fn ensure_screen_bitmap(&mut self, memory: &mut [u8]) -> Result<u32> {
        if self.screen_bitmap_handle != 0 {
            return Ok(self.screen_bitmap_handle);
        }
        let stride = SCREEN_WIDTH * 4;
        let size = stride * SCREEN_HEIGHT;
        let bits = self.alloc(memory, size as u32, 4)?;
        let handle = self.new_handle(Handle::Bitmap(Bitmap {
            width: SCREEN_WIDTH as i32,
            height: SCREEN_HEIGHT as i32,
            bits_per_pixel: 32,
            stride,
            size,
            bits,
            top_down: true,
            screen: true,
            palette: None,
        }));
        self.screen_bitmap_handle = handle;
        Ok(handle)
    }

    fn new_handle(&mut self, value: Handle) -> u32 {
        let handle = self.next_handle;
        self.next_handle += 1;
        self.handles.insert(handle, value);
        handle
    }

    fn selected_bitmap(&self, dc: u32) -> Option<(u32, Bitmap)> {
        let selected = match self.handles.get(&dc) {
            Some(Handle::Dc { selected, .. }) => *selected,
            _ => return None,
        };
        match self.handles.get(&selected) {
            Some(Handle::Bitmap(bitmap)) => Some((selected, bitmap.clone())),
            _ => None,
        }
    }

    fn read_c_string(&self, memory: &[u8], pointer: u32) -> String {
        if pointer == 0 || pointer as usize >= memory.len() {
            return String::new();
        }
        let tail = &memory[pointer as usize..];
        let length = tail
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(tail.len());
        String::from_utf8_lossy(&tail[..length]).into_owned()
    }

    fn write_c_string(
        &self,
        memory: &mut [u8],
        pointer: u32,
        capacity: u32,
        value: &str,
    ) -> Result<u32> {
        if pointer == 0 || capacity == 0 {
            return Ok(0);
        }
        let encoded = value.as_bytes();
        let length = encoded.len().min(capacity.saturating_sub(1) as usize);
        let output = memory
            .get_mut(pointer as usize..pointer as usize + capacity as usize)
            .context("string output exceeds Wasm memory")?;
        output[..length].copy_from_slice(&encoded[..length]);
        output[length] = 0;
        Ok(length as u32)
    }

    fn alloc_c_string(&mut self, memory: &mut [u8], value: &str) -> Result<u32> {
        let pointer = self.alloc(memory, value.len() as u32 + 1, 1)?;
        self.write_c_string(memory, pointer, value.len() as u32 + 1, value)?;
        Ok(pointer)
    }

    fn host_path(&self, windows_path: &str) -> PathBuf {
        let mut text = windows_path.replace('/', "\\");
        if text.len() >= 2 && text.as_bytes()[1] == b':' {
            text = text[2..].to_owned();
        }
        text = text.trim_start_matches('\\').to_owned();
        if text.to_ascii_lowercase().starts_with("diablo ii\\") {
            text = text[10..].to_owned();
        }
        let normalized = text.replace('\\', "/");
        let components = Path::new(&normalized).components().collect::<Vec<_>>();
        let save_override = components.first().is_some_and(|component| {
            matches!(component, Component::Normal(value) if value.to_string_lossy().eq_ignore_ascii_case("save"))
        });
        let mut output = if save_override {
            self.gameplay
                .save_root()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| self.host_root.clone())
        } else {
            self.host_root.clone()
        };
        for (index, component) in components.into_iter().enumerate() {
            if save_override && self.gameplay.save_root().is_some() && index == 0 {
                continue;
            }
            if let Component::Normal(value) = component {
                output.push(value);
            }
        }
        output
    }
}

#[cfg(test)]
mod critical_section_tests {
    use super::*;

    #[test]
    fn ownership_is_recursive_and_exclusive() -> Result<()> {
        let mut section = CriticalSectionState::default();
        assert!(section.try_enter(0x101));
        assert!(section.try_enter(0x101));
        assert!(!section.try_enter(0x202));
        assert_eq!(section.owner, 0x101);
        assert_eq!(section.recursion, 2);
        section.leave(0x101)?;
        assert_eq!(section.owner, 0x101);
        section.leave(0x101)?;
        assert_eq!(section.owner, 0);
        assert!(section.try_enter(0x202));
        assert!(section.may_delete(0x202));
        assert!(!section.may_delete(0x101));
        Ok(())
    }
}

fn point_lparam(x: i32, y: i32) -> u32 {
    ((y as u32 & 0xffff) << 16) | (x as u32 & 0xffff)
}

fn arg(memory: &[u8], sp: u32, index: u32) -> u32 {
    read_u32(memory, sp.wrapping_add(index * 4)).unwrap_or(0)
}

fn read_u16(memory: &[u8], pointer: u32) -> Result<u16> {
    let bytes: [u8; 2] = memory
        .get(pointer as usize..pointer as usize + 2)
        .context("read outside Wasm memory")?
        .try_into()
        .expect("two-byte range");
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(memory: &[u8], pointer: u32) -> Result<u32> {
    let bytes: [u8; 4] = memory
        .get(pointer as usize..pointer as usize + 4)
        .context("read outside Wasm memory")?
        .try_into()
        .expect("four-byte range");
    Ok(u32::from_le_bytes(bytes))
}

fn read_i32(memory: &[u8], pointer: u32) -> Result<i32> {
    Ok(read_u32(memory, pointer)? as i32)
}

fn write_u16(memory: &mut [u8], pointer: u32, value: u16) -> Result<()> {
    memory
        .get_mut(pointer as usize..pointer as usize + 2)
        .context("write outside Wasm memory")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(memory: &mut [u8], pointer: u32, value: u32) -> Result<()> {
    memory
        .get_mut(pointer as usize..pointer as usize + 4)
        .context("write outside Wasm memory")?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_i32(memory: &mut [u8], pointer: u32, value: i32) -> Result<()> {
    write_u32(memory, pointer, value as u32)
}

mod gdi32;
mod kernel32;
mod misc;
mod user32;
