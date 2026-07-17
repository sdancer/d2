use super::*;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::FileExt;

const PAGE_SIZE: u32 = 65_536;

impl Runtime {
    pub(super) fn kernel32(&mut self, name: &str, sp: u32, memory: &mut [u8]) -> Result<u32> {
        match name {
            "GetLastError" => Ok(self.last_error),
            "SetLastError" => {
                self.last_error = arg(memory, sp, 0);
                Ok(0)
            }
            "GetCurrentProcess" => Ok(u32::MAX),
            "GetCurrentProcessId" => Ok(1),
            "GetCurrentThreadId" => Ok(self.current_thread_id()),
            "GetCurrentThread" => Ok(0xffff_fffe),
            "SetThreadPriority" | "DisableThreadLibraryCalls" => Ok(1),
            "GetExitCodeProcess" => {
                let exit_code = match self.handles.get(&arg(memory, sp, 0)) {
                    Some(Handle::Thread(thread)) => thread.exit_code,
                    _ => 259,
                };
                write_u32(memory, arg(memory, sp, 1), exit_code)?;
                Ok(1)
            }
            "TerminateProcess" => Ok(arg(memory, sp, 1)),
            "ExitProcess" => Ok(arg(memory, sp, 0)),
            "GetVersion" => Ok(4),
            "GetVersionExA" => {
                let pointer = arg(memory, sp, 0);
                if read_u32(memory, pointer)? < 148 {
                    self.last_error = 122;
                    return Ok(0);
                }
                write_u32(memory, pointer + 4, 4)?;
                write_u32(memory, pointer + 8, 0)?;
                write_u32(memory, pointer + 12, 950)?;
                write_u32(memory, pointer + 16, 2)?;
                memory[pointer as usize + 20..pointer as usize + 148].fill(0);
                Ok(1)
            }
            "GetCommandLineA" => {
                if self.command_line_pointer == 0 {
                    let value = self.command_line.clone();
                    self.command_line_pointer = self.alloc_c_string(memory, &value)?;
                }
                Ok(self.command_line_pointer)
            }
            "GetCurrentDirectoryA" => {
                let required = self.current_directory.len() as u32;
                if arg(memory, sp, 0) <= required {
                    Ok(required + 1)
                } else {
                    let value = self.current_directory.clone();
                    self.write_c_string(memory, arg(memory, sp, 1), arg(memory, sp, 0), &value)?;
                    Ok(required)
                }
            }
            "SetCurrentDirectoryA" => {
                self.current_directory = self.read_c_string(memory, arg(memory, sp, 0));
                Ok(1)
            }
            "GetStartupInfoA" => {
                let pointer = arg(memory, sp, 0);
                memory[pointer as usize..pointer as usize + 68].fill(0);
                write_u32(memory, pointer, 68)?;
                Ok(0)
            }
            "GetModuleHandleA" => {
                let pointer = arg(memory, sp, 0);
                let key = if pointer == 0 {
                    String::from("<main>")
                } else {
                    self.read_c_string(memory, pointer).to_ascii_lowercase()
                };
                Ok(self.module_handles.get(&key).copied().unwrap_or(0))
            }
            "GetModuleFileNameA" => {
                let text = "C:\\Diablo II\\Diablo II.exe";
                self.write_c_string(memory, arg(memory, sp, 1), arg(memory, sp, 2), text)
            }
            "LoadLibraryA" | "LoadLibraryExA" => {
                let key = self
                    .read_c_string(memory, arg(memory, sp, 0))
                    .to_ascii_lowercase();
                if let Some(value) = self.module_handles.get(&key) {
                    Ok(*value)
                } else {
                    let handle = self.new_handle(Handle::Generic);
                    self.module_handles.insert(key, handle);
                    Ok(handle)
                }
            }
            "FreeLibrary" => Ok(1),
            "GetProcAddress" => {
                let handle = arg(memory, sp, 0);
                let symbol_pointer = arg(memory, sp, 1);
                let symbol = if symbol_pointer <= 0xffff {
                    format!("#{symbol_pointer}")
                } else {
                    self.read_c_string(memory, symbol_pointer)
                        .to_ascii_lowercase()
                };
                let result = self.module_exports.get(&(handle, symbol)).copied();
                if result.is_none() {
                    self.last_error = 127;
                }
                Ok(result.unwrap_or(0))
            }
            "InterlockedIncrement" | "InterlockedDecrement" => {
                let pointer = arg(memory, sp, 0);
                let delta = if name == "InterlockedIncrement" {
                    1
                } else {
                    -1
                };
                let value = read_i32(memory, pointer)?.wrapping_add(delta);
                write_i32(memory, pointer, value)?;
                Ok(value as u32)
            }
            "InitializeCriticalSection" => {
                self.initialize_critical_section(arg(memory, sp, 0), memory)?;
                Ok(0)
            }
            "DeleteCriticalSection" => {
                self.delete_critical_section(arg(memory, sp, 0), memory)?;
                Ok(0)
            }
            "EnterCriticalSection" => {
                self.enter_critical_section(arg(memory, sp, 0), memory)?;
                Ok(0)
            }
            "LeaveCriticalSection" => {
                self.leave_critical_section(arg(memory, sp, 0), memory)?;
                Ok(0)
            }
            "TlsAlloc" => {
                let value = self.next_tls;
                self.next_tls += 1;
                Ok(value)
            }
            "TlsFree" => {
                self.tls.remove(&arg(memory, sp, 0));
                Ok(1)
            }
            "TlsSetValue" => {
                self.tls.insert(arg(memory, sp, 0), arg(memory, sp, 1));
                Ok(1)
            }
            "TlsGetValue" => Ok(self.tls.get(&arg(memory, sp, 0)).copied().unwrap_or(0)),
            "GetTickCount" => Ok(self.clock_now()),
            "Sleep" => Ok(0),
            "WaitForSingleObject" => {
                let handle = arg(memory, sp, 0);
                Ok(match self.handles.get(&handle) {
                    Some(Handle::Event { signaled: true, .. }) => 0,
                    _ => 0,
                })
            }
            "WaitForMultipleObjects" => Ok(0),
            "CloseHandle" | "FindClose" => {
                self.release_handle(arg(memory, sp, 0));
                Ok(1)
            }
            "OpenEventA" => Ok(0),
            "CreateEventA" => Ok(self.new_handle(Handle::Event {
                manual_reset: arg(memory, sp, 1) != 0,
                signaled: arg(memory, sp, 2) != 0,
            })),
            "SetEvent" | "ResetEvent" => {
                let handle = arg(memory, sp, 0);
                if let Some(Handle::Event { signaled, .. }) = self.handles.get_mut(&handle) {
                    *signaled = name == "SetEvent";
                    Ok(1)
                } else {
                    Ok(0)
                }
            }
            "SetUnhandledExceptionFilter" | "SetErrorMode" => Ok(0),
            "UnhandledExceptionFilter" | "IsBadCodePtr" | "IsBadReadPtr" | "IsBadWritePtr" => Ok(0),
            "GetProcessHeap" => Ok(1),
            "QueryPerformanceFrequency" => {
                write_u64(memory, arg(memory, sp, 0), 1_000_000_000)?;
                Ok(1)
            }
            "QueryPerformanceCounter" => {
                let value = self.performance_counter();
                write_u64(memory, arg(memory, sp, 0), value)?;
                Ok(1)
            }
            "OutputDebugStringA" => {
                let text = self.read_c_string(memory, arg(memory, sp, 0));
                let _ = self
                    .event_tx
                    .try_send(HostEvent::Log(format!("debug: {text}")));
                Ok(0)
            }
            "GetLocalTime" | "GetSystemTime" => {
                let pointer = arg(memory, sp, 0);
                for (index, value) in [2000, 1, 6, 1, 0, 0, 0, 0].into_iter().enumerate() {
                    write_u16(memory, pointer + index as u32 * 2, value)?;
                }
                Ok(0)
            }
            "GetTimeZoneInformation" => {
                let pointer = arg(memory, sp, 0) as usize;
                memory[pointer..pointer + 172].fill(0);
                Ok(1)
            }
            "GetSystemInfo" => {
                let pointer = arg(memory, sp, 0);
                memory[pointer as usize..pointer as usize + 36].fill(0);
                write_u32(memory, pointer + 4, PAGE_SIZE)?;
                write_u32(memory, pointer + 8, 0x0001_0000)?;
                write_u32(memory, pointer + 12, 0x7ffe_ffff)?;
                write_u32(memory, pointer + 20, 1)?;
                write_u32(memory, pointer + 24, 1)?;
                write_u16(memory, pointer + 32, 5)?;
                Ok(0)
            }
            "FormatMessageA" => {
                let flags = arg(memory, sp, 0);
                let text = format!("Win32 error {}", arg(memory, sp, 2));
                let destination = arg(memory, sp, 4);
                if flags & 0x100 != 0 {
                    let pointer = self.alloc_c_string(memory, &text)?;
                    write_u32(memory, destination, pointer)?;
                } else {
                    self.write_c_string(memory, destination, arg(memory, sp, 5), &text)?;
                }
                Ok(text.len() as u32)
            }
            "CompareStringA" => self.compare_string_a(sp, memory),
            "CompareStringW" => self.compare_string_w(sp, memory),
            "CreateThread" => {
                let requested = arg(memory, sp, 1);
                let stack_size = if requested == 0 {
                    0x4_0000
                } else {
                    requested.clamp(0x1_0000, 0x10_0000)
                };
                let stack_base = self.alloc(memory, stack_size, 16)?;
                let stack_top = stack_base.wrapping_add(stack_size).wrapping_sub(0x100) & !15;
                write_u32(memory, stack_top, arg(memory, sp, 3))?;
                let context = match self.alloc(memory, 256, 8) {
                    Ok(context) => context,
                    Err(error) => {
                        self.free(stack_base);
                        return Err(error);
                    }
                };
                let handle = self.new_handle(Handle::Thread(ThreadState {
                    start: arg(memory, sp, 2),
                    stack_base,
                    stack_top,
                    context,
                    exit_code: 259,
                    status: 0,
                    finished: false,
                    wait: None,
                    resume_result: None,
                }));
                let thread_id = arg(memory, sp, 5);
                if thread_id != 0 {
                    write_u32(memory, thread_id, handle)?;
                }
                Ok(handle)
            }
            "SuspendThread" | "ResumeThread" | "GetThreadContext" => Ok(0),
            "GetStdHandle" | "SetHandleCount" => Ok(arg(memory, sp, 0)),
            "GetFileType" => Ok(2),
            "GetEnvironmentVariableA" => {
                let key = self.read_c_string(memory, arg(memory, sp, 0));
                let Ok(value) = std::env::var(&key) else {
                    self.last_error = 203;
                    return Ok(0);
                };
                let capacity = arg(memory, sp, 2);
                if capacity <= value.len() as u32 {
                    Ok(value.len() as u32 + 1)
                } else {
                    self.write_c_string(memory, arg(memory, sp, 1), capacity, &value)?;
                    Ok(value.len() as u32)
                }
            }
            "SetEnvironmentVariableA" => Ok(1),
            "GetSystemDefaultLangID" => Ok(0x0409),
            "GetPrivateProfileIntA" => Ok(arg(memory, sp, 2)),
            "GetPrivateProfileStringA" => {
                let fallback = self.read_c_string(memory, arg(memory, sp, 2));
                self.write_c_string(memory, arg(memory, sp, 3), arg(memory, sp, 4), &fallback)
            }
            "GetDiskFreeSpaceA" => {
                for (index, value) in [8, 512, 0x4_0000, 0x8_0000].into_iter().enumerate() {
                    let pointer = arg(memory, sp, index as u32 + 1);
                    if pointer != 0 {
                        write_u32(memory, pointer, value)?;
                    }
                }
                Ok(1)
            }
            "GetVolumeInformationA" => self.volume_information(sp, memory),
            "GlobalMemoryStatus" => {
                let pointer = arg(memory, sp, 0);
                write_u32(memory, pointer, 32)?;
                write_u32(memory, pointer + 4, 50)?;
                for offset in (8..32).step_by(4) {
                    write_u32(memory, pointer + offset, 0x2000_0000)?;
                }
                Ok(0)
            }
            "GetEnvironmentStrings" | "GetEnvironmentStringsA" => self.alloc_c_string(memory, ""),
            "GetEnvironmentStringsW" => {
                let pointer = self.alloc(memory, 4, 2)?;
                write_u32(memory, pointer, 0)?;
                Ok(pointer)
            }
            "FreeEnvironmentStringsA" | "FreeEnvironmentStringsW" => {
                self.free(arg(memory, sp, 0));
                Ok(1)
            }
            "HeapCreate" | "HeapDestroy" => Ok(1),
            "HeapSize" => Ok(self.allocation_size(arg(memory, sp, 2)).unwrap_or(u32::MAX)),
            "HeapAlloc" => self.alloc(memory, arg(memory, sp, 2), 8),
            "HeapFree" => {
                self.free(arg(memory, sp, 2));
                Ok(1)
            }
            "HeapReAlloc" => self.heap_realloc(sp, memory),
            "LocalAlloc" | "GlobalAlloc" => self.alloc(memory, arg(memory, sp, 1), 8),
            "LocalFree" | "GlobalFree" => {
                self.free(arg(memory, sp, 0));
                Ok(0)
            }
            "GlobalLock" => Ok(arg(memory, sp, 0)),
            "GlobalUnlock" => Ok(1),
            "VirtualAlloc" => {
                let requested = arg(memory, sp, 0);
                if requested == 0 {
                    self.alloc(memory, arg(memory, sp, 1), PAGE_SIZE)
                } else {
                    Ok(requested)
                }
            }
            "VirtualFree" => {
                let free_type = arg(memory, sp, 2);
                if free_type & 0x8000 != 0 {
                    Ok(u32::from(self.free(arg(memory, sp, 0))))
                } else {
                    Ok(1)
                }
            }
            "VirtualUnlock" => Ok(1),
            "VirtualQuery" | "VirtualQueryEx" => self.virtual_query(name, sp, memory),
            "CreateDirectoryA" => {
                let path = self.host_path(&self.read_c_string(memory, arg(memory, sp, 0)));
                Ok(u32::from(fs::create_dir_all(path).is_ok()))
            }
            "RemoveDirectoryA" => {
                let path = self.host_path(&self.read_c_string(memory, arg(memory, sp, 0)));
                Ok(u32::from(fs::remove_dir(path).is_ok()))
            }
            "MoveFileA" => {
                let source = self.host_path(&self.read_c_string(memory, arg(memory, sp, 0)));
                let destination = self.host_path(&self.read_c_string(memory, arg(memory, sp, 1)));
                Ok(u32::from(fs::rename(source, destination).is_ok()))
            }
            "DuplicateHandle" => {
                let handle = self.new_handle(Handle::Generic);
                let output = arg(memory, sp, 3);
                if output != 0 {
                    write_u32(memory, output, handle)?;
                }
                Ok(1)
            }
            "CreateIoCompletionPort" => Ok(self.new_handle(Handle::Generic)),
            "GetQueuedCompletionStatus" => Ok(0),
            "GetComputerNameA" => {
                let size = arg(memory, sp, 1);
                let capacity = read_u32(memory, size)?;
                if capacity < 7 {
                    write_u32(memory, size, 7)?;
                    Ok(0)
                } else {
                    self.write_c_string(memory, arg(memory, sp, 0), capacity, "D2WASM")?;
                    write_u32(memory, size, 6)?;
                    Ok(1)
                }
            }
            "CreateFileA" => self.create_file(sp, memory),
            "ReadFile" => self.read_file(sp, memory),
            "WriteFile" => self.write_file(sp, memory),
            "SetFilePointer" => self.set_file_pointer(sp, memory),
            "GetFileSize" => self.get_file_size(sp, memory),
            "FlushFileBuffers" => self.flush_file(sp, memory),
            "SetEndOfFile" => self.set_end_of_file(sp, memory),
            "DeleteFileA" => {
                let path = self.host_path(&self.read_c_string(memory, arg(memory, sp, 0)));
                if fs::remove_file(path).is_ok() {
                    Ok(1)
                } else {
                    self.last_error = 2;
                    Ok(0)
                }
            }
            "CreateProcessA" => {
                self.last_error = 2;
                Ok(0)
            }
            "FindFirstFileA" => self.find_first(sp, memory),
            "FindNextFileA" => self.find_next(sp, memory),
            "GetFileAttributesA" => {
                let path = self.host_path(&self.read_c_string(memory, arg(memory, sp, 0)));
                match fs::metadata(path) {
                    Ok(metadata) => Ok(if metadata.is_dir() { 0x10 } else { 0x80 }),
                    Err(_) => {
                        self.last_error = 2;
                        Ok(u32::MAX)
                    }
                }
            }
            "GetDriveTypeA" => Ok(3),
            "GetLogicalDriveStringsA" => {
                let output = arg(memory, sp, 1);
                if output == 0 || arg(memory, sp, 0) < 5 {
                    Ok(5)
                } else {
                    memory[output as usize..output as usize + 5].copy_from_slice(b"C:\\\0\0");
                    Ok(4)
                }
            }
            "GetWindowsDirectoryA" => self.write_c_string(
                memory,
                arg(memory, sp, 0),
                arg(memory, sp, 1),
                "C:\\Windows",
            ),
            "GetSystemDirectoryA" => self.write_c_string(
                memory,
                arg(memory, sp, 0),
                arg(memory, sp, 1),
                "C:\\Windows\\System",
            ),
            "SetStdHandle" => Ok(1),
            "lstrcpyA" | "lstrcpynA" | "lstrcatA" => self.string_copy(name, sp, memory),
            "GetACP" => Ok(1252),
            "GetOEMCP" => Ok(437),
            "GetCPInfo" => {
                let pointer = arg(memory, sp, 1);
                memory[pointer as usize..pointer as usize + 20].fill(0);
                write_u32(memory, pointer, 1)?;
                memory[pointer as usize + 4] = b'?';
                Ok(1)
            }
            "GetStringTypeW" => {
                let count = arg(memory, sp, 2);
                let output = arg(memory, sp, 3);
                memory[output as usize..output as usize + count as usize * 2].fill(0);
                Ok(1)
            }
            "GetStringTypeA" => {
                let count = arg(memory, sp, 3);
                let output = arg(memory, sp, 4);
                memory[output as usize..output as usize + count as usize * 2].fill(0);
                Ok(1)
            }
            "LCMapStringA" => self.lc_map_a(sp, memory),
            "LCMapStringW" => self.lc_map_w(sp, memory),
            "MultiByteToWideChar" => self.multi_byte_to_wide(sp, memory),
            "WideCharToMultiByte" => self.wide_to_multi_byte(sp, memory),
            _ => Ok(self.unknown("win32.kernel32.dll", name, 1)),
        }
    }

    fn compare_string_a(&self, sp: u32, memory: &[u8]) -> Result<u32> {
        let read = |pointer: u32, count: i32| {
            if count < 0 {
                self.read_c_string(memory, pointer)
            } else {
                String::from_utf8_lossy(
                    &memory[pointer as usize..pointer as usize + count as usize],
                )
                .into_owned()
            }
        };
        let mut left = read(arg(memory, sp, 2), arg(memory, sp, 3) as i32);
        let mut right = read(arg(memory, sp, 4), arg(memory, sp, 5) as i32);
        if arg(memory, sp, 1) & 1 != 0 {
            left = left.to_ascii_lowercase();
            right = right.to_ascii_lowercase();
        }
        Ok(if left < right {
            1
        } else if left > right {
            3
        } else {
            2
        })
    }

    fn compare_string_w(&self, sp: u32, memory: &[u8]) -> Result<u32> {
        let read = |pointer: u32, count: i32| -> Result<String> {
            let mut values = Vec::new();
            let mut index = 0;
            while count < 0 || index < count as u32 {
                let value = read_u16(memory, pointer + index * 2)?;
                if count < 0 && value == 0 {
                    break;
                }
                values.push(value);
                index += 1;
            }
            Ok(String::from_utf16_lossy(&values))
        };
        let mut left = read(arg(memory, sp, 2), arg(memory, sp, 3) as i32)?;
        let mut right = read(arg(memory, sp, 4), arg(memory, sp, 5) as i32)?;
        if arg(memory, sp, 1) & 1 != 0 {
            left = left.to_lowercase();
            right = right.to_lowercase();
        }
        Ok(if left < right {
            1
        } else if left > right {
            3
        } else {
            2
        })
    }

    fn volume_information(&self, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let volume = arg(memory, sp, 1);
        if volume != 0 {
            self.write_c_string(memory, volume, arg(memory, sp, 2), "D2WASM")?;
        }
        for (index, value) in [(3, 0xd200_0101), (4, 255), (5, 3)] {
            let pointer = arg(memory, sp, index);
            if pointer != 0 {
                write_u32(memory, pointer, value)?;
            }
        }
        let filesystem = arg(memory, sp, 6);
        if filesystem != 0 {
            self.write_c_string(memory, filesystem, arg(memory, sp, 7), "FAT32")?;
        }
        Ok(1)
    }

    fn heap_realloc(&mut self, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let old = arg(memory, sp, 2);
        let size = arg(memory, sp, 3);
        let old_size = self.allocation_size(old).unwrap_or(0);
        let pointer = self.alloc(memory, size, 8)?;
        if old != 0 && old_size != 0 {
            let count = old_size.min(size) as usize;
            let bytes = memory[old as usize..old as usize + count].to_vec();
            memory[pointer as usize..pointer as usize + count].copy_from_slice(&bytes);
            self.free(old);
        }
        Ok(pointer)
    }

    fn virtual_query(&self, name: &str, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let offset = u32::from(name == "VirtualQueryEx");
        let address = arg(memory, sp, offset);
        let output = arg(memory, sp, offset + 1);
        let length = arg(memory, sp, offset + 2);
        if output == 0 || length < 28 {
            return Ok(0);
        }
        for (field, value) in [
            (0, address & 0xffff_0000),
            (4, address & 0xffff_0000),
            (8, 4),
            (12, 0x1_0000),
            (16, 0x1000),
            (20, 4),
            (24, 0x2_0000),
        ] {
            write_u32(memory, output + field, value)?;
        }
        Ok(28)
    }

    fn create_file(&mut self, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let requested = self.read_c_string(memory, arg(memory, sp, 0));
        let path = self.host_path(&requested);
        let writable = arg(memory, sp, 1) & 0x4000_0000 != 0;
        let disposition = arg(memory, sp, 4);
        if writable {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
        }
        let mut options = OpenOptions::new();
        options.read(true).write(writable);
        match disposition {
            1 if writable => {
                options.create_new(true);
            }
            2 if writable => {
                options.create(true).truncate(true);
            }
            4 if writable => {
                options.create(true);
            }
            5 if writable => {
                options.truncate(true);
            }
            _ => {}
        }
        match options.open(&path) {
            Ok(file) => Ok(self.new_handle(Handle::File(FileHandle {
                file,
                path,
                position: 0,
                writable,
            }))),
            Err(error) => {
                self.last_error = 2;
                let _ = self.event_tx.try_send(HostEvent::Log(format!(
                    "CreateFileA failed for {requested}: {error}"
                )));
                Ok(u32::MAX)
            }
        }
    }

    fn read_file(&mut self, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let handle = arg(memory, sp, 0);
        let pointer = arg(memory, sp, 1);
        let count = arg(memory, sp, 2) as usize;
        let actual = match self.handles.get_mut(&handle) {
            Some(Handle::File(item)) => {
                let position = item.position;
                let result = item.file.read_at(
                    &mut memory[pointer as usize..pointer as usize + count],
                    position,
                );
                if let Ok(actual) = result {
                    item.position = item.position.saturating_add(actual as u64);
                }
                result.map_err(|error| (item.path.clone(), position, error))
            }
            _ => {
                self.last_error = 6;
                return Ok(0);
            }
        };
        match actual {
            Ok(actual) => {
                if arg(memory, sp, 3) != 0 {
                    write_u32(memory, arg(memory, sp, 3), actual as u32)?;
                }
                Ok(1)
            }
            Err((path, position, error)) => {
                if arg(memory, sp, 3) != 0 {
                    write_u32(memory, arg(memory, sp, 3), 0)?;
                }
                self.last_error = 30;
                let _ = self.event_tx.try_send(HostEvent::Log(format!(
                    "ReadFile failed for {} at {position} requesting {count} bytes: {error}",
                    path.display()
                )));
                Ok(0)
            }
        }
    }

    fn write_file(&mut self, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let handle = arg(memory, sp, 0);
        let pointer = arg(memory, sp, 1) as usize;
        let count = arg(memory, sp, 2) as usize;
        let bytes = &memory[pointer..pointer + count];
        let actual = match self.handles.get_mut(&handle) {
            Some(Handle::File(item)) if item.writable => {
                let actual = item.file.write_at(bytes, item.position).unwrap_or(0);
                item.position = item.position.saturating_add(actual as u64);
                actual
            }
            Some(Handle::File(_)) => {
                self.last_error = 5;
                0
            }
            _ => {
                let text = String::from_utf8_lossy(bytes);
                let _ = self.event_tx.try_send(HostEvent::Log(text.into_owned()));
                count
            }
        };
        if arg(memory, sp, 3) != 0 {
            write_u32(memory, arg(memory, sp, 3), actual as u32)?;
        }
        Ok(1)
    }

    fn set_file_pointer(&mut self, sp: u32, memory: &[u8]) -> Result<u32> {
        let handle = arg(memory, sp, 0);
        let distance = arg(memory, sp, 1) as i32;
        match self.handles.get_mut(&handle) {
            Some(Handle::File(item)) => {
                let base = match arg(memory, sp, 3) {
                    1 => item.position as i128,
                    2 => item.file.metadata()?.len() as i128,
                    _ => 0,
                };
                item.position = (base + i128::from(distance)).max(0) as u64;
                Ok(item.position as u32)
            }
            _ => {
                self.last_error = 6;
                Ok(u32::MAX)
            }
        }
    }

    fn get_file_size(&mut self, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let size = match self.handles.get(&arg(memory, sp, 0)) {
            Some(Handle::File(item)) => item.file.metadata()?.len(),
            _ => {
                self.last_error = 6;
                return Ok(u32::MAX);
            }
        };
        let high = arg(memory, sp, 1);
        if high != 0 {
            write_u32(memory, high, (size >> 32) as u32)?;
        }
        Ok(size as u32)
    }

    fn flush_file(&mut self, sp: u32, memory: &[u8]) -> Result<u32> {
        if let Some(Handle::File(item)) = self.handles.get_mut(&arg(memory, sp, 0)) {
            if item.writable {
                item.file.sync_all()?;
            }
        }
        Ok(1)
    }

    fn set_end_of_file(&mut self, sp: u32, memory: &[u8]) -> Result<u32> {
        match self.handles.get_mut(&arg(memory, sp, 0)) {
            Some(Handle::File(item)) if item.writable => {
                item.file.set_len(item.position)?;
                Ok(1)
            }
            _ => Ok(0),
        }
    }

    fn find_first(&mut self, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let requested = self
            .read_c_string(memory, arg(memory, sp, 0))
            .replace('\\', "/");
        let (directory_text, pattern) = requested.rsplit_once('/').unwrap_or((".", &requested));
        let directory = self.host_path(directory_text);
        let mut names = fs::read_dir(&directory)
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| wildcard_matches(pattern, name))
            .collect::<Vec<_>>();
        names.sort();
        if names.is_empty() {
            self.last_error = 2;
            return Ok(u32::MAX);
        }
        self.write_find_data(
            memory,
            arg(memory, sp, 1),
            &directory.join(&names[0]),
            &names[0],
        )?;
        Ok(self.new_handle(Handle::Find(FindState {
            directory,
            names,
            index: 0,
        })))
    }

    fn find_next(&mut self, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let handle = arg(memory, sp, 0);
        let Some(Handle::Find(item)) = self.handles.get_mut(&handle) else {
            self.last_error = 18;
            return Ok(0);
        };
        item.index += 1;
        if item.index >= item.names.len() {
            self.last_error = 18;
            return Ok(0);
        }
        let path = item.directory.join(&item.names[item.index]);
        let name = item.names[item.index].clone();
        self.write_find_data(memory, arg(memory, sp, 1), &path, &name)?;
        Ok(1)
    }

    fn write_find_data(
        &self,
        memory: &mut [u8],
        output: u32,
        path: &Path,
        name: &str,
    ) -> Result<()> {
        memory[output as usize..output as usize + 320].fill(0);
        let metadata = fs::metadata(path)?;
        write_u32(memory, output, if metadata.is_dir() { 0x10 } else { 0x80 })?;
        write_u32(memory, output + 28, (metadata.len() >> 32) as u32)?;
        write_u32(memory, output + 32, metadata.len() as u32)?;
        self.write_c_string(memory, output + 44, 260, name)?;
        Ok(())
    }

    fn string_copy(&self, name: &str, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let destination = arg(memory, sp, 0);
        let source = self.read_c_string(memory, arg(memory, sp, 1));
        let text = if name == "lstrcatA" {
            self.read_c_string(memory, destination) + &source
        } else {
            source
        };
        let capacity = if name == "lstrcpynA" {
            arg(memory, sp, 2)
        } else {
            text.len() as u32 + 1
        };
        self.write_c_string(memory, destination, capacity, &text)?;
        Ok(destination)
    }

    fn lc_map_a(&self, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let flags = arg(memory, sp, 1);
        let source = arg(memory, sp, 2);
        let raw_count = arg(memory, sp, 3) as i32;
        let output = arg(memory, sp, 4);
        let capacity = arg(memory, sp, 5);
        let count = if raw_count < 0 {
            self.read_c_string(memory, source).len() as u32 + 1
        } else {
            raw_count as u32
        };
        if output == 0 || capacity == 0 {
            return Ok(count);
        }
        let written = count.min(capacity);
        for index in 0..written {
            let mut value = memory[source as usize + index as usize];
            if flags & 0x100 != 0 {
                value = value.to_ascii_lowercase();
            }
            if flags & 0x200 != 0 {
                value = value.to_ascii_uppercase();
            }
            memory[output as usize + index as usize] = value;
        }
        Ok(written)
    }

    fn lc_map_w(&self, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let flags = arg(memory, sp, 1);
        let source = arg(memory, sp, 2);
        let raw_count = arg(memory, sp, 3) as i32;
        let output = arg(memory, sp, 4);
        let capacity = arg(memory, sp, 5);
        let mut count = raw_count.max(0) as u32;
        if raw_count < 0 {
            while read_u16(memory, source + count * 2)? != 0 {
                count += 1;
            }
            count += 1;
        }
        if output == 0 || capacity == 0 {
            return Ok(count);
        }
        let written = count.min(capacity);
        for index in 0..written {
            let mut value = read_u16(memory, source + index * 2)?;
            if flags & 0x100 != 0 && (65..=90).contains(&value) {
                value += 32;
            }
            if flags & 0x200 != 0 && (97..=122).contains(&value) {
                value -= 32;
            }
            write_u16(memory, output + index * 2, value)?;
        }
        Ok(written)
    }

    fn multi_byte_to_wide(&self, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let input = arg(memory, sp, 2);
        let raw_count = arg(memory, sp, 3) as i32;
        let output = arg(memory, sp, 4);
        let capacity = arg(memory, sp, 5);
        let mut bytes = if raw_count < 0 {
            let mut value = self.read_c_string(memory, input).into_bytes();
            value.push(0);
            value
        } else {
            memory[input as usize..input as usize + raw_count as usize].to_vec()
        };
        if output == 0 || capacity == 0 {
            return Ok(bytes.len() as u32);
        }
        bytes.truncate(capacity as usize);
        for (index, value) in bytes.iter().enumerate() {
            write_u16(memory, output + index as u32 * 2, *value as u16)?;
        }
        Ok(bytes.len() as u32)
    }

    fn wide_to_multi_byte(&self, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let input = arg(memory, sp, 2);
        let raw_count = arg(memory, sp, 3) as i32;
        let output = arg(memory, sp, 4);
        let capacity = arg(memory, sp, 5);
        let mut count = raw_count.max(0) as u32;
        if raw_count < 0 {
            while read_u16(memory, input + count * 2)? != 0 {
                count += 1;
            }
            count += 1;
        }
        if output == 0 || capacity == 0 {
            return Ok(count);
        }
        let written = count.min(capacity);
        for index in 0..written {
            memory[output as usize + index as usize] = read_u16(memory, input + index * 2)? as u8;
        }
        Ok(written)
    }
}

fn write_u64(memory: &mut [u8], pointer: u32, value: u64) -> Result<()> {
    memory[pointer as usize..pointer as usize + 8].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase().into_bytes();
    let value = value.to_ascii_lowercase().into_bytes();
    let (mut p, mut v, mut star, mut mark) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            mark = v;
        } else if let Some(index) = star {
            p = index + 1;
            mark += 1;
            v = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}
