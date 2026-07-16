use super::*;

impl Runtime {
    pub(super) fn user32(
        &mut self,
        name: &str,
        sp: u32,
        memory: &mut [u8],
    ) -> Result<DispatchResult> {
        let value = match name {
            "MessageBoxA" => {
                let text = self.read_c_string(memory, arg(memory, sp, 1));
                let caption = self.read_c_string(memory, arg(memory, sp, 2));
                self.message_box(caption, text);
                1
            }
            "LoadStringA" => {
                let output = arg(memory, sp, 2);
                let capacity = arg(memory, sp, 3);
                if output != 0 && capacity != 0 {
                    memory[output as usize] = 0;
                }
                0
            }
            "GetSystemMetrics" => match arg(memory, sp, 0) {
                0 => SCREEN_WIDTH as u32,
                1 => SCREEN_HEIGHT as u32,
                32 | 33 => 8,
                _ => 0,
            },
            "GetDesktopWindow" => 1,
            "GetDC" => {
                let screen = self.ensure_screen_bitmap(memory)?;
                self.new_handle(Handle::Dc {
                    selected: screen,
                    palette: 0,
                })
            }
            "ReleaseDC" => {
                self.handles.remove(&arg(memory, sp, 1));
                1
            }
            "DrawTextA" => 16,
            "GetActiveWindow" => self.active_window.max(1),
            "IsWindow"
            | "IsWindowVisible"
            | "ShowWindow"
            | "UpdateWindow"
            | "SetWindowPos"
            | "AdjustWindowRectEx"
            | "ScreenToClient"
            | "InvalidateRect"
            | "UnregisterClassA"
            | "TranslateMessage"
            | "CopyRect"
            | "LoadCursorA"
            | "LoadImageA"
            | "SetForegroundWindow"
            | "OpenClipboard"
            | "CloseClipboard"
            | "KillTimer" => {
                if name == "CopyRect" {
                    let output = arg(memory, sp, 0) as usize;
                    let input = arg(memory, sp, 1) as usize;
                    let bytes = memory[input..input + 16].to_vec();
                    memory[output..output + 16].copy_from_slice(&bytes);
                }
                1
            }
            "DestroyWindow" => {
                self.handles.remove(&arg(memory, sp, 0));
                1
            }
            "SetFocus" => {
                let previous = self.active_window;
                self.active_window = arg(memory, sp, 0);
                previous
            }
            "GetWindowLongA"
            | "IsIconic"
            | "GetKeyState"
            | "GetAsyncKeyState"
            | "TranslateAcceleratorA"
            | "DefWindowProcA"
            | "FindWindowA" => 0,
            "GetWindowThreadProcessId" => {
                let process = arg(memory, sp, 1);
                if process != 0 {
                    write_u32(memory, process, 1)?;
                }
                1
            }
            "SetRect" => {
                let pointer = arg(memory, sp, 0);
                for index in 0..4 {
                    write_i32(
                        memory,
                        pointer + index * 4,
                        arg(memory, sp, index + 1) as i32,
                    )?;
                }
                1
            }
            "GetClientRect" | "GetWindowRect" => {
                let pointer = arg(memory, sp, 1);
                write_i32(memory, pointer, 0)?;
                write_i32(memory, pointer + 4, 0)?;
                write_i32(memory, pointer + 8, SCREEN_WIDTH as i32)?;
                write_i32(memory, pointer + 12, SCREEN_HEIGHT as i32)?;
                1
            }
            "GetWindowPlacement" => {
                let pointer = arg(memory, sp, 1);
                memory[pointer as usize..pointer as usize + 44].fill(0);
                write_u32(memory, pointer, 44)?;
                write_u32(memory, pointer + 8, 1)?;
                write_i32(memory, pointer + 36, SCREEN_WIDTH as i32)?;
                write_i32(memory, pointer + 40, SCREEN_HEIGHT as i32)?;
                1
            }
            "PtInRect" => {
                let pointer = arg(memory, sp, 0);
                let x = arg(memory, sp, 1) as i32;
                let y = arg(memory, sp, 2) as i32;
                u32::from(
                    x >= read_i32(memory, pointer)?
                        && x < read_i32(memory, pointer + 8)?
                        && y >= read_i32(memory, pointer + 4)?
                        && y < read_i32(memory, pointer + 12)?,
                )
            }
            "GetCursorPos" => {
                let pointer = arg(memory, sp, 0);
                write_i32(memory, pointer, self.cursor_x)?;
                write_i32(memory, pointer + 4, self.cursor_y)?;
                1
            }
            "RegisterClassA" => {
                let definition = arg(memory, sp, 0);
                let name_pointer = read_u32(memory, definition + 36)?;
                let class_name = if name_pointer <= 0xffff {
                    format!("#{name_pointer}")
                } else {
                    self.read_c_string(memory, name_pointer)
                        .to_ascii_lowercase()
                };
                let atom = self.next_window_atom;
                self.next_window_atom += 1;
                let item = WindowClass {
                    atom,
                    wnd_proc: read_u32(memory, definition + 4)?,
                };
                self.window_classes.insert(class_name, item.clone());
                self.window_classes.insert(format!("#{atom}"), item);
                atom
            }
            "CreateWindowExA" => {
                let class_pointer = arg(memory, sp, 1);
                let class_name = if class_pointer <= 0xffff {
                    format!("#{class_pointer}")
                } else {
                    self.read_c_string(memory, class_pointer)
                        .to_ascii_lowercase()
                };
                let wnd_proc = self
                    .window_classes
                    .get(&class_name)
                    .map(|item| item.wnd_proc)
                    .unwrap_or(0);
                let handle = self.new_handle(Handle::Window {
                    wnd_proc,
                    width: arg(memory, sp, 6) as i32,
                    height: arg(memory, sp, 7) as i32,
                });
                self.active_window = handle;
                let _ = self.event_tx.try_send(HostEvent::Status(format!(
                    "Created game window ({class_name}, HWND {handle:#x})"
                )));
                handle
            }
            "PeekMessageA" | "GetMessageA" => {
                let output = arg(memory, sp, 0);
                let hwnd = arg(memory, sp, 1);
                let minimum = arg(memory, sp, 2);
                let maximum = arg(memory, sp, 3);
                let index = self.messages.iter().position(|message| {
                    (hwnd == 0 || message.hwnd == hwnd)
                        && ((minimum == 0 && maximum == 0)
                            || (message.message >= minimum && message.message <= maximum))
                });
                let Some(index) = index else {
                    return Ok(DispatchResult::Value(0));
                };
                let message = self.messages[index].clone();
                self.write_message(memory, output, &message)?;
                if name == "GetMessageA" || arg(memory, sp, 4) & 1 != 0 {
                    self.messages.remove(index);
                }
                if message.message == 0x12 { 0 } else { 1 }
            }
            "DispatchMessageA" => {
                let pointer = arg(memory, sp, 0);
                let hwnd = read_u32(memory, pointer)?;
                let wnd_proc = match self.handles.get(&hwnd) {
                    Some(Handle::Window { wnd_proc, .. }) => *wnd_proc,
                    _ => 0,
                };
                if wnd_proc == 0 {
                    0
                } else {
                    return Ok(DispatchResult::Invoke(InvokeRequest {
                        address: wnd_proc,
                        arguments: vec![
                            hwnd,
                            read_u32(memory, pointer + 4)?,
                            read_u32(memory, pointer + 8)?,
                            read_u32(memory, pointer + 12)?,
                        ],
                    }));
                }
            }
            "SendMessageA" => {
                let hwnd = arg(memory, sp, 0);
                let wnd_proc = match self.handles.get(&hwnd) {
                    Some(Handle::Window { wnd_proc, .. }) => *wnd_proc,
                    _ => 0,
                };
                if wnd_proc == 0 {
                    0
                } else {
                    return Ok(DispatchResult::Invoke(InvokeRequest {
                        address: wnd_proc,
                        arguments: vec![
                            hwnd,
                            arg(memory, sp, 1),
                            arg(memory, sp, 2),
                            arg(memory, sp, 3),
                        ],
                    }));
                }
            }
            "IntersectRect" => {
                let output = arg(memory, sp, 0);
                let left = arg(memory, sp, 1);
                let right = arg(memory, sp, 2);
                let values = [
                    read_i32(memory, left)?.max(read_i32(memory, right)?),
                    read_i32(memory, left + 4)?.max(read_i32(memory, right + 4)?),
                    read_i32(memory, left + 8)?.min(read_i32(memory, right + 8)?),
                    read_i32(memory, left + 12)?.min(read_i32(memory, right + 12)?),
                ];
                for (index, value) in values.iter().enumerate() {
                    write_i32(memory, output + index as u32 * 4, *value)?;
                }
                u32::from(values[0] < values[2] && values[1] < values[3])
            }
            "SetCursorPos" => {
                self.cursor_x = arg(memory, sp, 0) as i32;
                self.cursor_y = arg(memory, sp, 1) as i32;
                1
            }
            "GetKeyboardLayout" => 0x0409_0409,
            "LoadAcceleratorsA" => 1,
            "SetTimer" => arg(memory, sp, 2).max(1),
            "RegisterWindowMessageA" => 0xc000,
            "PostQuitMessage" => 0,
            "EmptyClipboard" => {
                self.clipboard.clear();
                1
            }
            "SetClipboardData" => {
                let format = arg(memory, sp, 0);
                let value = arg(memory, sp, 1);
                self.clipboard.insert(format, value);
                value
            }
            "GetClipboardData" => self
                .clipboard
                .get(&arg(memory, sp, 0))
                .copied()
                .unwrap_or(0),
            "IsClipboardFormatAvailable" => {
                u32::from(self.clipboard.contains_key(&arg(memory, sp, 0)))
            }
            "ShowCursor" => {
                self.show_cursor_count += if arg(memory, sp, 0) != 0 { 1 } else { -1 };
                self.show_cursor_count as u32
            }
            "wsprintfA" | "wvsprintfA" => {
                let destination = arg(memory, sp, 0);
                let format_pointer = arg(memory, sp, 1);
                let arguments = if name == "wsprintfA" {
                    sp + 8
                } else {
                    arg(memory, sp, 2)
                };
                let text = self.format_ansi(memory, format_pointer, arguments);
                self.write_c_string(memory, destination, text.len() as u32 + 1, &text)?;
                text.len() as u32
            }
            _ => self.unknown("win32.user32.dll", name, 0),
        };
        Ok(DispatchResult::Value(value))
    }

    fn write_message(&mut self, memory: &mut [u8], pointer: u32, message: &Message) -> Result<()> {
        write_u32(memory, pointer, message.hwnd)?;
        write_u32(memory, pointer + 4, message.message)?;
        write_u32(memory, pointer + 8, message.w_param)?;
        write_u32(memory, pointer + 12, message.l_param)?;
        write_u32(memory, pointer + 16, self.clock_now())?;
        write_i32(memory, pointer + 20, self.cursor_x)?;
        write_i32(memory, pointer + 24, self.cursor_y)?;
        Ok(())
    }
}
