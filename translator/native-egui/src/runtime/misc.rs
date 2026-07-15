use super::*;

impl Runtime {
    pub(super) fn format_ansi(&self, memory: &[u8], format_pointer: u32, arguments: u32) -> String {
        let format = self.read_c_string(memory, format_pointer);
        let chars = format.chars().collect::<Vec<_>>();
        let mut output = String::new();
        let mut index = 0;
        let mut argument = arguments;
        while index < chars.len() {
            if chars[index] != '%' {
                output.push(chars[index]);
                index += 1;
                continue;
            }
            index += 1;
            if chars.get(index) == Some(&'%') {
                output.push('%');
                index += 1;
                continue;
            }
            let mut zero = false;
            let mut width = 0usize;
            if chars.get(index) == Some(&'0') {
                zero = true;
                index += 1;
            }
            while let Some(digit) = chars.get(index).and_then(|value| value.to_digit(10)) {
                width = width * 10 + digit as usize;
                index += 1;
            }
            while matches!(chars.get(index), Some('l' | 'h')) {
                index += 1;
            }
            let kind = chars.get(index).copied().unwrap_or('\0');
            index += 1;
            let value = read_u32(memory, argument).unwrap_or(0);
            argument += 4;
            let mut text = match kind {
                's' | 'S' => self.read_c_string(memory, value),
                'd' | 'i' => (value as i32).to_string(),
                'u' => value.to_string(),
                'x' | 'p' => format!("{value:x}"),
                'X' => format!("{value:X}"),
                'c' => char::from_u32(value & 0xff).unwrap_or('?').to_string(),
                _ => format!("%{kind}"),
            };
            if text.len() < width {
                text = format!(
                    "{}{}",
                    if zero { "0" } else { " " }.repeat(width - text.len()),
                    text
                );
            }
            output.push_str(&text);
        }
        output
    }

    pub(super) fn advapi32(&mut self, name: &str, sp: u32, memory: &mut [u8]) -> Result<u32> {
        match name {
            "RegOpenKeyA" | "RegCreateKeyA" => self.open_registry(sp, memory, 2),
            "RegOpenKeyExA" => self.open_registry(sp, memory, 4),
            "RegCreateKeyExA" => {
                let result = self.open_registry(sp, memory, 7)?;
                let disposition = arg(memory, sp, 8);
                if disposition != 0 {
                    write_u32(memory, disposition, 1)?;
                }
                Ok(result)
            }
            "RegDeleteKeyA" => Ok(0),
            "RegDeleteValueA" => {
                let key = self
                    .read_c_string(memory, arg(memory, sp, 1))
                    .to_ascii_lowercase();
                self.registry_values.remove(&key);
                Ok(0)
            }
            "RegEnumValueA" => Ok(259),
            "RegFlushKey" => Ok(0),
            "RegQueryValueExA" => {
                let key = self
                    .read_c_string(memory, arg(memory, sp, 1))
                    .to_ascii_lowercase();
                let Some(value) = self.registry_values.get(&key).cloned() else {
                    return Ok(2);
                };
                let size_pointer = arg(memory, sp, 5);
                if size_pointer == 0 {
                    return Ok(87);
                }
                let bytes = value.as_bytes();
                let required = bytes.len() as u32 + 1;
                let capacity = read_u32(memory, size_pointer)?;
                write_u32(memory, size_pointer, required)?;
                let type_pointer = arg(memory, sp, 3);
                if type_pointer != 0 {
                    write_u32(memory, type_pointer, 1)?;
                }
                let data = arg(memory, sp, 4);
                if data == 0 {
                    return Ok(0);
                }
                if capacity < required {
                    return Ok(234);
                }
                self.write_c_string(memory, data, required, &value)?;
                Ok(0)
            }
            "RegSetValueExA" => {
                let key = self
                    .read_c_string(memory, arg(memory, sp, 1))
                    .to_ascii_lowercase();
                if arg(memory, sp, 3) == 1 && arg(memory, sp, 4) != 0 {
                    let value = self.read_c_string(memory, arg(memory, sp, 4));
                    self.registry_values.insert(key, value);
                }
                Ok(0)
            }
            "RegCloseKey" => {
                self.handles.remove(&arg(memory, sp, 0));
                Ok(0)
            }
            "GetUserNameA" => {
                let size = arg(memory, sp, 1);
                if size == 0 {
                    return Ok(0);
                }
                let capacity = read_u32(memory, size)?;
                write_u32(memory, size, 7)?;
                if arg(memory, sp, 0) == 0 || capacity < 7 {
                    self.last_error = 122;
                    Ok(0)
                } else {
                    self.write_c_string(memory, arg(memory, sp, 0), capacity, "Player")?;
                    Ok(1)
                }
            }
            "OpenSCManagerA" | "RegisterServiceCtrlHandlerA" | "CreateServiceA" => {
                Ok(self.new_handle(Handle::Generic))
            }
            "OpenServiceA" => {
                self.last_error = 1060;
                Ok(0)
            }
            "CloseServiceHandle" => {
                self.handles.remove(&arg(memory, sp, 0));
                Ok(1)
            }
            "SetServiceStatus" => Ok(1),
            "StartServiceCtrlDispatcherA" => Ok(0),
            _ => Ok(self.unknown("win32.advapi32.dll", name, 0)),
        }
    }

    fn open_registry(&mut self, sp: u32, memory: &mut [u8], output_index: u32) -> Result<u32> {
        let output = arg(memory, sp, output_index);
        if output == 0 {
            return Ok(87);
        }
        let parent = arg(memory, sp, 0);
        let subkey = self.read_c_string(memory, arg(memory, sp, 1));
        let path = format!("{}\\{subkey}", registry_root(parent));
        let handle = self.new_handle(Handle::Registry(path));
        write_u32(memory, output, handle)?;
        Ok(0)
    }

    pub(super) fn crtdll(&mut self, name: &str, sp: u32, memory: &mut [u8]) -> Result<u32> {
        match name {
            "_fullpath" => {
                let mut destination = arg(memory, sp, 0);
                let source = self
                    .read_c_string(memory, arg(memory, sp, 1))
                    .replace('/', "\\");
                let absolute = if source.as_bytes().get(1) == Some(&b':') {
                    source
                } else {
                    format!("{}\\{source}", self.current_directory)
                };
                if destination == 0 {
                    destination = self.alloc(memory, absolute.len() as u32 + 1, 1)?;
                }
                let capacity = if arg(memory, sp, 0) == 0 {
                    absolute.len() as u32 + 1
                } else {
                    arg(memory, sp, 2)
                };
                self.write_c_string(memory, destination, capacity, &absolute)?;
                Ok(destination)
            }
            "_stricmp" | "_strnicmp" | "strncmp" => {
                let mut left = self.read_c_string(memory, arg(memory, sp, 0));
                let mut right = self.read_c_string(memory, arg(memory, sp, 1));
                if matches!(name, "_strnicmp" | "strncmp") {
                    left.truncate(arg(memory, sp, 2) as usize);
                    right.truncate(arg(memory, sp, 2) as usize);
                }
                if name != "strncmp" {
                    left = left.to_ascii_lowercase();
                    right = right.to_ascii_lowercase();
                }
                Ok(if left < right {
                    u32::MAX
                } else if left > right {
                    1
                } else {
                    0
                })
            }
            "_strupr" => {
                let pointer = arg(memory, sp, 0);
                let value = self.read_c_string(memory, pointer).to_ascii_uppercase();
                self.write_c_string(memory, pointer, value.len() as u32 + 1, &value)?;
                Ok(pointer)
            }
            "_vsnprintf" | "vsprintf" => {
                let destination = arg(memory, sp, 0);
                let (capacity, format, arguments) = if name == "_vsnprintf" {
                    (arg(memory, sp, 1), arg(memory, sp, 2), arg(memory, sp, 3))
                } else {
                    (
                        u32::MAX - destination,
                        arg(memory, sp, 1),
                        arg(memory, sp, 2),
                    )
                };
                let text = self.format_ansi(memory, format, arguments);
                self.write_c_string(memory, destination, capacity, &text)?;
                Ok(text.len() as u32)
            }
            "memmove" => {
                let destination = arg(memory, sp, 0) as usize;
                let source = arg(memory, sp, 1) as usize;
                let count = arg(memory, sp, 2) as usize;
                let bytes = memory[source..source + count].to_vec();
                memory[destination..destination + count].copy_from_slice(&bytes);
                Ok(destination as u32)
            }
            "setlocale" => self.alloc_c_string(memory, "C"),
            "strpbrk" => {
                let pointer = arg(memory, sp, 0);
                let text = self.read_c_string(memory, pointer);
                let accepted = self.read_c_string(memory, arg(memory, sp, 1));
                Ok(text
                    .find(|value| accepted.contains(value))
                    .map(|index| pointer + index as u32)
                    .unwrap_or(0))
            }
            "strstr" => {
                let pointer = arg(memory, sp, 0);
                let text = self.read_c_string(memory, pointer);
                let needle = self.read_c_string(memory, arg(memory, sp, 1));
                Ok(text
                    .find(&needle)
                    .map(|index| pointer + index as u32)
                    .unwrap_or(0))
            }
            "strtol" | "strtoul" => self.parse_integer(sp, memory),
            "toupper" => {
                let value = arg(memory, sp, 0);
                Ok(if (b'a' as u32..=b'z' as u32).contains(&value) {
                    value - 32
                } else {
                    value
                })
            }
            "wcslen" => {
                let pointer = arg(memory, sp, 0);
                let mut length = 0;
                while read_u16(memory, pointer + length * 2)? != 0 {
                    length += 1;
                }
                Ok(length)
            }
            "wcstombs" => {
                let destination = arg(memory, sp, 0);
                let source = arg(memory, sp, 1);
                let capacity = arg(memory, sp, 2);
                let mut bytes = Vec::new();
                while let Ok(value) = read_u16(memory, source + bytes.len() as u32 * 2) {
                    if value == 0 {
                        break;
                    }
                    bytes.push(if value <= 0xff { value as u8 } else { b'?' });
                }
                let text = String::from_utf8_lossy(&bytes);
                if destination != 0 && capacity != 0 {
                    self.write_c_string(memory, destination, capacity, &text)?;
                }
                Ok(bytes.len() as u32)
            }
            _ => Ok(self.unknown("win32.crtdll.dll", name, 0)),
        }
    }

    fn parse_integer(&self, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let input = arg(memory, sp, 0);
        let text = self.read_c_string(memory, input);
        let trimmed = text.trim_start();
        let requested_base = arg(memory, sp, 2);
        let base = if requested_base != 0 {
            requested_base
        } else if trimmed.trim_start_matches(['+', '-']).starts_with("0x") {
            16
        } else if trimmed.starts_with('0') {
            8
        } else {
            10
        };
        let signed = trimmed.starts_with('-');
        let digits = trimmed
            .trim_start_matches(['+', '-'])
            .trim_start_matches("0x");
        let count = digits
            .chars()
            .take_while(|value| value.to_digit(base).is_some())
            .count();
        let value = u32::from_str_radix(&digits[..count], base).unwrap_or(0);
        let end = arg(memory, sp, 1);
        if end != 0 {
            write_u32(
                memory,
                end,
                input + (text.len() - trimmed.len() + count) as u32,
            )?;
        }
        Ok(if signed {
            0u32.wrapping_sub(value)
        } else {
            value
        })
    }

    pub(super) fn version(&mut self, name: &str, sp: u32, memory: &mut [u8]) -> Result<u32> {
        match name {
            "GetFileVersionInfoSizeA" => {
                let ignored = arg(memory, sp, 1);
                if ignored != 0 {
                    write_u32(memory, ignored, 0)?;
                }
                Ok(512)
            }
            "GetFileVersionInfoA" => {
                let capacity = arg(memory, sp, 2);
                let block = arg(memory, sp, 3);
                if block == 0 || capacity < 256 {
                    return Ok(0);
                }
                memory[block as usize..block as usize + capacity as usize].fill(0);
                for (offset, value) in [
                    (0, 0xfeef_04bd),
                    (4, 0x0001_0000),
                    (8, 0x0001_0001),
                    (12, 0x0002_0010),
                    (16, 0x0001_0001),
                    (20, 0x0002_0010),
                ] {
                    write_u32(memory, block + offset, value)?;
                }
                self.write_c_string(memory, block + 0x80, capacity - 0x80, "1.1.2.16")?;
                self.write_c_string(memory, block + 0xc0, capacity - 0xc0, "ijl11.dll")?;
                Ok(1)
            }
            "VerQueryValueA" => {
                let block = arg(memory, sp, 0);
                let query = self
                    .read_c_string(memory, arg(memory, sp, 1))
                    .to_ascii_lowercase();
                let (value, length) = if query.contains("productversion") {
                    (block + 0x80, 9)
                } else if query.contains("originalfilename") {
                    (block + 0xc0, 10)
                } else if query == "\\" {
                    (block, 52)
                } else {
                    return Ok(0);
                };
                write_u32(memory, arg(memory, sp, 2), value)?;
                write_u32(memory, arg(memory, sp, 3), length)?;
                Ok(1)
            }
            _ => Ok(0),
        }
    }

    pub(super) fn imm32(&mut self, name: &str, sp: u32, memory: &mut [u8]) -> Result<u32> {
        match name {
            "ImmGetContext"
            | "ImmReleaseContext"
            | "ImmSetOpenStatus"
            | "ImmSetConversionStatus" => Ok(1),
            "ImmGetConversionStatus" => {
                for index in [1, 2] {
                    let pointer = arg(memory, sp, index);
                    if pointer != 0 {
                        write_u32(memory, pointer, 0)?;
                    }
                }
                Ok(1)
            }
            "ImmGetCandidateListCountA" => {
                let pointer = arg(memory, sp, 1);
                if pointer != 0 {
                    write_u32(memory, pointer, 0)?;
                }
                Ok(0)
            }
            _ => Ok(0),
        }
    }

    pub(super) fn wsock32(&mut self, name: &str, sp: u32, memory: &mut [u8]) -> Result<u32> {
        match name {
            "#1" | "#16" | "#19" => {
                self.last_error = 10035;
                Ok(u32::MAX)
            }
            "#4" => {
                self.last_error = 10061;
                Ok(u32::MAX)
            }
            "#3" => {
                self.handles.remove(&arg(memory, sp, 0));
                Ok(0)
            }
            "#9" => {
                let value = arg(memory, sp, 0);
                Ok((value & 0xff) << 8 | (value >> 8) & 0xff)
            }
            "#10" => {
                let parts = self
                    .read_c_string(memory, arg(memory, sp, 0))
                    .split('.')
                    .filter_map(|part| part.parse::<u8>().ok())
                    .collect::<Vec<_>>();
                Ok(if parts.len() == 4 {
                    u32::from(parts[0])
                        | u32::from(parts[1]) << 8
                        | u32::from(parts[2]) << 16
                        | u32::from(parts[3]) << 24
                } else {
                    u32::MAX
                })
            }
            "#11" => {
                let value = arg(memory, sp, 0);
                self.alloc_c_string(
                    memory,
                    &format!(
                        "{}.{}.{}.{}",
                        value & 0xff,
                        value >> 8 & 0xff,
                        value >> 16 & 0xff,
                        value >> 24 & 0xff
                    ),
                )
            }
            "#23" => Ok(self.new_handle(Handle::Socket)),
            "#57" => {
                self.write_c_string(memory, arg(memory, sp, 0), arg(memory, sp, 1), "d2wasm")?;
                Ok(0)
            }
            "#111" => Ok(self.last_error),
            "#112" => {
                self.last_error = arg(memory, sp, 0);
                Ok(0)
            }
            "#115" => {
                let data = arg(memory, sp, 1);
                memory[data as usize..data as usize + 400].fill(0);
                write_u16(memory, data, 0x0101)?;
                write_u16(memory, data + 2, 0x0101)?;
                self.write_c_string(memory, data + 4, 257, "D2Wasm Winsock 1.1")?;
                self.write_c_string(memory, data + 261, 129, "Running")?;
                write_u16(memory, data + 390, 64)?;
                write_u16(memory, data + 392, 64)?;
                Ok(0)
            }
            _ => Ok(0),
        }
    }
}

fn registry_root(handle: u32) -> String {
    match handle {
        0x8000_0000 => "HKEY_CLASSES_ROOT".into(),
        0x8000_0001 => "HKEY_CURRENT_USER".into(),
        0x8000_0002 => "HKEY_LOCAL_MACHINE".into(),
        0x8000_0003 => "HKEY_USERS".into(),
        0x8000_0005 => "HKEY_CURRENT_CONFIG".into(),
        _ => format!("HKEY_{handle:x}"),
    }
}
