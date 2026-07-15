use super::*;

impl Runtime {
    pub(super) fn gdi32(&mut self, name: &str, sp: u32, memory: &mut [u8]) -> Result<u32> {
        match name {
            "GetStockObject" => Ok(0x7000_0000 | arg(memory, sp, 0)),
            "DeleteObject" | "DeleteDC" => {
                self.handles.remove(&arg(memory, sp, 0));
                Ok(1)
            }
            "CreateCompatibleDC" | "CreateDCA" => Ok(self.new_handle(Handle::Dc {
                selected: 0,
                palette: 0,
            })),
            "SelectObject" => {
                let dc = arg(memory, sp, 0);
                let selected = arg(memory, sp, 1);
                match self.handles.get_mut(&dc) {
                    Some(Handle::Dc {
                        selected: current, ..
                    }) => {
                        let previous = *current;
                        *current = selected;
                        Ok(previous)
                    }
                    _ => Ok(0),
                }
            }
            "GetCurrentObject" => Ok(match self.handles.get(&arg(memory, sp, 0)) {
                Some(Handle::Dc { selected, .. }) => *selected,
                _ => 0,
            }),
            "SetTextColor" | "SetBkColor" => Ok(0),
            "SetBkMode" | "SetTextAlign" => Ok(arg(memory, sp, 1)),
            "GetDeviceCaps" => Ok(match arg(memory, sp, 1) {
                8 => 800,
                10 => 600,
                12 => 32,
                14 => 1,
                88 | 90 => 96,
                104 => 256,
                _ => 0,
            }),
            "CreateRectRgn" => Ok(self.new_handle(Handle::Generic)),
            "CombineRgn" | "RectInRegion" => Ok(1),
            "GetRegionData" => {
                let capacity = arg(memory, sp, 1);
                let output = arg(memory, sp, 2);
                if output == 0 || capacity < 32 {
                    return Ok(32);
                }
                memory[output as usize..output as usize + 32].fill(0);
                write_u32(memory, output, 32)?;
                write_u32(memory, output + 4, 1)?;
                write_u32(memory, output + 8, 1)?;
                write_u32(memory, output + 12, 16)?;
                Ok(32)
            }
            "CreatePalette" => Ok(self.new_handle(Handle::Generic)),
            "SelectPalette" => {
                let dc = arg(memory, sp, 0);
                let palette = arg(memory, sp, 1);
                if let Some(Handle::Dc {
                    palette: current, ..
                }) = self.handles.get_mut(&dc)
                {
                    *current = palette;
                }
                Ok(0)
            }
            "RealizePalette" => Ok(256),
            "SetPaletteEntries" => Ok(arg(memory, sp, 2)),
            "GetSystemPaletteEntries" => {
                let count = arg(memory, sp, 2);
                let output = arg(memory, sp, 3);
                if output != 0 {
                    let end = output as usize + count as usize * 4;
                    memory[output as usize..end].fill(0);
                }
                Ok(count)
            }
            "CreateFontA" => Ok(self.new_handle(Handle::Generic)),
            "GetCharWidthA" => {
                let first = arg(memory, sp, 1);
                let last = arg(memory, sp, 2);
                let output = arg(memory, sp, 3);
                for value in first..=last {
                    write_u32(memory, output + (value - first) * 4, 8)?;
                }
                Ok(1)
            }
            "GetCharABCWidthsA" => {
                let first = arg(memory, sp, 1);
                let last = arg(memory, sp, 2);
                let output = arg(memory, sp, 3);
                for value in first..=last {
                    let pointer = output + (value - first) * 12;
                    write_i32(memory, pointer, 0)?;
                    write_u32(memory, pointer + 4, 8)?;
                    write_i32(memory, pointer + 8, 0)?;
                }
                Ok(1)
            }
            "GetTextExtentPoint32A" => {
                let output = arg(memory, sp, 3);
                write_i32(memory, output, arg(memory, sp, 2) as i32 * 8)?;
                write_i32(memory, output + 4, 16)?;
                Ok(1)
            }
            "CreateBitmap" => self.create_bitmap(
                memory,
                arg(memory, sp, 0) as i32,
                arg(memory, sp, 1) as i32,
                (arg(memory, sp, 2) * arg(memory, sp, 3)).max(1),
                arg(memory, sp, 4),
            ),
            "CreateCompatibleBitmap" => self.create_bitmap(
                memory,
                arg(memory, sp, 1) as i32,
                arg(memory, sp, 2) as i32,
                32,
                0,
            ),
            "CreateDIBSection" => {
                let info = arg(memory, sp, 1);
                let width = read_i32(memory, info + 4)?;
                let height = read_i32(memory, info + 8)?;
                let bits_per_pixel = read_u16(memory, info + 14)?.max(1) as u32;
                let handle = self.create_bitmap(memory, width, height, bits_per_pixel, 0)?;
                let bits_pointer = arg(memory, sp, 3);
                if bits_pointer != 0 {
                    let bits = match self.handles.get(&handle) {
                        Some(Handle::Bitmap(bitmap)) => bitmap.bits,
                        _ => 0,
                    };
                    write_u32(memory, bits_pointer, bits)?;
                }
                Ok(handle)
            }
            "GetDIBits" => {
                let handle = arg(memory, sp, 1);
                let output = arg(memory, sp, 4);
                if let Some(Handle::Bitmap(bitmap)) = self.handles.get(&handle) {
                    if output != 0 {
                        let bytes = memory
                            [bitmap.bits as usize..bitmap.bits as usize + bitmap.size]
                            .to_vec();
                        memory[output as usize..output as usize + bytes.len()]
                            .copy_from_slice(&bytes);
                    }
                    Ok(arg(memory, sp, 3))
                } else {
                    Ok(0)
                }
            }
            "SetDIBColorTable" => {
                let dc = arg(memory, sp, 0);
                let start = arg(memory, sp, 1) as usize;
                let count = arg(memory, sp, 2) as usize;
                let entries = arg(memory, sp, 3) as usize;
                let Some((handle, _)) = self.selected_bitmap(dc) else {
                    return Ok(0);
                };
                let Some(Handle::Bitmap(bitmap)) = self.handles.get_mut(&handle) else {
                    return Ok(0);
                };
                let palette = bitmap.palette.get_or_insert_with(|| vec![0; 256]);
                for index in 0..count.min(256usize.saturating_sub(start)) {
                    let pointer = entries + index * 4;
                    palette[start + index] = u32::from(memory[pointer])
                        | u32::from(memory[pointer + 1]) << 8
                        | u32::from(memory[pointer + 2]) << 16
                        | 0xff00_0000;
                }
                Ok(count as u32)
            }
            "GetPixel" => {
                let Some((_, bitmap)) = self.selected_bitmap(arg(memory, sp, 0)) else {
                    return Ok(u32::MAX);
                };
                let x = arg(memory, sp, 1) as i32;
                let y = arg(memory, sp, 2) as i32;
                if bitmap.bits_per_pixel != 32
                    || x < 0
                    || y < 0
                    || x >= bitmap.width
                    || y >= bitmap.height
                {
                    return Ok(u32::MAX);
                }
                Ok(read_u32(
                    memory,
                    bitmap.bits + y as u32 * bitmap.stride as u32 + x as u32 * 4,
                )? & 0x00ff_ffff)
            }
            "SetPixel" => {
                let Some((_, bitmap)) = self.selected_bitmap(arg(memory, sp, 0)) else {
                    return Ok(u32::MAX);
                };
                let x = arg(memory, sp, 1) as i32;
                let y = arg(memory, sp, 2) as i32;
                let color = arg(memory, sp, 3);
                if bitmap.bits_per_pixel != 32
                    || x < 0
                    || y < 0
                    || x >= bitmap.width
                    || y >= bitmap.height
                {
                    return Ok(u32::MAX);
                }
                write_u32(
                    memory,
                    bitmap.bits + y as u32 * bitmap.stride as u32 + x as u32 * 4,
                    color,
                )?;
                Ok(color)
            }
            "BitBlt" => self.bit_blt(sp, memory),
            "GdiFlush" | "GdiSetBatchLimit" => Ok(1),
            _ => Ok(self.unknown("win32.gdi32.dll", name, 0)),
        }
    }

    fn create_bitmap(
        &mut self,
        memory: &mut [u8],
        width: i32,
        height: i32,
        bits_per_pixel: u32,
        source: u32,
    ) -> Result<u32> {
        let top_down = height < 0;
        let width = width.max(1);
        let height = height.unsigned_abs().max(1) as i32;
        let stride = ((width as usize * bits_per_pixel as usize + 31) >> 5) << 2;
        let size = stride * height as usize;
        let bits = self.alloc(memory, size as u32, 4)?;
        if source != 0 {
            let bytes = memory[source as usize..source as usize + size].to_vec();
            memory[bits as usize..bits as usize + size].copy_from_slice(&bytes);
        }
        Ok(self.new_handle(Handle::Bitmap(Bitmap {
            width,
            height,
            bits_per_pixel,
            stride,
            size,
            bits,
            top_down,
            screen: false,
            palette: None,
        })))
    }

    fn bit_blt(&mut self, sp: u32, memory: &mut [u8]) -> Result<u32> {
        let Some((destination_handle, destination)) = self.selected_bitmap(arg(memory, sp, 0))
        else {
            return Ok(1);
        };
        let Some((_, source)) = self.selected_bitmap(arg(memory, sp, 5)) else {
            return Ok(1);
        };
        let dx = arg(memory, sp, 1) as i32;
        let dy = arg(memory, sp, 2) as i32;
        let width = arg(memory, sp, 3) as i32;
        let height = arg(memory, sp, 4) as i32;
        let sx = arg(memory, sp, 6) as i32;
        let sy = arg(memory, sp, 7) as i32;
        for row in 0..height {
            if dy + row < 0
                || dy + row >= destination.height
                || sy + row < 0
                || sy + row >= source.height
            {
                continue;
            }
            let count = width
                .min(destination.width - dx)
                .min(source.width - sx)
                .max(0) as usize;
            if count == 0 {
                continue;
            }
            let source_row = if source.top_down {
                sy + row
            } else {
                source.height - 1 - sy - row
            } as usize;
            let destination_row = if destination.top_down {
                dy + row
            } else {
                destination.height - 1 - dy - row
            } as usize;
            if destination.bits_per_pixel == 32 && source.bits_per_pixel == 32 {
                let input =
                    source.bits as usize + source_row * source.stride + sx.max(0) as usize * 4;
                let output = destination.bits as usize
                    + destination_row * destination.stride
                    + dx.max(0) as usize * 4;
                let bytes = memory[input..input + count * 4].to_vec();
                memory[output..output + count * 4].copy_from_slice(&bytes);
            } else if destination.bits_per_pixel == 32 && source.bits_per_pixel == 8 {
                let input = source.bits as usize + source_row * source.stride + sx.max(0) as usize;
                let output = destination.bits as usize
                    + destination_row * destination.stride
                    + dx.max(0) as usize * 4;
                for column in 0..count {
                    let value = source
                        .palette
                        .as_ref()
                        .and_then(|palette| palette.get(memory[input + column] as usize))
                        .copied()
                        .unwrap_or(0xff00_0000);
                    memory[output + column * 4..output + column * 4 + 4]
                        .copy_from_slice(&value.to_le_bytes());
                }
            } else if destination.bits_per_pixel == 8 && source.bits_per_pixel == 8 {
                let input = source.bits as usize + source_row * source.stride + sx.max(0) as usize;
                let output = destination.bits as usize
                    + destination_row * destination.stride
                    + dx.max(0) as usize;
                let bytes = memory[input..input + count].to_vec();
                memory[output..output + count].copy_from_slice(&bytes);
            }
        }
        if destination.screen {
            let bitmap = match self.handles.get(&destination_handle) {
                Some(Handle::Bitmap(bitmap)) => bitmap.clone(),
                _ => destination,
            };
            let visible_width = width
                .min(bitmap.width - dx.max(0))
                .min(source.width - sx.max(0))
                .max(1) as usize;
            let visible_height = height
                .min(bitmap.height - dy.max(0))
                .min(source.height - sy.max(0))
                .max(1) as usize;
            self.present(memory, &bitmap, visible_width, visible_height);
        }
        Ok(1)
    }
}
