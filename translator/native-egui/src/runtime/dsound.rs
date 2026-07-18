use super::*;

const DSOUND_PC_BASE: u32 = 0xfffe_0000;
const DSERR_INVALIDPARAM: u32 = 0x8007_0057;
const DSERR_INVALIDCALL: u32 = 0x8878_0032;

impl Runtime {
    pub(super) fn dsound(&mut self, name: &str, sp: u32, memory: &mut [u8]) -> Result<u32> {
        match name {
            "#1" => {
                let output = arg(memory, sp, 1);
                if output == 0 {
                    return Ok(DSERR_INVALIDPARAM);
                }
                let object = self.create_com_object(memory, 0, 11)?;
                self.direct_sound_objects.insert(object);
                if let Err(error) = write_u32(memory, output, object) {
                    self.release_com_object(object);
                    return Err(error);
                }
                Ok(0)
            }
            _ => Ok(self.unknown("win32.dsound.dll", name, 0)),
        }
    }

    pub(crate) fn dispatch_dsound_method(
        &mut self,
        method: u32,
        sp: u32,
        memory: &mut [u8],
    ) -> Result<u32> {
        let object = arg(memory, sp, 0);
        if method <= 2 || (32..=34).contains(&method) {
            let relative = if method >= 32 { method - 32 } else { method };
            return match relative {
                0 => {
                    if self.add_com_reference(object).is_none() {
                        return Ok(DSERR_INVALIDCALL);
                    }
                    let output = arg(memory, sp, 2);
                    if output != 0 {
                        write_u32(memory, output, object)?;
                    }
                    Ok(0)
                }
                1 => Ok(self.add_com_reference(object).unwrap_or(0)),
                _ => Ok(self.release_com_object(object)),
            };
        }
        if method < 32 {
            return self.dispatch_direct_sound_object(method, sp, object, memory);
        }
        self.dispatch_sound_buffer(method - 32, sp, object, memory)
    }

    fn create_com_object(
        &mut self,
        memory: &mut [u8],
        method_base: u32,
        method_count: u32,
    ) -> Result<u32> {
        let vtable = self.alloc(memory, method_count * 4, 4)?;
        for method in 0..method_count {
            write_u32(
                memory,
                vtable + method * 4,
                DSOUND_PC_BASE + (method_base + method) * 4,
            )?;
        }
        let object = match self.alloc(memory, 4, 4) {
            Ok(object) => object,
            Err(error) => {
                self.free(vtable);
                return Err(error);
            }
        };
        if let Err(error) = write_u32(memory, object, vtable) {
            self.free(object);
            self.free(vtable);
            return Err(error);
        }
        self.com_objects.insert(
            object,
            ComObject {
                vtable,
                references: 1,
            },
        );
        Ok(object)
    }

    fn add_com_reference(&mut self, object: u32) -> Option<u32> {
        let allocation = self.com_objects.get_mut(&object)?;
        allocation.references = allocation.references.saturating_add(1);
        Some(allocation.references)
    }

    fn release_com_object(&mut self, object: u32) -> u32 {
        let Some(allocation) = self.com_objects.get_mut(&object) else {
            return 0;
        };
        if allocation.references > 1 {
            allocation.references -= 1;
            return allocation.references;
        }
        let allocation = self.com_objects.remove(&object).expect("checked above");
        self.direct_sound_objects.remove(&object);
        if let Some(buffer) = self.sound_buffers.remove(&object) {
            if self.audio_output_enabled {
                let _ = self
                    .event_tx
                    .try_send(HostEvent::AudioStop { id: buffer.id });
            }
            if buffer.bytes != 0 {
                self.free(buffer.bytes);
            }
        }
        self.free(object);
        self.free(allocation.vtable);
        0
    }

    fn read_wave_format(&self, memory: &[u8], pointer: u32) -> Result<WaveFormat> {
        if pointer == 0 {
            return Ok(WaveFormat {
                format_tag: 1,
                channels: 2,
                samples_per_second: 22_050,
                average_bytes_per_second: 88_200,
                block_align: 4,
                bits_per_sample: 16,
            });
        }
        Ok(WaveFormat {
            format_tag: read_u16(memory, pointer)?,
            channels: read_u16(memory, pointer + 2)?,
            samples_per_second: read_u32(memory, pointer + 4)?,
            average_bytes_per_second: read_u32(memory, pointer + 8)?,
            block_align: read_u16(memory, pointer + 12)?,
            bits_per_sample: read_u16(memory, pointer + 14)?,
        })
    }

    fn write_wave_format(memory: &mut [u8], pointer: u32, format: &WaveFormat) -> Result<()> {
        write_u16(memory, pointer, format.format_tag)?;
        write_u16(memory, pointer + 2, format.channels)?;
        write_u32(memory, pointer + 4, format.samples_per_second)?;
        write_u32(memory, pointer + 8, format.average_bytes_per_second)?;
        write_u16(memory, pointer + 12, format.block_align)?;
        write_u16(memory, pointer + 14, format.bits_per_sample)?;
        write_u16(memory, pointer + 16, 0)
    }

    fn sound_bytes_per_second(buffer: &SoundBuffer) -> u64 {
        let base_rate = u64::from(buffer.format.samples_per_second.max(1));
        (u64::from(buffer.format.average_bytes_per_second) * u64::from(buffer.frequency.max(1))
            / base_rate)
            .max(1)
    }

    fn refresh_sound_playback(&mut self, object: u32, now: u32) {
        let buffer = self.sound_buffers.get_mut(&object).expect("checked above");
        if !buffer.playing || buffer.play_flags & 1 != 0 || buffer.size == 0 {
            return;
        }
        let elapsed = u64::from(now.wrapping_sub(buffer.play_started));
        if elapsed * Self::sound_bytes_per_second(buffer) >= u64::from(buffer.size) * 1_000 {
            buffer.playing = false;
        }
    }

    fn dispatch_direct_sound_object(
        &mut self,
        method: u32,
        sp: u32,
        object: u32,
        memory: &mut [u8],
    ) -> Result<u32> {
        if !self.direct_sound_objects.contains(&object) {
            return Ok(DSERR_INVALIDCALL);
        }
        match method {
            3 => {
                let descriptor = arg(memory, sp, 1);
                let output = arg(memory, sp, 2);
                if descriptor == 0 || output == 0 {
                    return Ok(DSERR_INVALIDPARAM);
                }
                let flags = read_u32(memory, descriptor + 4)?;
                let primary = flags & 1 != 0;
                let size = if primary {
                    0
                } else {
                    read_u32(memory, descriptor + 8)?
                };
                let format = self.read_wave_format(memory, read_u32(memory, descriptor + 16)?)?;
                let buffer_object = self.create_com_object(memory, 32, 21)?;
                let bytes = if primary || size == 0 {
                    0
                } else {
                    match self.alloc(memory, size, 16) {
                        Ok(bytes) => bytes,
                        Err(error) => {
                            self.release_com_object(buffer_object);
                            return Err(error);
                        }
                    }
                };
                let id = self.next_sound_id;
                self.next_sound_id += 1;
                self.sound_buffers.insert(
                    buffer_object,
                    SoundBuffer {
                        id,
                        primary,
                        flags,
                        size,
                        bytes,
                        frequency: format.samples_per_second,
                        format,
                        volume: 0,
                        pan: 0,
                        playing: false,
                        play_flags: 0,
                        play_started: 0,
                    },
                );
                if let Err(error) = write_u32(memory, output, buffer_object) {
                    self.release_com_object(buffer_object);
                    return Err(error);
                }
            }
            4 => {
                let output = arg(memory, sp, 1);
                if output != 0 {
                    let size = read_u32(memory, output)?.min(96);
                    if size > 4 {
                        memory[output as usize + 4..output as usize + size as usize].fill(0);
                    }
                    if size >= 8 {
                        write_u32(memory, output + 4, 0x3f)?;
                    }
                }
            }
            8 => {
                let output = arg(memory, sp, 1);
                if output != 0 {
                    write_u32(memory, output, 4)?;
                }
            }
            _ => {}
        }
        Ok(0)
    }

    fn dispatch_sound_buffer(
        &mut self,
        method: u32,
        sp: u32,
        object: u32,
        memory: &mut [u8],
    ) -> Result<u32> {
        if !self.sound_buffers.contains_key(&object) {
            return Ok(DSERR_INVALIDCALL);
        }
        match method {
            3 => {
                let output = arg(memory, sp, 1);
                let buffer = &self.sound_buffers[&object];
                if output != 0 {
                    let size = read_u32(memory, output)?.min(32);
                    if size > 4 {
                        memory[output as usize + 4..output as usize + size as usize].fill(0);
                    }
                    if size >= 8 {
                        write_u32(memory, output + 4, buffer.flags)?;
                    }
                    if size >= 12 {
                        write_u32(memory, output + 8, buffer.size)?;
                    }
                }
            }
            4 => {
                let now = self.clock_now();
                let buffer = &self.sound_buffers[&object];
                let elapsed = u64::from(if buffer.playing {
                    now.wrapping_sub(buffer.play_started)
                } else {
                    0
                });
                let played = elapsed * Self::sound_bytes_per_second(buffer) / 1_000;
                let size = buffer.size;
                let looping = buffer.play_flags & 1 != 0;
                let block_align = buffer.format.block_align;
                self.refresh_sound_playback(object, now);
                let cursor = if size == 0 {
                    0
                } else if looping {
                    (played % u64::from(size)) as u32
                } else {
                    played.min(u64::from(size - 1)) as u32
                };
                let play = arg(memory, sp, 1);
                let write = arg(memory, sp, 2);
                if play != 0 {
                    write_u32(memory, play, cursor)?;
                }
                if write != 0 {
                    let ahead = u32::from(block_align) * 4;
                    write_u32(
                        memory,
                        write,
                        if size == 0 {
                            0
                        } else {
                            (cursor + ahead) % size
                        },
                    )?;
                }
            }
            5 => {
                let output = arg(memory, sp, 1);
                let capacity = arg(memory, sp, 2);
                let written = arg(memory, sp, 3);
                let buffer = &self.sound_buffers[&object];
                if output != 0 && capacity >= 18 {
                    Self::write_wave_format(memory, output, &buffer.format)?;
                }
                if written != 0 {
                    write_u32(memory, written, 18)?;
                }
            }
            6..=9 => {
                if method == 9 {
                    let now = self.clock_now();
                    self.refresh_sound_playback(object, now);
                }
                let output = arg(memory, sp, 1);
                if output != 0 {
                    let buffer = &self.sound_buffers[&object];
                    let value = match method {
                        6 => buffer.volume as u32,
                        7 => buffer.pan as u32,
                        8 => buffer.frequency,
                        _ => {
                            u32::from(buffer.playing)
                                | if buffer.playing && buffer.play_flags & 1 != 0 {
                                    4
                                } else {
                                    0
                                }
                        }
                    };
                    write_u32(memory, output, value)?;
                }
            }
            11 => {
                let buffer = &self.sound_buffers[&object];
                if buffer.bytes == 0 || buffer.size == 0 {
                    return Ok(DSERR_INVALIDCALL);
                }
                let offset = arg(memory, sp, 1) % buffer.size;
                let mut count = arg(memory, sp, 2);
                if arg(memory, sp, 7) & 2 != 0 || count == 0 {
                    count = buffer.size;
                }
                count = count.min(buffer.size);
                let first = count.min(buffer.size - offset);
                let second = count - first;
                write_u32(memory, arg(memory, sp, 3), buffer.bytes + offset)?;
                write_u32(memory, arg(memory, sp, 4), first)?;
                let second_pointer = arg(memory, sp, 5);
                let second_size = arg(memory, sp, 6);
                if second_pointer != 0 {
                    write_u32(
                        memory,
                        second_pointer,
                        if second == 0 { 0 } else { buffer.bytes },
                    )?;
                }
                if second_size != 0 {
                    write_u32(memory, second_size, second)?;
                }
            }
            12 => {
                let now = self.clock_now();
                let buffer = self.sound_buffers.get_mut(&object).expect("checked above");
                buffer.play_flags = arg(memory, sp, 3);
                buffer.playing = true;
                buffer.play_started = now;
                self.emit_sound(object, memory)?;
            }
            13 => {
                let now = self.clock_now();
                let position = arg(memory, sp, 1);
                let buffer = self.sound_buffers.get_mut(&object).expect("checked above");
                let elapsed = u64::from(position) * 1000
                    / u64::from(buffer.format.average_bytes_per_second.max(1));
                buffer.play_started = now.wrapping_sub(elapsed as u32);
            }
            14 => {
                let format = self.read_wave_format(memory, arg(memory, sp, 1))?;
                let buffer = self.sound_buffers.get_mut(&object).expect("checked above");
                buffer.frequency = format.samples_per_second;
                buffer.format = format;
            }
            15 => {
                self.sound_buffers
                    .get_mut(&object)
                    .expect("checked above")
                    .volume = arg(memory, sp, 1) as i32
            }
            16 => {
                self.sound_buffers
                    .get_mut(&object)
                    .expect("checked above")
                    .pan = arg(memory, sp, 1) as i32
            }
            17 => {
                self.sound_buffers
                    .get_mut(&object)
                    .expect("checked above")
                    .frequency = arg(memory, sp, 1)
            }
            18 => {
                let buffer = self.sound_buffers.get_mut(&object).expect("checked above");
                buffer.playing = false;
                if self.audio_output_enabled {
                    let _ = self
                        .event_tx
                        .try_send(HostEvent::AudioStop { id: buffer.id });
                }
            }
            _ => {}
        }
        Ok(0)
    }

    fn emit_sound(&self, object: u32, memory: &[u8]) -> Result<()> {
        if !self.audio_output_enabled {
            return Ok(());
        }
        let buffer = &self.sound_buffers[&object];
        if buffer.primary || buffer.bytes == 0 || buffer.size == 0 || buffer.format.format_tag != 1
        {
            return Ok(());
        }
        let bytes = memory
            .get(buffer.bytes as usize..buffer.bytes as usize + buffer.size as usize)
            .context("DirectSound buffer exceeds Wasm memory")?;
        let samples = match buffer.format.bits_per_sample {
            8 => bytes
                .iter()
                .map(|sample| (*sample as f32 - 128.0) / 128.0)
                .collect(),
            16 => bytes
                .chunks_exact(2)
                .map(|sample| i16::from_le_bytes([sample[0], sample[1]]) as f32 / 32768.0)
                .collect(),
            _ => return Ok(()),
        };
        let volume = 10.0_f32.powf(buffer.volume as f32 / 2000.0).clamp(0.0, 1.0);
        let _ = self.event_tx.try_send(HostEvent::AudioPlay {
            id: buffer.id,
            channels: buffer.format.channels.clamp(1, 2),
            sample_rate: buffer.frequency.max(8_000),
            samples,
            looping: buffer.play_flags & 1 != 0,
            volume,
        });
        Ok(())
    }
}
