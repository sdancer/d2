use crate::protocol::{HostEvent, InputEvent};
use eframe::egui;
use std::sync::mpsc::{Receiver, Sender};

pub struct D2App {
    events: Receiver<HostEvent>,
    input: Sender<InputEvent>,
    texture: Option<egui::TextureHandle>,
    framebuffer_size: [usize; 2],
    presentation: u64,
    status: String,
    logs: Vec<String>,
}

impl D2App {
    pub fn new(events: Receiver<HostEvent>, input: Sender<InputEvent>) -> Self {
        Self {
            events,
            input,
            texture: None,
            framebuffer_size: [800, 600],
            presentation: 0,
            status: String::from("Starting native host…"),
            logs: Vec::new(),
        }
    }

    fn receive(&mut self, context: &egui::Context) {
        while let Ok(event) = self.events.try_recv() {
            match event {
                HostEvent::Frame {
                    width,
                    height,
                    rgba,
                    presentation,
                } => {
                    let image = egui::ColorImage::from_rgba_unmultiplied([width, height], &rgba);
                    if let Some(texture) = self.texture.as_mut() {
                        texture.set(image, egui::TextureOptions::NEAREST);
                    } else {
                        self.texture = Some(context.load_texture(
                            "d2-framebuffer",
                            image,
                            egui::TextureOptions::NEAREST,
                        ));
                    }
                    self.framebuffer_size = [width, height];
                    self.presentation = presentation;
                    context.request_repaint();
                }
                HostEvent::Status(status) => self.status = status,
                HostEvent::Log(log) => {
                    self.logs.push(log);
                    if self.logs.len() > 256 {
                        self.logs.drain(..128);
                    }
                }
                HostEvent::Stopped(status) => {
                    self.status = status.clone();
                    self.logs.push(status);
                }
            }
        }
    }

    fn forward_input(&self, context: &egui::Context, screen: egui::Rect) {
        let framebuffer = egui::vec2(
            self.framebuffer_size[0] as f32,
            self.framebuffer_size[1] as f32,
        );
        let map = |position: egui::Pos2| -> Option<(i32, i32)> {
            if !screen.contains(position) {
                return None;
            }
            let local = (position - screen.min) / screen.size();
            Some((
                (local.x * framebuffer.x).clamp(0.0, framebuffer.x - 1.0) as i32,
                (local.y * framebuffer.y).clamp(0.0, framebuffer.y - 1.0) as i32,
            ))
        };
        for event in context.input(|input| input.events.clone()) {
            let translated = match event {
                egui::Event::PointerMoved(position) => {
                    map(position).map(|(x, y)| InputEvent::PointerMoved { x, y })
                }
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    ..
                } => map(pos).map(|(x, y)| InputEvent::MouseButton {
                    x,
                    y,
                    down: pressed,
                }),
                egui::Event::Text(text) => {
                    for character in text.chars() {
                        let _ = self.input.send(InputEvent::Character(character));
                    }
                    None
                }
                egui::Event::Key { key, pressed, .. } => {
                    virtual_key(key).map(|virtual_key| InputEvent::Key {
                        virtual_key,
                        down: pressed,
                    })
                }
                _ => None,
            };
            if let Some(event) = translated {
                let _ = self.input.send(event);
            }
        }
    }
}

impl eframe::App for D2App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let context = ui.ctx().clone();
        self.receive(&context);
        ui.horizontal(|ui| {
            ui.strong("Diablo II — native WASM host");
            ui.separator();
            ui.label(&self.status);
            ui.separator();
            ui.label(format!("presentation {}", self.presentation));
        });
        ui.separator();
        let available = ui.available_size() - egui::vec2(0.0, 145.0);
        let aspect = self.framebuffer_size[0] as f32 / self.framebuffer_size[1] as f32;
        let size = if available.x / available.y > aspect {
            egui::vec2(available.y * aspect, available.y)
        } else {
            egui::vec2(available.x, available.x / aspect)
        };
        ui.vertical_centered(|ui| {
            if let Some(texture) = &self.texture {
                let response = ui.add(
                    egui::Image::new((texture.id(), size))
                        .texture_options(egui::TextureOptions::NEAREST)
                        .sense(egui::Sense::click_and_drag()),
                );
                self.forward_input(&context, response.rect);
            } else {
                ui.spinner();
            }
        });
        ui.separator();
        ui.collapsing("Host diagnostics", |ui| {
            ui.small(
                "Mouse and keyboard events over the game surface are forwarded as Win32 messages.",
            );
            egui::ScrollArea::vertical()
                .max_height(100.0)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for line in &self.logs {
                        ui.monospace(line);
                    }
                });
        });
        context.request_repaint_after(std::time::Duration::from_millis(16));
    }
}

impl Drop for D2App {
    fn drop(&mut self) {
        let _ = self.input.send(InputEvent::Quit);
    }
}

fn virtual_key(key: egui::Key) -> Option<u32> {
    Some(match key {
        egui::Key::ArrowLeft => 0x25,
        egui::Key::ArrowUp => 0x26,
        egui::Key::ArrowRight => 0x27,
        egui::Key::ArrowDown => 0x28,
        egui::Key::Escape => 0x1b,
        egui::Key::Tab => 0x09,
        egui::Key::Backspace => 0x08,
        egui::Key::Enter => 0x0d,
        egui::Key::Space => 0x20,
        egui::Key::Insert => 0x2d,
        egui::Key::Delete => 0x2e,
        egui::Key::Home => 0x24,
        egui::Key::End => 0x23,
        egui::Key::PageUp => 0x21,
        egui::Key::PageDown => 0x22,
        egui::Key::A => 0x41,
        egui::Key::B => 0x42,
        egui::Key::C => 0x43,
        egui::Key::D => 0x44,
        egui::Key::E => 0x45,
        egui::Key::F => 0x46,
        egui::Key::G => 0x47,
        egui::Key::H => 0x48,
        egui::Key::I => 0x49,
        egui::Key::J => 0x4a,
        egui::Key::K => 0x4b,
        egui::Key::L => 0x4c,
        egui::Key::M => 0x4d,
        egui::Key::N => 0x4e,
        egui::Key::O => 0x4f,
        egui::Key::P => 0x50,
        egui::Key::Q => 0x51,
        egui::Key::R => 0x52,
        egui::Key::S => 0x53,
        egui::Key::T => 0x54,
        egui::Key::U => 0x55,
        egui::Key::V => 0x56,
        egui::Key::W => 0x57,
        egui::Key::X => 0x58,
        egui::Key::Y => 0x59,
        egui::Key::Z => 0x5a,
        egui::Key::Num0 => 0x30,
        egui::Key::Num1 => 0x31,
        egui::Key::Num2 => 0x32,
        egui::Key::Num3 => 0x33,
        egui::Key::Num4 => 0x34,
        egui::Key::Num5 => 0x35,
        egui::Key::Num6 => 0x36,
        egui::Key::Num7 => 0x37,
        egui::Key::Num8 => 0x38,
        egui::Key::Num9 => 0x39,
        _ => return None,
    })
}
