mod game;
mod gameplay;
mod manifest;
mod pe;
mod protocol;
mod runtime;
mod ui;

use anyhow::{Result, anyhow};
use eframe::egui;
use game::RunnerOptions;
use protocol::HostEvent;
use std::{sync::mpsc, thread};
use ui::D2App;

fn main() -> Result<()> {
    let options = RunnerOptions::from_args()?;
    let (event_tx, event_rx) = mpsc::sync_channel(128);
    let (input_tx, input_rx) = mpsc::channel();
    thread::Builder::new()
        .name(String::from("d2-wasmtime"))
        .spawn(move || {
            if let Err(error) = game::run(options, event_tx.clone(), input_rx) {
                eprintln!("Native host failed: {error:#}");
                let _ = event_tx.send(HostEvent::Stopped(format!("Native host failed: {error:#}")));
            }
        })?;

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Diablo II — egui WASM host")
            .with_inner_size([1180.0, 720.0])
            .with_min_inner_size([800.0, 600.0]),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "d2-egui",
        native_options,
        Box::new(move |_creation_context| Ok(Box::new(D2App::new(event_rx, input_tx)))),
    )
    .map_err(|error| anyhow!(error.to_string()))
}
