#[derive(Clone, Debug)]
pub enum HostEvent {
    Frame {
        width: usize,
        height: usize,
        input_width: usize,
        input_height: usize,
        rgba: Vec<u8>,
        presentation: u64,
    },
    Status(String),
    Log(String),
    Stopped(String),
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InputEvent {
    PointerMoved { x: i32, y: i32 },
    MouseButton { x: i32, y: i32, down: bool },
    Character(char),
    Key { virtual_key: u32, down: bool },
    Quit,
}
