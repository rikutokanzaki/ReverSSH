use std::collections::VecDeque;

pub enum InputEvent {
    Char(char),
    Backspace,
    Delete,
    Enter,
    Escape,
    ArrowUp,
    ArrowDown,
    ArrowRight,
    ArrowLeft,
    Tab,
    Unknown,
}

pub struct LineReader {
    buffer: String,
    cursor: usize,
    esc_buffer: Vec<u8>,
    history: VecDeque<String>,
    history_max: usize,
    history_pos: Option<usize>,
    saved_buffer: String,
}

const MAX_ESC_BUFFER: usize = 16;

impl LineReader {
    pub fn new(history_max: usize) -> Self {
        Self {
            buffer: String::new(),
            cursor: 0,
            esc_buffer: Vec::new(),
            history: VecDeque::new(),
            history_max,
            history_pos: None,
            saved_buffer: String::new(),
        }
    }

    pub fn buffer(&self) -> &str {
        &self.buffer
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn replace_buffer(&mut self, new_content: String) {
        self.buffer = new_content;
        self.cursor = self.buffer.len();
        self.history_pos = None;
    }

    pub fn get_buffer_clone(&self) -> String {
        self.buffer.clone()
    }

    pub fn feed_bytes(&mut self, data: &[u8]) -> Vec<InputEvent> {
        let mut events = Vec::new();

        for &byte in data {
            if !self.esc_buffer.is_empty() || byte == 0x1b {
                self.esc_buffer.push(byte);

                if let Some(event) = self.parse_escape() {
                    events.push(event);
                    self.esc_buffer.clear();
                } else if self.esc_buffer.len() >= MAX_ESC_BUFFER {
                    self.esc_buffer.clear();
                }

                continue;
            }

            let event = match byte {
                b'\r' | b'\n' => InputEvent::Enter,
                0x7f | 0x08 => InputEvent::Backspace,
                0x09 => InputEvent::Tab,
                _ if byte.is_ascii_graphic() || byte == b' ' => InputEvent::Char(byte as char),
                _ => InputEvent::Unknown,
            };

            events.push(event);
        }

        events
    }

    fn parse_escape(&self) -> Option<InputEvent> {
        match self.esc_buffer.as_slice() {
            [0x1b, b'[', b'A'] => Some(InputEvent::ArrowUp),
            [0x1b, b'[', b'B'] => Some(InputEvent::ArrowDown),
            [0x1b, b'[', b'C'] => Some(InputEvent::ArrowRight),
            [0x1b, b'[', b'D'] => Some(InputEvent::ArrowLeft),
            [0x1b, b'[', b'3', b'~'] => Some(InputEvent::Delete),
            _ => None,
        }
    }

    pub fn apply(&mut self, event: InputEvent) -> Option<String> {
        match event {
            InputEvent::Char(c) => {
                self.buffer.insert(self.cursor, c);
                self.cursor += 1;
                self.history_pos = None;
            }

            // Backspace
            InputEvent::Backspace => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.buffer.remove(self.cursor);
                    self.history_pos = None;
                }
            }

            // Delete
            InputEvent::Delete => {
                if self.cursor < self.buffer.len() {
                    self.buffer.remove(self.cursor);
                    self.history_pos = None;
                }
            }

            // Left
            InputEvent::ArrowLeft => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                }
            }

            // Right
            InputEvent::ArrowRight => {
                if self.cursor < self.buffer.len() {
                    self.cursor += 1;
                }
            }

            // Up
            InputEvent::ArrowUp => {
                if self.history.is_empty() {
                    return None;
                }

                if self.history_pos.is_none() {
                    self.saved_buffer = self.buffer.clone();
                    self.history_pos = Some(self.history.len() - 1);
                } else if let Some(pos) = self.history_pos {
                    if pos > 0 {
                        self.history_pos = Some(pos - 1);
                    } else {
                        return None;
                    }
                }

                if let Some(pos) = self.history_pos {
                    self.buffer = self.history[pos].clone();
                    self.cursor = self.buffer.len();
                }
            }

            // Down
            InputEvent::ArrowDown => {
                if let Some(pos) = self.history_pos {
                    if pos < self.history.len() - 1 {
                        self.history_pos = Some(pos + 1);
                        self.buffer = self.history[pos + 1].clone();
                        self.cursor = self.buffer.len();
                    }
                }
            }

            // Enter
            InputEvent::Enter => {
                let line = self.buffer.clone();

                if !line.trim().is_empty() {
                    if self.history.len() >= self.history_max {
                        self.history.pop_front();
                    }
                    self.history.push_back(line.clone());
                }

                self.buffer.clear();
                self.cursor = 0;
                self.history_pos = None;
                self.saved_buffer.clear();
                return Some(line);
            }

            _ => {}
        }
        None
    }
}
