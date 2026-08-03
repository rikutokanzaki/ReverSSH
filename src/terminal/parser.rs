use lazy_static::lazy_static;
use regex::Regex;

pub struct TerminalOutputParser;

lazy_static! {
    static ref ANSI_ESCAPE_RE: Regex =
        Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").expect("Invalid regex pattern");
    static ref PROMPT_CWD_RE: Regex =
        Regex::new(r"[\w-]+@[\w-]+:(.*?)[\$#]\s*$").expect("Invalid prompt regex");
}

impl TerminalOutputParser {
    pub fn is_prompt(data: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(data) {
            let ansi_stripped = ANSI_ESCAPE_RE.replace_all(text, "");
            let lines: Vec<&str> = ansi_stripped.lines().collect();

            if let Some(last_line) = lines.last() {
                return last_line.ends_with("$ ") || last_line.ends_with("# ");
            }
        }

        false
    }

    pub fn extract_cwd_from_output(data: &[u8]) -> Option<String> {
        let text = String::from_utf8_lossy(data);
        let ansi_stripped = ANSI_ESCAPE_RE.replace_all(&text, "");
        let lines: Vec<&str> = ansi_stripped.lines().collect();

        if let Some(last_line) = lines.last() {
            if let Some(captures) = PROMPT_CWD_RE.captures(last_line) {
                if let Some(cwd_match) = captures.get(1) {
                    return Some(cwd_match.as_str().to_string());
                }
            }
        }

        None
    }

    pub fn clean_output(data: &[u8], cmd: &str) -> Vec<u8> {
        let text = String::from_utf8_lossy(data);
        let ansi_stripped = ANSI_ESCAPE_RE.replace_all(&text, "");
        let mut lines: Vec<&str> = ansi_stripped.lines().collect();

        if !lines.is_empty() {
            let echo_ascii: String = lines[0].trim().chars().filter(|c| c.is_ascii()).collect();
            let cmd_ascii: String = cmd.chars().filter(|c| c.is_ascii()).collect();

            if !cmd_ascii.is_empty() && echo_ascii.ends_with(&cmd_ascii) {
                lines.remove(0);
            }
        }

        if matches!(lines.last(), Some(last) if last.ends_with("$ ") || last.ends_with("# ")) {
            lines.pop();
        }

        while lines.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
            lines.pop();
        }

        let result = lines.join("\r\n");

        if !result.is_empty() {
            format!("{}\r\n", result).into_bytes()
        } else {
            Vec::new()
        }
    }

    pub fn extract_completed_line(data: &[u8]) -> Option<String> {
        let text = String::from_utf8_lossy(data);
        let ansi_stripped = ANSI_ESCAPE_RE.replace_all(&text, "");

        if ansi_stripped.trim().is_empty() {
            return None;
        }

        let lines: Vec<&str> = ansi_stripped
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect();

        if let Some(last_line) = lines.last() {
            if let Some(prompt_end) = last_line.find(|c| c == '$' || c == '#') {
                let command_part = last_line[prompt_end + 1..].trim_start();
                return Some(command_part.to_string());
            }

            let trimmed = last_line.trim();
            let words: Vec<&str> = trimmed.split_whitespace().collect();

            if words.is_empty() {
                return None;
            }

            if words.len() == 1 {
                return Some(words[0].to_string());
            }

            return Some(format!("{} {}", words[0], words[words.len() - 1]));
        }

        None
    }
}
