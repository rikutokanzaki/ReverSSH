use lazy_static::lazy_static;
use regex::Regex;

pub struct TerminalOutputParser;

lazy_static! {
    static ref ANSI_ESCAPE_RE: Regex =
        Regex::new(r"\x1b\[[0-9;]*[a-zA-Z]").expect("Invalid regex pattern");
}

impl TerminalOutputParser {
    pub fn is_prompt(data: &[u8]) -> bool {
        if let Ok(text) = std::str::from_utf8(data) {
            let ansi_stripped = ANSI_ESCAPE_RE.replace_all(text, "");
            return ansi_stripped
                .lines()
                .rfind(|line| !line.trim().is_empty())
                .map(|line| line.trim_end().ends_with(['$', '#']))
                .unwrap_or(false);
        }

        false
    }

    pub fn extract_cwd_from_output(data: &[u8]) -> Option<String> {
        let text = String::from_utf8_lossy(data);
        let ansi_stripped = ANSI_ESCAPE_RE.replace_all(&text, "");
        let last_line = ansi_stripped
            .lines()
            .rfind(|line| !line.trim().is_empty())?
            .trim_end();
        let prompt_end = last_line
            .char_indices()
            .rfind(|(_, c)| *c == '$' || *c == '#')
            .map(|(index, _)| index)?;
        let prompt = &last_line[..prompt_end];
        let colon = prompt.rfind(':')?;
        let cwd = prompt[colon + 1..].trim();

        (!cwd.is_empty()).then(|| cwd.to_string())
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

        if matches!(lines.last(), Some(last) if last.trim_end().ends_with(['$', '#'])) {
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
            if let Some(prompt_end) = last_line.rfind(['$', '#']) {
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

#[cfg(test)]
mod tests {
    use super::TerminalOutputParser;

    #[test]
    fn recognizes_prompts_without_trailing_space() {
        assert!(TerminalOutputParser::is_prompt(b"alice@host.example:/tmp$"));
        assert!(TerminalOutputParser::is_prompt(b"root@host.example:/tmp# "));
    }

    #[test]
    fn extracts_cwd_from_hosts_with_dots() {
        assert_eq!(
            TerminalOutputParser::extract_cwd_from_output(b"cd /tmp\r\nalice@host.example:/tmp$"),
            Some("/tmp".to_string())
        );
    }
}
