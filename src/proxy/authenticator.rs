use std::fs;

type AuthRule = (String, String);

pub type AuthResult = String;

pub trait Authentication: Send + Sync {
    fn auth(&self, username: &str, password: &str) -> Option<AuthResult>;
}

pub struct FileBasedAuthenticator {
    rules: Vec<AuthRule>,
}

impl FileBasedAuthenticator {
    pub fn new(file_path: &str) -> Result<Self, std::io::Error> {
        let content = fs::read_to_string(file_path)?;
        let rules = Self::parse_rules(&content);

        Ok(Self { rules })
    }

    fn parse_rules(content: &str) -> Vec<AuthRule> {
        content.lines().filter_map(Self::parse_line).collect()
    }

    fn parse_line(line: &str) -> Option<AuthRule> {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || !trimmed.contains(':') {
            return None;
        }

        let mut parts = trimmed.splitn(2, ':');
        let user = parts.next()?.to_string();
        let pass = parts.next()?.to_string();
        Some((user, pass))
    }
}

impl Authentication for FileBasedAuthenticator {
    fn auth(&self, username: &str, password: &str) -> Option<AuthResult> {
        for (rule_user, rule_pass) in &self.rules {
            if rule_user == username || rule_user == "*" {
                if rule_pass == "*" {
                    return Some(username.to_string());
                }

                if let Some(denied) = rule_pass.strip_prefix('!') {
                    if password != denied {
                        return Some(username.to_string());
                    }
                    return None;
                }

                if password == rule_pass {
                    return Some(username.to_string());
                }
                return None;
            }
        }
        None
    }
}
