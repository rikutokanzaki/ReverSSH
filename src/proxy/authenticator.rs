use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub struct Credentials {
    pub username: String,
    pub password: String,
}

pub type AuthResult = String;

pub trait Authentication: Send + Sync {
    fn auth(&self, username: &str, password: &str) -> Option<AuthResult>;
}

#[derive(Debug, Clone)]
enum PasswordRule {
    Deny(String),
    DenyRegex(Regex),
    Allow(String),
    Wildcard,
}

#[derive(Debug, Clone)]
struct AuthRule {
    username_pattern: String,
    password_rule: PasswordRule,
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
        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| Self::parse_line(line))
            .collect()
    }

    fn parse_line(line: &str) -> Option<AuthRule> {
        let parts: Vec<&str> = line.splitn(2, ':').collect();

        if parts.len() != 2 {
            return None;
        }

        let username_pattern = parts[0].to_string();
        let password_str = parts[1];

        let password_rule = if password_str == "*" {
            PasswordRule::Wildcard
        } else if let Some(stripped) = password_str.strip_prefix('!') {
            if stripped.starts_with('/') && stripped.ends_with("/i") {
                let pattern = &stripped[1..stripped.len() - 2];

                if let Ok(regex) = Regex::new(&format!("(?i){}", pattern)) {
                    PasswordRule::DenyRegex(regex)
                } else {
                    return None;
                }
            } else if stripped.starts_with('/') && stripped.ends_with('/') {
                let pattern = &stripped[1..stripped.len() - 1];

                if let Ok(regex) = Regex::new(pattern) {
                    PasswordRule::DenyRegex(regex)
                } else {
                    return None;
                }
            } else {
                PasswordRule::Deny(stripped.to_string())
            }
        } else if password_str.starts_with('/') && password_str.ends_with("/i") {
            let pattern = &password_str[1..password_str.len() - 2];

            if let Ok(regex) = Regex::new(&format!("(?i){}", pattern)) {
                PasswordRule::DenyRegex(regex)
            } else {
                return None;
            }
        } else if password_str.starts_with('/') && password_str.ends_with('/') {
            let pattern = &password_str[1..password_str.len() - 1];

            if let Ok(regex) = Regex::new(pattern) {
                PasswordRule::DenyRegex(regex)
            } else {
                return None;
            }
        } else {
            PasswordRule::Allow(password_str.to_string())
        };

        Some(AuthRule {
            username_pattern,
            password_rule,
        })
    }

    fn matches_rule(&self, rule: &AuthRule, username: &str, password: &str) -> Option<bool> {
        let username_match = rule.username_pattern == "*" || rule.username_pattern == username;

        if !username_match {
            return None;
        }

        match &rule.password_rule {
            PasswordRule::Wildcard => Some(true),
            PasswordRule::Allow(allowed_pwd) => Some(allowed_pwd == password),
            PasswordRule::Deny(denied_pwd) => {
                if denied_pwd == password {
                    Some(false)
                } else {
                    None
                }
            }
            PasswordRule::DenyRegex(regex) => {
                if regex.is_match(password) {
                    Some(false)
                } else {
                    None
                }
            }
        }
    }
}

impl Authentication for FileBasedAuthenticator {
    fn auth(&self, username: &str, password: &str) -> Option<AuthResult> {
        for rule in &self.rules {
            if let Some(result) = self.matches_rule(rule, username, password) {
                return if result {
                    Some(username.to_string())
                } else {
                    None
                };
            }
        }
        None
    }
}

pub fn load_allowed_usernames<P: AsRef<Path>>(path: P) -> Result<HashSet<String>, std::io::Error> {
    let content = fs::read_to_string(path.as_ref())?;
    let mut set = HashSet::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.splitn(2, ':');
        let username = parts.next().unwrap_or("").trim();

        if username.is_empty() || username == "*" {
            continue;
        }

        set.insert(username.to_string());
    }

    Ok(set)
}
