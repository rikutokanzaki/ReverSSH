use regex::Regex;
use std::sync::Arc;

use crate::terminal::state::CmdInfo;

pub trait Detector: Send + Sync {
    fn detect(&self, cmd: &CmdInfo) -> Option<String>;
}

pub struct KeywordDetector {
    pub keywords: Vec<String>,
    pub target: String,
}

impl KeywordDetector {
    pub fn new(keywords: &[&str], target: &str) -> Self {
        Self {
            keywords: keywords.iter().map(|s| s.to_string()).collect(),
            target: target.to_string(),
        }
    }
}

pub struct RegexDetector {
    pub re: Regex,
    pub target: String,
}

impl RegexDetector {
    pub fn new(pattern: &str, target: &str) -> Self {
        Self {
            re: Regex::new(pattern).expect("Invalid regex pattern"),
            target: target.to_string(),
        }
    }
}

pub struct CompositeDetector {
    pub detectors: Vec<Arc<dyn Detector>>,
}

impl Detector for KeywordDetector {
    fn detect(&self, cmd_info: &CmdInfo) -> Option<String> {
        if self
            .keywords
            .iter()
            .any(|kw| cmd_info.cmd.contains(kw.as_str()))
        {
            Some(self.target.clone())
        } else {
            None
        }
    }
}

impl Detector for RegexDetector {
    fn detect(&self, cmd_info: &CmdInfo) -> Option<String> {
        if self.re.is_match(&cmd_info.cmd) {
            Some(self.target.clone())
        } else {
            None
        }
    }
}

impl Detector for CompositeDetector {
    fn detect(&self, cmd_info: &CmdInfo) -> Option<String> {
        for detector in &self.detectors {
            if let Some(target) = detector.detect(cmd_info) {
                return Some(target);
            }
        }
        None
    }
}
