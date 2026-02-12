use regex::Regex;
use std::sync::Arc;

use crate::terminal::state::CmdInfo;

pub trait Detector: Send + Sync {
    fn detect(&self, cmd: &CmdInfo) -> Option<String>;
}

pub struct KeywordDetector {
    pub keyword: String,
    pub target: String,
}

pub struct RegexDetector {
    pub re: Regex,
    pub target: String,
}

pub struct CompositeDetector {
    pub detectors: Vec<Arc<dyn Detector>>,
}

impl Detector for KeywordDetector {
    fn detect(&self, cmd_info: &CmdInfo) -> Option<String> {
        if cmd_info.cmd.contains(&self.keyword) {
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
