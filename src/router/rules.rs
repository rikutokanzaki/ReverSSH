use std::sync::Arc;

use crate::router::migration::{CompositeDetector, Detector, KeywordDetector, RegexDetector};

pub fn build_detector() -> Arc<dyn Detector> {
    Arc::new(CompositeDetector {
        detectors: vec![
            // Arc::new(KeywordDetector::new(&["wget", "curl"], "download")),
            // Arc::new(RegexDetector::new(r"nc\s+-", "allow_all")),
        ],
    })
}
