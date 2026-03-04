use std::sync::Arc;

use crate::router::migration::{CompositeDetector, Detector, KeywordDetector};

pub fn build_detector() -> Arc<dyn Detector> {
    Arc::new(CompositeDetector {
        detectors: vec![
            Arc::new(KeywordDetector::new(&["wget", "curl"], "cowrie2")),
            // Arc::new(RegexDetector::new(r"nc\s+-", "cowrie2")),
        ],
    })
}
