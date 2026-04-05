pub mod ast;
pub mod binary;
pub(crate) mod comment_strip;
pub mod cve;
pub mod dataflow;
pub mod deptree;
pub mod diff;
pub mod hallucination;
pub mod install_scripts;
pub mod maintainer;
pub mod obfuscation;
pub mod provenance;
pub mod static_code;

use std::path::PathBuf;

use crate::types::Finding;

/// Trait that all security analyzers must implement.
///
/// `files` contains (path, content) tuples for every file in the package.
/// `package_json` is the parsed package.json value.
pub trait Analyzer {
    fn analyze(
        &self,
        files: &[(PathBuf, String)],
        package_json: &serde_json::Value,
    ) -> Vec<Finding>;
}

/// Helper: truncate a string to at most `max` characters, appending "..." if truncated.
pub(crate) fn truncate(s: &str, max: usize) -> String {
    let trimmed = s.trim();
    if trimmed.chars().count() <= max {
        trimmed.to_string()
    } else {
        let truncated: String = trimmed.chars().take(max).collect();
        format!("{truncated}...")
    }
}
