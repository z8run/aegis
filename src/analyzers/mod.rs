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

use crate::types::{AnalysisContext, Finding};

/// Trait that all security analyzers must implement.
///
/// Analyzers receive an `AnalysisContext` containing all data they may need:
/// file contents, package.json, registry metadata, and the package directory.
pub trait Analyzer: Send + Sync {
    /// A short, unique name for this analyzer (used in diagnostics/logging).
    fn name(&self) -> &str;

    /// Run the analysis and return any findings.
    fn analyze(&self, ctx: &AnalysisContext) -> Vec<Finding>;
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
