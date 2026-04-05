use std::path::Path;

use regex::Regex;

use crate::analyzers::Analyzer;
use crate::types::{AnalysisContext, Finding};

use super::loader::Rule;

/// A compiled rule ready for matching.
struct CompiledRule {
    rule: Rule,
    regex: Regex,
    /// Pre-compiled glob pattern for file matching (simple glob: *.ext).
    file_glob: Option<glob::Pattern>,
}

/// Community rules engine that matches file contents against YAML-defined
/// regex patterns.
pub struct RulesEngine {
    compiled: Vec<CompiledRule>,
}

impl RulesEngine {
    /// Create a new engine, compiling all rule patterns into regexes.
    ///
    /// Rules whose patterns fail to compile are logged and skipped.
    pub fn new(rules: Vec<Rule>) -> Self {
        let compiled = rules
            .into_iter()
            .filter_map(|rule| {
                let regex = match Regex::new(&rule.pattern) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(
                            rule_id = %rule.id,
                            error = %e,
                            "skipping rule with invalid regex"
                        );
                        return None;
                    }
                };

                let file_glob = rule.file_pattern.as_ref().and_then(|pat| {
                    glob::Pattern::new(pat)
                        .map_err(|e| {
                            tracing::warn!(
                                rule_id = %rule.id,
                                error = %e,
                                "invalid file_pattern glob, ignoring"
                            );
                            e
                        })
                        .ok()
                });

                Some(CompiledRule {
                    rule,
                    regex,
                    file_glob,
                })
            })
            .collect();

        Self { compiled }
    }

    /// Check whether a file path should be excluded by the rule's
    /// `exclude_paths` list.
    fn is_excluded(path: &str, exclude_paths: &[String]) -> bool {
        let path_lower = path.to_lowercase();
        exclude_paths.iter().any(|excl| {
            let excl_lower = excl.to_lowercase();
            // Direct substring/prefix check first (handles "dist/", "test/", etc.)
            if path_lower.contains(&excl_lower) || path_lower.starts_with(&excl_lower) {
                return true;
            }
            // Then try glob pattern (handles "*.min.js", etc.)
            if let Ok(pat) = glob::Pattern::new(excl) {
                let file_name = std::path::Path::new(path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("");
                return pat.matches(file_name) || pat.matches(path);
            }
            false
        })
    }

    /// Check whether a filename matches the rule's `file_pattern` glob.
    fn matches_file_pattern(file_glob: Option<&glob::Pattern>, path: &Path) -> bool {
        match file_glob {
            None => true, // No filter means match everything.
            Some(pat) => {
                let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                pat.matches(file_name)
            }
        }
    }
}

impl Analyzer for RulesEngine {
    fn name(&self) -> &str {
        "rules"
    }

    fn analyze(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for cr in &self.compiled {
            for (path, content) in ctx.files {
                let path_str = path.to_string_lossy();

                // Check file_pattern.
                if !Self::matches_file_pattern(cr.file_glob.as_ref(), path) {
                    continue;
                }

                // Check exclude_paths.
                if Self::is_excluded(&path_str, &cr.rule.exclude_paths) {
                    continue;
                }

                // Scan line by line for matches.
                for (line_idx, line) in content.lines().enumerate() {
                    if cr.regex.is_match(line) {
                        findings.push(Finding {
                            severity: cr.rule.parsed_severity(),
                            category: cr.rule.parsed_category(),
                            title: format!("[{}] {}", cr.rule.id, cr.rule.name),
                            description: cr.rule.description.clone(),
                            file: Some(path_str.to_string()),
                            line: Some(line_idx + 1),
                            snippet: Some(crate::analyzers::truncate(line, 120)),
                        });
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::package::PackageMetadata;
    use crate::rules::loader::load_default_rules;
    use std::path::PathBuf;

    fn default_metadata() -> PackageMetadata {
        PackageMetadata {
            name: Some("test-pkg".into()),
            description: None,
            versions: std::collections::HashMap::new(),
            time: std::collections::HashMap::new(),
            maintainers: None,
            dist_tags: None,
            extra: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn engine_matches_eval_base64() {
        let engine = RulesEngine::new(load_default_rules());
        let files = vec![(
            PathBuf::from("index.js"),
            r#"var x = eval(Buffer.from("dGVzdA==", "base64").toString());"#.to_string(),
        )];
        let pkg = serde_json::Value::Object(serde_json::Map::new());
        let metadata = default_metadata();
        let tmp = Path::new("/tmp");
        let ctx = AnalysisContext {
            name: "test-pkg",
            version: "1.0.0",
            files: &files,
            package_json: &pkg,
            metadata: &metadata,
            package_dir: tmp,
        };
        let findings = engine.analyze(&ctx);
        assert!(!findings.is_empty(), "should detect eval + Buffer.from");
        assert!(findings[0].title.contains("AEGIS-001"));
    }

    #[test]
    fn engine_excludes_min_js() {
        let engine = RulesEngine::new(load_default_rules());
        let files = vec![(
            PathBuf::from("bundle.min.js"),
            r#"var x = eval(Buffer.from("dGVzdA==", "base64").toString());"#.to_string(),
        )];
        let pkg = serde_json::Value::Object(serde_json::Map::new());
        let metadata = default_metadata();
        let tmp = Path::new("/tmp");
        let ctx = AnalysisContext {
            name: "test-pkg",
            version: "1.0.0",
            files: &files,
            package_json: &pkg,
            metadata: &metadata,
            package_dir: tmp,
        };
        let findings = engine.analyze(&ctx);
        // AEGIS-001 excludes *.min.js
        let aegis001: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("AEGIS-001"))
            .collect();
        assert!(aegis001.is_empty(), "should exclude *.min.js files");
    }

    #[test]
    fn engine_skips_non_js_for_js_rules() {
        let engine = RulesEngine::new(load_default_rules());
        let files = vec![(
            PathBuf::from("readme.md"),
            r#"eval(Buffer.from("dGVzdA==", "base64"))"#.to_string(),
        )];
        let pkg = serde_json::Value::Object(serde_json::Map::new());
        let metadata = default_metadata();
        let tmp = Path::new("/tmp");
        let ctx = AnalysisContext {
            name: "test-pkg",
            version: "1.0.0",
            files: &files,
            package_json: &pkg,
            metadata: &metadata,
            package_dir: tmp,
        };
        let findings = engine.analyze(&ctx);
        let aegis001: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("AEGIS-001"))
            .collect();
        assert!(
            aegis001.is_empty(),
            "should skip non-.js files for js-only rules"
        );
    }
}
