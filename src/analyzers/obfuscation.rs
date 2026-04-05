use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::types::{AnalysisContext, Finding, FindingCategory, Severity};

use super::{truncate, Analyzer};

// ---------------------------------------------------------------------------
// Regex helpers
// ---------------------------------------------------------------------------

fn re_long_hex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"[0-9a-fA-F]{50,}"#).unwrap())
}

fn re_long_base64() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Base64 chars in a continuous run of 100+, ending with optional padding
        Regex::new(r#"[A-Za-z0-9+/]{100,}={0,2}"#).unwrap()
    })
}

fn re_hex_escapes() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // 4+ consecutive \xNN or \uNNNN escapes
        Regex::new(r#"(?:\\x[0-9a-fA-F]{2}){4,}|(?:\\u[0-9a-fA-F]{4}){4,}"#).unwrap()
    })
}

// ---------------------------------------------------------------------------
// Shannon entropy
// ---------------------------------------------------------------------------

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<u8, usize> = HashMap::new();
    for &b in s.as_bytes() {
        *freq.entry(b).or_insert(0) += 1;
    }
    let len = s.len() as f64;
    freq.values().fold(0.0f64, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

/// Detects obfuscated or encoded code patterns.
pub struct ObfuscationAnalyzer;

impl Analyzer for ObfuscationAnalyzer {
    fn name(&self) -> &str {
        "obfuscation"
    }

    fn analyze(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        let hex_re = re_long_hex();
        let b64_re = re_long_base64();
        let esc_re = re_hex_escapes();

        for (path, content) in ctx.files {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

            // Only scan JS/TS/JSON files
            if !matches!(ext, "js" | "cjs" | "mjs" | "ts" | "tsx" | "jsx" | "json") {
                continue;
            }

            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let is_minified_file = file_name.contains(".min.");

            // Skip minified files entirely — they always look "obfuscated"
            if is_minified_file {
                continue;
            }

            // Skip dist/bundle directories entirely — build outputs always look obfuscated
            let path_str = path.display().to_string();
            let path_lower = path_str.to_lowercase();
            let is_dist = path_lower.contains("/dist/")
                || path_lower.contains("/bundle/")
                || path_lower.contains("/build/")
                || path_lower.contains("/umd/")
                || path_lower.contains("/cjs/")
                || path_lower.contains("/esm/")
                || path_lower.starts_with("dist/")
                || path_lower.starts_with("bundle/")
                || path_lower.starts_with("build/")
                || path_lower.starts_with("umd/")
                || path_lower.starts_with("cjs/")
                || path_lower.starts_with("esm/");
            if is_dist {
                continue;
            }

            for (line_num, line) in content.lines().enumerate() {
                let ln = line_num + 1;

                // CRITICAL: long hex strings
                if hex_re.is_match(line) {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        category: FindingCategory::Obfuscation,
                        title: "Long hex string detected".to_string(),
                        description:
                            "A hex string longer than 50 characters may be an encoded payload"
                                .to_string(),
                        file: Some(path.display().to_string()),
                        line: Some(ln),
                        snippet: Some(truncate(line, 100)),
                    });
                }

                // HIGH: long base64 strings
                if b64_re.is_match(line) {
                    // Skip common false positives: package-lock.json integrity hashes,
                    // data URIs in test fixtures, etc.
                    let trimmed = line.trim();
                    let is_integrity =
                        trimmed.starts_with("\"integrity\"") || trimmed.starts_with("\"sha");
                    if !is_integrity {
                        findings.push(Finding {
                            severity: Severity::High,
                            category: FindingCategory::Obfuscation,
                            title: "Long base64 string detected".to_string(),
                            description: "A base64 string longer than 100 characters may be an encoded payload".to_string(),
                            file: Some(path.display().to_string()),
                            line: Some(ln),
                            snippet: Some(truncate(line, 100)),
                        });
                    }
                }

                // HIGH: high entropy lines (only for lines > 100 chars)
                if line.len() > 100 {
                    let entropy = shannon_entropy(line);
                    if entropy > 5.5 {
                        findings.push(Finding {
                            severity: Severity::High,
                            category: FindingCategory::Obfuscation,
                            title: "High entropy line".to_string(),
                            description: format!(
                                "Line has Shannon entropy {:.2} (threshold 5.5), suggesting obfuscated content",
                                entropy
                            ),
                            file: Some(path.display().to_string()),
                            line: Some(ln),
                            snippet: Some(truncate(line, 100)),
                        });
                    }
                }

                // MEDIUM: excessive hex/unicode escapes
                if esc_re.is_match(line) {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        category: FindingCategory::Obfuscation,
                        title: "Excessive string escaping".to_string(),
                        description:
                            "Bulk \\x or \\u escape sequences often indicate obfuscated strings"
                                .to_string(),
                        file: Some(path.display().to_string()),
                        line: Some(ln),
                        snippet: Some(truncate(line, 100)),
                    });
                }

                // LOW: suspiciously long lines in source files
                if line.len() > 500 {
                    findings.push(Finding {
                        severity: Severity::Low,
                        category: FindingCategory::Obfuscation,
                        title: "Minified code in non-minified file".to_string(),
                        description: format!(
                            "Line is {} chars long in a non-.min.js file -- possible obfuscation",
                            line.len()
                        ),
                        file: Some(path.display().to_string()),
                        line: Some(ln),
                        snippet: Some(truncate(line, 100)),
                    });
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_uniform() {
        // All same char -> entropy 0
        let e = shannon_entropy("aaaaaaaaaa");
        assert!((e - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_shannon_entropy_high() {
        // Random-looking string should have higher entropy
        let e = shannon_entropy("aB3$xZ9!qW7@mK2&");
        assert!(e > 3.0);
    }
}
