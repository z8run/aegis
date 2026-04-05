//! SARIF v2.1.0 output for integration with GitHub's Security tab.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::types::{AnalysisReport, FindingCategory, Severity};

/// Generate a SARIF v2.1.0 JSON document from one or more analysis reports.
pub fn generate_sarif(reports: &[AnalysisReport]) -> Value {
    // Collect all findings across reports, tagging each with its package context.
    let mut all_findings = Vec::new();
    for report in reports {
        for finding in &report.findings {
            all_findings.push((report, finding));
        }
    }

    // Build the set of unique rules (one per FindingCategory).
    let mut rules_map: BTreeMap<String, Value> = BTreeMap::new();
    for (_report, finding) in &all_findings {
        let rule_id = category_to_rule_id(&finding.category);
        rules_map.entry(rule_id.clone()).or_insert_with(|| {
            json!({
                "id": rule_id,
                "shortDescription": {
                    "text": finding.category.to_string()
                },
                "defaultConfiguration": {
                    "level": severity_to_level(&finding.severity)
                }
            })
        });
    }
    let rules: Vec<Value> = rules_map.values().cloned().collect();

    // Build results array.
    let results: Vec<Value> = all_findings
        .iter()
        .map(|(report, finding)| {
            let rule_id = category_to_rule_id(&finding.category);
            let level = severity_to_level(&finding.severity);

            let fallback_uri = format!("{}@{}", report.package_name, report.version);
            let uri = finding.file.as_deref().unwrap_or(&fallback_uri);

            let start_line = finding.line.unwrap_or(1);

            json!({
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": finding.description
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri
                        },
                        "region": {
                            "startLine": start_line
                        }
                    }
                }]
            })
        })
        .collect();

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "aegis-scan",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/z8run/aegis",
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

/// Map a `FindingCategory` to a stable SARIF rule ID string.
fn category_to_rule_id(category: &FindingCategory) -> String {
    match category {
        FindingCategory::CodeExecution => "aegis/code-execution".to_string(),
        FindingCategory::NetworkAccess => "aegis/network-access".to_string(),
        FindingCategory::ProcessSpawn => "aegis/process-spawn".to_string(),
        FindingCategory::FileSystemAccess => "aegis/filesystem-access".to_string(),
        FindingCategory::Obfuscation => "aegis/obfuscation".to_string(),
        FindingCategory::InstallScript => "aegis/install-script".to_string(),
        FindingCategory::EnvAccess => "aegis/env-access".to_string(),
        FindingCategory::Suspicious => "aegis/suspicious".to_string(),
        FindingCategory::MaintainerChange => "aegis/maintainer-change".to_string(),
        FindingCategory::HallucinatedPackage => "aegis/hallucinated-package".to_string(),
        FindingCategory::KnownVulnerability => "aegis/known-vulnerability".to_string(),
        FindingCategory::DependencyRisk => "aegis/dependency-risk".to_string(),
        FindingCategory::Provenance => "aegis/provenance".to_string(),
        FindingCategory::BinaryFile => "aegis/binary-file".to_string(),
        FindingCategory::DataFlow => "aegis/data-flow".to_string(),
    }
}

/// Map `Severity` to the SARIF `level` string.
fn severity_to_level(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Finding, RiskLabel};

    fn make_report(findings: Vec<Finding>) -> AnalysisReport {
        AnalysisReport {
            package_name: "test-pkg".to_string(),
            version: "1.0.0".to_string(),
            findings,
            risk_score: 5.0,
            risk_label: RiskLabel::Medium,
        }
    }

    #[test]
    fn sarif_structure_valid() {
        let report = make_report(vec![Finding {
            severity: Severity::Critical,
            category: FindingCategory::CodeExecution,
            title: "eval detected".to_string(),
            description: "Dynamic eval usage".to_string(),
            file: Some("index.js".to_string()),
            line: Some(42),
            snippet: Some("eval(x)".to_string()),
        }]);

        let sarif = generate_sarif(&[report]);

        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["$schema"]
            .as_str()
            .unwrap()
            .contains("sarif-schema-2.1.0"));

        let runs = sarif["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);

        let driver = &runs[0]["tool"]["driver"];
        assert_eq!(driver["name"], "aegis-scan");
        assert_eq!(driver["version"], "0.1.0");

        let rules = driver["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], "aegis/code-execution");

        let results = runs[0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["ruleId"], "aegis/code-execution");
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[0]["message"]["text"], "Dynamic eval usage");

        let loc = &results[0]["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "index.js");
        assert_eq!(loc["region"]["startLine"], 42);
    }

    #[test]
    fn sarif_empty_reports() {
        let sarif = generate_sarif(&[]);
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn sarif_multiple_reports() {
        let r1 = make_report(vec![Finding {
            severity: Severity::High,
            category: FindingCategory::NetworkAccess,
            title: "fetch call".to_string(),
            description: "Network access detected".to_string(),
            file: Some("lib.js".to_string()),
            line: Some(10),
            snippet: None,
        }]);
        let r2 = make_report(vec![Finding {
            severity: Severity::Low,
            category: FindingCategory::Obfuscation,
            title: "obfuscated code".to_string(),
            description: "Obfuscation detected".to_string(),
            file: None,
            line: None,
            snippet: None,
        }]);

        let sarif = generate_sarif(&[r1, r2]);
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "note");
    }

    #[test]
    fn severity_levels_correct() {
        assert_eq!(severity_to_level(&Severity::Critical), "error");
        assert_eq!(severity_to_level(&Severity::High), "error");
        assert_eq!(severity_to_level(&Severity::Medium), "warning");
        assert_eq!(severity_to_level(&Severity::Low), "note");
        assert_eq!(severity_to_level(&Severity::Info), "note");
    }

    #[test]
    fn sarif_no_file_uses_package_fallback() {
        let report = make_report(vec![Finding {
            severity: Severity::Medium,
            category: FindingCategory::MaintainerChange,
            title: "maintainer changed".to_string(),
            description: "Ownership changed".to_string(),
            file: None,
            line: None,
            snippet: None,
        }]);

        let sarif = generate_sarif(&[report]);
        let uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"]
            .as_str()
            .unwrap();
        assert_eq!(uri, "test-pkg@1.0.0");
    }
}
