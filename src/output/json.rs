use crate::types::AnalysisReport;

/// Serialize the analysis report to pretty-printed JSON.
///
/// Returns `None` only if serialization fails (shouldn't happen for our types).
pub fn to_json_string(report: &AnalysisReport) -> Option<String> {
    serde_json::to_string_pretty(report).ok()
}

/// Print the analysis report as pretty-printed JSON to stdout.
pub fn print_json(report: &AnalysisReport) {
    match to_json_string(report) {
        Some(json) => println!("{}", json),
        None => eprintln!("Failed to serialize report to JSON"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Finding, FindingCategory, RiskLabel, Severity};

    fn make_report(findings: Vec<Finding>) -> AnalysisReport {
        AnalysisReport {
            package_name: "test-pkg".to_string(),
            version: "1.0.0".to_string(),
            findings,
            risk_score: 5.0,
            risk_label: RiskLabel::Medium,
        }
    }

    fn make_finding(severity: Severity, category: FindingCategory) -> Finding {
        Finding {
            severity,
            category,
            title: "test finding".to_string(),
            description: "a test description".to_string(),
            file: Some("index.js".to_string()),
            line: Some(10),
            snippet: Some("eval(x)".to_string()),
        }
    }

    #[test]
    fn json_contains_package_name_and_version() {
        let report = make_report(vec![]);
        let json = to_json_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["package_name"], "test-pkg");
        assert_eq!(v["version"], "1.0.0");
    }

    #[test]
    fn json_contains_findings_array() {
        let report = make_report(vec![make_finding(
            Severity::High,
            FindingCategory::CodeExecution,
        )]);
        let json = to_json_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(v["findings"].is_array());
        assert_eq!(v["findings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn json_contains_risk_score_and_label() {
        let report = make_report(vec![]);
        let json = to_json_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(v["risk_score"], 5.0);
        assert_eq!(v["risk_label"], "Medium");
    }

    #[test]
    fn empty_findings_produce_valid_json() {
        let report = make_report(vec![]);
        let json = to_json_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(v["findings"].is_array());
        assert_eq!(v["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn multiple_findings_serialized_correctly() {
        let report = make_report(vec![
            make_finding(Severity::Critical, FindingCategory::CodeExecution),
            make_finding(Severity::Medium, FindingCategory::NetworkAccess),
            make_finding(Severity::Low, FindingCategory::EnvAccess),
        ]);
        let json = to_json_string(&report).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();

        let findings = v["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0]["severity"], "Critical");
        assert_eq!(findings[1]["severity"], "Medium");
        assert_eq!(findings[2]["severity"], "Low");
    }
}
