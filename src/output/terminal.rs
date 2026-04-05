use colored::Colorize;

use crate::types::{AnalysisReport, Finding, RiskLabel, Severity};

/// Print a human-readable, tree-style security report to the terminal.
pub fn print_report(report: &AnalysisReport) {
    println!();
    println!(
        "  \u{1f4e6} {}@{}",
        report.package_name.bold(),
        report.version
    );
    println!();

    if report.findings.is_empty() {
        println!("  \u{2705} {}", "Clean — no issues found".green());
        println!();
        print_risk_line(report.risk_score, &report.risk_label);
        println!();
        return;
    }

    for finding in &report.findings {
        print_finding(finding);
    }

    print_risk_line(report.risk_score, &report.risk_label);
    println!();
}

fn print_finding(f: &Finding) {
    let (icon, styled_header) = match f.severity {
        Severity::Critical => (
            "\u{26d4}",
            format!("CRITICAL — {}", f.category)
                .red()
                .bold()
                .to_string(),
        ),
        Severity::High => (
            "\u{26a0}\u{fe0f} ",
            format!("HIGH — {}", f.category).red().to_string(),
        ),
        Severity::Medium => (
            "\u{26a0}\u{fe0f} ",
            format!("MEDIUM — {}", f.category).yellow().to_string(),
        ),
        Severity::Low => (
            "\u{2139}\u{fe0f} ",
            format!("LOW — {}", f.category).blue().to_string(),
        ),
        Severity::Info => (
            "\u{2139}\u{fe0f} ",
            format!("INFO — {}", f.category).green().to_string(),
        ),
    };

    println!("  {} {}", icon, styled_header);
    println!("  {}  {}", "\u{2502}".dimmed(), f.description);

    if let Some(ref file) = f.file {
        let location = match f.line {
            Some(line) => format!("{}:{}", file, line),
            None => file.clone(),
        };
        println!("  {}  \u{1f4c4} {}", "\u{2502}".dimmed(), location.dimmed());
    }

    if let Some(ref snippet) = f.snippet {
        println!(
            "  {}  {} {}",
            "\u{2502}".dimmed(),
            "\u{2514}\u{2500}".dimmed(),
            snippet.dimmed()
        );
    }

    println!();
}

fn print_risk_line(score: f64, label: &RiskLabel) {
    let score_str = format!("{:.1}/10", score);
    let colored_score = if score < 3.0 {
        score_str.green()
    } else if score <= 7.0 {
        score_str.yellow()
    } else {
        score_str.red()
    };

    let label_str = format!("{}", label);
    let colored_label = match label {
        RiskLabel::Clean => label_str.green().bold(),
        RiskLabel::Low => label_str.green().bold(),
        RiskLabel::Medium => label_str.yellow().bold(),
        RiskLabel::High => label_str.red().bold(),
        RiskLabel::Critical => label_str.red().bold(),
    };

    println!("  Risk: {} — {}", colored_score, colored_label);
}

/// Format the risk line as a plain string (useful for testing without ANSI).
#[cfg(test)]
fn format_risk_line(score: f64, label: &RiskLabel) -> String {
    format!("{:.1}/10 — {}", score, label)
}

/// Format a finding header as a plain string (severity + category).
#[cfg(test)]
fn format_finding_header(f: &Finding) -> String {
    let prefix = match f.severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    };
    format!("{} — {}", prefix, f.category)
}

/// Truncate a snippet to a maximum length, appending "…" if it was cut.
#[cfg(test)]
fn truncate_snippet(snippet: &str, max_len: usize) -> String {
    if snippet.len() <= max_len {
        snippet.to_string()
    } else {
        format!("{}…", &snippet[..max_len])
    }
}

/// Format a complete report as a plain-text string (no ANSI colours).
#[cfg(test)]
fn format_report_plain(report: &AnalysisReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("{}@{}\n", report.package_name, report.version));

    if report.findings.is_empty() {
        out.push_str("Clean — no issues found\n");
    } else {
        for f in &report.findings {
            out.push_str(&format!("{}\n", format_finding_header(f)));
            out.push_str(&format!("  {}\n", f.description));
            if let Some(ref file) = f.file {
                match f.line {
                    Some(line) => out.push_str(&format!("  {}:{}\n", file, line)),
                    None => out.push_str(&format!("  {}\n", file)),
                };
            }
            if let Some(ref snippet) = f.snippet {
                out.push_str(&format!("  {}\n", truncate_snippet(snippet, 120)));
            }
        }
    }

    out.push_str(&format!(
        "Risk: {}\n",
        format_risk_line(report.risk_score, &report.risk_label)
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FindingCategory, RiskLabel, Severity};

    fn make_report(findings: Vec<Finding>) -> AnalysisReport {
        AnalysisReport {
            package_name: "my-pkg".to_string(),
            version: "2.3.4".to_string(),
            findings,
            risk_score: 6.5,
            risk_label: RiskLabel::High,
        }
    }

    fn make_finding(severity: Severity, category: FindingCategory) -> Finding {
        Finding {
            severity,
            category,
            title: "test".to_string(),
            description: "some issue".to_string(),
            file: Some("lib/index.js".to_string()),
            line: Some(42),
            snippet: Some("eval(payload)".to_string()),
        }
    }

    #[test]
    fn report_contains_package_name_and_version() {
        let report = make_report(vec![]);
        let text = format_report_plain(&report);
        assert!(text.contains("my-pkg@2.3.4"));
    }

    #[test]
    fn finding_header_uses_correct_severity_label() {
        let f = make_finding(Severity::Critical, FindingCategory::CodeExecution);
        assert_eq!(format_finding_header(&f), "CRITICAL — Code Execution");

        let f = make_finding(Severity::High, FindingCategory::NetworkAccess);
        assert_eq!(format_finding_header(&f), "HIGH — Network Access");

        let f = make_finding(Severity::Medium, FindingCategory::Obfuscation);
        assert_eq!(format_finding_header(&f), "MEDIUM — Obfuscation");

        let f = make_finding(Severity::Low, FindingCategory::EnvAccess);
        assert_eq!(format_finding_header(&f), "LOW — Env Access");

        let f = make_finding(Severity::Info, FindingCategory::Suspicious);
        assert_eq!(format_finding_header(&f), "INFO — Suspicious");
    }

    #[test]
    fn risk_score_display_is_correct() {
        assert_eq!(
            format_risk_line(0.0, &RiskLabel::Clean),
            "0.0/10 — CLEAN"
        );
        assert_eq!(
            format_risk_line(9.5, &RiskLabel::Critical),
            "9.5/10 — DO NOT INSTALL"
        );
        assert_eq!(
            format_risk_line(5.0, &RiskLabel::Medium),
            "5.0/10 — MEDIUM RISK"
        );
    }

    #[test]
    fn empty_findings_produce_valid_output() {
        let report = make_report(vec![]);
        let text = format_report_plain(&report);
        assert!(text.contains("Clean — no issues found"));
        assert!(text.contains("Risk:"));
    }

    #[test]
    fn long_snippets_are_truncated() {
        let short = "eval(x)";
        assert_eq!(truncate_snippet(short, 120), "eval(x)");

        let long = "a".repeat(200);
        let truncated = truncate_snippet(&long, 120);
        assert_eq!(truncated.len(), 120 + "…".len());
        assert!(truncated.ends_with('…'));
    }

    #[test]
    fn report_with_findings_includes_details() {
        let report = make_report(vec![make_finding(
            Severity::High,
            FindingCategory::ProcessSpawn,
        )]);
        let text = format_report_plain(&report);
        assert!(text.contains("HIGH — Process Spawn"));
        assert!(text.contains("some issue"));
        assert!(text.contains("lib/index.js:42"));
        assert!(text.contains("eval(payload)"));
    }
}
