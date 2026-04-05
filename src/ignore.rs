use std::path::Path;

use crate::types::Finding;

/// Parse an `.aegisignore` file into a list of rules.
pub fn parse_ignore_file(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

/// Load ignore rules from `.aegisignore` (project-local) and `~/.aegis/ignore` (global).
pub fn load_ignore_files(project_dir: Option<&Path>) -> Vec<String> {
    let mut rules = Vec::new();
    if let Some(dir) = project_dir {
        let local_path = dir.join(".aegisignore");
        if let Ok(content) = std::fs::read_to_string(&local_path) {
            rules.extend(parse_ignore_file(&content));
        }
    }
    if let Some(home) = dirs::home_dir() {
        let global_path = home.join(".aegis").join("ignore");
        if let Ok(content) = std::fs::read_to_string(&global_path) {
            rules.extend(parse_ignore_file(&content));
        }
    }
    rules
}

/// Filter out findings matching any ignore rule (case-insensitive substring on
/// category, title, or exact match on severity).
pub fn filter_ignored(findings: Vec<Finding>, ignore_rules: &[String]) -> (Vec<Finding>, usize) {
    if ignore_rules.is_empty() {
        return (findings, 0);
    }
    let rules_lower: Vec<String> = ignore_rules.iter().map(|r| r.to_lowercase()).collect();
    let original_count = findings.len();
    let kept: Vec<Finding> = findings
        .into_iter()
        .filter(|f| {
            let cat = f.category.to_string().to_lowercase();
            let title = f.title.to_lowercase();
            let sev = f.severity.to_string().to_lowercase();
            !rules_lower.iter().any(|rule| {
                cat.contains(rule.as_str()) || title.contains(rule.as_str()) || sev == *rule
            })
        })
        .collect();
    let ignored = original_count - kept.len();
    (kept, ignored)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FindingCategory, Severity};

    #[test]
    fn parse_ignore_file_skips_comments_and_blanks() {
        let content = "# comment\n\nnetwork\n  obfuscation  \n# another\n";
        let rules = parse_ignore_file(content);
        assert_eq!(rules, vec!["network", "obfuscation"]);
    }

    #[test]
    fn filter_ignored_empty_rules_returns_all() {
        let findings = vec![Finding {
            title: "test".to_string(),
            description: "desc".to_string(),
            severity: Severity::Medium,
            category: FindingCategory::NetworkAccess,
            file: None,
            line: None,
            snippet: None,
        }];
        let (kept, ignored) = filter_ignored(findings, &[]);
        assert_eq!(kept.len(), 1);
        assert_eq!(ignored, 0);
    }

    #[test]
    fn filter_ignored_matches_category() {
        let findings = vec![Finding {
            title: "test".to_string(),
            description: "desc".to_string(),
            severity: Severity::Medium,
            category: FindingCategory::NetworkAccess,
            file: None,
            line: None,
            snippet: None,
        }];
        let (kept, ignored) = filter_ignored(findings, &["network".to_string()]);
        assert_eq!(kept.len(), 0);
        assert_eq!(ignored, 1);
    }

    #[test]
    fn filter_ignored_matches_title_substring() {
        let findings = vec![Finding {
            title: "Suspicious network call".to_string(),
            description: "desc".to_string(),
            severity: Severity::High,
            category: FindingCategory::NetworkAccess,
            file: None,
            line: None,
            snippet: None,
        }];
        let (kept, ignored) = filter_ignored(findings, &["suspicious".to_string()]);
        assert_eq!(kept.len(), 0);
        assert_eq!(ignored, 1);
    }

    #[test]
    fn filter_ignored_matches_severity() {
        let findings = vec![Finding {
            title: "test".to_string(),
            description: "desc".to_string(),
            severity: Severity::High,
            category: FindingCategory::NetworkAccess,
            file: None,
            line: None,
            snippet: None,
        }];
        let (kept, ignored) = filter_ignored(findings, &["high".to_string()]);
        assert_eq!(kept.len(), 0);
        assert_eq!(ignored, 1);
    }

    #[test]
    fn filter_ignored_keeps_non_matching() {
        let findings = vec![
            Finding {
                title: "test".to_string(),
                description: "desc".to_string(),
                severity: Severity::High,
                category: FindingCategory::NetworkAccess,
                file: None,
                line: None,
                snippet: None,
            },
            Finding {
                title: "safe".to_string(),
                description: "desc".to_string(),
                severity: Severity::Low,
                category: FindingCategory::Obfuscation,
                file: None,
                line: None,
                snippet: None,
            },
        ];
        let (kept, ignored) = filter_ignored(findings, &["network".to_string()]);
        assert_eq!(kept.len(), 1);
        assert_eq!(ignored, 1);
        assert_eq!(kept[0].title, "safe");
    }
}
