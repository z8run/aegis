//! Check packages against known vulnerabilities via the OSV.dev API.
//!
//! The [OSV API](https://osv.dev/) aggregates CVEs, GHSAs, and other
//! vulnerability databases. We query it for a specific npm package + version
//! and translate every reported vulnerability into an Aegis `Finding`.

use std::time::Duration;

use serde::Deserialize;
use tracing::warn;

use crate::types::{Finding, FindingCategory, Severity};

/// OSV.dev query endpoint.
const OSV_API_URL: &str = "https://api.osv.dev/v1/query";

/// Timeout for the HTTP request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// OSV response types (only the fields we need)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct OsvResponse {
    #[serde(default)]
    vulns: Vec<OsvVuln>,
}

#[derive(Debug, Deserialize)]
struct OsvVuln {
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    references: Vec<OsvReference>,
}

#[derive(Debug, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type", default)]
    severity_type: Option<String>,
    #[serde(default)]
    score: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OsvReference {
    #[allow(dead_code)]
    #[serde(rename = "type", default)]
    ref_type: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

// ---------------------------------------------------------------------------
// CveChecker
// ---------------------------------------------------------------------------

/// Queries the OSV.dev API for known vulnerabilities affecting a given npm
/// package at a specific version.
pub struct CveChecker {
    client: reqwest::Client,
}

impl Default for CveChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl CveChecker {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .unwrap_or_default();
        Self { client }
    }

    /// Check a single package version against OSV.dev.
    ///
    /// Returns one `Finding` per reported vulnerability. On network or API
    /// errors the method logs a warning and returns an empty vector so that
    /// the rest of the scan can proceed.
    pub async fn check(&self, name: &str, version: &str) -> Vec<Finding> {
        let body = serde_json::json!({
            "package": {
                "name": name,
                "ecosystem": "npm"
            },
            "version": version
        });

        let response = match self.client.post(OSV_API_URL).json(&body).send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("OSV API request failed for {name}@{version}: {e}");
                return Vec::new();
            }
        };

        if !response.status().is_success() {
            warn!(
                "OSV API returned status {} for {name}@{version}",
                response.status()
            );
            return Vec::new();
        }

        let osv: OsvResponse = match response.json().await {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to parse OSV response for {name}@{version}: {e}");
                return Vec::new();
            }
        };

        osv.vulns
            .into_iter()
            .map(|vuln| self.vuln_to_finding(name, version, vuln))
            .collect()
    }

    /// Convenience method that extracts name/version from an `AnalysisContext`.
    pub async fn check_ctx(&self, ctx: &crate::types::AnalysisContext<'_>) -> Vec<Finding> {
        self.check(ctx.name, ctx.version).await
    }

    /// Map a single OSV vulnerability to an Aegis `Finding`.
    fn vuln_to_finding(&self, name: &str, version: &str, vuln: OsvVuln) -> Finding {
        let severity = self.determine_severity(&vuln);

        let summary = vuln
            .summary
            .as_deref()
            .or(vuln.details.as_deref())
            .unwrap_or("No description available");

        let link = vuln
            .references
            .iter()
            .find_map(|r| r.url.clone())
            .unwrap_or_else(|| format!("https://osv.dev/vulnerability/{}", vuln.id));

        Finding {
            severity,
            category: FindingCategory::KnownVulnerability,
            title: format!("{}: {}", vuln.id, truncate(summary, 80)),
            description: format!(
                "Package {name}@{version} is affected by {}.\n\n{summary}\n\nMore info: {link}",
                vuln.id
            ),
            file: None,
            line: None,
            snippet: None,
        }
    }

    /// Determine the `Severity` based on CVSS score or severity label.
    fn determine_severity(&self, vuln: &OsvVuln) -> Severity {
        // Try to extract a numeric CVSS score first.
        for sev in &vuln.severity {
            if let Some(score_str) = &sev.score {
                // The score field may be a CVSS vector string; try to parse the
                // numeric part. OSV sometimes provides just a float, sometimes
                // a full CVSS vector like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
                if let Some(cvss) = parse_cvss_score(score_str) {
                    if cvss >= 9.0 {
                        return Severity::Critical;
                    } else if cvss >= 7.0 {
                        return Severity::High;
                    } else if cvss >= 4.0 {
                        return Severity::Medium;
                    } else {
                        return Severity::Low;
                    }
                }

                // Fall back to string matching on the type/label.
                let upper = score_str.to_uppercase();
                if upper.contains("CRITICAL") {
                    return Severity::Critical;
                } else if upper.contains("HIGH") {
                    return Severity::High;
                } else if upper.contains("MODERATE") || upper.contains("MEDIUM") {
                    return Severity::Medium;
                }
            }

            // Also check `severity_type` for textual labels.
            if let Some(st) = &sev.severity_type {
                let upper = st.to_uppercase();
                if upper.contains("CRITICAL") {
                    return Severity::Critical;
                } else if upper.contains("HIGH") {
                    return Severity::High;
                }
            }
        }

        // If we couldn't determine severity, default to Medium (we know there
        // IS a vulnerability; just unsure how bad).
        Severity::Medium
    }
}

/// Try to extract a numeric CVSS score from a string that may be either a
/// plain float (`"9.8"`) or a CVSS vector string.
fn parse_cvss_score(s: &str) -> Option<f64> {
    // Plain float?
    if let Ok(v) = s.parse::<f64>() {
        return Some(v);
    }
    // Not a plain float — not worth fully decoding the CVSS vector here.
    None
}

/// Build a finding to surface when the OSV API itself fails.
pub fn api_error_finding(name: &str, version: &str, error: &str) -> Finding {
    Finding {
        severity: Severity::Low,
        category: FindingCategory::KnownVulnerability,
        title: format!("OSV API error for {}@{}", name, version),
        description: format!(
            "Could not check {}@{} against the OSV.dev vulnerability database: {}. \
             Manual verification is recommended.",
            name, version, error
        ),
        file: None,
        line: None,
        snippet: None,
    }
}

/// Truncate a string to at most `max` characters.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max).collect();
        format!("{t}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cvss_score_plain() {
        assert_eq!(parse_cvss_score("9.8"), Some(9.8));
        assert_eq!(parse_cvss_score("7.0"), Some(7.0));
    }

    #[test]
    fn test_parse_cvss_score_vector() {
        // We don't decode CVSS vectors yet, so this should return None.
        assert_eq!(
            parse_cvss_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            None
        );
    }

    #[test]
    fn test_truncate_short() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_long() {
        let long = "a".repeat(100);
        let t = truncate(&long, 10);
        assert_eq!(t.len(), 13); // 10 chars + "..."
    }
}
