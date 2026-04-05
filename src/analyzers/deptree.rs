use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

use crate::types::{Finding, FindingCategory, Severity};

const NPM_REGISTRY: &str = "https://registry.npmjs.org";
const MAX_PACKAGES: usize = 200;
const DEFAULT_DEPTH: usize = 3;

/// Minimal metadata we fetch per package for tree analysis.
#[derive(Debug, Deserialize)]
struct AbbreviatedVersion {
    #[serde(default)]
    #[allow(dead_code)] // deserialized by serde but accessed indirectly via HashMap key
    version: Option<String>,
    #[serde(default)]
    deprecated: Option<String>,
    #[serde(default)]
    scripts: Option<HashMap<String, String>>,
    #[serde(default)]
    dependencies: Option<HashMap<String, String>>,
}

/// Abbreviated package document (we only need versions + dist-tags).
#[derive(Debug, Deserialize)]
struct AbbreviatedPackage {
    #[serde(default)]
    versions: HashMap<String, AbbreviatedVersion>,
    #[serde(default, rename = "dist-tags")]
    dist_tags: Option<HashMap<String, String>>,
    #[serde(default)]
    time: HashMap<String, String>,
}

/// Queued item for BFS traversal.
struct QueueItem {
    name: String,
    version_spec: String,
    depth: usize,
}

/// Install-script keys that run automatically.
const INSTALL_SCRIPT_KEYS: &[&str] = &["preinstall", "install", "postinstall"];

/// Analyzer that walks the transitive dependency tree of an npm package.
pub struct DepTreeAnalyzer {
    max_depth: usize,
}

impl DepTreeAnalyzer {
    pub fn new() -> Self {
        Self {
            max_depth: DEFAULT_DEPTH,
        }
    }

    /// Analyze the transitive dependency tree rooted at `name@version`.
    pub async fn analyze(&self, name: &str, version: &str, depth: Option<usize>) -> Vec<Finding> {
        let max_depth = depth.unwrap_or(self.max_depth);
        match self.scan_tree(name, version, max_depth).await {
            Ok(findings) => findings,
            Err(e) => {
                tracing::warn!(
                    package = %name,
                    version = %version,
                    error = %e,
                    "dependency tree scan failed"
                );
                Vec::new()
            }
        }
    }

    async fn scan_tree(&self, name: &str, version: &str, max_depth: usize) -> Result<Vec<Finding>> {
        let client = Client::builder()
            .user_agent("aegis-cli/0.3.0")
            .build()
            .context("failed to build HTTP client")?;

        let mut findings = Vec::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue: VecDeque<QueueItem> = VecDeque::new();
        let mut total_deps: usize = 0;

        queue.push_back(QueueItem {
            name: name.to_string(),
            version_spec: version.to_string(),
            depth: 0,
        });

        while let Some(item) = queue.pop_front() {
            if total_deps >= MAX_PACKAGES {
                findings.push(Finding {
                    severity: Severity::Low,
                    category: FindingCategory::DependencyRisk,
                    title: "Dependency tree scan limit reached".to_string(),
                    description: format!(
                        "Stopped scanning after {} packages. The dependency tree is very large.",
                        MAX_PACKAGES
                    ),
                    file: None,
                    line: None,
                    snippet: None,
                });
                break;
            }

            let key = format!("{}@{}", item.name, item.version_spec);
            if visited.contains(&key) {
                continue;
            }
            visited.insert(key);

            // Skip the root package itself for counting.
            if item.depth > 0 {
                total_deps += 1;
            }

            // Fetch metadata for this package.
            let pkg = match Self::fetch_abbreviated(&client, &item.name).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(
                        package = %item.name,
                        error = %e,
                        "failed to fetch package metadata for dep tree"
                    );
                    continue;
                }
            };

            // Resolve the version.
            let resolved_version =
                Self::resolve_version(&item.version_spec, &pkg.versions, &pkg.dist_tags);

            let version_info = match resolved_version
                .as_deref()
                .and_then(|v| pkg.versions.get(v))
            {
                Some(vi) => vi,
                None => continue,
            };

            let resolved_ver = resolved_version.unwrap_or_else(|| item.version_spec.clone());
            let dep_label = format!("{}@{}", item.name, resolved_ver);

            // Check for install scripts (skip root).
            if item.depth > 0 {
                if let Some(scripts) = &version_info.scripts {
                    let dangerous: Vec<&str> = INSTALL_SCRIPT_KEYS
                        .iter()
                        .filter(|k| scripts.contains_key(**k))
                        .copied()
                        .collect();

                    if !dangerous.is_empty() {
                        findings.push(Finding {
                            severity: Severity::High,
                            category: FindingCategory::DependencyRisk,
                            title: format!(
                                "Transitive dependency has install scripts: {}",
                                dep_label
                            ),
                            description: format!(
                                "The transitive dependency {} has automatic install scripts ({}). \
                                 These run with full system access during `npm install`.",
                                dep_label,
                                dangerous.join(", ")
                            ),
                            file: None,
                            line: None,
                            snippet: None,
                        });
                    }
                }

                // Check for deprecated.
                if let Some(msg) = &version_info.deprecated {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        category: FindingCategory::DependencyRisk,
                        title: format!("Transitive dependency is deprecated: {}", dep_label),
                        description: format!(
                            "The transitive dependency {} is deprecated: {}",
                            dep_label, msg
                        ),
                        file: None,
                        line: None,
                        snippet: None,
                    });
                }

                // Check if very new (published in the last 7 days and only 1 version).
                if pkg.versions.len() <= 1 {
                    if let Some(created) = pkg.time.get("created") {
                        if Self::is_very_recent(created) {
                            findings.push(Finding {
                                severity: Severity::High,
                                category: FindingCategory::DependencyRisk,
                                title: format!("Transitive dependency is very new: {}", dep_label),
                                description: format!(
                                    "The transitive dependency {} was created very recently \
                                     and has only {} version(s). It may be a typosquat or \
                                     hallucinated package name.",
                                    dep_label,
                                    pkg.versions.len()
                                ),
                                file: None,
                                line: None,
                                snippet: None,
                            });
                        }
                    }
                }
            }

            // Enqueue children if within depth.
            if item.depth < max_depth {
                if let Some(deps) = &version_info.dependencies {
                    for (dep_name, dep_ver) in deps {
                        queue.push_back(QueueItem {
                            name: dep_name.clone(),
                            version_spec: dep_ver.clone(),
                            depth: item.depth + 1,
                        });
                    }
                }
            }
        }

        // Warn about large attack surface.
        if total_deps > 100 {
            findings.push(Finding {
                severity: Severity::Low,
                category: FindingCategory::DependencyRisk,
                title: format!("Large transitive dependency tree: {} packages", total_deps),
                description: format!(
                    "This package pulls in {} transitive dependencies (within {} levels), \
                     increasing the supply-chain attack surface.",
                    total_deps, self.max_depth
                ),
                file: None,
                line: None,
                snippet: None,
            });
        }

        Ok(findings)
    }

    /// Fetch abbreviated package metadata from the npm registry.
    async fn fetch_abbreviated(client: &Client, name: &str) -> Result<AbbreviatedPackage> {
        let url = format!("{}/{}", NPM_REGISTRY, name);
        let response = client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .with_context(|| format!("HTTP request failed for '{}'", name))?;

        if !response.status().is_success() {
            anyhow::bail!("npm registry returned {} for '{}'", response.status(), name);
        }

        response
            .json()
            .await
            .with_context(|| format!("failed to parse registry JSON for '{}'", name))
    }

    /// Resolve a semver range to a concrete version.
    ///
    /// This is intentionally simple: try exact match, then latest dist-tag,
    /// then pick the last key in the versions map.
    fn resolve_version(
        spec: &str,
        versions: &HashMap<String, AbbreviatedVersion>,
        dist_tags: &Option<HashMap<String, String>>,
    ) -> Option<String> {
        // Strip common range prefixes for a best-effort exact match.
        let cleaned = spec
            .trim_start_matches('^')
            .trim_start_matches('~')
            .trim_start_matches(">=")
            .trim_start_matches('=')
            .trim();

        // 1. Exact match.
        if versions.contains_key(cleaned) {
            return Some(cleaned.to_string());
        }

        // 2. latest dist-tag.
        if let Some(tags) = dist_tags {
            if let Some(latest) = tags.get("latest") {
                if versions.contains_key(latest) {
                    return Some(latest.clone());
                }
            }
        }

        // 3. Last version in the map (HashMap order is arbitrary, but it's
        //    better than nothing).
        versions.keys().last().cloned()
    }

    /// Return true if the ISO-8601 timestamp is less than 7 days old.
    fn is_very_recent(iso_timestamp: &str) -> bool {
        // Simple check: parse the date portion and compare.
        // The npm `time` field looks like "2024-01-15T12:00:00.000Z".
        let now = chrono_lite_days_since_epoch();
        let created = parse_iso_days(iso_timestamp);
        match (now, created) {
            (Some(n), Some(c)) => (n - c) < 7,
            _ => false,
        }
    }
}

/// Super-lightweight "days since unix epoch" from system time.
fn chrono_lite_days_since_epoch() -> Option<i64> {
    let dur = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    Some((dur.as_secs() / 86400) as i64)
}

/// Parse "YYYY-MM-DDT..." into approximate days since unix epoch.
fn parse_iso_days(s: &str) -> Option<i64> {
    let date_part = s.split('T').next()?;
    let parts: Vec<&str> = date_part.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let y: i64 = parts[0].parse().ok()?;
    let m: i64 = parts[1].parse().ok()?;
    let d: i64 = parts[2].parse().ok()?;

    // Approximate days since epoch using a simplified calculation.
    // Accurate enough for a "less than 7 days" check.
    let days = (y - 1970) * 365 + (y - 1969) / 4 + month_day_offset(m) + d - 1;
    Some(days)
}

fn month_day_offset(m: i64) -> i64 {
    match m {
        1 => 0,
        2 => 31,
        3 => 59,
        4 => 90,
        5 => 120,
        6 => 151,
        7 => 181,
        8 => 212,
        9 => 243,
        10 => 273,
        11 => 304,
        12 => 334,
        _ => 0,
    }
}

impl Default for DepTreeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_iso_days_works() {
        // 2024-01-01 should return some positive number of days.
        let days = parse_iso_days("2024-01-01T00:00:00.000Z");
        assert!(days.is_some());
        assert!(days.unwrap() > 19000); // 2024 is well past 1970
    }

    #[test]
    fn is_very_recent_old_date() {
        assert!(!DepTreeAnalyzer::is_very_recent("2020-01-01T00:00:00.000Z"));
    }

    #[test]
    fn resolve_version_exact() {
        let mut versions = HashMap::new();
        versions.insert(
            "1.2.3".to_string(),
            AbbreviatedVersion {
                version: Some("1.2.3".to_string()),
                deprecated: None,
                scripts: None,
                dependencies: None,
            },
        );
        let result = DepTreeAnalyzer::resolve_version("^1.2.3", &versions, &None);
        assert_eq!(result, Some("1.2.3".to_string()));
    }
}
