use crate::registry::package::{Maintainer, PackageMetadata};
use crate::types::{AnalysisContext, Finding, FindingCategory, Severity};
use std::collections::HashSet;

use super::Analyzer;

/// Analyzes npm package maintainer metadata for suspicious changes.
pub struct MaintainerAnalyzer;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return a canonical lowercase key for a maintainer — prefer the npm username,
/// fall back to email.
fn maintainer_key(m: &Maintainer) -> String {
    m.name
        .as_deref()
        .or(m.email.as_deref())
        .unwrap_or("unknown")
        .to_lowercase()
}

/// Extract the domain part of an email (everything after the last '@').
fn email_domain(email: &str) -> Option<&str> {
    email.rsplit_once('@').map(|(_, domain)| domain)
}

/// Very lightweight ISO-8601 parser — returns (year, month, day) or `None`.
/// Expects strings that start with `YYYY-MM-DD` (the npm registry format).
fn parse_ymd(ts: &str) -> Option<(i32, u32, u32)> {
    if ts.len() < 10 {
        return None;
    }
    let y: i32 = ts[..4].parse().ok()?;
    let m: u32 = ts[5..7].parse().ok()?;
    let d: u32 = ts[8..10].parse().ok()?;
    Some((y, m, d))
}

/// Return an approximate day-ordinal so we can compare two dates.
/// Not astronomically precise, but good enough for a 7-day window.
fn day_ordinal(y: i32, m: u32, d: u32) -> i64 {
    let y = y as i64;
    let m = m as i64;
    let d = d as i64;
    y * 365 + y / 4 - y / 100 + y / 400 + (m * 30) + d
}

/// Return `true` if the ISO timestamp is within `days` of `reference_ts`.
fn is_within_days(ts: &str, reference_ts: &str, days: i64) -> bool {
    let Some((ry, rm, rd)) = parse_ymd(reference_ts) else {
        return false;
    };
    let Some((ty, tm, td)) = parse_ymd(ts) else {
        return false;
    };
    let ref_ord = day_ordinal(ry, rm, rd);
    let ts_ord = day_ordinal(ty, tm, td);
    (ref_ord - ts_ord).abs() <= days
}

/// Return versions sorted by their publish time (ascending), paired with their
/// timestamp.  Skips the special `created` / `modified` keys that npm includes
/// in the `time` map.
fn versions_by_time(meta: &PackageMetadata) -> Vec<(String, String)> {
    let skip: HashSet<&str> = ["created", "modified"].into_iter().collect();
    let mut pairs: Vec<(String, String)> = meta
        .time
        .iter()
        .filter(|(k, _)| !skip.contains(k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    pairs.sort_by(|a, b| a.1.cmp(&b.1));
    pairs
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

impl MaintainerAnalyzer {
    /// Analyze the package metadata for suspicious maintainer changes.
    pub fn analyze_metadata(&self, metadata: &PackageMetadata) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();

        let current_maintainers = match &metadata.maintainers {
            Some(m) if !m.is_empty() => m,
            _ => return findings,
        };

        let pkg_name = metadata.name.as_deref().unwrap_or("<unknown>");

        // ---- Derive a "today" reference from the most recent publish time ----
        let sorted_versions = versions_by_time(metadata);
        let latest_ts = sorted_versions.last().map(|(_, ts)| ts.as_str());

        // ---- LOW: single maintainer (bus factor) ----------------------------
        if current_maintainers.len() == 1 {
            findings.push(Finding {
                severity: Severity::Low,
                category: FindingCategory::MaintainerChange,
                title: "Single maintainer (bus factor risk)".into(),
                description: format!(
                    "Package `{pkg_name}` has only 1 maintainer ({}). \
                     If the account is compromised there is no second party to notice.",
                    maintainer_key(&current_maintainers[0]),
                ),
                file: None,
                line: None,
                snippet: None,
            });
        }

        // ---- Compare maintainers across the last two versions ---------------
        if sorted_versions.len() >= 2 {
            let prev_ver = &sorted_versions[sorted_versions.len() - 2].0;
            let latest_ver = &sorted_versions[sorted_versions.len() - 1].0;

            let prev_maintainers = metadata
                .versions
                .get(prev_ver)
                .and_then(|v| v.maintainers.as_ref());

            let latest_maintainers = metadata
                .versions
                .get(latest_ver)
                .and_then(|v| v.maintainers.as_ref())
                .or(Some(current_maintainers));

            if let (Some(prev), Some(curr)) = (prev_maintainers, latest_maintainers) {
                let prev_keys: HashSet<String> = prev.iter().map(maintainer_key).collect();
                let curr_keys: HashSet<String> = curr.iter().map(maintainer_key).collect();

                let added: Vec<&String> = curr_keys.difference(&prev_keys).collect();
                let removed: Vec<&String> = prev_keys.difference(&curr_keys).collect();

                // CRITICAL: ownership transferred to entirely new maintainer
                if !prev_keys.is_empty()
                    && !curr_keys.is_empty()
                    && prev_keys.is_disjoint(&curr_keys)
                {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        category: FindingCategory::MaintainerChange,
                        title: "Complete ownership transfer".into(),
                        description: format!(
                            "Package `{pkg_name}` ownership was transferred between versions \
                             {prev_ver} and {latest_ver}. Previous maintainers ({}) were \
                             completely replaced by new maintainers ({}).",
                            prev_keys.iter().cloned().collect::<Vec<_>>().join(", "),
                            curr_keys.iter().cloned().collect::<Vec<_>>().join(", "),
                        ),
                        file: None,
                        line: None,
                        snippet: None,
                    });
                }

                // HIGH: all previous maintainers removed and replaced (full takeover)
                // (overlaps with critical — only emit if there IS some intersection)
                if !prev_keys.is_empty()
                    && !removed.is_empty()
                    && removed.len() == prev_keys.len()
                    && !prev_keys.is_disjoint(&curr_keys)
                {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: FindingCategory::MaintainerChange,
                        title: "All previous maintainers removed".into(),
                        description: format!(
                            "Every maintainer present in version {prev_ver} was removed by \
                             version {latest_ver}. Removed: {}. Current: {}.",
                            removed
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                            curr_keys.iter().cloned().collect::<Vec<_>>().join(", "),
                        ),
                        file: None,
                        line: None,
                        snippet: None,
                    });
                }

                // HIGH: new maintainer added in the last 7 days
                if !added.is_empty() {
                    if let Some(ref_ts) = latest_ts {
                        let latest_publish_ts = &sorted_versions[sorted_versions.len() - 1].1;
                        // "today" is approximated as the most-recent publish time.
                        if is_within_days(latest_publish_ts, ref_ts, 7) {
                            findings.push(Finding {
                                severity: Severity::High,
                                category: FindingCategory::MaintainerChange,
                                title: "New maintainer added recently".into(),
                                description: format!(
                                    "New maintainer(s) ({}) were added to `{pkg_name}` in the \
                                     latest version published on {latest_publish_ts}.",
                                    added
                                        .iter()
                                        .map(|s| s.as_str())
                                        .collect::<Vec<_>>()
                                        .join(", "),
                                ),
                                file: None,
                                line: None,
                                snippet: None,
                            });
                        }
                    }
                }

                // MEDIUM: any new maintainer added (even if old ones remain)
                if !added.is_empty() {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        category: FindingCategory::MaintainerChange,
                        title: "New maintainer added".into(),
                        description: format!(
                            "Maintainer(s) added between versions {prev_ver} and {latest_ver}: {}.",
                            added
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join(", "),
                        ),
                        file: None,
                        line: None,
                        snippet: None,
                    });
                }

                // MEDIUM: maintainer email domain changed
                check_email_domain_changes(prev, curr, pkg_name, &mut findings);
            }
        }

        // HIGH: maintainer with no other packages (brand-new npm account)
        // We cannot query the registry for other packages here, but we can flag
        // maintainers whose npm username looks like a throwaway (no email or
        // free-mail provider combined with a single-package context).  This is a
        // heuristic stand-in; a full implementation would query the npm user API.
        for m in current_maintainers {
            if let Some(email) = m.email.as_deref() {
                if email.is_empty() {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: FindingCategory::MaintainerChange,
                        title: "Maintainer with no email".into(),
                        description: format!(
                            "Maintainer `{}` on `{pkg_name}` has no email address, which may \
                             indicate a brand-new or throwaway npm account.",
                            maintainer_key(m),
                        ),
                        file: None,
                        line: None,
                        snippet: None,
                    });
                }
            } else {
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::MaintainerChange,
                    title: "Maintainer with no email".into(),
                    description: format!(
                        "Maintainer `{}` on `{pkg_name}` has no email address, which may \
                         indicate a brand-new or throwaway npm account.",
                        maintainer_key(m),
                    ),
                    file: None,
                    line: None,
                    snippet: None,
                });
            }
        }

        findings
    }
}

impl Analyzer for MaintainerAnalyzer {
    fn name(&self) -> &str {
        "maintainer"
    }

    fn analyze(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        self.analyze_metadata(ctx.metadata)
    }
}

/// Detect email domain changes between previous and current maintainer lists.
fn check_email_domain_changes(
    prev: &[Maintainer],
    curr: &[Maintainer],
    pkg_name: &str,
    findings: &mut Vec<Finding>,
) {
    // Build a map: maintainer key -> email domain for the previous version.
    let prev_domains: std::collections::HashMap<String, String> = prev
        .iter()
        .filter_map(|m| {
            let email = m.email.as_deref()?;
            let domain = email_domain(email)?;
            Some((maintainer_key(m), domain.to_lowercase()))
        })
        .collect();

    for m in curr {
        let key = maintainer_key(m);
        if let Some(old_domain) = prev_domains.get(&key) {
            if let Some(email) = m.email.as_deref() {
                if let Some(new_domain) = email_domain(email) {
                    let new_domain_lower = new_domain.to_lowercase();
                    if *old_domain != new_domain_lower {
                        findings.push(Finding {
                            severity: Severity::Medium,
                            category: FindingCategory::MaintainerChange,
                            title: "Maintainer email domain changed".into(),
                            description: format!(
                                "Maintainer `{key}` on `{pkg_name}` changed email domain \
                                 from @{old_domain} to @{new_domain_lower}.",
                            ),
                            file: None,
                            line: None,
                            snippet: None,
                        });
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::package::{Maintainer, PackageMetadata, VersionInfo};
    use std::collections::HashMap;

    fn make_maintainer(name: &str, email: &str) -> Maintainer {
        Maintainer {
            name: Some(name.into()),
            email: Some(email.into()),
        }
    }

    fn make_version(maintainers: Vec<Maintainer>) -> VersionInfo {
        VersionInfo {
            name: None,
            version: None,
            description: None,
            dist: None,
            scripts: None,
            dependencies: None,
            dev_dependencies: None,
            maintainers: Some(maintainers),
            extra: HashMap::new(),
        }
    }

    fn base_metadata() -> PackageMetadata {
        PackageMetadata {
            name: Some("test-pkg".into()),
            description: None,
            versions: HashMap::new(),
            time: HashMap::new(),
            maintainers: None,
            dist_tags: None,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn single_maintainer_bus_factor() {
        let mut meta = base_metadata();
        meta.maintainers = Some(vec![make_maintainer("alice", "alice@example.com")]);

        let findings = MaintainerAnalyzer.analyze_metadata(&meta);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Low && f.title.contains("Single maintainer")));
    }

    #[test]
    fn complete_ownership_transfer() {
        let mut meta = base_metadata();
        meta.maintainers = Some(vec![make_maintainer("eve", "eve@evil.com")]);
        meta.versions.insert(
            "1.0.0".into(),
            make_version(vec![make_maintainer("alice", "alice@co.com")]),
        );
        meta.versions.insert(
            "1.0.1".into(),
            make_version(vec![make_maintainer("eve", "eve@evil.com")]),
        );
        meta.time
            .insert("1.0.0".into(), "2026-01-01T00:00:00Z".into());
        meta.time
            .insert("1.0.1".into(), "2026-03-30T00:00:00Z".into());

        let findings = MaintainerAnalyzer.analyze_metadata(&meta);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.title.contains("ownership transfer")));
    }

    #[test]
    fn new_maintainer_added() {
        let mut meta = base_metadata();
        meta.maintainers = Some(vec![
            make_maintainer("alice", "alice@co.com"),
            make_maintainer("bob", "bob@co.com"),
        ]);
        meta.versions.insert(
            "1.0.0".into(),
            make_version(vec![make_maintainer("alice", "alice@co.com")]),
        );
        meta.versions.insert(
            "1.0.1".into(),
            make_version(vec![
                make_maintainer("alice", "alice@co.com"),
                make_maintainer("bob", "bob@co.com"),
            ]),
        );
        meta.time
            .insert("1.0.0".into(), "2026-01-01T00:00:00Z".into());
        meta.time
            .insert("1.0.1".into(), "2026-03-30T00:00:00Z".into());

        let findings = MaintainerAnalyzer.analyze_metadata(&meta);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Medium && f.title.contains("New maintainer added")));
    }

    #[test]
    fn email_domain_change() {
        let mut meta = base_metadata();
        meta.maintainers = Some(vec![make_maintainer("alice", "alice@gmail.com")]);
        meta.versions.insert(
            "1.0.0".into(),
            make_version(vec![make_maintainer("alice", "alice@company.com")]),
        );
        meta.versions.insert(
            "1.0.1".into(),
            make_version(vec![make_maintainer("alice", "alice@gmail.com")]),
        );
        meta.time
            .insert("1.0.0".into(), "2026-01-01T00:00:00Z".into());
        meta.time
            .insert("1.0.1".into(), "2026-03-30T00:00:00Z".into());

        let findings = MaintainerAnalyzer.analyze_metadata(&meta);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Medium && f.title.contains("email domain changed")));
    }
}
