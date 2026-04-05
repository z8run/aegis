//! Provenance verification: compare npm tarball contents against the
//! package's declared GitHub repository source.
//!
//! This analyzer detects supply-chain attacks where an attacker maintains a
//! clean GitHub repository but publishes a different (malicious) tarball to npm.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use tracing::warn;

use crate::registry::package::PackageMetadata;
use crate::types::{Finding, FindingCategory, Severity};

/// Timeout for GitHub API requests.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

// ---------------------------------------------------------------------------
// GitHub API response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct GitHubTree {
    #[serde(default)]
    tree: Vec<GitHubTreeEntry>,
    #[serde(default)]
    truncated: bool,
}

#[derive(Debug, Deserialize)]
struct GitHubTreeEntry {
    path: String,
    #[serde(rename = "type")]
    entry_type: String,
}

// ---------------------------------------------------------------------------
// Repository URL parsing
// ---------------------------------------------------------------------------

/// Parsed GitHub owner/repo pair.
#[derive(Debug, Clone)]
struct GitHubRepo {
    owner: String,
    repo: String,
}

/// Validate that a GitHub component (owner or repo name) contains only safe
/// characters. This prevents SSRF attacks where a malicious package.json
/// could craft a repository URL that redirects API requests to internal
/// networks.
fn is_safe_github_component(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // Reject path traversal, protocol injection, and control characters
    if s.contains("..") || s.contains("://") || s.contains('@') {
        return false;
    }
    // Only allow alphanumeric, hyphen, underscore, dot
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Validate that a git ref contains only safe characters.
fn is_safe_git_ref(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    if s.contains("..") || s.contains("://") || s.contains('@') {
        return false;
    }
    if s.chars()
        .any(|c| c.is_ascii_whitespace() || c.is_ascii_control())
    {
        return false;
    }
    // Allow alphanumeric, hyphen, underscore, dot, slash (for refs like heads/main)
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '/')
}

/// Try to extract a GitHub owner/repo from a `package.json` `repository` field.
///
/// Handles:
///   - `"https://github.com/user/repo"`
///   - `"https://github.com/user/repo.git"`
///   - `{"type": "git", "url": "https://github.com/user/repo.git"}`
///   - `"github:user/repo"`
///   - `"user/repo"` (shorthand)
///   - `"git+https://github.com/user/repo.git"`
///   - `"git://github.com/user/repo.git"`
///   - `"ssh://git@github.com/user/repo.git"`
///   - `"git@github.com:user/repo.git"`
fn parse_github_repo(repository: &serde_json::Value) -> Option<GitHubRepo> {
    let url_str = match repository {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(obj) => {
            // {"type": "git", "url": "..."}
            obj.get("url")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())?
        }
        _ => return None,
    };

    parse_github_url(&url_str)
}

/// Parse a raw URL/shorthand string into a `GitHubRepo`.
fn parse_github_url(raw: &str) -> Option<GitHubRepo> {
    let s = raw.trim();

    // "github:user/repo"
    if let Some(rest) = s.strip_prefix("github:") {
        return parse_owner_repo(rest);
    }

    // "git@github.com:user/repo.git" (SSH shorthand)
    if s.starts_with("git@github.com:") {
        let rest = s.strip_prefix("git@github.com:")?;
        return parse_owner_repo(rest);
    }

    // URL-based: strip protocol prefixes and try to find github.com in path
    let normalized = s
        .replace("git+https://", "https://")
        .replace("git+ssh://", "ssh://")
        .replace("git://", "https://")
        .replace("ssh://git@", "https://");

    if let Some(idx) = normalized.find("github.com/") {
        let after = &normalized[idx + "github.com/".len()..];
        return parse_owner_repo(after);
    }

    // Bare "user/repo" shorthand — must contain exactly one slash, no dots or colons
    if !s.contains("://") && !s.contains(':') && !s.contains('.') {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() {
            let owner = parts[0].to_string();
            let repo = parts[1].trim_end_matches(".git").to_string();

            // Validate components to prevent SSRF via crafted repository URLs.
            if !is_safe_github_component(&owner) || !is_safe_github_component(&repo) {
                warn!(
                    "Rejected unsafe GitHub component: owner={:?}, repo={:?}",
                    owner, repo
                );
                return None;
            }

            return Some(GitHubRepo { owner, repo });
        }
    }

    None
}

/// Parse "owner/repo" or "owner/repo.git" with possible trailing path segments.
fn parse_owner_repo(s: &str) -> Option<GitHubRepo> {
    let trimmed = s.trim().trim_end_matches('/');
    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.len() >= 2 && !parts[0].is_empty() && !parts[1].is_empty() {
        let owner = parts[0].to_string();
        let repo = parts[1]
            .trim_end_matches(".git")
            .trim_end_matches('/')
            .to_string();

        // Validate components to prevent SSRF via crafted repository URLs.
        if !is_safe_github_component(&owner) || !is_safe_github_component(&repo) {
            warn!(
                "Rejected unsafe GitHub component: owner={:?}, repo={:?}",
                owner, repo
            );
            return None;
        }

        return Some(GitHubRepo { owner, repo });
    }
    None
}

// ---------------------------------------------------------------------------
// File extension helpers
// ---------------------------------------------------------------------------

/// Extensions we consider JS-family source files (matching tarball.rs).
const JS_EXTENSIONS: &[&str] = &["js", "mjs", "cjs", "ts"];

fn is_js_file(path: &str) -> bool {
    if let Some(ext) = path.rsplit('.').next() {
        JS_EXTENSIONS.contains(&ext)
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// ProvenanceAnalyzer
// ---------------------------------------------------------------------------

/// Verifies that the code published to npm matches the source in the package's
/// declared GitHub repository.
pub struct ProvenanceAnalyzer {
    client: reqwest::Client,
}

impl Default for ProvenanceAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvenanceAnalyzer {
    pub fn new() -> Self {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Ok(token) = std::env::var("GITHUB_TOKEN") {
            if let Ok(value) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert(reqwest::header::AUTHORIZATION, value);
            }
        }
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("aegis-cli/", env!("CARGO_PKG_VERSION")))
            .default_headers(headers)
            .build()
            .unwrap_or_default();
        Self { client }
    }

    /// Convenience method that extracts data from an `AnalysisContext`.
    pub async fn analyze_ctx(&self, ctx: &crate::types::AnalysisContext<'_>) -> Vec<Finding> {
        self.analyze(ctx.files, ctx.package_json, ctx.metadata, ctx.version)
            .await
    }

    /// Run the full provenance analysis.
    ///
    /// `files` are the extracted tarball contents (relative path, content).
    /// `package_json` is the parsed package.json.
    /// `metadata` is the npm registry metadata for the package.
    /// `version` is the resolved version string.
    pub async fn analyze(
        &self,
        files: &[(PathBuf, String)],
        package_json: &serde_json::Value,
        metadata: &PackageMetadata,
        version: &str,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let pkg_name = metadata
            .name
            .as_deref()
            .or_else(|| package_json.get("name").and_then(|v| v.as_str()))
            .unwrap_or("<unknown>");

        // 1. Check npm provenance attestation.
        let has_attestation = self.check_attestation(metadata, version, &mut findings, pkg_name);

        // 2. Extract repository URL from package.json.
        let repo_field = package_json.get("repository");
        let github_repo = repo_field.and_then(parse_github_repo);

        if github_repo.is_none() {
            // No repository URL at all.
            if !has_attestation {
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::Provenance,
                    title: "No provenance attestation and no repository URL".into(),
                    description: format!(
                        "Package `{pkg_name}@{version}` has no npm provenance attestation \
                         and no repository URL in package.json. There is no way to verify \
                         the source of the published code."
                    ),
                    file: None,
                    line: None,
                    snippet: None,
                });
            }
            return findings;
        }

        let github_repo = github_repo.unwrap();

        // 3. Fetch GitHub tree and compare file lists.
        match self
            .compare_with_github(files, &github_repo, version, pkg_name)
            .await
        {
            Ok(comparison_findings) => findings.extend(comparison_findings),
            Err(CompareError::RepoNotAccessible) => {
                findings.push(Finding {
                    severity: Severity::Medium,
                    category: FindingCategory::Provenance,
                    title: "Repository URL not accessible".into(),
                    description: format!(
                        "Package `{pkg_name}@{version}` declares repository \
                         https://github.com/{}/{} but it returned a 404. \
                         The source code cannot be verified.",
                        github_repo.owner, github_repo.repo,
                    ),
                    file: None,
                    line: None,
                    snippet: None,
                });
            }
            Err(CompareError::ApiError(msg)) => {
                // Non-fatal: log and move on.
                warn!("GitHub API error during provenance check for {pkg_name}@{version}: {msg}");
            }
        }

        findings
    }

    /// Check if the package version has npm provenance attestation.
    /// Returns `true` if attestation was found.
    fn check_attestation(
        &self,
        metadata: &PackageMetadata,
        version: &str,
        findings: &mut Vec<Finding>,
        pkg_name: &str,
    ) -> bool {
        let version_info = metadata.versions.get(version);

        // Check for attestations in the dist or extra fields.
        let has_attestation = version_info
            .map(|vi| {
                // Check dist.attestations (if the registry exposes it)
                let in_dist = vi
                    .extra
                    .get("dist")
                    .and_then(|d| d.get("attestations"))
                    .is_some();

                // Also check top-level extra for attestations
                let in_extra = vi.extra.contains_key("attestations");

                // Check for the `_npmSignature` or Sigstore-related fields
                let has_signature = vi.extra.contains_key("_npmSignature");

                in_dist || in_extra || has_signature
            })
            .unwrap_or(false);

        if has_attestation {
            findings.push(Finding {
                severity: Severity::Info,
                category: FindingCategory::Provenance,
                title: "npm provenance attestation present".into(),
                description: format!(
                    "Package `{pkg_name}@{version}` has npm provenance attestation \
                     (Sigstore-based). This links the published package to its source \
                     repository and build process."
                ),
                file: None,
                line: None,
                snippet: None,
            });
        } else {
            findings.push(Finding {
                severity: Severity::Low,
                category: FindingCategory::Provenance,
                title: "No npm provenance attestation".into(),
                description: format!(
                    "Package `{pkg_name}@{version}` does not have npm provenance attestation. \
                     Provenance links a published package to its source repo and build, \
                     making supply-chain attacks harder."
                ),
                file: None,
                line: None,
                snippet: None,
            });
        }

        has_attestation
    }

    /// Fetch the GitHub tree for the given version tag and compare JS files.
    async fn compare_with_github(
        &self,
        files: &[(PathBuf, String)],
        repo: &GitHubRepo,
        version: &str,
        pkg_name: &str,
    ) -> Result<Vec<Finding>, CompareError> {
        // Collect JS file paths from the npm tarball.
        let tarball_js_files: HashSet<String> = files
            .iter()
            .map(|(p, _)| p.to_string_lossy().to_string())
            .filter(|p| is_js_file(p))
            .collect();

        if tarball_js_files.is_empty() {
            // No JS files in the tarball; nothing to compare.
            return Ok(Vec::new());
        }

        // Try multiple tag formats: v1.0.0, 1.0.0, package@1.0.0
        let tag_candidates = vec![
            format!("v{version}"),
            version.to_string(),
            format!("{pkg_name}@{version}"),
        ];

        let mut github_tree = None;
        for tag in &tag_candidates {
            match self.fetch_github_tree(repo, tag).await {
                Ok(tree) => {
                    github_tree = Some(tree);
                    break;
                }
                Err(CompareError::RepoNotAccessible) => {
                    // Try next tag
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        // If none of the tags worked, try the default branch (HEAD).
        if github_tree.is_none() {
            match self.fetch_github_tree(repo, "HEAD").await {
                Ok(tree) => github_tree = Some(tree),
                Err(CompareError::RepoNotAccessible) => {
                    return Err(CompareError::RepoNotAccessible);
                }
                Err(e) => return Err(e),
            }
        }

        let github_tree = match github_tree {
            Some(t) => t,
            None => return Err(CompareError::RepoNotAccessible),
        };

        // Collect JS file paths from the GitHub tree.
        let github_js_files: HashSet<String> = github_tree
            .tree
            .iter()
            .filter(|e| e.entry_type == "blob")
            .map(|e| e.path.clone())
            .filter(|p| is_js_file(p))
            .collect();

        let mut findings = Vec::new();

        // Find files in the npm tarball that are NOT in GitHub.
        let mut npm_only: Vec<&String> = tarball_js_files
            .iter()
            .filter(|f| !github_js_files.contains(f.as_str()))
            .collect();
        npm_only.sort();

        // Filter out common build artifacts that are expected to differ.
        let npm_only_suspicious: Vec<&&String> = npm_only
            .iter()
            .filter(|f| !is_expected_build_artifact(f))
            .collect();

        if !npm_only_suspicious.is_empty() {
            let file_list: Vec<String> = npm_only_suspicious
                .iter()
                .take(20)
                .map(|f| format!("  - {f}"))
                .collect();
            let truncation_note = if npm_only_suspicious.len() > 20 {
                format!("\n  ... and {} more", npm_only_suspicious.len() - 20)
            } else {
                String::new()
            };

            findings.push(Finding {
                severity: Severity::Critical,
                category: FindingCategory::Provenance,
                title: format!(
                    "{} JS file(s) in npm tarball not found in GitHub source",
                    npm_only_suspicious.len()
                ),
                description: format!(
                    "Package `{pkg_name}` has JavaScript files in the npm tarball that \
                     do not exist in the GitHub repository ({}/{}). This could indicate \
                     injected malicious code:\n{}{truncation_note}",
                    repo.owner,
                    repo.repo,
                    file_list.join("\n"),
                ),
                file: npm_only_suspicious.first().map(|f| f.to_string()),
                line: None,
                snippet: None,
            });
        }

        if github_tree.truncated {
            findings.push(Finding {
                severity: Severity::Info,
                category: FindingCategory::Provenance,
                title: "GitHub tree response was truncated".into(),
                description: format!(
                    "The GitHub tree API response for {}/{} was truncated (repository \
                     has too many files). The file comparison may be incomplete.",
                    repo.owner, repo.repo,
                ),
                file: None,
                line: None,
                snippet: None,
            });
        }

        Ok(findings)
    }

    /// Fetch the recursive file tree from GitHub for a given ref.
    async fn fetch_github_tree(
        &self,
        repo: &GitHubRepo,
        git_ref: &str,
    ) -> Result<GitHubTree, CompareError> {
        // Validate all URL components before constructing the request to
        // prevent SSRF via crafted package.json repository fields.
        if !is_safe_github_component(&repo.owner) || !is_safe_github_component(&repo.repo) {
            return Err(CompareError::ApiError(format!(
                "Unsafe GitHub owner/repo: {}/{}",
                repo.owner, repo.repo,
            )));
        }
        if !is_safe_git_ref(git_ref) {
            return Err(CompareError::ApiError(format!(
                "Unsafe git ref: {:?}",
                git_ref,
            )));
        }

        let url = format!(
            "https://api.github.com/repos/{}/{}/git/trees/{}?recursive=1",
            repo.owner, repo.repo, git_ref,
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| CompareError::ApiError(format!("HTTP request failed: {e}")))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(CompareError::RepoNotAccessible);
        }

        if !response.status().is_success() {
            return Err(CompareError::ApiError(format!(
                "GitHub API returned {}",
                response.status()
            )));
        }

        let tree: GitHubTree = response
            .json()
            .await
            .map_err(|e| CompareError::ApiError(format!("Failed to parse GitHub tree: {e}")))?;

        Ok(tree)
    }
}

/// Errors that can occur during GitHub comparison.
enum CompareError {
    /// Repository or tag returned 404.
    RepoNotAccessible,
    /// Other API error.
    ApiError(String),
}

/// Check if a file path looks like a common build artifact that would
/// reasonably exist in an npm tarball but not in the GitHub source.
fn is_expected_build_artifact(path: &str) -> bool {
    let lower = path.to_lowercase();

    // Common build output directories
    let build_prefixes = [
        "dist/", "build/", "lib/", "out/", "cjs/", "esm/", "umd/", "es/", "module/", "_cjs/",
        "_esm/",
    ];

    for prefix in &build_prefixes {
        if lower.starts_with(prefix) {
            return true;
        }
    }

    // Common generated/bundled file patterns
    if lower.ends_with(".min.js") || lower.ends_with(".bundle.js") {
        return true;
    }

    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_https_url() {
        let v = serde_json::json!("https://github.com/axios/axios");
        let repo = parse_github_repo(&v).unwrap();
        assert_eq!(repo.owner, "axios");
        assert_eq!(repo.repo, "axios");
    }

    #[test]
    fn parse_https_url_with_git_suffix() {
        let v = serde_json::json!("https://github.com/lodash/lodash.git");
        let repo = parse_github_repo(&v).unwrap();
        assert_eq!(repo.owner, "lodash");
        assert_eq!(repo.repo, "lodash");
    }

    #[test]
    fn parse_git_plus_https() {
        let v = serde_json::json!("git+https://github.com/user/repo.git");
        let repo = parse_github_repo(&v).unwrap();
        assert_eq!(repo.owner, "user");
        assert_eq!(repo.repo, "repo");
    }

    #[test]
    fn parse_object_format() {
        let v = serde_json::json!({"type": "git", "url": "https://github.com/facebook/react.git"});
        let repo = parse_github_repo(&v).unwrap();
        assert_eq!(repo.owner, "facebook");
        assert_eq!(repo.repo, "react");
    }

    #[test]
    fn parse_github_shorthand() {
        let v = serde_json::json!("github:user/repo");
        let repo = parse_github_repo(&v).unwrap();
        assert_eq!(repo.owner, "user");
        assert_eq!(repo.repo, "repo");
    }

    #[test]
    fn parse_bare_shorthand() {
        let v = serde_json::json!("user/repo");
        let repo = parse_github_repo(&v).unwrap();
        assert_eq!(repo.owner, "user");
        assert_eq!(repo.repo, "repo");
    }

    #[test]
    fn parse_ssh_url() {
        let v = serde_json::json!("git@github.com:user/repo.git");
        let repo = parse_github_repo(&v).unwrap();
        assert_eq!(repo.owner, "user");
        assert_eq!(repo.repo, "repo");
    }

    #[test]
    fn parse_non_github_returns_none() {
        let v = serde_json::json!("https://gitlab.com/user/repo");
        assert!(parse_github_repo(&v).is_none());
    }

    #[test]
    fn is_js_file_positive() {
        assert!(is_js_file("index.js"));
        assert!(is_js_file("src/main.mjs"));
        assert!(is_js_file("lib/util.cjs"));
        assert!(is_js_file("types.ts"));
    }

    #[test]
    fn is_js_file_negative() {
        assert!(!is_js_file("readme.md"));
        assert!(!is_js_file("package.json"));
        assert!(!is_js_file("logo.png"));
    }

    #[test]
    fn build_artifact_detection() {
        assert!(is_expected_build_artifact("dist/index.js"));
        assert!(is_expected_build_artifact("build/main.js"));
        assert!(is_expected_build_artifact("lib/utils.js"));
        assert!(is_expected_build_artifact("jquery.min.js"));
        assert!(is_expected_build_artifact("app.bundle.js"));
        assert!(!is_expected_build_artifact("src/index.js"));
        assert!(!is_expected_build_artifact("index.js"));
    }

    // -----------------------------------------------------------------------
    // SSRF validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn safe_github_component_accepts_normal_names() {
        assert!(is_safe_github_component("axios"));
        assert!(is_safe_github_component("facebook"));
        assert!(is_safe_github_component("my-repo"));
        assert!(is_safe_github_component("my_repo"));
        assert!(is_safe_github_component("lodash.js"));
        assert!(is_safe_github_component("repo123"));
    }

    #[test]
    fn safe_github_component_rejects_malicious_input() {
        // Path traversal
        assert!(!is_safe_github_component("../../../etc/passwd"));
        assert!(!is_safe_github_component(".."));
        assert!(!is_safe_github_component("foo..bar"));

        // Protocol injection
        assert!(!is_safe_github_component("http://evil.com"));
        assert!(!is_safe_github_component("https://evil.com"));

        // At-sign (SSH/auth injection)
        assert!(!is_safe_github_component("git@evil.com"));

        // Whitespace and control characters
        assert!(!is_safe_github_component("foo bar"));
        assert!(!is_safe_github_component("foo\tbar"));
        assert!(!is_safe_github_component("foo\nbar"));
        assert!(!is_safe_github_component("foo\0bar"));

        // Empty
        assert!(!is_safe_github_component(""));

        // Slashes (should not appear in owner or repo)
        assert!(!is_safe_github_component("evil/path"));
    }

    #[test]
    fn safe_git_ref_accepts_normal_refs() {
        assert!(is_safe_git_ref("HEAD"));
        assert!(is_safe_git_ref("v1.0.0"));
        assert!(is_safe_git_ref("1.0.0"));
        assert!(is_safe_git_ref("main"));
        assert!(is_safe_git_ref("heads/main"));
        assert!(is_safe_git_ref("my-package_v1.2.3"));
    }

    #[test]
    fn safe_git_ref_rejects_malicious_input() {
        assert!(!is_safe_git_ref("../../../etc/passwd"));
        assert!(!is_safe_git_ref("http://evil.com"));
        assert!(!is_safe_git_ref("git@evil.com:foo"));
        assert!(!is_safe_git_ref("ref with spaces"));
        assert!(!is_safe_git_ref("ref\nnewline"));
        assert!(!is_safe_git_ref(""));
    }

    #[test]
    fn parse_rejects_ssrf_payloads_in_owner() {
        let v = serde_json::json!("https://github.com/../../../api/v1");
        assert!(parse_github_repo(&v).is_none());
    }

    #[test]
    fn parse_rejects_ssrf_payloads_in_repo() {
        let v = serde_json::json!("https://github.com/legit/repo@evil.com");
        assert!(parse_github_repo(&v).is_none());
    }

    #[test]
    fn parse_rejects_encoded_traversal() {
        // Even if someone tries to sneak in ".." via the repo name
        let v = serde_json::json!("https://github.com/evil..com/repo");
        assert!(parse_github_repo(&v).is_none());
    }

    #[test]
    fn parse_rejects_whitespace_in_components() {
        let v = serde_json::json!("https://github.com/evil user/repo");
        assert!(parse_github_repo(&v).is_none());
    }

    #[test]
    fn parse_accepts_normal_repos_after_validation() {
        // Ensure validation doesn't break legitimate repos
        let cases = vec![
            ("https://github.com/axios/axios", "axios", "axios"),
            ("https://github.com/facebook/react.git", "facebook", "react"),
            (
                "git+https://github.com/lodash/lodash.git",
                "lodash",
                "lodash",
            ),
            ("github:chalk/chalk", "chalk", "chalk"),
            (
                "git@github.com:expressjs/express.git",
                "expressjs",
                "express",
            ),
        ];
        for (url, expected_owner, expected_repo) in cases {
            let v = serde_json::json!(url);
            let repo = parse_github_repo(&v).unwrap_or_else(|| panic!("Expected to parse {url}"));
            assert_eq!(repo.owner, expected_owner, "owner mismatch for {url}");
            assert_eq!(repo.repo, expected_repo, "repo mismatch for {url}");
        }
    }
}
