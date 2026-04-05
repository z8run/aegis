use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Maintainer information from the npm registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Maintainer {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
}

/// Distribution metadata for a specific version (tarball URL, checksums).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dist {
    #[serde(default)]
    pub tarball: Option<String>,
    #[serde(default)]
    pub shasum: Option<String>,
    #[serde(default)]
    pub integrity: Option<String>,
}

/// All the information we care about for a specific published version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub dist: Option<Dist>,
    #[serde(default)]
    pub scripts: Option<HashMap<String, String>>,
    #[serde(default)]
    pub dependencies: Option<HashMap<String, String>>,
    #[serde(default, rename = "devDependencies")]
    pub dev_dependencies: Option<HashMap<String, String>>,
    #[serde(default)]
    pub maintainers: Option<Vec<Maintainer>>,
    /// Catch-all for fields we don't explicitly model.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Top-level package metadata returned by `https://registry.npmjs.org/{pkg}`.
///
/// We intentionally keep this flat and optional — the npm registry response
/// varies between full-doc and abbreviated-doc endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMetadata {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Map of semver string -> VersionInfo for every published version.
    #[serde(default)]
    pub versions: HashMap<String, VersionInfo>,
    /// Map of semver string -> ISO-8601 publish timestamp.
    #[serde(default)]
    pub time: HashMap<String, String>,
    #[serde(default)]
    pub maintainers: Option<Vec<Maintainer>>,
    #[serde(default, rename = "dist-tags")]
    pub dist_tags: Option<HashMap<String, String>>,
    /// Catch-all for fields we don't explicitly model.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

/// Names of npm lifecycle scripts that run automatically on install and are
/// commonly abused by malicious packages.
const INSTALL_SCRIPT_KEYS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "postuninstall",
    "prepare",
];

impl VersionInfo {
    /// Return only the lifecycle/install-related scripts (the ones that fire
    /// automatically when a user runs `npm install`).
    pub fn install_scripts(&self) -> HashMap<String, String> {
        let Some(scripts) = &self.scripts else {
            return HashMap::new();
        };
        scripts
            .iter()
            .filter(|(key, _)| INSTALL_SCRIPT_KEYS.contains(&key.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

impl PackageMetadata {
    /// Resolve the `latest` dist-tag to a concrete version string.
    pub fn latest_version(&self) -> Option<&str> {
        self.dist_tags
            .as_ref()
            .and_then(|tags| tags.get("latest"))
            .map(|s| s.as_str())
    }

    /// Convenience: get the `VersionInfo` for the `latest` tag.
    pub fn latest_version_info(&self) -> Option<&VersionInfo> {
        let v = self.latest_version()?;
        self.versions.get(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_full_package_metadata() {
        let json = r#"{
            "name": "my-pkg",
            "description": "A test package",
            "dist-tags": { "latest": "1.2.3" },
            "versions": {
                "1.2.3": {
                    "name": "my-pkg",
                    "version": "1.2.3",
                    "description": "A test package",
                    "scripts": { "postinstall": "node setup.js" },
                    "dependencies": { "lodash": "^4.0.0" }
                }
            },
            "time": {
                "1.2.3": "2024-01-15T10:00:00.000Z"
            },
            "maintainers": [
                { "name": "alice", "email": "alice@example.com" }
            ]
        }"#;

        let meta: PackageMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.name.as_deref(), Some("my-pkg"));
        assert_eq!(meta.description.as_deref(), Some("A test package"));
        assert_eq!(meta.latest_version(), Some("1.2.3"));
        assert!(meta.versions.contains_key("1.2.3"));
        assert_eq!(meta.time.get("1.2.3").unwrap(), "2024-01-15T10:00:00.000Z");
    }

    #[test]
    fn deserialize_version_info() {
        let json = r#"{
            "name": "my-pkg",
            "version": "1.2.3",
            "description": "desc",
            "dist": {
                "tarball": "https://example.com/pkg.tgz",
                "shasum": "abc123",
                "integrity": "sha512-xyz"
            },
            "scripts": {
                "preinstall": "echo hi",
                "test": "jest"
            },
            "dependencies": { "foo": "^1.0.0" },
            "devDependencies": { "bar": "^2.0.0" },
            "maintainers": [
                { "name": "bob", "email": "bob@example.com" }
            ]
        }"#;

        let vi: VersionInfo = serde_json::from_str(json).unwrap();
        assert_eq!(vi.name.as_deref(), Some("my-pkg"));
        assert_eq!(vi.version.as_deref(), Some("1.2.3"));
        let dist = vi.dist.as_ref().unwrap();
        assert_eq!(dist.tarball.as_deref(), Some("https://example.com/pkg.tgz"));
        assert_eq!(dist.shasum.as_deref(), Some("abc123"));
        assert_eq!(dist.integrity.as_deref(), Some("sha512-xyz"));
        assert!(vi.scripts.as_ref().unwrap().contains_key("preinstall"));
        assert!(vi.dependencies.as_ref().unwrap().contains_key("foo"));
        assert!(vi.dev_dependencies.as_ref().unwrap().contains_key("bar"));
    }

    #[test]
    fn missing_optional_fields_handled() {
        let json = r#"{}"#;

        let vi: VersionInfo = serde_json::from_str(json).unwrap();
        assert!(vi.name.is_none());
        assert!(vi.version.is_none());
        assert!(vi.description.is_none());
        assert!(vi.dist.is_none());
        assert!(vi.scripts.is_none());
        assert!(vi.dependencies.is_none());
        assert!(vi.dev_dependencies.is_none());
        assert!(vi.maintainers.is_none());

        let meta: PackageMetadata = serde_json::from_str(json).unwrap();
        assert!(meta.name.is_none());
        assert!(meta.versions.is_empty());
        assert!(meta.dist_tags.is_none());
        assert!(meta.latest_version().is_none());
    }

    #[test]
    fn maintainer_list_parsing() {
        let json = r#"{
            "maintainers": [
                { "name": "alice", "email": "alice@example.com" },
                { "name": "bob" },
                { "email": "charlie@example.com" }
            ]
        }"#;

        let meta: PackageMetadata = serde_json::from_str(json).unwrap();
        let maintainers = meta.maintainers.unwrap();
        assert_eq!(maintainers.len(), 3);
        assert_eq!(maintainers[0].name.as_deref(), Some("alice"));
        assert_eq!(maintainers[0].email.as_deref(), Some("alice@example.com"));
        assert_eq!(maintainers[1].name.as_deref(), Some("bob"));
        assert!(maintainers[1].email.is_none());
        assert!(maintainers[2].name.is_none());
        assert_eq!(
            maintainers[2].email.as_deref(),
            Some("charlie@example.com")
        );
    }

    #[test]
    fn install_scripts_filters_correctly() {
        let json = r#"{
            "scripts": {
                "preinstall": "echo pre",
                "postinstall": "node setup.js",
                "test": "jest",
                "build": "tsc",
                "prepare": "husky install"
            }
        }"#;

        let vi: VersionInfo = serde_json::from_str(json).unwrap();
        let install = vi.install_scripts();
        assert_eq!(install.len(), 3);
        assert!(install.contains_key("preinstall"));
        assert!(install.contains_key("postinstall"));
        assert!(install.contains_key("prepare"));
        assert!(!install.contains_key("test"));
        assert!(!install.contains_key("build"));
    }

    #[test]
    fn latest_version_resolves_from_dist_tags() {
        let json = r#"{
            "dist-tags": { "latest": "3.0.0", "next": "4.0.0-beta.1" },
            "versions": {
                "3.0.0": { "version": "3.0.0" },
                "4.0.0-beta.1": { "version": "4.0.0-beta.1" }
            }
        }"#;

        let meta: PackageMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.latest_version(), Some("3.0.0"));
        let info = meta.latest_version_info().unwrap();
        assert_eq!(info.version.as_deref(), Some("3.0.0"));
    }

    #[test]
    fn extra_fields_captured_in_flatten() {
        let json = r#"{
            "name": "pkg",
            "repository": { "type": "git", "url": "https://github.com/x/y" },
            "license": "MIT"
        }"#;

        let meta: PackageMetadata = serde_json::from_str(json).unwrap();
        assert!(meta.extra.contains_key("license"));
        assert!(meta.extra.contains_key("repository"));
    }
}
