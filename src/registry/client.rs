use anyhow::{Context, Result};
use reqwest::Client;

use super::package::{PackageMetadata, VersionInfo};

const NPM_REGISTRY: &str = "https://registry.npmjs.org";

/// Build a reusable HTTP client with sensible defaults for talking to the npm
/// registry.
fn http_client() -> Result<Client> {
    Client::builder()
        .user_agent(concat!("aegis-cli/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("failed to build HTTP client")
}

/// Encode the package name for use in a URL path segment.
///
/// Scoped packages like `@scope/name` must be passed as `@scope%2Fname` in the
/// URL path for the single-version endpoint, but the full-metadata endpoint
/// accepts the `/` as-is because the scope is the first path segment.
fn encode_package_name(name: &str) -> String {
    // For full-metadata URLs the registry actually handles `@scope/name` fine,
    // but for the per-version endpoint we need to encode the slash.
    name.replace('/', "%2F")
}

/// Fetch the **full** package document (all versions) from the npm registry.
///
/// Equivalent to: `GET https://registry.npmjs.org/{package}`
pub async fn fetch_package_metadata(name: &str, version: Option<&str>) -> Result<PackageMetadata> {
    let client = http_client()?;

    match version {
        Some(v) => fetch_version_as_metadata(&client, name, v).await,
        None => fetch_full_metadata(&client, name).await,
    }
}

/// Internal: fetch the full document with every version.
async fn fetch_full_metadata(client: &Client, name: &str) -> Result<PackageMetadata> {
    let url = format!("{}/{}", NPM_REGISTRY, name);
    tracing::info!(package = %name, "fetching full package metadata");
    tracing::debug!(url = %url);

    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("HTTP request failed for package '{name}'"))?;

    if !response.status().is_success() {
        anyhow::bail!(
            "npm registry returned {} for package '{}'",
            response.status(),
            name
        );
    }

    let metadata: PackageMetadata = response
        .json()
        .await
        .with_context(|| format!("failed to parse registry JSON for package '{name}'"))?;

    tracing::info!(
        package = %name,
        versions = metadata.versions.len(),
        "successfully fetched metadata"
    );

    Ok(metadata)
}

/// Internal: fetch a single version and wrap it in a `PackageMetadata` so the
/// caller always gets the same return type.
async fn fetch_version_as_metadata(
    client: &Client,
    name: &str,
    version: &str,
) -> Result<PackageMetadata> {
    let encoded = encode_package_name(name);
    let url = format!("{}/{}/{}", NPM_REGISTRY, encoded, version);
    tracing::info!(package = %name, version = %version, "fetching version metadata");
    tracing::debug!(url = %url);

    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("HTTP request failed for '{name}@{version}'"))?;

    if !response.status().is_success() {
        anyhow::bail!(
            "npm registry returned {} for '{}@{}'",
            response.status(),
            name,
            version
        );
    }

    let version_info: VersionInfo = response
        .json()
        .await
        .with_context(|| format!("failed to parse registry JSON for '{name}@{version}'"))?;

    // Wrap the single version in a full PackageMetadata for a uniform API.
    let ver_string = version_info
        .version
        .clone()
        .unwrap_or_else(|| version.to_string());

    let mut versions = std::collections::HashMap::new();
    versions.insert(ver_string.clone(), version_info);

    let mut dist_tags = std::collections::HashMap::new();
    dist_tags.insert("latest".to_string(), ver_string);

    Ok(PackageMetadata {
        name: Some(name.to_string()),
        description: None,
        versions,
        time: std::collections::HashMap::new(),
        maintainers: None,
        dist_tags: Some(dist_tags),
        extra: std::collections::HashMap::new(),
    })
}

/// Build the full-metadata URL for a package (testing helper).
#[cfg(test)]
fn build_full_metadata_url(name: &str) -> String {
    format!("{}/{}", NPM_REGISTRY, name)
}

/// Build the single-version URL for a package (testing helper).
#[cfg(test)]
fn build_version_url(name: &str, version: &str) -> String {
    let encoded = encode_package_name(name);
    format!("{}/{}/{}", NPM_REGISTRY, encoded, version)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_simple_package_name() {
        assert_eq!(encode_package_name("express"), "express");
    }

    #[test]
    fn encode_scoped_package_name() {
        assert_eq!(encode_package_name("@babel/core"), "@babel%2Fcore");
    }

    #[test]
    fn encode_deeply_scoped_package() {
        // Hypothetical double-slash; each slash should be encoded.
        assert_eq!(encode_package_name("@scope/sub/pkg"), "@scope%2Fsub%2Fpkg");
    }

    #[test]
    fn full_metadata_url_simple() {
        let url = build_full_metadata_url("lodash");
        assert_eq!(url, "https://registry.npmjs.org/lodash");
    }

    #[test]
    fn full_metadata_url_scoped() {
        // The full-metadata endpoint takes the raw name (including '/').
        let url = build_full_metadata_url("@angular/core");
        assert_eq!(url, "https://registry.npmjs.org/@angular/core");
    }

    #[test]
    fn version_url_encodes_scoped_package() {
        let url = build_version_url("@babel/core", "7.20.0");
        assert_eq!(url, "https://registry.npmjs.org/@babel%2Fcore/7.20.0");
    }

    #[test]
    fn version_url_simple_package() {
        let url = build_version_url("express", "4.18.2");
        assert_eq!(url, "https://registry.npmjs.org/express/4.18.2");
    }
}
