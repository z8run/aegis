use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use colored::Colorize;

use crate::analyzers::{self, Analyzer};
use crate::cache;
use crate::registry;
use crate::rules;
use crate::scoring;
use crate::types::{AnalysisContext, AnalysisReport};

use registry::tarball;
use rules::loader::load_default_rules;
use scoring::calculator;

/// Analyze a single package and return its report.
///
/// This contains the full fetch -> download -> analyze -> score pipeline.
/// When `use_cache` is true the result is looked up / stored in the local
/// cache.
pub async fn analyze_package(
    name: &str,
    version: Option<&str>,
    use_cache: bool,
    progress_prefix: &str,
    custom_rules_dir: Option<&Path>,
) -> Result<AnalysisReport> {
    let display_version = version.unwrap_or("latest");

    // 1. Fetch metadata from the npm registry.
    eprintln!(
        "{}Fetching {}@{} from npm registry...",
        progress_prefix,
        name.bold(),
        display_version
    );

    let metadata = registry::client::fetch_package_metadata(name, version)
        .await
        .with_context(|| format!("could not fetch metadata for '{}'", name))?;

    // Resolve the concrete version we'll analyze.
    let resolved_version = version
        .or_else(|| metadata.latest_version())
        .unwrap_or("0.0.0");

    // Check cache (after resolving the concrete version).
    if use_cache {
        if let Some(cached) = cache::get_cached(name, resolved_version) {
            eprintln!(
                "{}Using cached result for {}@{}",
                progress_prefix,
                name.bold(),
                resolved_version
            );
            return Ok(cached);
        }
    }

    let version_info = metadata.versions.get(resolved_version).with_context(|| {
        format!(
            "version '{}' not found in registry data for '{}'",
            resolved_version, name
        )
    })?;

    // 2. Download and extract the tarball.
    let tarball_url = version_info
        .dist
        .as_ref()
        .and_then(|d| d.tarball.as_deref())
        .with_context(|| format!("no tarball URL found for {}@{}", name, resolved_version))?;

    let (_tmp_dir, package_dir) = tarball::download_and_extract_temp(tarball_url)
        .await
        .context("failed to download/extract tarball")?;

    // 3. Collect JS files and read contents.
    let js_paths = tarball::collect_js_files(&package_dir);

    let files: Vec<(PathBuf, String)> = js_paths
        .into_iter()
        .filter_map(|path| {
            let content = std::fs::read_to_string(&path).ok()?;
            let rel = path
                .strip_prefix(&package_dir)
                .unwrap_or(&path)
                .to_path_buf();
            Some((rel, content))
        })
        .collect();

    // 4. Load package.json for analyzers that need it.
    let package_json_path = package_dir.join("package.json");
    let package_json: serde_json::Value = if package_json_path.exists() {
        let raw =
            std::fs::read_to_string(&package_json_path).context("failed to read package.json")?;
        serde_json::from_str(&raw).context("failed to parse package.json")?
    } else {
        serde_json::Value::Object(serde_json::Map::new())
    };

    // 5. Build analysis context.
    let ctx = AnalysisContext {
        name,
        version: resolved_version,
        files: &files,
        package_json: &package_json,
        metadata: &metadata,
        package_dir: &package_dir,
    };

    // 6. Run all trait-based analyzers.
    let mut all_rules = load_default_rules();
    if let Some(rules_dir) = custom_rules_dir {
        match rules::loader::load_rules(rules_dir) {
            Ok(custom) => all_rules.extend(custom),
            Err(e) => tracing::warn!("failed to load custom rules: {:#}", e),
        }
    }

    let all_analyzers: Vec<Box<dyn Analyzer>> = vec![
        Box::new(analyzers::static_code::StaticCodeAnalyzer),
        Box::new(analyzers::install_scripts::InstallScriptAnalyzer),
        Box::new(analyzers::obfuscation::ObfuscationAnalyzer),
        Box::new(analyzers::ast::AstAnalyzer),
        Box::new(analyzers::dataflow::DataFlowAnalyzer),
        Box::new(rules::engine::RulesEngine::new(all_rules)),
        Box::new(analyzers::binary::BinaryAnalyzer),
        Box::new(analyzers::maintainer::MaintainerAnalyzer),
        Box::new(analyzers::hallucination::HallucinationAnalyzer::new()),
    ];

    let mut findings = Vec::new();
    for a in &all_analyzers {
        findings.extend(a.analyze(&ctx));
    }

    // Run async analyzers separately (cannot be trait objects due to async).
    let cve_checker = analyzers::cve::CveChecker::new();
    findings.extend(cve_checker.check_ctx(&ctx).await);

    let provenance_analyzer = analyzers::provenance::ProvenanceAnalyzer::new();
    findings.extend(provenance_analyzer.analyze_ctx(&ctx).await);

    // Sort findings by severity (most critical first).
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    // 7. Build report.
    let report = calculator::build_report(name, resolved_version, findings);

    // 8. Store in cache.
    if use_cache {
        if let Err(e) = cache::save_cache(&report) {
            tracing::warn!("failed to save cache: {:#}", e);
        }
    }

    // Explicitly drop the temp dir handle.
    drop(_tmp_dir);

    Ok(report)
}
