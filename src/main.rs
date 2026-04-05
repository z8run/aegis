use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;

use aegis_scan::analyzers::{self, Analyzer};
use aegis_scan::cache;
use aegis_scan::output;
use aegis_scan::registry;
use aegis_scan::rules;
use aegis_scan::scoring;
use aegis_scan::types::{AnalysisReport, Finding, RiskLabel};

use registry::tarball;
use rules::loader::load_default_rules;
use scoring::calculator;

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "aegis-scan",
    about = "Supply-chain security scanner for npm packages",
    version,
    after_help = "Examples:\n  aegis check axios\n  aegis check axios@1.7.0\n  aegis check @scope/pkg@1.0.0\n  aegis check lodash --json\n  aegis scan .\n  aegis scan ./my-project --skip-dev\n  aegis install axios express\n  aegis install --force\n  aegis install"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output results as JSON instead of the default terminal format
    #[arg(long, global = true, conflicts_with = "sarif")]
    json: bool,

    /// Output results as SARIF v2.1.0 JSON (for GitHub Security tab)
    #[arg(long, global = true, conflicts_with = "json")]
    sarif: bool,

    /// Enable verbose / debug logging
    #[arg(long, short, global = true)]
    verbose: bool,

    /// Bypass the local analysis cache
    #[arg(long, global = true)]
    no_cache: bool,

    /// Directory containing custom YAML rule files
    #[arg(long, global = true)]
    rules: Option<PathBuf>,

    /// Disable colored output (also respects NO_COLOR env var and non-TTY stdout)
    #[arg(long, global = true)]
    no_color: bool,

    /// Ignore findings matching a rule (case-insensitive substring match on
    /// category, title, or severity). Can be specified multiple times.
    #[arg(long = "ignore-rule", global = true)]
    ignore_rules: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Check a specific npm package for security issues
    Check {
        /// Package specifier, e.g. "axios", "axios@1.7.0", "@scope/pkg@1.0.0"
        package: String,

        /// Compare against a previous version to detect security-relevant changes
        #[arg(long)]
        compare: Option<String>,

        /// Run deep transitive dependency tree analysis
        #[arg(long)]
        deep: bool,
    },

    /// Scan a local project's dependencies for security issues
    Scan {
        /// Path to the project directory (must contain a package.json)
        path: PathBuf,

        /// Skip devDependencies
        #[arg(long)]
        skip_dev: bool,
    },

    /// Install npm packages after checking them for security issues
    Install {
        /// Packages to install (e.g. "axios", "lodash@4.17.21"). If omitted,
        /// runs `npm install` for the whole project after scanning all deps.
        packages: Vec<String>,

        /// Skip confirmation prompts and install even if high-risk packages are found
        #[arg(long)]
        force: bool,

        /// Skip devDependencies when scanning the whole project
        #[arg(long)]
        skip_dev: bool,
    },

    /// Manage the local analysis cache
    Cache {
        #[command(subcommand)]
        action: CacheCommands,
    },
}

#[derive(Subcommand)]
enum CacheCommands {
    /// Remove all cached analysis results
    Clear,
}

// ---------------------------------------------------------------------------
// Package specifier parsing
// ---------------------------------------------------------------------------

/// Parse a package specifier into (name, optional version).
///
/// Handles:
///   - `axios`           -> ("axios", None)
///   - `axios@1.7.0`     -> ("axios", Some("1.7.0"))
///   - `@scope/pkg`      -> ("@scope/pkg", None)
///   - `@scope/pkg@1.0`  -> ("@scope/pkg", Some("1.0"))
fn parse_package_specifier(spec: &str) -> (String, Option<String>) {
    if let Some(scoped) = spec.strip_prefix('@') {
        // Scoped package: find the *second* '@' (version separator).
        if let Some(at_pos) = scoped.find('@') {
            // Make sure the '@' comes after the '/', otherwise it's part of
            // the scope itself (malformed, but be defensive).
            if scoped[..at_pos].contains('/') {
                let name = format!("@{}", &scoped[..at_pos]);
                let version = scoped[at_pos + 1..].to_string();
                return (name, Some(version));
            }
        }
        // No version portion found — the whole string is the package name.
        (spec.to_string(), None)
    } else {
        // Unscoped package: split on the first '@'.
        match spec.split_once('@') {
            Some((name, version)) => (name.to_string(), Some(version.to_string())),
            None => (spec.to_string(), None),
        }
    }
}

// ---------------------------------------------------------------------------
// Finding suppression (--ignore-rule and .aegisignore)
// ---------------------------------------------------------------------------

/// Parse an `.aegisignore` file into a list of rules.
fn parse_ignore_file(content: &str) -> Vec<String> {
    content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.to_string())
        .collect()
}

/// Load ignore rules from `.aegisignore` (project-local) and `~/.aegis/ignore` (global).
fn load_ignore_files(project_dir: Option<&Path>) -> Vec<String> {
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
fn filter_ignored(findings: Vec<Finding>, ignore_rules: &[String]) -> (Vec<Finding>, usize) {
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
            !rules_lower
                .iter()
                .any(|rule| cat.contains(rule.as_str()) || title.contains(rule.as_str()) || sev == *rule)
        })
        .collect();
    let ignored = original_count - kept.len();
    (kept, ignored)
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Disable colors when requested via flag, NO_COLOR env var, or non-TTY stdout.
    if cli.no_color
        || std::env::var_os("NO_COLOR").is_some()
        || !std::io::stdout().is_terminal()
    {
        colored::control::set_override(false);
    }

    // Collect ignore rules from CLI flags and .aegisignore files.
    let mut ignore_rules = cli.ignore_rules.clone();
    let project_dir = match &cli.command {
        Commands::Scan { path, .. } => Some(path.as_path()),
        Commands::Install { .. } => Some(Path::new(".")),
        _ => None,
    };
    ignore_rules.extend(load_ignore_files(project_dir));

    // Logging setup.
    let filter = if cli.verbose { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(false)
        .init();

    let result = match &cli.command {
        Commands::Check {
            package,
            compare,
            deep,
        } => {
            run_check(
                package,
                cli.json,
                cli.sarif,
                cli.no_cache,
                compare.as_deref(),
                *deep,
                cli.rules.as_deref(),
                &ignore_rules,
            )
            .await
        }
        Commands::Scan { path, skip_dev } => {
            run_scan(
                path,
                *skip_dev,
                cli.json,
                cli.sarif,
                cli.no_cache,
                cli.rules.as_deref(),
                &ignore_rules,
            )
            .await
        }
        Commands::Install {
            packages,
            force,
            skip_dev,
        } => run_install(packages, *force, *skip_dev, cli.no_cache).await,
        Commands::Cache { action } => match action {
            CacheCommands::Clear => cache::clear_cache(),
        },
    };

    if let Err(err) = result {
        eprintln!("{} {:#}", "Error:".red().bold(), err);
        process::exit(2);
    }
}

// ---------------------------------------------------------------------------
// Core analysis — shared between `check` and `scan`
// ---------------------------------------------------------------------------

/// Analyze a single package and return its report.
///
/// This contains the full fetch -> download -> analyze -> score pipeline.
/// When `use_cache` is true the result is looked up / stored in the local
/// cache.
async fn analyze_package(
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

    // 5. Run all analyzers.
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
    ];

    let mut findings = Vec::new();
    for a in &all_analyzers {
        findings.extend(a.analyze(&files, &package_json));
    }

    // Run binary file analyzer (works on raw filesystem, not text pipeline).
    let binary_analyzer = analyzers::binary::BinaryAnalyzer;
    findings.extend(binary_analyzer.analyze_directory(&package_dir));

    // Run metadata-based analyzers (not trait-based).
    let maintainer_analyzer = analyzers::maintainer::MaintainerAnalyzer;
    findings.extend(maintainer_analyzer.analyze(&metadata));

    let hallucination_analyzer = analyzers::hallucination::HallucinationAnalyzer::new();
    findings.extend(hallucination_analyzer.analyze(&metadata));

    // Run CVE checker (async).
    let cve_checker = analyzers::cve::CveChecker::new();
    findings.extend(cve_checker.check(name, resolved_version).await);

    // Run provenance verification (async — compares npm tarball vs GitHub source).
    let provenance_analyzer = analyzers::provenance::ProvenanceAnalyzer::new();
    findings.extend(
        provenance_analyzer
            .analyze(&files, &package_json, &metadata, resolved_version)
            .await,
    );

    // Sort findings by severity (most critical first).
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    // 6. Build report.
    let report = calculator::build_report(name, resolved_version, findings);

    // 7. Store in cache.
    if use_cache {
        if let Err(e) = cache::save_cache(&report) {
            tracing::warn!("failed to save cache: {:#}", e);
        }
    }

    // Explicitly drop the temp dir handle.
    drop(_tmp_dir);

    Ok(report)
}

// ---------------------------------------------------------------------------
// `aegis check`
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn run_check(
    package: &str,
    json_output: bool,
    sarif_output: bool,
    no_cache: bool,
    compare_version: Option<&str>,
    deep: bool,
    custom_rules_dir: Option<&Path>,
    ignore_rules: &[String],
) -> Result<()> {
    let (name, version) = parse_package_specifier(package);

    let prefix = "  \u{1f50d} ";
    let mut report = analyze_package(
        &name,
        version.as_deref(),
        !no_cache,
        prefix,
        custom_rules_dir,
    )
    .await?;

    // --compare: diff analysis against a previous version.
    if let Some(old_ver) = compare_version {
        eprintln!(
            "  \u{1f50d} Comparing {}@{} against {}@{}...",
            name, report.version, name, old_ver
        );

        let old_tarball_url = {
            let old_meta = registry::client::fetch_package_metadata(&name, Some(old_ver))
                .await
                .with_context(|| format!("could not fetch metadata for '{}@{}'", name, old_ver))?;
            let old_vi = old_meta
                .versions
                .get(old_ver)
                .with_context(|| format!("version '{}' not found for '{}'", old_ver, name))?;
            old_vi
                .dist
                .as_ref()
                .and_then(|d| d.tarball.clone())
                .with_context(|| format!("no tarball URL for {}@{}", name, old_ver))?
        };

        let new_tarball_url = {
            let new_meta = registry::client::fetch_package_metadata(&name, Some(&report.version))
                .await
                .with_context(|| {
                    format!("could not fetch metadata for '{}@{}'", name, report.version)
                })?;
            let new_vi = new_meta.versions.get(&report.version).with_context(|| {
                format!("version '{}' not found for '{}'", report.version, name)
            })?;
            new_vi
                .dist
                .as_ref()
                .and_then(|d| d.tarball.clone())
                .with_context(|| format!("no tarball URL for {}@{}", name, report.version))?
        };

        let (_old_tmp, old_dir) = tarball::download_and_extract_temp(&old_tarball_url)
            .await
            .context("failed to download old version tarball")?;
        let (_new_tmp, new_dir) = tarball::download_and_extract_temp(&new_tarball_url)
            .await
            .context("failed to download new version tarball")?;

        let diff_findings = analyzers::diff::DiffAnalyzer::analyze_diff(
            &old_dir,
            &new_dir,
            old_ver,
            &report.version,
        );
        report.findings.extend(diff_findings);
        report.findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    }

    // --deep: transitive dependency tree analysis.
    if deep {
        eprintln!(
            "  \u{1f50d} Running deep dependency tree analysis for {}@{}...",
            name, report.version
        );
        let tree_findings = analyzers::deptree::DepTreeAnalyzer::new()
            .analyze(&name, &report.version, None)
            .await;
        report.findings.extend(tree_findings);
        report.findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    }

    // Re-score after adding new findings.
    if compare_version.is_some() || deep {
        report = scoring::calculator::build_report(
            &report.package_name,
            &report.version,
            report.findings,
        );
    }

    // Apply ignore rules.
    if !ignore_rules.is_empty() {
        let (kept, ignored_count) = filter_ignored(report.findings, ignore_rules);
        if ignored_count > 0 {
            eprintln!("  {} finding(s) ignored by rules", ignored_count);
        }
        report = scoring::calculator::build_report(&report.package_name, &report.version, kept);
    }

    if sarif_output {
        let sarif = output::sarif::generate_sarif(std::slice::from_ref(&report));
        let sarif_str = serde_json::to_string_pretty(&sarif)
            .context("failed to serialize SARIF output")?;
        println!("{}", sarif_str);
    } else if json_output {
        output::json::print_json(&report);
    } else {
        output::terminal::print_report(&report);
        println!();
    }

    // Exit code: 1 if risk is High or Critical, 0 otherwise.
    let exit_high = matches!(report.risk_label, RiskLabel::High | RiskLabel::Critical);

    if exit_high {
        process::exit(1);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// `aegis scan`
// ---------------------------------------------------------------------------

/// Read a project's package.json and collect `(name, version_spec)` pairs for
/// all its dependencies.
fn collect_dependencies(project_path: &Path, skip_dev: bool) -> Result<Vec<(String, String)>> {
    let pkg_path = project_path.join("package.json");
    let raw = std::fs::read_to_string(&pkg_path)
        .with_context(|| format!("could not read {}", pkg_path.display()))?;
    let pkg: serde_json::Value =
        serde_json::from_str(&raw).context("failed to parse package.json")?;

    let mut deps: Vec<(String, String)> = Vec::new();

    if let Some(obj) = pkg.get("dependencies").and_then(|v| v.as_object()) {
        for (name, ver) in obj {
            deps.push((name.clone(), ver.as_str().unwrap_or("latest").to_string()));
        }
    }

    if !skip_dev {
        if let Some(obj) = pkg.get("devDependencies").and_then(|v| v.as_object()) {
            for (name, ver) in obj {
                deps.push((name.clone(), ver.as_str().unwrap_or("latest").to_string()));
            }
        }
    }

    // Sort for deterministic output.
    deps.sort_by(|a, b| a.0.cmp(&b.0));

    Ok(deps)
}

/// Clean a semver range into an exact version hint, or None if we should
/// resolve "latest".
///
/// This is intentionally simplistic: strip leading `^`, `~`, `>=`, `=` and
/// keep whatever remains.  If the result doesn't look like a version string
/// we return None and let the registry resolve it.
fn clean_version_spec(spec: &str) -> Option<String> {
    let trimmed = spec
        .trim_start_matches('^')
        .trim_start_matches('~')
        .trim_start_matches(">=")
        .trim_start_matches('=')
        .trim();

    if trimmed.is_empty() || trimmed == "*" || trimmed.contains("||") || trimmed.contains(' ') {
        return None;
    }

    Some(trimmed.to_string())
}

async fn run_scan(
    project_path: &Path,
    skip_dev: bool,
    json_output: bool,
    sarif_output: bool,
    no_cache: bool,
    custom_rules_dir: Option<&Path>,
    ignore_rules: &[String],
) -> Result<()> {
    let deps = collect_dependencies(project_path, skip_dev)?;
    let total = deps.len();

    if total == 0 {
        println!("No dependencies found in {}", project_path.display());
        return Ok(());
    }

    eprintln!("\n\u{1f4e6} Scanning {} dependencies...\n", total);

    let use_cache = !no_cache;
    let mut reports: Vec<AnalysisReport> = Vec::new();
    let mut errors: Vec<(String, String)> = Vec::new();

    for (i, (name, version_spec)) in deps.iter().enumerate() {
        let idx = i + 1;
        let version_hint = clean_version_spec(version_spec);
        let display_ver = version_hint.as_deref().unwrap_or("latest");

        let prefix = format!("  [{}/{}] ", idx, total);

        eprintln!(
            "  [{}/{}] Checking {}@{}...",
            idx,
            total,
            name.bold(),
            display_ver
        );

        match analyze_package(
            name,
            version_hint.as_deref(),
            use_cache,
            &prefix,
            custom_rules_dir,
        )
        .await
        {
            Ok(report) => reports.push(report),
            Err(e) => {
                eprintln!(
                    "  [{}/{}] \u{274c} Failed to analyze {}: {:#}",
                    idx, total, name, e
                );
                errors.push((name.clone(), format!("{:#}", e)));
            }
        }
    }

    // Apply ignore rules to all reports.
    if !ignore_rules.is_empty() {
        let mut total_ignored = 0;
        reports = reports
            .into_iter()
            .map(|r| {
                let (kept, ignored) = filter_ignored(r.findings, ignore_rules);
                total_ignored += ignored;
                scoring::calculator::build_report(&r.package_name, &r.version, kept)
            })
            .collect();
        if total_ignored > 0 {
            eprintln!("  {} finding(s) ignored by rules", total_ignored);
        }
    }

    // ----- Output -----

    if sarif_output {
        let sarif = output::sarif::generate_sarif(&reports);
        println!(
            "{}",
            serde_json::to_string_pretty(&sarif).context("failed to serialize SARIF output")?
        );
    } else if json_output {
        let json =
            serde_json::to_string_pretty(&reports).context("failed to serialize scan results")?;
        println!("{}", json);
    } else {
        print_scan_summary(&reports, &errors);
    }

    // Exit code 1 if any dependency is High or Critical.
    let has_high = reports
        .iter()
        .any(|r| matches!(r.risk_label, RiskLabel::High | RiskLabel::Critical));

    if has_high {
        process::exit(1);
    }

    Ok(())
}

/// Bucket counts by risk label.
struct RiskBuckets {
    critical: Vec<AnalysisReport>,
    high: Vec<AnalysisReport>,
    medium: Vec<AnalysisReport>,
    clean: Vec<AnalysisReport>, // Clean + Low
}

fn bucket_reports(reports: &[AnalysisReport]) -> RiskBuckets {
    let mut b = RiskBuckets {
        critical: Vec::new(),
        high: Vec::new(),
        medium: Vec::new(),
        clean: Vec::new(),
    };
    for r in reports {
        match r.risk_label {
            RiskLabel::Critical => b.critical.push(r.clone()),
            RiskLabel::High => b.high.push(r.clone()),
            RiskLabel::Medium => b.medium.push(r.clone()),
            RiskLabel::Low | RiskLabel::Clean => b.clean.push(r.clone()),
        }
    }
    b
}

fn print_scan_summary(reports: &[AnalysisReport], errors: &[(String, String)]) {
    let b = bucket_reports(reports);

    println!();
    if !b.critical.is_empty() {
        println!(
            "  \u{26d4} {} critical",
            b.critical.len().to_string().red().bold()
        );
    }
    if !b.high.is_empty() {
        println!(
            "  \u{26a0}\u{fe0f}  {} high risk",
            b.high.len().to_string().red()
        );
    }
    if !b.medium.is_empty() {
        println!(
            "  \u{26a1} {} medium risk",
            b.medium.len().to_string().yellow()
        );
    }
    println!("  \u{2705} {} clean", b.clean.len().to_string().green());
    if !errors.is_empty() {
        println!("  \u{274c} {} failed", errors.len().to_string().red());
    }
    println!();

    // Detailed lists for critical and high.
    if !b.critical.is_empty() {
        println!("  {}:", "CRITICAL".red().bold());
        print_report_list(&b.critical);
        println!();
    }

    if !b.high.is_empty() {
        println!("  {}:", "HIGH".red());
        print_report_list(&b.high);
        println!();
    }

    if !b.medium.is_empty() {
        println!("  {}:", "MEDIUM".yellow());
        print_report_list(&b.medium);
        println!();
    }

    if !errors.is_empty() {
        println!("  {}:", "ERRORS".red());
        for (i, (name, err)) in errors.iter().enumerate() {
            let connector = if i == errors.len() - 1 {
                "\u{2514}\u{2500}"
            } else {
                "\u{251c}\u{2500}"
            };
            println!("  {} {} \u{2014} {}", connector, name.bold(), err.dimmed());
        }
        println!();
    }

    println!(
        "  Full results: {} for details",
        "aegis check <package>".bold()
    );
    println!();
}

fn print_report_list(reports: &[AnalysisReport]) {
    for (i, r) in reports.iter().enumerate() {
        let connector = if i == reports.len() - 1 {
            "\u{2514}\u{2500}"
        } else {
            "\u{251c}\u{2500}"
        };

        // Build a short description from the top finding(s).
        let desc = if r.findings.is_empty() {
            "no details".to_string()
        } else {
            // Summarize the top 1-2 finding titles.
            let summaries: Vec<&str> = r
                .findings
                .iter()
                .take(2)
                .map(|f| f.title.as_str())
                .collect();
            summaries.join(", ")
        };

        println!(
            "  {} {}@{} \u{2014} {} ({:.1}/10)",
            connector,
            r.package_name.bold(),
            r.version,
            desc,
            r.risk_score
        );
    }
}

// ---------------------------------------------------------------------------
// `aegis install`
// ---------------------------------------------------------------------------

/// Prompt the user for y/N confirmation. Returns true if the user types "y" or
/// "yes" (case-insensitive). Defaults to No on empty input.
fn confirm(prompt: &str) -> bool {
    eprint!("{}", prompt);
    std::io::stderr().flush().ok();
    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

/// Run `npm install` with optional package arguments. Returns the exit status.
fn run_npm_install(packages: &[String]) -> Result<()> {
    let mut cmd = std::process::Command::new("npm");
    cmd.arg("install");
    for pkg in packages {
        cmd.arg(pkg);
    }

    eprintln!("\n\u{1f4e6} Running: npm install {}\n", packages.join(" "));

    let status = cmd
        .status()
        .context("failed to run `npm install` — is npm installed and on PATH?")?;

    if !status.success() {
        anyhow::bail!("`npm install` exited with status {}", status);
    }

    Ok(())
}

async fn run_install(
    packages: &[String],
    force: bool,
    skip_dev: bool,
    no_cache: bool,
) -> Result<()> {
    let use_cache = !no_cache;

    if packages.is_empty() {
        // ---- No explicit packages: scan the whole project, then npm install ----
        let project_path = PathBuf::from(".");
        let deps = collect_dependencies(&project_path, skip_dev)?;
        let total = deps.len();

        if total == 0 {
            eprintln!("No dependencies found in package.json — running npm install directly.");
            return run_npm_install(&[]);
        }

        eprintln!(
            "\n\u{1f50d} Scanning {} dependencies before install...\n",
            total
        );

        let mut reports: Vec<AnalysisReport> = Vec::new();
        let mut errors: Vec<(String, String)> = Vec::new();

        for (i, (name, version_spec)) in deps.iter().enumerate() {
            let idx = i + 1;
            let version_hint = clean_version_spec(version_spec);
            let display_ver = version_hint.as_deref().unwrap_or("latest");
            let prefix = format!("  [{}/{}] ", idx, total);

            eprintln!(
                "  [{}/{}] Checking {}@{}...",
                idx,
                total,
                name.bold(),
                display_ver
            );

            match analyze_package(name, version_hint.as_deref(), use_cache, &prefix, None).await {
                Ok(report) => reports.push(report),
                Err(e) => {
                    eprintln!(
                        "  [{}/{}] \u{274c} Failed to analyze {}: {:#}",
                        idx, total, name, e
                    );
                    errors.push((name.clone(), format!("{:#}", e)));
                }
            }
        }

        // Show summary.
        print_scan_summary(&reports, &errors);

        let risky: Vec<&AnalysisReport> = reports
            .iter()
            .filter(|r| matches!(r.risk_label, RiskLabel::High | RiskLabel::Critical))
            .collect();

        if !risky.is_empty() && !force {
            eprintln!(
                "\u{26a0}\u{fe0f} {} package(s) rated HIGH or CRITICAL risk:",
                risky.len()
            );
            for r in &risky {
                eprintln!(
                    "  - {}@{} ({}, {:.1}/10)",
                    r.package_name.bold(),
                    r.version,
                    r.risk_label,
                    r.risk_score
                );
            }
            eprintln!();

            if !confirm("Proceed with npm install anyway? [y/N] ") {
                eprintln!("Aborted.");
                process::exit(1);
            }
        }

        run_npm_install(&[])
    } else {
        // ---- Explicit packages: check each, then npm install the approved set ----
        let mut approved: Vec<String> = Vec::new();
        let prefix = "  \u{1f50d} ";

        for spec in packages {
            let (name, version) = parse_package_specifier(spec);

            eprintln!("\n\u{1f50d} Checking {} before install...\n", spec.bold());

            let report =
                match analyze_package(&name, version.as_deref(), use_cache, prefix, None).await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("\u{274c} Failed to analyze {}: {:#}", spec, e);
                        // If analysis fails, still ask whether to install.
                        if force
                            || confirm(&format!(
                                "Could not analyze {}. Install anyway? [y/N] ",
                                spec
                            ))
                        {
                            approved.push(spec.clone());
                        }
                        continue;
                    }
                };

            output::terminal::print_report(&report);

            let is_risky = matches!(report.risk_label, RiskLabel::High | RiskLabel::Critical);

            if is_risky && !force {
                let prompt = format!(
                    "\n\u{26a0}\u{fe0f}  {} has {} ({:.1}/10). Install anyway? [y/N] ",
                    spec.bold(),
                    report.risk_label.to_string().red(),
                    report.risk_score
                );
                if !confirm(&prompt) {
                    eprintln!("Skipping {}.", spec);
                    continue;
                }
            }

            approved.push(spec.clone());
        }

        if approved.is_empty() {
            eprintln!("No packages approved for installation.");
            return Ok(());
        }

        run_npm_install(&approved)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unscoped_no_version() {
        let (name, ver) = parse_package_specifier("axios");
        assert_eq!(name, "axios");
        assert_eq!(ver, None);
    }

    #[test]
    fn parse_unscoped_with_version() {
        let (name, ver) = parse_package_specifier("axios@1.7.0");
        assert_eq!(name, "axios");
        assert_eq!(ver, Some("1.7.0".to_string()));
    }

    #[test]
    fn parse_scoped_no_version() {
        let (name, ver) = parse_package_specifier("@scope/pkg");
        assert_eq!(name, "@scope/pkg");
        assert_eq!(ver, None);
    }

    #[test]
    fn parse_scoped_with_version() {
        let (name, ver) = parse_package_specifier("@scope/pkg@1.0.0");
        assert_eq!(name, "@scope/pkg");
        assert_eq!(ver, Some("1.0.0".to_string()));
    }

    #[test]
    fn clean_version_spec_caret() {
        assert_eq!(clean_version_spec("^4.18.0"), Some("4.18.0".to_string()));
    }

    #[test]
    fn clean_version_spec_tilde() {
        assert_eq!(clean_version_spec("~1.2.3"), Some("1.2.3".to_string()));
    }

    #[test]
    fn clean_version_spec_star() {
        assert_eq!(clean_version_spec("*"), None);
    }

    #[test]
    fn clean_version_spec_range() {
        assert_eq!(clean_version_spec(">=1.0.0 <2.0.0"), None);
    }

    #[test]
    fn clean_version_spec_exact() {
        assert_eq!(clean_version_spec("1.0.0"), Some("1.0.0".to_string()));
    }
}
