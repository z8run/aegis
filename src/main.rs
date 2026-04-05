use std::io::IsTerminal;
use std::path::Path;
use std::process;

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;

use aegis_scan::cache;
use aegis_scan::cli::{
    clean_version_spec, collect_dependencies, parse_package_specifier, CacheCommands, Cli, Commands,
};
use aegis_scan::commands::install::run_install;
use aegis_scan::ignore::{filter_ignored, load_ignore_files};
use aegis_scan::output;
use aegis_scan::output::scan_summary::print_scan_summary;
use aegis_scan::pipeline::analyze_package;
use aegis_scan::registry;
use aegis_scan::scoring;
use aegis_scan::types::{AnalysisReport, RiskLabel};

use registry::tarball;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Disable colors when requested via flag, NO_COLOR env var, or non-TTY stdout.
    if cli.no_color || std::env::var_os("NO_COLOR").is_some() || !std::io::stdout().is_terminal() {
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

        let diff_findings = aegis_scan::analyzers::diff::DiffAnalyzer::analyze_diff(
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
        let tree_findings = aegis_scan::analyzers::deptree::DepTreeAnalyzer::new()
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
        let sarif_str =
            serde_json::to_string_pretty(&sarif).context("failed to serialize SARIF output")?;
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
