use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::registry::package::PackageMetadata;

/// Severity level for a finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single security finding from an analyzer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    pub category: FindingCategory,
    pub title: String,
    pub description: String,
    /// File where the finding was detected (relative to package root)
    pub file: Option<String>,
    /// Line number in the file
    pub line: Option<usize>,
    /// The matched code snippet
    pub snippet: Option<String>,
}

/// Categories of security findings
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingCategory {
    /// eval(), Function(), Buffer.from + eval patterns
    CodeExecution,
    /// http.request, fetch, dns.lookup, net.connect
    NetworkAccess,
    /// child_process, exec, spawn, execSync
    ProcessSpawn,
    /// fs operations on sensitive paths
    FileSystemAccess,
    /// Obfuscated/encoded code (high entropy, hex strings)
    Obfuscation,
    /// Suspicious preinstall/postinstall scripts
    InstallScript,
    /// Environment variable harvesting
    EnvAccess,
    /// Suspicious patterns that don't fit other categories
    Suspicious,
    /// Maintainer changes (ownership transfers, new accounts, etc.)
    MaintainerChange,
    /// Package looks like an AI-hallucinated name (typosquat / fake package)
    HallucinatedPackage,
    /// Known vulnerability (CVE) from OSV.dev
    KnownVulnerability,
    /// Risks in the transitive dependency tree
    DependencyRisk,
    /// Provenance verification (npm tarball vs GitHub source)
    Provenance,
    /// Binary/executable files detected in package
    BinaryFile,
    /// Multi-step data flow analysis (taint tracking)
    DataFlow,
}

impl fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindingCategory::CodeExecution => write!(f, "Code Execution"),
            FindingCategory::NetworkAccess => write!(f, "Network Access"),
            FindingCategory::ProcessSpawn => write!(f, "Process Spawn"),
            FindingCategory::FileSystemAccess => write!(f, "File System Access"),
            FindingCategory::Obfuscation => write!(f, "Obfuscation"),
            FindingCategory::InstallScript => write!(f, "Install Script"),
            FindingCategory::EnvAccess => write!(f, "Env Access"),
            FindingCategory::Suspicious => write!(f, "Suspicious"),
            FindingCategory::MaintainerChange => write!(f, "Maintainer Change"),
            FindingCategory::HallucinatedPackage => write!(f, "Hallucinated Package"),
            FindingCategory::KnownVulnerability => write!(f, "Known Vulnerability"),
            FindingCategory::DependencyRisk => write!(f, "Dependency Risk"),
            FindingCategory::Provenance => write!(f, "Provenance"),
            FindingCategory::BinaryFile => write!(f, "Binary File"),
            FindingCategory::DataFlow => write!(f, "Data Flow"),
        }
    }
}

/// Complete analysis report for a package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub package_name: String,
    pub version: String,
    pub findings: Vec<Finding>,
    pub risk_score: f64,
    pub risk_label: RiskLabel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RiskLabel {
    Clean,
    Low,
    Medium,
    High,
    Critical,
}

/// Context passed to unified analyzers, containing all data needed for analysis.
pub struct AnalysisContext<'a> {
    pub name: &'a str,
    pub version: &'a str,
    pub files: &'a [(PathBuf, String)],
    pub package_json: &'a serde_json::Value,
    pub metadata: &'a PackageMetadata,
    pub package_dir: &'a Path,
}

impl fmt::Display for RiskLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLabel::Clean => write!(f, "CLEAN"),
            RiskLabel::Low => write!(f, "LOW RISK"),
            RiskLabel::Medium => write!(f, "MEDIUM RISK"),
            RiskLabel::High => write!(f, "HIGH RISK"),
            RiskLabel::Critical => write!(f, "DO NOT INSTALL"),
        }
    }
}
