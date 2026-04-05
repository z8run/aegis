use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::types::{Finding, FindingCategory, Severity};

// ---------------------------------------------------------------------------
// Binary file extensions
// ---------------------------------------------------------------------------

/// Extensions considered native addons / executables (HIGH severity).
const NATIVE_EXTENSIONS: &[&str] = &["node", "exe", "dll", "so", "dylib"];

/// Extensions considered WebAssembly (MEDIUM severity).
const WASM_EXTENSIONS: &[&str] = &["wasm"];

/// All binary extensions we scan for.
const ALL_BINARY_EXTENSIONS: &[&str] = &["wasm", "node", "exe", "dll", "so", "dylib"];

// ---------------------------------------------------------------------------
// Suspicious strings to look for inside binaries
// ---------------------------------------------------------------------------

const SHELL_COMMANDS: &[&str] = &[
    "/bin/sh",
    "/bin/bash",
    "/bin/zsh",
    "cmd.exe",
    "powershell",
    "command.com",
];

const CREDENTIAL_STRINGS: &[&str] = &[
    "AWS_SECRET",
    "AWS_ACCESS_KEY",
    "NPM_TOKEN",
    "npm_token",
    "password",
    "passwd",
    ".npmrc",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "PRIVATE_KEY",
];

const SUSPICIOUS_URL_PREFIXES: &[&str] = &["http://", "https://", "ftp://", "ws://", "wss://"];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract printable ASCII strings of length >= `min_len` from raw bytes.
fn extract_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for &byte in data {
        if (0x20..0x7F).contains(&byte) {
            current.push(byte);
        } else {
            if current.len() >= min_len {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    strings.push(s);
                }
            }
            current.clear();
        }
    }
    // Don't forget the last run.
    if current.len() >= min_len {
        if let Ok(s) = String::from_utf8(current) {
            strings.push(s);
        }
    }

    strings
}

/// Compute Shannon entropy over raw bytes (0.0 – 8.0 for byte-level).
fn byte_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<u8, usize> = HashMap::new();
    for &b in data {
        *freq.entry(b).or_insert(0) += 1;
    }
    let len = data.len() as f64;
    freq.values().fold(0.0f64, |acc, &count| {
        let p = count as f64 / len;
        acc - p * p.log2()
    })
}

/// Walk a directory recursively and collect files matching given extensions.
fn collect_binary_files(dir: &Path, extensions: &[&str]) -> Vec<PathBuf> {
    let mut results = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                results.extend(collect_binary_files(&path, extensions));
            } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let ext_lower = ext.to_lowercase();
                if extensions.iter().any(|&e| e == ext_lower) {
                    results.push(path);
                }
            }
        }
    }
    results
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

/// Detects binary/executable files in a package and inspects their contents
/// for suspicious embedded strings and high-entropy (packed) payloads.
pub struct BinaryAnalyzer;

impl BinaryAnalyzer {
    /// Analyze the extracted package directory for binary files.
    ///
    /// Unlike the text-based `Analyzer` trait, this works directly on the
    /// filesystem because binary files are skipped by the normal text pipeline.
    pub fn analyze_directory(&self, package_dir: &Path) -> Vec<Finding> {
        let binary_paths = collect_binary_files(package_dir, ALL_BINARY_EXTENSIONS);
        let mut findings = Vec::new();

        for path in &binary_paths {
            let rel = path
                .strip_prefix(package_dir)
                .unwrap_or(path)
                .to_path_buf();
            let rel_str = rel.display().to_string();

            let ext = path
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_lowercase();

            // --- Presence finding ---
            if NATIVE_EXTENSIONS.contains(&ext.as_str()) {
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::BinaryFile,
                    title: format!("Native binary file: {}", rel_str),
                    description: format!(
                        "Package contains a native binary (.{}) which can execute arbitrary code",
                        ext
                    ),
                    file: Some(rel_str.clone()),
                    line: None,
                    snippet: None,
                });
            } else if WASM_EXTENSIONS.contains(&ext.as_str()) {
                findings.push(Finding {
                    severity: Severity::Medium,
                    category: FindingCategory::BinaryFile,
                    title: format!("WebAssembly file: {}", rel_str),
                    description:
                        "Package contains a .wasm file; verify it is expected for this package"
                            .to_string(),
                    file: Some(rel_str.clone()),
                    line: None,
                    snippet: None,
                });
            } else {
                findings.push(Finding {
                    severity: Severity::Low,
                    category: FindingCategory::BinaryFile,
                    title: format!("Binary file detected: {}", rel_str),
                    description: format!(
                        "Package contains a binary file (.{})",
                        ext
                    ),
                    file: Some(rel_str.clone()),
                    line: None,
                    snippet: None,
                });
            }

            // --- Content inspection ---
            let data = match std::fs::read(path) {
                Ok(d) => d,
                Err(_) => continue,
            };

            let strings = extract_strings(&data, 4);

            // Check for shell commands.
            for s in &strings {
                for &cmd in SHELL_COMMANDS {
                    if s.contains(cmd) {
                        findings.push(Finding {
                            severity: Severity::Critical,
                            category: FindingCategory::BinaryFile,
                            title: format!("Shell command in binary: {}", rel_str),
                            description: format!(
                                "Binary contains shell command reference: \"{}\"",
                                truncate_str(s, 80)
                            ),
                            file: Some(rel_str.clone()),
                            line: None,
                            snippet: Some(truncate_str(s, 100)),
                        });
                        break; // one finding per string is enough
                    }
                }
            }

            // Check for credential strings.
            for s in &strings {
                for &cred in CREDENTIAL_STRINGS {
                    if s.contains(cred) {
                        findings.push(Finding {
                            severity: Severity::Critical,
                            category: FindingCategory::BinaryFile,
                            title: format!("Credential string in binary: {}", rel_str),
                            description: format!(
                                "Binary contains credential-related string: \"{}\"",
                                truncate_str(s, 80)
                            ),
                            file: Some(rel_str.clone()),
                            line: None,
                            snippet: Some(truncate_str(s, 100)),
                        });
                        break;
                    }
                }
            }

            // Check for embedded URLs / IPs.
            for s in &strings {
                for &prefix in SUSPICIOUS_URL_PREFIXES {
                    if s.contains(prefix) {
                        findings.push(Finding {
                            severity: Severity::Critical,
                            category: FindingCategory::BinaryFile,
                            title: format!("URL embedded in binary: {}", rel_str),
                            description: format!(
                                "Binary contains an embedded URL: \"{}\"",
                                truncate_str(s, 120)
                            ),
                            file: Some(rel_str.clone()),
                            line: None,
                            snippet: Some(truncate_str(s, 100)),
                        });
                        break;
                    }
                }
            }

            // Check entropy for packed/encrypted payloads (only for files > 1 KB).
            if data.len() > 1024 {
                let entropy = byte_entropy(&data);
                // Byte-level entropy > 7.5 (out of 8.0) is very suspicious.
                if entropy > 7.5 {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: FindingCategory::BinaryFile,
                        title: format!("High-entropy binary: {}", rel_str),
                        description: format!(
                            "Binary has Shannon entropy {:.2}/8.0, suggesting packed or encrypted content",
                            entropy
                        ),
                        file: Some(rel_str.clone()),
                        line: None,
                        snippet: None,
                    });
                }
            }
        }

        findings
    }
}

/// Truncate a string for display.
fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max).collect();
        format!("{truncated}...")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_extract_strings_basic() {
        let data = b"hello\x00world\x00ab\x00longer_string\x00";
        let strings = extract_strings(data, 4);
        assert_eq!(strings, vec!["hello", "world", "longer_string"]);
    }

    #[test]
    fn test_extract_strings_min_length() {
        let data = b"hi\x00there\x00";
        let strings = extract_strings(data, 4);
        assert_eq!(strings, vec!["there"]);
    }

    #[test]
    fn test_byte_entropy_zero() {
        let data = vec![0u8; 100];
        let e = byte_entropy(&data);
        assert!((e - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_byte_entropy_high() {
        // All 256 byte values equally -> entropy = 8.0
        let data: Vec<u8> = (0..=255).collect();
        let e = byte_entropy(&data);
        assert!((e - 8.0).abs() < 0.01);
    }

    #[test]
    fn test_byte_entropy_empty() {
        assert!((byte_entropy(&[]) - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_detect_native_binary() {
        let dir = tempfile::tempdir().unwrap();
        let node_file = dir.path().join("addon.node");
        fs::write(&node_file, b"\x00\x00\x00\x00").unwrap();

        let analyzer = BinaryAnalyzer;
        let findings = analyzer.analyze_directory(dir.path());

        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::High && f.title.contains("Native binary")));
    }

    #[test]
    fn test_detect_wasm_file() {
        let dir = tempfile::tempdir().unwrap();
        let wasm_file = dir.path().join("module.wasm");
        fs::write(&wasm_file, b"\x00asm\x01\x00\x00\x00").unwrap();

        let analyzer = BinaryAnalyzer;
        let findings = analyzer.analyze_directory(dir.path());

        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Medium && f.title.contains("WebAssembly")));
    }

    #[test]
    fn test_detect_shell_command_in_binary() {
        let dir = tempfile::tempdir().unwrap();
        let bin_file = dir.path().join("malicious.node");
        let mut data = vec![0u8; 20];
        data.extend_from_slice(b"/bin/sh");
        data.extend_from_slice(&[0u8; 20]);
        fs::write(&bin_file, &data).unwrap();

        let analyzer = BinaryAnalyzer;
        let findings = analyzer.analyze_directory(dir.path());

        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.title.contains("Shell command")));
    }

    #[test]
    fn test_detect_credential_in_binary() {
        let dir = tempfile::tempdir().unwrap();
        let bin_file = dir.path().join("steal.dll");
        let mut data = vec![0u8; 20];
        data.extend_from_slice(b"AWS_SECRET_ACCESS_KEY");
        data.extend_from_slice(&[0u8; 20]);
        fs::write(&bin_file, &data).unwrap();

        let analyzer = BinaryAnalyzer;
        let findings = analyzer.analyze_directory(dir.path());

        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.title.contains("Credential")));
    }

    #[test]
    fn test_detect_url_in_binary() {
        let dir = tempfile::tempdir().unwrap();
        let bin_file = dir.path().join("exfil.so");
        let mut data = vec![0u8; 20];
        data.extend_from_slice(b"https://evil.com/steal");
        data.extend_from_slice(&[0u8; 20]);
        fs::write(&bin_file, &data).unwrap();

        let analyzer = BinaryAnalyzer;
        let findings = analyzer.analyze_directory(dir.path());

        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Critical && f.title.contains("URL")));
    }

    #[test]
    fn test_no_findings_for_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let analyzer = BinaryAnalyzer;
        let findings = analyzer.analyze_directory(dir.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_truncate_str() {
        assert_eq!(truncate_str("short", 10), "short");
        assert_eq!(truncate_str("hello world", 5), "hello...");
    }
}
