use std::path::PathBuf;

use tree_sitter::{Language, Node, Parser};

use crate::types::{Finding, FindingCategory, Severity};

use super::{truncate, Analyzer};

// ---------------------------------------------------------------------------
// AST-based security analyzer
// ---------------------------------------------------------------------------

pub struct AstAnalyzer;

/// Maximum file size to parse (1 MB). Larger files are skipped to avoid slow
/// tree-sitter parsing.
const MAX_FILE_SIZE: usize = 1_024 * 1_024;

/// Nesting depth threshold for obfuscation detection.
const DEEP_NESTING_THRESHOLD: usize = 5;

// ---------------------------------------------------------------------------
// Language selection
// ---------------------------------------------------------------------------

fn language_for_ext(ext: &str) -> Option<Language> {
    match ext {
        "js" | "cjs" | "mjs" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "ts" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "tsx" => Some(tree_sitter_typescript::LANGUAGE_TSX.into()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl Analyzer for AstAnalyzer {
    fn analyze(
        &self,
        files: &[(PathBuf, String)],
        _package_json: &serde_json::Value,
    ) -> Vec<Finding> {
        let mut parser = Parser::new();

        let mut findings = Vec::new();

        for (path, content) in files {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let lang = match language_for_ext(ext) {
                Some(l) => l,
                None => continue,
            };

            // Skip minified files
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if file_name.contains(".min.") {
                continue;
            }

            // Skip dist/bundle/build directories — build outputs cause false positives
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

            // Skip files that are too large
            if content.len() > MAX_FILE_SIZE {
                continue;
            }

            parser
                .set_language(&lang)
                .expect("failed to load grammar");

            let tree = match parser.parse(content, None) {
                Some(t) => t,
                None => continue,
            };

            let root = tree.root_node();
            walk_node(root, content, &path_str, &mut findings);
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Recursive tree walker
// ---------------------------------------------------------------------------

fn walk_node(node: Node, source: &str, file: &str, findings: &mut Vec<Finding>) {
    match node.kind() {
        "call_expression" => {
            check_call_expression(node, source, file, findings);
        }
        "new_expression" => {
            check_new_expression(node, source, file, findings);
        }
        "member_expression" => {
            check_member_expression(node, source, file, findings);
        }
        "binary_expression" => {
            check_char_concat(node, source, file, findings);
        }
        "subscript_expression" => {
            check_computed_call(node, source, file, findings);
        }
        _ => {}
    }

    // Check deep nesting on any call_expression
    if node.kind() == "call_expression" {
        check_deep_nesting(node, source, file, findings);
    }

    // Recurse into children
    let child_count = node.child_count();
    for i in 0..child_count {
        if let Some(child) = node.child(i) {
            walk_node(child, source, file, findings);
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers to extract node text
// ---------------------------------------------------------------------------

fn node_text<'a>(node: Node, source: &'a str) -> &'a str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

fn line_number(node: Node) -> usize {
    node.start_position().row + 1 // tree-sitter rows are 0-based
}

fn snippet_for(node: Node, source: &str) -> String {
    truncate(node_text(node, source), 120)
}

// ---------------------------------------------------------------------------
// CRITICAL: Code execution patterns
// ---------------------------------------------------------------------------

/// Detect `eval(...)` where the argument is NOT a string literal.
fn check_eval_dynamic(
    node: Node,
    args_node: Node,
    source: &str,
    file: &str,
    findings: &mut Vec<Finding>,
) {
    let callee_text = node_text(node, source);
    if callee_text != "eval" {
        return;
    }
    // If the first argument is a string literal, it's less suspicious
    if let Some(first_arg) = args_node.child(1) {
        // child(0) is '(', child(1) is the first argument
        if first_arg.kind() == "string" {
            return; // Static eval — less suspicious
        }
    }

    findings.push(Finding {
        severity: Severity::Critical,
        category: FindingCategory::CodeExecution,
        title: "Dynamic eval() detected (AST-verified)".to_string(),
        description: "eval() called with a non-literal argument — can execute arbitrary code"
            .to_string(),
        file: Some(file.to_string()),
        line: Some(line_number(args_node)),
        snippet: Some(snippet_for(args_node.parent().unwrap_or(args_node), source)),
    });
}

/// Detect `new Function(...)` with non-literal arguments.
fn check_new_expression(node: Node, source: &str, file: &str, findings: &mut Vec<Finding>) {
    // new_expression -> constructor + arguments
    let constructor = match node.child_by_field_name("constructor") {
        Some(c) => c,
        None => return,
    };
    if node_text(constructor, source) != "Function" {
        return;
    }
    let args = match node.child_by_field_name("arguments") {
        Some(a) => a,
        None => return,
    };
    // Check if ALL arguments are string literals
    let mut all_literal = true;
    let arg_count = args.child_count();
    for i in 0..arg_count {
        if let Some(arg) = args.child(i) {
            if arg.kind() != "string" && arg.kind() != "(" && arg.kind() != ")" && arg.kind() != ","
            {
                all_literal = false;
                break;
            }
        }
    }
    if all_literal {
        return;
    }

    findings.push(Finding {
        severity: Severity::Critical,
        category: FindingCategory::CodeExecution,
        title: "new Function() with dynamic arguments (AST-verified)".to_string(),
        description:
            "Function constructor with non-literal arguments enables arbitrary code execution"
                .to_string(),
        file: Some(file.to_string()),
        line: Some(line_number(node)),
        snippet: Some(snippet_for(node, source)),
    });
}

/// Detect `require('child_process').exec(...)` call chains and `import('child_process')`.
fn check_child_process_call(
    callee: Node,
    source: &str,
    file: &str,
    findings: &mut Vec<Finding>,
    full_node: Node,
) {
    let callee_text = node_text(callee, source);

    // Pattern: require('child_process').exec / .execSync / .spawn
    if callee.kind() == "member_expression" {
        if let Some(object) = callee.child_by_field_name("object") {
            let obj_text = node_text(object, source);
            if obj_text.contains("child_process")
                && (obj_text.contains("require") || obj_text.contains("import"))
            {
                if let Some(prop) = callee.child_by_field_name("property") {
                    let prop_name = node_text(prop, source);
                    if matches!(
                        prop_name,
                        "exec"
                            | "execSync"
                            | "spawn"
                            | "spawnSync"
                            | "execFile"
                            | "execFileSync"
                            | "fork"
                    ) {
                        findings.push(Finding {
                            severity: Severity::Critical,
                            category: FindingCategory::ProcessSpawn,
                            title: format!("child_process.{prop_name}() call chain (AST-verified)"),
                            description:
                                "Direct child_process method invocation can execute system commands"
                                    .to_string(),
                            file: Some(file.to_string()),
                            line: Some(line_number(full_node)),
                            snippet: Some(snippet_for(full_node, source)),
                        });
                    }
                }
            }
        }
    }

    // Pattern: import('child_process')  — dynamic import
    if callee_text == "import" {
        if let Some(parent) = callee.parent() {
            let parent_text = node_text(parent, source);
            if parent_text.contains("child_process") {
                findings.push(Finding {
                    severity: Severity::Critical,
                    category: FindingCategory::ProcessSpawn,
                    title: "Dynamic import('child_process') (AST-verified)".to_string(),
                    description: "Dynamically imports child_process module for shell access"
                        .to_string(),
                    file: Some(file.to_string()),
                    line: Some(line_number(full_node)),
                    snippet: Some(snippet_for(full_node, source)),
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HIGH: Data exfiltration patterns
// ---------------------------------------------------------------------------

/// Detect `fs.readFileSync('/etc/passwd')` and similar sensitive paths.
fn check_sensitive_read(
    callee: Node,
    args: Node,
    source: &str,
    file: &str,
    findings: &mut Vec<Finding>,
    full_node: Node,
) {
    let callee_text = node_text(callee, source);
    if !(callee_text.contains("readFileSync") || callee_text.contains("readFile")) {
        return;
    }

    // Check first argument for a sensitive path
    if let Some(first_arg) = args.child(1) {
        if first_arg.kind() == "string" {
            let path_val = node_text(first_arg, source);
            let sensitive = [
                "/etc/passwd",
                "/etc/shadow",
                "~/.ssh",
                "~/.aws",
                "~/.npmrc",
                ".env",
                ".git/config",
                "/etc/hosts",
            ];
            for s in &sensitive {
                if path_val.contains(s) {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: FindingCategory::FileSystemAccess,
                        title: "Read of sensitive file path (AST-verified)".to_string(),
                        description: format!(
                            "Reads sensitive path {s} — potential credential theft"
                        ),
                        file: Some(file.to_string()),
                        line: Some(line_number(full_node)),
                        snippet: Some(snippet_for(full_node, source)),
                    });
                    return;
                }
            }
        }
    }
}

/// Detect `process.env` access (for scope-level exfiltration checks).
fn check_process_env_access(node: Node, source: &str, file: &str, findings: &mut Vec<Finding>) {
    let text = node_text(node, source);
    if text != "process.env" {
        return;
    }

    // Walk up to the nearest function scope and look for network calls
    let mut parent = node.parent();
    while let Some(p) = parent {
        if matches!(
            p.kind(),
            "function_declaration" | "arrow_function" | "function_expression" | "method_definition"
        ) {
            let scope_text = node_text(p, source);
            if scope_text.contains("fetch(")
                || scope_text.contains("http.request")
                || scope_text.contains("https.request")
                || scope_text.contains("XMLHttpRequest")
                || scope_text.contains("axios")
                || scope_text.contains(".post(")
                || scope_text.contains("request(")
            {
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::EnvAccess,
                    title: "process.env access with network call in same scope (AST-verified)"
                        .to_string(),
                    description:
                        "Reads environment variables and makes a network request in the same function — credential stealing pattern"
                            .to_string(),
                    file: Some(file.to_string()),
                    line: Some(line_number(node)),
                    snippet: Some(snippet_for(node, source)),
                });
            }
            break;
        }
        parent = p.parent();
    }
}

/// Detect `Buffer.from(...).toString('base64')` followed by fetch/http in scope.
fn check_base64_exfiltration(
    callee: Node,
    source: &str,
    file: &str,
    findings: &mut Vec<Finding>,
    full_node: Node,
) {
    let callee_text = node_text(callee, source);
    if !callee_text.contains("toString") {
        return;
    }

    // Check if the object chain includes Buffer.from
    if let Some(obj) = callee.child_by_field_name("object") {
        let obj_text = node_text(obj, source);
        if !obj_text.contains("Buffer.from") {
            return;
        }
    } else {
        return;
    }

    // Check argument is 'base64'
    if let Some(parent) = callee.parent() {
        let parent_text = node_text(parent, source);
        if !parent_text.contains("base64") {
            return;
        }
    }

    // Walk up to function scope and check for network calls
    let mut parent = full_node.parent();
    while let Some(p) = parent {
        if matches!(
            p.kind(),
            "function_declaration"
                | "arrow_function"
                | "function_expression"
                | "method_definition"
                | "program"
        ) {
            let scope_text = node_text(p, source);
            if scope_text.contains("fetch(")
                || scope_text.contains("http.request")
                || scope_text.contains("https.request")
                || scope_text.contains("request(")
            {
                findings.push(Finding {
                    severity: Severity::High,
                    category: FindingCategory::NetworkAccess,
                    title: "Base64 encode then exfiltrate pattern (AST-verified)".to_string(),
                    description: "Buffer.from().toString('base64') combined with a network call — data exfiltration pattern".to_string(),
                    file: Some(file.to_string()),
                    line: Some(line_number(full_node)),
                    snippet: Some(snippet_for(full_node, source)),
                });
            }
            break;
        }
        parent = p.parent();
    }
}

// ---------------------------------------------------------------------------
// HIGH: Obfuscation patterns
// ---------------------------------------------------------------------------

/// Detect deeply nested call expressions (> DEEP_NESTING_THRESHOLD levels).
fn check_deep_nesting(node: Node, source: &str, file: &str, findings: &mut Vec<Finding>) {
    let mut depth: usize = 0;
    let mut current = node;
    loop {
        // Look for a call_expression among the children (callee position)
        let callee = current.child_by_field_name("function");
        match callee {
            Some(c) if c.kind() == "call_expression" => {
                depth += 1;
                current = c;
            }
            _ => break,
        }
    }

    if depth > DEEP_NESTING_THRESHOLD {
        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::Obfuscation,
            title: format!(
                "Deeply nested function calls ({} levels, AST-verified)",
                depth
            ),
            description: "Excessive call nesting is common in obfuscated malicious code"
                .to_string(),
            file: Some(file.to_string()),
            line: Some(line_number(node)),
            snippet: Some(snippet_for(node, source)),
        });
    }
}

/// Detect computed property access used as a function call: `arr[0x1a]()`.
fn check_computed_call(node: Node, source: &str, file: &str, findings: &mut Vec<Finding>) {
    // subscript_expression as the callee of a call_expression
    if let Some(parent) = node.parent() {
        if parent.kind() == "call_expression" {
            // Check that the index is a computed (non-string, non-identifier) expression
            if let Some(index) = node.child_by_field_name("index") {
                if matches!(
                    index.kind(),
                    "number" | "binary_expression" | "unary_expression"
                ) {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: FindingCategory::Obfuscation,
                        title: "Computed array index used as function call (AST-verified)"
                            .to_string(),
                        description:
                            "Calling a function via computed array index (e.g. arr[0x1a]()) is common in obfuscated code"
                                .to_string(),
                        file: Some(file.to_string()),
                        line: Some(line_number(node)),
                        snippet: Some(snippet_for(parent, source)),
                    });
                }
            }
        }
    }
}

/// Detect string concatenation of single characters: `'h'+'t'+'t'+'p'`.
fn check_char_concat(node: Node, source: &str, file: &str, findings: &mut Vec<Finding>) {
    if node.kind() != "binary_expression" {
        return;
    }
    // Check operator is '+'
    if let Some(op) = node.child_by_field_name("operator") {
        if node_text(op, source) != "+" {
            return;
        }
    } else {
        return;
    }

    // Count consecutive single-char string concatenations
    let count = count_char_concats(node, source);
    if count >= 4 {
        findings.push(Finding {
            severity: Severity::High,
            category: FindingCategory::Obfuscation,
            title: format!(
                "Single-char string concatenation ({} chars, AST-verified)",
                count
            ),
            description:
                "Building strings by concatenating single characters is a common obfuscation technique"
                    .to_string(),
            file: Some(file.to_string()),
            line: Some(line_number(node)),
            snippet: Some(snippet_for(node, source)),
        });
    }
}

fn count_char_concats(node: Node, source: &str) -> usize {
    if node.kind() == "string" {
        let text = node_text(node, source);
        // A single-char string literal: 'x' or "x" (length 3 with quotes)
        if text.len() == 3 {
            return 1;
        }
        return 0;
    }
    if node.kind() != "binary_expression" {
        return 0;
    }
    let left = node.child_by_field_name("left");
    let right = node.child_by_field_name("right");
    let lc = left.map(|n| count_char_concats(n, source)).unwrap_or(0);
    let rc = right.map(|n| count_char_concats(n, source)).unwrap_or(0);
    if lc > 0 && rc > 0 {
        lc + rc
    } else {
        0
    }
}

// ---------------------------------------------------------------------------
// MEDIUM: Suspicious API usage
// ---------------------------------------------------------------------------

fn check_suspicious_api(
    callee: Node,
    source: &str,
    file: &str,
    findings: &mut Vec<Finding>,
    full_node: Node,
) {
    let callee_text = node_text(callee, source);

    // process.binding() — access to internal Node APIs
    if callee_text.contains("process.binding") {
        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::Suspicious,
            title: "process.binding() call (AST-verified)".to_string(),
            description:
                "Accesses internal Node.js C++ bindings — rarely needed in normal packages"
                    .to_string(),
            file: Some(file.to_string()),
            line: Some(line_number(full_node)),
            snippet: Some(snippet_for(full_node, source)),
        });
    }

    // vm.runInNewContext() / vm.createScript()
    if callee_text.contains("vm.runInNewContext")
        || callee_text.contains("vm.createScript")
        || callee_text.contains("vm.runInThisContext")
    {
        findings.push(Finding {
            severity: Severity::Medium,
            category: FindingCategory::CodeExecution,
            title: "VM code execution API (AST-verified)".to_string(),
            description: "Uses Node.js VM module for dynamic code execution".to_string(),
            file: Some(file.to_string()),
            line: Some(line_number(full_node)),
            snippet: Some(snippet_for(full_node, source)),
        });
    }
}

/// Check for Proxy/Reflect intercepting require/import at member_expression level.
fn check_proxy_reflect_intercept(
    node: Node,
    source: &str,
    file: &str,
    findings: &mut Vec<Finding>,
) {
    let text = node_text(node, source);
    // Only fire if Proxy or Reflect is the object and is combined with require/import in scope
    if text == "Proxy" || text == "Reflect" {
        // Walk up to see if this is in a context that references require/import
        if let Some(parent) = node.parent() {
            if let Some(grandparent) = parent.parent() {
                let ctx = node_text(grandparent, source);
                if ctx.contains("require") || ctx.contains("import") {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        category: FindingCategory::Suspicious,
                        title: format!("{text} used to intercept module loading (AST-verified)"),
                        description: format!(
                            "{text} combined with require/import can intercept module resolution"
                        ),
                        file: Some(file.to_string()),
                        line: Some(line_number(node)),
                        snippet: Some(snippet_for(grandparent, source)),
                    });
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Main call_expression dispatcher
// ---------------------------------------------------------------------------

fn check_call_expression(node: Node, source: &str, file: &str, findings: &mut Vec<Finding>) {
    let callee = match node.child_by_field_name("function") {
        Some(c) => c,
        None => return,
    };
    let args = match node.child_by_field_name("arguments") {
        Some(a) => a,
        None => return,
    };

    // CRITICAL: dynamic eval()
    check_eval_dynamic(callee, args, source, file, findings);

    // CRITICAL: child_process call chains & dynamic import('child_process')
    check_child_process_call(callee, source, file, findings, node);

    // HIGH: sensitive file reads
    check_sensitive_read(callee, args, source, file, findings, node);

    // HIGH: base64 encode + exfiltrate
    check_base64_exfiltration(callee, source, file, findings, node);

    // MEDIUM: suspicious APIs
    check_suspicious_api(callee, source, file, findings, node);
}

fn check_member_expression(node: Node, source: &str, file: &str, findings: &mut Vec<Finding>) {
    // HIGH: process.env access + network call in same scope
    check_process_env_access(node, source, file, findings);

    // MEDIUM: Proxy / Reflect intercept
    if let Some(object) = node.child_by_field_name("object") {
        check_proxy_reflect_intercept(object, source, file, findings);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn analyze_js(code: &str) -> Vec<Finding> {
        let analyzer = AstAnalyzer;
        let files = vec![(PathBuf::from("index.js"), code.to_string())];
        let pkg = serde_json::json!({});
        analyzer.analyze(&files, &pkg)
    }

    #[test]
    fn detects_dynamic_eval() {
        let findings = analyze_js("const x = eval(userInput);");
        assert!(!findings.is_empty(), "should detect dynamic eval");
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[test]
    fn ignores_static_eval() {
        let findings = analyze_js(r#"eval("console.log('ok')");"#);
        let eval_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("eval"))
            .collect();
        assert!(eval_findings.is_empty(), "should ignore static eval");
    }

    #[test]
    fn detects_new_function_dynamic() {
        let findings = analyze_js("const f = new Function(code);");
        assert!(!findings.is_empty(), "should detect dynamic new Function");
    }

    #[test]
    fn detects_sensitive_read() {
        let findings = analyze_js(r#"fs.readFileSync('/etc/passwd');"#);
        let fs_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("sensitive"))
            .collect();
        assert!(!fs_findings.is_empty(), "should detect sensitive file read");
    }

    #[test]
    fn detects_char_concatenation() {
        let findings = analyze_js("const url = 'h'+'t'+'t'+'p';");
        let obf: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Single-char"))
            .collect();
        assert!(!obf.is_empty(), "should detect char concatenation");
    }

    #[test]
    fn detects_eval_in_ts_files() {
        let analyzer = AstAnalyzer;
        let files = vec![(PathBuf::from("index.ts"), "eval(x);".to_string())];
        let pkg = serde_json::json!({});
        let findings = analyzer.analyze(&files, &pkg);
        assert!(!findings.is_empty(), "should detect eval in .ts files");
    }

    #[test]
    fn skips_non_js_ts_files() {
        let analyzer = AstAnalyzer;
        let files = vec![(PathBuf::from("index.py"), "eval(x);".to_string())];
        let pkg = serde_json::json!({});
        let findings = analyzer.analyze(&files, &pkg);
        assert!(findings.is_empty(), "should skip non-JS/TS files");
    }

    #[test]
    fn skips_minified_files() {
        let analyzer = AstAnalyzer;
        let files = vec![(PathBuf::from("bundle.min.js"), "eval(x);".to_string())];
        let pkg = serde_json::json!({});
        let findings = analyzer.analyze(&files, &pkg);
        assert!(findings.is_empty(), "should skip .min.js files");
    }

    #[test]
    fn detects_process_binding() {
        let findings = analyze_js("process.binding('spawn_sync');");
        let sus: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("process.binding"))
            .collect();
        assert!(!sus.is_empty(), "should detect process.binding()");
    }
}
