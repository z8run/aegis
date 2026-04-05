# Troubleshooting

Common issues and solutions for Aegis.

---

## "Rate limit exceeded" from GitHub API

The provenance analyzer compares npm tarball contents against the GitHub source repository. Unauthenticated requests are limited to 60/hour by GitHub.

**Fix:** Set a `GITHUB_TOKEN` environment variable with a personal access token (no special scopes required):

```bash
export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
aegis-scan check some-package
```

In CI, use a repository secret:

```yaml
env:
  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## False positive on a legitimate package

If a package triggers a finding you believe is incorrect, you have two options:

**Option 1 -- Ignore a specific rule for one scan:**

```bash
aegis-scan check my-package --ignore-rule STATIC-001
```

You can pass `--ignore-rule` multiple times to suppress several rules.

**Option 2 -- Create an `.aegisignore` file** in your project root to persistently ignore specific packages or rules:

```
# Ignore a specific package entirely
lodash
@types/node

# Ignore a specific rule ID
rule:STATIC-001
rule:OBFUSC-001
```

---

## Scan is slow on large projects

A full project scan checks every dependency in `package.json`. Several options can speed things up:

**Skip devDependencies:**

```bash
aegis-scan scan . --skip-dev
```

**Understand caching:** Results are cached locally in `~/.aegis/cache/` with a 24-hour TTL. Repeated scans of the same package version will be nearly instant.

**Force a fresh scan** if you suspect stale cache data:

```bash
aegis-scan check axios --no-cache
```

**Clear the entire cache:**

```bash
aegis-scan cache clear
```

---

## Binary not found after `cargo install`

After running `cargo install aegis-scan`, the `aegis-scan` binary is placed in `~/.cargo/bin/`.

**Fix:** Make sure `~/.cargo/bin` is in your `PATH`:

```bash
# bash / zsh
export PATH="$HOME/.cargo/bin:$PATH"

# Verify
which aegis-scan
```

Add the export line to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.) to make it permanent.

---

## SARIF output not showing in GitHub Security tab

The SARIF format integrates with GitHub's code scanning alerts. If results are not appearing:

1. **Generate SARIF output** in your workflow:

   ```yaml
   - name: Run Aegis
     run: aegis-scan scan . --sarif > results.sarif

   - name: Upload SARIF
     uses: github/codeql-action/upload-sarif@v3
     with:
       sarif_file: results.sarif
   ```

   Or use the official action with `sarif: 'true'`:

   ```yaml
   - uses: z8run/aegis-action@v1
     with:
       path: '.'
       sarif: 'true'
   ```

2. **Check repository settings:** Go to Settings > Code security and analysis and confirm that "Code scanning" is enabled.

3. **Check permissions:** The workflow needs `security-events: write` permission to upload SARIF results.

---

## "Package not found" error

This means the package could not be fetched from the npm registry.

**Common causes:**

- Typo in the package name. Double-check spelling, especially for scoped packages (`@scope/name`).
- The package is private or unpublished. Aegis queries the public npm registry at `https://registry.npmjs.org`.
- Temporary npm registry outage. Check [status.npmjs.org](https://status.npmjs.org).

```bash
# Verify the package exists
npm view some-package version
```

---

## High risk score on a known-good package

The risk score (0--10) is a weighted sum of all findings. A high score does not necessarily mean a package is malicious -- it means Aegis detected patterns that warrant review.

**How scoring works:**

| Severity | Weight per finding |
|---|---|
| Critical | 3.0 |
| High | 1.5 |
| Medium | 0.5 |
| Low | 0.1 |

A package with several medium-severity findings (e.g., legitimate network calls and file writes) can accumulate a moderate score. Review the individual findings listed in the output to decide whether they represent actual risk in your context.

| Score | Label |
|---|---|
| 0--1 | CLEAN |
| 1--3 | LOW RISK |
| 3--5 | MEDIUM RISK |
| 5--7 | HIGH RISK |
| 7--10 | DO NOT INSTALL |

---

## Colors not showing or garbled output

Aegis uses the `colored` crate for terminal output, which respects the `NO_COLOR` standard.

**Disable colors** if your terminal does not support ANSI escape codes:

```bash
NO_COLOR=1 aegis-scan check axios
```

**Piping or redirecting output** automatically disables colors in most terminals. If colors still appear in piped output, set `NO_COLOR=1` explicitly.

**Windows:** Colors work in Windows Terminal and PowerShell. The legacy `cmd.exe` console may not render ANSI codes correctly -- use Windows Terminal instead, or set `NO_COLOR=1`.
