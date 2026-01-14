# Development Utilities

Professional development utilities and scripts for code quality and security analysis.

## Tools

### script_security_scanner.py

A comprehensive security scanner that combines industry-standard security analysis tools to detect vulnerabilities in your codebase.

**Features:**
- Runs **Bandit** (Python security scanner) to detect Python-specific vulnerabilities
- Runs **Semgrep** (multi-language SAST) for cross-language security analysis
- Runs **pip-audit** to scan Python dependencies for known CVEs
- Runs **detect-secrets** to find hardcoded secrets and credentials
- Runs **dotnet list package --vulnerable** to scan .NET/NuGet dependencies for CVEs
- Provides detailed and summary reporting modes
- Exports results to JSON for CI/CD integration
- Categorizes issues by severity (Critical/High/Medium/Low)
- Returns proper exit codes for automation

**Usage:**
```bash
python script_security_scanner.py /path/to/repo
python script_security_scanner.py /path/to/repo --detailed
python script_security_scanner.py /path/to/repo --json results.json
```

---

### comprehensive_security_review.py

A fast, regex-based security scanner for Python and C# codebases. No external tools required.

**Features:**
- Scans Python (.py) and C# (.cs) files
- Auto-excludes test directories by default
- Supports suppressions file for whitelisting
- Provides line numbers for all findings
- Fast execution (no external dependencies)

**Usage:**
```bash
# Scan a single repository
python comprehensive_security_review.py /path/to/repo

# Scan all projects in ~/git/
python comprehensive_security_review.py

# Include test files (excluded by default)
python comprehensive_security_review.py /path/to/repo --include-tests

# Exclude additional patterns
python comprehensive_security_review.py /path/to/repo --exclude "*.Generated.cs" --exclude "**/Migrations/*"

# Ignore suppressions file
python comprehensive_security_review.py /path/to/repo --no-suppressions
```

**Detects:**

| Category | Python | C#/.NET |
|----------|--------|---------|
| Hardcoded Secrets | Passwords, API keys, tokens | Passwords, connection strings, API keys |
| Injection | SQL injection, command injection (os.system, subprocess) | SQL injection, command injection (Process.Start), LDAP injection |
| Insecure Deserialization | pickle.loads | BinaryFormatter, SoapFormatter, NetDataContractSerializer |
| XSS | - | Html.Raw, Response.Write |
| Weak Cryptography | MD5, SHA1 | MD5, SHA1, DES, RC2, TripleDES |
| Other | eval(), exec(), debug mode, path traversal | System.Random for security, debug/trace enabled |

---

## Suppressions File

Create a `.security-suppressions.json` file in your repository root to exclude files or suppress specific findings.

### File Location

The suppressions file must be placed in the **root of the repository being scanned**.

### Format

```json
{
  "exclude_patterns": [
    "*.Generated.cs",
    "**/Migrations/*",
    "**/obj/*"
  ],
  "suppress_rules": {
    "Path/To/File.cs": ["rule-keyword"],
    "Path/To/File.cs:123": ["all"]
  }
}
```

### Example

```json
{
  "exclude_patterns": [
    "*.Generated.cs",
    "*.Designer.cs",
    "**/Migrations/*"
  ],
  "suppress_rules": {
    "MyProject.Infrastructure/Db/Repository.cs": ["hardcoded-api-key"],
    "MyProject.Config/Settings.cs": ["hardcoded-password", "connection-string"],
    "MyProject.Legacy/OldCode.cs:45": ["all"]
  }
}
```

### Rule Keywords

Rule matching is **partial, case-insensitive**, and supports **hyphens, underscores, or spaces**:
- `"hardcoded-api-key"`, `"hardcoded_api_key"`, and `"hardcoded api key"` all work

**Python Rules:**

| Severity | Keywords |
|----------|----------|
| CRITICAL | `hardcoded-password`, `hardcoded-api-key-openai`, `hardcoded-github-token`, `command-injection-os-system`, `eval`, `exec` |
| HIGH | `hardcoded-api-key`, `hardcoded-secret`, `hardcoded-token`, `sql-injection`, `subprocess-shell`, `pickle`, `path-traversal` |
| MEDIUM | `os-system`, `md5`, `sha1`, `debug-mode` |

**C#/.NET Rules:**

| Severity | Keywords |
|----------|----------|
| CRITICAL | `hardcoded-password`, `connection-string`, `binaryformatter`, `soapformatter`, `netdatacontractserializer`, `xss-response-write` |
| HIGH | `hardcoded-api-key`, `hardcoded-secret`, `sql-injection`, `process-start`, `des`, `rc2`, `path-traversal`, `ldap-injection`, `html-raw`, `system-random` |
| MEDIUM | `javascriptserializer`, `md5`, `sha1`, `tripledes`, `debug-mode`, `trace-enabled` |
| LOW | `hardcoded-ip` |

### Special Values

- `"all"` - Suppress all rules for a file or line
- File paths must match exactly as shown in scanner output
- Line-specific suppressions use format: `"Path/To/File.cs:123"`

---

## Installation

### Prerequisites

For `script_security_scanner.py`, install the security scanning tools:

```bash
pip install bandit semgrep pip-audit detect-secrets
```

Or install from requirements.txt:

```bash
pip install -r requirements.txt
```

For `comprehensive_security_review.py`, no external dependencies are required.

### Clone this repository

```bash
git clone https://github.com/bulump/utilities.git
cd utilities
```

---

## CI/CD Integration

### GitHub Actions - Full Scanner

```yaml
- name: Run Security Scan
  run: |
    pip install bandit semgrep pip-audit detect-secrets
    python script_security_scanner.py . --detailed --json security-results.json

- name: Upload Security Results
  uses: actions/upload-artifact@v3
  with:
    name: security-scan-results
    path: security-results.json
```

### GitHub Actions - Fast Scanner

```yaml
- name: Run Comprehensive Security Review
  run: |
    python comprehensive_security_review.py . --exclude "*.Generated.cs"
```

---

## Exit Codes

| Scanner | Code | Meaning |
|---------|------|---------|
| script_security_scanner.py | 0 | No critical issues |
| script_security_scanner.py | 1 | Critical/high issues detected |
| comprehensive_security_review.py | 0 | Always (informational) |

---

## License

MIT License
