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
- Provides detailed and summary reporting modes
- Exports results to JSON for CI/CD integration
- Categorizes issues by severity (High/Medium/Low)
- Returns proper exit codes for automation

**Detects:**
- **Code vulnerabilities:** SQL injection, XSS, command injection, path traversal
- **Dependency vulnerabilities:** Known CVEs in Python packages (via pip-audit)
- **Secrets:** Hardcoded API keys, passwords, tokens, credentials (via detect-secrets)
- **Cryptographic issues:** Weak algorithms, insecure key generation
- **Unsafe practices:** Insecure deserialization, eval/exec usage
- And many more security issues across multiple languages

## Installation

### Prerequisites

Install the security scanning tools:

```bash
pip install bandit semgrep pip-audit detect-secrets
```

Or install from the repository's requirements.txt:

```bash
pip install -r requirements.txt
```

### Clone this repository

```bash
git clone https://github.com/bulump/utilities.git
cd utilities
```

## Usage

### Basic Scan

Run a security scan on a repository:

```bash
python script_security_scanner.py /path/to/your/repo
```

### Detailed Output

Get detailed information about each security issue:

```bash
python script_security_scanner.py /path/to/your/repo --detailed
```

### Export to JSON

Save results to a JSON file for CI/CD integration:

```bash
python script_security_scanner.py /path/to/your/repo --json results.json
```

### Combined Options

```bash
python script_security_scanner.py /path/to/your/repo --detailed --json scan_results.json
```

## Example Output

```
🔒 Security Scanner
Repository: /path/to/your/repo

Running Bandit (Python Security Scanner)...
Running Semgrep (Multi-language SAST)...
Running pip-audit (Dependency Vulnerability Scanner)...
Running detect-secrets (Secret Detection)...

================================================================================
SECURITY SCAN RESULTS
================================================================================

Repository: /path/to/your/repo
Scan Date: 2025-10-24T14:56:33

BANDIT (Python Security)
--------------------------------------------------------------------------------
  Status: ✅ PASS
  Total Issues: 3
    High: 0
    Medium: 2
    Low: 1

SEMGREP (Multi-language SAST)
--------------------------------------------------------------------------------
  Status: ✅ PASS
  Total Findings: 5
    Errors/High: 0
    Warnings/Medium: 3
    Info/Low: 2

PIP-AUDIT (Dependency Vulnerabilities)
--------------------------------------------------------------------------------
  Status: ⚠️  VULNERABILITIES FOUND
  Total Vulnerabilities: 2
  Files Scanned: 1

DETECT-SECRETS (Secret Detection)
--------------------------------------------------------------------------------
  Status: ✅ PASS
  Total Secrets: 0
  Files with Secrets: 0

================================================================================
SUMMARY
================================================================================

Overall Status: WARN
Total Issues: 10
Critical Issues: 2
Vulnerable Dependencies: 2

Recommendations:
  • Review and address medium/low severity issues
  • Update vulnerable dependencies to secure versions
```

## Exit Codes

- `0`: Success - no critical issues found
- `1`: Failure - critical/high severity issues detected

## CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
- name: Run Security Scan
  run: |
    pip install bandit semgrep pip-audit detect-secrets
    python script_security_scanner.py . --json security-results.json

- name: Upload Security Results
  uses: actions/upload-artifact@v3
  with:
    name: security-scan-results
    path: security-results.json
```

Or use the requirements.txt:

```yaml
- name: Run Security Scan
  run: |
    pip install -r requirements.txt
    python script_security_scanner.py . --detailed --json security-results.json
```

## Requirements

See `requirements.txt` for Python dependencies.

## License

MIT License

## Author

Built with Claude AI
