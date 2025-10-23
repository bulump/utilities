# Development Utilities

Professional development utilities and scripts for code quality and security analysis.

## Tools

### script_security_scanner.py

A comprehensive security scanner that combines industry-standard security analysis tools to detect vulnerabilities in your codebase.

**Features:**
- Runs **Bandit** (Python security scanner) to detect Python-specific vulnerabilities
- Runs **Semgrep** (multi-language SAST) for cross-language security analysis
- Provides detailed and summary reporting modes
- Exports results to JSON for CI/CD integration
- Categorizes issues by severity (High/Medium/Low)
- Returns proper exit codes for automation

**Detects:**
- SQL injection vulnerabilities
- Cross-site scripting (XSS) risks
- Hardcoded secrets and API keys
- Insecure cryptographic practices
- Command injection vulnerabilities
- Path traversal issues
- Unsafe deserialization
- And many more security issues

## Installation

### Prerequisites

Install the security scanning tools:

```bash
pip install bandit semgrep
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

================================================================================
SECURITY SCAN RESULTS
================================================================================

Repository: /path/to/your/repo
Scan Date: 2025-10-23T16:30:00

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

================================================================================
SUMMARY
================================================================================

Overall Status: PASS
Total Issues: 8
Critical Issues: 0

Recommendations:
  • Review and address medium/low severity issues
```

## Exit Codes

- `0`: Success - no critical issues found
- `1`: Failure - critical/high severity issues detected

## CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
- name: Run Security Scan
  run: |
    pip install bandit semgrep
    python script_security_scanner.py . --json security-results.json

- name: Upload Security Results
  uses: actions/upload-artifact@v3
  with:
    name: security-scan-results
    path: security-results.json
```

## Requirements

See `requirements.txt` for Python dependencies.

## License

MIT License

## Author

Built with Claude AI
