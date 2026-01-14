"""
Comprehensive Security Review Across All Portfolio Projects
"""
import os
import re
import json
import argparse
import fnmatch
from pathlib import Path


# Default test directory patterns to exclude
DEFAULT_TEST_PATTERNS = [
    '*.Tests/*',
    '*.Tests.*',
    '*.Test/*',
    '*.Test.*',
    '**/test_*.py',
    '**/tests/*',
    '**/*_test.py',
    '**/*_test.cs',
    '**/TestHelpers/*',
    '**/Fixtures/*',
    '**/Mock/*',
    '**/Mocks/*',
]


def load_suppressions(repo_path):
    """Load suppressions from .security-suppressions.json if it exists."""
    suppressions = {
        'exclude_patterns': [],
        'suppress_files': [],
        'suppress_rules': {}
    }

    suppression_file = Path(repo_path) / '.security-suppressions.json'
    if suppression_file.exists():
        try:
            with open(suppression_file, 'r') as f:
                data = json.load(f)
                suppressions['exclude_patterns'] = data.get('exclude_patterns', [])
                suppressions['suppress_files'] = data.get('suppress_files', [])
                suppressions['suppress_rules'] = data.get('suppress_rules', {})
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load suppressions file: {e}")

    return suppressions


def should_exclude_file(rel_path, exclude_patterns):
    """Check if a file should be excluded based on patterns."""
    for pattern in exclude_patterns:
        if fnmatch.fnmatch(rel_path, pattern):
            return True
        # Also check with forward slashes normalized
        if fnmatch.fnmatch(rel_path.replace('\\', '/'), pattern):
            return True
    return False


def normalize_rule(rule):
    """Normalize rule name for matching (hyphens/underscores become spaces)."""
    return rule.lower().replace('-', ' ').replace('_', ' ')


def rule_matches(rule, issue_text):
    """Check if a suppression rule matches an issue."""
    normalized_rule = normalize_rule(rule)
    normalized_issue = normalize_rule(issue_text)
    return normalized_rule in normalized_issue


def filter_suppressed_issues(rel_path, issues, suppress_rules):
    """Filter out suppressed issues for a specific file."""
    if not suppress_rules:
        return issues

    # Check for file-level suppressions
    if rel_path in suppress_rules:
        rules_to_suppress = suppress_rules[rel_path]
        if 'all' in rules_to_suppress:
            return []
        # Filter out specific rules
        issues = [i for i in issues if not any(rule_matches(rule, i['issue']) for rule in rules_to_suppress)]

    # Check for line-specific suppressions (e.g., "file.cs:45")
    filtered_issues = []
    for issue in issues:
        line_key = f"{rel_path}:{issue.get('line', 0)}"
        if line_key in suppress_rules:
            rules_to_suppress = suppress_rules[line_key]
            if 'all' in rules_to_suppress:
                continue
            if any(rule_matches(rule, issue['issue']) for rule in rules_to_suppress):
                continue
        filtered_issues.append(issue)

    return filtered_issues


def find_pattern_with_line(content, pattern, flags=0):
    """Find pattern and return (match, line_number) or (None, 0) if not found."""
    match = re.search(pattern, content, flags)
    if match:
        line_num = content[:match.start()].count('\n') + 1
        return match, line_num
    return None, 0


def find_all_patterns_with_lines(content, pattern, flags=0):
    """Find all pattern matches and return list of (match, line_number)."""
    results = []
    for match in re.finditer(pattern, content, flags):
        line_num = content[:match.start()].count('\n') + 1
        results.append((match, line_num))
    return results


def find_string_with_line(content, search_str):
    """Find string and return line number, or 0 if not found."""
    idx = content.find(search_str)
    if idx >= 0:
        return content[:idx].count('\n') + 1
    return 0


def review_python_file(filepath):
    """Review a single Python file for security issues."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        return []

    issues = []

    # CRITICAL Security checks
    # 1. Hardcoded secrets (looking for actual values, not env var references)
    secret_patterns = [
        (r'password\s*=\s*["\'][^"\']{3,}["\']', 'CRITICAL: Hardcoded password', 'critical'),
        (r'["\']sk-[a-zA-Z0-9]{20,}["\']', 'CRITICAL: Hardcoded API key (OpenAI/Anthropic pattern)', 'critical'),
        (r'["\']ghp_[a-zA-Z0-9]{36,}["\']', 'CRITICAL: Hardcoded GitHub token', 'critical'),
        (r'api[_-]?key\s*=\s*["\'][^"\'$]{10,}["\']', 'HIGH: Possible hardcoded API key', 'high'),
        (r'secret\s*=\s*["\'][^"\'$]{10,}["\']', 'HIGH: Possible hardcoded secret', 'high'),
        (r'token\s*=\s*["\'][^"\'$]{10,}["\']', 'HIGH: Possible hardcoded token', 'high'),
    ]

    for pattern, issue_name, severity in secret_patterns:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            # Exclude environment variable references
            matched_text = match.group()
            if 'os.getenv' not in content[max(0, match.start()-50):match.end()+50] and \
               'ANTHROPIC_API_KEY' not in matched_text and \
               'GITHUB_TOKEN' not in matched_text and \
               '${' not in matched_text:
                line_num = content[:match.start()].count('\n') + 1
                issues.append({
                    'severity': severity,
                    'line': line_num,
                    'issue': issue_name,
                    'context': matched_text[:50]
                })

    # 2. SQL Injection
    sql_patterns = [
        (r'execute\s*\([^)]*\+', 'HIGH: Possible SQL injection (string concatenation)', 'high'),
        (r'\.format\s*\([^)]*SELECT', 'HIGH: Possible SQL injection (format with SELECT)', 'high'),
        (r'f["\'].*SELECT.*\{', 'HIGH: Possible SQL injection (f-string with SELECT)', 'high'),
    ]

    for pattern, issue_name, severity in sql_patterns:
        match, line_num = find_pattern_with_line(content, pattern, re.IGNORECASE)
        if match:
            issues.append({'severity': severity, 'line': line_num, 'issue': issue_name, 'context': ''})

    # 3. Command Injection
    line_num = find_string_with_line(content, 'os.system')
    if line_num:
        if '+' in content or 'input(' in content or 'request.' in content:
            issues.append({'severity': 'critical', 'line': line_num, 'issue': 'CRITICAL: Command injection via os.system with user input', 'context': ''})
        else:
            issues.append({'severity': 'medium', 'line': line_num, 'issue': 'MEDIUM: os.system() usage - ensure input is sanitized', 'context': ''})

    if 'subprocess.call' in content and ('+' in content or 'shell=True' in content):
        line_num = find_string_with_line(content, 'subprocess.call')
        issues.append({'severity': 'high', 'line': line_num, 'issue': 'HIGH: subprocess with shell=True or concatenation', 'context': ''})

    # 4. Eval/Exec usage
    match, line_num = find_pattern_with_line(content, r'\beval\s*\(')
    if match:
        issues.append({'severity': 'critical', 'line': line_num, 'issue': 'CRITICAL: eval() usage detected', 'context': ''})

    match, line_num = find_pattern_with_line(content, r'\bexec\s*\(')
    if match:
        issues.append({'severity': 'critical', 'line': line_num, 'issue': 'CRITICAL: exec() usage detected', 'context': ''})

    # 5. Insecure deserialization
    line_num = find_string_with_line(content, 'pickle.loads')
    if line_num:
        issues.append({'severity': 'high', 'line': line_num, 'issue': 'HIGH: Insecure deserialization with pickle.loads', 'context': ''})

    # 6. Path Traversal
    match, line_num = find_pattern_with_line(content, r'open\s*\([^)]*\+|open\s*\(.*f["\']')
    if match and ('../' in content or '..\\' in content):
        issues.append({'severity': 'high', 'line': line_num, 'issue': 'HIGH: Possible path traversal vulnerability', 'context': ''})

    # 7. Weak crypto
    match, line_num = find_pattern_with_line(content, r'\bmd5\b', re.IGNORECASE)
    if match:
        issues.append({'severity': 'medium', 'line': line_num, 'issue': 'MEDIUM: Weak cryptographic algorithm (MD5)', 'context': ''})
    match, line_num = find_pattern_with_line(content, r'\bsha1\b', re.IGNORECASE)
    if match:
        issues.append({'severity': 'medium', 'line': line_num, 'issue': 'MEDIUM: Weak cryptographic algorithm (SHA1)', 'context': ''})

    # 8. Debug mode in production
    match, line_num = find_pattern_with_line(content, r'debug\s*=\s*True', re.IGNORECASE)
    if match:
        issues.append({'severity': 'medium', 'line': line_num, 'issue': 'MEDIUM: Debug mode enabled', 'context': ''})

    # Deduplicate issues by (line, issue) - keep first occurrence
    seen = set()
    unique_issues = []
    for issue in issues:
        key = (issue['line'], issue['issue'])
        if key not in seen:
            seen.add(key)
            unique_issues.append(issue)

    return unique_issues


def review_csharp_file(filepath):
    """Review a single C# file for security issues."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        return []

    issues = []

    # CRITICAL Security checks for C#
    # 1. Hardcoded secrets
    secret_patterns = [
        (r'[Pp]assword\s*=\s*"[^"]{3,}"', 'CRITICAL: Hardcoded password', 'critical'),
        (r'[Cc]onnection[Ss]tring\s*=\s*"[^"]*[Pp]assword=[^"]*"', 'CRITICAL: Hardcoded connection string with password', 'critical'),
        (r'"[a-zA-Z0-9]{32,}"', 'HIGH: Possible hardcoded API key or secret', 'high'),
        (r'[Aa]pi[Kk]ey\s*=\s*"[^"]{10,}"', 'HIGH: Possible hardcoded API key', 'high'),
        (r'[Ss]ecret\s*=\s*"[^"]{10,}"', 'HIGH: Possible hardcoded secret', 'high'),
    ]

    for pattern, issue_name, severity in secret_patterns:
        matches = re.finditer(pattern, content)
        for match in matches:
            matched_text = match.group()
            # Exclude configuration placeholders and env var patterns
            if 'Environment.GetEnvironmentVariable' not in content[max(0, match.start()-100):match.end()+100] and \
               '${' not in matched_text and \
               '{0}' not in matched_text and \
               'Configuration[' not in content[max(0, match.start()-50):match.end()+50]:
                line_num = content[:match.start()].count('\n') + 1
                issues.append({
                    'severity': severity,
                    'line': line_num,
                    'issue': issue_name,
                    'context': matched_text[:50]
                })

    # 2. SQL Injection
    sql_patterns = [
        (r'ExecuteReader\s*\([^)]*\+', 'HIGH: Possible SQL injection (string concatenation)', 'high'),
        (r'ExecuteNonQuery\s*\([^)]*\+', 'HIGH: Possible SQL injection (string concatenation)', 'high'),
        (r'ExecuteScalar\s*\([^)]*\+', 'HIGH: Possible SQL injection (string concatenation)', 'high'),
        (r'\$"[^"]*SELECT[^"]*\{', 'HIGH: Possible SQL injection (interpolated string with SELECT)', 'high'),
        (r'\$"[^"]*INSERT[^"]*\{', 'HIGH: Possible SQL injection (interpolated string with INSERT)', 'high'),
        (r'\$"[^"]*UPDATE[^"]*\{', 'HIGH: Possible SQL injection (interpolated string with UPDATE)', 'high'),
        (r'\$"[^"]*DELETE[^"]*\{', 'HIGH: Possible SQL injection (interpolated string with DELETE)', 'high'),
        (r'string\.Format\s*\([^)]*SELECT', 'HIGH: Possible SQL injection (Format with SELECT)', 'high'),
        (r'FromSqlRaw\s*\(\s*\$"', 'HIGH: Possible SQL injection (FromSqlRaw with interpolation)', 'high'),
    ]

    for pattern, issue_name, severity in sql_patterns:
        match, line_num = find_pattern_with_line(content, pattern, re.IGNORECASE)
        if match:
            issues.append({'severity': severity, 'line': line_num, 'issue': issue_name, 'context': ''})

    # 3. Command Injection
    line_num = find_string_with_line(content, 'Process.Start')
    if line_num:
        if '+' in content or 'Request.' in content or 'user' in content.lower():
            issues.append({'severity': 'critical', 'line': line_num, 'issue': 'CRITICAL: Command injection via Process.Start with user input', 'context': ''})
        else:
            match, line_num2 = find_pattern_with_line(content, r'Process\.Start\s*\([^)]*\+')
            if match:
                issues.append({'severity': 'high', 'line': line_num2, 'issue': 'HIGH: Process.Start with string concatenation', 'context': ''})

    # 4. Dangerous deserialization
    dangerous_deserializers = [
        ('BinaryFormatter', 'CRITICAL: BinaryFormatter usage (insecure deserialization)'),
        ('NetDataContractSerializer', 'CRITICAL: NetDataContractSerializer usage (insecure deserialization)'),
        ('ObjectStateFormatter', 'HIGH: ObjectStateFormatter usage (potentially insecure)'),
        ('SoapFormatter', 'CRITICAL: SoapFormatter usage (insecure deserialization)'),
        ('LosFormatter', 'HIGH: LosFormatter usage (potentially insecure)'),
        ('JavaScriptSerializer', 'MEDIUM: JavaScriptSerializer - ensure type handling is secure'),
    ]

    for deserializer, issue_name in dangerous_deserializers:
        line_num = find_string_with_line(content, deserializer)
        if line_num:
            severity = 'critical' if 'CRITICAL' in issue_name else 'high' if 'HIGH' in issue_name else 'medium'
            issues.append({'severity': severity, 'line': line_num, 'issue': issue_name, 'context': ''})

    # 5. Path Traversal
    match, line_num = find_pattern_with_line(content, r'File\.(Read|Write|Open|Delete|Copy|Move)')
    if match:
        if re.search(r'\+\s*(Request|user|input)', content, re.IGNORECASE) or '../' in content:
            issues.append({'severity': 'high', 'line': line_num, 'issue': 'HIGH: Possible path traversal vulnerability', 'context': ''})

    # 6. Weak cryptography
    weak_crypto = [
        ('MD5', 'MEDIUM: Weak cryptographic algorithm (MD5)'),
        ('SHA1', 'MEDIUM: Weak cryptographic algorithm (SHA1)'),
        ('DES', 'HIGH: Weak encryption algorithm (DES)'),
        ('TripleDES', 'MEDIUM: Weak encryption algorithm (3DES) - consider AES'),
        ('RC2', 'HIGH: Weak encryption algorithm (RC2)'),
    ]

    for algo, issue_name in weak_crypto:
        match, line_num = find_pattern_with_line(content, rf'\b{algo}\b')
        if match:
            severity = 'high' if 'HIGH' in issue_name else 'medium'
            issues.append({'severity': severity, 'line': line_num, 'issue': issue_name, 'context': ''})

    # 7. LDAP Injection
    line_num = find_string_with_line(content, 'DirectorySearcher')
    if not line_num:
        line_num = find_string_with_line(content, 'DirectoryEntry')
    if line_num:
        if '+' in content or 'Request.' in content:
            issues.append({'severity': 'high', 'line': line_num, 'issue': 'HIGH: Possible LDAP injection', 'context': ''})

    # 8. XSS vulnerabilities
    line_num = find_string_with_line(content, 'Html.Raw')
    if line_num:
        issues.append({'severity': 'high', 'line': line_num, 'issue': 'HIGH: Html.Raw usage - potential XSS if user input', 'context': ''})

    match, line_num = find_pattern_with_line(content, r'Response\.Write\s*\([^)]*Request')
    if match:
        issues.append({'severity': 'critical', 'line': line_num, 'issue': 'CRITICAL: Direct output of request data - XSS vulnerability', 'context': ''})

    # 9. Insecure random number generation
    match, line_num = find_pattern_with_line(content, r'new\s+Random\s*\(')
    if match:
        if 'password' in content.lower() or 'token' in content.lower() or 'key' in content.lower():
            issues.append({'severity': 'high', 'line': line_num, 'issue': 'HIGH: System.Random used for security-sensitive value - use RNGCryptoServiceProvider', 'context': ''})

    # 10. Debug/Trace enabled
    match, line_num = find_pattern_with_line(content, r'<compilation\s+debug\s*=\s*"true"', re.IGNORECASE)
    if match:
        issues.append({'severity': 'medium', 'line': line_num, 'issue': 'MEDIUM: Debug mode enabled in config', 'context': ''})

    match, line_num = find_pattern_with_line(content, r'<trace\s+enabled\s*=\s*"true"', re.IGNORECASE)
    if match:
        issues.append({'severity': 'medium', 'line': line_num, 'issue': 'MEDIUM: Trace enabled in config', 'context': ''})

    # 11. Hardcoded IP addresses (potential security config issue)
    match, line_num = find_pattern_with_line(content, r'"(?:\d{1,3}\.){3}\d{1,3}"')
    if match:
        issues.append({'severity': 'low', 'line': line_num, 'issue': 'LOW: Hardcoded IP address found', 'context': ''})

    # Deduplicate issues by (line, issue) - keep first occurrence
    seen = set()
    unique_issues = []
    for issue in issues:
        key = (issue['line'], issue['issue'])
        if key not in seen:
            seen.add(key)
            unique_issues.append(issue)

    return unique_issues


def scan_directory(base_path, exclude_patterns=None, suppress_rules=None):
    """Scan all Python and C# files in a directory."""
    results = {}
    exclude_patterns = exclude_patterns or []
    suppress_rules = suppress_rules or {}

    for root, dirs, files in os.walk(base_path):
        # Skip virtual environments and common ignore directories
        dirs[:] = [d for d in dirs if d not in ['venv', 'env', '.venv', 'node_modules', '.git', '__pycache__', '.streamlit', 'bin', 'obj', 'packages']]

        for file in files:
            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, base_path)

            # Check if file should be excluded
            if should_exclude_file(rel_path, exclude_patterns):
                continue

            issues = []

            if file.endswith('.py'):
                issues = review_python_file(filepath)
            elif file.endswith('.cs'):
                issues = review_csharp_file(filepath)
            elif file.endswith(('.config', '.csproj')) and 'web.config' in file.lower() or 'app.config' in file.lower():
                # Also scan .NET config files for security issues
                issues = review_csharp_file(filepath)

            # Apply suppressions
            if issues and suppress_rules:
                issues = filter_suppressed_issues(rel_path, issues, suppress_rules)

            if issues:
                results[rel_path] = issues

    return results

def main():
    """Run comprehensive security review."""
    parser = argparse.ArgumentParser(
        description='Comprehensive Security Review - Scan Python and C# files for security issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Scan all projects in ~/git/
  %(prog)s /path/to/repo             # Scan a single repository
  %(prog)s ../MyProject              # Scan relative path
  %(prog)s . --include-tests         # Include test files in scan
  %(prog)s . --exclude "*.Generated.*" --exclude "**/Migrations/*"

Suppressions File:
  Create a .security-suppressions.json in your repo root:
  {
    "exclude_patterns": ["*.Tests/*", "**/Migrations/*"],
    "suppress_rules": {
      "SomeFile.cs": ["hardcoded-secret"],
      "TestHelper.cs:45": ["all"]
    }
  }
        """
    )
    parser.add_argument(
        'repo_path',
        nargs='?',
        default=None,
        help='Path to a single repository to scan (optional, defaults to all projects in ~/git/)'
    )
    parser.add_argument(
        '--include-tests',
        action='store_true',
        help='Include test files/directories in scan (excluded by default)'
    )
    parser.add_argument(
        '--exclude',
        action='append',
        default=[],
        metavar='PATTERN',
        help='Exclude files matching pattern (can be specified multiple times)'
    )
    parser.add_argument(
        '--no-suppressions',
        action='store_true',
        help='Ignore .security-suppressions.json file'
    )
    args = parser.parse_args()

    print("🔒 COMPREHENSIVE SECURITY REVIEW")
    print("   Scanning Python (.py) and C# (.cs) files")
    print("=" * 80)

    if args.repo_path:
        # Single repo mode
        repo_path = Path(args.repo_path).resolve()
        if not repo_path.exists():
            print(f"\n❌ Error: Path does not exist: {repo_path}")
            return
        project_name = repo_path.name
        projects = [project_name]
        project_paths = {project_name: str(repo_path)}
        print(f"\nScanning single repository: {repo_path}\n")
    else:
        # All projects mode
        git_dir = os.path.expanduser("~/git")
        projects = [d for d in os.listdir(git_dir) if os.path.isdir(os.path.join(git_dir, d)) and not d.startswith('.')]
        project_paths = {p: os.path.join(git_dir, p) for p in projects}
        print(f"\nScanning {len(projects)} projects in ~/git/\n")

    # Build exclusion patterns
    exclude_patterns = list(args.exclude)  # CLI patterns
    if not args.include_tests:
        exclude_patterns.extend(DEFAULT_TEST_PATTERNS)
        print("   (Test files excluded by default. Use --include-tests to include them)\n")

    all_results = {}
    project_summaries = {}

    for project in sorted(projects):
        project_path = project_paths[project]

        # Load per-project suppressions
        suppressions = {}
        suppress_rules = {}
        if not args.no_suppressions:
            suppressions = load_suppressions(project_path)
            # Combine file suppressions with CLI exclusions
            project_exclude = exclude_patterns + suppressions.get('exclude_patterns', [])
            suppress_rules = suppressions.get('suppress_rules', {})
        else:
            project_exclude = exclude_patterns

        results = scan_directory(project_path, project_exclude, suppress_rules)

        if results:
            all_results[project] = results

            # Count by severity
            critical = sum(1 for file_issues in results.values() for issue in file_issues if issue['severity'] == 'critical')
            high = sum(1 for file_issues in results.values() for issue in file_issues if issue['severity'] == 'high')
            medium = sum(1 for file_issues in results.values() for issue in file_issues if issue['severity'] == 'medium')

            project_summaries[project] = {'critical': critical, 'high': high, 'medium': medium, 'files': len(results)}
            print(f"⚠️  {project}: {critical} critical, {high} high, {medium} medium")

    # Detailed results
    if all_results:
        print("\n" + "=" * 80)
        print("DETAILED FINDINGS")
        print("=" * 80)

        for project, files in all_results.items():
            print(f"\n{'='*80}")
            print(f"PROJECT: {project}")
            print(f"{'='*80}")

            for filepath, issues in files.items():
                print(f"\n  📄 {filepath}")

                # Group by severity
                critical = [i for i in issues if i['severity'] == 'critical']
                high = [i for i in issues if i['severity'] == 'high']
                medium = [i for i in issues if i['severity'] == 'medium']

                if critical:
                    print(f"    🔴 CRITICAL ISSUES:")
                    for issue in critical:
                        line_info = f" (line {issue['line']})" if issue.get('line', 0) > 0 else ""
                        print(f"       - {issue['issue']}{line_info}")
                        if issue.get('context'):
                            print(f"         Context: {issue['context']}")

                if high:
                    print(f"    🟠 HIGH ISSUES:")
                    for issue in high:
                        line_info = f" (line {issue['line']})" if issue.get('line', 0) > 0 else ""
                        print(f"       - {issue['issue']}{line_info}")

                if medium:
                    print(f"    🟡 MEDIUM ISSUES:")
                    for issue in medium:
                        line_info = f" (line {issue['line']})" if issue.get('line', 0) > 0 else ""
                        print(f"       - {issue['issue']}{line_info}")

    # Summary
    print("\n" + "=" * 80)
    print("SECURITY REVIEW SUMMARY")
    print("=" * 80)

    if all_results:
        total_critical = sum(s['critical'] for s in project_summaries.values())
        total_high = sum(s['high'] for s in project_summaries.values())
        total_medium = sum(s['medium'] for s in project_summaries.values())

        print(f"\n⚠️  Total Issues Found:")
        print(f"   🔴 CRITICAL: {total_critical}")
        print(f"   🟠 HIGH: {total_high}")
        print(f"   🟡 MEDIUM: {total_medium}")

        print(f"\nProjects with issues: {len(all_results)}/{len(projects)}")

        print("\n" + "-" * 80)
        print("PROJECT BREAKDOWN:")
        print("-" * 80)

        for project, summary in sorted(project_summaries.items(), key=lambda x: (x[1]['critical'], x[1]['high']), reverse=True):
            status = "🔴" if summary['critical'] > 0 else "🟠" if summary['high'] > 0 else "🟡"
            print(f"{status} {project:40} C:{summary['critical']} H:{summary['high']} M:{summary['medium']} ({summary['files']} files)")
    else:
        print("\n✅ NO SECURITY ISSUES FOUND IN ANY PROJECT!")
        print(f"\n   Scanned {len(projects)} projects - all passed security review!")

    print("\n" + "=" * 80)
    print("RECOMMENDATIONS")
    print("=" * 80)
    print("""
✅ PYTHON BEST PRACTICES:
  1. Use environment variables for all secrets
  2. Keep .env files in .gitignore
  3. Avoid eval(), exec(), and pickle.loads()
  4. Use parameterized queries for SQL
  5. Sanitize all user inputs
  6. Use subprocess with shell=False

✅ C#/.NET BEST PRACTICES:
  1. Use IConfiguration and environment variables for secrets
  2. Use parameterized queries or stored procedures (never string concatenation)
  3. Avoid BinaryFormatter, use System.Text.Json or JsonSerializer
  4. Use RNGCryptoServiceProvider for security-sensitive random values
  5. Disable debug mode in production (compilation debug="false")
  6. Use Html.Encode() instead of Html.Raw() for user content
  7. Validate and sanitize all user inputs
  8. Use Path.Combine() and validate paths to prevent traversal
    """)

if __name__ == "__main__":
    main()
