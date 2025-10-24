"""
Comprehensive Security Review Across All Portfolio Projects
"""
import os
import re
from pathlib import Path

def review_file(filepath):
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
        if re.search(pattern, content, re.IGNORECASE):
            issues.append({'severity': severity, 'line': 0, 'issue': issue_name, 'context': ''})

    # 3. Command Injection
    if 'os.system' in content:
        # Check if it's using user input
        if '+' in content or 'input(' in content or 'request.' in content:
            issues.append({'severity': 'critical', 'line': 0, 'issue': 'CRITICAL: Command injection via os.system with user input', 'context': ''})
        else:
            issues.append({'severity': 'medium', 'line': 0, 'issue': 'MEDIUM: os.system() usage - ensure input is sanitized', 'context': ''})

    if 'subprocess.call' in content and ('+' in content or 'shell=True' in content):
        issues.append({'severity': 'high', 'line': 0, 'issue': 'HIGH: subprocess with shell=True or concatenation', 'context': ''})

    # 4. Eval/Exec usage
    if re.search(r'\beval\s*\(', content):
        issues.append({'severity': 'critical', 'line': 0, 'issue': 'CRITICAL: eval() usage detected', 'context': ''})

    if re.search(r'\bexec\s*\(', content):
        issues.append({'severity': 'critical', 'line': 0, 'issue': 'CRITICAL: exec() usage detected', 'context': ''})

    # 5. Insecure deserialization
    if 'pickle.loads' in content:
        issues.append({'severity': 'high', 'line': 0, 'issue': 'HIGH: Insecure deserialization with pickle.loads', 'context': ''})

    # 6. Path Traversal
    path_traversal = re.findall(r'open\s*\([^)]*\+|open\s*\(.*f["\']', content)
    if path_traversal and ('../' in content or '..\\' in content):
        issues.append({'severity': 'high', 'line': 0, 'issue': 'HIGH: Possible path traversal vulnerability', 'context': ''})

    # 7. Weak crypto
    if 'md5' in content.lower() or 'sha1' in content.lower():
        issues.append({'severity': 'medium', 'line': 0, 'issue': 'MEDIUM: Weak cryptographic algorithm (MD5/SHA1)', 'context': ''})

    # 8. Debug mode in production
    if re.search(r'debug\s*=\s*True', content, re.IGNORECASE):
        issues.append({'severity': 'medium', 'line': 0, 'issue': 'MEDIUM: Debug mode enabled', 'context': ''})

    return issues

def scan_directory(base_path):
    """Scan all Python files in a directory."""
    results = {}

    for root, dirs, files in os.walk(base_path):
        # Skip virtual environments and common ignore directories
        dirs[:] = [d for d in dirs if d not in ['venv', 'env', '.venv', 'node_modules', '.git', '__pycache__', '.streamlit']]

        for file in files:
            if file.endswith('.py'):
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, base_path)

                issues = review_file(filepath)
                if issues:
                    results[rel_path] = issues

    return results

def main():
    """Run comprehensive security review."""
    print("🔒 COMPREHENSIVE SECURITY REVIEW - ALL PORTFOLIO PROJECTS")
    print("=" * 80)

    git_dir = os.path.expanduser("~/git")

    # Get all project directories
    projects = [d for d in os.listdir(git_dir) if os.path.isdir(os.path.join(git_dir, d)) and not d.startswith('.')]

    print(f"\nScanning {len(projects)} projects in ~/git/\n")

    all_results = {}
    project_summaries = {}

    for project in sorted(projects):
        project_path = os.path.join(git_dir, project)
        print(f"Scanning: {project}...", end=" ")

        results = scan_directory(project_path)

        if results:
            all_results[project] = results

            # Count by severity
            critical = sum(1 for file_issues in results.values() for issue in file_issues if issue['severity'] == 'critical')
            high = sum(1 for file_issues in results.values() for issue in file_issues if issue['severity'] == 'high')
            medium = sum(1 for file_issues in results.values() for issue in file_issues if issue['severity'] == 'medium')

            project_summaries[project] = {'critical': critical, 'high': high, 'medium': medium, 'files': len(results)}
            print(f"⚠️  {critical} critical, {high} high, {medium} medium")
        else:
            print("✅ No issues")

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
                        print(f"       - {issue['issue']}")
                        if issue['context']:
                            print(f"         Context: {issue['context']}")

                if high:
                    print(f"    🟠 HIGH ISSUES:")
                    for issue in high:
                        print(f"       - {issue['issue']}")

                if medium:
                    print(f"    🟡 MEDIUM ISSUES:")
                    for issue in medium:
                        print(f"       - {issue['issue']}")

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
✅ BEST PRACTICES TO MAINTAIN:
  1. Continue using environment variables for all secrets
  2. Keep .env files in .gitignore
  3. Avoid eval(), exec(), and pickle.loads()
  4. Use parameterized queries for SQL
  5. Sanitize all user inputs
  6. Use subprocess with shell=False
  7. Implement proper error handling

🔒 FOR INTERVIEW PREPARATION:
  - Be ready to discuss your security practices
  - Emphasize environment variable usage
  - Highlight .gitignore configuration
  - Mention input validation strategies
  - Show awareness of common vulnerabilities (OWASP Top 10)
    """)

if __name__ == "__main__":
    main()
