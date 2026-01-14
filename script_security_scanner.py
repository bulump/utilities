#!/usr/bin/env python3
"""
Security Scanner - Professional Code Security Analysis Tool
Runs Bandit (Python) and Semgrep (multi-language) security scans on a repository.

Usage:
    python security_scanner.py /path/to/repo
    python security_scanner.py /path/to/repo --detailed
    python security_scanner.py /path/to/repo --json output.json
"""
import os
import sys
import argparse
import subprocess
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict
import textwrap


class SecurityScanner:
    """Professional security scanner using industry-standard tools."""

    def __init__(self, repo_path: str):
        """
        Initialize security scanner.

        Args:
            repo_path: Path to repository to scan
        """
        self.repo_path = Path(repo_path).resolve()
        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        self.results = {
            'scan_date': datetime.now().isoformat(),
            'repository': str(self.repo_path),
            'bandit': None,
            'semgrep': None,
            'pip_audit': None,
            'detect_secrets': None,
            'dotnet_audit': None,
            'summary': None
        }

    def _ensure_tools_installed(self) -> Dict[str, bool]:
        """Check if security tools are installed."""
        tools = {}

        # Check Bandit
        try:
            subprocess.run(['bandit', '--version'], capture_output=True, check=True)
            tools['bandit'] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            tools['bandit'] = False

        # Check Semgrep
        try:
            subprocess.run(['semgrep', '--version'], capture_output=True, check=True)
            tools['semgrep'] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            tools['semgrep'] = False

        # Check pip-audit
        try:
            subprocess.run(['pip-audit', '--version'], capture_output=True, check=True)
            tools['pip_audit'] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            tools['pip_audit'] = False

        # Check detect-secrets
        try:
            subprocess.run(['detect-secrets', '--version'], capture_output=True, check=True)
            tools['detect_secrets'] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            tools['detect_secrets'] = False

        # Check dotnet CLI
        try:
            subprocess.run(['dotnet', '--version'], capture_output=True, check=True)
            tools['dotnet'] = True
        except (subprocess.CalledProcessError, FileNotFoundError):
            tools['dotnet'] = False

        return tools

    def run_bandit(self) -> Dict[str, Any]:
        """
        Run Bandit Python security scanner.

        Returns:
            Dictionary with Bandit results
        """
        print("Running Bandit (Python Security Scanner)...")

        try:
            # Exclude venv and other common directories
            result = subprocess.run(
                ['bandit', '-r', str(self.repo_path), '-ll', '-f', 'json',
                 '--exclude', '*/venv/*,*/.venv/*,*/env/*,*/node_modules/*'],
                capture_output=True,
                text=True,
                timeout=300
            )

            # Bandit returns 0 for no issues, 1 for issues found
            if result.returncode in [0, 1]:
                try:
                    if not result.stdout:
                        return {'status': 'error', 'message': 'Bandit produced no output'}

                    data = json.loads(result.stdout)
                    issues = data.get('results', [])

                    # Categorize by severity
                    high = [i for i in issues if i.get('issue_severity') == 'HIGH']
                    medium = [i for i in issues if i.get('issue_severity') == 'MEDIUM']
                    low = [i for i in issues if i.get('issue_severity') == 'LOW']

                    return {
                        'status': 'success',
                        'total_issues': len(issues),
                        'high': len(high),
                        'medium': len(medium),
                        'low': len(low),
                        'details': issues,
                        'metrics': data.get('metrics', {})
                    }
                except json.JSONDecodeError as e:
                    return {'status': 'error', 'message': f'Failed to parse Bandit output: {str(e)}'}
            else:
                return {'status': 'error', 'message': result.stderr}

        except subprocess.TimeoutExpired:
            return {'status': 'error', 'message': 'Bandit scan timed out'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def run_semgrep(self) -> Dict[str, Any]:
        """
        Run Semgrep multi-language security scanner.

        Returns:
            Dictionary with Semgrep results
        """
        print("Running Semgrep (Multi-language SAST)...")

        try:
            # Add semgrep to PATH if needed
            env = os.environ.copy()
            semgrep_path = Path.home() / "Library/Python/3.9/bin"
            if semgrep_path.exists():
                env['PATH'] = f"{semgrep_path}:{env.get('PATH', '')}"

            result = subprocess.run(
                ['semgrep', '--config=auto', '--json', str(self.repo_path)],
                capture_output=True,
                text=True,
                timeout=300,
                env=env
            )

            try:
                data = json.loads(result.stdout)
                findings = data.get('results', [])

                # Categorize by severity
                errors = [f for f in findings if f.get('extra', {}).get('severity') in ['ERROR', 'HIGH']]
                warnings = [f for f in findings if f.get('extra', {}).get('severity') in ['WARNING', 'MEDIUM']]
                info = [f for f in findings if f.get('extra', {}).get('severity') in ['INFO', 'LOW']]

                return {
                    'status': 'success',
                    'total_findings': len(findings),
                    'errors': len(errors),
                    'warnings': len(warnings),
                    'info': len(info),
                    'details': findings,
                    'paths': data.get('paths', {})
                }
            except json.JSONDecodeError:
                return {'status': 'error', 'message': 'Failed to parse Semgrep output'}

        except subprocess.TimeoutExpired:
            return {'status': 'error', 'message': 'Semgrep scan timed out'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def run_pip_audit(self) -> Dict[str, Any]:
        """
        Run pip-audit to check for vulnerable dependencies.

        Returns:
            Dictionary with pip-audit results
        """
        print("Running pip-audit (Dependency Vulnerability Scanner)...")

        try:
            # Look for requirements.txt files
            requirements_files = list(self.repo_path.glob('**/requirements.txt'))

            if not requirements_files:
                return {
                    'status': 'skipped',
                    'message': 'No requirements.txt found',
                    'total_vulnerabilities': 0
                }

            all_vulnerabilities = []

            for req_file in requirements_files:
                result = subprocess.run(
                    ['pip-audit', '--requirement', str(req_file), '--format', 'json'],
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                try:
                    if result.stdout:
                        data = json.loads(result.stdout)
                        vulnerabilities = data.get('vulnerabilities', [])

                        for vuln in vulnerabilities:
                            vuln['requirements_file'] = str(req_file.relative_to(self.repo_path))
                            all_vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    pass

            return {
                'status': 'success',
                'total_vulnerabilities': len(all_vulnerabilities),
                'details': all_vulnerabilities,
                'files_scanned': len(requirements_files)
            }

        except subprocess.TimeoutExpired:
            return {'status': 'error', 'message': 'pip-audit scan timed out'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def run_detect_secrets(self) -> Dict[str, Any]:
        """
        Run detect-secrets to find secrets in code.

        Returns:
            Dictionary with detect-secrets results
        """
        print("Running detect-secrets (Secret Detection)...")

        try:
            # Exclude common directories that have false positives
            result = subprocess.run(
                ['detect-secrets', 'scan', '--all-files',
                 '--exclude-files', 'venv/.*',
                 '--exclude-files', '.venv/.*',
                 '--exclude-files', 'env/.*',
                 '--exclude-files', 'node_modules/.*',
                 '--exclude-files', '.git/.*',
                 str(self.repo_path)],
                capture_output=True,
                text=True,
                timeout=300
            )

            try:
                data = json.loads(result.stdout)
                results_data = data.get('results', {})

                # Count total secrets found
                total_secrets = sum(len(secrets) for secrets in results_data.values())

                # Collect all secrets with file information
                secrets_list = []
                for filepath, secrets in results_data.items():
                    for secret in secrets:
                        secrets_list.append({
                            'file': filepath,
                            'type': secret.get('type'),
                            'line_number': secret.get('line_number'),
                            'hashed_secret': secret.get('hashed_secret')
                        })

                return {
                    'status': 'success',
                    'total_secrets': total_secrets,
                    'files_with_secrets': len(results_data),
                    'details': secrets_list
                }
            except json.JSONDecodeError:
                return {'status': 'error', 'message': 'Failed to parse detect-secrets output'}

        except subprocess.TimeoutExpired:
            return {'status': 'error', 'message': 'detect-secrets scan timed out'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def run_dotnet_audit(self) -> Dict[str, Any]:
        """
        Run dotnet list package --vulnerable to check for .NET dependency vulnerabilities.

        Returns:
            Dictionary with dotnet audit results
        """
        print("Running dotnet list package --vulnerable (.NET Dependency Scanner)...")

        try:
            # Look for .csproj or .sln files
            csproj_files = list(self.repo_path.glob('**/*.csproj'))
            sln_files = list(self.repo_path.glob('**/*.sln'))

            if not csproj_files and not sln_files:
                return {
                    'status': 'skipped',
                    'message': 'No .NET project files found (.csproj or .sln)',
                    'total_vulnerabilities': 0
                }

            all_vulnerabilities = []
            projects_scanned = []

            # Scan each .csproj file
            for csproj_file in csproj_files:
                project_dir = csproj_file.parent
                rel_path = str(csproj_file.relative_to(self.repo_path))

                result = subprocess.run(
                    ['dotnet', 'list', str(csproj_file), 'package', '--vulnerable', '--format', 'json'],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    cwd=project_dir
                )

                projects_scanned.append(rel_path)

                try:
                    if result.stdout:
                        data = json.loads(result.stdout)
                        # Parse the dotnet vulnerable packages output
                        for project in data.get('projects', []):
                            for framework in project.get('frameworks', []):
                                for pkg in framework.get('topLevelPackages', []):
                                    if pkg.get('vulnerabilities'):
                                        for vuln in pkg['vulnerabilities']:
                                            all_vulnerabilities.append({
                                                'project': rel_path,
                                                'framework': framework.get('framework', 'unknown'),
                                                'package': pkg.get('id', 'Unknown'),
                                                'version': pkg.get('resolvedVersion', 'Unknown'),
                                                'severity': vuln.get('severity', 'Unknown'),
                                                'advisory_url': vuln.get('advisoryurl', '')
                                            })
                                for pkg in framework.get('transitivePackages', []):
                                    if pkg.get('vulnerabilities'):
                                        for vuln in pkg['vulnerabilities']:
                                            all_vulnerabilities.append({
                                                'project': rel_path,
                                                'framework': framework.get('framework', 'unknown'),
                                                'package': pkg.get('id', 'Unknown'),
                                                'version': pkg.get('resolvedVersion', 'Unknown'),
                                                'severity': vuln.get('severity', 'Unknown'),
                                                'advisory_url': vuln.get('advisoryurl', ''),
                                                'transitive': True
                                            })
                except json.JSONDecodeError:
                    # Older dotnet versions may not support --format json
                    # Fall back to text parsing
                    if 'has the following vulnerable packages' in result.stdout:
                        all_vulnerabilities.append({
                            'project': rel_path,
                            'raw_output': result.stdout,
                            'note': 'JSON parsing failed, vulnerabilities detected in text output'
                        })

            # Categorize by severity
            critical = [v for v in all_vulnerabilities if v.get('severity', '').lower() == 'critical']
            high = [v for v in all_vulnerabilities if v.get('severity', '').lower() == 'high']
            moderate = [v for v in all_vulnerabilities if v.get('severity', '').lower() in ['moderate', 'medium']]
            low = [v for v in all_vulnerabilities if v.get('severity', '').lower() == 'low']

            return {
                'status': 'success',
                'total_vulnerabilities': len(all_vulnerabilities),
                'critical': len(critical),
                'high': len(high),
                'moderate': len(moderate),
                'low': len(low),
                'details': all_vulnerabilities,
                'projects_scanned': len(projects_scanned)
            }

        except subprocess.TimeoutExpired:
            return {'status': 'error', 'message': 'dotnet audit scan timed out'}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def run_scan(self) -> Dict[str, Any]:
        """
        Run full security scan with all tools.

        Returns:
            Complete scan results
        """
        # Check tool availability
        tools = self._ensure_tools_installed()

        if not any(tools.values()):
            raise RuntimeError(
                "No security tools installed. "
                "Install with: pip install bandit semgrep pip-audit detect-secrets"
            )

        # Run Bandit
        if tools['bandit']:
            self.results['bandit'] = self.run_bandit()
        else:
            print("⚠️  Bandit not installed, skipping Python scan")
            self.results['bandit'] = {'status': 'skipped', 'message': 'Tool not installed'}

        # Run Semgrep
        if tools['semgrep']:
            self.results['semgrep'] = self.run_semgrep()
        else:
            print("⚠️  Semgrep not installed, skipping multi-language scan")
            self.results['semgrep'] = {'status': 'skipped', 'message': 'Tool not installed'}

        # Run pip-audit
        if tools.get('pip_audit'):
            self.results['pip_audit'] = self.run_pip_audit()
        else:
            print("⚠️  pip-audit not installed, skipping dependency vulnerability scan")
            self.results['pip_audit'] = {'status': 'skipped', 'message': 'Tool not installed'}

        # Run detect-secrets
        if tools.get('detect_secrets'):
            self.results['detect_secrets'] = self.run_detect_secrets()
        else:
            print("⚠️  detect-secrets not installed, skipping secret detection")
            self.results['detect_secrets'] = {'status': 'skipped', 'message': 'Tool not installed'}

        # Run dotnet audit
        if tools.get('dotnet'):
            self.results['dotnet_audit'] = self.run_dotnet_audit()
        else:
            print("⚠️  dotnet CLI not installed, skipping .NET dependency scan")
            self.results['dotnet_audit'] = {'status': 'skipped', 'message': 'Tool not installed'}

        # Generate summary
        self.results['summary'] = self._generate_summary()

        return self.results

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate scan summary."""
        summary = {
            'overall_status': 'PASS',
            'total_issues': 0,
            'critical_issues': 0,
            'vulnerable_dependencies': 0,
            'dotnet_vulnerabilities': 0,
            'secrets_found': 0,
            'recommendations': []
        }

        # Bandit summary
        if self.results['bandit'] and self.results['bandit'].get('status') == 'success':
            bandit_total = self.results['bandit']['total_issues']
            bandit_high = self.results['bandit']['high']
            summary['total_issues'] += bandit_total
            summary['critical_issues'] += bandit_high

        # Semgrep summary
        if self.results['semgrep'] and self.results['semgrep'].get('status') == 'success':
            semgrep_total = self.results['semgrep']['total_findings']
            semgrep_errors = self.results['semgrep']['errors']
            summary['total_issues'] += semgrep_total
            summary['critical_issues'] += semgrep_errors

        # pip-audit summary
        if self.results['pip_audit'] and self.results['pip_audit'].get('status') == 'success':
            pip_audit_vulns = self.results['pip_audit']['total_vulnerabilities']
            summary['total_issues'] += pip_audit_vulns
            summary['vulnerable_dependencies'] = pip_audit_vulns
            if pip_audit_vulns > 0:
                summary['critical_issues'] += pip_audit_vulns

        # detect-secrets summary
        if self.results['detect_secrets'] and self.results['detect_secrets'].get('status') == 'success':
            secrets = self.results['detect_secrets']['total_secrets']
            summary['total_issues'] += secrets
            summary['secrets_found'] = secrets
            if secrets > 0:
                summary['critical_issues'] += secrets

        # dotnet audit summary
        if self.results['dotnet_audit'] and self.results['dotnet_audit'].get('status') == 'success':
            dotnet_vulns = self.results['dotnet_audit']['total_vulnerabilities']
            dotnet_critical = self.results['dotnet_audit'].get('critical', 0)
            dotnet_high = self.results['dotnet_audit'].get('high', 0)
            summary['total_issues'] += dotnet_vulns
            summary['dotnet_vulnerabilities'] = dotnet_vulns
            if dotnet_critical > 0 or dotnet_high > 0:
                summary['critical_issues'] += dotnet_critical + dotnet_high

        # Determine overall status
        if summary['critical_issues'] > 0:
            summary['overall_status'] = 'FAIL'
            summary['recommendations'].append('Address critical/high severity issues immediately')
        elif summary['total_issues'] > 0:
            summary['overall_status'] = 'WARN'
            summary['recommendations'].append('Review and address medium/low severity issues')
        else:
            summary['recommendations'].append('No security issues detected - great job!')

        # Specific recommendations
        if summary['vulnerable_dependencies'] > 0:
            summary['recommendations'].append('Update vulnerable Python dependencies to secure versions')
        if summary['dotnet_vulnerabilities'] > 0:
            summary['recommendations'].append('Update vulnerable .NET/NuGet packages to secure versions')
        if summary['secrets_found'] > 0:
            summary['recommendations'].append('Remove hardcoded secrets and use environment variables')

        return summary

    def print_results(self, detailed: bool = False) -> None:
        """
        Print scan results to console.

        Args:
            detailed: If True, show detailed issue information
        """
        print("\n" + "=" * 80)
        print("SECURITY SCAN RESULTS")
        print("=" * 80)
        print(f"\nRepository: {self.results['repository']}")
        print(f"Scan Date: {self.results['scan_date']}")
        print()

        # Bandit Results
        print("BANDIT (Python Security)")
        print("-" * 80)
        if self.results['bandit']:
            bandit = self.results['bandit']
            if bandit.get('status') == 'success':
                print(f"  Status: {'✅ PASS' if bandit['total_issues'] == 0 else '⚠️  ISSUES FOUND'}")
                print(f"  Total Issues: {bandit['total_issues']}")
                print(f"    High: {bandit['high']}")
                print(f"    Medium: {bandit['medium']}")
                print(f"    Low: {bandit['low']}")

                if detailed and bandit['details']:
                    print("\n  Detailed Issues:")
                    for issue in bandit['details'][:10]:  # Show first 10
                        print(f"    [{issue.get('issue_severity')}] {issue.get('filename')}:{issue.get('line_number')}")
                        print(f"      {issue.get('issue_text')}")
            else:
                print(f"  Status: {bandit.get('status')} - {bandit.get('message', '')}")
        print()

        # Semgrep Results
        print("SEMGREP (Multi-language SAST)")
        print("-" * 80)
        if self.results['semgrep']:
            semgrep = self.results['semgrep']
            if semgrep.get('status') == 'success':
                print(f"  Status: {'✅ PASS' if semgrep['total_findings'] == 0 else '⚠️  FINDINGS'}")
                print(f"  Total Findings: {semgrep['total_findings']}")
                print(f"    Errors/High: {semgrep['errors']}")
                print(f"    Warnings/Medium: {semgrep['warnings']}")
                print(f"    Info/Low: {semgrep['info']}")

                if semgrep['details']:
                    # Group findings by check_id/rule to show summary
                    by_rule = defaultdict(list)
                    for finding in semgrep['details']:
                        rule_id = finding.get('check_id', 'unknown')
                        severity = finding.get('extra', {}).get('severity', 'UNKNOWN')
                        by_rule[(severity, rule_id)].append(finding)

                    # Sort by severity (ERROR/HIGH first)
                    severity_order = {'ERROR': 0, 'HIGH': 0, 'WARNING': 1, 'MEDIUM': 1, 'INFO': 2, 'LOW': 2}
                    sorted_rules = sorted(by_rule.items(), key=lambda x: (severity_order.get(x[0][0], 3), -len(x[1])))

                    print("\n  Issues by Type:")
                    for (severity, rule_id), findings in sorted_rules:
                        # Shorten rule_id for display
                        short_rule = rule_id.split('.')[-1] if '.' in rule_id else rule_id
                        print(f"    [{severity}] {short_rule}: {len(findings)} occurrence(s)")

                    if detailed:
                        # Show HIGH/ERROR issues first and completely
                        high_findings = [f for f in semgrep['details']
                                        if f.get('extra', {}).get('severity') in ['ERROR', 'HIGH']]
                        medium_findings = [f for f in semgrep['details']
                                          if f.get('extra', {}).get('severity') in ['WARNING', 'MEDIUM']]

                        if high_findings:
                            print(f"\n  🔴 HIGH/ERROR Severity Details ({len(high_findings)} issues):")
                            for finding in high_findings:
                                severity = finding.get('extra', {}).get('severity', 'UNKNOWN')
                                message = finding.get('extra', {}).get('message', 'No description')
                                path = finding.get('path', '?')
                                line = finding.get('start', {}).get('line', '?')
                                rule_id = finding.get('check_id', 'unknown').split('.')[-1]
                                print(f"    [{severity}] {path}:{line}")
                                print(f"      Rule: {rule_id}")
                                wrapped = textwrap.fill(message, width=100, initial_indent='      ', subsequent_indent='      ')
                                print(wrapped)

                        if medium_findings:
                            print(f"\n  🟡 MEDIUM/WARNING Severity Details ({len(medium_findings)} issues):")
                            for finding in medium_findings[:15]:  # Limit medium to 15
                                severity = finding.get('extra', {}).get('severity', 'UNKNOWN')
                                message = finding.get('extra', {}).get('message', 'No description')
                                path = finding.get('path', '?')
                                line = finding.get('start', {}).get('line', '?')
                                print(f"    [{severity}] {path}:{line}")
                                wrapped = textwrap.fill(message, width=100, initial_indent='      ', subsequent_indent='      ')
                                print(wrapped)
                            if len(medium_findings) > 15:
                                print(f"    ... and {len(medium_findings) - 15} more medium severity issues")
            else:
                print(f"  Status: {semgrep.get('status')} - {semgrep.get('message', '')}")
        print()

        # pip-audit Results
        print("PIP-AUDIT (Dependency Vulnerabilities)")
        print("-" * 80)
        if self.results['pip_audit']:
            pip_audit = self.results['pip_audit']
            if pip_audit.get('status') == 'success':
                print(f"  Status: {'✅ PASS' if pip_audit['total_vulnerabilities'] == 0 else '⚠️  VULNERABILITIES FOUND'}")
                print(f"  Total Vulnerabilities: {pip_audit['total_vulnerabilities']}")
                print(f"  Files Scanned: {pip_audit.get('files_scanned', 0)}")

                if detailed and pip_audit.get('details'):
                    print("\n  Vulnerable Packages:")
                    for vuln in pip_audit['details'][:10]:  # Show first 10
                        package = vuln.get('name', 'Unknown')
                        version = vuln.get('version', 'Unknown')
                        vuln_id = vuln.get('id', 'Unknown')
                        print(f"    [{vuln_id}] {package} {version}")
                        if 'requirements_file' in vuln:
                            print(f"      File: {vuln['requirements_file']}")
            elif pip_audit.get('status') == 'skipped':
                print(f"  Status: {pip_audit.get('message', 'Skipped')}")
            else:
                print(f"  Status: {pip_audit.get('status')} - {pip_audit.get('message', '')}")
        print()

        # detect-secrets Results
        print("DETECT-SECRETS (Secret Detection)")
        print("-" * 80)
        if self.results['detect_secrets']:
            detect_secrets = self.results['detect_secrets']
            if detect_secrets.get('status') == 'success':
                print(f"  Status: {'✅ PASS' if detect_secrets['total_secrets'] == 0 else '🔴 SECRETS FOUND'}")
                print(f"  Total Secrets: {detect_secrets['total_secrets']}")
                print(f"  Files with Secrets: {detect_secrets.get('files_with_secrets', 0)}")

                if detailed and detect_secrets.get('details'):
                    print("\n  Detected Secrets:")
                    for secret in detect_secrets['details'][:10]:  # Show first 10
                        print(f"    [{secret.get('type')}] {secret.get('file')}:{secret.get('line_number')}")
            elif detect_secrets.get('status') == 'skipped':
                print(f"  Status: {detect_secrets.get('message', 'Skipped')}")
            else:
                print(f"  Status: {detect_secrets.get('status')} - {detect_secrets.get('message', '')}")
        print()

        # dotnet audit Results
        print("DOTNET AUDIT (.NET/NuGet Vulnerabilities)")
        print("-" * 80)
        if self.results['dotnet_audit']:
            dotnet_audit = self.results['dotnet_audit']
            if dotnet_audit.get('status') == 'success':
                print(f"  Status: {'✅ PASS' if dotnet_audit['total_vulnerabilities'] == 0 else '⚠️  VULNERABILITIES FOUND'}")
                print(f"  Total Vulnerabilities: {dotnet_audit['total_vulnerabilities']}")
                print(f"    Critical: {dotnet_audit.get('critical', 0)}")
                print(f"    High: {dotnet_audit.get('high', 0)}")
                print(f"    Moderate: {dotnet_audit.get('moderate', 0)}")
                print(f"    Low: {dotnet_audit.get('low', 0)}")
                print(f"  Projects Scanned: {dotnet_audit.get('projects_scanned', 0)}")

                if detailed and dotnet_audit.get('details'):
                    print("\n  Vulnerable Packages:")
                    for vuln in dotnet_audit['details'][:10]:  # Show first 10
                        package = vuln.get('package', 'Unknown')
                        version = vuln.get('version', 'Unknown')
                        severity = vuln.get('severity', 'Unknown')
                        project = vuln.get('project', 'Unknown')
                        transitive = ' (transitive)' if vuln.get('transitive') else ''
                        print(f"    [{severity}] {package} {version}{transitive}")
                        print(f"      Project: {project}")
                        if vuln.get('advisory_url'):
                            print(f"      Advisory: {vuln['advisory_url']}")
            elif dotnet_audit.get('status') == 'skipped':
                print(f"  Status: {dotnet_audit.get('message', 'Skipped')}")
            else:
                print(f"  Status: {dotnet_audit.get('status')} - {dotnet_audit.get('message', '')}")
        print()

        # Summary
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)
        summary = self.results['summary']
        print(f"\nOverall Status: {summary['overall_status']}")
        print(f"Total Issues: {summary['total_issues']}")
        print(f"Critical Issues: {summary['critical_issues']}")
        if summary.get('vulnerable_dependencies', 0) > 0:
            print(f"Vulnerable Python Dependencies: {summary['vulnerable_dependencies']}")
        if summary.get('dotnet_vulnerabilities', 0) > 0:
            print(f"Vulnerable .NET Dependencies: {summary['dotnet_vulnerabilities']}")
        if summary.get('secrets_found', 0) > 0:
            print(f"Secrets Found: {summary['secrets_found']}")
        print("\nRecommendations:")
        for rec in summary['recommendations']:
            print(f"  • {rec}")
        print()

    def save_json(self, output_path: str) -> None:
        """
        Save results to JSON file.

        Args:
            output_path: Path to output JSON file
        """
        with open(output_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"✅ Results saved to: {output_path}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Enhanced Security Scanner - Comprehensive security analysis with multiple tools',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/repo
  %(prog)s /path/to/repo --detailed
  %(prog)s /path/to/repo --json results.json
  %(prog)s . --detailed --json scan_results.json

Tools Included:
  - Bandit: Python SAST security scanner
  - Semgrep: Multi-language SAST scanner
  - pip-audit: Python dependency vulnerability scanner
  - detect-secrets: Secret detection in code

Installation:
  pip install bandit semgrep pip-audit detect-secrets
        """
    )

    parser.add_argument(
        'repo_path',
        help='Path to repository to scan'
    )
    parser.add_argument(
        '--detailed',
        action='store_true',
        help='Show detailed issue information'
    )
    parser.add_argument(
        '--json',
        metavar='FILE',
        help='Save results to JSON file'
    )

    args = parser.parse_args()

    try:
        # Run scan
        print(f"\n🔒 Security Scanner")
        print(f"Repository: {args.repo_path}\n")

        scanner = SecurityScanner(args.repo_path)
        scanner.run_scan()

        # Print results
        scanner.print_results(detailed=args.detailed)

        # Save JSON if requested
        if args.json:
            scanner.save_json(args.json)

        # Exit with appropriate code
        summary = scanner.results['summary']
        if summary['overall_status'] == 'FAIL':
            sys.exit(1)
        elif summary['overall_status'] == 'WARN':
            sys.exit(0)  # or use 2 for warnings if preferred
        else:
            sys.exit(0)

    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
