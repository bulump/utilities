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

        return tools

    def run_bandit(self) -> Dict[str, Any]:
        """
        Run Bandit Python security scanner.

        Returns:
            Dictionary with Bandit results
        """
        print("Running Bandit (Python Security Scanner)...")

        try:
            result = subprocess.run(
                ['bandit', '-r', str(self.repo_path), '-ll', '-f', 'json'],
                capture_output=True,
                text=True,
                timeout=300
            )

            # Bandit returns 0 for no issues, 1 for issues found
            if result.returncode in [0, 1]:
                try:
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
                except json.JSONDecodeError:
                    return {'status': 'error', 'message': 'Failed to parse Bandit output'}
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

    def run_scan(self) -> Dict[str, Any]:
        """
        Run full security scan with both tools.

        Returns:
            Complete scan results
        """
        # Check tool availability
        tools = self._ensure_tools_installed()

        if not tools['bandit'] and not tools['semgrep']:
            raise RuntimeError(
                "Neither Bandit nor Semgrep is installed. "
                "Install with: pip install bandit semgrep"
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

        # Generate summary
        self.results['summary'] = self._generate_summary()

        return self.results

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate scan summary."""
        summary = {
            'overall_status': 'PASS',
            'total_issues': 0,
            'critical_issues': 0,
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

        # Determine overall status
        if summary['critical_issues'] > 0:
            summary['overall_status'] = 'FAIL'
            summary['recommendations'].append('Address critical/high severity issues immediately')
        elif summary['total_issues'] > 0:
            summary['overall_status'] = 'WARN'
            summary['recommendations'].append('Review and address medium/low severity issues')
        else:
            summary['recommendations'].append('No security issues detected - great job!')

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

                if detailed and semgrep['details']:
                    print("\n  Detailed Findings:")
                    for finding in semgrep['details'][:10]:  # Show first 10
                        severity = finding.get('extra', {}).get('severity', 'UNKNOWN')
                        message = finding.get('extra', {}).get('message', 'No description')
                        path = finding.get('path', '?')
                        print(f"    [{severity}] {path}")
                        print(f"      {message[:100]}")
            else:
                print(f"  Status: {semgrep.get('status')} - {semgrep.get('message', '')}")
        print()

        # Summary
        print("=" * 80)
        print("SUMMARY")
        print("=" * 80)
        summary = self.results['summary']
        print(f"\nOverall Status: {summary['overall_status']}")
        print(f"Total Issues: {summary['total_issues']}")
        print(f"Critical Issues: {summary['critical_issues']}")
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
        description='Security Scanner - Run Bandit and Semgrep on a repository',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /path/to/repo
  %(prog)s /path/to/repo --detailed
  %(prog)s /path/to/repo --json results.json
  %(prog)s . --detailed --json scan_results.json

Installation:
  pip install bandit semgrep
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
