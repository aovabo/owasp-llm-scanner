import click
import asyncio
from rich.console import Console
from rich.progress import Progress
from ..probe_engine.probe_engine import ProbeEngine
from ..targets import create_target
from typing import List, Optional
import time
from datetime import datetime, timedelta
from pathlib import Path
import pkg_resources
import sys

console = Console()

def check_package_versions() -> None:
    """Check installed package versions against requirements"""
    required_versions = {
        'click': ('8.1.7', '8.2.0'),
        'rich': ('13.7.0', '13.8.0'),
        'openai': ('1.12.0', '1.12.0'),  # Exact version
        'anthropic': ('0.18.1', '0.18.1'),  # Exact version
        'fastapi': ('0.110.0', '0.111.0'),
        'streamlit': ('1.31.1', '1.32.0'),
    }
    
    issues = []
    for package, (min_ver, max_ver) in required_versions.items():
        try:
            installed = pkg_resources.get_distribution(package).version
            if not (min_ver <= installed <= max_ver):
                issues.append(
                    f"{package} version {installed} not compatible. "
                    f"Required: >={min_ver},<={max_ver}"
                )
        except pkg_resources.DistributionNotFound:
            issues.append(f"{package} not installed")
    
    if issues:
        console.print("[red]Compatibility Issues Found:[/red]")
        for issue in issues:
            console.print(f"[red]• {issue}[/red]")
        console.print("\nRun 'pip install -e .' to install correct versions")
        sys.exit(1)

@click.group()
def cli():
    """LLM Security Scanner - Test your LLM applications for vulnerabilities"""
    pass

@cli.command()
@click.option('--provider', required=True, help='LLM provider (openai, anthropic, etc)')
@click.option('--model', help='Model name (e.g., gpt-4, claude-3-opus)')
@click.option('--api-key', required=True, help='API key for the provider')
@click.option('--vulnerabilities', multiple=True, help='Specific vulnerabilities to test')
@click.option('--output', help='Output file for the report (HTML or JSON)')
@click.option('--config', help='Path to configuration file')
@click.option('--timeout', type=int, default=300, help='Scan timeout in seconds')
@click.option('--max-retries', type=int, default=3, help='Maximum retries for failed probes')
@click.option('--verbose', is_flag=True, help='Enable verbose output')
@click.option('--save-artifacts', is_flag=True, help='Save scan artifacts')
@click.option('--risk-threshold', type=int, default=7, help='Minimum risk score to report')
@click.option('--parallel', is_flag=True, help='Run probes in parallel')
@click.option('--no-progress', is_flag=True, help='Disable progress bar')
@click.option('--format', type=click.Choice(['text', 'json', 'yaml']), default='text', help='Output format')
def scan(provider: str, model: Optional[str], api_key: str, 
         vulnerabilities: List[str], output: Optional[str], 
         config: Optional[str], timeout: int, max_retries: int,
         verbose: bool, save_artifacts: bool, risk_threshold: int,
         parallel: bool, no_progress: bool, format: str):
    """Run a security scan on an LLM provider"""
    try:
        # Create target
        target_url = f"{provider}:{model}" if model else provider
        target = create_target(target_url, api_key=api_key)
        
        # Initialize probe engine
        engine = ProbeEngine(
            enabled_vulnerabilities=vulnerabilities if vulnerabilities else None
        )
        
        # Run scan with progress bar
        with Progress() as progress:
            task = progress.add_task("[cyan]Running security scan...", total=100)
            
            async def run_scan():
                results = await engine.run_scan(target)
                progress.update(task, completed=100)
                return results
            
            results = asyncio.run(run_scan())
        
        # Display results
        console.print("\n[green]Scan completed![/green]\n")
        
        if results:
            console.print(f"Found {len(results)} potential vulnerabilities:\n")
            for result in results:
                console.print(f"[red]• {result['vulnerability_type']}[/red]")
                console.print(f"  {result['details']}\n")
        else:
            console.print("[green]No vulnerabilities found![/green]\n")
            
        # Generate report if requested
        if output:
            from ..reporting.security_report import SecurityReportGenerator
            report_gen = SecurityReportGenerator()
            report = report_gen.generate_report(results, format=output.split('.')[-1])
            with open(output, 'w') as f:
                f.write(report)
            console.print(f"[green]Report saved to {output}[/green]")
            
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise click.Abort()

@cli.command()
@click.option('--config', required=True, help='Path to configuration file to validate')
def validate(config: str):
    """Validate a configuration file"""
    try:
        import yaml
        with open(config) as f:
            yaml.safe_load(f)
        console.print("[green]Configuration file is valid![/green]")
    except Exception as e:
        console.print(f"[red]Invalid configuration: {str(e)}[/red]")
        raise click.Abort()

@cli.command()
@click.option('--list-probes', is_flag=True, help='List all available security probes')
@click.option('--list-providers', is_flag=True, help='List supported LLM providers')
def info(list_probes: bool, list_providers: bool):
    """Show information about available probes and providers"""
    if list_probes:
        console.print("\n[bold]Available Security Probes:[/bold]\n")
        probes = {
            "PROMPT_INJECTION": "Tests for direct and indirect prompt injection",
            "DATA_DISCLOSURE": "Tests for sensitive information disclosure",
            "PROMPT_LEAKAGE": "Tests for system prompt leakage",
            "SUPPLY_CHAIN": "Tests for supply chain vulnerabilities",
            "DATA_POISONING": "Tests for training data poisoning",
            "OUTPUT_HANDLING": "Tests for improper output handling",
            "EXCESSIVE_AGENCY": "Tests for excessive agency",
            "VECTOR_WEAKNESSES": "Tests for embedding vulnerabilities",
            "MISINFORMATION": "Tests for misinformation generation",
            "CONSUMPTION": "Tests for resource consumption issues"
        }
        for probe, desc in probes.items():
            console.print(f"[cyan]{probe}[/cyan]: {desc}")

    if list_providers:
        console.print("\n[bold]Supported LLM Providers:[/bold]\n")
        providers = {
            "openai": ["gpt-4", "gpt-3.5-turbo"],
            "anthropic": ["claude-3-opus", "claude-3-sonnet"],
            "google": ["gemini-pro"],
            "azure": ["gpt-4", "gpt-35-turbo"],
            "cohere": ["command", "command-light"]
        }
        for provider, models in providers.items():
            console.print(f"[cyan]{provider}[/cyan]:")
            for model in models:
                console.print(f"  • {model}")

@cli.command()
@click.option('--init', is_flag=True, help='Initialize a new configuration file')
@click.option('--output', default='config.yaml', help='Output path for the config file')
def config(init: bool, output: str):
    """Manage configuration files"""
    if init:
        import shutil
        import pkg_resources
        
        # Copy template to specified location
        template_path = pkg_resources.resource_filename('scanner', 'config-template.yaml')
        shutil.copy(template_path, output)
        console.print(f"[green]Created configuration file at: {output}[/green]")

@cli.command()
@click.option('--continuous', is_flag=True, help='Run continuous monitoring')
@click.option('--interval', default=3600, help='Interval between scans in seconds')
@click.option('--alert-threshold', default='HIGH', help='Minimum severity level for alerts')
def monitor(continuous: bool, interval: int, alert_threshold: str):
    """Run continuous security monitoring"""
    try:
        from ..monitoring import AlertManager
        alert_manager = AlertManager()
        
        if continuous:
            console.print("[cyan]Starting continuous monitoring...[/cyan]")
            while True:
                try:
                    # Run scan
                    results = asyncio.run(run_scan())
                    
                    # Check for alerts
                    for result in results:
                        if result['severity'] >= alert_threshold:
                            asyncio.run(alert_manager.send_alert(
                                title=f"Found {result['vulnerability_type']}",
                                description=result['details'],
                                severity=result['severity']
                            ))
                    
                    # Wait for next interval
                    time.sleep(interval)
                    
                except KeyboardInterrupt:
                    console.print("\n[yellow]Monitoring stopped by user[/yellow]")
                    break
                except Exception as e:
                    console.print(f"[red]Error during monitoring: {str(e)}[/red]")
                    asyncio.run(alert_manager.send_alert(
                        title="Monitoring Error",
                        description=str(e),
                        severity="ERROR"
                    ))
                    
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise click.Abort()

@cli.command()
@click.option('--format', type=click.Choice(['html', 'json', 'pdf', 'markdown']), default='html', help='Report format')
@click.option('--output', help='Output file path')
@click.option('--scan-id', help='Specific scan ID to generate report for')
@click.option('--last', is_flag=True, help='Generate report for last scan')
@click.option('--summary', is_flag=True, help='Include only summary')
@click.option('--full', is_flag=True, help='Include full details and evidence')
def report(format: str, output: str, scan_id: str, last: bool, summary: bool, full: bool):
    """Generate security scan reports"""
    try:
        from ..reporting.security_report import SecurityReportGenerator
        report_gen = SecurityReportGenerator()

        # Determine output path
        if not output:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output = f"security_report_{timestamp}.{format}"

        # Get scan results
        if scan_id:
            results = get_scan_results(scan_id)
        elif last:
            results = get_last_scan_results()
        else:
            console.print("[red]Error: Must specify --scan-id or --last[/red]")
            raise click.Abort()

        # Generate report
        report = report_gen.generate_report(
            results,
            format=format,
            summary_only=summary,
            include_evidence=full
        )

        # Save report
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            f.write(report)

        console.print(f"[green]Report saved to: {output_path}[/green]")

    except Exception as e:
        console.print(f"[red]Error generating report: {str(e)}[/red]")
        raise click.Abort()

@cli.command()
@click.option('--scan-id', help='Scan ID to analyze')
@click.option('--vulnerability-type', help='Focus on specific vulnerability type')
@click.option('--severity', type=click.Choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']), help='Filter by severity')
@click.option('--compare', help='Compare with another scan ID')
@click.option('--trend', is_flag=True, help='Show vulnerability trends over time')
@click.option('--output', help='Save analysis to file')
def analyze(scan_id: str, vulnerability_type: str, severity: str, compare: str, trend: bool, output: str):
    """Perform detailed vulnerability analysis"""
    try:
        from ..analysis import VulnerabilityAnalyzer
        analyzer = VulnerabilityAnalyzer()

        # Get scan results
        if scan_id:
            results = get_scan_results(scan_id)
        else:
            results = get_last_scan_results()

        # Perform analysis
        analysis = analyzer.analyze(
            results,
            vulnerability_type=vulnerability_type,
            severity=severity
        )

        # Compare scans if requested
        if compare:
            compare_results = get_scan_results(compare)
            diff = analyzer.compare_scans(results, compare_results)
            console.print("\n[bold]Scan Comparison:[/bold]")
            console.print(f"New vulnerabilities: {len(diff['new'])}")
            console.print(f"Fixed vulnerabilities: {len(diff['fixed'])}")
            console.print(f"Changed severity: {len(diff['changed'])}")

        # Show trends if requested
        if trend:
            trends = analyzer.analyze_trends(scan_id)
            console.print("\n[bold]Vulnerability Trends:[/bold]")
            for vuln_type, trend_data in trends.items():
                console.print(f"\n{vuln_type}:")
                console.print(f"  Frequency: {trend_data['frequency']}%")
                console.print(f"  Severity trend: {trend_data['severity_trend']}")

        # Display analysis
        console.print("\n[bold]Analysis Results:[/bold]")
        console.print(f"\nTotal vulnerabilities: {analysis['total_count']}")
        
        console.print("\n[bold]Severity Distribution:[/bold]")
        for sev, count in analysis['severity_distribution'].items():
            console.print(f"{sev}: {count}")

        console.print("\n[bold]Top Vulnerability Types:[/bold]")
        for vuln_type, count in analysis['vulnerability_types'].items():
            console.print(f"{vuln_type}: {count}")

        if analysis['recommendations']:
            console.print("\n[bold]Recommendations:[/bold]")
            for rec in analysis['recommendations']:
                console.print(f"• {rec}")

        # Save to file if requested
        if output:
            import json
            with open(output, 'w') as f:
                json.dump(analysis, f, indent=2)
            console.print(f"\n[green]Analysis saved to {output}[/green]")

    except Exception as e:
        console.print(f"[red]Error during analysis: {str(e)}[/red]")
        raise click.Abort()

def main():
    """Main entry point for the CLI"""
    try:
        check_package_versions()
        cli()
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    main() 