# Package Usage Examples

## Basic Usage

```python
from scanner.probe_engine import ProbeEngine
from scanner.targets import create_target

# Basic scan
async def run_basic_scan():
    target = create_target("openai:gpt-4", api_key="your_api_key")
    engine = ProbeEngine()
    results = await engine.run_scan(target)
    return results

# With specific vulnerabilities
async def run_targeted_scan():
    target = create_target("anthropic:claude-3", api_key="your_api_key")
    engine = ProbeEngine(enabled_vulnerabilities=["PROMPT_INJECTION", "DATA_DISCLOSURE"])
    results = await engine.run_scan(target)
    return results

# With custom configuration
async def run_configured_scan():
    import yaml
    
    # Load configuration
    with open("config.yaml") as f:
        config = yaml.safe_load(f)
    
    # Create target from config
    target = create_target(
        f"{config['provider']['name']}:{config['provider']['model']}",
        api_key=config['provider']['api_key']
    )
    
    # Run scan
    engine = ProbeEngine(enabled_vulnerabilities=config['scan']['vulnerabilities'])
    results = await engine.run_scan(target)
    return results
```

## Integration Examples

### CI/CD Pipeline

```python
from scanner.probe_engine import ProbeEngine
from scanner.targets import create_target
from scanner.reporting import SecurityReportGenerator

async def ci_cd_scan():
    # Run scan
    target = create_target("openai:gpt-4", api_key="your_api_key")
    engine = ProbeEngine()
    results = await engine.run_scan(target)
    
    # Generate report
    report_gen = SecurityReportGenerator()
    report = report_gen.generate_report(results, format="html")
    
    # Save report
    with open("security_report.html", "w") as f:
        f.write(report)
    
    # Check for critical vulnerabilities
    critical_vulns = [r for r in results if r["severity"] == "CRITICAL"]
    if critical_vulns:
        raise Exception(f"Found {len(critical_vulns)} critical vulnerabilities!")
```

### Monitoring Integration

```python
from scanner.probe_engine import ProbeEngine
from scanner.targets import create_target
from scanner.monitoring import AlertManager
import asyncio

async def monitor_llm():
    target = create_target("openai:gpt-4", api_key="your_api_key")
    engine = ProbeEngine()
    alert_manager = AlertManager()
    
    while True:
        try:
            results = await engine.run_scan(target)
            
            # Alert on findings
            for result in results:
                await alert_manager.send_alert(
                    title=f"Found {result['vulnerability_type']}",
                    description=result['details'],
                    severity=result['severity']
                )
                
            # Wait before next scan
            await asyncio.sleep(3600)  # 1 hour
            
        except Exception as e:
            await alert_manager.send_alert(
                title="Monitoring Error",
                description=str(e),
                severity="ERROR"
            )
``` 