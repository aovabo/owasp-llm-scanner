from typing import Dict, Any, List
import json
from datetime import datetime
from jinja2 import Template
import plotly.graph_objects as go
from ..probe_engine.base_probe import Severity

class SecurityReportGenerator:
    """Generates detailed security reports"""
    
    def __init__(self):
        self.mitigation_recommendations = {
            "PROMPT_INJECTION": [
                "Implement strict input validation",
                "Use content filtering",
                "Add rate limiting for requests",
                "Monitor for suspicious patterns"
            ],
            "DATA_DISCLOSURE": [
                "Implement PII detection and filtering",
                "Use output sanitization",
                "Add audit logging",
                "Regular security testing"
            ],
            "PROMPT_LEAKAGE": [
                "Regular system prompt audits",
                "Implement prompt encryption",
                "Monitor for prompt extraction attempts",
                "Use role-based access control"
            ]
        }

    def generate_report(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive security report"""
        report = {
            "summary": self._generate_summary(findings),
            "risk_analysis": self._analyze_risks(findings),
            "critical_findings": self._get_critical_findings(findings),
            "mitigation_plan": self._create_mitigation_plan(findings),
            "visualizations": self._create_visualizations(findings)
        }
        return report

    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for finding in findings:
            severity = finding.get("severity", "LOW")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        return {
            "total_findings": len(findings),
            "severity_distribution": severity_counts,
            "timestamp": datetime.now().isoformat(),
            "risk_score": self._calculate_risk_score(severity_counts)
        }

    def _analyze_risks(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        vulnerability_types = {}
        
        for finding in findings:
            vuln_type = finding.get("vulnerability_type", "UNKNOWN")
            if vuln_type not in vulnerability_types:
                vulnerability_types[vuln_type] = {
                    "count": 0,
                    "severity_distribution": {},
                    "examples": []
                }
            
            vuln_info = vulnerability_types[vuln_type]
            vuln_info["count"] += 1
            
            severity = finding.get("severity", "LOW")
            vuln_info["severity_distribution"][severity] = \
                vuln_info["severity_distribution"].get(severity, 0) + 1
            
            if len(vuln_info["examples"]) < 3:  # Keep top 3 examples
                vuln_info["examples"].append({
                    "details": finding.get("details", ""),
                    "evidence": finding.get("evidence", {})
                })

        return vulnerability_types

    def _get_critical_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [
            finding for finding in findings
            if finding.get("severity") == "CRITICAL"
        ]

    def _create_mitigation_plan(self, findings: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        mitigation_plan = {}
        
        for finding in findings:
            vuln_type = finding.get("vulnerability_type")
            if vuln_type in self.mitigation_recommendations:
                if vuln_type not in mitigation_plan:
                    mitigation_plan[vuln_type] = {
                        "recommendations": self.mitigation_recommendations[vuln_type],
                        "priority": "HIGH" if finding.get("severity") == "CRITICAL" else "MEDIUM",
                        "affected_findings": []
                    }
                mitigation_plan[vuln_type]["affected_findings"].append(
                    finding.get("details", "No details")
                )

        return mitigation_plan

    def _create_visualizations(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        # Create severity distribution pie chart
        severity_counts = {}
        for finding in findings:
            severity = finding.get("severity", "LOW")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        severity_fig = go.Figure(data=[
            go.Pie(
                labels=list(severity_counts.keys()),
                values=list(severity_counts.values()),
                hole=.3
            )
        ])
        severity_fig.update_layout(title="Severity Distribution")

        # Create vulnerability type bar chart
        vuln_counts = {}
        for finding in findings:
            vuln_type = finding.get("vulnerability_type", "UNKNOWN")
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1

        vuln_fig = go.Figure(data=[
            go.Bar(
                x=list(vuln_counts.keys()),
                y=list(vuln_counts.values())
            )
        ])
        vuln_fig.update_layout(
            title="Vulnerability Types",
            xaxis_title="Vulnerability Type",
            yaxis_title="Count"
        )

        return {
            "severity_distribution": severity_fig,
            "vulnerability_types": vuln_fig
        }

    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> float:
        weights = {
            "CRITICAL": 10,
            "HIGH": 5,
            "MEDIUM": 2,
            "LOW": 1
        }
        
        total_weight = sum(
            count * weights[severity]
            for severity, count in severity_counts.items()
        )
        total_findings = sum(severity_counts.values())
        
        if total_findings == 0:
            return 0.0
            
        return round(total_weight / total_findings, 2)

    def export_html_report(self, report: Dict[str, Any], output_path: str):
        """Export report as HTML"""
        template = Template("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>LLM Security Report</title>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .section { margin: 20px 0; }
                .finding { border: 1px solid #ddd; padding: 10px; margin: 10px 0; }
                .CRITICAL { color: red; }
                .HIGH { color: orange; }
                .MEDIUM { color: yellow; }
                .LOW { color: green; }
            </style>
        </head>
        <body>
            <h1>LLM Security Report</h1>
            
            <div class="section">
                <h2>Summary</h2>
                <p>Total Findings: {{ report.summary.total_findings }}</p>
                <p>Risk Score: {{ report.summary.risk_score }}</p>
                <div id="severity-chart"></div>
            </div>

            <div class="section">
                <h2>Critical Findings</h2>
                {% for finding in report.critical_findings %}
                <div class="finding CRITICAL">
                    <h3>{{ finding.vulnerability_type }}</h3>
                    <p>{{ finding.details }}</p>
                    <pre>{{ finding.evidence | tojson(indent=2) }}</pre>
                </div>
                {% endfor %}
            </div>

            <div class="section">
                <h2>Mitigation Plan</h2>
                {% for vuln_type, plan in report.mitigation_plan.items() %}
                <div class="finding">
                    <h3>{{ vuln_type }}</h3>
                    <p>Priority: {{ plan.priority }}</p>
                    <ul>
                    {% for rec in plan.recommendations %}
                        <li>{{ rec }}</li>
                    {% endfor %}
                    </ul>
                </div>
                {% endfor %}
            </div>

            <script>
                {{ report.visualizations.severity_distribution | safe }}
                {{ report.visualizations.vulnerability_types | safe }}
            </script>
        </body>
        </html>
        """)

        with open(output_path, 'w') as f:
            f.write(template.render(report=report)) 