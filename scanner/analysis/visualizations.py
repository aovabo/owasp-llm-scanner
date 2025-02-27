from typing import Dict, List, Any
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd
from datetime import datetime, timedelta

class VulnerabilityVisualizer:
    """Generates visualizations for vulnerability scan results"""
    
    def create_dashboard(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Create interactive dashboard visualizations"""
        figures = {
            "risk_distribution": self._create_risk_distribution(
                analysis["risk_distribution"]
            ),
            "vulnerability_timeline": self._create_vulnerability_timeline(
                analysis.get("historical_data", [])
            ),
            "risk_heatmap": self._create_risk_heatmap(
                analysis.get("critical_findings", [])
            )
        }
        return figures
    
    def _create_risk_distribution(self, risk_dist: Dict[str, int]) -> go.Figure:
        """Create pie chart of risk distribution"""
        colors = {
            "CRITICAL": "red",
            "HIGH": "orange",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFO": "blue"
        }
        
        fig = go.Figure(data=[
            go.Pie(
                labels=list(risk_dist.keys()),
                values=list(risk_dist.values()),
                marker_colors=[colors.get(level, "gray") for level in risk_dist.keys()]
            )
        ])
        
        fig.update_layout(
            title="Risk Distribution",
            showlegend=True
        )
        return fig
    
    def _create_vulnerability_timeline(self, historical_data: List[Dict[str, Any]]) -> go.Figure:
        """Create timeline of vulnerability trends"""
        if not historical_data:
            # Create sample data if no historical data
            dates = pd.date_range(
                start=datetime.now() - timedelta(days=30),
                end=datetime.now(),
                freq='D'
            )
            historical_data = [
                {"date": date.isoformat(), "total_vulnerabilities": 0}
                for date in dates
            ]
        
        df = pd.DataFrame(historical_data)
        df['date'] = pd.to_datetime(df['date'])
        
        fig = go.Figure(data=[
            go.Scatter(
                x=df['date'],
                y=df['total_vulnerabilities'],
                mode='lines+markers'
            )
        ])
        
        fig.update_layout(
            title="Vulnerability Trends",
            xaxis_title="Date",
            yaxis_title="Total Vulnerabilities"
        )
        return fig
    
    def _create_risk_heatmap(self, findings: List[Dict[str, Any]]) -> go.Figure:
        """Create heatmap of vulnerability types vs severity"""
        # Group findings by type and severity
        vuln_matrix = {}
        for finding in findings:
            vuln_type = finding.get("type", "Unknown")
            severity = finding.get("severity", "INFO")
            if vuln_type not in vuln_matrix:
                vuln_matrix[vuln_type] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
            vuln_matrix[vuln_type][severity] += 1
        
        # Convert to matrix format
        x_labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        y_labels = list(vuln_matrix.keys())
        z_values = [[vuln_matrix[y][x] for x in x_labels] for y in y_labels]
        
        fig = go.Figure(data=[
            go.Heatmap(
                z=z_values,
                x=x_labels,
                y=y_labels,
                colorscale='RdYlGn_r'
            )
        ])
        
        fig.update_layout(
            title="Vulnerability Risk Heatmap",
            xaxis_title="Severity",
            yaxis_title="Vulnerability Type"
        )
        return fig 