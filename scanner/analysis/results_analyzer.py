from typing import List, Dict, Any
from collections import Counter
from dataclasses import dataclass
from enum import Enum

class RiskLevel(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

@dataclass
class ScanAnalysis:
    total_vulnerabilities: int
    risk_distribution: Dict[str, int]
    top_vulnerabilities: List[Dict[str, Any]]
    mitigation_summary: Dict[str, List[str]]
    risk_score: float

class ResultsAnalyzer:
    """Analyzes vulnerability scan results"""

    def analyze_results(self, results: List[Dict[str, Any]]) -> ScanAnalysis:
        """Perform comprehensive analysis of scan results"""
        
        # Count vulnerabilities by severity
        risk_distribution = Counter(
            result.get("severity", "UNKNOWN") 
            for result in results
        )
        
        # Calculate risk score (weighted by severity)
        risk_score = sum(
            RiskLevel[severity].value * count 
            for severity, count in risk_distribution.items()
            if severity in RiskLevel.__members__
        )
        
        # Get top vulnerabilities (by severity)
        top_vulnerabilities = sorted(
            results,
            key=lambda x: RiskLevel[x.get("severity", "INFO")].value,
            reverse=True
        )[:5]
        
        # Group mitigations by vulnerability type
        mitigation_summary = {}
        for result in results:
            vuln_type = result.get("vulnerability_type")
            mitigation = result.get("mitigation")
            if vuln_type and mitigation:
                if vuln_type not in mitigation_summary:
                    mitigation_summary[vuln_type] = []
                if mitigation not in mitigation_summary[vuln_type]:
                    mitigation_summary[vuln_type].append(mitigation)
        
        return ScanAnalysis(
            total_vulnerabilities=len(results),
            risk_distribution=dict(risk_distribution),
            top_vulnerabilities=top_vulnerabilities,
            mitigation_summary=mitigation_summary,
            risk_score=risk_score
        )

    def generate_report(self, analysis: ScanAnalysis) -> Dict[str, Any]:
        """Generate a detailed report from analysis"""
        return {
            "summary": {
                "total_vulnerabilities": analysis.total_vulnerabilities,
                "risk_score": analysis.risk_score,
                "risk_level": self._get_risk_level(analysis.risk_score)
            },
            "risk_distribution": analysis.risk_distribution,
            "critical_findings": [
                {
                    "type": vuln.get("vulnerability_type"),
                    "severity": vuln.get("severity"),
                    "details": vuln.get("details"),
                    "evidence": vuln.get("evidence")
                }
                for vuln in analysis.top_vulnerabilities
            ],
            "mitigation_recommendations": analysis.mitigation_summary
        }

    def _get_risk_level(self, risk_score: float) -> str:
        """Determine overall risk level based on score"""
        if risk_score >= 10:
            return "CRITICAL"
        elif risk_score >= 7:
            return "HIGH"
        elif risk_score >= 4:
            return "MEDIUM"
        elif risk_score >= 1:
            return "LOW"
        return "INFO" 