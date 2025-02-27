import asyncio
from typing import Dict, Any, Optional, List
import logging
from datetime import datetime
from ..probe_engine.security_probes import APIKeyLeakageProbe
from ..targets import BaseLLMTarget

logger = logging.getLogger(__name__)

class SecurityMonitor:
    """Monitors LLM security in real-time"""
    
    def __init__(self):
        self.probes = [
            APIKeyLeakageProbe()
        ]
        self.alerts = []
        self.is_monitoring = False

    async def start_monitoring(
        self,
        target: BaseLLMTarget,
        interval: int = 3600  # 1 hour
    ):
        """Start security monitoring"""
        self.is_monitoring = True
        
        while self.is_monitoring:
            try:
                # Run security probes
                for probe in self.probes:
                    results = await probe.run(target)
                    
                    # Check for critical findings
                    critical_findings = [
                        r for r in results 
                        if r["severity"] == "CRITICAL"
                    ]
                    
                    if critical_findings:
                        await self._handle_critical_findings(
                            critical_findings,
                            target
                        )
                
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error in security monitoring: {str(e)}")
                await asyncio.sleep(60)  # Wait before retry

    async def _handle_critical_findings(
        self,
        findings: List[Dict[str, Any]],
        target: BaseLLMTarget
    ):
        """Handle critical security findings"""
        for finding in findings:
            alert = {
                "timestamp": datetime.now().isoformat(),
                "target": target.__class__.__name__,
                "severity": finding["severity"],
                "details": finding["details"],
                "evidence": finding["evidence"]
            }
            
            self.alerts.append(alert)
            logger.critical(
                f"Security Alert: {alert['details']}\n"
                f"Target: {alert['target']}\n"
                f"Evidence: {alert['evidence']}"
            )

    def stop_monitoring(self):
        """Stop security monitoring"""
        self.is_monitoring = False

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Get all security alerts"""
        return self.alerts 