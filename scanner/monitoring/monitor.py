import asyncio
from typing import Dict, Any, Optional, Callable
from datetime import datetime
import logging
from scanner.probe_engine.probe_engine import ProbeEngine
from scanner.analysis.results_analyzer import ResultsAnalyzer
from scanner.config.scan_config import ConfigManager

logger = logging.getLogger(__name__)

class VulnerabilityMonitor:
    """Continuous vulnerability monitoring"""
    
    def __init__(
        self,
        config_path: Optional[str] = None,
        alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.config = ConfigManager(config_path).config if config_path else None
        self.alert_callback = alert_callback
        self.historical_data = []
        self.is_running = False
    
    async def start_monitoring(self, target_url: str):
        """Start continuous monitoring"""
        self.is_running = True
        
        while self.is_running:
            try:
                # Run scan
                engine = ProbeEngine()
                results = await engine.run_scan(target_url)
                
                # Analyze results
                analyzer = ResultsAnalyzer()
                analysis = analyzer.analyze_results(results)
                
                # Store historical data
                self.historical_data.append({
                    "date": datetime.now().isoformat(),
                    "total_vulnerabilities": analysis.total_vulnerabilities,
                    "risk_score": analysis.risk_score,
                    "risk_level": analyzer._get_risk_level(analysis.risk_score)
                })
                
                # Check for alerts
                if self.should_alert(analysis):
                    await self.send_alert(analysis)
                
                # Wait for next interval
                interval = (
                    self.config.monitoring["interval"]
                    if self.config else 3600
                )
                await asyncio.sleep(interval)
                
            except Exception as e:
                logger.error(f"Error during monitoring: {str(e)}")
                await asyncio.sleep(60)  # Wait before retry
    
    def stop_monitoring(self):
        """Stop continuous monitoring"""
        self.is_running = False
    
    def should_alert(self, analysis: Dict[str, Any]) -> bool:
        """Check if alert should be triggered"""
        if not self.config:
            return False
            
        threshold = self.config.monitoring.get("alert_threshold", "HIGH")
        current_level = analysis["risk_level"]
        
        risk_levels = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1,
            "INFO": 0
        }
        
        return risk_levels.get(current_level, 0) >= risk_levels.get(threshold, 0)
    
    async def send_alert(self, analysis: Dict[str, Any]):
        """Send alert for high-risk findings"""
        if self.alert_callback:
            await self.alert_callback(analysis)
        else:
            logger.warning(
                f"High risk vulnerabilities detected! "
                f"Risk Score: {analysis['risk_score']}, "
                f"Level: {analysis['risk_level']}"
            ) 