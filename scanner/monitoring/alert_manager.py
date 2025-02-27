from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging
from .alert_integrations import AlertIntegration

logger = logging.getLogger(__name__)

class AlertManager:
    """Manages alert filtering and aggregation"""
    
    def __init__(
        self,
        integrations: List[AlertIntegration],
        aggregation_window: int = 3600,  # 1 hour
        min_severity: str = "HIGH"
    ):
        self.integrations = integrations
        self.aggregation_window = aggregation_window
        self.min_severity = min_severity
        self.alert_buffer = []
        self.last_alert_time = {}  # Track last alert time per vulnerability type

    async def handle_alert(self, alert: Dict[str, Any]):
        """Handle new security alert"""
        if not self._should_alert(alert):
            logger.debug(f"Alert filtered out: {alert['details']}")
            return

        self.alert_buffer.append(alert)
        
        # Check if we should aggregate and send
        if self._should_send_aggregated():
            await self._send_aggregated_alerts()
            self.alert_buffer = []  # Clear buffer after sending

    def _should_alert(self, alert: Dict[str, Any]) -> bool:
        """Determine if alert should be processed"""
        severity_levels = {
            "CRITICAL": 4,
            "HIGH": 3,
            "MEDIUM": 2,
            "LOW": 1
        }
        
        # Check severity threshold
        alert_severity = severity_levels.get(alert["severity"], 0)
        min_severity = severity_levels.get(self.min_severity, 0)
        if alert_severity < min_severity:
            return False

        # Check rate limiting
        vuln_type = alert.get("vulnerability_type", "UNKNOWN")
        last_time = self.last_alert_time.get(vuln_type)
        
        if last_time:
            time_diff = datetime.now() - last_time
            if time_diff < timedelta(minutes=5):  # Rate limit: 1 alert per 5 minutes per type
                return False

        self.last_alert_time[vuln_type] = datetime.now()
        return True

    def _should_send_aggregated(self) -> bool:
        """Determine if aggregated alerts should be sent"""
        if not self.alert_buffer:
            return False

        # Send if we have critical alerts
        if any(a["severity"] == "CRITICAL" for a in self.alert_buffer):
            return True

        # Send if buffer is getting large
        if len(self.alert_buffer) >= 10:
            return True

        # Send if oldest alert is getting old
        oldest_time = datetime.fromisoformat(self.alert_buffer[0]["timestamp"])
        time_diff = datetime.now() - oldest_time
        
        return time_diff.total_seconds() >= self.aggregation_window

    async def _send_aggregated_alerts(self):
        """Send aggregated alerts through integrations"""
        if not self.alert_buffer:
            return

        # Group alerts by type
        grouped_alerts = {}
        for alert in self.alert_buffer:
            vuln_type = alert.get("vulnerability_type", "UNKNOWN")
            if vuln_type not in grouped_alerts:
                grouped_alerts[vuln_type] = []
            grouped_alerts[vuln_type].append(alert)

        # Create aggregated alert
        aggregated = {
            "timestamp": datetime.now().isoformat(),
            "alert_count": len(self.alert_buffer),
            "severity": max(a["severity"] for a in self.alert_buffer),
            "details": f"Multiple security issues detected ({len(self.alert_buffer)} alerts)",
            "grouped_alerts": grouped_alerts
        }

        # Send through all integrations
        for integration in self.integrations:
            try:
                await integration.send_alert(aggregated)
            except Exception as e:
                logger.error(f"Failed to send alert through {integration.__class__.__name__}: {str(e)}") 