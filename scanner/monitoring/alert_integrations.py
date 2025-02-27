import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import aiohttp
from typing import Dict, Any, List
import logging
import json

logger = logging.getLogger(__name__)

class AlertIntegration:
    """Base class for alert integrations"""
    
    async def send_alert(self, alert: Dict[str, Any]):
        """Send alert through integration"""
        raise NotImplementedError


class EmailAlertIntegration(AlertIntegration):
    """Email alert integration"""
    
    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        username: str,
        password: str,
        from_email: str,
        to_emails: List[str]
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_email = from_email
        self.to_emails = to_emails

    async def send_alert(self, alert: Dict[str, Any]):
        try:
            msg = MIMEMultipart()
            msg["From"] = self.from_email
            msg["To"] = ", ".join(self.to_emails)
            msg["Subject"] = f"LLM Security Alert: {alert['severity']}"
            
            body = (
                f"Security Alert Details:\n\n"
                f"Timestamp: {alert['timestamp']}\n"
                f"Target: {alert['target']}\n"
                f"Severity: {alert['severity']}\n"
                f"Details: {alert['details']}\n\n"
                f"Evidence: {json.dumps(alert['evidence'], indent=2)}"
            )
            
            msg.attach(MIMEText(body, "plain"))
            
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
                
            logger.info(f"Email alert sent to {self.to_emails}")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {str(e)}")


class SlackAlertIntegration(AlertIntegration):
    """Slack alert integration"""
    
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    async def send_alert(self, alert: Dict[str, Any]):
        try:
            message = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🚨 LLM Security Alert: {alert['severity']}"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {
                                "type": "mrkdwn",
                                "text": f"*Target:*\n{alert['target']}"
                            },
                            {
                                "type": "mrkdwn",
                                "text": f"*Timestamp:*\n{alert['timestamp']}"
                            }
                        ]
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Details:*\n{alert['details']}"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Evidence:*\n```{json.dumps(alert['evidence'], indent=2)}```"
                        }
                    }
                ]
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=message
                ) as response:
                    if response.status != 200:
                        raise Exception(
                            f"Slack API returned status {response.status}"
                        )
                        
            logger.info("Slack alert sent successfully")
            
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {str(e)}") 