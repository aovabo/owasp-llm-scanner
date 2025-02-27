from typing import Optional, Dict, Any
from datetime import datetime
import logging
import json
from pathlib import Path
from .auth import User

class AuditLogger:
    """Audit logger for user actions"""
    
    def __init__(self, log_dir: Path = Path("audit_logs")):
        self.log_dir = log_dir
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup file handler
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(logging.INFO)
        
        # Create rotating file handler
        handler = logging.FileHandler(
            self.log_dir / f"audit_{datetime.now().strftime('%Y%m')}.log"
        )
        handler.setFormatter(
            logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
        )
        self.logger.addHandler(handler)

    async def log_action(
        self,
        user: User,
        action: str,
        resource: str,
        details: Optional[Dict[str, Any]] = None,
        status: str = "success"
    ):
        """Log user action"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "user_id": user.id,
            "user_email": user.email,
            "action": action,
            "resource": resource,
            "details": details or {},
            "status": status,
            "ip_address": None,  # Add request.client.host if needed
            "user_agent": None   # Add request headers if needed
        }
        
        self.logger.info(json.dumps(log_entry))
        return log_entry

    def get_user_actions(
        self,
        user_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        action_type: Optional[str] = None
    ) -> list:
        """Get user action history"""
        actions = []
        
        # Read and filter logs
        for log_file in self.log_dir.glob("audit_*.log"):
            with open(log_file) as f:
                for line in f:
                    try:
                        entry = json.loads(line.split(" - ")[-1])
                        if entry["user_id"] != user_id:
                            continue
                            
                        timestamp = datetime.fromisoformat(entry["timestamp"])
                        if start_date and timestamp < start_date:
                            continue
                        if end_date and timestamp > end_date:
                            continue
                        if action_type and entry["action"] != action_type:
                            continue
                            
                        actions.append(entry)
                    except:
                        continue
                        
        return sorted(
            actions,
            key=lambda x: x["timestamp"],
            reverse=True
        ) 