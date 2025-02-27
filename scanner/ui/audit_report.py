from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from pathlib import Path
from .audit import AuditLogger

class AuditReportGenerator:
    """Generates audit reports and analytics"""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        
    async def generate_report(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        user_ids: Optional[List[str]] = None,
        organization_id: Optional[str] = None,
        format: str = "html"
    ) -> Dict[str, Any]:
        """Generate a comprehensive audit report"""
        if not start_date:
            start_date = datetime.now() - timedelta(days=30)
        if not end_date:
            end_date = datetime.now()
            
        # Get all audit logs
        all_logs = []
        for log_file in self.audit_logger.log_dir.glob("audit_*.log"):
            with open(log_file) as f:
                for line in f:
                    try:
                        # Extract JSON part from log line
                        json_part = line.split(" - ")[-1]
                        entry = json.loads(json_part)
                        
                        # Apply filters
                        timestamp = datetime.fromisoformat(entry["timestamp"])
                        if timestamp < start_date or timestamp > end_date:
                            continue
                            
                        if user_ids and entry["user_id"] not in user_ids:
                            continue
                            
                        # Add to logs collection
                        all_logs.append(entry)
                    except Exception as e:
                        continue
        
        # Convert to DataFrame for analysis
        if not all_logs:
            return {"error": "No audit logs found for the specified criteria"}
            
        df = pd.DataFrame(all_logs)
        
        # Generate insights
        report = {
            "summary": self._generate_summary(df),
            "visualizations": self._generate_visualizations(df),
            "action_breakdown": self._action_breakdown(df),
            "user_activity": self._user_activity(df),
            "raw_logs": df.to_dict(orient="records")
        }
        
        # Generate appropriate format
        if format == "json":
            return report
        elif format == "html":
            return self._generate_html(report)
        else:
            return report
    
    def _generate_summary(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate summary statistics"""
        total_actions = len(df)
        unique_users = df["user_id"].nunique()
        action_types = df["action"].nunique()
        error_count = df[df["status"] == "error"].shape[0]
        
        return {
            "total_actions": total_actions,
            "unique_users": unique_users,
            "action_types": action_types,
            "error_count": error_count,
            "error_rate": round(error_count / total_actions * 100, 2) if total_actions else 0,
            "time_range": {
                "start": df["timestamp"].min(),
                "end": df["timestamp"].max()
            }
        }
    
    def _generate_visualizations(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Generate visualization data"""
        # Add datetime column for time analysis
        df["datetime"] = pd.to_datetime(df["timestamp"])
        df["date"] = df["datetime"].dt.date
        
        # Activity over time
        activity_by_date = df.groupby("date").size().reset_index(name="count")
        
        # Actions by status
        status_counts = df["status"].value_counts().reset_index()
        status_counts.columns = ["status", "count"]
        
        # Create Plotly figures
        time_series = px.line(
            activity_by_date, 
            x="date", y="count", 
            title="Activity Over Time"
        )
        
        status_pie = px.pie(
            status_counts,
            values="count",
            names="status",
            title="Actions by Status"
        )
        
        return {
            "time_series": time_series,
            "status_distribution": status_pie
        }
    
    def _action_breakdown(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze actions by type"""
        action_counts = df["action"].value_counts().reset_index()
        action_counts.columns = ["action", "count"]
        
        # Calculate success rate by action
        action_success = df.groupby("action")["status"].apply(
            lambda x: (x == "success").mean() * 100
        ).reset_index()
        action_success.columns = ["action", "success_rate"]
        
        return {
            "action_counts": action_counts.to_dict(orient="records"),
            "action_success": action_success.to_dict(orient="records")
        }
    
    def _user_activity(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze user activity"""
        user_counts = df.groupby(["user_id", "user_email"]).size().reset_index(name="action_count")
        user_counts = user_counts.sort_values("action_count", ascending=False)
        
        # Most active users
        most_active = user_counts.head(10)
        
        # User actions by type
        user_actions = df.groupby(["user_id", "action"]).size().reset_index(name="count")
        user_actions = user_actions.sort_values(["user_id", "count"], ascending=[True, False])
        
        return {
            "most_active_users": most_active.to_dict(orient="records"),
            "user_actions": user_actions.to_dict(orient="records")
        }
    
    def _generate_html(self, report: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Audit Report</title>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ text-align: center; margin-bottom: 30px; }}
                .section {{ margin-bottom: 30px; }}
                .summary-box {{ 
                    display: flex; 
                    flex-wrap: wrap; 
                    gap: 20px; 
                    margin-bottom: 20px; 
                }}
                .metric {{ 
                    background: #f5f5f5; 
                    padding: 15px; 
                    border-radius: 5px; 
                    width: calc(25% - 20px);
                    box-sizing: border-box;
                }}
                .visualization {{ height: 400px; margin-bottom: 30px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
                tr:hover {{ background-color: #f5f5f5; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Security Audit Report</h1>
                    <p>Period: {report["summary"]["time_range"]["start"]} to {report["summary"]["time_range"]["end"]}</p>
                </div>
                
                <div class="section">
                    <h2>Summary</h2>
                    <div class="summary-box">
                        <div class="metric">
                            <h3>Total Actions</h3>
                            <p>{report["summary"]["total_actions"]}</p>
                        </div>
                        <div class="metric">
                            <h3>Unique Users</h3>
                            <p>{report["summary"]["unique_users"]}</p>
                        </div>
                        <div class="metric">
                            <h3>Action Types</h3>
                            <p>{report["summary"]["action_types"]}</p>
                        </div>
                        <div class="metric">
                            <h3>Error Rate</h3>
                            <p>{report["summary"]["error_rate"]}%</p>
                        </div>
                    </div>
                </div>
                
                <div class="section">
                    <h2>Activity Over Time</h2>
                    <div id="time-series" class="visualization"></div>
                </div>
                
                <div class="section">
                    <h2>Actions by Status</h2>
                    <div id="status-pie" class="visualization"></div>
                </div>
                
                <div class="section">
                    <h2>Most Active Users</h2>
                    <table>
                        <tr>
                            <th>User ID</th>
                            <th>Email</th>
                            <th>Action Count</th>
                        </tr>
                        {"".join([f"<tr><td>{user['user_id']}</td><td>{user['user_email']}</td><td>{user['action_count']}</td></tr>" for user in report["user_activity"]["most_active_users"]])}
                    </table>
                </div>
                
                <div class="section">
                    <h2>Action Breakdown</h2>
                    <table>
                        <tr>
                            <th>Action</th>
                            <th>Count</th>
                            <th>Success Rate</th>
                        </tr>
                        {"".join([f"<tr><td>{action['action']}</td><td>{action['count']}</td><td>{next((item['success_rate'] for item in report['action_breakdown']['action_success'] if item['action'] == action['action']), 0)}%</td></tr>" for action in report["action_breakdown"]["action_counts"]])}
                    </table>
                </div>
            </div>

            <script>
                var timeSeries = {report["visualizations"]["time_series"].to_json()};
                var statusPie = {report["visualizations"]["status_distribution"].to_json()};
                
                Plotly.newPlot('time-series', timeSeries.data, timeSeries.layout);
                Plotly.newPlot('status-pie', statusPie.data, statusPie.layout);
            </script>
        </body>
        </html>
        """
        
        return html

    def export_report(
        self,
        report: Dict[str, Any],
        format: str = "html",
        output_path: Optional[Path] = None
    ):
        """Export report to file"""
        if not output_path:
            output_path = Path(f"audit_report_{datetime.now().strftime('%Y%m%d')}.{format}")
            
        if format == "html":
            with open(output_path, "w") as f:
                f.write(self._generate_html(report))
        elif format == "json":
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2, default=str)
                
        return output_path 