from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, WebSocket
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import asyncio
from ..probe_engine.probe_engine import ProbeEngine
from ..targets import create_target
from ..reporting.security_report import SecurityReportGenerator
from .auth import oauth, get_current_user, create_access_token
from starlette.responses import RedirectResponse
from starlette.requests import Request
import json
from .rbac import requires_permission, Permission
from .user_management import UserManager
from .models.profile import UserProfile, ProfileUpdate
from .models.organization import Organization, Team, TeamRole
from .audit import AuditLogger
import uuid
from datetime import datetime, timedelta
from .audit_report import AuditReportGenerator
from fastapi.responses import HTMLResponse
from ..utils.version_checker import VersionChecker
import uvicorn

app = FastAPI(title="LLM Security Scanner API")

@app.on_event("startup")
async def startup_event():
    """Check versions on startup"""
    VersionChecker.check_and_warn("fastapi")

class ScanRequest(BaseModel):
    target_url: str
    api_key: str
    model: Optional[str] = None
    provider_options: Optional[Dict[str, Any]] = None
    vulnerabilities: Optional[List[str]] = None

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    results: Optional[Dict[str, Any]] = None

# Store scan results in memory (replace with database in production)
scan_results = {}

# Store active websocket connections
websocket_connections: Dict[str, WebSocket] = {}

user_manager = UserManager()

audit_logger = AuditLogger()

# Initialize audit report generator
audit_report_generator = AuditReportGenerator(audit_logger)

@app.get('/login/github')
async def github_login(request: Request):
    redirect_uri = request.url_for('github_auth')
    return await oauth.github.authorize_redirect(request, redirect_uri)

@app.get('/login/github/callback')
async def github_auth(request: Request):
    try:
        token = await oauth.github.authorize_access_token(request)
        resp = await oauth.github.get('user', token=token)
        user = resp.json()
        
        # Create JWT token
        access_token = create_access_token({"sub": user["login"]})
        
        response = RedirectResponse(url="/")
        response.set_cookie(
            key="access_token",
            value=access_token,
            httponly=True
        )
        return response
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/scan", response_model=ScanResponse)
@requires_permission(Permission.SCAN_RUN)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user)
):
    scan_id = f"scan_{user.id}_{len(scan_results) + 1}"
    scan_results[scan_id] = {"status": "running"}
    
    background_tasks.add_task(
        run_scan,
        scan_id,
        request.target_url,
        request.api_key,
        request.model,
        request.provider_options,
        request.vulnerabilities
    )
    
    return {"scan_id": scan_id, "status": "running"}

@app.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan_results(scan_id: str):
    if scan_id not in scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan_id,
        **scan_results[scan_id]
    }

@app.websocket("/ws/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    await websocket.accept()
    websocket_connections[scan_id] = websocket
    try:
        while True:
            await websocket.receive_text()
    except:
        del websocket_connections[scan_id]

async def send_scan_update(scan_id: str, status: str, progress: float, message: str):
    if scan_id in websocket_connections:
        ws = websocket_connections[scan_id]
        await ws.send_json({
            "status": status,
            "progress": progress,
            "message": message
        })

async def run_scan(
    scan_id: str,
    target_url: str,
    api_key: str,
    model: Optional[str],
    provider_options: Optional[Dict[str, Any]],
    vulnerabilities: Optional[List[str]]
):
    try:
        # Create target
        target = create_target(
            target_url,
            api_key=api_key,
            model=model,
            **(provider_options or {})
        )
        
        # Run scan
        engine = ProbeEngine(enabled_vulnerabilities=vulnerabilities)
        results = await engine.run_scan(target)
        
        # Generate report
        generator = SecurityReportGenerator()
        report = generator.generate_report(results)
        
        # Update scan results
        scan_results[scan_id] = {
            "status": "completed",
            "results": report
        }
        
    except Exception as e:
        scan_results[scan_id] = {
            "status": "failed",
            "error": str(e)
        }

@app.get("/users", response_model=List[User])
@requires_permission(Permission.USER_MANAGE)
async def list_users(user: User = Depends(get_current_user)):
    return list(user_manager.users.values())

@app.post("/users/{user_id}/role")
@requires_permission(Permission.USER_MANAGE)
async def update_user_role(
    user_id: str,
    role: UserRole,
    current_user: User = Depends(get_current_user)
):
    return user_manager.update_user(user_id, role=role)

# Profile management
@app.get("/profile", response_model=UserProfile)
async def get_profile(user: User = Depends(get_current_user)):
    profile = user_manager.get_user_profile(user.id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile

@app.put("/profile", response_model=UserProfile)
async def update_profile(
    update: ProfileUpdate,
    user: User = Depends(get_current_user)
):
    try:
        profile = user_manager.update_user_profile(user.id, update)
        await audit_logger.log_action(
            user=user,
            action="update_profile",
            resource=f"profile/{user.id}",
            details=update.dict()
        )
        return profile
    except Exception as e:
        await audit_logger.log_action(
            user=user,
            action="update_profile",
            resource=f"profile/{user.id}",
            details=update.dict(),
            status="error"
        )
        raise

# Organization management
@app.post("/organizations", response_model=Organization)
@requires_permission(Permission.USER_MANAGE)
async def create_organization(
    org_data: dict,
    user: User = Depends(get_current_user)
):
    org = Organization(
        id=str(uuid.uuid4()),
        name=org_data["name"],
        description=org_data.get("description"),
        members={user.id: TeamRole.OWNER},
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    
    user_manager.create_organization(org)
    await audit_logger.log_action(
        user=user,
        action="create_organization",
        resource=f"organization/{org.id}",
        details=org_data
    )
    return org

@app.post("/organizations/{org_id}/teams", response_model=Team)
@requires_permission(Permission.USER_MANAGE)
async def create_team(
    org_id: str,
    team_data: dict,
    user: User = Depends(get_current_user)
):
    org = user_manager.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
        
    if user.id not in org.members or org.members[user.id] not in [TeamRole.OWNER, TeamRole.ADMIN]:
        raise HTTPException(status_code=403, detail="Permission denied")
    
    team = Team(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        name=team_data["name"],
        description=team_data.get("description"),
        members={user.id: TeamRole.ADMIN},
        created_at=datetime.now(),
        updated_at=datetime.now()
    )
    
    org.teams[team.id] = team
    user_manager.update_organization(org)
    
    await audit_logger.log_action(
        user=user,
        action="create_team",
        resource=f"organization/{org_id}/team/{team.id}",
        details=team_data
    )
    return team

@app.get("/audit/report", response_class=HTMLResponse)
@requires_permission(Permission.USER_MANAGE)
async def generate_audit_report(
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    user_ids: Optional[str] = None,
    organization_id: Optional[str] = None,
    format: str = "html",
    user: User = Depends(get_current_user)
):
    """Generate audit report"""
    # Parse dates
    start = datetime.fromisoformat(start_date) if start_date else datetime.now() - timedelta(days=30)
    end = datetime.fromisoformat(end_date) if end_date else datetime.now()
    
    # Parse user IDs (comma-separated)
    users = user_ids.split(",") if user_ids else None
    
    # Generate report
    report = await audit_report_generator.generate_report(
        start_date=start,
        end_date=end,
        user_ids=users,
        organization_id=organization_id,
        format=format
    )
    
    # Log report generation
    await audit_logger.log_action(
        user=user,
        action="generate_audit_report",
        resource="audit/report",
        details={"start_date": start_date, "end_date": end_date}
    )
    
    # Return appropriate format
    if format == "json":
        return JSONResponse(content=report)
    else:
        return HTMLResponse(content=report) 