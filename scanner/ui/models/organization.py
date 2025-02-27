from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum

class TeamRole(Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"

class Team(BaseModel):
    id: str
    name: str
    organization_id: str
    description: Optional[str] = None
    members: Dict[str, TeamRole] = {}  # user_id: role
    created_at: datetime
    updated_at: datetime

class Organization(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    teams: Dict[str, Team] = {}
    members: Dict[str, TeamRole] = {}
    settings: Dict[str, Any] = {}
    created_at: datetime
    updated_at: datetime 