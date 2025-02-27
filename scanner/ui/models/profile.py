from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
from datetime import datetime

class UserProfile(BaseModel):
    user_id: str
    email: EmailStr
    name: str
    organization: Optional[str] = None
    team: Optional[str] = None
    preferences: Dict[str, Any] = {}
    last_login: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

class ProfileUpdate(BaseModel):
    name: Optional[str] = None
    organization: Optional[str] = None
    team: Optional[str] = None
    preferences: Optional[Dict[str, Any]] = None 