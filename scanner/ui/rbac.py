from typing import List, Set
from enum import Enum
from functools import wraps
from fastapi import HTTPException, status
from .auth import UserRole, User

class Permission(Enum):
    SCAN_RUN = "scan:run"
    SCAN_VIEW = "scan:view"
    CONFIG_MANAGE = "config:manage"
    USER_MANAGE = "user:manage"
    REPORT_GENERATE = "report:generate"
    ALERT_MANAGE = "alert:manage"

# Role-based permissions
ROLE_PERMISSIONS = {
    UserRole.ADMIN: {
        Permission.SCAN_RUN,
        Permission.SCAN_VIEW,
        Permission.CONFIG_MANAGE,
        Permission.USER_MANAGE,
        Permission.REPORT_GENERATE,
        Permission.ALERT_MANAGE
    },
    UserRole.USER: {
        Permission.SCAN_RUN,
        Permission.SCAN_VIEW,
        Permission.CONFIG_MANAGE,
        Permission.REPORT_GENERATE
    },
    UserRole.AUDITOR: {
        Permission.SCAN_VIEW,
        Permission.REPORT_GENERATE
    }
}

def requires_permission(permission: Permission):
    """Decorator to check permission"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, user: User, **kwargs):
            if not has_permission(user, permission):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Permission denied: {permission.value}"
                )
            return await func(*args, user=user, **kwargs)
        return wrapper
    return decorator

def has_permission(user: User, permission: Permission) -> bool:
    """Check if user has permission"""
    if not user or not user.role:
        return False
    return permission in ROLE_PERMISSIONS.get(user.role, set())

def get_user_permissions(user: User) -> Set[Permission]:
    """Get all permissions for user"""
    return ROLE_PERMISSIONS.get(user.role, set()) 