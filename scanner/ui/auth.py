from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from starlette.config import Config
from starlette.requests import Request
from starlette.responses import RedirectResponse
from authlib.integrations.starlette_client import OAuth, OAuthError
import jwt
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

class UserRole(Enum):
    ADMIN = "admin"
    USER = "user"
    AUDITOR = "auditor"

class User:
    def __init__(
        self,
        id: str,
        email: str,
        name: str,
        provider: str,
        role: UserRole = UserRole.USER
    ):
        self.id = id
        self.email = email
        self.name = name
        self.provider = provider
        self.role = role

# Load config
config = Config(".env")
oauth = OAuth()

# GitHub OAuth
oauth.register(
    name='github',
    client_id=config('GITHUB_CLIENT_ID'),
    client_secret=config('GITHUB_CLIENT_SECRET'),
    authorize_url='https://github.com/login/oauth/authorize',
    token_url='https://github.com/login/oauth/access_token',
    api_base_url='https://api.github.com/',
    client_kwargs={'scope': 'read:user user:email'},
)

# Google OAuth
oauth.register(
    name='google',
    client_id=config('GOOGLE_CLIENT_ID'),
    client_secret=config('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# Microsoft OAuth
oauth.register(
    name='microsoft',
    client_id=config('MICROSOFT_CLIENT_ID'),
    client_secret=config('MICROSOFT_CLIENT_SECRET'),
    api_base_url='https://graph.microsoft.com/v1.0/',
    authorize_url='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
    token_url='https://login.microsoftonline.com/common/oauth2/v2.0/token',
    client_kwargs={'scope': 'User.Read'},
)

# User storage (replace with database in production)
users = {}

# JWT settings
SECRET_KEY = config('SECRET_KEY', default='your-secret-key')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        ) 