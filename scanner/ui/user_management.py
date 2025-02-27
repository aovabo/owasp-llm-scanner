from typing import Dict, Optional, List
from .auth import User, UserRole
import json
from pathlib import Path

class UserManager:
    def __init__(self, storage_path: Optional[Path] = None):
        self.storage_path = storage_path or Path("users.json")
        self.users: Dict[str, User] = {}
        self.load_users()

    def load_users(self):
        """Load users from storage"""
        if self.storage_path.exists():
            with open(self.storage_path) as f:
                data = json.load(f)
                self.users = {
                    id: User(**user_data)
                    for id, user_data in data.items()
                }

    def save_users(self):
        """Save users to storage"""
        with open(self.storage_path, 'w') as f:
            json.dump(
                {
                    id: user.__dict__
                    for id, user in self.users.items()
                },
                f,
                indent=2
            )

    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        return self.users.get(user_id)

    def create_user(self, user: User) -> User:
        """Create new user"""
        if user.id in self.users:
            raise ValueError(f"User {user.id} already exists")
        self.users[user.id] = user
        self.save_users()
        return user

    def update_user(self, user_id: str, **updates) -> User:
        """Update user"""
        if user_id not in self.users:
            raise ValueError(f"User {user_id} not found")
        
        user = self.users[user_id]
        for key, value in updates.items():
            if hasattr(user, key):
                setattr(user, key, value)
        
        self.save_users()
        return user

    def delete_user(self, user_id: str):
        """Delete user"""
        if user_id in self.users:
            del self.users[user_id]
            self.save_users()

    def get_users_by_role(self, role: UserRole) -> List[User]:
        """Get users by role"""
        return [
            user for user in self.users.values()
            if user.role == role
        ] 