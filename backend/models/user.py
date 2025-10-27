from pydantic import BaseModel
from typing import Optional, List

class User(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    phone: Optional[str] = None
    is_active: bool = True
    is_verified: bool = False
    role_ids: Optional[List[int]] = []

class UserCreate(User):
    password: str

class UserUpdate(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    phone: Optional[str] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    role_ids: Optional[List[int]] = None

class UserPasswordUpdate(BaseModel):
    current_password: str
    new_password: str

class Role(BaseModel):
    name: str
    display_name: str
    description: Optional[str] = None
    permissions: List[str] = []
    is_active: bool = True
    
class ClusterSpecificRole(BaseModel):
    name: str
    display_name: str
    description: Optional[str] = None
    permissions: List[str] = []
    cluster_ids: Optional[List[int]] = []  # Empty means all clusters
    is_active: bool = True

class UserRoleAssignment(BaseModel):
    user_id: int
    role_ids: List[int]

class LoginRequest(BaseModel):
    username: str
    password: str 