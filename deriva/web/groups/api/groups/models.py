#
# Copyright 2025 University of Southern California
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import time
import uuid
import json
from datetime import datetime
from zoneinfo import ZoneInfo
from tzlocal import get_localzone_name
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
from enum import Enum


class GroupRole(Enum):
    MEMBER = "member"
    MANAGER = "manager"
    ADMINISTRATOR = "administrator"


class InvitationStatus(Enum):
    PENDING = "pending"
    ACCEPTED = "accepted"
    EXPIRED = "expired"
    REVOKED = "revoked"
    FAILED = "failed"


class JoinRequestStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass
class Group:
    id: str
    name: str
    description: str = ""
    visibility: str = "private"  # "public" or "private"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    created_by: str = ""  # user ID who created the group
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        result = asdict(self)
        # Convert epoch timestamps to ISO format with timezone for API responses
        tz = ZoneInfo(get_localzone_name())
        result["created_at"] = datetime.fromtimestamp(self.created_at, tz=tz).isoformat()
        result["updated_at"] = datetime.fromtimestamp(self.updated_at, tz=tz).isoformat()
        return result

    @staticmethod
    def from_dict(data: dict) -> "Group":
        # Ensure timestamps are floats, not strings
        if isinstance(data.get("created_at"), str):
            # Parse ISO string back to timestamp
            try:
                dt = datetime.fromisoformat(data["created_at"].replace('Z', '+00:00'))
                data["created_at"] = dt.timestamp()
            except:
                # Fallback: use current time
                data["created_at"] = time.time()
        
        if isinstance(data.get("updated_at"), str):
            # Parse ISO string back to timestamp  
            try:
                dt = datetime.fromisoformat(data["updated_at"].replace('Z', '+00:00'))
                data["updated_at"] = dt.timestamp()
            except:
                # Fallback: use current time
                data["updated_at"] = time.time()
                
        return Group(**data)

    @staticmethod
    def generate_id() -> str:
        return str(uuid.uuid4())


@dataclass
class GroupMembership:
    group_id: str
    user_id: str  # subject from OIDC token
    user_email: str
    role: GroupRole
    joined_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    added_by: str = ""  # user ID who added this member
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        result = asdict(self)
        result["role"] = self.role.value
        # Convert epoch timestamps to ISO format with timezone for API responses
        tz = ZoneInfo(get_localzone_name())
        result["joined_at"] = datetime.fromtimestamp(self.joined_at, tz=tz).isoformat()
        result["updated_at"] = datetime.fromtimestamp(self.updated_at, tz=tz).isoformat()
        return result

    @staticmethod
    def from_dict(data: dict) -> "GroupMembership":
        data["role"] = GroupRole(data["role"])
        
        # Ensure timestamps are floats, not strings
        if isinstance(data.get("joined_at"), str):
            try:
                dt = datetime.fromisoformat(data["joined_at"].replace('Z', '+00:00'))
                data["joined_at"] = dt.timestamp()
            except:
                data["joined_at"] = time.time()
        
        if isinstance(data.get("updated_at"), str):
            try:
                dt = datetime.fromisoformat(data["updated_at"].replace('Z', '+00:00'))
                data["updated_at"] = dt.timestamp()
            except:
                data["updated_at"] = time.time()
                
        return GroupMembership(**data)


@dataclass
class GroupInvitation:
    id: str
    group_id: str
    group_name: str
    email: str
    role: GroupRole
    token: str  # unique invitation token
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + (7 * 24 * 3600))  # 7 days
    status: InvitationStatus = InvitationStatus.PENDING
    invited_by: str = ""  # user ID who sent the invitation
    accepted_at: Optional[float] = None
    accepted_by: Optional[str] = None  # user ID who accepted
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        result = asdict(self)
        result["role"] = self.role.value
        result["status"] = self.status.value
        # Convert epoch timestamps to ISO format with timezone for API responses
        tz = ZoneInfo(get_localzone_name())
        result["created_at"] = datetime.fromtimestamp(self.created_at, tz=tz).isoformat()
        result["expires_at"] = datetime.fromtimestamp(self.expires_at, tz=tz).isoformat()
        if self.accepted_at is not None:
            result["accepted_at"] = datetime.fromtimestamp(self.accepted_at, tz=tz).isoformat()
        return result

    @staticmethod
    def from_dict(data: dict) -> "GroupInvitation":
        data["role"] = GroupRole(data["role"])
        data["status"] = InvitationStatus(data["status"])
        
        # Ensure timestamps are floats, not strings
        if isinstance(data.get("created_at"), str):
            try:
                dt = datetime.fromisoformat(data["created_at"].replace('Z', '+00:00'))
                data["created_at"] = dt.timestamp()
            except:
                data["created_at"] = time.time()
        
        if isinstance(data.get("expires_at"), str):
            try:
                dt = datetime.fromisoformat(data["expires_at"].replace('Z', '+00:00'))
                data["expires_at"] = dt.timestamp()
            except:
                data["expires_at"] = time.time() + 86400  # Default 1 day
        
        if data.get("accepted_at") and isinstance(data.get("accepted_at"), str):
            try:
                dt = datetime.fromisoformat(data["accepted_at"].replace('Z', '+00:00'))
                data["accepted_at"] = dt.timestamp()
            except:
                data["accepted_at"] = None
                
        return GroupInvitation(**data)

    @staticmethod
    def generate_id() -> str:
        return str(uuid.uuid4())

    @staticmethod
    def generate_token() -> str:
        return str(uuid.uuid4().hex)

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def is_valid(self) -> bool:
        return (self.status == InvitationStatus.PENDING and 
                not self.is_expired())

@dataclass
class JoinRequest:
    id: str
    group_id: str
    group_name: str
    user_id: str  # subject from OIDC token
    user_email: str
    user_name: str  # display name
    message: str = ""  # optional message from user
    token: str = ""  # unique request token for tracking
    created_at: float = field(default_factory=time.time)
    expires_at: float = field(default_factory=lambda: time.time() + (30 * 24 * 3600))  # 30 days
    status: JoinRequestStatus = JoinRequestStatus.PENDING
    reviewed_at: Optional[float] = None
    reviewed_by: Optional[str] = None  # user ID who approved/denied
    reviewer_comment: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        result = asdict(self)
        result["status"] = self.status.value
        # Convert epoch timestamps to ISO format with timezone for API responses
        tz = ZoneInfo(get_localzone_name())
        result["created_at"] = datetime.fromtimestamp(self.created_at, tz=tz).isoformat()
        result["expires_at"] = datetime.fromtimestamp(self.expires_at, tz=tz).isoformat()
        if self.reviewed_at is not None:
            result["reviewed_at"] = datetime.fromtimestamp(self.reviewed_at, tz=tz).isoformat()
        return result

    @staticmethod
    def from_dict(data: dict) -> "JoinRequest":
        data["status"] = JoinRequestStatus(data["status"])

        # Ensure timestamps are floats, not strings
        if isinstance(data.get("created_at"), str):
            try:
                dt = datetime.fromisoformat(data["created_at"].replace('Z', '+00:00'))
                data["created_at"] = dt.timestamp()
            except:
                data["created_at"] = time.time()

        if isinstance(data.get("expires_at"), str):
            try:
                dt = datetime.fromisoformat(data["expires_at"].replace('Z', '+00:00'))
                data["expires_at"] = dt.timestamp()
            except:
                data["expires_at"] = time.time() + 86400  # Default 1 day

        if data.get("reviewed_at") and isinstance(data.get("reviewed_at"), str):
            try:
                dt = datetime.fromisoformat(data["reviewed_at"].replace('Z', '+00:00'))
                data["reviewed_at"] = dt.timestamp()
            except:
                data["reviewed_at"] = None

        return JoinRequest(**data)

    @staticmethod
    def generate_id() -> str:
        return str(uuid.uuid4())

    @staticmethod
    def generate_token() -> str:
        return str(uuid.uuid4().hex)

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def is_pending(self) -> bool:
        return self.status == JoinRequestStatus.PENDING and not self.is_expired()

    def can_be_reviewed(self) -> bool:
        return self.is_pending()