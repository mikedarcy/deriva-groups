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

"""
Common utilities and logic shared between invitations and join requests
"""

import logging
import time
from typing import Dict, Any, Optional
from .models import GroupRole
from .email_service import EmailService

logger = logging.getLogger(__name__)


class NotificationService:
    """Handles email notifications for both invitations and join requests"""
    
    def __init__(self, email_service: Optional[EmailService] = None):
        self.email_service = email_service

    def send_invitation_email(self, invitation, group, base_url: str, invited_by_name: str = "Administrator") -> bool:
        """Send invitation email to join a group"""
        if not self.email_service:
            logger.warning("Email service not configured - invitation email not sent")
            return False
            
        return self.email_service.send_invitation_email(invitation, group, base_url, invited_by_name)

    def send_join_request_notification(self, join_request, group, requester_name: str, base_url: str) -> bool:
        """Send notification to group admins/managers about new join request"""
        if not self.email_service:
            logger.warning("Email service not configured - join request notification not sent")
            return False
            
        return self.email_service.send_join_request_notification(join_request, group, requester_name, base_url)

    def send_join_request_decision_email(self, join_request, group, decision: str, reviewer_name: str, reviewer_comment: str = "") -> bool:
        """Send email to user about join request decision"""
        if not self.email_service:
            logger.warning("Email service not configured - decision email not sent")
            return False
            
        return self.email_service.send_join_request_decision_email(join_request, group, decision, reviewer_name, reviewer_comment)


class MembershipService:
    """Handles common membership operations for both invitations and join requests"""
    
    @staticmethod
    def create_membership_from_approval(group_id: str, user_id: str, user_email: str, 
                                      role: GroupRole, added_by: str, source_type: str, 
                                      source_id: str) -> Dict[str, Any]:
        """Create membership data structure from approved invitation or join request"""
        return {
            "group_id": group_id,
            "user_id": user_id,
            "user_email": user_email,
            "role": role,
            "added_by": added_by,
            "metadata": {
                "source_type": source_type,  # "invitation" or "join_request"
                "source_id": source_id,
                "approved_at": time.time()
            }
        }

    @staticmethod
    def validate_role_assignment(assigner_role: GroupRole, target_role: GroupRole) -> bool:
        """Validate if the assigner can assign the target role"""
        role_hierarchy = {
            GroupRole.MEMBER: 1,
            GroupRole.MANAGER: 2,
            GroupRole.ADMINISTRATOR: 3
        }
        
        assigner_level = role_hierarchy.get(assigner_role, 0)
        target_level = role_hierarchy.get(target_role, 0)
        
        # Only administrators can assign administrator roles
        if target_role == GroupRole.ADMINISTRATOR:
            return assigner_role == GroupRole.ADMINISTRATOR
            
        # Managers and administrators can assign member and manager roles
        return assigner_level >= 2


class TokenService:
    """Handles token generation and validation for both invitations and join requests"""
    
    @staticmethod
    def generate_secure_token() -> str:
        """Generate a secure token for invitations and join requests"""
        import uuid
        return str(uuid.uuid4().hex)

    @staticmethod
    def is_token_expired(expires_at: float) -> bool:
        """Check if a token has expired"""
        return time.time() > expires_at

    @staticmethod
    def get_expiry_date(days: int = 7) -> float:
        """Get expiry timestamp for given number of days"""
        return time.time() + (days * 24 * 3600)


class WorkflowStatus:
    """Common status tracking for invitations and join requests"""
    
    # Shared status types
    PENDING = "pending"
    APPROVED = "approved"
    ACCEPTED = "accepted"  # For invitations
    DENIED = "denied"
    EXPIRED = "expired"
    REVOKED = "revoked"  # For invitations
    
    @staticmethod
    def can_transition(current_status: str, new_status: str) -> bool:
        """Check if status transition is valid"""
        valid_transitions = {
            WorkflowStatus.PENDING: [WorkflowStatus.APPROVED, WorkflowStatus.ACCEPTED, 
                                   WorkflowStatus.DENIED, WorkflowStatus.EXPIRED, WorkflowStatus.REVOKED],
            WorkflowStatus.APPROVED: [WorkflowStatus.EXPIRED],
            WorkflowStatus.ACCEPTED: [],
            WorkflowStatus.DENIED: [],
            WorkflowStatus.EXPIRED: [],
            WorkflowStatus.REVOKED: []
        }
        
        return new_status in valid_transitions.get(current_status, [])


class PermissionService:
    """Common permission checking for group operations"""
    
    @staticmethod
    def can_manage_group(user_role: Optional[GroupRole]) -> bool:
        """Check if user can manage group (invite, approve requests, etc.)"""
        if not user_role:
            return False
        return user_role in [GroupRole.ADMINISTRATOR, GroupRole.MANAGER]

    @staticmethod
    def can_admin_group(user_role: Optional[GroupRole]) -> bool:
        """Check if user can admin group (edit, delete, etc.)"""
        if not user_role:
            return False
        return user_role == GroupRole.ADMINISTRATOR

    @staticmethod
    def get_role_level(role: GroupRole) -> int:
        """Get numeric level for role comparison"""
        role_levels = {
            GroupRole.MEMBER: 1,
            GroupRole.MANAGER: 2,
            GroupRole.ADMINISTRATOR: 3
        }
        return role_levels.get(role, 0)