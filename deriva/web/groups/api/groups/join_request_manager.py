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

import logging
import time
from typing import List, Optional, Tuple
from .models import GroupRole, JoinRequest, JoinRequestStatus
from .common import NotificationService
from ..storage.core import Storage


logger = logging.getLogger(__name__)


class JoinRequestManager:
    def __init__(self, store: Storage, notification_service: Optional[NotificationService] = None):
        self.store = store
        self.notification_service = notification_service

    def create_join_request(self, group_id: str, group_name, user_id: str, user_email: str,
                          user_name: str, message: str = "", base_url: str = "") -> Optional[JoinRequest]:
        """Create a new join request"""
        # Check if user already has a pending request for this group
        if self.store.has_pending_join_request(group_id, user_id):
            logger.warning(f"User {user_id} already has a pending join request for group {group_id}")
            return None
        
        join_request = JoinRequest(
            id=JoinRequest.generate_id(),
            group_id=group_id,
            group_name=group_name,
            user_id=user_id,
            user_email=user_email,
            user_name=user_name,
            message=message.strip(),
            token=JoinRequest.generate_token()
        )
        
        self.store.create_join_request(join_request)
        
        # Send notification to group admins/managers
        if self.notification_service and base_url:
            try:
                # TODO: We need to get the group and admin emails
                # This would require integration with the GroupManager
                logger.info(f"Join request notification would be sent for request {join_request.id}")
            except Exception as e:
                logger.error(f"Failed to send join request notification: {e}")
        
        return join_request

    def get_join_request(self, request_id: str) -> Optional[JoinRequest]:
        """Get a join request by ID"""
        return self.store.get_join_request(request_id)

    def get_join_request_by_token(self, token: str) -> Optional[JoinRequest]:
        """Get a join request by token"""
        return self.store.get_join_request_by_token(token)

    def get_group_join_requests(self, group_id: str, pending_only: bool = True) -> List[JoinRequest]:
        """Get join requests for a group"""
        if pending_only:
            return self.store.get_pending_join_requests_for_group(group_id)
        else:
            return self.store.get_group_join_requests(group_id)

    def get_user_join_requests(self, user_id: str) -> List[JoinRequest]:
        """Get all join requests for a user"""
        return self.store.get_user_join_requests(user_id)

    def approve_join_request(self, request_id: str, reviewer_id: str, reviewer_name: str, 
                           role: GroupRole = GroupRole.MEMBER, reviewer_comment: str = "") -> Tuple[bool, Optional[str]]:
        """Approve a join request"""
        join_request = self.store.get_join_request(request_id)
        if not join_request:
            return False, "Join request not found"
        
        if not join_request.can_be_reviewed():
            return False, "Join request cannot be reviewed (may be expired or already processed)"
        
        # Update join request status
        join_request.status = JoinRequestStatus.APPROVED
        join_request.reviewed_at = time.time()
        join_request.reviewed_by = reviewer_id
        join_request.reviewer_comment = reviewer_comment.strip()
        
        self.store.update_join_request(join_request)
        
        # Send approval notification to user
        if self.notification_service:
            try:
                # TODO: Need group information for the email
                logger.info(f"Approval notification would be sent to {join_request.user_email}")
            except Exception as e:
                logger.error(f"Failed to send approval notification: {e}")
        
        logger.info(f"Join request {request_id} approved by {reviewer_id}")
        return True, None

    def deny_join_request(self, request_id: str, reviewer_id: str, reviewer_name: str, 
                         reviewer_comment: str = "") -> Tuple[bool, Optional[str]]:
        """Deny a join request"""
        join_request = self.store.get_join_request(request_id)
        if not join_request:
            return False, "Join request not found"
        
        if not join_request.can_be_reviewed():
            return False, "Join request cannot be reviewed (may be expired or already processed)"
        
        # Update join request status
        join_request.status = JoinRequestStatus.DENIED
        join_request.reviewed_at = time.time()
        join_request.reviewed_by = reviewer_id
        join_request.reviewer_comment = reviewer_comment.strip()
        
        self.store.update_join_request(join_request)
        
        # Send denial notification to user
        if self.notification_service:
            try:
                # TODO: Need group information for the email
                logger.info(f"Denial notification would be sent to {join_request.user_email}")
            except Exception as e:
                logger.error(f"Failed to send denial notification: {e}")
        
        logger.info(f"Join request {request_id} denied by {reviewer_id}")
        return True, None

    def cancel_join_request(self, request_id: str, user_id: str) -> Tuple[bool, Optional[str]]:
        """Cancel a join request (by the user who created it)"""
        join_request = self.store.get_join_request(request_id)
        if not join_request:
            return False, "Join request not found"
        
        if join_request.user_id != user_id:
            return False, "You can only cancel your own join requests"
        
        if not join_request.is_pending():
            return False, "Join request cannot be cancelled (may be expired or already processed)"
        
        # Delete the join request
        self.store.delete_join_request(request_id)
        
        logger.info(f"Join request {request_id} cancelled by user {user_id}")
        return True, None

    def cleanup_expired_requests(self) -> int:
        """Clean up expired join requests"""
        return self.store.cleanup_expired_requests()

    def get_join_request_summary(self, group_id: str) -> dict:
        """Get a summary of join requests for a group"""
        all_requests = self.store.get_group_join_requests(group_id)
        
        summary = {
            "total": len(all_requests),
            "pending": 0,
            "approved": 0,
            "denied": 0,
            "expired": 0
        }
        
        for request in all_requests:
            if request.is_expired() and request.status == JoinRequestStatus.PENDING:
                summary["expired"] += 1
            else:
                summary[request.status.value] += 1
        
        return summary

    def has_pending_request(self, group_id: str, user_id: str) -> bool:
        """Check if user has a pending join request for a group"""
        return self.store.has_pending_join_request(group_id, user_id)

    def get_public_join_info(self, token: str) -> Optional[dict]:
        """Get public information about a join request (for join pages)"""
        join_request = self.store.get_join_request_by_token(token)
        if not join_request:
            return None
        
        return {
            "group_id": join_request.group_id,
            "is_valid": join_request.is_pending(),
            "expires_at": join_request.expires_at,
            "created_at": join_request.created_at
        }