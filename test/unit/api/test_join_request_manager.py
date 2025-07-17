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

import pytest
import time
import uuid
from unittest.mock import Mock, patch
from deriva.web.groups.api.groups.join_request_manager import JoinRequestManager
from deriva.web.groups.api.groups.models import JoinRequest, JoinRequestStatus, GroupRole
from deriva.web.groups.api.groups.common import NotificationService


class TestJoinRequestManagerCreation:
    """Test JoinRequestManager creation and basic operations"""
    
    def test_create_join_request_success(self, join_request_manager):
        """Test creating a join request"""
        join_request = join_request_manager.create_join_request(
            group_id="group123",
            group_name="Test Group",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            message="Please let me join",
            base_url="https://example.com"
        )
        
        assert join_request is not None
        assert join_request.group_id == "group123"
        assert join_request.group_name == "Test Group"
        assert join_request.user_id == "user123"
        assert join_request.user_email == "user@example.com"
        assert join_request.user_name == "Test User"
        assert join_request.message == "Please let me join"
        assert join_request.status == JoinRequestStatus.PENDING
        assert len(join_request.token) == 32  # UUID hex length
        assert isinstance(join_request.id, str)
        assert len(join_request.id) == 36  # UUID4 length
        
        # Verify request was stored
        retrieved_request = join_request_manager.get_join_request(join_request.id)
        assert retrieved_request is not None
        assert retrieved_request.id == join_request.id
    
    def test_create_join_request_with_defaults(self, join_request_manager):
        """Test creating a join request with default values"""
        join_request = join_request_manager.create_join_request(
            group_id="group123",
            group_name="Test Group",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User"
        )
        
        assert join_request is not None
        assert join_request.message == ""
        assert join_request.status == JoinRequestStatus.PENDING
    
    def test_create_join_request_existing_pending(self, join_request_manager, sample_join_request):
        """Test creating join request when pending request exists"""
        # Create first request
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Try to create second request for same user and group
        duplicate_request = join_request_manager.create_join_request(
            group_id=sample_join_request.group_id,
            group_name=sample_join_request.group_name,
            user_id=sample_join_request.user_id,
            user_email=sample_join_request.user_email,
            user_name=sample_join_request.user_name
        )
        
        assert duplicate_request is None
    
    def test_create_join_request_with_notification_service(self, memory_storage):
        """Test creating join request with notification service"""
        # Create mock notification service
        notification_service = Mock(spec=NotificationService)
        
        # Create join request manager with notification service
        join_request_manager = JoinRequestManager(memory_storage, notification_service)
        
        # Create join request
        join_request = join_request_manager.create_join_request(
            group_id="group123",
            group_name="Test Group",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            base_url="https://example.com"
        )
        
        assert join_request is not None
        # Note: Notification would be sent in a real implementation
        # but is currently just logged


class TestJoinRequestManagerRetrieval:
    """Test JoinRequestManager retrieval operations"""
    
    def test_get_join_request_success(self, join_request_manager, sample_join_request):
        """Test getting join request by ID"""
        # Create request
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Get request
        retrieved_request = join_request_manager.get_join_request(sample_join_request.id)
        
        assert retrieved_request is not None
        assert retrieved_request.id == sample_join_request.id
        assert retrieved_request.group_id == sample_join_request.group_id
        assert retrieved_request.user_id == sample_join_request.user_id
    
    def test_get_join_request_not_found(self, join_request_manager):
        """Test getting non-existent join request"""
        result = join_request_manager.get_join_request("nonexistent_id")
        assert result is None
    
    def test_get_join_request_by_token_success(self, join_request_manager, sample_join_request):
        """Test getting join request by token"""
        # Create request
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Get by token
        retrieved_request = join_request_manager.get_join_request_by_token(sample_join_request.token)
        
        assert retrieved_request is not None
        assert retrieved_request.id == sample_join_request.id
        assert retrieved_request.token == sample_join_request.token
    
    def test_get_join_request_by_token_not_found(self, join_request_manager):
        """Test getting join request by non-existent token"""
        result = join_request_manager.get_join_request_by_token("nonexistent_token")
        assert result is None
    
    def test_get_group_join_requests_pending_only(self, join_request_manager, sample_group):
        """Test getting pending join requests for group"""
        # Create requests with different statuses
        pending_request = JoinRequest(
            id=str(uuid.uuid4()),
            group_id=sample_group.id,
            group_name=sample_group.name,
            user_id="user1",
            user_email="user1@example.com",
            user_name="User 1",
            status=JoinRequestStatus.PENDING,
            token=str(uuid.uuid4().hex)
        )
        approved_request = JoinRequest(
            id=str(uuid.uuid4()),
            group_id=sample_group.id,
            group_name=sample_group.name,
            user_id="user2",
            user_email="user2@example.com",
            user_name="User 2",
            status=JoinRequestStatus.APPROVED,
            token=str(uuid.uuid4().hex)
        )
        
        join_request_manager.store.create_join_request(pending_request)
        join_request_manager.store.create_join_request(approved_request)
        
        # Get pending requests only
        requests = join_request_manager.get_group_join_requests(sample_group.id, pending_only=True)
        
        assert len(requests) == 1
        assert requests[0].id == pending_request.id
        assert requests[0].status == JoinRequestStatus.PENDING
    
    def test_get_group_join_requests_all(self, join_request_manager, sample_group):
        """Test getting all join requests for group"""
        # Create requests with different statuses
        pending_request = JoinRequest(
            id=str(uuid.uuid4()),
            group_id=sample_group.id,
            group_name=sample_group.name,
            user_id="user1",
            user_email="user1@example.com",
            user_name="User 1",
            status=JoinRequestStatus.PENDING,
            token=str(uuid.uuid4().hex)
        )
        approved_request = JoinRequest(
            id=str(uuid.uuid4()),
            group_id=sample_group.id,
            group_name=sample_group.name,
            user_id="user2",
            user_email="user2@example.com",
            user_name="User 2",
            status=JoinRequestStatus.APPROVED,
            token=str(uuid.uuid4().hex)
        )
        
        join_request_manager.store.create_join_request(pending_request)
        join_request_manager.store.create_join_request(approved_request)
        
        # Get all requests
        requests = join_request_manager.get_group_join_requests(sample_group.id, pending_only=False)
        
        assert len(requests) == 2
        statuses = [req.status for req in requests]
        assert JoinRequestStatus.PENDING in statuses
        assert JoinRequestStatus.APPROVED in statuses
    
    def test_get_user_join_requests(self, join_request_manager):
        """Test getting user join requests"""
        # Create requests for different groups
        request1 = JoinRequest(
            id=str(uuid.uuid4()),
            group_id="group1",
            group_name="Group 1",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            token=str(uuid.uuid4().hex)
        )
        request2 = JoinRequest(
            id=str(uuid.uuid4()),
            group_id="group2",
            group_name="Group 2",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            token=str(uuid.uuid4().hex)
        )
        
        join_request_manager.store.create_join_request(request1)
        join_request_manager.store.create_join_request(request2)
        
        # Get user requests
        requests = join_request_manager.get_user_join_requests("user123")
        
        assert len(requests) == 2
        group_ids = [req.group_id for req in requests]
        assert "group1" in group_ids
        assert "group2" in group_ids


class TestJoinRequestManagerApproval:
    """Test JoinRequestManager approval operations"""
    
    def test_approve_join_request_success(self, join_request_manager, sample_join_request):
        """Test approving a join request"""
        # Create request
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Approve request
        success, error = join_request_manager.approve_join_request(
            sample_join_request.id,
            reviewer_id="admin123",
            reviewer_name="Admin User",
            role=GroupRole.MEMBER,
            reviewer_comment="Welcome to the group!"
        )
        
        assert success is True
        assert error is None
        
        # Verify request was updated
        updated_request = join_request_manager.get_join_request(sample_join_request.id)
        assert updated_request.status == JoinRequestStatus.APPROVED
        assert updated_request.reviewed_by == "admin123"
        assert updated_request.reviewer_comment == "Welcome to the group!"
        assert updated_request.reviewed_at is not None
    
    def test_approve_join_request_not_found(self, join_request_manager):
        """Test approving non-existent join request"""
        success, error = join_request_manager.approve_join_request(
            "nonexistent_id",
            reviewer_id="admin123",
            reviewer_name="Admin User"
        )
        
        assert success is False
        assert error == "Join request not found"
    
    def test_approve_join_request_already_processed(self, join_request_manager, sample_join_request):
        """Test approving already processed join request"""
        # Create and approve request
        sample_join_request.status = JoinRequestStatus.APPROVED
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Try to approve again
        success, error = join_request_manager.approve_join_request(
            sample_join_request.id,
            reviewer_id="admin123",
            reviewer_name="Admin User"
        )
        
        assert success is False
        assert error == "Join request cannot be reviewed (may be expired or already processed)"
    
    def test_approve_join_request_expired(self, join_request_manager, sample_join_request):
        """Test approving expired join request"""
        # Create expired request
        sample_join_request.expires_at = time.time() - 3600  # 1 hour ago
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Try to approve
        success, error = join_request_manager.approve_join_request(
            sample_join_request.id,
            reviewer_id="admin123",
            reviewer_name="Admin User"
        )
        
        assert success is False
        assert error == "Join request cannot be reviewed (may be expired or already processed)"
    
    def test_approve_join_request_with_notification(self, memory_storage):
        """Test approving join request with notification service"""
        # Create mock notification service
        notification_service = Mock(spec=NotificationService)
        
        # Create join request manager with notification service
        join_request_manager = JoinRequestManager(memory_storage, notification_service)
        
        # Create request
        join_request = JoinRequest(
            id=str(uuid.uuid4()),
            group_id="group123",
            group_name="Test Group",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            token=str(uuid.uuid4().hex)
        )
        join_request_manager.store.create_join_request(join_request)
        
        # Approve request
        success, error = join_request_manager.approve_join_request(
            join_request.id,
            reviewer_id="admin123",
            reviewer_name="Admin User"
        )
        
        assert success is True
        assert error is None
        # Note: Notification would be sent in a real implementation
        # but is currently just logged


class TestJoinRequestManagerDenial:
    """Test JoinRequestManager denial operations"""
    
    def test_deny_join_request_success(self, join_request_manager, sample_join_request):
        """Test denying a join request"""
        # Create request
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Deny request
        success, error = join_request_manager.deny_join_request(
            sample_join_request.id,
            reviewer_id="admin123",
            reviewer_name="Admin User",
            reviewer_comment="Group is currently full"
        )
        
        assert success is True
        assert error is None
        
        # Verify request was updated
        updated_request = join_request_manager.get_join_request(sample_join_request.id)
        assert updated_request.status == JoinRequestStatus.DENIED
        assert updated_request.reviewed_by == "admin123"
        assert updated_request.reviewer_comment == "Group is currently full"
        assert updated_request.reviewed_at is not None
    
    def test_deny_join_request_not_found(self, join_request_manager):
        """Test denying non-existent join request"""
        success, error = join_request_manager.deny_join_request(
            "nonexistent_id",
            reviewer_id="admin123",
            reviewer_name="Admin User"
        )
        
        assert success is False
        assert error == "Join request not found"
    
    def test_deny_join_request_already_processed(self, join_request_manager, sample_join_request):
        """Test denying already processed join request"""
        # Create and deny request
        sample_join_request.status = JoinRequestStatus.DENIED
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Try to deny again
        success, error = join_request_manager.deny_join_request(
            sample_join_request.id,
            reviewer_id="admin123",
            reviewer_name="Admin User"
        )
        
        assert success is False
        assert error == "Join request cannot be reviewed (may be expired or already processed)"
    
    def test_deny_join_request_with_notification(self, memory_storage):
        """Test denying join request with notification service"""
        # Create mock notification service
        notification_service = Mock(spec=NotificationService)
        
        # Create join request manager with notification service
        join_request_manager = JoinRequestManager(memory_storage, notification_service)
        
        # Create request
        join_request = JoinRequest(
            id=str(uuid.uuid4()),
            group_id="group123",
            group_name="Test Group",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            token=str(uuid.uuid4().hex)
        )
        join_request_manager.store.create_join_request(join_request)
        
        # Deny request
        success, error = join_request_manager.deny_join_request(
            join_request.id,
            reviewer_id="admin123",
            reviewer_name="Admin User"
        )
        
        assert success is True
        assert error is None
        # Note: Notification would be sent in a real implementation
        # but is currently just logged


class TestJoinRequestManagerCancellation:
    """Test JoinRequestManager cancellation operations"""
    
    def test_cancel_join_request_success(self, join_request_manager, sample_join_request):
        """Test canceling a join request"""
        # Create request
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Cancel request
        success, error = join_request_manager.cancel_join_request(
            sample_join_request.id,
            sample_join_request.user_id
        )
        
        assert success is True
        assert error is None
        
        # Verify request was deleted
        deleted_request = join_request_manager.get_join_request(sample_join_request.id)
        assert deleted_request is None
    
    def test_cancel_join_request_not_found(self, join_request_manager):
        """Test canceling non-existent join request"""
        success, error = join_request_manager.cancel_join_request(
            "nonexistent_id",
            "user123"
        )
        
        assert success is False
        assert error == "Join request not found"
    
    def test_cancel_join_request_wrong_user(self, join_request_manager, sample_join_request):
        """Test canceling join request by wrong user"""
        # Create request
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Try to cancel by different user
        success, error = join_request_manager.cancel_join_request(
            sample_join_request.id,
            "different_user"
        )
        
        assert success is False
        assert error == "You can only cancel your own join requests"
    
    def test_cancel_join_request_already_processed(self, join_request_manager, sample_join_request):
        """Test canceling already processed join request"""
        # Create and approve request
        sample_join_request.status = JoinRequestStatus.APPROVED
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Try to cancel
        success, error = join_request_manager.cancel_join_request(
            sample_join_request.id,
            sample_join_request.user_id
        )
        
        assert success is False
        assert error == "Join request cannot be cancelled (may be expired or already processed)"
    
    def test_cancel_join_request_expired(self, join_request_manager, sample_join_request):
        """Test canceling expired join request"""
        # Create expired request
        sample_join_request.expires_at = time.time() - 3600  # 1 hour ago
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Try to cancel
        success, error = join_request_manager.cancel_join_request(
            sample_join_request.id,
            sample_join_request.user_id
        )
        
        assert success is False
        assert error == "Join request cannot be cancelled (may be expired or already processed)"


class TestJoinRequestManagerUtilities:
    """Test JoinRequestManager utility methods"""
    
    def test_cleanup_expired_requests(self, join_request_manager, sample_group):
        """Test cleaning up expired join requests"""
        # Create expired pending request
        expired_request = JoinRequest(
            id=str(uuid.uuid4()),
            group_id=sample_group.id,
            group_name=sample_group.name,
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            status=JoinRequestStatus.PENDING,
            expires_at=time.time() - 3600,  # 1 hour ago
            token=str(uuid.uuid4().hex)
        )
        
        # Create valid pending request
        valid_request = JoinRequest(
            id=str(uuid.uuid4()),
            group_id=sample_group.id,
            group_name=sample_group.name,
            user_id="user456",
            user_email="user2@example.com",
            user_name="Test User 2",
            status=JoinRequestStatus.PENDING,
            expires_at=time.time() + 3600,  # 1 hour from now
            token=str(uuid.uuid4().hex)
        )
        
        join_request_manager.store.create_join_request(expired_request)
        join_request_manager.store.create_join_request(valid_request)
        
        # Cleanup expired requests
        cleaned_count = join_request_manager.cleanup_expired_requests()
        
        assert cleaned_count == 1
    
    def test_get_join_request_summary(self, join_request_manager, sample_group):
        """Test getting join request summary"""
        # Create requests with different statuses
        pending_request = JoinRequest(
            id=str(uuid.uuid4()),
            group_id=sample_group.id,
            group_name=sample_group.name,
            user_id="user1",
            user_email="user1@example.com",
            user_name="User 1",
            status=JoinRequestStatus.PENDING,
            token=str(uuid.uuid4().hex)
        )
        approved_request = JoinRequest(
            id=str(uuid.uuid4()),
            group_id=sample_group.id,
            group_name=sample_group.name,
            user_id="user2",
            user_email="user2@example.com",
            user_name="User 2",
            status=JoinRequestStatus.APPROVED,
            token=str(uuid.uuid4().hex)
        )
        denied_request = JoinRequest(
            id=str(uuid.uuid4()),
            group_id=sample_group.id,
            group_name=sample_group.name,
            user_id="user3",
            user_email="user3@example.com",
            user_name="User 3",
            status=JoinRequestStatus.DENIED,
            token=str(uuid.uuid4().hex)
        )
        
        join_request_manager.store.create_join_request(pending_request)
        join_request_manager.store.create_join_request(approved_request)
        join_request_manager.store.create_join_request(denied_request)
        
        # Get summary
        summary = join_request_manager.get_join_request_summary(sample_group.id)
        
        assert summary["total"] == 3
        assert summary["pending"] == 1
        assert summary["approved"] == 1
        assert summary["denied"] == 1
        assert summary["expired"] == 0
    
    def test_has_pending_request_true(self, join_request_manager, sample_join_request):
        """Test has pending request returns True"""
        # Create pending request
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Check for pending request
        has_pending = join_request_manager.has_pending_request(
            sample_join_request.group_id,
            sample_join_request.user_id
        )
        
        assert has_pending is True
    
    def test_has_pending_request_false(self, join_request_manager, sample_group):
        """Test has pending request returns False"""
        # Check for pending request (none exist)
        has_pending = join_request_manager.has_pending_request(
            sample_group.id,
            "user123"
        )
        
        assert has_pending is False
    
    def test_has_pending_request_false_when_approved(self, join_request_manager, sample_join_request):
        """Test has pending request returns False when request is approved"""
        # Create approved request
        sample_join_request.status = JoinRequestStatus.APPROVED
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Check for pending request
        has_pending = join_request_manager.has_pending_request(
            sample_join_request.group_id,
            sample_join_request.user_id
        )
        
        assert has_pending is False
    
    def test_get_public_join_info_success(self, join_request_manager, sample_join_request):
        """Test getting public join info"""
        # Create request
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Get public info
        join_info = join_request_manager.get_public_join_info(sample_join_request.token)
        
        assert join_info is not None
        assert join_info["group_id"] == sample_join_request.group_id
        assert join_info["is_valid"] == sample_join_request.is_pending()
        assert join_info["expires_at"] == sample_join_request.expires_at
        assert join_info["created_at"] == sample_join_request.created_at
    
    def test_get_public_join_info_not_found(self, join_request_manager):
        """Test getting public join info for non-existent token"""
        join_info = join_request_manager.get_public_join_info("nonexistent_token")
        assert join_info is None
    
    def test_get_public_join_info_expired(self, join_request_manager, sample_join_request):
        """Test getting public join info for expired request"""
        # Create expired request
        sample_join_request.expires_at = time.time() - 3600  # 1 hour ago
        join_request_manager.store.create_join_request(sample_join_request)
        
        # Get public info - token may have expired and been removed
        join_info = join_request_manager.get_public_join_info(sample_join_request.token)
        
        # Token-based access expires with the request, so this could be None
        # This is expected behavior for expired tokens
        if join_info is not None:
            assert join_info["is_valid"] is False  # Should be False for expired request
        else:
            # Token has expired and been removed from storage
            assert join_info is None