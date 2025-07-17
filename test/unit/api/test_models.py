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
from datetime import datetime
from deriva.web.groups.api.groups.models import (
    Group, GroupMembership, GroupInvitation, JoinRequest,
    GroupRole, InvitationStatus, JoinRequestStatus
)


class TestGroup:
    """Test Group model"""
    
    def test_create_group_with_defaults(self):
        """Test creating a group with default values"""
        group = Group(
            id="test-id",
            name="Test Group"
        )
        
        assert group.id == "test-id"
        assert group.name == "Test Group"
        assert group.description == ""
        assert group.visibility == "private"
        assert group.created_by == ""
        assert group.metadata == {}
        assert isinstance(group.created_at, float)
        assert isinstance(group.updated_at, float)
    
    def test_create_group_with_all_fields(self):
        """Test creating a group with all fields specified"""
        metadata = {"department": "IT", "budget": 50000}
        
        group = Group(
            id="test-id",
            name="Test Group",
            description="A test group",
            visibility="public",
            created_by="user123",
            metadata=metadata
        )
        
        assert group.id == "test-id"
        assert group.name == "Test Group"
        assert group.description == "A test group"
        assert group.visibility == "public"
        assert group.created_by == "user123"
        assert group.metadata == metadata
    
    def test_group_to_dict(self):
        """Test converting group to dictionary"""
        group = Group(
            id="test-id",
            name="Test Group",
            description="A test group",
            visibility="public",
            created_by="user123",
            metadata={"key": "value"}
        )
        
        result = group.to_dict()
        
        assert result["id"] == "test-id"
        assert result["name"] == "Test Group"
        assert result["description"] == "A test group"
        assert result["visibility"] == "public"
        assert result["created_by"] == "user123"
        assert result["metadata"] == {"key": "value"}
        # Timestamps should be converted to ISO format
        assert isinstance(result["created_at"], str)
        assert isinstance(result["updated_at"], str)
    
    def test_group_from_dict(self):
        """Test creating group from dictionary"""
        data = {
            "id": "test-id",
            "name": "Test Group",
            "description": "A test group",
            "visibility": "public",
            "created_by": "user123",
            "metadata": {"key": "value"},
            "created_at": time.time(),
            "updated_at": time.time()
        }
        
        group = Group.from_dict(data)
        
        assert group.id == "test-id"
        assert group.name == "Test Group"
        assert group.description == "A test group"
        assert group.visibility == "public"
        assert group.created_by == "user123"
        assert group.metadata == {"key": "value"}
        assert isinstance(group.created_at, float)
        assert isinstance(group.updated_at, float)
    
    def test_group_from_dict_with_iso_timestamps(self):
        """Test creating group from dictionary with ISO timestamp strings"""
        data = {
            "id": "test-id",
            "name": "Test Group",
            "created_at": "2025-01-01T10:00:00+00:00",
            "updated_at": "2025-01-01T10:00:00+00:00"
        }
        
        group = Group.from_dict(data)
        
        assert group.id == "test-id"
        assert group.name == "Test Group"
        assert isinstance(group.created_at, float)
        assert isinstance(group.updated_at, float)
    
    def test_group_generate_id(self):
        """Test generating unique group IDs"""
        id1 = Group.generate_id()
        id2 = Group.generate_id()
        
        assert id1 != id2
        assert len(id1) == 36  # UUID4 length
        assert len(id2) == 36


class TestGroupMembership:
    """Test GroupMembership model"""
    
    def test_create_membership_with_defaults(self):
        """Test creating membership with default values"""
        membership = GroupMembership(
            group_id="group123",
            user_id="user123",
            user_email="user@example.com",
            role=GroupRole.MEMBER
        )
        
        assert membership.group_id == "group123"
        assert membership.user_id == "user123"
        assert membership.user_email == "user@example.com"
        assert membership.role == GroupRole.MEMBER
        assert membership.added_by == ""
        assert membership.metadata == {}
        assert isinstance(membership.joined_at, float)
        assert isinstance(membership.updated_at, float)
    
    def test_create_membership_with_all_fields(self):
        """Test creating membership with all fields"""
        metadata = {"source": "invitation", "invitation_id": "inv123"}
        
        membership = GroupMembership(
            group_id="group123",
            user_id="user123",
            user_email="user@example.com",
            role=GroupRole.ADMINISTRATOR,
            added_by="admin123",
            metadata=metadata
        )
        
        assert membership.group_id == "group123"
        assert membership.user_id == "user123"
        assert membership.user_email == "user@example.com"
        assert membership.role == GroupRole.ADMINISTRATOR
        assert membership.added_by == "admin123"
        assert membership.metadata == metadata
    
    def test_membership_to_dict(self):
        """Test converting membership to dictionary"""
        membership = GroupMembership(
            group_id="group123",
            user_id="user123",
            user_email="user@example.com",
            role=GroupRole.MANAGER,
            added_by="admin123",
            metadata={"key": "value"}
        )
        
        result = membership.to_dict()
        
        assert result["group_id"] == "group123"
        assert result["user_id"] == "user123"
        assert result["user_email"] == "user@example.com"
        assert result["role"] == "manager"  # Enum value
        assert result["added_by"] == "admin123"
        assert result["metadata"] == {"key": "value"}
        assert isinstance(result["joined_at"], str)
        assert isinstance(result["updated_at"], str)
    
    def test_membership_from_dict(self):
        """Test creating membership from dictionary"""
        data = {
            "group_id": "group123",
            "user_id": "user123",
            "user_email": "user@example.com",
            "role": "administrator",
            "added_by": "admin123",
            "metadata": {"key": "value"},
            "joined_at": time.time(),
            "updated_at": time.time()
        }
        
        membership = GroupMembership.from_dict(data)
        
        assert membership.group_id == "group123"
        assert membership.user_id == "user123"
        assert membership.user_email == "user@example.com"
        assert membership.role == GroupRole.ADMINISTRATOR
        assert membership.added_by == "admin123"
        assert membership.metadata == {"key": "value"}
        assert isinstance(membership.joined_at, float)
        assert isinstance(membership.updated_at, float)


class TestGroupInvitation:
    """Test GroupInvitation model"""
    
    def test_create_invitation_with_defaults(self):
        """Test creating invitation with default values"""
        invitation = GroupInvitation(
            id="inv123",
            group_id="group123",
            group_name="Test Group",
            email="user@example.com",
            role=GroupRole.MEMBER,
            token="token123"
        )
        
        assert invitation.id == "inv123"
        assert invitation.group_id == "group123"
        assert invitation.group_name == "Test Group"
        assert invitation.email == "user@example.com"
        assert invitation.role == GroupRole.MEMBER
        assert invitation.token == "token123"
        assert invitation.status == InvitationStatus.PENDING
        assert invitation.invited_by == ""
        assert invitation.accepted_at is None
        assert invitation.accepted_by is None
        assert invitation.metadata == {}
        assert isinstance(invitation.created_at, float)
        assert isinstance(invitation.expires_at, float)
        # Expires at should be set to a future time (default is 7 days)
        assert invitation.expires_at != invitation.created_at
    
    def test_create_invitation_with_all_fields(self):
        """Test creating invitation with all fields"""
        metadata = {"source": "api", "referrer": "admin"}
        
        invitation = GroupInvitation(
            id="inv123",
            group_id="group123",
            group_name="Test Group",
            email="user@example.com",
            role=GroupRole.ADMINISTRATOR,
            token="token123",
            status=InvitationStatus.ACCEPTED,
            invited_by="admin123",
            accepted_by="user123",
            metadata=metadata
        )
        
        assert invitation.id == "inv123"
        assert invitation.group_id == "group123"
        assert invitation.group_name == "Test Group"
        assert invitation.email == "user@example.com"
        assert invitation.role == GroupRole.ADMINISTRATOR
        assert invitation.token == "token123"
        assert invitation.status == InvitationStatus.ACCEPTED
        assert invitation.invited_by == "admin123"
        assert invitation.accepted_by == "user123"
        assert invitation.metadata == metadata
    
    def test_invitation_to_dict(self):
        """Test converting invitation to dictionary"""
        invitation = GroupInvitation(
            id="inv123",
            group_id="group123",
            group_name="Test Group",
            email="user@example.com",
            role=GroupRole.MANAGER,
            token="token123",
            status=InvitationStatus.ACCEPTED,
            invited_by="admin123",
            accepted_by="user123",
            metadata={"key": "value"}
        )
        
        result = invitation.to_dict()
        
        assert result["id"] == "inv123"
        assert result["group_id"] == "group123"
        assert result["group_name"] == "Test Group"
        assert result["email"] == "user@example.com"
        assert result["role"] == "manager"  # Enum value
        assert result["token"] == "token123"
        assert result["status"] == "accepted"  # Enum value
        assert result["invited_by"] == "admin123"
        assert result["accepted_by"] == "user123"
        assert result["metadata"] == {"key": "value"}
        assert isinstance(result["created_at"], str)
        assert isinstance(result["expires_at"], str)
    
    def test_invitation_from_dict(self):
        """Test creating invitation from dictionary"""
        data = {
            "id": "inv123",
            "group_id": "group123",
            "group_name": "Test Group",
            "email": "user@example.com",
            "role": "administrator",
            "token": "token123",
            "status": "pending",
            "invited_by": "admin123",
            "metadata": {"key": "value"},
            "created_at": time.time(),
            "expires_at": time.time() + 3600
        }
        
        invitation = GroupInvitation.from_dict(data)
        
        assert invitation.id == "inv123"
        assert invitation.group_id == "group123"
        assert invitation.group_name == "Test Group"
        assert invitation.email == "user@example.com"
        assert invitation.role == GroupRole.ADMINISTRATOR
        assert invitation.token == "token123"
        assert invitation.status == InvitationStatus.PENDING
        assert invitation.invited_by == "admin123"
        assert invitation.metadata == {"key": "value"}
        assert isinstance(invitation.created_at, float)
        assert isinstance(invitation.expires_at, float)
    
    def test_invitation_generate_id(self):
        """Test generating unique invitation IDs"""
        id1 = GroupInvitation.generate_id()
        id2 = GroupInvitation.generate_id()
        
        assert id1 != id2
        assert len(id1) == 36  # UUID4 length
    
    def test_invitation_generate_token(self):
        """Test generating unique invitation tokens"""
        token1 = GroupInvitation.generate_token()
        token2 = GroupInvitation.generate_token()
        
        assert token1 != token2
        assert len(token1) == 32  # UUID4 hex length
    
    def test_invitation_is_expired(self):
        """Test invitation expiration check"""
        # Create expired invitation
        expired_invitation = GroupInvitation(
            id="inv123",
            group_id="group123",
            group_name="Test Group",
            email="user@example.com",
            role=GroupRole.MEMBER,
            token="token123",
            expires_at=time.time() - 3600  # 1 hour ago
        )
        
        # Create valid invitation
        valid_invitation = GroupInvitation(
            id="inv124",
            group_id="group123",
            group_name="Test Group",
            email="user@example.com",
            role=GroupRole.MEMBER,
            token="token124",
            expires_at=time.time() + 3600  # 1 hour from now
        )
        
        assert expired_invitation.is_expired() is True
        assert valid_invitation.is_expired() is False
    
    def test_invitation_is_valid(self):
        """Test invitation validity check"""
        # Create valid pending invitation
        valid_invitation = GroupInvitation(
            id="inv123",
            group_id="group123",
            group_name="Test Group",
            email="user@example.com",
            role=GroupRole.MEMBER,
            token="token123",
            status=InvitationStatus.PENDING,
            expires_at=time.time() + 3600  # 1 hour from now
        )
        
        # Create expired invitation
        expired_invitation = GroupInvitation(
            id="inv124",
            group_id="group123",
            group_name="Test Group",
            email="user@example.com",
            role=GroupRole.MEMBER,
            token="token124",
            status=InvitationStatus.PENDING,
            expires_at=time.time() - 3600  # 1 hour ago
        )
        
        # Create accepted invitation
        accepted_invitation = GroupInvitation(
            id="inv125",
            group_id="group123",
            group_name="Test Group",
            email="user@example.com",
            role=GroupRole.MEMBER,
            token="token125",
            status=InvitationStatus.ACCEPTED,
            expires_at=time.time() + 3600  # 1 hour from now
        )
        
        assert valid_invitation.is_valid() is True
        assert expired_invitation.is_valid() is False
        assert accepted_invitation.is_valid() is False


class TestJoinRequest:
    """Test JoinRequest model"""
    
    def test_create_join_request_with_defaults(self):
        """Test creating join request with default values"""
        join_request = JoinRequest(
            id="req123",
            group_id="group123",
            group_name="Test Group",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User"
        )
        
        assert join_request.id == "req123"
        assert join_request.group_id == "group123"
        assert join_request.group_name == "Test Group"
        assert join_request.user_id == "user123"
        assert join_request.user_email == "user@example.com"
        assert join_request.user_name == "Test User"
        assert join_request.message == ""
        assert join_request.token == ""
        assert join_request.status == JoinRequestStatus.PENDING
        assert join_request.reviewed_at is None
        assert join_request.reviewed_by is None
        assert join_request.reviewer_comment == ""
        assert join_request.metadata == {}
        assert isinstance(join_request.created_at, float)
        assert isinstance(join_request.expires_at, float)
        # Expires at should be set to a future time (default is 30 days)
        assert join_request.expires_at != join_request.created_at
    
    def test_create_join_request_with_all_fields(self):
        """Test creating join request with all fields"""
        metadata = {"source": "web", "referrer": "google"}
        
        join_request = JoinRequest(
            id="req123",
            group_id="group123",
            group_name="Test Group",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            message="Please let me join",
            token="token123",
            status=JoinRequestStatus.APPROVED,
            reviewed_by="admin123",
            reviewer_comment="Welcome!",
            metadata=metadata
        )
        
        assert join_request.id == "req123"
        assert join_request.group_id == "group123"
        assert join_request.group_name == "Test Group"
        assert join_request.user_id == "user123"
        assert join_request.user_email == "user@example.com"
        assert join_request.user_name == "Test User"
        assert join_request.message == "Please let me join"
        assert join_request.token == "token123"
        assert join_request.status == JoinRequestStatus.APPROVED
        assert join_request.reviewed_by == "admin123"
        assert join_request.reviewer_comment == "Welcome!"
        assert join_request.metadata == metadata
    
    def test_join_request_to_dict(self):
        """Test converting join request to dictionary"""
        join_request = JoinRequest(
            id="req123",
            group_id="group123",
            group_name="Test Group",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            message="Please let me join",
            token="token123",
            status=JoinRequestStatus.APPROVED,
            reviewed_by="admin123",
            reviewer_comment="Welcome!",
            metadata={"key": "value"}
        )
        
        result = join_request.to_dict()
        
        assert result["id"] == "req123"
        assert result["group_id"] == "group123"
        assert result["group_name"] == "Test Group"
        assert result["user_id"] == "user123"
        assert result["user_email"] == "user@example.com"
        assert result["user_name"] == "Test User"
        assert result["message"] == "Please let me join"
        assert result["token"] == "token123"
        assert result["status"] == "approved"  # Enum value
        assert result["reviewed_by"] == "admin123"
        assert result["reviewer_comment"] == "Welcome!"
        assert result["metadata"] == {"key": "value"}
        assert isinstance(result["created_at"], str)
        assert isinstance(result["expires_at"], str)
    
    def test_join_request_from_dict(self):
        """Test creating join request from dictionary"""
        data = {
            "id": "req123",
            "group_id": "group123",
            "group_name": "Test Group",
            "user_id": "user123",
            "user_email": "user@example.com",
            "user_name": "Test User",
            "message": "Please let me join",
            "token": "token123",
            "status": "pending",
            "reviewed_by": "admin123",
            "reviewer_comment": "Welcome!",
            "metadata": {"key": "value"},
            "created_at": time.time(),
            "expires_at": time.time() + 3600
        }
        
        join_request = JoinRequest.from_dict(data)
        
        assert join_request.id == "req123"
        assert join_request.group_id == "group123"
        assert join_request.group_name == "Test Group"
        assert join_request.user_id == "user123"
        assert join_request.user_email == "user@example.com"
        assert join_request.user_name == "Test User"
        assert join_request.message == "Please let me join"
        assert join_request.token == "token123"
        assert join_request.status == JoinRequestStatus.PENDING
        assert join_request.reviewed_by == "admin123"
        assert join_request.reviewer_comment == "Welcome!"
        assert join_request.metadata == {"key": "value"}
        assert isinstance(join_request.created_at, float)
        assert isinstance(join_request.expires_at, float)
    
    def test_join_request_generate_id(self):
        """Test generating unique join request IDs"""
        id1 = JoinRequest.generate_id()
        id2 = JoinRequest.generate_id()
        
        assert id1 != id2
        assert len(id1) == 36  # UUID4 length
    
    def test_join_request_generate_token(self):
        """Test generating unique join request tokens"""
        token1 = JoinRequest.generate_token()
        token2 = JoinRequest.generate_token()
        
        assert token1 != token2
        assert len(token1) == 32  # UUID4 hex length
    
    def test_join_request_is_expired(self):
        """Test join request expiration check"""
        # Create expired join request
        expired_request = JoinRequest(
            id="req123",
            group_id="group123",
            group_name="Test Group",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            expires_at=time.time() - 3600  # 1 hour ago
        )
        
        # Create valid join request
        valid_request = JoinRequest(
            id="req124",
            group_id="group123",
            group_name="Test Group",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            expires_at=time.time() + 3600  # 1 hour from now
        )
        
        assert expired_request.is_expired() is True
        assert valid_request.is_expired() is False
    
    def test_join_request_is_pending(self):
        """Test join request pending status check"""
        # Create pending non-expired request
        pending_request = JoinRequest(
            id="req123",
            group_id="group123",
            group_name="Test Group",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            status=JoinRequestStatus.PENDING,
            expires_at=time.time() + 3600  # 1 hour from now
        )
        
        # Create expired pending request
        expired_pending_request = JoinRequest(
            id="req124",
            group_id="group123",
            group_name="Test Group",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            status=JoinRequestStatus.PENDING,
            expires_at=time.time() - 3600  # 1 hour ago
        )
        
        # Create approved request
        approved_request = JoinRequest(
            id="req125",
            group_id="group123",
            group_name="Test Group",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            status=JoinRequestStatus.APPROVED,
            expires_at=time.time() + 3600  # 1 hour from now
        )
        
        assert pending_request.is_pending() is True
        assert expired_pending_request.is_pending() is False
        assert approved_request.is_pending() is False
    
    def test_join_request_can_be_reviewed(self):
        """Test join request review eligibility"""
        # Create reviewable request
        reviewable_request = JoinRequest(
            id="req123",
            group_id="group123",
            group_name="Test Group",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            status=JoinRequestStatus.PENDING,
            expires_at=time.time() + 3600  # 1 hour from now
        )
        
        # Create non-reviewable request (already approved)
        non_reviewable_request = JoinRequest(
            id="req124",
            group_id="group123",
            group_name="Test Group",
            user_id="user123",
            user_email="user@example.com",
            user_name="Test User",
            status=JoinRequestStatus.APPROVED,
            expires_at=time.time() + 3600  # 1 hour from now
        )
        
        assert reviewable_request.can_be_reviewed() is True
        assert non_reviewable_request.can_be_reviewed() is False


class TestEnums:
    """Test enum classes"""
    
    def test_group_role_enum(self):
        """Test GroupRole enum values"""
        assert GroupRole.MEMBER.value == "member"
        assert GroupRole.MANAGER.value == "manager"
        assert GroupRole.ADMINISTRATOR.value == "administrator"
    
    def test_invitation_status_enum(self):
        """Test InvitationStatus enum values"""
        assert InvitationStatus.PENDING.value == "pending"
        assert InvitationStatus.ACCEPTED.value == "accepted"
        assert InvitationStatus.EXPIRED.value == "expired"
        assert InvitationStatus.REVOKED.value == "revoked"
        assert InvitationStatus.FAILED.value == "failed"
    
    def test_join_request_status_enum(self):
        """Test JoinRequestStatus enum values"""
        assert JoinRequestStatus.PENDING.value == "pending"
        assert JoinRequestStatus.APPROVED.value == "approved"
        assert JoinRequestStatus.DENIED.value == "denied"
        assert JoinRequestStatus.EXPIRED.value == "expired"